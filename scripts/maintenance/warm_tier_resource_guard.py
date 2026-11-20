#!/usr/bin/env python3
"""Measure the isolated ClickHouse warm-tier resource envelope read-only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTAINER = "sli-warm-tier-step1"
DATABASE = "sli_warm"
DEFAULT_OUTPUT = (
    ROOT / "artifacts" / "stage7" / "evidence" / "warm-tier-resource-guard.json"
)

GIB = 1024**3
MIN_CONTAINER_MEMORY_BYTES = 4 * GIB
MIN_ENGINE_HEADROOM_BYTES = 2 * GIB
PROJECTED_365_DAY_FOOTPRINT_BYTES = int(33.8 * GIB)
DISK_RESERVE_FACTOR = 1.5
MAX_ACCEPTED_MEMORY_USAGE_RATIO = 0.70


def _docker(args: list[str]) -> str:
    completed = subprocess.run(
        ["docker", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(f"docker {args[0]} failed: {detail}")
    return completed.stdout.strip()


def _parse_percentage(value: str) -> float:
    return float(value.strip().rstrip("%")) / 100.0


def evaluate_resources(measurements: dict[str, Any]) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []

    memory_limit = int(measurements["container_memory_limit_bytes"])
    memory_swap = int(measurements["container_memory_swap_bytes"])
    memory_ratio = float(measurements["container_memory_usage_ratio"])
    engine_memory = int(measurements["docker_engine_memory_bytes"])
    host_free = int(measurements["host_root_free_bytes"])
    volume_free = int(measurements["clickhouse_volume_free_bytes"])
    required_disk_reserve = int(
        PROJECTED_365_DAY_FOOTPRINT_BYTES * DISK_RESERVE_FACTOR
    )

    if not bool(measurements["container_running"]):
        blockers.append("container_is_not_running")
    if memory_limit < MIN_CONTAINER_MEMORY_BYTES:
        blockers.append("container_memory_limit_below_4_gib")
    if memory_swap < memory_limit:
        blockers.append("container_swap_limit_below_memory_limit")
    if memory_ratio > MAX_ACCEPTED_MEMORY_USAGE_RATIO:
        blockers.append("container_memory_usage_above_70_percent")
    if engine_memory - memory_limit < MIN_ENGINE_HEADROOM_BYTES:
        blockers.append("docker_engine_headroom_below_2_gib")
    if host_free < required_disk_reserve:
        blockers.append("host_root_free_space_below_365_day_reserve")
    if volume_free < required_disk_reserve:
        blockers.append("clickhouse_volume_free_space_below_365_day_reserve")

    if int(measurements["container_nano_cpus"]) == 0:
        warnings.append("container_cpu_is_not_hard_capped")
    if measurements["container_restart_policy"] == "no":
        warnings.append("container_has_no_automatic_restart_policy")

    return {
        "ready_for_isolated_warm_tier": not blockers,
        "ready_for_production_cutover": False,
        "blockers": blockers,
        "warnings": warnings,
        "thresholds": {
            "minimum_container_memory_bytes": MIN_CONTAINER_MEMORY_BYTES,
            "minimum_engine_headroom_bytes": MIN_ENGINE_HEADROOM_BYTES,
            "maximum_memory_usage_ratio": MAX_ACCEPTED_MEMORY_USAGE_RATIO,
            "projected_365_day_footprint_bytes": PROJECTED_365_DAY_FOOTPRINT_BYTES,
            "disk_reserve_factor": DISK_RESERVE_FACTOR,
            "required_disk_reserve_bytes": required_disk_reserve,
        },
    }


def collect_measurements() -> dict[str, Any]:
    inspection = json.loads(
        _docker(["inspect", CONTAINER, "--format", "{{json .}}"])
    )
    host_config = inspection["HostConfig"]
    state = inspection["State"]
    info = json.loads(_docker(["info", "--format", "{{json .}}"]))
    stats = json.loads(
        _docker(["stats", CONTAINER, "--no-stream", "--format", "{{json .}}"])
    )

    block_size, total_blocks, available_blocks = (
        _docker(
            [
                "exec",
                CONTAINER,
                "stat",
                "-f",
                "-c",
                "%S %b %a",
                "/var/lib/clickhouse",
            ]
        )
        .splitlines()[-1]
        .split()
    )
    volume_total = int(block_size) * int(total_blocks)
    volume_free = int(block_size) * int(available_blocks)

    warm_rows, warm_bytes = (
        _docker(
            [
                "exec",
                CONTAINER,
                "clickhouse-client",
                "--readonly",
                "1",
                "--query",
                (
                    "SELECT sum(rows),sum(bytes_on_disk) FROM system.parts "
                    f"WHERE active AND database='{DATABASE}' FORMAT TSV"
                ),
            ]
        )
        .splitlines()[-1]
        .split("\t")
    )
    root_usage = shutil.disk_usage(ROOT.anchor)

    return {
        "container": CONTAINER,
        "database": DATABASE,
        "container_running": bool(state["Running"]),
        "container_memory_limit_bytes": int(host_config["Memory"]),
        "container_memory_swap_bytes": int(host_config["MemorySwap"]),
        "container_memory_usage_ratio": _parse_percentage(stats["MemPerc"]),
        "container_memory_usage_display": stats["MemUsage"],
        "container_cpu_usage_display": stats["CPUPerc"],
        "container_pids": int(stats["PIDs"]),
        "container_nano_cpus": int(host_config["NanoCpus"]),
        "container_restart_policy": host_config["RestartPolicy"]["Name"],
        "docker_engine_cpu_count": int(info["NCPU"]),
        "docker_engine_memory_bytes": int(info["MemTotal"]),
        "host_root": ROOT.anchor,
        "host_root_total_bytes": int(root_usage.total),
        "host_root_free_bytes": int(root_usage.free),
        "clickhouse_volume_total_bytes": volume_total,
        "clickhouse_volume_free_bytes": volume_free,
        "warm_active_rows": int(warm_rows),
        "warm_active_bytes_on_disk": int(warm_bytes),
    }


def build_report(measurements: dict[str, Any]) -> dict[str, Any]:
    return {
        "package_type": "WARM_TIER_RESOURCE_GUARD",
        "status": "ok",
        "mode": "isolated_read_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "measurements": measurements,
        "assessment": evaluate_resources(measurements),
        "safety": {
            "docker_configuration_changed": False,
            "clickhouse_data_changed": False,
            "production_postgresql_contacted": False,
            "production_routing_changed": False,
            "feature_flags_changed": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    output = args.output.resolve()
    evidence_root = (ROOT / "artifacts" / "stage7" / "evidence").resolve()
    if output.parent != evidence_root:
        parser.error(f"output must be directly inside {evidence_root}")

    report = build_report(collect_measurements())
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["assessment"]["ready_for_isolated_warm_tier"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
