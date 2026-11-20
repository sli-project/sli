#!/usr/bin/env python3
"""Bound ClickHouse diagnostic storage without touching SLI warm data."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CONTAINER = "sli-warm-tier-step1"
VOLUME = "sli-warm-tier-step1-data"
IMAGE = "clickhouse/clickhouse-server:25.8.28.1"
SERVER_CONFIG = ROOT / "config/clickhouse/010_system_log_retention.xml"
USER_CONFIG = ROOT / "config/clickhouse/011_disable_sampling_profiler.xml"
CONFIRMATION = "STABILIZE-CLICKHOUSE-DIAGNOSTIC-STORAGE"
EVIDENCE = ROOT / "artifacts/operations/clickhouse-storage-guard-latest.json"
SAFE_LOG_PREFIXES = (
    "trace_log", "text_log", "query_thread_log", "query_metric_log",
    "metric_log", "asynchronous_metric_log",
)


class GuardError(RuntimeError):
    pass


def _run(args: list[str], *, timeout: int = 120) -> str:
    completed = subprocess.run(
        args, cwd=ROOT, text=True, capture_output=True, timeout=timeout,
        check=False,
    )
    if completed.returncode:
        raise GuardError(
            f"command_failed:{args[:4]!r}:"
            + (completed.stderr or completed.stdout)[-1500:]
        )
    return completed.stdout.strip()


def _docker(*args: str, timeout: int = 120) -> str:
    return _run(["docker", *args], timeout=timeout)


def _inspect(name: str) -> dict[str, Any] | None:
    completed = subprocess.run(
        ["docker", "inspect", name], cwd=ROOT, text=True,
        capture_output=True, timeout=30, check=False,
    )
    if completed.returncode:
        return None
    rows = json.loads(completed.stdout)
    return rows[0] if rows else None


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _clickhouse(query: str, *, readonly: bool = True, timeout: int = 120) -> str:
    args = ["exec", CONTAINER, "clickhouse-client"]
    if readonly:
        args.extend(["--readonly", "2"])
    args.extend(["--query", query])
    return _docker(*args, timeout=timeout)


def _wait_ready(timeout: int = 90) -> None:
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            if _clickhouse("SELECT 1", timeout=10) == "1":
                return
        except Exception as exc:
            last = type(exc).__name__
        time.sleep(1)
    raise GuardError(f"clickhouse_not_ready:{last}")


def _useful_snapshot() -> dict[str, Any]:
    query = """
SELECT database, table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes,
       groupUniqArray(toString(uuid)) AS uuids
FROM system.parts
WHERE active AND database NOT IN ('system','INFORMATION_SCHEMA','information_schema')
GROUP BY database, table ORDER BY database, table FORMAT JSON
""".strip()
    data = json.loads(_clickhouse(query))["data"]
    return {
        "tables": data,
        "identity": hashlib.sha256(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
    }


def _system_log_snapshot() -> dict[str, Any]:
    query = """
SELECT table, sum(rows) AS rows, sum(bytes_on_disk) AS bytes
FROM system.parts WHERE active AND database='system'
GROUP BY table ORDER BY bytes DESC FORMAT JSON
""".strip()
    data = json.loads(_clickhouse(query))["data"]
    return {"tables": data, "bytes": sum(int(row["bytes"]) for row in data)}


def _volume_bytes() -> int:
    return int(
        _docker("exec", CONTAINER, "du", "-sx", "-B1", "/var/lib/clickhouse").split()[0]
    )


def _validate_contract(info: dict[str, Any]) -> None:
    mounts = info.get("Mounts") or []
    data_mounts = [m for m in mounts if m.get("Destination") == "/var/lib/clickhouse"]
    if (
        len(data_mounts) != 1
        or data_mounts[0].get("Name") != VOLUME
        or not data_mounts[0].get("RW")
    ):
        raise GuardError("unexpected_clickhouse_data_mount")
    host = info.get("HostConfig") or {}
    if int(host.get("Memory") or 0) != 4 * 1024**3:
        raise GuardError("unexpected_clickhouse_memory_limit")
    if int(host.get("MemorySwap") or 0) != 6 * 1024**3:
        raise GuardError("unexpected_clickhouse_swap_limit")
    if (info.get("Config") or {}).get("Image") != IMAGE:
        raise GuardError("unexpected_clickhouse_image")


def plan() -> dict[str, Any]:
    info = _inspect(CONTAINER)
    if info is None:
        raise GuardError("clickhouse_container_missing")
    _validate_contract(info)
    _wait_ready()
    return {
        "status": "ready", "action": "plan", "container": CONTAINER,
        "volume": VOLUME, "image": IMAGE,
        "config": {
            "server_path": str(SERVER_CONFIG),
            "server_sha256": _sha256(SERVER_CONFIG),
            "user_path": str(USER_CONFIG),
            "user_sha256": _sha256(USER_CONFIG),
        },
        "useful": _useful_snapshot(),
        "system_logs": _system_log_snapshot(),
        "volume_bytes": _volume_bytes(),
        "required_confirmation": CONFIRMATION,
        "production_useful_data_changed": False,
    }


def _start_replacement() -> None:
    _docker(
        "run", "-d", "--name", CONTAINER, "--restart", "unless-stopped",
        "--memory", "4g", "--memory-swap", "6g",
        "--ulimit", "nofile=262144:262144",
        "-e", "CLICKHOUSE_SKIP_USER_SETUP=1", "-p", "127.0.0.1::8123",
        "-v", f"{VOLUME}:/var/lib/clickhouse",
        "--mount", (
            f"type=bind,source={SERVER_CONFIG.resolve()},"
            "target=/etc/clickhouse-server/config.d/010_system_log_retention.xml,readonly"
        ),
        "--mount", (
            f"type=bind,source={USER_CONFIG.resolve()},"
            "target=/etc/clickhouse-server/users.d/011_disable_sampling_profiler.xml,readonly"
        ),
        IMAGE, timeout=120,
    )
    _wait_ready()


def _safe_log_tables() -> list[str]:
    names = _clickhouse(
        "SELECT name FROM system.tables WHERE database='system' ORDER BY name FORMAT TSVRaw"
    ).splitlines()
    return [
        name for name in names
        if re.fullmatch(r"[A-Za-z0-9_]+", name)
        and any(name == p or name.startswith(p + "_") for p in SAFE_LOG_PREFIXES)
    ]


def apply(confirmation: str) -> dict[str, Any]:
    if confirmation != CONFIRMATION:
        raise GuardError("exact_confirmation_required")
    before = plan()
    rollback_name = f"{CONTAINER}-rollback-{datetime.now(timezone.utc):%Y%m%d%H%M%S}"
    _docker("stop", "--time", "60", CONTAINER, timeout=90)
    _docker("rename", CONTAINER, rollback_name)
    try:
        _start_replacement()
        if _useful_snapshot() != before["useful"]:
            raise GuardError("useful_data_snapshot_changed_after_restart")
        truncated = []
        for table in _safe_log_tables():
            _clickhouse(
                f"TRUNCATE TABLE system.{table} SYNC", readonly=False, timeout=300
            )
            truncated.append(table)
        _clickhouse("SYSTEM FLUSH LOGS", readonly=False)
        useful_after = _useful_snapshot()
        if useful_after != before["useful"]:
            raise GuardError("useful_data_snapshot_changed_after_cleanup")
        active = _inspect(CONTAINER) or {}
        result = {
            "status": "applied",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "container": CONTAINER, "volume": VOLUME,
            "restart_policy": (
                ((active.get("HostConfig") or {}).get("RestartPolicy") or {}).get("Name")
            ),
            "useful_before": before["useful"], "useful_after": useful_after,
            "useful_data_unchanged": True,
            "system_logs_before": before["system_logs"],
            "system_logs_after": _system_log_snapshot(),
            "volume_bytes_before": before["volume_bytes"],
            "volume_bytes_after": _volume_bytes(),
            "truncated_system_log_tables": truncated,
            "rollback_used": False, "production_useful_data_changed": False,
        }
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        _docker("rm", rollback_name, timeout=120)
        return result
    except BaseException:
        if _inspect(CONTAINER) is not None:
            try:
                _docker("rm", "-f", CONTAINER, timeout=120)
            except Exception:
                pass
        _docker("rename", rollback_name, CONTAINER)
        _docker("start", CONTAINER, timeout=120)
        _wait_ready()
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=("plan", "apply"), default="plan")
    parser.add_argument("--confirmation", default="")
    args = parser.parse_args()
    try:
        result = plan() if args.action == "plan" else apply(args.confirmation)
    except Exception as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
