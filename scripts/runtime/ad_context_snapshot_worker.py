#!/usr/bin/env python3
"""Collect and atomically import the complete configured AD context every cycle.

One process owns one PostgreSQL advisory lock and sequentially executes the
bounded, repository-owned collectors for:

* privileged group membership;
* directory accounts;
* VPN group membership;
* bounded GPO report and configured permission facts.

The four bundles are imported in one PostgreSQL transaction.  A collector
failure therefore leaves the previous complete database snapshot untouched.
This worker never changes AD, GPO or VPN configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.ad_context.contracts import load_bundle
from server.sli.core.app_config import load_config
from server.sli.core.postgres_runtime_pipeline import connect as runtime_connect
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.ops.postgres_session_lock import session_advisory_lock
from server.sli.ops.runtime_workers import record_worker_heartbeat
from server.sli.sources.collection_packet_import import import_snapshot_packet
from server.sli.sources.windows_runtime_identity import verify_collection_identity
from server.source_packs.adapters import AdContextRequest, build_ad_context_command
from sli_collect.snapshots import snapshot_packet

from server.sli.agents.snapshot_publication_connection import _import_connect

LOCK_NAME = "ad_log_reports_runtime_ad_context_snapshot_worker"
WORKER_NAME = "ad_context_snapshot"
LIGHT_SECTIONS = (
    "privileged_membership",
    "directory_accounts",
    "directory_group_graph",
    "vpn_membership",
    "gpo_governance",
    "domain_posture",
)
DEEP_SECTIONS = ("domain_health",)
EXACT_LOGON_SECTIONS = ("directory_exact_logon",)
SECTIONS = LIGHT_SECTIONS
SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]{0,252}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
SID_RE = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)
MAX_GROUP_REFERENCES = 50
DEFAULT_OUTPUT_ROOT = ROOT / "data" / "runtime" / "ad_context_snapshot"
MANIFEST_COORDINATOR_INTERVAL_SECONDS = 43200
AD_SNAPSHOT_BASE_PROFILE = "ad_snapshot_base_v1"


def _immutable_base_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _immutable_base_value(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_immutable_base_value(item) for item in value)
    return value


def _bounded_base_rows(
    rows: Any,
    *,
    family: str,
    record_limit: int,
    byte_limit: int,
) -> tuple[tuple[Mapping[str, Any], ...], str, int]:
    materialized = list(rows)
    if len(materialized) > record_limit:
        raise ValueError(f"{family}_record_bound_exceeded")
    canonical = json.dumps(
        materialized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    if len(canonical) > byte_limit:
        raise ValueError(f"{family}_byte_bound_exceeded")
    seen: set[str] = set()
    for row in materialized:
        if not isinstance(row, Mapping):
            raise ValueError(f"{family}_row_invalid")
        try:
            guid = str(UUID(str(row.get("object_guid") or ""))).lower()
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(f"{family}_stable_guid_invalid") from exc
        if guid in seen:
            raise ValueError(f"{family}_stable_guid_duplicate")
        seen.add(guid)
    import hashlib

    frozen = tuple(_immutable_base_value(row) for row in materialized)
    return frozen, hashlib.sha256(canonical).hexdigest(), len(canonical)


def coordinate_ad_snapshot_base_v1(
    *,
    enumerate_users: Callable[[], Any],
    enumerate_computers: Callable[[], Any],
    consume_group_graph: Callable[[tuple[Mapping[str, Any], ...], frozenset[str]], Any],
    consume_exact_user_logon: Callable[[frozenset[str]], Any],
    consume_computer_enrichment: Callable[[tuple[tuple[str, str | None], ...]], Any],
    max_user_records: int,
    max_computer_records: int,
    max_base_bytes: int,
    max_elapsed_seconds: float,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run the dormant P4 source boundary without scheduling or source fallback."""
    if not 1 <= int(max_user_records) <= 50_000:
        raise ValueError("user_record_bound_invalid")
    if not 1 <= int(max_computer_records) <= 50_000:
        raise ValueError("computer_record_bound_invalid")
    if not 1024 <= int(max_base_bytes) <= 25 * 1024 * 1024:
        raise ValueError("base_byte_bound_invalid")
    if not 0 < float(max_elapsed_seconds) <= 900:
        raise ValueError("base_time_bound_invalid")
    started = clock()

    users, user_hash, user_bytes = _bounded_base_rows(
        enumerate_users(),
        family="user",
        record_limit=int(max_user_records),
        byte_limit=int(max_base_bytes),
    )
    if clock() - started > max_elapsed_seconds:
        raise TimeoutError("user_base_time_bound_exceeded")
    computers, computer_hash, computer_bytes = _bounded_base_rows(
        enumerate_computers(),
        family="computer",
        record_limit=int(max_computer_records),
        byte_limit=int(max_base_bytes) - user_bytes,
    )
    if clock() - started > max_elapsed_seconds:
        raise TimeoutError("computer_base_time_bound_exceeded")

    user_allowlist = frozenset(
        str(UUID(str(row["object_guid"]))).lower() for row in users
    )
    computer_allowlist = tuple(
        (
            str(UUID(str(row["object_guid"]))).lower(),
            str(row.get("dns_name") or "").strip() or None,
        )
        for row in computers
    )
    consume_group_graph(users, user_allowlist)
    consume_exact_user_logon(user_allowlist)
    consume_computer_enrichment(computer_allowlist)
    return {
        "profile": AD_SNAPSHOT_BASE_PROFILE,
        "users": {"count": len(users), "sha256": user_hash, "bytes": user_bytes},
        "computers": {
            "count": len(computers),
            "sha256": computer_hash,
            "bytes": computer_bytes,
        },
    }


@dataclass(frozen=True)
class SnapshotConfig:
    directory_server: str
    domain: str
    search_base: str
    privileged_group_sids: tuple[str, ...]
    vpn_group_references: tuple[str, ...]
    interval_seconds: int = 1800
    deep_interval_seconds: int = 21600
    exact_logon_interval_seconds: int = 86400
    initial_delay_seconds: int = 30
    timeout_seconds: int = 300
    inactive_days: int = 180
    max_records: int = 50000
    max_bundle_bytes: int = 25 * 1024 * 1024
    max_directory_accounts: int = 50000
    max_directory_groups: int = 10000
    max_directory_memberships: int = 35000
    max_vpn_members: int = 50000
    max_gpos: int = 72
    technical_servers: tuple[str, ...] = ()
    technical_inventory_timeout_seconds: int = 20
    output_root: Path = DEFAULT_OUTPUT_ROOT


def _trusted_powershell() -> Path:
    if os.name != "nt":
        raise RuntimeError("AD context collection requires Windows")
    windows_root = Path(os.environ.get("WINDIR") or r"C:\Windows").resolve()
    executable = (
        windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    ).resolve()
    if not executable.is_file():
        raise RuntimeError("trusted system Windows PowerShell was not found")
    return executable


def _validate_config(config: SnapshotConfig) -> SnapshotConfig:
    if not SERVER_RE.fullmatch(config.directory_server):
        raise ValueError("directory_server must be one hostname, FQDN or IP")
    if not DNS_RE.fullmatch(config.domain):
        raise ValueError("domain must be one DNS domain")
    if (
        not config.search_base.upper().startswith("DC=")
        or "\r" in config.search_base
        or "\n" in config.search_base
    ):
        raise ValueError("search_base must be one directory DN")
    if (
        not config.privileged_group_sids
        or len(config.privileged_group_sids) > MAX_GROUP_REFERENCES
        or any(not SID_RE.fullmatch(value) for value in config.privileged_group_sids)
    ):
        raise ValueError("one to fifty exact privileged group SIDs are required")
    if (
        not config.vpn_group_references
        or len(config.vpn_group_references) > MAX_GROUP_REFERENCES
        or any(not SID_RE.fullmatch(value) for value in config.vpn_group_references)
    ):
        raise ValueError("one to fifty exact VPN group SIDs are required")
    if not 300 <= config.interval_seconds <= 86400:
        raise ValueError("interval_seconds must be between 300 and 86400")
    if not config.interval_seconds <= config.deep_interval_seconds <= 86400:
        raise ValueError("deep_interval_seconds must be between interval_seconds and 86400")
    if not config.interval_seconds <= config.exact_logon_interval_seconds <= 86400:
        raise ValueError("exact_logon_interval_seconds must be between interval_seconds and 86400")
    if not 0 <= config.initial_delay_seconds <= config.interval_seconds:
        raise ValueError("initial_delay_seconds must fit inside the interval")
    if not 30 <= config.timeout_seconds <= 900:
        raise ValueError("timeout_seconds must be between 30 and 900")
    if not 1 <= config.max_records <= 50000:
        raise ValueError("max_records must be between 1 and 50000")
    if not 1024 <= config.max_bundle_bytes <= 25 * 1024 * 1024:
        raise ValueError("max_bundle_bytes is out of bounds")
    for value in (
        config.max_directory_accounts,
        config.max_directory_groups,
        config.max_directory_memberships,
        config.max_vpn_members,
        config.max_gpos,
    ):
        if not 1 <= value <= config.max_records:
            raise ValueError("section limits must fit inside max_records")
    if config.max_gpos > 72:
        raise ValueError("max_gpos exceeds the proven 72-policy contract")
    if (
        len(config.technical_servers) > 50
        or any(not SERVER_RE.fullmatch(value) for value in config.technical_servers)
    ):
        raise ValueError("technical_servers must contain at most 50 exact hostnames")
    if not 5 <= config.technical_inventory_timeout_seconds <= 60:
        raise ValueError("technical_inventory_timeout_seconds must be between 5 and 60")
    output_root = config.output_root.resolve()
    allowed = DEFAULT_OUTPUT_ROOT.resolve()
    if output_root != allowed and allowed not in output_root.parents:
        raise ValueError("output_root must stay under data/runtime/ad_context_snapshot")
    return config


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        result = subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0 and process.poll() is None:
            process.kill()
    else:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()


def _section_request(
    config: SnapshotConfig,
    *,
    section: str,
    run_id: str,
    bundle_path: Path,
    powershell: Path,
) -> AdContextRequest:
    return AdContextRequest(
        powershell_executable=str(powershell),
        output_path=bundle_path,
        run_id=run_id,
        directory_server=config.directory_server,
        search_base=config.search_base,
        domain=config.domain,
        sections=(section,),
        privileged_groups=(
            config.privileged_group_sids
            if section == "privileged_membership"
            else ()
        ),
        vpn_groups=(
            config.vpn_group_references if section == "vpn_membership" else ()
        ),
        inactive_days=config.inactive_days,
        mode="reconcile",
        max_records=config.max_records,
        max_bundle_bytes=config.max_bundle_bytes,
        max_directory_accounts=config.max_directory_accounts,
        max_directory_groups=config.max_directory_groups,
        max_directory_memberships=config.max_directory_memberships,
        max_vpn_members=config.max_vpn_members,
        max_gpos=config.max_gpos,
        technical_servers=(
            config.technical_servers if section == "directory_accounts" else ()
        ),
        technical_inventory_timeout_seconds=config.technical_inventory_timeout_seconds,
    )


def _validate_collected_bundle(
    bundle: dict[str, Any],
    *,
    config: SnapshotConfig,
    section: str,
    run_id: str,
) -> None:
    if bundle["run_id"] != run_id:
        raise ValueError("collector returned an unexpected run_id")
    if bundle["domain"]["dns_name"].casefold() != config.domain.casefold():
        raise ValueError("collector returned an unexpected domain")
    if bundle["scope"]["search_base"].casefold() != config.search_base.casefold():
        raise ValueError("collector returned an unexpected search_base")
    if [item["name"] for item in bundle["sections"]] != [section]:
        raise ValueError("collector returned an unexpected section")
    expected_privileged = (
        {value.casefold() for value in config.privileged_group_sids}
        if section == "privileged_membership"
        else set()
    )
    actual_privileged = {
        value.casefold() for value in bundle["scope"]["privileged_group_sids"]
    }
    if actual_privileged != expected_privileged:
        raise ValueError("collector returned an unexpected privileged scope")
    expected_vpn = (
        {value.casefold() for value in config.vpn_group_references}
        if section == "vpn_membership"
        else set()
    )
    actual_vpn = {
        value.casefold() for value in bundle["scope"]["vpn_group_sids"]
    }
    if actual_vpn != expected_vpn:
        raise ValueError("collector returned an unexpected VPN scope")


def _collect_section(
    config: SnapshotConfig,
    *,
    section: str,
    cycle_dir: Path,
    powershell: Path,
) -> tuple[dict[str, Any], Path]:
    run_id = str(uuid4())
    bundle_path = cycle_dir / f"{section}-{run_id}.json"
    stdout_path = cycle_dir / f"{section}-{run_id}.stdout.log"
    stderr_path = cycle_dir / f"{section}-{run_id}.stderr.log"
    command = build_ad_context_command(
        _section_request(
            config,
            section=section,
            run_id=run_id,
            bundle_path=bundle_path,
            powershell=powershell,
        )
    )
    popen_kwargs: dict[str, Any] = {}
    if os.name == "nt":
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    with stdout_path.open("w", encoding="utf-8") as stdout_file, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_file:
        process = subprocess.Popen(
            command,
            cwd=str(ROOT),
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            text=True,
            **popen_kwargs,
        )
        try:
            exit_code = process.wait(timeout=config.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            _terminate_process_tree(process)
            raise TimeoutError(f"{section} collector exceeded its deadline") from exc
    if exit_code != 0:
        raise RuntimeError(
            f"{section} collector failed with exit code {exit_code}; "
            f"inspect {stderr_path.name}"
        )
    bundle = load_bundle(bundle_path)
    _validate_collected_bundle(
        bundle,
        config=config,
        section=section,
        run_id=run_id,
    )
    return bundle, bundle_path


def _import_cycle(bundles: list[dict[str, Any]]) -> list[dict[str, int]]:
    packets = [snapshot_packet(bundle, source=bundle["domain"]["sid"], channel="ad_context")
               for bundle in bundles]
    results: list[dict[str, int]] = []
    with _import_connect() as conn:
        for packet in packets:
            results.append(import_snapshot_packet(conn, packet))
    return results


def run_cycle(
    config: SnapshotConfig,
    *,
    worker_id: str,
    started_at: datetime,
    powershell: Path | None = None,
    sections: tuple[str, ...] = SECTIONS,
) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    config = _validate_config(config)
    cycle_id = str(uuid4())
    cycle_dir = config.output_root.resolve() / cycle_id
    cycle_dir.mkdir(parents=True, exist_ok=False)
    collected: list[dict[str, Any]] = []
    bundle_paths: list[Path] = []
    section_results: dict[str, dict[str, Any]] = {}
    started = time.monotonic()
    try:
        executable = powershell or _trusted_powershell()
        for section in sections:
            record_worker_heartbeat(
                worker_name=WORKER_NAME,
                worker_id=worker_id,
                status="running",
                phase=f"collect:{section}",
                expected_interval_seconds=config.interval_seconds,
                started_at=started_at,
                details={"cycle_id": cycle_id, "completed_sections": list(section_results)},
                connection_factory=runtime_connect,
            )
            bundle, bundle_path = _collect_section(
                config,
                section=section,
                cycle_dir=cycle_dir,
                powershell=executable,
            )
            collected.append(bundle)
            bundle_paths.append(bundle_path)
            section_meta = bundle["sections"][0]
            section_results[section] = {
                "status": section_meta["status"],
                "record_count": section_meta["record_count"],
                "duration_ms": section_meta["duration_ms"],
            }

        record_worker_heartbeat(
            worker_name=WORKER_NAME,
            worker_id=worker_id,
            status="running",
            phase="import",
            expected_interval_seconds=config.interval_seconds,
            started_at=started_at,
            details={"cycle_id": cycle_id, "sections": section_results},
            connection_factory=runtime_connect,
        )
        import_results = _import_cycle(collected)
        reported_statuses = {
            str(bundle["sections"][0]["status"]) for bundle in collected
        }
        status = "idle" if reported_statuses == {"complete"} else "partial"
        result = {
            "cycle_id": cycle_id,
            "status": status,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "sections": section_results,
            "imports": import_results,
        }
        shutil.rmtree(cycle_dir)
        return result
    except Exception:
        # Retain the bounded local evidence only for failed cycles.
        raise


def _deep_cycle_due(
    last_attempt_monotonic: float | None,
    *,
    now_monotonic: float,
    interval_seconds: int,
) -> bool:
    return last_attempt_monotonic is None or now_monotonic - last_attempt_monotonic >= interval_seconds


def manifest_slot_start_utc(value: datetime) -> str:
    """Return the immutable 00:00/12:00 UTC slot without scheduling work."""
    if value.tzinfo is None:
        raise ValueError("manifest slot input must include a timezone")
    utc = value.astimezone(timezone.utc)
    slot = utc.replace(
        hour=0 if utc.hour < 12 else 12, minute=0, second=0, microsecond=0
    )
    return slot.isoformat().replace("+00:00", "Z")


def coordinate_manifest_source_only(
    *,
    slot_start_utc: str,
    source_members: list[dict[str, Any]],
    publish: Any,
) -> dict[str, Any]:
    """Dormant source-only gate; runtime loops do not invoke this boundary."""
    del slot_start_utc
    if any(
        member.get("family") in {"ad_context", "computers_v6"}
        and member.get("source_state") == "failed"
        for member in source_members
    ):
        return {"status": "blocked", "reason": "base_source_failed"}
    candidate = {"source_members": [dict(member) for member in source_members]}
    publish(candidate)
    return {"status": "published"}


def run(config: SnapshotConfig, *, once: bool) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    config = _validate_config(config)
    identity = verify_collection_identity()
    if identity.get("status") != "ok":
        print(
            json.dumps(
                {
                    "status": "refused",
                    "reason": "windows_collection_identity_invalid",
                    "detail": identity,
                },
                ensure_ascii=False,
            ),
            flush=True,
        )
        return 1
    worker_id = f"ad-context-snapshot-{socket.gethostname()}-{os.getpid()}"
    started_at = datetime.now(timezone.utc)
    log_event(
        "runtime_worker",
        "ad_context_snapshot_worker_started",
        "Unified AD context snapshot worker started.",
        worker_id=worker_id,
        interval_seconds=config.interval_seconds,
    )
    with session_advisory_lock(runtime_connect, LOCK_NAME) as acquired:
        if not acquired:
            print(
                json.dumps(
                    {
                        "worker_id": worker_id,
                        "status": "skipped",
                        "reason": "ad_context_snapshot_worker_lock_held",
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            return 0
        if not once and config.initial_delay_seconds:
            record_worker_heartbeat(
                worker_name=WORKER_NAME,
                worker_id=worker_id,
                status="idle",
                phase="initial_delay",
                expected_interval_seconds=config.interval_seconds,
                started_at=started_at,
                details={"next_cycle_in_seconds": config.initial_delay_seconds},
                connection_factory=runtime_connect,
            )
            time.sleep(config.initial_delay_seconds)
        last_deep_attempt_monotonic: float | None = None
        last_exact_logon_attempt_monotonic: float | None = None
        while True:
            cycle_started_monotonic = time.monotonic()
            try:
                result = run_cycle(
                    config,
                    worker_id=worker_id,
                    started_at=started_at,
                    sections=LIGHT_SECTIONS,
                )
                deep_result = None
                deep_now = time.monotonic()
                if _deep_cycle_due(
                    last_deep_attempt_monotonic,
                    now_monotonic=deep_now,
                    interval_seconds=config.deep_interval_seconds,
                ):
                    last_deep_attempt_monotonic = deep_now
                    deep_result = run_cycle(
                        config,
                        worker_id=worker_id,
                        started_at=started_at,
                        sections=DEEP_SECTIONS,
                    )
                    result["deep_cycle"] = deep_result
                    if deep_result["status"] != "idle":
                        result["status"] = "partial"
                exact_logon_result = None
                exact_logon_now = time.monotonic()
                if _deep_cycle_due(
                    last_exact_logon_attempt_monotonic,
                    now_monotonic=exact_logon_now,
                    interval_seconds=config.exact_logon_interval_seconds,
                ):
                    last_exact_logon_attempt_monotonic = exact_logon_now
                    exact_logon_result = run_cycle(
                        config,
                        worker_id=worker_id,
                        started_at=started_at,
                        sections=EXACT_LOGON_SECTIONS,
                    )
                    result["exact_logon_cycle"] = exact_logon_result
                    if exact_logon_result["status"] != "idle":
                        result["status"] = "partial"
                print(json.dumps(result, ensure_ascii=False), flush=True)
                record_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    worker_id=worker_id,
                    status=str(result["status"]),
                    phase="sleep",
                    expected_interval_seconds=config.interval_seconds,
                    started_at=started_at,
                    details={
                        "last_cycle_id": result["cycle_id"],
                        "last_cycle_elapsed_ms": result["elapsed_ms"],
                        "sections": result["sections"],
                        "deep_cycle": deep_result,
                        "deep_interval_seconds": config.deep_interval_seconds,
                        "exact_logon_cycle": exact_logon_result,
                        "exact_logon_interval_seconds": config.exact_logon_interval_seconds,
                    },
                    connection_factory=runtime_connect,
                )
                if once:
                    return 0
            except Exception as exc:
                error_id = log_internal_error(
                    "runtime_worker",
                    "ad_context_snapshot_cycle_failed",
                    "Unified AD context snapshot cycle failed.",
                    exc=exc,
                    worker_id=worker_id,
                )
                failure = {
                    "worker_id": worker_id,
                    "status": "failed",
                    "error_id": error_id,
                    "error_type": type(exc).__name__,
                }
                print(json.dumps(failure, ensure_ascii=False), flush=True)
                record_worker_heartbeat(
                    worker_name=WORKER_NAME,
                    worker_id=worker_id,
                    status="failed",
                    phase="sleep",
                    expected_interval_seconds=config.interval_seconds,
                    started_at=started_at,
                    details=failure,
                    connection_factory=runtime_connect,
                )
                if once:
                    return 1
            elapsed = time.monotonic() - cycle_started_monotonic
            time.sleep(max(30, config.interval_seconds - elapsed))


def _csv_values(value: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(item.strip() for item in value.split(",") if item.strip()))


def _configured_technical_servers() -> tuple[str, ...]:
    """Reuse registered collection sources without creating another schedule."""
    try:
        from server.sli.sources.dc_discovery import stored_enabled_targets

        stored = stored_enabled_targets()
    except Exception:  # noqa: BLE001 - fall back to the file below
        stored = None
    if stored is not None:
        items: list = list(stored)
    else:
        path = ROOT / "config" / "domain_controllers.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return ()
        items = list(payload.get("domain_controllers") or [])
    values: list[str] = []
    seen: set[str] = set()
    for item in items:
        raw = item if isinstance(item, str) else item.get("hostname", "")
        hostname = str(raw or "").strip().lstrip("\\").split(".", 1)[0]
        key = hostname.casefold()
        if hostname and key not in seen:
            seen.add(key)
            values.append(hostname)
        if len(values) >= 50:
            break
    return tuple(values)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory-server")
    parser.add_argument("--domain")
    parser.add_argument("--search-base")
    parser.add_argument("--privileged-group-sids")
    parser.add_argument("--vpn-group-references")
    parser.add_argument("--interval-seconds", type=int, default=1800)
    parser.add_argument("--deep-interval-seconds", type=int, default=21600)
    parser.add_argument("--exact-logon-interval-seconds", type=int, default=86400)
    parser.add_argument("--initial-delay-seconds", type=int, default=30)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--inactive-days", type=int, default=180)
    parser.add_argument("--max-records", type=int, default=50000)
    parser.add_argument("--max-bundle-bytes", type=int, default=25 * 1024 * 1024)
    parser.add_argument("--max-directory-accounts", type=int, default=50000)
    parser.add_argument("--max-directory-groups", type=int, default=10000)
    parser.add_argument("--max-directory-memberships", type=int, default=35000)
    parser.add_argument("--max-vpn-members", type=int, default=50000)
    parser.add_argument("--max-gpos", type=int, default=72)
    parser.add_argument("--technical-servers", default="")
    parser.add_argument("--technical-inventory-timeout-seconds", type=int, default=20)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--load-supervisor-environment", action="store_true")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not args.load_supervisor_environment:
        missing = [
            option
            for option, value in (
                ("--directory-server", args.directory_server),
                ("--domain", args.domain),
                ("--search-base", args.search_base),
                ("--privileged-group-sids", args.privileged_group_sids),
                ("--vpn-group-references", args.vpn_group_references),
            )
            if not value
        ]
        if missing:
            parser.error(f"the following arguments are required: {', '.join(missing)}")
    return args


def main(argv: list[str] | None = None) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    args = parse_args(argv)
    if args.load_supervisor_environment:
        from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment

        load_supervisor_environment()
        protected_settings = {
            "directory_server": (
                os.environ.get("ADLOG_AD_CONTEXT_DIRECTORY_SERVER")
                or os.environ.get("ADLOG_COLLECTION_PREFLIGHT_SERVER")
                or ""
            ).strip(),
            "domain": os.environ.get("ADLOG_AD_CONTEXT_DOMAIN", "").strip(),
            "search_base": os.environ.get("ADLOG_AD_CONTEXT_SEARCH_BASE", "").strip(),
            "privileged_group_sids": os.environ.get(
                "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS", ""
            ).strip(),
            "vpn_group_references": os.environ.get(
                "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES", ""
            ).strip(),
        }
        environment_names = {
            "directory_server": "ADLOG_AD_CONTEXT_DIRECTORY_SERVER",
            "domain": "ADLOG_AD_CONTEXT_DOMAIN",
            "search_base": "ADLOG_AD_CONTEXT_SEARCH_BASE",
            "privileged_group_sids": "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS",
            "vpn_group_references": "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES",
        }
        missing = sorted(
            environment_names[name]
            for name, value in protected_settings.items()
            if not value
        )
        if missing:
            print(
                json.dumps(
                    {
                        "status": "refused",
                        "reason": "ad_context_snapshot_configuration_missing",
                        "missing": missing,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
            return 2
    else:
        protected_settings = {
            "directory_server": args.directory_server,
            "domain": args.domain,
            "search_base": args.search_base,
            "privileged_group_sids": args.privileged_group_sids,
            "vpn_group_references": args.vpn_group_references,
        }
    config = SnapshotConfig(
        directory_server=protected_settings["directory_server"],
        domain=protected_settings["domain"],
        search_base=protected_settings["search_base"],
        privileged_group_sids=_csv_values(protected_settings["privileged_group_sids"]),
        vpn_group_references=_csv_values(protected_settings["vpn_group_references"]),
        interval_seconds=args.interval_seconds,
        deep_interval_seconds=args.deep_interval_seconds,
        exact_logon_interval_seconds=args.exact_logon_interval_seconds,
        initial_delay_seconds=args.initial_delay_seconds,
        timeout_seconds=args.timeout_seconds,
        inactive_days=args.inactive_days,
        max_records=args.max_records,
        max_bundle_bytes=args.max_bundle_bytes,
        max_directory_accounts=args.max_directory_accounts,
        max_directory_groups=args.max_directory_groups,
        max_directory_memberships=args.max_directory_memberships,
        max_vpn_members=args.max_vpn_members,
        max_gpos=args.max_gpos,
        technical_servers=_csv_values(args.technical_servers) or _configured_technical_servers(),
        technical_inventory_timeout_seconds=args.technical_inventory_timeout_seconds,
        output_root=args.output_root,
    )
    return run(config, once=bool(args.once))


if __name__ == "__main__":
    raise SystemExit(main())
