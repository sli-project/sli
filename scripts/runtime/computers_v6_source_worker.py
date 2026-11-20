#!/usr/bin/env python3
"""Capture and persist the V6-only approved Computers source snapshot.

The high-cost DNS, AD-Site, and exact-lastLogon operations live in this dedicated
worker and are never added to the shared low-cost AD context collector.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.computers_v6_source import (
    MAX_SNAPSHOT_BYTES,
    base_inventory_status,
    canonical_computers_v6_snapshot,
    parse_computers_v6_snapshot,
    validate_computers_v6_snapshot,
)


from server.sli.plugins.ad.snapshots.computers_persistence import (
    _utc, _source_timestamp, _domain_id,
    persist_computers_v6_source_snapshot,
)

COLLECTOR_ADAPTER = (
    ROOT / "scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1"
)
WORKER_NAME = "computers_v6_source"
LOCK_NAME = "ad_log_reports_runtime_computers_v6_source_worker"
DEFAULT_CAPTURE_INTERVAL_SECONDS = 12 * 60 * 60
ALLOWED_CAPTURE_INTERVAL_SECONDS = frozenset({12 * 60 * 60, 24 * 60 * 60})
INITIAL_DELAY_SECONDS = 120
COLLECTOR_TIMEOUT_SECONDS = 60 * 60

APPROVED_REFERENCE_SHA256 = (
    "caf0ee7e590e133a4e834bb31997e5253a5e707e347e677158260ab7085154d5"
)
APPROVED_REFERENCE_SHA256_BYTES = bytes.fromhex(APPROVED_REFERENCE_SHA256)


def build_collector_command(
    *,
    output_path: str | Path,
    powershell_executable: str,
    server: str | None = None,
    search_base: str | None = None,
    skip_dns: bool = False,
    collect_ad_site: bool = False,
    collect_exact_last_logon: bool = False,
    coordinator_base_input_path: str | Path | None = None,
) -> list[str]:
    command = [
        str(powershell_executable),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(COLLECTOR_ADAPTER),
        "-OutputPath",
        str(output_path),
    ]
    if server:
        command.extend(("-Server", str(server)))
    if search_base:
        command.extend(("-SearchBase", str(search_base)))
    if skip_dns:
        command.append("-SkipDns")
    if collect_ad_site:
        command.append("-CollectAdSite")
    if collect_exact_last_logon:
        command.append("-CollectExactLastLogon")
    if coordinator_base_input_path is not None:
        command.extend(
            ("-CoordinatorBaseInputPath", str(coordinator_base_input_path))
        )
    return command


def capture_and_persist_once(
    *,
    connection_factory: Callable[[], Any],
    captured_at: datetime | None,
    powershell_executable: str,
    server: str | None,
    search_base: str | None,
    skip_dns: bool,
    collect_ad_site: bool,
    collect_exact_last_logon: bool,
    coordinator_base_rows: list[Mapping[str, Any]] | None = None,
    runner: Callable[..., Any] | None = None,
    temp_directory: str | Path | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    timeout_seconds: int = COLLECTOR_TIMEOUT_SECONDS,
    max_snapshot_bytes: int = MAX_SNAPSHOT_BYTES,
) -> dict[str, Any]:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_source_auth import validate_ad_source_credential_mode
    credential_mode = validate_ad_source_credential_mode(
        os.environ.get("ADLOG_AD_SOURCE_CREDENTIAL_MODE", "process")
    )
    if runner is None and credential_mode == "dpapi_current_user" and powershell_executable == "powershell.exe":
        powershell_executable = str(Path(os.environ.get("SystemRoot", "C:/Windows")) /
                                   "System32/WindowsPowerShell/v1.0/powershell.exe")
    timeout = int(timeout_seconds)
    if timeout <= 0 or timeout > COLLECTOR_TIMEOUT_SECONDS:
        raise ValueError("collector_timeout_out_of_bounds")
    snapshot_limit = int(max_snapshot_bytes)
    if snapshot_limit <= 0 or snapshot_limit > MAX_SNAPSHOT_BYTES:
        raise ValueError("collector_snapshot_size_out_of_bounds")
    root = Path(temp_directory) if temp_directory is not None else Path(
        tempfile.gettempdir()
    )
    root.mkdir(parents=True, exist_ok=True)
    output_path = root / f"computers-v6-source-{uuid4()}.json"
    coordinator_base_path: Path | None = None
    coordinator_identity_allowlist: frozenset[str] | None = None
    options = {
        "server": server,
        "search_base": search_base,
        "skip_dns": bool(skip_dns),
        "collect_ad_site": bool(collect_ad_site),
        "collect_exact_last_logon": bool(collect_exact_last_logon),
    }
    if coordinator_base_rows is not None:
        if len(coordinator_base_rows) > 50_000:
            raise ValueError("coordinator_base_record_bound_exceeded")
        identities: list[str] = []
        for row in coordinator_base_rows:
            try:
                identities.append(str(UUID(str(row.get("ObjectGUID") or ""))).lower())
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("coordinator_base_identity_invalid") from exc
        if len(set(identities)) != len(identities):
            raise ValueError("coordinator_base_identity_duplicate")
        objects_json = json.dumps(
            coordinator_base_rows,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        envelope = json.dumps(
            {
                "schema_version": "sli.ad-computer-base/1.0",
                "object_count": len(coordinator_base_rows),
                "objects_sha256": hashlib.sha256(objects_json.encode("utf-8")).hexdigest(),
                "objects_json": objects_json,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(envelope) > MAX_SNAPSHOT_BYTES:
            raise ValueError("coordinator_base_byte_bound_exceeded")
        coordinator_base_path = root / f"computers-v6-base-{uuid4()}.json"
        coordinator_base_path.write_bytes(envelope)
        coordinator_identity_allowlist = frozenset(identities)
    command = build_collector_command(
        output_path=output_path,
        powershell_executable=powershell_executable,
        coordinator_base_input_path=coordinator_base_path,
        **options,
    )
    try:
        if runner is None and credential_mode == "dpapi_current_user":
            from server.sli.sources.ad_source_process import run_ad_source_process
            completed_process = run_ad_source_process(
                command, server=server or "", cwd=ROOT, timeout_seconds=timeout,
            )
        else:
            completed_process = (runner or subprocess.run)(
                command,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
            )
        exit_code = int(completed_process.returncode)
        if not output_path.is_file():
            stderr_tail = str(completed_process.stderr or "").strip()[-1000:]
            raise RuntimeError(
                "computers_v6_collector_wrote_no_snapshot:"
                f"exit_code={exit_code}:stderr={stderr_tail}"
            )
        size = output_path.stat().st_size
        if size <= 0 or size > snapshot_limit:
            raise RuntimeError("computers_v6_source_snapshot_size_out_of_bounds")
        snapshot = parse_computers_v6_snapshot(
            output_path.read_bytes(), max_bytes=snapshot_limit
        )
        if coordinator_identity_allowlist is not None:
            output_identities = frozenset(
                str(UUID(str(item["objectGuid"]))).lower()
                for item in snapshot["objects"]
            )
            if output_identities != coordinator_identity_allowlist:
                raise RuntimeError("coordinator_base_identity_mismatch")
        base_status = base_inventory_status(snapshot)
        collection_status = str(snapshot["metadata"]["collection_status"])
        if exit_code != 0 and not (
            base_status != "observed" and collection_status == "failed"
        ):
            raise RuntimeError("collector_failed_after_usable_snapshot")
        if exit_code == 0 and collection_status == "failed":
            raise RuntimeError("collector_reported_success_with_failed_snapshot")
        persisted_at = captured_at if captured_at is not None else clock()
        with connection_factory() as connection:
            persisted = persist_computers_v6_source_snapshot(
                connection,
                snapshot=snapshot,
                captured_at=persisted_at,
                capture_options=options,
                collector_exit_code=exit_code,
            )
        return {
            **persisted,
            "collector_exit_code": exit_code,
        }
    finally:
        try:
            output_path.unlink()
        except FileNotFoundError:
            pass
        if coordinator_base_path is not None:
            try:
                coordinator_base_path.unlink()
            except FileNotFoundError:
                pass


def run_worker_cycle(
    *,
    lock_context_factory: Callable[[], Any],
    capture_once: Callable[[], dict[str, Any]],
    heartbeat: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    with lock_context_factory() as acquired:
        if acquired:
            result = capture_once()
        else:
            result = {"status": "skipped", "reason": "lock_busy"}
    heartbeat(result)
    return result


def run_coordinator_enrichment_cycle(
    *,
    lock_context_factory: Callable[[], Any],
    capture_from_base: Callable[[], dict[str, Any]],
    heartbeat: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    """Use the standalone lock and fail closed; never start its full collector."""
    with lock_context_factory() as acquired:
        if acquired:
            result = capture_from_base()
        else:
            result = {"status": "blocked", "reason": "standalone_source_lock_busy"}
    heartbeat(result)
    return result


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true")
    parser.add_argument(
        "--interval-hours",
        type=int,
        choices=(12, 24),
        default=DEFAULT_CAPTURE_INTERVAL_SECONDS // 3600,
    )
    parser.add_argument("--server")
    parser.add_argument("--search-base")
    parser.add_argument("--skip-dns", action="store_true")
    parser.add_argument("--collect-ad-site", action="store_true")
    parser.add_argument("--collect-exact-last-logon", action="store_true")
    parser.add_argument("--powershell", default="powershell.exe")
    parser.add_argument("--temp-directory")
    parser.add_argument("--no-initial-delay", action="store_true")
    return parser


def main(
    argv: list[str] | None = None,
    *,
    connection_factory: Callable[[], Any] | None = None,
    lock_context_factory: Callable[[], Any] | None = None,
    heartbeat_recorder: Callable[[dict[str, Any]], Any] | None = None,
    runner: Callable[..., Any] | None = None,
    sleep_fn: Callable[[float], Any] = time.sleep,
) -> int:
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    from server.sli.sources.ad_gpo_jobs import enabled

    if enabled():
        return 0
    args = build_argument_parser().parse_args(argv)
    interval_seconds = int(args.interval_hours) * 60 * 60
    if interval_seconds not in ALLOWED_CAPTURE_INTERVAL_SECONDS:
        raise ValueError("capture_interval_not_allowed")

    if connection_factory is None:
        from server.sli.core.postgres_runtime_pipeline import connect

        connection_factory = connect
    if lock_context_factory is None:
        from server.sli.ops.postgres_session_lock import session_advisory_lock

        lock_context_factory = lambda: session_advisory_lock(
            connection_factory, LOCK_NAME
        )

    worker_id = f"{socket.gethostname()}:{os.getpid()}:{uuid4()}"
    started_at = datetime.now(timezone.utc)
    if heartbeat_recorder is None:
        from server.sli.ops.runtime_workers import record_worker_heartbeat

        def heartbeat_recorder(payload: dict[str, Any]) -> Any:
            return record_worker_heartbeat(
                worker_name=WORKER_NAME,
                worker_id=worker_id,
                status=str(payload["status"]),
                phase="sleeping" if payload["status"] != "failed" else "failed",
                expected_interval_seconds=interval_seconds,
                started_at=started_at,
                details=payload,
                connection_factory=connection_factory,
            )

    def emit_heartbeat(result: dict[str, Any]) -> None:
        heartbeat_recorder(
            {
                **result,
                "worker_name": WORKER_NAME,
                "worker_id": worker_id,
                "expected_interval_seconds": interval_seconds,
            }
        )

    def capture_once() -> dict[str, Any]:
        return capture_and_persist_once(
            connection_factory=connection_factory,
            captured_at=None,
            powershell_executable=args.powershell,
            server=args.server,
            search_base=args.search_base,
            skip_dns=args.skip_dns,
            collect_ad_site=args.collect_ad_site,
            collect_exact_last_logon=args.collect_exact_last_logon,
            runner=runner,
            temp_directory=args.temp_directory,
        )

    if not args.once and not args.no_initial_delay:
        sleep_fn(INITIAL_DELAY_SECONDS)
    while True:
        try:
            result = run_worker_cycle(
                lock_context_factory=lock_context_factory,
                capture_once=capture_once,
                heartbeat=emit_heartbeat,
            )
            print(json.dumps(result, ensure_ascii=False, default=str), flush=True)
        except Exception as exc:
            result = {
                "status": "failed",
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            emit_heartbeat(result)
            print(
                json.dumps(result, ensure_ascii=False, default=str),
                file=sys.stderr,
                flush=True,
            )
            if args.once:
                return 1
        if args.once:
            if result.get("collection_status") == "failed":
                return 1
            return 0
        sleep_fn(interval_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
