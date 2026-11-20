# ruff: noqa: F401 -- re-export hub (plan 6.3); split parts import names from here.
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
from collections import deque
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

COLLECT_SCRIPT = ROOT / "scripts" / "collect" / "Collect-DcEventsLastHour.ps1"
PY_COLLECT_SCRIPT = ROOT / "scripts" / "collect" / "collect_windows_events.py"
POSTGRES_IMPORT_SCRIPT = ROOT / "scripts" / "import" / "import_event_jsonl_to_postgres.py"
from server.sli.core.paths import RAW_SPOOL_DIR

DEFAULT_RAW_ROOT = RAW_SPOOL_DIR
DEFAULT_REPORT_ROOT = ROOT / "data" / "reports"
POSTGRES_SOURCE_IDENTITY_PLACEHOLDERS = {"example", "example.invalid"}
DNS_LABEL_RE = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)\Z", re.IGNORECASE)

from server.sli.core.app_config import load_config
from server.sli.ops.logging_config import log_event, log_internal_error
from server.sli.ops.performance import log_performance_stage, monotonic_ms
from server.sli.sources.source_capture_continuity import AUTHENTICATION_EVENT_KEYS
from server.source_packs.registry import source_pack_metadata_for_channels, validate_adapter_for_channels
from server.source_packs.adapters import (
    BoundedWindowsEventLogSelection,
    WINDOWS_EVENTLOG_PYTHON,
    WindowsEventLogRequest,
    adapter_id_for_backend,
    build_windows_eventlog_command,
    parse_bounded_eventlog_selection,
)
from functools import partial
from server.sli.plugins.registry import require_plugin

load_radius_collection_routes = partial(require_plugin, "sli.remote-access", "load_radius_collection_routes")
resolve_nps_eventlog_endpoint = partial(require_plugin, "sli.remote-access", "resolve_nps_eventlog_endpoint")
validate_continuous_nps_admission = partial(require_plugin, "sli.remote-access", "validate_continuous_nps_admission")


def run_import_for_backend(
    *,
    target_backend: str,
    output_dir: Path,
    server: str,
    trace_id: str,
    job_id: int | None,
    collector_backend: str,
    db: Path | None = None,  # deprecated, ignored: PostgreSQL needs no database file
    domain_fqdn: str | None = None,
    forest_name: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], int, int, str]:
    if target_backend == "postgres":
        if domain_fqdn is None or forest_name is None:
            raise ValueError("postgres_source_identity_required")
        domain_fqdn = _normalize_source_fqdn(domain_fqdn, field_name="domain")
        forest_name = _normalize_source_fqdn(forest_name, field_name="forest")
        from server.sli.sources.postgres_import_queue import (
            PostgresImportQueueTimeout,
            postgres_import_queue,
        )

        import_cmd = [
            sys.executable,
            str(POSTGRES_IMPORT_SCRIPT),
            "--input-dir",
            str(output_dir),
            "--server",
            server,
            "--trace-id",
            trace_id,
            "--backend",
            collector_backend,
            "--domain",
            domain_fqdn,
            "--forest",
            forest_name,
            "--profile-output",
            str(output_dir / "postgres-import-profile.json"),
        ]
        if job_id is not None:
            import_cmd.extend(["--job-id", str(job_id)])
        queue_wait_ms = 0
        try:
            with postgres_import_queue(
                trace_id=trace_id,
                job_id=job_id,
                server=server,
            ) as queue_info:
                queue_wait_ms = queue_info.wait_ms
                log_performance_stage(
                    "import_queue_wait",
                    trace_id=trace_id,
                    job_id=job_id,
                    server=server,
                    backend=collector_backend,
                    status="completed",
                    duration_ms=queue_wait_ms,
                    queue_backend="postgres",
                )
                # The importer publishes straight to Storage V2 (plan 6.5); there is
                # no V1 outbox left to drain after it.
                imported = run_command(import_cmd, timeout_seconds=postgres_import_timeout_seconds())
        except PostgresImportQueueTimeout as exc:
            queue_wait_ms = exc.wait_ms
            message = str(exc)
            imported = subprocess.CompletedProcess(import_cmd, 75, "", message)
            imported.duration_ms = 0
            log_performance_stage(
                "import_queue_wait",
                trace_id=trace_id,
                job_id=job_id,
                server=server,
                backend=collector_backend,
                status="failed",
                duration_ms=queue_wait_ms,
                queue_backend="postgres",
                error=message,
            )
        status = "completed" if imported.returncode == 0 else "failed"
        log_performance_stage(
            "import_postgres",
            trace_id=trace_id,
            job_id=job_id,
            server=server,
            backend=collector_backend,
            status=status,
            duration_ms=getattr(imported, "duration_ms", None),
            queue_wait_ms=queue_wait_ms,
            error=((imported.stdout or imported.stderr or "")[-500:] if imported.returncode != 0 else None),
        )
        return imported, queue_wait_ms, 0, "postgres"

    raise ValueError(f"non_postgres_backend_forbidden: {target_backend}")


def main() -> int:
    # The scheduler reads this program through a pipe.  Force line buffering so
    # channel progress reaches the live job/API view while collection is still
    # running, rather than only when the whole DC run exits.
    from server.sli.sources.legacy_collection import require_legacy_collection

    require_legacy_collection()
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    parser = argparse.ArgumentParser(description="Run read-only DC log collection, import, and summary report.")
    parser.add_argument("--server", required=True, help="Logical DC hostname for DB/reports, for example DC2")
    parser.add_argument("--connect-address", help="FQDN used for remote Event Log access; defaults to --server.")
    parser.add_argument("--ad-source-credential-mode", default="process", help="Explicit AD/DC Python auth: process or dpapi_current_user; never a password.")
    parser.add_argument("--domain", help="Explicit source domain FQDN for PostgreSQL import; defaults to the domain suffix of --connect-address.")
    parser.add_argument("--forest", help="Explicit source forest FQDN for PostgreSQL import; defaults to --domain for the single-domain runtime.")
    parser.add_argument("--hours", type=int, default=1)
    parser.add_argument("--max-events-per-channel", type=int, default=200)
    parser.add_argument("--channels", help="Comma-separated channel list for this run. Defaults to the PowerShell collector default order.")
    parser.add_argument("--channel-limits-json", help="JSON object with per-channel MaxEvents overrides.")
    parser.add_argument("--channel-timeouts-json", help="JSON object with per-channel timeout overrides.")
    parser.add_argument("--job-id", type=int, help="Parent dashboard job id for collector history.")
    parser.add_argument("--use-record-id-cursor", default=os.environ.get("ADLOG_SECURITY_USE_RECORD_ID_CURSOR", "true"), help="Use EventRecordID cursor when archive state has it: true/false.")
    parser.add_argument("--collect-message", default=os.environ.get("ADLOG_COLLECT_MESSAGE", "false"), help="Collect heavy Windows Message field: true/false. Default false for bulk Security collection.")
    parser.add_argument("--collection-mode", choices=["auto", "current", "backfill", "recovery"], default="auto", help="Operational mode label stored in collection summary and collector health.")
    parser.add_argument("--collector-backend", choices=["auto", "python", "powershell"], default=os.environ.get("ADLOG_COLLECTOR_BACKEND", "auto"), help="Collector backend: auto prefers Python EventLog on the central host and falls back to PowerShell.")
    parser.add_argument("--start-time-utc", help="Collect events starting from this UTC timestamp instead of --hours.")
    parser.add_argument("--end-time-utc", help="Bounded NPS collection end timestamp in explicit UTC.")
    parser.add_argument("--event-ids-json", help="Bounded NPS exact Event ID allowlist as JSON.")
    parser.add_argument("--nps-continuous", action="store_true", help="Explicit separate NPS 6272/6273 runtime admission; never a DC target.")
    parser.add_argument(
        "--source-continuity-canary",
        action="store_true",
        help="Admit only the exact bounded AD Security source-continuity canary contract.",
    )
    parser.add_argument("--archive", action="store_true", help="Use archive state: first run from archive start, next runs from watermarks.")
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW_ROOT)
    parser.add_argument("--report-root", type=Path, default=DEFAULT_REPORT_ROOT, help="Deprecated no-op; kept for command-line compatibility.")
    # Deprecated no-op: the legacy SQLite HTML report was removed. Still accepted so that
    # existing callers (server collector, workers, external scheduled tasks) do not fail argparse.
    parser.add_argument("--no-technical-report", action="store_true", help="Deprecated no-op; the legacy pilot HTML report no longer exists.")
    parser.add_argument(
        "--adaptive-state-mode",
        choices=["update", "observe"],
        default=os.environ.get("ADLOG_ADAPTIVE_STATE_MODE", "update"),
        help="Adaptive state handling: update for normal cycles; observe records run evidence without changing working adaptive state.",
    )
    parser.add_argument(
        "--command-timeout-seconds",
        type=int,
        default=int(os.environ.get("ADLOG_COMMAND_TIMEOUT_SECONDS", "600")),
        help="Timeout for external PowerShell collection command.",
    )
    parser.add_argument(
        "--channel-timeout-seconds",
        type=int,
        default=int(os.environ.get("ADLOG_CHANNEL_TIMEOUT_SECONDS", "300")),
        help="Timeout for each Windows Event Log channel inside the PowerShell collector.",
    )
    args = parser.parse_args()
    connect_address = args.connect_address or args.server
    from server.sli.sources.ad_source_auth import resolve_ad_source_endpoint, validate_ad_source_credential_mode

    try:
        credential_mode = validate_ad_source_credential_mode(args.ad_source_credential_mode, backend=args.collector_backend)
        if args.nps_continuous:
            connect_address = resolve_nps_eventlog_endpoint(args.server, connect_address=connect_address)
        elif credential_mode != "process":
            connect_address = resolve_ad_source_endpoint(args.server, connect_address=args.connect_address)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 74
    use_record_id_cursor = str(args.use_record_id_cursor).lower() not in {"0", "false", "no", "off"}
    collect_message = str(args.collect_message).lower() not in {"0", "false", "no", "off"}
    selected_channels = [item.strip() for item in (args.channels or "").split(",") if item.strip()]
    channel_limits = _load_json_object(args.channel_limits_json)
    channel_timeouts = _load_json_object(args.channel_timeouts_json)
    try:
        if args.nps_continuous:
            if args.source_continuity_canary or args.channel_limits_json is not None or args.channel_timeouts_json is not None:
                raise ValueError("continuous_nps_conflicting_mode_or_overrides")
            bounded_selection = validate_continuous_nps_admission(
                event_ids_json=args.event_ids_json, start_time_utc=args.start_time_utc,
                end_time_utc=args.end_time_utc, requested_backend=args.collector_backend,
                server=args.server, connect_address=connect_address, channels=tuple(selected_channels),
                archive=args.archive, use_record_id_cursor=use_record_id_cursor,
                adaptive_state_mode=args.adaptive_state_mode, collect_message=collect_message,
                max_events_per_channel=args.max_events_per_channel,
                channel_timeout_seconds=args.channel_timeout_seconds,
                command_timeout_seconds=args.command_timeout_seconds,
                ad_source_credential_mode=credential_mode, allow_source_contact=True,
            )
        elif args.source_continuity_canary:
            if args.channel_limits_json is not None or args.channel_timeouts_json is not None:
                raise ValueError("source_continuity_canary_channel_overrides_forbidden")
            bounded_selection = validate_bounded_source_continuity_canary_admission(
                event_ids_json=args.event_ids_json,
                start_time_utc=args.start_time_utc,
                end_time_utc=args.end_time_utc,
                requested_backend=args.collector_backend,
                channels=tuple(selected_channels),
                archive=args.archive,
                use_record_id_cursor=use_record_id_cursor,
                adaptive_state_mode=args.adaptive_state_mode,
                collect_message=collect_message,
                max_events_per_channel=args.max_events_per_channel,
                channel_timeout_seconds=args.channel_timeout_seconds,
                command_timeout_seconds=args.command_timeout_seconds,
            )
        else:
            bounded_selection = validate_bounded_nps_admission(
                event_ids_json=args.event_ids_json,
                start_time_utc=args.start_time_utc,
                end_time_utc=args.end_time_utc,
                requested_backend=args.collector_backend,
                server=args.server,
                connect_address=connect_address,
                channels=tuple(selected_channels),
                archive=args.archive,
                use_record_id_cursor=use_record_id_cursor,
                adaptive_state_mode=args.adaptive_state_mode,
                collect_message=collect_message,
                max_events_per_channel=args.max_events_per_channel,
                channel_timeout_seconds=args.channel_timeout_seconds,
                command_timeout_seconds=args.command_timeout_seconds,
                route_loader=load_radius_collection_routes,
            )
    except (RuntimeError, ValueError) as exc:
        admission_name = (
            "source_continuity_canary_admission"
            if args.source_continuity_canary
            else "bounded_nps_admission"
        )
        print(f"{admission_name}_failed: {exc}", file=sys.stderr)
        return 64
    try:
        collector_backend, backend_reason = choose_collector_backend(args.collector_backend)
    except CollectorBackendUnavailableError as exc:
        print(f"collector_backend_unavailable: {exc}", file=sys.stderr)
        log_event(
            "runner", "collector_backend_unavailable",
            "No collector backend available; automatic PowerShell fallback was removed -- "
            "pass --collector-backend powershell explicitly if this host genuinely needs it.",
            level=logging.ERROR, server=args.server, error=str(exc),
        )
        return 65
    trace_id = f"job-{args.job_id or 'manual'}-{args.server}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    pipeline_started_ms = monotonic_ms()
    log_event("runner", "collection_pipeline_started", "DC collection pipeline started.", server=args.server, channels=selected_channels or None, channel_limits=channel_limits or None, collection_mode=args.collection_mode, collect_message=collect_message, collector_backend=collector_backend, backend_reason=backend_reason, adaptive_state_mode=args.adaptive_state_mode, trace_id=trace_id)

    target_db_backend = runtime_db_backend()
    if target_db_backend != "postgres":
        print(
            f"non_postgres_backend_not_supported: {target_db_backend}",
            file=sys.stderr,
        )
        log_event(
            "runner", "collector_db_backend_not_supported",
            "Collection imports into PostgreSQL only; a non-postgres backend value is rejected.",
            level=logging.ERROR, server=args.server, requested_backend=target_db_backend,
        )
        return 66
    domain_fqdn: str | None = None
    forest_name: str | None = None
    if target_db_backend == "postgres":
        try:
            domain_fqdn, forest_name = resolve_postgres_source_identity(
                connect_address=connect_address,
                domain_override=args.domain,
                forest_override=args.forest,
            )
        except ValueError as exc:
            print(f"postgres_source_identity_invalid: {exc}", file=sys.stderr)
            return 67
    collection_start_utc = (
        bounded_selection.start_time_utc
        if bounded_selection is not None
        else args.start_time_utc
    )
    channel_start_times: dict[str, str] = {}
    channel_after_record_ids: dict[str, int] = {}
    channel_cursor_generations: dict[str, str] = {}
    if args.archive:
        from server.sli.core.postgres_runtime_pipeline import get_collection_plan_for_server_pg

        channel_plan = get_collection_plan_for_server_pg(args.server, channels=selected_channels or None)
        archive_plan_backend = "postgres"
        channel_plan = apply_collection_not_before_floor(
            channel_plan,
            os.environ.get("ADLOG_COLLECTION_NOT_BEFORE_UTC"),
        )
        channel_start_times = {channel: str(item["start_time_utc"]) for channel, item in channel_plan.items()}
        channel_after_record_ids = {
            channel: int(item["after_record_id"])
            for channel, item in channel_plan.items()
            if use_record_id_cursor and item.get("after_record_id") is not None
        }
        channel_cursor_generations = {
            channel: str(item["channel_generation_identity"])
            for channel, item in channel_plan.items()
            if use_record_id_cursor and item.get("channel_generation_identity")
        }
        if args.nps_continuous and (
            ("Security" in channel_after_record_ids)
            != ("Security" in channel_cursor_generations)
        ):
            # A record ID without its observed generation cannot safely resume
            # the filtered NPS cursor.  Keep the canonical archive start from
            # the plan and make the child perform an explicit time-window cycle;
            # do not manufacture a generation identity.
            channel_after_record_ids.pop("Security", None)
            channel_cursor_generations.pop("Security", None)
        collection_start_utc = min(channel_start_times.values()) if channel_start_times else None
        print(f"Archive plan backend for {args.server}: {archive_plan_backend}")
        print(f"Archive collection start UTC for {args.server}: {collection_start_utc}")
        print("Archive channel starts:", json.dumps(channel_start_times, ensure_ascii=False, sort_keys=True))
        print("Archive channel record IDs:", json.dumps(channel_after_record_ids, ensure_ascii=False, sort_keys=True))
    if connect_address != args.server:
        print(f"Collection connect address for {args.server}: {connect_address}")

    def build_collect_command(selected_backend: str) -> list[str]:
        channels = tuple(selected_channels) or (
            "Security", "System", "Directory Service",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational", "DNS Server",
        )
        return build_windows_eventlog_command(WindowsEventLogRequest(
            backend=selected_backend,
            python_executable=sys.executable,
            python_script=PY_COLLECT_SCRIPT,
            powershell_script=COLLECT_SCRIPT,
            computer_name=connect_address,
            source_name=args.server,
            hours=args.hours,
            max_events_per_channel=args.max_events_per_channel,
            channel_timeout_seconds=args.channel_timeout_seconds,
            output_root=args.raw_root,
            channels=channels,
            collection_mode=args.collection_mode,
            collect_message=collect_message,
            channel_limits=channel_limits,
            channel_timeouts=channel_timeouts,
            start_time_utc=collection_start_utc,
            channel_start_times=channel_start_times,
            channel_after_record_ids=channel_after_record_ids,
            channel_cursor_generations=channel_cursor_generations,
            event_ids=bounded_selection.event_ids if bounded_selection is not None else (),
            end_time_utc=bounded_selection.end_time_utc if bounded_selection is not None else None,
            source_continuity_canary=args.source_continuity_canary,
            ad_source_credential_mode=credential_mode,
            **({"nps_continuous": True} if args.nps_continuous else {}),
        ))

    def run_collection_backend(selected_backend: str, selected_reason: str) -> tuple[subprocess.CompletedProcess[str], str, str]:
        effective_channels = tuple(selected_channels) or (
            "Security", "System", "Directory Service",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-TaskScheduler/Operational", "DNS Server",
        )
        source_packs = validate_adapter_for_channels(adapter_id_for_backend(selected_backend), effective_channels)
        log_event("runner", "collector_backend_selected", "Collector backend selected.", server=args.server, collector_backend=selected_backend, backend_reason=selected_reason, source_packs=[item["pack_id"] for item in source_packs], source_adapter=adapter_id_for_backend(selected_backend), trace_id=trace_id)
        result = run_command(build_collect_command(selected_backend), timeout_seconds=args.command_timeout_seconds)
        log_performance_stage(
            "collection_backend_command",
            trace_id=trace_id,
            job_id=args.job_id,
            server=args.server,
            backend=selected_backend,
            status="completed" if result.returncode == 0 else "failed",
            duration_ms=getattr(result, "duration_ms", None),
            error=(result.stderr or "")[-500:] if result.returncode != 0 else None,
        )
        return result, selected_backend, selected_reason

    def load_collection_result(collection_result: subprocess.CompletedProcess[str], selected_backend: str, selected_reason: str) -> tuple[Path, dict, dict] | tuple[None, None, None]:
        output = find_output_dir(collection_result.stdout)
        if output is None or not output.exists():
            print("Unable to find collection output folder.", file=sys.stderr)
            log_internal_error("runner", "collection_output_missing", "Unable to find collection output folder.", server=args.server, collector_backend=selected_backend, backend_reason=selected_reason, exit_code=collection_result.returncode, stdout_tail=(collection_result.stdout or "")[-2000:], stderr_tail=(collection_result.stderr or "")[-2000:])
            return None, None, None
        summary_file = output / "collection-summary.json"
        if collection_result.returncode != 0 and not summary_file.exists():
            print("Collection failed before collection-summary.json was created.", file=sys.stderr)
            return None, None, None
        loaded_summary = load_summary(output)
        loaded_summary["collector_backend"] = selected_backend
        loaded_summary["backend_reason"] = selected_reason
        loaded_summary["source_adapter"] = adapter_id_for_backend(selected_backend)
        loaded_summary["source_packs"] = source_pack_metadata_for_channels(
            [str(item.get("channel") or "") for item in loaded_summary.get("channels") or []]
        )
        for channel_item in loaded_summary.get("channels") or []:
            channel_item.setdefault("collector_backend", selected_backend)
            channel_item.setdefault("backend_reason", selected_reason)
        try:
            summary_file.write_text(json.dumps(loaded_summary, ensure_ascii=False, indent=2), encoding="utf-8")
        except OSError:
            pass
        log_channel_summaries(args.server, output, loaded_summary, phase="collection")
        for channel_item in loaded_summary.get("channels") or []:
            if channel_item.get("cursor_fallback_reason"):
                log_event(
                    "runner",
                    "record_id_cursor_fallback",
                    "EventRecordID cursor fallback was used for a channel.",
                    server=args.server,
                    channel=channel_item.get("channel"),
                    cursor_strategy=channel_item.get("cursor_strategy"),
                    cursor_fallback_reason=channel_item.get("cursor_fallback_reason"),
                    latest_available_record_id=channel_item.get("latest_available_record_id"),
                )
        loaded_status = summarize_channel_status(loaded_summary)
        print("Collection channel status:", json.dumps(loaded_status, ensure_ascii=False))
        log_event(
            "runner",
            "collection_summary_loaded",
            "Collection summary loaded.",
            server=args.server,
            status="partial" if loaded_status["partial_failed"] else "completed",
            count=loaded_status["events_collected"],
            collector_backend=selected_backend,
            backend_reason=selected_reason,
            source_packs=[item["pack_id"] for item in loaded_summary["source_packs"]],
            source_adapter=loaded_summary["source_adapter"],
        )
        return output, loaded_summary, loaded_status

    collection, collector_backend, backend_reason = run_collection_backend(collector_backend, backend_reason)
    output_dir, summary, channel_status = load_collection_result(collection, collector_backend, backend_reason)
    if output_dir is None:
        return collection.returncode if collection.returncode != 0 else 2

    if channel_status.get("terminal_block"):
        marker = write_collection_block_marker(output_dir, summary, channel_status, server=args.server)
        if target_db_backend == "postgres":
            try:
                from server.sli.sources.collection_runtime_block import activate_collection_block

                activate_collection_block(
                    reason_code=str(channel_status.get("failure_code") or "collection_non_retryable"),
                    operator_action=str(summary.get("operator_action") or (
                        "Восстановите Windows-контекст процесса сбора и выполните явную контрольную проверку."
                    )),
                    source_job_id=args.job_id,
                    source_server=args.server,
                    evidence={
                        "failure_code": channel_status.get("failure_code"),
                        "failure_scope": "worker_identity",
                        "collector_backend": collector_backend,
                        "marker": str(marker),
                    },
                )
            except Exception as exc:
                log_internal_error(
                    "runner", "collection_block_persist_failed",
                    "Collection remains blocked locally, but durable circuit-breaker persistence failed.",
                    exc=exc, server=args.server, marker=str(marker),
                )
        print(
            "Collection blocked before backend fallback/import/cursor update: "
            f"{channel_status.get('failure_code')} ({marker})",
            file=sys.stderr,
        )
        log_event(
            "runner", "collection_blocked_pre_import",
            "Collection stopped before fallback and import because operator recovery is required.",
            level=logging.ERROR, server=args.server, status="blocked",
            error=channel_status.get("failure_code"), marker=str(marker),
        )
        return 74

    if channel_status["all_failed"]:
        print("All collection channels failed; import is skipped to avoid a false successful cycle.", file=sys.stderr)
        log_event("runner", "collection_all_failed", "All collection channels failed; import skipped.", server=args.server, status="failed", error="all_channels_failed", collector_backend=collector_backend, backend_reason=backend_reason)
        return collection.returncode if collection.returncode != 0 else 3

    batch_manifest: dict[str, object] | None = None
    lifecycle_ready = False
    lifecycle_api: object | None = None
    if target_db_backend == "postgres":
        try:
            from server.sli.core import postgres_runtime_pipeline as lifecycle_api

            batch_manifest = raw_batch_manifest(
                output_dir=output_dir, raw_root=args.raw_root, server=args.server,
            )
            lifecycle_api.begin_raw_batch_lifecycle_pg(
                batch_identity=str(batch_manifest["batch_identity"]),
                manifest_hash=str(batch_manifest["manifest_hash"]),
                server=args.server,
                raw_path=str(batch_manifest["raw_path"]),
                trace_id=trace_id,
                expected_channels=len(summary.get("channels") or []),
            )
            lifecycle_ready = True
        except Exception as exc:
            log_internal_error(
                "runner", "raw_batch_lifecycle_begin_failed",
                "Raw batch will be retained because lifecycle journaling is unavailable.",
                exc=exc, server=args.server, output_dir=str(output_dir),
            )

    imported, import_queue_wait_ms, import_retry_count_value, importer_backend = run_import_for_backend(
        target_backend=target_db_backend,
        output_dir=output_dir,
        server=args.server,
        trace_id=trace_id,
        job_id=args.job_id,
        collector_backend=collector_backend,
        domain_fqdn=domain_fqdn,
        forest_name=forest_name,
    )
    print(imported.stdout)
    if imported.returncode != 0:
        if lifecycle_ready and batch_manifest is not None and lifecycle_api is not None:
            try:
                lifecycle_api.record_raw_batch_import_outcome_pg(
                    batch_identity=str(batch_manifest["batch_identity"]),
                    manifest_hash=str(batch_manifest["manifest_hash"]),
                    outcome="failed",
                    error=(imported.stderr or imported.stdout or "")[-2000:],
                )
            except Exception as exc:
                log_internal_error(
                    "runner", "raw_batch_import_failure_journal_failed",
                    "Raw batch retained; import failure journal readback failed.",
                    exc=exc, server=args.server,
                )
        log_event("runner", "import_failed", "Importer returned non-zero code.", server=args.server, exit_code=imported.returncode, stdout_tail=(imported.stdout or "")[-2000:], stderr_tail=(imported.stderr or "")[-2000:])
        return imported.returncode

    if lifecycle_ready and batch_manifest is not None and lifecycle_api is not None:
        try:
            lifecycle_api.record_raw_batch_import_outcome_pg(
                batch_identity=str(batch_manifest["batch_identity"]),
                manifest_hash=str(batch_manifest["manifest_hash"]),
                outcome="succeeded",
            )
        except Exception as exc:
            lifecycle_ready = False
            log_internal_error(
                "runner", "raw_batch_import_success_journal_failed",
                "Raw batch retained; durable import success readback failed.",
                exc=exc, server=args.server,
            )

    import_stats = parse_import_stats(imported.stdout or "")
    import_profile = parse_import_profile(imported.stdout or "")
    if importer_backend == "postgres" and not import_profile:
        profile_path = output_dir / "postgres-import-profile.json"
        try:
            loaded_profile = json.loads(profile_path.read_text(encoding="utf-8"))
            import_profile = loaded_profile if isinstance(loaded_profile, dict) else {}
        except (OSError, json.JSONDecodeError):
            import_profile = {}

    if importer_backend == "postgres":
        from server.sli.core.postgres_runtime_pipeline import (
            record_collector_channel_runs_pg,
            record_collector_stage_metrics_pg,
            update_collection_state_from_summary_pg,
        )

        if args.archive and collection_start_utc:
            archive_started_ms = monotonic_ms()
            update_collection_state_from_summary_pg(
                server=args.server,
                collection_start_utc=collection_start_utc,
                summary=summary,
                import_stats=import_stats,
                job_id=args.job_id,
                trace_id=trace_id,
                **({"require_query_exhaustion": True} if args.nps_continuous else {}),
            )
            if lifecycle_ready and batch_manifest is not None and lifecycle_api is not None:
                try:
                    lifecycle_api.record_raw_batch_cursor_outcome_pg(
                        batch_identity=str(batch_manifest["batch_identity"]),
                        manifest_hash=str(batch_manifest["manifest_hash"]),
                        server=args.server,
                        trace_id=trace_id,
                        summary=summary,
                    )
                except Exception as exc:
                    lifecycle_ready = False
                    log_internal_error(
                        "runner", "raw_batch_cursor_journal_failed",
                        "Raw batch retained; durable cursor outcome readback failed.",
                        exc=exc, server=args.server,
                    )
            log_performance_stage("archive_state_update_postgres", trace_id=trace_id, job_id=args.job_id, server=args.server, backend=collector_backend, started_ms=archive_started_ms)
            print(f"PostgreSQL archive state updated for {args.server}.")
        history_started_ms = monotonic_ms()
        record_collector_channel_runs_pg(
            server=args.server,
            summary=summary,
            import_stats=import_stats,
            job_id=args.job_id,
            import_duration_ms=getattr(imported, "duration_ms", None),
            import_queue_wait_ms=import_queue_wait_ms,
            import_retry_count=import_retry_count_value,
            report_duration_ms=None,
            adaptive_state_mode=args.adaptive_state_mode,
        )
        record_collector_stage_metrics_pg(
            server=args.server,
            summary=summary,
            import_duration_ms=getattr(imported, "duration_ms", None),
            import_profile=import_profile,
            job_id=args.job_id,
        )
        log_performance_stage("collector_history_record_postgres", trace_id=trace_id, job_id=args.job_id, server=args.server, backend=collector_backend, started_ms=history_started_ms)

    if (
        target_db_backend == "postgres"
        and lifecycle_ready
        and batch_manifest is not None
        and lifecycle_api is not None
        and cleanup_confirmed_raw_output(
            output_dir=output_dir,
            raw_root=args.raw_root,
            server=args.server,
            archive=args.archive,
            batch_identity=str(batch_manifest["batch_identity"]),
            manifest_hash=str(batch_manifest["manifest_hash"]),
            authorize_cleanup=lifecycle_api.authorize_raw_batch_cleanup_pg,
            record_cleanup_outcome=lifecycle_api.record_raw_batch_cleanup_outcome_pg,
        )
    ):
        print(f"Deleted confirmed raw batch: {output_dir}")

    if collection.returncode != 0:
        print("Collection process returned a non-zero code after importing successful channels.", file=sys.stderr)
        log_event("runner", "collection_non_zero_after_import", "Collection returned non-zero after successful-channel import.", server=args.server, exit_code=collection.returncode, error="collection_returned_non_zero")
        return 4
    if channel_status["partial_failed"]:
        print("Collection completed with failed channels; data was imported only from successful channels.", file=sys.stderr)
        log_event("runner", "collection_partial_failed", "Collection completed with failed channels; successful channels imported.", server=args.server, status="partial", error="partial_failed")
        return 4
    pipeline_status = "completed"
    if channel_status.get("partial_warning"):
        pipeline_status = "partial"
        print("Collection completed with partial timeout channels; partial data was imported and watermarks/history were updated.")
        log_event("runner", "collection_partial_warning", "Collection completed with partial timeout channels; partial data imported.", server=args.server, status="partial_warning", warnings=channel_status.get("warnings"))
    log_performance_stage("dc_pipeline_total", trace_id=trace_id, job_id=args.job_id, server=args.server, backend=collector_backend, started_ms=pipeline_started_ms, events_count=channel_status.get("events_collected"))
    log_event("runner", "collection_pipeline_completed", "DC collection pipeline completed.", server=args.server, status=pipeline_status, collector_backend=collector_backend, trace_id=trace_id)
    print("collection_result=" + json.dumps({"status": pipeline_status}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    import sys as _sys

    _sys.modules.setdefault("scripts.run_dc_log_pilot", _sys.modules[__name__])
from scripts.run_dc_log_pilot_admission import (  # noqa: F401
    validate_bounded_nps_admission,
    validate_bounded_source_continuity_canary_admission,
    apply_collection_not_before_floor,
    CollectorBackendUnavailableError,
    python_collector_available,
    choose_collector_backend,
    append_powershell_bool_param,
)

from scripts.run_dc_log_pilot_process import (  # noqa: F401
    _terminate_process_tree,
    run_command,
)

from scripts.run_dc_log_pilot_summary import (  # noqa: F401
    find_output_dir,
    load_summary,
    summarize_channel_status,
    write_collection_block_marker,
    channel_file_stats,
    log_channel_summaries,
    _load_json_object,
    parse_import_stats,
    parse_import_profile,
)

from scripts.run_dc_log_pilot_import import (  # noqa: F401
    runtime_db_backend,
    postgres_import_timeout_seconds,
    raw_batch_manifest,
    cleanup_confirmed_raw_output,
    _normalize_source_fqdn,
    resolve_postgres_source_identity,
)

if __name__ == "__main__":
    raise SystemExit(main())
