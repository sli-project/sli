"""Fail-closed replay of one retained, previously failed DC raw batch.

The controller deliberately reuses the pilot's import, lifecycle, cursor and
history owners.  It never contacts a DC, creates a collector job, or deletes
the retained JSONL files.
"""
from __future__ import annotations

import argparse
import json
import re
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_dc_log_pilot import (
    parse_import_profile,
    parse_import_stats,
    raw_batch_manifest,
    resolve_postgres_source_identity,
    run_import_for_backend,
)
from server.sli.core.postgres_runtime_pipeline import (
    connect,
    record_collector_channel_runs_pg,
    record_collector_stage_metrics_pg,
    record_raw_batch_cursor_outcome_pg,
    record_raw_batch_import_outcome_pg,
    update_collection_state_from_summary_pg,
)
from server.sli.ops.postgres_session_lock import session_advisory_lock


RAW_RELATIVE_ROOT = Path("data") / "raw" / "pilot"
SUMMARY_NAME = "collection-summary.json"
EXPECTED_CHANNELS = 6
MAX_BATCH_FILES = 16
MAX_SUMMARY_BYTES = 1024 * 1024
MAX_BATCH_BYTES = 512 * 1024 * 1024
PROCESS_LOCK_NAME = "ad_log_reports_runtime_collection_process"
WORKER_LOCK_NAME = "ad_log_reports_runtime_collection_worker"
CONFIRMATION_PREFIX = "replay-retained-dc-batch:"


@dataclass(frozen=True)
class PreparedBatch:
    output_dir: Path
    server: str
    trace_id: str
    job_id: int | None
    domain_fqdn: str
    forest_name: str
    collector_backend: str
    summary: dict[str, Any]
    batch_identity: str
    manifest_hash: str
    confirmation: str


def _is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def retained_batch_path(value: Path | str) -> Path:
    raw_root = ROOT / RAW_RELATIVE_ROOT
    raw_candidate = Path(value)
    if not raw_candidate.is_absolute():
        raw_candidate = ROOT / raw_candidate
    try:
        relative = raw_candidate.relative_to(raw_root)
    except ValueError as exc:
        raise RuntimeError("retained_batch_outside_pilot_root") from exc
    if len(relative.parts) != 1:
        raise RuntimeError("retained_batch_path_invalid")
    for path in (ROOT, ROOT / "data", ROOT / "data" / "raw", raw_root, raw_candidate):
        if _is_link_or_reparse(path):
            raise RuntimeError("retained_batch_link_or_reparse_forbidden")
    root = raw_root.resolve(strict=True)
    candidate = raw_candidate.resolve(strict=True)
    if candidate.parent != root or not candidate.is_dir():
        raise RuntimeError("retained_batch_path_invalid")
    entries = list(candidate.iterdir())
    if len(entries) > MAX_BATCH_FILES or any(_is_link_or_reparse(item) for item in entries):
        raise RuntimeError("retained_batch_contents_untrusted")
    if any(not item.is_file() for item in entries):
        raise RuntimeError("retained_batch_nested_content_forbidden")
    if sum(item.stat().st_size for item in entries) > MAX_BATCH_BYTES:
        raise RuntimeError("retained_batch_too_large")
    return candidate


def load_summary(output_dir: Path) -> dict[str, Any]:
    path = output_dir / SUMMARY_NAME
    if not path.is_file() or path.stat().st_size > MAX_SUMMARY_BYTES:
        raise RuntimeError("retained_summary_missing_or_unbounded")
    try:
        summary = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("retained_summary_invalid") from exc
    if not isinstance(summary, dict):
        raise RuntimeError("retained_summary_invalid")
    required = ("computer_name", "connect_address", "start_time_utc", "collector_backend", "channels")
    if any(not str(summary.get(name) or "").strip() for name in required[:-1]):
        raise RuntimeError("retained_summary_identity_missing")
    channels = summary.get("channels")
    if not isinstance(channels, list) or len(channels) != EXPECTED_CHANNELS:
        raise RuntimeError("retained_summary_channel_count_invalid")
    names = [str(item.get("channel") or "") for item in channels if isinstance(item, dict)]
    if len(names) != EXPECTED_CHANNELS or len(set(names)) != EXPECTED_CHANNELS:
        raise RuntimeError("retained_summary_channels_invalid")
    if any(str(item.get("status") or "") != "completed" for item in channels):
        raise RuntimeError("retained_summary_channels_incomplete")
    expected_files = {
        re.sub(r'[\\/:*?"<>| ]+', "_", name) + ".jsonl" for name in names
    }
    actual_files = {item.name for item in output_dir.iterdir() if item.suffix == ".jsonl"}
    if actual_files != expected_files:
        raise RuntimeError("retained_raw_channel_files_invalid")
    for item in channels:
        expected_path = output_dir / (re.sub(r'[\\/:*?"<>| ]+', "_", str(item["channel"])) + ".jsonl")
        if Path(str(item.get("file") or "")).resolve(strict=False) != expected_path.resolve():
            raise RuntimeError("retained_summary_file_provenance_invalid")
    return summary


def load_lifecycle(*, batch_identity: str) -> dict[str, Any]:
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                """select batch_identity,manifest_hash,server,raw_path,trace_id,
                          expected_channels,import_outcome,cursor_outcome,cleanup_outcome
                   from raw_batch_lifecycle where batch_identity=%s""",
                (batch_identity,),
            )
            rows = [dict(row) for row in cur.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("raw_batch_lifecycle_missing_or_ambiguous")
    return rows[0]


def catalog_identity(*, connect_address: str) -> tuple[str, str]:
    domain_fqdn, forest_name = resolve_postgres_source_identity(
        connect_address=connect_address, domain_override=None, forest_override=None,
    )
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute("set transaction read only")
            cur.execute(
                """select d.fqdn as domain_fqdn,f.name as forest_name
                   from domains d join forests f on f.id=d.forest_id
                   where lower(d.fqdn)=lower(%s) and lower(f.name)=lower(%s)
                   order by d.id""",
                (domain_fqdn, forest_name),
            )
            rows = [dict(row) for row in cur.fetchall()]
    if len(rows) != 1:
        raise RuntimeError("source_identity_catalog_not_exactly_one")
    row = rows[0]
    if str(row.get("domain_fqdn") or "").casefold() != domain_fqdn.casefold() or str(row.get("forest_name") or "").casefold() != forest_name.casefold():
        raise RuntimeError("source_identity_catalog_mismatch")
    return domain_fqdn, forest_name


def _validate_lifecycle(*, lifecycle: dict[str, Any], manifest: dict[str, object], server: str) -> str:
    exact = (
        lifecycle.get("batch_identity") == manifest["batch_identity"]
        and lifecycle.get("manifest_hash") == manifest["manifest_hash"]
        and lifecycle.get("server") == server
        and lifecycle.get("raw_path") == manifest["raw_path"]
        and int(lifecycle.get("expected_channels") or 0) == EXPECTED_CHANNELS
    )
    if not exact:
        raise RuntimeError("raw_batch_lifecycle_manifest_mismatch")
    trace_id = str(lifecycle.get("trace_id") or "").strip()
    if not trace_id:
        raise RuntimeError("raw_batch_lifecycle_trace_missing")
    if lifecycle.get("import_outcome") != "failed":
        raise RuntimeError("raw_batch_lifecycle_not_failed")
    if lifecycle.get("cursor_outcome") not in {"unknown", "not_committed"} or lifecycle.get("cleanup_outcome") != "retained":
        raise RuntimeError("raw_batch_lifecycle_retry_state_invalid")
    return trace_id


def prepare(batch: Path | str) -> PreparedBatch:
    output_dir = retained_batch_path(batch)
    summary = load_summary(output_dir)
    server = str(summary["computer_name"]).strip()
    manifest = raw_batch_manifest(
        output_dir=output_dir, raw_root=(ROOT / RAW_RELATIVE_ROOT), server=server,
    )
    lifecycle = load_lifecycle(batch_identity=str(manifest["batch_identity"]))
    trace_id = _validate_lifecycle(lifecycle=lifecycle, manifest=manifest, server=server)
    domain_fqdn, forest_name = catalog_identity(connect_address=str(summary["connect_address"]))
    return PreparedBatch(
        output_dir=output_dir, server=server, trace_id=trace_id, job_id=None,
        domain_fqdn=domain_fqdn, forest_name=forest_name,
        collector_backend=str(summary["collector_backend"]).strip(), summary=summary,
        batch_identity=str(manifest["batch_identity"]), manifest_hash=str(manifest["manifest_hash"]),
        confirmation=CONFIRMATION_PREFIX + str(manifest["manifest_hash"]),
    )


def revalidate_prepared(prepared: PreparedBatch) -> None:
    current = prepare(prepared.output_dir)
    if current != prepared:
        raise RuntimeError("retained_batch_changed_since_plan")


def _import_profile(*, output: str, output_dir: Path) -> dict[str, Any]:
    profile = parse_import_profile(output)
    if profile:
        return profile
    path = output_dir / "postgres-import-profile.json"
    try:
        if path.stat().st_size > MAX_SUMMARY_BYTES:
            raise OSError("profile too large")
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


@contextmanager
def held_collection_locks() -> Iterator[None]:
    with session_advisory_lock(connect, PROCESS_LOCK_NAME) as process_acquired:
        if not process_acquired:
            raise RuntimeError("collection_process_lock_busy")
        with session_advisory_lock(connect, WORKER_LOCK_NAME) as worker_acquired:
            if not worker_acquired:
                raise RuntimeError("collection_worker_lock_busy")
            yield


def apply_prepared(prepared: PreparedBatch) -> None:
    with held_collection_locks():
        revalidate_prepared(prepared)
        imported, queue_wait_ms, retry_count, backend = run_import_for_backend(
            target_backend="postgres", output_dir=prepared.output_dir, server=prepared.server,
            trace_id=prepared.trace_id, job_id=prepared.job_id,
            collector_backend=prepared.collector_backend, domain_fqdn=prepared.domain_fqdn,
            forest_name=prepared.forest_name,
        )
        if imported.returncode != 0:
            record_raw_batch_import_outcome_pg(
                batch_identity=prepared.batch_identity, manifest_hash=prepared.manifest_hash,
                outcome="failed", error=(imported.stderr or imported.stdout or "")[-2000:],
            )
            raise RuntimeError(f"retained_batch_import_failed:{imported.returncode}")
        record_raw_batch_import_outcome_pg(
            batch_identity=prepared.batch_identity, manifest_hash=prepared.manifest_hash,
            outcome="succeeded",
        )
        import_stats = parse_import_stats(imported.stdout or "")
        import_profile = _import_profile(output=imported.stdout or "", output_dir=prepared.output_dir)
        update_collection_state_from_summary_pg(
            server=prepared.server, collection_start_utc=str(prepared.summary["start_time_utc"]),
            summary=prepared.summary, import_stats=import_stats, job_id=None, trace_id=prepared.trace_id,
        )
        cursor_row = record_raw_batch_cursor_outcome_pg(
            batch_identity=prepared.batch_identity, manifest_hash=prepared.manifest_hash,
            server=prepared.server, trace_id=prepared.trace_id, summary=prepared.summary,
        )
        if (
            str(cursor_row.get("cursor_outcome") or "") != "committed"
            or int(cursor_row.get("committed_channels") or 0) != EXPECTED_CHANNELS
        ):
            raise RuntimeError("retained_batch_cursor_pending")
        record_collector_channel_runs_pg(
            server=prepared.server, summary=prepared.summary, import_stats=import_stats,
            job_id=None, import_duration_ms=getattr(imported, "duration_ms", None),
            import_queue_wait_ms=queue_wait_ms, import_retry_count=retry_count,
            report_duration_ms=None, adaptive_state_mode="update",
        )
        record_collector_stage_metrics_pg(
            server=prepared.server, summary=prepared.summary,
            import_duration_ms=getattr(imported, "duration_ms", None),
            import_profile=import_profile, job_id=None,
        )


def run(*, action: str, batch: Path | str, confirmation: str | None = None) -> PreparedBatch:
    if action not in {"plan", "apply"}:
        raise RuntimeError("action_invalid")
    prepared = prepare(batch)
    if action == "plan":
        return prepared
    if confirmation != prepared.confirmation:
        raise RuntimeError("confirmation_invalid")
    apply_prepared(prepared)
    return prepared


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("batch", type=Path, help="retained batch directly below data/raw/pilot")
    parser.add_argument("--action", choices=("plan", "apply"), default="plan")
    parser.add_argument("--confirm")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    args = parser.parse_args()
    try:
        if args.load_supervisor_environment:
            from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment
            load_supervisor_environment(override_existing=True)
        prepared = run(action=args.action, batch=args.batch, confirmation=args.confirm)
    except (OSError, RuntimeError, ValueError) as exc:
        code = str(exc)
        if not re.fullmatch(r"[a-z0-9_:-]{1,120}", code):
            code = "replay_retained_dc_batch_failed"
        print(json.dumps({"status": "failed", "error_code": code}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps({
        "action": args.action, "server": prepared.server, "batch_identity": prepared.batch_identity,
        "manifest_hash": prepared.manifest_hash, "trace_id": prepared.trace_id,
        "confirmation": prepared.confirmation if args.action == "plan" else None,
        "raw_retained": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
