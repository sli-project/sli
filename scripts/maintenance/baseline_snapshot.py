#!/usr/bin/env python3
"""Produce a compact stable-baseline snapshot for Stage 0.

The snapshot is read-only. It does not collect AD/DC data and does not mutate the
project database. It is meant to make the current stable point explicit before
larger roadmap work continues.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (  # noqa: E402
    DATA_DIR,
    LOG_DIR,
    assess_recent_internal_errors,
    basic_project_snapshot,
    dir_size_report,
    fmt_bytes,
    run_command,
    tail_lines,
    timestamp,
    write_json,
    write_text,
)
from server.sli.core.database import active_backend, is_postgres_runtime_db  # noqa: E402
from server.sli.ops.version import get_release_metadata  # noqa: E402

CRITICAL_FILES = [
    "frontend/package.json",
    "server/jobs/collector.py",
    "scripts/collect/collect_windows_events.py",
    "scripts/run_dc_log_pilot.py",
    "scripts/import/import_event_jsonl_to_postgres.py",
    "server/sli/core/postgres_runtime_pipeline.py",
    "server/sli/sources/collector_adaptive.py",
    "server/sli/ops/performance.py",
    "server/sli/sources/collector_health.py",
    "server/sli/ops/system_health.py",
    "scripts/maintenance/release_check.py",
    "scripts/maintenance/http_copy_control.py",
    "scripts/maintenance/export_dev_handoff.py",
    "scripts/maintenance/collect_diagnostics.py",
    "scripts/maintenance/capture_report.py",
    "scripts/maintenance/apply_update.py",
    "tools/adlog-tool.ps1",
    "tools/ADLog-Toolkit.cmd",
    "docs/ADMIN_GUIDE.md",
]


def _db_schema_state() -> dict[str, Any]:
    if is_postgres_runtime_db():
        return _postgres_schema_state()
    return {
        "backend": active_backend(),
        "exists": False,
        "probe_error": {
            "error_type": "UnsupportedBackend",
            "error": "runtime database backend is not postgres; SQLite runtime is removed",
        },
    }


def _postgres_schema_state() -> dict[str, Any]:
    result: dict[str, Any] = {"backend": "postgres", "exists": False}
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("select current_database() as database_name, pg_database_size(current_database()) as size_bytes")
                row = cur.fetchone() or {}
                result["database_name"] = row.get("database_name")
                result["size_bytes"] = int(row.get("size_bytes") or 0)
                result["size_human"] = fmt_bytes(result["size_bytes"])
                cur.execute("select count(*) as count from information_schema.tables where table_schema = 'public'")
                row = cur.fetchone() or {}
                result["tables_count"] = int(row.get("count") or 0)
                cur.execute("select coalesce(max(version), 0) as version from schema_migrations")
                row = cur.fetchone() or {}
                result["schema_migration_version"] = int(row.get("version") or 0)
                event_relation = _physical_event_relation(cur)
                cur.execute(
                    "select greatest(reltuples, 0)::bigint as count from pg_class where oid = %s::regclass",
                    (event_relation,),
                )
                row = cur.fetchone() or {}
                result["events_total"] = int(row.get("count") or 0)
                result["events_total_estimated"] = True
                result["exists"] = True
    except Exception as exc:
        result["probe_error"] = {"error_type": type(exc).__name__, "error": str(exc)}
    return result


def _physical_event_relation(cur) -> str:
    cur.execute(
        """select to_regclass('public.events') is not null as v1_available,
                  to_regclass('public.events_v2_core') is not null as v2_available"""
    )
    row = cur.fetchone() or {}
    if row.get("v1_available"):
        return "events"
    if row.get("v2_available"):
        return "events_v2_core"
    raise RuntimeError("no physical event relation is available")


def build_baseline_snapshot(*, include_checks: bool = False) -> dict[str, Any]:
    critical = [{"path": item, "exists": (PROJECT_ROOT / item).exists()} for item in CRITICAL_FILES]
    missing = [item["path"] for item in critical if not item["exists"]]
    project_size = dir_size_report(PROJECT_ROOT, max_entries=5000, max_seconds=3.0, skip_dir_names={".venv", ".git", "__pycache__", ".pytest_cache", "bin", "obj"})
    data_size = dir_size_report(DATA_DIR, max_entries=5000, max_seconds=3.0)
    logs_size = dir_size_report(LOG_DIR, max_entries=2000, max_seconds=1.0)
    storage = {
        "mode": "fast_bounded",
        "project_root": str(PROJECT_ROOT),
        "project_size_bytes": project_size["bytes"],
        "project_size_human": project_size["human"],
        "project_size_truncated": project_size.get("truncated", False),
        "data_dir": str(DATA_DIR),
        "data_size_bytes": data_size["bytes"],
        "data_size_human": data_size["human"],
        "data_size_truncated": data_size.get("truncated", False),
        "logs_size_bytes": logs_size["bytes"],
        "logs_size_human": logs_size["human"],
        "details": {"project": project_size, "data": data_size, "logs": logs_size},
    }
    recent_internal_errors = assess_recent_internal_errors(
        tail_lines(LOG_DIR / "internal-errors.log", 50),
        activity_text=tail_lines(LOG_DIR / "adlog-monitor.log", 1000),
    )
    snapshot: dict[str, Any] = {
        "package_type": "BASELINE_SNAPSHOT",
        "status": "warn" if missing or recent_internal_errors["active"] else "ok",
        "reasons": ([f"missing critical files: {', '.join(missing)}"] if missing else [])
        + ([f"internal-errors.log has {recent_internal_errors['active_count']} active errors in the last 30 minutes"] if recent_internal_errors["active"] else []),
        "project_snapshot": basic_project_snapshot(),
        "release_metadata": get_release_metadata(PROJECT_ROOT),
        "active_backend": active_backend(),
        "critical_files": critical,
        "db_schema_state": _db_schema_state(),
        "storage": storage,
        "baseline_guarantees": [
            "read-only AD/DC collection model remains unchanged",
            "Python collector is primary when pywin32 is available; PowerShell remains fallback",
            "PostgreSQL is the primary runtime backend after cutover",
            "adaptive Security planning and state use the active runtime backend",
            "SQLite is not opened by PostgreSQL scheduler planning/status paths",
            "cursor/watermark must move only after successful import",
            "runtime data is excluded from developer handoff and release packages",
        ],
        "known_limits": [
            "post-collection analysis/report remains guarded by skip_report=true in the stable scheduler profile",
            "5k/10k collection is operator-controlled through SECURITY-SCALE-1 and is not enabled by package apply",
            "PostgreSQL findings refresh and full UI/report parity remain incomplete",
            "legacy SQLite, raw and backup storage still require an explicit lifecycle policy",
        ],
    }
    if include_checks:
        snapshot["checks"] = {
            "compileall": run_command([sys.executable, "-m", "compileall", "-q", "server", "sli_collect", "sli_agent", "scripts", "tests"], timeout=300),
            "release_check": run_command([sys.executable, "scripts/maintenance/release_check.py", "--json"], timeout=180),
        }
    return snapshot


def _markdown(snapshot: dict[str, Any]) -> str:
    metadata = snapshot.get("release_metadata") or {}
    db = snapshot.get("db_schema_state") or {}
    reasons = snapshot.get("reasons") or []
    return "\n".join([
        "# Current baseline snapshot",
        "",
        f"Status: **{snapshot.get('status')}**",
        f"Project version: `{metadata.get('project_version')}`",
        f"Baseline ID: `{metadata.get('baseline_id')}`",
        f"Build ID: `{metadata.get('build_id')}`",
        f"Source-declared maximum migration version: `{(metadata.get('schema') or {}).get('schema_declared_max_version')}`",
        f"Active runtime backend: `{snapshot.get('active_backend')}`",
        f"Runtime DB backend: `{db.get('backend', 'unknown')}`",
        f"Runtime DB available: `{db.get('exists')}`",
        f"Runtime DB size: `{db.get('size_human', 'unknown')}`",
        f"Runtime DB schema migration version: `{db.get('schema_migration_version', 'unknown')}`",
        "",
        "## Reasons",
        *(f"- {item}" for item in reasons),
        *( ["- none"] if not reasons else [] ),
        "",
        "## Baseline guarantees",
        *(f"- {item}" for item in snapshot.get('baseline_guarantees') or []),
        "",
        "## Known limits",
        *(f"- {item}" for item in snapshot.get('known_limits') or []),
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description="Write or print the current stable baseline snapshot.")
    parser.add_argument("--out", type=Path, help="Output directory for baseline_snapshot.json and baseline_snapshot.md")
    parser.add_argument("--include-checks", action="store_true", help="Run compileall/release_check and include their tails")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    args = parser.parse_args()
    snapshot = build_baseline_snapshot(include_checks=args.include_checks)
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        write_json(args.out / f"baseline_snapshot-{timestamp()}.json", snapshot)
        write_text(args.out / f"baseline_snapshot-{timestamp()}.md", _markdown(snapshot))
    if args.json or not args.out:
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
    return 0 if snapshot.get("status") in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
