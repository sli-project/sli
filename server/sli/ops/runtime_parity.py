from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.core.paths import ROOT

# Modules in this set are runtime surfaces that must never open SQLite directly.
PG_ONLY_RUNTIME_MODULES = (
    "server/api/http_server.py",
    "server/sli/events/event_search.py",
    "server/sli/events/event_details.py",
    "server/sli/entities/entity_details.py",
    "server/sli/semantic/investigation.py",
    "server/sli/access/role_views.py",
    "server/sli/events/security_events_monitor.py",
    "server/sli/reporting/dashboard_snapshot.py",
)

# PostgreSQL-backed modules: these guards and entry points must stay present.
DUAL_BACKEND_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "server/sli/ai/ai_reports.py": ("is_postgres_runtime_db", "query_rows", "postgres_runtime_pipeline import connect"),
    "server/sli/semantic/findings.py": ("is_postgres_runtime_db", "_refresh_findings_postgres", "update_finding_lifecycle"),
    "server/sli/sources/collector_health.py": ("is_postgres_runtime_db", "_db_history_stats_pg", "get_post_collection_overview", "cursor_audit"),
    "server/sli/core/postgres_runtime_pipeline.py": ("collector_cursor_audit", "record_id_rollback_detected", "get_cursor_audit_overview_pg"),
    "server/sli/sources/collector_adaptive.py": ("is_postgres_runtime_db", "get_adaptive_plan_state_pg"),
    "server/sli/core/database.py": ("is_postgres_runtime_db", "postgres_runtime_pipeline import connect"),
    "server/sli/reporting/dashboard_fast.py": ("is_postgres_runtime_db", "pg_stat_user_tables", "raw_log_files", "bounded recent"),
    "server/sli/sources/postgres_import_queue.py": ("ADLOG_POSTGRES_IMPORT_QUEUE_TIMEOUT_SECONDS", "msvcrt.locking", "fcntl.flock"),
    "scripts/run_dc_log_pilot.py": ("postgres_import_queue", "import_queue_wait", 'return imported, queue_wait_ms, 0, "postgres"'),
    "server/jobs/collector.py": ("_runtime_db_backend", "query_rows"),
}

ROUTE_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "server/api/http_server.py": (
        '"bootstrap_skipped"',
    ),
    "server/api/routes/workspace.py": (
        'path == "/api/dashboard/snapshot"',
    ),
    "server/api/routes/ai.py": (
        'path == "/api/ai/runs"',
    ),
    "server/api/routes/diagnostics.py": (
        'path == "/api/storage/health"',
    ),
    "server/api/routes/investigations.py": (
        'path == "/api/investigation/workspace"',
    ),
    "server/api/routes/findings.py": (
        'path == "/api/findings"',
        'path.startswith("/api/findings/") and path.endswith("/status")',
    ),
}


def _read(root: Path, rel: str) -> str:
    path = root / rel
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def audit_pg_runtime_parity(root: Path = ROOT) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    sqlite_inventory: list[dict[str, Any]] = []

    for rel in PG_ONLY_RUNTIME_MODULES:
        text = _read(root, rel)
        missing = not bool(text)
        direct_sqlite = "sqlite3.connect" in text
        status = "ok" if not missing and not direct_sqlite else "failed"
        if missing:
            failures.append(f"missing runtime module: {rel}")
        if direct_sqlite:
            failures.append(f"direct SQLite access in PG-only runtime module: {rel}")
        checks.append({"surface": rel, "kind": "pg_only", "status": status, "direct_sqlite": direct_sqlite})

    for rel, markers in DUAL_BACKEND_REQUIREMENTS.items():
        text = _read(root, rel)
        missing_markers = [marker for marker in markers if marker not in text]
        status = "ok" if text and not missing_markers else "failed"
        if not text:
            failures.append(f"missing dual-backend module: {rel}")
        if missing_markers:
            failures.append(f"missing PostgreSQL guard markers in {rel}: {', '.join(missing_markers)}")
        checks.append({"surface": rel, "kind": "dual_backend", "status": status, "missing_markers": missing_markers})

    for rel, markers in ROUTE_REQUIREMENTS.items():
        text = _read(root, rel)
        missing_markers = [marker for marker in markers if marker not in text]
        status = "ok" if text and not missing_markers else "failed"
        if missing_markers:
            failures.append(f"missing runtime route/boundary markers in {rel}: {', '.join(missing_markers)}")
        checks.append({"surface": rel, "kind": "routes", "status": status, "missing_markers": missing_markers})

    scan_paths = []
    for scan_root, pattern in ((root / "server" / "app", "*.py"), (root / "server" / "sli", "**/*.py")):
        if scan_root.is_dir():
            scan_paths.extend(sorted(scan_root.glob(pattern)))
    if scan_paths:
        for path in scan_paths:
            text = path.read_text(encoding="utf-8", errors="replace")
            if path.name == "runtime_parity.py" or "sqlite3.connect" not in text:
                continue
            rel = path.relative_to(root).as_posix()
            if rel in DUAL_BACKEND_REQUIREMENTS:
                classification = "dual_backend_guarded"
            elif rel in PG_ONLY_RUNTIME_MODULES:
                classification = "forbidden_runtime"
            else:
                classification = "sqlite_backend_or_maintenance"
            sqlite_inventory.append({"path": rel, "classification": classification, "connect_calls": text.count("sqlite3.connect")})

    return {
        "package_type": "PG_RUNTIME_PARITY_AUDIT",
        "status": "failed" if failures else "ok",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "failures": failures,
        "sqlite_inventory": sqlite_inventory,
        "principle": "PostgreSQL runtime paths must be PG-native or explicit; hidden SQLite fallback is forbidden.",
    }
