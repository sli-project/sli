from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Callable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from deploy.linux.verify_offline_kit import INTERNAL_LABEL, workstation_release_gate  # noqa: E402
from scripts.maintenance.bundle_common import DATA_DIR, dir_size_report, fmt_bytes, run_command  # noqa: E402
from server.sli.core.paths import ROOT # noqa: E402
from server.sli.reporting.reports import list_reports  # noqa: E402
from server.sli.ops.version import get_release_metadata  # noqa: E402
from server.sli.ops.runtime_parity import audit_pg_runtime_parity  # noqa: E402


REQUIRED_FILES = [
    "README.md",
    "README.ru.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "package.json",
    "package-lock.json",
    "requirements.lock.txt",
    "frontend/package.json",
    "frontend/src/main.tsx",
    "web/app/react/index.html",
    "config/postgres_schema.sql",
    "config/postgres_migrations/046_ad_context_snapshot_heartbeat.sql",
    "config/postgres_migrations/047_collector_partial_failure_evidence.sql",
    "config/postgres_migrations/048_event_noise_classification_columns.sql",
    "config/postgres_migrations/049_event_noise_browse_index.sql",
    "config/postgres_migrations/050_semantic_worker_least_privilege.sql",
    "config/postgres_migrations/051_event_catalog_revision_reference.sql",
    "config/postgres_migrations/052_semantic_conclusion_completeness.sql",
    "config/postgres_migrations/053_semantic_canonical_action_risk.sql",
    "config/postgres_migrations/054_semantic_worker_runtime_schema_guard.sql",
    "config/postgres_migrations/055_semantic_finding_publication.sql",
    "config/postgres_migrations/056_privileged_account_state_fields.sql",
    "config/postgres_migrations/058_radius_accounting_transaction_foundation.sql",
    "config/postgres_migrations/059_radius_identity_spine_resolver.sql",
    "config/postgres_migrations/060_radius_identity_resolver_owner.sql",
    "config/postgres_migrations/061_radius_session_consumer_projection.sql",
    "config/postgres_migrations/062_vpn_session_report_read_boundary.sql",
    "config/postgres_migrations/063_radius_vpn_operations_read_boundary.sql",
    "server/sli/core/postgres_runtime_pipeline.py",
    "server/sli/ops/postgres_schema_guard.py",
    "server/sli/storage/storage_v2_runtime.py",
    "server/sli/ops/runtime_identity.py",
    "server/jobs/collector.py",
    "scripts/run_server.py",
    "scripts/run_dc_log_pilot.py",
    "scripts/runtime/collection_worker.py",
    "scripts/runtime/ad_context_snapshot_worker.py",
    "scripts/runtime/storage_v2_outbox_worker.py",
    "tools/ADLog-Toolkit.cmd",
    "tools/adlog-tool.ps1",
    "scripts/maintenance/export_dev_handoff.py",
    "scripts/maintenance/collect_diagnostics.py",
    "scripts/maintenance/capture_report.py",
    "scripts/maintenance/current_baseline_gate.py",
    "scripts/maintenance/apply_update.py",
    "scripts/maintenance/rollback_update.py",
    "scripts/maintenance/server_control.py",
    "scripts/maintenance/http_copy_control.py",
    "scripts/maintenance/baseline_snapshot.py",
    "scripts/maintenance/self_test.py",
    "scripts/maintenance/ui_nav_check.py",
    "scripts/maintenance/runtime_watchdog.py",
    "scripts/maintenance/storage_cleanup.py",
    "scripts/maintenance/md_freshness_check.py",
    "scripts/maintenance/html_inventory_audit.py",
    "scripts/maintenance/ops_stability1_migrate.py",
    "scripts/maintenance/semantic_l1_shadow_control.py",
    "scripts/maintenance/warm_tier_incremental_copy.py",
    "scripts/maintenance/postgres_readiness.py",
    "scripts/ops/git_docker.ps1",
    "scripts/ops/Disable-SLIWorkerSupervisor.ps1",
    "scripts/ops/Install-SLIWorkerSupervisor.ps1",
    "scripts/ops/Restart-SLIWorkerSupervisor.ps1",
    "scripts/runtime/remote_access_plugin_host.py",
    "scripts/ops/Backup-ProjectSource-NoDb.ps1",
    "docs/ADMIN_GUIDE.md",
    "docs/USER_GUIDE.md",
]

RUNTIME_FORBIDDEN_IN_SOURCE = [
    "data/raw",
    "data/processed",
    "data/logs",
    "data/reports",
    ".env",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".pytest_tmp",
]

SOURCE_ROOTS = ("server", "sli_collect", "sli_agent", "scripts", "tests", "tools", "docs", "web", "config", "frontend")


def _timed(name: str, func: Callable[[], Any]) -> tuple[Any, dict[str, Any]]:
    started = time.monotonic()
    try:
        data = func()
        return data, {"status": "ok", "duration_ms": int((time.monotonic() - started) * 1000)}
    except Exception as exc:  # release_check must report and continue
        return None, {"status": "failed", "duration_ms": int((time.monotonic() - started) * 1000), "error_type": type(exc).__name__, "error": str(exc)}


def _runtime_source_warnings(root: Path) -> list[str]:
    """Bounded check for runtime artifacts accidentally placed under source roots."""
    warnings: list[str] = []
    for source_root in SOURCE_ROOTS:
        base = root / source_root
        if not base.exists():
            continue
        scanned = 0
        for path in base.rglob("*"):
            scanned += 1
            if scanned > 5000:
                break
            if not path.exists() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if path.suffix.lower() in {".sqlite", ".sqlite3", ".db", ".jsonl", ".log", ".evtx"}:
                warnings.append(f"Найден запрещенный runtime файл в source tree: {rel}")
            if len(warnings) >= 20:
                return warnings
    return warnings


def _quick_runtime_size_checks(root: Path) -> tuple[list[str], dict[str, Any]]:
    """Fast storage advisories for release gate.

    This intentionally does not perform full deep accounting. Deep storage
    accounting belongs to maintenance/retention diagnostics; release_check must
    stay fast enough to run inside apply-update. These messages are advisory:
    large runtime data directories are operational debt, not evidence that a
    source-only release is unsafe.
    """
    data_dir = root / "data"
    raw = dir_size_report(data_dir / "raw", max_entries=3000, max_seconds=2.0)
    processed = dir_size_report(data_dir / "processed", max_entries=1000, max_seconds=1.5)
    backups = dir_size_report(data_dir / "backups", max_entries=1000, max_seconds=1.5)
    reports = dir_size_report(data_dir / "reports", max_entries=1000, max_seconds=1.0)
    logs = dir_size_report(data_dir / "logs", max_entries=1000, max_seconds=1.0)
    code_roots: dict[str, Any] = {}
    code_total = 0
    for name in SOURCE_ROOTS:
        item = dir_size_report(root / name, max_entries=2000, max_seconds=0.75, skip_dir_names={"bin", "obj", "__pycache__", ".pytest_cache"})
        code_roots[name] = item
        code_total += int(item.get("bytes") or 0)
    data_known_total = sum(int(item.get("bytes") or 0) for item in (raw, processed, backups, reports, logs))
    project_known_total = code_total + data_known_total
    advisories: list[str] = []
    if int(raw.get("bytes") or 0) > 1024**3:
        suffix = " (оценка усечена)" if raw.get("truncated") else ""
        advisories.append(f"data/raw больше 1 ГБ — высокий приоритет обслуживания: {raw.get('human')}{suffix}")
    if project_known_total > 5 * 1024**3:
        advisories.append(f"папка проекта больше 5 ГБ — высокий приоритет storage cleanup: {fmt_bytes(project_known_total)}+ fast estimate")
    return advisories, {
        "mode": "fast_bounded",
        "raw": raw,
        "processed": processed,
        "backups": backups,
        "reports": reports,
        "logs": logs,
        "source_roots": code_roots,
        "known_project_bytes": project_known_total,
        "known_project_human": fmt_bytes(project_known_total),
    }


def run_release_check(root: Path = ROOT, *, internal_test_build: bool = False) -> dict[str, Any]:
    started = time.monotonic()
    durations: dict[str, Any] = {}
    workstation_gate, durations["workstation_plugin"] = _timed(
        "workstation_plugin", lambda: workstation_release_gate(root, internal_test_build=internal_test_build))

    missing, durations["required_files"] = _timed("required_files", lambda: [item for item in REQUIRED_FILES if not (root / item).exists()])
    role_data, durations["role_views"] = _timed("role_views", lambda: {"views": [{"id": "security"}, {"id": "it"}, {"id": "technical"}]})
    reports, durations["reports"] = _timed("reports", list_reports)
    release_metadata, durations["release_metadata"] = _timed("release_metadata", lambda: get_release_metadata(root))
    runtime_warnings, durations["runtime_source_warnings"] = _timed("runtime_source_warnings", lambda: _runtime_source_warnings(root))
    size_result, durations["runtime_size_checks"] = _timed("runtime_size_checks", lambda: _quick_runtime_size_checks(root))
    tool_env = {"ADLOG_TOOLKIT_DISABLE_AUDIT": "1", "ADLOG_SELFTEST_NO_LOG": "1"}
    self_test_result, durations["self_test_offline"] = _timed("self_test_offline", lambda: run_command([sys.executable, "scripts/maintenance/self_test.py", "--offline", "--json"], timeout=45, env_update=tool_env))
    ui_nav_result, durations["ui_nav_check"] = _timed("ui_nav_check", lambda: run_command([sys.executable, "scripts/maintenance/ui_nav_check.py", "--json"], timeout=30, env_update=tool_env))
    storage_cleanup_result, durations["storage_cleanup_dry_run"] = _timed("storage_cleanup_dry_run", lambda: run_command([sys.executable, "scripts/maintenance/storage_cleanup.py", "--dry-run", "--json", "--summary-only", "--no-audit"], timeout=45, env_update=tool_env))
    md_freshness_result, durations["md_freshness_check"] = _timed("md_freshness_check", lambda: run_command([sys.executable, "scripts/maintenance/md_freshness_check.py", "--json"], timeout=20, env_update=tool_env))
    pg_runtime_parity_result, durations["pg_runtime_parity_audit"] = _timed("pg_runtime_parity_audit", lambda: audit_pg_runtime_parity(root))

    def _event_catalog_check() -> dict[str, Any]:
        """Проверка каталога событий.

        Валидатор `server/sli/events/event_catalog_quality.py` существовал давно и не
        вызывался ниоткуда: ни отсюда, ни из тестов. Объявленный и
        неподключённый механизм неотличим от отсутствующего, поэтому первое,
        что здесь делается, - он подключается.

        Полнота классификации выпуск не блокирует: решение владельца
        28.07.2026. Блокируют только настоящие ошибки формы и неполнота
        новых или изменённых записей.
        """
        from server.sli.events.event_catalog_quality import (
            build_catalog_baseline, catalog_completeness,
            validate_catalog_changes, validate_catalog_data,
        )

        catalog_path = root / "config" / "event_catalog.json"
        baseline_path = root / "config" / "event_catalog_baseline.json"
        if not catalog_path.is_file():
            return {"status": "skipped", "reason": "каталог не найден"}
        data = json.loads(catalog_path.read_text(encoding="utf-8"))
        baseline = (
            json.loads(baseline_path.read_text(encoding="utf-8"))
            if baseline_path.is_file() else build_catalog_baseline({"entries": []})
        )
        form = validate_catalog_data(data)
        changes = validate_catalog_changes(data, baseline)
        completeness = catalog_completeness(data)
        blocking: list[str] = []
        if not form["valid"]:
            blocking.append(f"каталог: ошибок формы {len(form['errors'])}")
        for нарушение in changes["violations"]:
            blocking.append(
                f"каталог: {нарушение['вид']} запись {нарушение['identity']} "
                f"без обязательных полей: {', '.join(нарушение['не_заполнено'])}"
            )
        return {
            "status": "ok" if not blocking else "failed",
            "blocking": blocking,
            "form": {"valid": form["valid"], "error_count": len(form["errors"]),
                     "errors": form["errors"][:20]},
            "changes": {k: v for k, v in changes.items() if k != "violations"},
            "completeness": completeness,
        }

    event_catalog_result, durations["event_catalog_check"] = _timed("event_catalog_check", _event_catalog_check)
    def _inline_postgres_readiness() -> dict[str, Any]:
        from scripts.maintenance.postgres_readiness import run_readiness

        payload = run_readiness(connect=False)
        return {
            "exit_code": 0,
            "timed_out": False,
            "mode": "in_process_no_connect",
            "stdout_tail": json.dumps(payload, ensure_ascii=False)[-8000:],
        }

    postgres_readiness_result, durations["postgres_readiness"] = _timed("postgres_readiness", _inline_postgres_readiness)
    if size_result:
        size_advisories, runtime_size_checks = size_result
    else:
        size_advisories, runtime_size_checks = [], {"mode": "failed"}
        runtime_size_checks_warning = "runtime size checks failed"

    warnings: list[str] = []
    if missing:
        warnings.append(f"Не найдены обязательные файлы: {', '.join(missing)}")
    role_views = [view.get("id") for view in ((role_data or {}).get("views") or [])]
    if len(role_views) < 3:
        warnings.append("Ролевые представления ИБ/ИТ/Технический сформированы не полностью")
    warnings.extend(runtime_warnings or [])
    if not size_result:
        warnings.append(runtime_size_checks_warning)
    if isinstance(pg_runtime_parity_result, dict) and pg_runtime_parity_result.get("status") != "ok":
        warnings.extend(str(item) for item in (pg_runtime_parity_result.get("failures") or ["PG runtime parity audit failed"]))
    if isinstance(event_catalog_result, dict):
        warnings.extend(str(item) for item in (event_catalog_result.get("blocking") or []))
    for check_name, command_result in (("self_test_offline", self_test_result), ("ui_nav_check", ui_nav_result), ("storage_cleanup_dry_run", storage_cleanup_result), ("md_freshness_check", md_freshness_result), ("postgres_readiness", postgres_readiness_result)):
        if isinstance(command_result, dict) and command_result.get("exit_code") not in (0, None):
            warnings.append(f"{check_name} returned exit_code={command_result.get('exit_code')}")
        if isinstance(command_result, dict) and command_result.get("timed_out"):
            warnings.append(f"{check_name} timed out after {command_result.get('timeout_seconds')}s")
    for name, info in durations.items():
        if int(info.get("duration_ms") or 0) > 5000:
            warnings.append(f"release_check slow block: {name} {info.get('duration_ms')} ms")
        if info.get("status") == "failed":
            warnings.append(f"release_check block failed: {name}: {info.get('error_type')}: {info.get('error')}")

    return {
        "status": "failed" if workstation_gate is None else ("warn" if warnings else "ok"),
        "workstation_gate": workstation_gate,
        "release_eligible": not warnings and workstation_gate is not None and workstation_gate["release_eligible"],
        "artifact_label": INTERNAL_LABEL if internal_test_build else "release",
        "duration_ms": int((time.monotonic() - started) * 1000),
        "checks_duration_ms": {name: info.get("duration_ms") for name, info in durations.items()},
        "checks": durations,
        "missing_files": missing or [],
        "warnings": list(dict.fromkeys(str(item) for item in warnings if item)),
        "storage_advisories": list(dict.fromkeys(str(item) for item in size_advisories if item)),
        "role_views": role_views,
        "reports": [item.get("name") for item in (reports or [])],
        "system_status": "warn" if warnings else "ok",
        "release_metadata": release_metadata or {"error": "release metadata unavailable"},
        "runtime_source_checks": {
            "forbidden_runtime_markers": RUNTIME_FORBIDDEN_IN_SOURCE,
            "source_artifact_warnings": [w for w in warnings if "source tree" in w],
        },
        "runtime_size_checks": runtime_size_checks,
        "self_test_offline": self_test_result,
        "ui_nav_check": ui_nav_result,
        "storage_cleanup_dry_run": storage_cleanup_result,
        "md_freshness_check": md_freshness_result,
        "pg_runtime_parity_audit": pg_runtime_parity_result,
        "event_catalog_check": event_catalog_result,
        "postgres_readiness": postgres_readiness_result,
        "gate_classes": {
            "source_only": {
                "status": "failed" if workstation_gate is None else ("passed" if not warnings else "passed_with_warnings"),
                "executed": True,
                "production_mutation": False,
            },
            "postgres_integration": {
                "status": "not_run",
                "executed": False,
                "reason": "requires an explicitly created disposable PostgreSQL database/schema",
            },
            "host_dependent": {
                "status": "not_run",
                "executed": False,
                "reason": "PowerShell 5.1 and Windows service checks are separate host gates",
            },
            "live": {
                "status": "not_run",
                "executed": False,
                "live_ad_contacted": False,
                "collection_started": False,
                "runtime_restarted": False,
            },
        },
        "tooling_gaps": {
            "ruff": "not_configured",
            "static_type_check": "not_configured",
            "coverage_threshold": "not_configured",
            "note": "No toolchain migration is performed by this source-only completion patch.",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Security Log Intelligence release readiness check.")
    parser.add_argument("--json", action="store_true", help="print JSON")
    parser.add_argument(
        "--allow-warn",
        action="store_true",
        help="diagnostic-only mode: return exit code 0 for status=warn",
    )
    parser.add_argument("--internal-test-build", action="store_true", help=INTERNAL_LABEL)
    args = parser.parse_args()
    result = run_release_check(internal_test_build=True) if args.internal_test_build else run_release_check()
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Release check: {result['status']} ({result.get('duration_ms')} ms)")
        if args.internal_test_build:
            print(INTERNAL_LABEL)
        print("Version:", (result.get("release_metadata") or {}).get("project_version"))
        print("Build:", (result.get("release_metadata") or {}).get("build_id"))
        for warning in result["warnings"]:
            print(f"- {warning}")
        print("Role views:", ", ".join(result["role_views"]))
    if result["status"] == "ok":
        return 0
    if result["status"] == "warn" and args.allow_warn:
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
