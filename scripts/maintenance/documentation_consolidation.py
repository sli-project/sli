from __future__ import annotations

"""Targeted consolidation of legacy Markdown documents.

The update tool already creates its normal technical rollback backup. This script
does not create a second documentation archive. It removes only the explicit
legacy list from the reviewed 2026-07-12 baseline and refuses to run unless the
canonical replacement documents are present.
"""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "documentation"

ACTIVE_CANONICAL_PATHS = {
    "CHANGELOG.md",
    "PROJECT_RULES.md",
    "docs/CURRENT_BASELINE.md",
    "docs/CURRENT_ROADMAP.md",
    "docs/forgtp.md",
    "docs/DOCUMENTATION_INDEX.md",
    "docs/DEVELOPMENT_AND_RELEASE.md",
    "docs/REPOSITORY_RELEVANCE_AUDIT.md",
}

REFERENCE_PATHS = {
    "PROJECT_MAP.md",
    "config/README.md",
    "docs/BACKLOG_GAP_AUDIT.md",
    "docs/SYSTEM_ARCHITECTURE.md",
    "docs/OPERATIONS_RUNBOOK.md",
    "docs/POSTGRES_OPERATIONS_RUNBOOK.md",
    "docs/SECURITY_COLLECTION_RUNBOOK.md",
    "docs/STORAGE_AND_RETENTION.md",
    "docs/REPORTING_AND_AI.md",
    "docs/DEVELOPMENT_AND_RELEASE.md",
    "docs/REQUIREMENTS.md",
    "docs/DATABASE_SCHEMA.md",
    "docs/EVENT_CATALOG.md",
    "docs/MICROSOFT_LOGGING_BASELINE.md",
    "docs/INTEGRATOR_HANDOFF_STANDARD.md",
    "scripts/dc_client/README.md",
    "scripts/manual_dc_audit/README.md",
}

CANONICAL_PATHS = ACTIVE_CANONICAL_PATHS | REFERENCE_PATHS

LEGACY_PATHS = {
    "_handoff_meta/REPRODUCTION_NOTES.md",
    "docs/AI_PROVIDER_DECISION.md",
    "docs/AI_REPORT_RUNBOOK.md",
    "docs/AI_SAFETY_LAYER.md",
    "docs/ARCHIVE_COLLECTION.md",
    "docs/CLIENT_SERVER_ARCHITECTURE.md",
    "docs/CORE_OPS1_COLLECTOR_STORAGE_DASHBOARD.md",
    "docs/CORE_PERF1_DASHBOARD_PERFORMANCE.md",
    "docs/CURRENT_RUNTIME_DETACH_HOTFIX.md",
    "docs/DB0101_STABLE_SCHEDULER_GUARD.md",
    "docs/DB011_SCHEDULER_NONBLOCKING_GUARD.md",
    "docs/DB012_ARCHIVE_WATERMARK_CANARY.md",
    "docs/DB013_ARCHIVE_WORKER_ISOLATION.md",
    "docs/DB0141_PYTEST_ENV_ISOLATION.md",
    "docs/DB014_POSTGRES_RUNTIME_BACKEND_FIX.md",
    "docs/DB0151_CANARY_ADAPTIVE_ISOLATION.md",
    "docs/DB015_POSTGRES_ADAPTIVE_PARITY.md",
    "docs/DB015_UPDATE_APPLY.md",
    "docs/DB016_NONBLOCKING_POST_COLLECTION.md",
    "docs/DB031_UPDATE_APPLY.md",
    "docs/DB04_UPDATE_APPLY.md",
    "docs/DB05_UPDATE_APPLY.md",
    "docs/DB06_RUNTIME_CUTOVER_GUARD.md",
    "docs/DB07_POSTGRES_RUNTIME_PIPELINE.md",
    "docs/DB08_POSTGRES_SCHEDULER_CANARY.md",
    "docs/DB09_POSTGRES_SCHEDULER_CONTROLLED.md",
    "docs/DB10_POSTGRES_SCHEDULER_10K.md",
    "docs/DC_LOG_ANALYSIS_SCOPE.md",
    "docs/DEVELOPER_HANDOFF_TOOLKIT.md",
    "docs/DEVELOPMENT_TOOLS.md",
    "docs/ENTITY_OBSERVATION_MODEL.md",
    "docs/FINDINGS_PG1_INCREMENTAL_PIPELINE.md",
    "docs/IMPORT_PERF1_POSTGRES_BATCHING.md",
    "docs/INTERNAL_ERROR_LOGGING_RUNBOOK.md",
    "docs/LEGACY_SQLITE_CLEANUP.md",
    "docs/LOG_COLLECTION_START_RUNBOOK.md",
    "docs/OBSERVABILITY_CONCEPT.md",
    "docs/PERFORMANCE_RECOVERY_RUNBOOK.md",
    "docs/PG_PRODUCT1_RUNTIME_PARITY_FINDINGS.md",
    "docs/PG_PRODUCT2_RUNTIME_PARITY_LIFECYCLE.md",
    "docs/PG_STABLE_AUDIT.md",
    "docs/PG_STABLE_RUNTIME_STATUS.md",
    "docs/PROJECT_STRUCTURE_AUDIT.md",
    "docs/PYTHON_COLLECTOR_MIGRATION.md",
    "docs/RELEASE_CHECKLIST.md",
    "docs/REPORT_REVIEW_RUNBOOK.md",
    "docs/REPORT_TARGET_STYLE.md",
    "docs/SECURITY_CURRENT1_COMPLETION.md",
    "docs/SECURITY_MONITOR_INVESTIGATION_RUNBOOK.md",
    "docs/SECURITY_OPS1_CONTROLLED_RECOVERY.md",
    "docs/SECURITY_OPS1_OBSERVABILITY_HOTFIX.md",
    "docs/SECURITY_RECOVERY1_CONTROLLED_CYCLES.md",
    "docs/SECURITY_SCALE1_CONTROLLED_VALIDATION.md",
    "docs/SQLITE_IMPORT_QUEUE_RUNBOOK.md",
    "docs/STAGE0_TOOLS_HOTFIX.md",
    "docs/STAGE1_DIAGNOSTICS_SELFTEST.md",
    "docs/STAGE2_STORAGE_SAFETY_RETENTION.md",
    "docs/STAGE3_PIPELINE_AUTOCOLLECTION_UX.md",
    "docs/STAGE4_UI_ROLE_UX.md",
    "docs/STAGE_DB0_2_MIGRATION_DRY_RUN.md",
    "docs/STAGE_DB0_3_MIGRATION_EXECUTOR.md",
    "docs/STAGE_DB0_4_MIGRATION_VERIFY.md",
    "docs/STAGE_DB0_5_FULL_MIGRATION.md",
    "docs/STAGE_DB0_POSTGRES_READINESS.md",
    "docs/STORAGE_DECISION.md",
    "docs/STORAGE_LIFECYCLE2.md",
    "docs/WEEK_1_4_DELIVERY.md",
}

FOLDER_INDEX_MARKER = "<!-- project-folder-index:v1 -->"


ACTIVE_SOURCE_ROOTS = {"docs", "config", "scripts", "server", "sli_collect", "sli_agent", "tests", "web", "tools"}


def active_markdown_paths() -> list[str]:
    result: list[str] = []
    for path in ROOT.rglob("*.md"):
        rel = path.relative_to(ROOT)
        if len(rel.parts) == 1 or rel.parts[0] in ACTIVE_SOURCE_ROOTS:
            result.append(rel.as_posix())
    return sorted(result)


def folder_index_paths(paths: list[str]) -> set[str]:
    result: set[str] = set()
    for rel in paths:
        path = ROOT / rel
        if path.name == "README.md" and path.is_file():
            text = path.read_text(encoding="utf-8-sig", errors="replace")
            if FOLDER_INDEX_MARKER in text:
                result.add(rel)
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def validate_paths() -> list[str]:
    failures: list[str] = []
    overlap = CANONICAL_PATHS & LEGACY_PATHS
    if overlap:
        failures.append(f"canonical/legacy overlap: {sorted(overlap)}")
    for rel in sorted(ACTIVE_CANONICAL_PATHS):
        path = ROOT / rel
        if not path.is_file():
            failures.append(f"active canonical document missing: {rel}")
        elif path.stat().st_size < 50:
            failures.append(f"active canonical document too small: {rel}")
    for rel in sorted(LEGACY_PATHS):
        path = Path(rel)
        if path.is_absolute() or ".." in path.parts:
            failures.append(f"unsafe legacy path: {rel}")
        if path.suffix.lower() != ".md":
            failures.append(f"non-Markdown legacy path: {rel}")
    return failures


def execute(*, apply: bool) -> dict[str, Any]:
    failures = validate_paths()
    existing = [rel for rel in sorted(LEGACY_PATHS) if (ROOT / rel).is_file()]
    missing = [rel for rel in sorted(LEGACY_PATHS) if not (ROOT / rel).exists()]
    result: dict[str, Any] = {
        "package_type": "DOCUMENTATION_CONSOLIDATION_1",
        "created_at": utc_now(),
        "mode": "apply" if apply else "plan",
        "status": "blocked" if failures else ("ready" if not apply else "ok"),
        "active_canonical_count": len(ACTIVE_CANONICAL_PATHS),
        "reference_count": len(REFERENCE_PATHS),
        "canonical_count": len(CANONICAL_PATHS),
        "legacy_list_count": len(LEGACY_PATHS),
        "existing_legacy_count": len(existing),
        "missing_legacy_count": len(missing),
        "active_canonical_paths": sorted(ACTIVE_CANONICAL_PATHS),
        "reference_paths": sorted(REFERENCE_PATHS),
        "canonical_paths": sorted(CANONICAL_PATHS),
        "planned_removals": existing,
        "missing_paths": missing,
        "removed": [],
        "failures": failures,
        "separate_documentation_archive_created": False,
        "technical_rollback_backup": "provided by the standard apply-update tool",
    }
    if failures or not apply:
        return result
    removed: list[str] = []
    for rel in existing:
        path = ROOT / rel
        path.unlink()
        removed.append(rel)
    # Remove only empty directories left by the explicit deletion list.
    for directory in sorted({(ROOT / rel).parent for rel in removed}, key=lambda p: len(p.parts), reverse=True):
        try:
            directory.rmdir()
        except OSError:
            pass
    result["removed"] = removed
    result["removed_count"] = len(removed)
    remaining_md = active_markdown_paths()
    result["remaining_markdown_count"] = len(remaining_md)
    result["remaining_markdown"] = remaining_md
    navigation_indexes = folder_index_paths(remaining_md)
    result["folder_navigation_indexes"] = sorted(navigation_indexes)
    unexpected = [
        rel for rel in remaining_md
        if rel not in CANONICAL_PATHS and rel not in navigation_indexes
    ]
    result["unexpected_remaining_markdown"] = unexpected
    if unexpected:
        result["status"] = "warning"
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Consolidate reviewed legacy Markdown documents into the canonical set.")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    result = execute(apply=args.apply)
    output = args.output or DEFAULT_OUTPUT_DIR / f"documentation_consolidation_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    write_json(output, result)
    result["evidence_path"] = str(output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("status") in {"ready", "ok", "warning"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
