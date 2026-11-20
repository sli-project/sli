#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import audit_action  # noqa: E402
from server.sli.storage.storage_policy import (  # noqa: E402
    apply_pytest_run_cleanup_plan,
    apply_storage_cleanup_plan,
    build_pytest_run_cleanup_plan,
    build_storage_cleanup_plan,
    get_storage_health,
)


def _json_default(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def render_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, default=_json_default)


def compact_cleanup_result(result: dict) -> dict:
    """Return bounded cleanup summary for release gates and diagnostics.

    Full action lists can contain hundreds/thousands of file paths and make
    release_check/diagnostic bundles noisy. Operator CLI without --summary-only
    still returns the full dry-run plan.
    """
    actions = list(result.get("actions") or [])
    sample = actions[:10]
    by_category: dict[str, dict[str, int]] = {}
    for item in actions:
        category = str(item.get("category") or "unknown")
        bucket = by_category.setdefault(category, {"count": 0, "bytes": 0})
        bucket["count"] += 1
        bucket["bytes"] += int(item.get("size_bytes") or 0)
    by_category_human = {
        key: {**value, "human": _fmt_bytes(value.get("bytes") or 0)}
        for key, value in by_category.items()
    }
    return {
        "status": result.get("status"),
        "mode": result.get("mode"),
        "category": result.get("category"),
        "generated_at_utc": result.get("generated_at_utc"),
        "duration_ms": result.get("duration_ms"),
        "deep": result.get("deep"),
        "limit": result.get("limit"),
        "root": result.get("root"),
        "min_age_hours": result.get("min_age_hours"),
        "total_candidates": result.get("total_candidates"),
        "total_bytes": result.get("total_bytes"),
        "total_human": result.get("total_human"),
        "by_category": by_category_human,
        "actions_sample": sample,
        "actions_omitted": max(0, len(actions) - len(sample)),
        "sqlite_retention": result.get("sqlite_retention"),
        "scan": result.get("scan"),
        "safety": result.get("safety"),
        "applied": result.get("applied", []),
        "errors": result.get("errors", []),
    }


def compact_storage_health(result: dict) -> dict:
    pressure = dict(result.get("disk_pressure") or {})
    disk = dict(pressure.get("disk") or {})
    postgres = dict(result.get("postgres_operations") or {})
    database = dict(postgres.get("database") or {})
    overview = dict(result.get("project_overview") or {})
    scan = dict(overview.get("scan") or {})
    cleanup = dict(result.get("cleanup_preview") or {})
    last_cleanup = dict(result.get("last_cleanup") or {})
    return {
        "status": result.get("status"),
        "warnings": list(result.get("warnings") or []),
        "disk": {
            "free_bytes": disk.get("free_bytes"),
            "free_human": disk.get("free_human"),
            "free_percent": disk.get("free_percent"),
            "collection_allowed": pressure.get("collection_allowed"),
            "blocking_free_human": (
                pressure.get("blocking_threshold") or {}
            ).get("free_human"),
        },
        "postgres": {
            "status": postgres.get("status"),
            "connectivity_status": postgres.get("connectivity_status"),
            "metrics_status": postgres.get("metrics_status"),
            "database_name": database.get("database_name"),
            "database_bytes": database.get("database_bytes"),
            "database_human": database.get("database_human"),
            "checked_at": database.get("checked_at"),
        },
        "project": {
            "files_human": overview.get("project_files_human"),
            "database_human": overview.get("database_human"),
            "total_human": overview.get("total_human"),
            "scan_complete": scan.get("complete_project_tree"),
            "scan_errors": scan.get("errors"),
            "scan_error_paths": list(scan.get("error_paths") or []),
        },
        "cleanup_preview": {
            "total_candidates": cleanup.get("total_candidates"),
            "total_human": cleanup.get("total_human"),
        },
        "last_cleanup": {
            "status": last_cleanup.get("status"),
            "mode": last_cleanup.get("mode"),
            "generated_at_utc": last_cleanup.get("generated_at_utc"),
        } if last_cleanup else None,
        "safety": {
            "read_only": True,
            "cleanup_executed": False,
            "vacuum_executed": False,
        },
    }


def _fmt_bytes(value: int | float | None) -> str:
    size = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{int(value or 0)} B"


def main() -> int:
    parser = argparse.ArgumentParser(description="Storage Safety & Retention cleanup. Dry-run by default; no AD/DC changes.")
    parser.add_argument("--dry-run", action="store_true", help="Show cleanup candidates without changing files. This is the default.")
    parser.add_argument("--apply", action="store_true", help="Apply file cleanup actions. Requires --confirm-apply.")
    parser.add_argument("--confirm-apply", action="store_true", help="Required with --apply to acknowledge destructive local file operations.")
    parser.add_argument("--deep", action="store_true", help="Use deeper bounded scans.")
    parser.add_argument("--limit", type=int, default=None, help="Maximum file cleanup candidates.")
    parser.add_argument("--health", action="store_true", help="Print storage health instead of cleanup plan.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument("--summary-only", action="store_true", help="Print compact JSON without full action list; intended for release_check/diagnostics.")
    parser.add_argument("--no-audit", action="store_true", help="Do not write audit-actions.log entry for this read-only dry-run.")
    parser.add_argument(
        "--pytest-runs-only",
        action="store_true",
        help="Limit the plan/apply operation to generated data/tmp/pytest-runs directories.",
    )
    parser.add_argument(
        "--pytest-min-age-hours",
        type=float,
        default=24,
        help="Minimum inactivity age for --pytest-runs-only candidates (default: 24).",
    )
    args = parser.parse_args()

    if args.health:
        result = get_storage_health(deep=args.deep)
        output = compact_storage_health(result) if args.summary_only else result
        print(render_json(output))
        return 0

    if args.pytest_runs_only:
        plan = build_pytest_run_cleanup_plan(
            min_age_hours=args.pytest_min_age_hours,
            limit=args.limit or 200,
        )
        result = apply_pytest_run_cleanup_plan(
            plan,
            apply=args.apply,
            confirm_apply=args.confirm_apply,
        )
    else:
        plan = build_storage_cleanup_plan(deep=args.deep, limit=args.limit)
        result = apply_storage_cleanup_plan(plan, apply=args.apply, confirm_apply=args.confirm_apply)
    if not args.no_audit:
        audit_action(
            "storage_cleanup_apply" if args.apply else "storage_cleanup_dry_run",
            str(result.get("status") or "ok"),
            total_candidates=result.get("total_candidates"),
            total_bytes=result.get("total_bytes"),
            errors=len(result.get("errors") or []),
            category=result.get("category") or "storage",
        )
    output = compact_cleanup_result(result) if args.summary_only else result
    if args.json or args.apply or args.dry_run or args.summary_only:
        print(render_json(output))
    else:
        print(f"Storage cleanup: {result.get('status')} ({result.get('mode')})")
        print(f"Candidates: {result.get('total_candidates')} / {result.get('total_human')}")
        if result.get("errors"):
            for item in result.get("errors") or []:
                print("-", item)
    return 0 if result.get("status") in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
