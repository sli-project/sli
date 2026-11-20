"""Project release and baseline metadata.

This module is intentionally small and side-effect free so it can be imported by
release checks, diagnostic tools and update tooling without touching AD/DC or
runtime collection state.
"""

from __future__ import annotations

import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_NAME = "Security Log Intelligence / ad_log_reports"
PROJECT_SLUG = "ad_log_reports"
PROJECT_VERSION = "2026.07.19-pg-product-sli-v4"
BASELINE_ID = "pg-product-sli-v4-20260719"
BASELINE_DATE_UTC = "2026-07-19T00:00:00+00:00"
BASELINE_LABEL = "SLI v4 product shell; composite server-side access; registered reports/datasets; universal object facade; PostgreSQL/Storage V2; surveyed systems remain read-only"
BASELINE_SCHEMA_MIGRATION_VERSION = 37


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _git_commit(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(root),
            text=True,
            capture_output=True,
            timeout=2,
        )
    except Exception:
        return None
    if proc.returncode != 0:
        return None
    value = proc.stdout.strip()
    return value or None


def _schema_versions_from_file(root: Path) -> dict[str, Any]:
    postgres_schema = root / "config" / "postgres_schema.sql"
    migrations_dir = root / "config" / "postgres_migrations"
    migration_files = sorted(
        path
        for path in migrations_dir.glob("[0-9][0-9][0-9]_*.sql")
        if not path.name.endswith(".rollback.sql")
    )
    result: dict[str, Any] = {
        "runtime_backend": "postgres",
        "schema_file": str(postgres_schema),
        "schema_file_exists": postgres_schema.exists(),
        "schema_files": [str(postgres_schema), *(str(path) for path in migration_files)],
        "baseline_schema_migration_version": BASELINE_SCHEMA_MIGRATION_VERSION,
        "schema_declared_max_version": BASELINE_SCHEMA_MIGRATION_VERSION,
    }
    migrations: list[int] = []
    if postgres_schema.exists():
        text = postgres_schema.read_text(encoding="utf-8", errors="replace")
        migrations.extend(
            int(item)
            for item in re.findall(r"\(\s*(\d+)\s*,\s*'[^']+'\s*\)", text)
        )
    migrations.extend(int(path.name[:3]) for path in migration_files)
    if migrations:
        result["schema_declared_max_version"] = max(migrations)
        result["schema_migrations_declared"] = sorted(set(migrations))
    return result


def get_release_metadata(root: Path | None = None) -> dict[str, Any]:
    """Return source release metadata for diagnostics/release_check/UI tooling."""
    root = root or _project_root()
    build_id = os.environ.get("ADLOG_BUILD_ID") or BASELINE_ID
    generated_at = datetime.now(timezone.utc).isoformat()
    schema = _schema_versions_from_file(root)
    return {
        "project": PROJECT_NAME,
        "project_slug": PROJECT_SLUG,
        "project_version": PROJECT_VERSION,
        "baseline_id": BASELINE_ID,
        "baseline_label": BASELINE_LABEL,
        "baseline_date_utc": BASELINE_DATE_UTC,
        "build_id": build_id,
        "generated_at_utc": generated_at,
        "git_commit": _git_commit(root),
        "schema": schema,
    }
