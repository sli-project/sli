#!/usr/bin/env python3
"""Create a source-code handoff bundle for an analyst or developer.

The bundle intentionally excludes runtime data: raw logs, databases, local
.env, reports, backups and caches. It includes project rules, source,
acceptance tools and a small curated set of current-state evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import (
    HANDOFF_DIR,
    PROJECT_ROOT,
    audit_action,
    basic_project_snapshot,
    configured_env_secret_values,
    copy_tree_filtered,
    is_safe_archive_member,
    redact_env_file,
    should_exclude_from_dev_handoff,
    timestamp,
    write_json,
    write_text,
    zip_dir,
)

INCLUDE_ROOTS = [
    "frontend",
    "server",
    "sli_collect",
    "sli_agent",
    "scripts",
    "web",
    "config",
    "docs",
    "tests",
    "tools",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements.lock.txt",
    "pyproject.toml",
    "pytest.ini",
    ".gitignore",
    ".env.example",
]

ANALYST_DENY_PREFIXES = (
    "frontend/.sli-v4-",
    "frontend/artifacts/",
    "web/app/react/",
)

REQUIRED_ANALYST_PATHS = (
    "README.md",
    "CONTRIBUTING.md",
    "docs/ADMIN_GUIDE.md",
    "config/postgres_schema.sql",
    "config/plugin_architecture_v1.json",
    "frontend/package.json",
    "frontend/package-lock.json",
    "package.json",
    "package-lock.json",
    "requirements.lock.txt",
    "tools/adlog-tool.ps1",
)

CURRENT_EVIDENCE_FILES = (
    "artifacts/stage7/evidence/stage7-readiness-gate.json",
    "artifacts/stage7/evidence/warm-tier-incremental-plan.json",
    "artifacts/stage7/evidence/provisional-entity-merge-plan.json",
    "artifacts/stage8/evidence/semantic-production-state.json",
    "artifacts/stage9/evidence/plugin-contract-p0b.json",
    "artifacts/stage9/evidence/radius-manual-worker-run-004.json",
    "artifacts/stage9/evidence/radius-session-consumer-production-run-003.json",
    "artifacts/stage9/evidence/vpn-session-frontend-connected-acceptance.json",
    "artifacts/stage9/evidence/radius-vpn-operations63-production-apply.json",
    "artifacts/stage9/evidence/ad-dc-compatibility-registration-v1.json",
    "artifacts/stage9/evidence/ad-dc-source-pack-parity-v1.json",
    "artifacts/stage10/evidence/plugin-worker-boundaries-contract-v1.json",
    "artifacts/stage10/evidence/plugin-management-readonly-contract-v1.json",
    "artifacts/stage10/evidence/remote-access-package-manifest-v1.json",
    "artifacts/stage10/evidence/plugin-postgresql-isolation67-production-apply.json",
    "artifacts/stage10/evidence/administrative-activity66-production-apply.json",
    "artifacts/stage10/evidence/administrative-activity-reader72-production-apply.json",
    "artifacts/stage10/evidence/plugin-lifecycle-source-contract-v1.json",
    "artifacts/stage10/evidence/plugin-lifecycle-registry73-production-apply.json",
    "artifacts/stage10/evidence/plugin-bundled-install74-production-apply.json",
    "artifacts/stage10/evidence/plugin-bundled-install-operation-production.json",
)


def _should_exclude_from_analyst_handoff(rel: str) -> bool:
    normalized = rel.replace("\\", "/").strip("/")
    if any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in ANALYST_DENY_PREFIXES):
        return True
    return should_exclude_from_dev_handoff(normalized)


def _db_schema_text() -> str:
    schema_file = PROJECT_ROOT / "config" / "postgres_schema.sql"
    if schema_file.exists():
        return schema_file.read_text(encoding="utf-8", errors="replace")
    return "-- config/postgres_schema.sql not found\n"


def _configured_secret_values() -> list[str]:
    return configured_env_secret_values(PROJECT_ROOT / ".env")


def _find_configured_secret_matches(staging: Path) -> list[str]:
    secrets = _configured_secret_values()
    if not secrets:
        return []
    matches: list[str] = []
    text_suffixes = {
        ".css", ".env", ".html", ".ini", ".js", ".json", ".jsx", ".md",
        ".mjs", ".ps1", ".py", ".sql", ".svg", ".toml", ".ts", ".tsx",
        ".txt", ".xml", ".yaml", ".yml",
    }
    for path in staging.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in text_suffixes or path.stat().st_size > 5 * 1024 * 1024:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        # Short passwords must match a whole token, not every ordinary word.
        # A coincidental standalone token still fails closed. This bounded
        # scan does not promise to detect arbitrary transformed log secrets.
        if any(
            secret in text if len(secret) >= 8
            else re.search(r"(?<!\w)" + re.escape(secret) + r"(?!\w)", text)
            for secret in secrets
        ):
            matches.append(path.relative_to(staging).as_posix())
    return sorted(matches)


def _validate_copied_files(copied: list[dict[str, Any]], staging: Path) -> dict[str, Any]:
    dangerous: list[str] = []
    build_artifacts: list[str] = []
    paths = {str(item.get("path") or "") for item in copied}
    for item in copied:
        rel = str(item.get("path") or "")
        if _should_exclude_from_analyst_handoff(rel):
            dangerous.append(rel)
        parts = rel.replace("\\", "/").split("/")
        if any(part in {"bin", "obj", "runtimes"} for part in parts):
            build_artifacts.append(rel)
    missing_required = [path for path in REQUIRED_ANALYST_PATHS if path not in paths]
    configured_secret_matches = _find_configured_secret_matches(staging)
    return {
        "status": (
            "ok"
            if not dangerous and not build_artifacts and not missing_required and not configured_secret_matches
            else "failed"
        ),
        "dangerous_files": dangerous,
        "build_artifacts": build_artifacts,
        "required_paths": list(REQUIRED_ANALYST_PATHS),
        "missing_required_paths": missing_required,
        "configured_secret_matches": configured_secret_matches,
    }


def _copy_current_evidence(
    meta_dir: Path,
    *,
    evidence_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    evidence_dir = meta_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    copied: list[dict[str, Any]] = []
    missing: list[str] = []
    for rel in CURRENT_EVIDENCE_FILES:
        source = evidence_root / rel
        if not source.is_file():
            missing.append(rel)
            continue
        target = evidence_dir / source.name
        shutil.copy2(source, target)
        copied.append(
            {
                "source_path": rel,
                "archive_path": target.relative_to(meta_dir.parent).as_posix(),
                "size": target.stat().st_size,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        )
    return {"copied": copied, "missing": missing}


def _write_tiny_fixtures(meta_dir: Path) -> list[str]:
    fixtures_dir = meta_dir / "fixtures"
    fixtures_dir.mkdir(parents=True, exist_ok=True)
    event = (
        '{"server":"DC-SYNTHETIC","channel":"Security","event_id":4624,'
        '"event_record_id":1,"time_created_utc":"2026-01-01T00:00:00+00:00",'
        '"provider":"Microsoft-Windows-Security-Auditing","message":"Synthetic fixture only"}\n'
    )
    path = fixtures_dir / "Security.synthetic.jsonl"
    path.write_text(event, encoding="utf-8")
    return [str(path.relative_to(meta_dir.parent).as_posix())]


def _verify_archive(zip_path: Path) -> dict[str, Any]:
    required_meta = {
        "_handoff_meta/MANIFEST.json",
        "_handoff_meta/ANALYST_ENTRYPOINT.md",
        "_handoff_meta/ENV_REDACTED.txt",
        "_handoff_meta/DB_SCHEMA.sql",
        "_handoff_meta/FILE_TREE.txt",
    }
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        unsafe_members = sorted(name for name in names if not is_safe_archive_member(name))
        manifest = __import__("json").loads(zf.read("_handoff_meta/MANIFEST.json").decode("utf-8"))
        expected = set(REQUIRED_ANALYST_PATHS) | required_meta
        expected.update(item["archive_path"] for item in manifest.get("current_evidence", {}).get("copied", []))
        missing = sorted(expected - names)
        hash_mismatches: list[str] = []
        for item in manifest.get("files", []):
            path = str(item["path"])
            if path not in names:
                continue
            actual = hashlib.sha256(zf.read(path)).hexdigest()
            if actual != item["sha256"]:
                hash_mismatches.append(path)
        forbidden = sorted(
            name
            for name in names
            if not name.startswith("_handoff_meta/") and _should_exclude_from_analyst_handoff(name)
        )
    status = "ok" if not unsafe_members and not missing and not hash_mismatches and not forbidden else "failed"
    return {
        "status": status,
        "missing_paths": missing,
        "unsafe_members": unsafe_members,
        "hash_mismatches": hash_mismatches,
        "forbidden_members": forbidden,
    }


def build_dev_handoff(
    *,
    out_dir: Path = HANDOFF_DIR,
    include_tiny_fixtures: bool = False,
    evidence_root: Path = PROJECT_ROOT,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    operation_id = f"OP-{timestamp()}-export-analyst"
    with __import__("tempfile").TemporaryDirectory(prefix="adlog-dev-handoff-") as tmp:
        staging = Path(tmp) / "adlog-dev-handoff"
        staging.mkdir(parents=True, exist_ok=True)
        copied = copy_tree_filtered(
            PROJECT_ROOT,
            staging,
            include_roots=INCLUDE_ROOTS,
            exclude=_should_exclude_from_analyst_handoff,
        )
        meta = staging / "_handoff_meta"
        meta.mkdir(parents=True, exist_ok=True)
        current_evidence = _copy_current_evidence(
            meta,
            evidence_root=evidence_root,
        )
        if current_evidence["missing"]:
            raise RuntimeError(
                "Required current handoff evidence is missing: "
                f"{current_evidence['missing']}"
            )
        fixture_files: list[str] = []
        if include_tiny_fixtures:
            fixture_files = _write_tiny_fixtures(meta)
        write_text(meta / "ENV_REDACTED.txt", redact_env_file(PROJECT_ROOT / ".env"))
        write_text(meta / "DB_SCHEMA.sql", _db_schema_text())
        write_text(meta / "FILE_TREE.txt", "".join(f"{item['path']}\n" for item in copied))
        write_text(
            meta / "ANALYST_ENTRYPOINT.md",
            "# Передача проекта SLI аналитику и разработчику\n\n"
            "Архив содержит исходный код, документацию, "
            "средства приёмки и небольшой набор актуальных технических доказательств. "
            "Рабочие события, базы данных, RAW, журналы, отчёты, резервные копии и `.env` исключены.\n\n"
            "## Порядок чтения\n\n"
            "1. `README.md` описывает продукт и установку.\n"
            "2. `CONTRIBUTING.md` описывает участие в разработке.\n"
            "3. `_handoff_meta/evidence/` — выбранные подтверждения текущего состояния.\n\n"
            "`_handoff_meta/DB_SCHEMA.sql` — копия действующего PostgreSQL schema "
            "contract из `config/postgres_schema.sql`; последовательные миграции "
            "находятся в `config/postgres_migrations/`. Исторический SQLite schema "
            "не является runtime-контрактом.\n\n"
            "## Текущая граница работ\n\n"
            "Пакет содержит исходники и материалы для анализа. "
            "Для действий с runtime и PostgreSQL/ClickHouse требуется отдельное разрешение. "
            "Выбранные подтверждения текущего этапа находятся "
            "в `_handoff_meta/evidence/`.\n\n"
            "## Рабочие области\n\n"
            "- Канонический React/TypeScript/Vite-код: `frontend/src`.\n"
            "- `web/app/react` — воспроизводимый build artifact и в handoff не включается.\n"
            "- В `web/app` включаются отдельные активные login assets и опубликованная "
            "React-сборка.\n"
            "- Сервер и API: `server/`.\n"
            "- Сценарии эксплуатации и обслуживания: `scripts/` и `tools/`.\n"
            "- Сборка интерфейса: из `frontend/` выполнить `npm ci`, `npm run lint`, "
            "`npm test -- --run`, `npm run build`.\n\n"
            "Если требуются реальные события, состояние процессов или снимок рабочего отчёта, "
            "нужно запросить отдельный диагностический пакет: source handoff их не подменяет.\n",
        )
        write_text(meta / "REPRODUCTION_NOTES.md", "См. `ANALYST_ENTRYPOINT.md`.\n")
        validation = _validate_copied_files(copied, staging)
        manifest = {
            "package_type": "DEV_HANDOFF",
            "handoff_type": "ANALYST_SOURCE_HANDOFF",
            "audience": ["product_analyst", "developer"],
            "handoff_scope": "source_rules_reference_acceptance_and_curated_stage7_stage8_stage9_stage10_evidence",
            "project": "ad_log_reports",
            "operation_id": operation_id,
            **basic_project_snapshot(),
            "include_tiny_fixtures": include_tiny_fixtures,
            "fixture_files": fixture_files,
            "current_evidence": current_evidence,
            "database_schema": {
                "backend": "postgresql",
                "source_path": "config/postgres_schema.sql",
                "archive_path": "_handoff_meta/DB_SCHEMA.sql",
                "migrations_path": "config/postgres_migrations/",
            },
            "files_count": len(copied),
            "files": copied,
            "validation": validation,
            "excluded_runtime": [
                "data/", ".env", ".venv/", "*.sqlite", "*.jsonl", "*.log", "*.zip",
                "*.pem", "*.key", "*.pfx", "*.p12",
                "tools/**/bin/", "tools/**/obj/", "*/bin/*", "*/obj/*", "*.dll", "*.pdb", "*.exe"
            ],
        }
        if validation["status"] != "ok":
            raise RuntimeError(f"Developer handoff validation failed: {validation}")
        write_json(meta / "MANIFEST.json", manifest)
        # Scan after the last metadata write as well as copied source files.
        secret_matches = _find_configured_secret_matches(staging)
        if secret_matches:
            raise RuntimeError(f"Developer handoff contains configured secrets: {secret_matches}")
        zip_path = out_dir / f"adlog-analyst-handoff-{timestamp()}.zip"
        zip_dir(staging, zip_path)
    archive_validation = _verify_archive(zip_path)
    if archive_validation["status"] != "ok":
        raise RuntimeError(f"Analyst handoff archive validation failed: {archive_validation}")
    result = {
        "status": "ok",
        "operation_id": operation_id,
        "zip_path": str(zip_path),
        "zip_size": zip_path.stat().st_size,
        "zip_sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "files_count": len(copied),
        "validation": validation,
        "archive_validation": archive_validation,
        "evidence_files_count": len(current_evidence["copied"]),
        "missing_evidence": current_evidence["missing"],
    }
    audit_action("export_analyst_handoff", "completed", operation_id=operation_id, zip_path=str(zip_path), files_count=len(copied))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Create analyst/developer source handoff without runtime data.")
    parser.add_argument("--out", type=Path, default=HANDOFF_DIR, help="Output directory")
    parser.add_argument("--include-tiny-fixtures", action="store_true", help="Include small synthetic JSONL fixtures")
    parser.add_argument("--json", action="store_true", help="Print JSON result")
    args = parser.parse_args()
    result = build_dev_handoff(out_dir=args.out, include_tiny_fixtures=args.include_tiny_fixtures)
    if args.json:
        import json
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Analyst/developer handoff created: {result['zip_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
