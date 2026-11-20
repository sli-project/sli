from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from scripts.maintenance import export_dev_handoff
from scripts.maintenance.bundle_common import (
    redact_env_value,
    should_exclude_from_dev_handoff,
)
from scripts.maintenance.capture_report import REPORTS
from scripts.maintenance.export_dev_handoff import _db_schema_text, build_dev_handoff


def test_redact_env_value_hides_secrets() -> None:
    assert redact_env_value("OPENAI_API_KEY", "abc") == "<REDACTED>"
    assert redact_env_value("ADLOG_SERVER_PORT", "8080") == "8080"


def test_dev_handoff_excludes_runtime_patterns() -> None:
    assert should_exclude_from_dev_handoff("data/processed/ad_logs.sqlite") is True
    assert should_exclude_from_dev_handoff("data/raw/pilot/DC1/Security.jsonl") is True
    assert should_exclude_from_dev_handoff(".env") is True
    assert should_exclude_from_dev_handoff("config/domain_controllers.json") is True
    assert should_exclude_from_dev_handoff("config/private.pem") is True
    assert should_exclude_from_dev_handoff("config/private.key") is True
    assert should_exclude_from_dev_handoff("config/identity.pfx") is True
    assert should_exclude_from_dev_handoff("config/identity.p12") is True
    assert should_exclude_from_dev_handoff("server/sli/core/paths.py") is False


def test_export_dev_handoff_creates_safe_zip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_TOOLKIT_DISABLE_AUDIT", "1")
    evidence_rel = "artifacts/test/evidence/synthetic-acceptance.json"
    evidence = tmp_path / evidence_rel
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"synthetic"}\n', encoding="utf-8")
    monkeypatch.setattr(
        export_dev_handoff,
        "CURRENT_EVIDENCE_FILES",
        (evidence_rel,),
    )
    result = build_dev_handoff(
        out_dir=tmp_path,
        include_tiny_fixtures=True,
        evidence_root=tmp_path,
    )
    zip_path = Path(result["zip_path"])
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as zf:
        names = set(zf.namelist())
        assert "_handoff_meta/MANIFEST.json" in names
        assert "_handoff_meta/ANALYST_ENTRYPOINT.md" in names
        assert "_handoff_meta/ENV_REDACTED.txt" in names
        assert "README.md" in names
        assert "docs/ADMIN_GUIDE.md" in names
        assert any(name.startswith("server/") for name in names)
        assert "package.json" in names
        assert "package-lock.json" in names
        assert "frontend/package-lock.json" in names
        assert "scripts/ad_context/collect_ad_inventory_evidence.ps1" in names
        assert "requirements.lock.txt" in names
        assert "config/postgres_schema.sql" in names
        assert "config/plugin_architecture_v1.json" in names
        assert "_handoff_meta/evidence/synthetic-acceptance.json" in names
        assert "_handoff_meta/evidence/purge_before_20260726_result.json" not in names
        assert not any(name.startswith("data/") for name in names)
        assert ".env" not in names
        entrypoint = zf.read("_handoff_meta/ANALYST_ENTRYPOINT.md").decode("utf-8")
        assert "Этап 7 сначала обсуждается" not in entrypoint
        assert "CONTRIBUTING.md" in entrypoint
        assert "config/postgres_schema.sql" in entrypoint
        schema = zf.read("_handoff_meta/DB_SCHEMA.sql").decode("utf-8")
        assert "pragma foreign_keys" not in schema.lower()
        assert "PostgreSQL" in schema or "postgres" in schema.lower()
        manifest = json.loads(zf.read("_handoff_meta/MANIFEST.json").decode("utf-8"))
        assert manifest["package_type"] == "DEV_HANDOFF"
        assert manifest["handoff_type"] == "ANALYST_SOURCE_HANDOFF"
        assert manifest["audience"] == ["product_analyst", "developer"]
        assert manifest["runtime_data_included"] is False
        assert manifest["database_schema"]["backend"] == "postgresql"
        assert manifest["database_schema"]["source_path"] == "config/postgres_schema.sql"
        assert manifest["current_evidence"]["missing"] == []
        copied_evidence = manifest["current_evidence"]["copied"]
        assert copied_evidence[0]["source_path"] == evidence_rel
        assert len(copied_evidence[0]["sha256"]) == 64
        assert manifest["validation"]["missing_required_paths"] == []
        assert manifest["validation"]["configured_secret_matches"] == []
        assert result["archive_validation"]["status"] == "ok"


def test_dev_handoff_uses_postgresql_schema_contract() -> None:
    schema = _db_schema_text()
    assert "pragma foreign_keys" not in schema.lower()
    assert "PostgreSQL" in schema or "postgres" in schema.lower()


@pytest.mark.parametrize("include_frontend_lockfile", [False, True])
def test_dev_handoff_requires_frontend_npm_lockfile(
    tmp_path: Path, monkeypatch, include_frontend_lockfile: bool,
) -> None:
    monkeypatch.setattr(export_dev_handoff, "PROJECT_ROOT", tmp_path)
    copied = [
        {"path": path}
        for path in export_dev_handoff.REQUIRED_ANALYST_PATHS
        if path != "frontend/package-lock.json"
    ]
    if include_frontend_lockfile:
        copied.append({"path": "frontend/package-lock.json"})

    validation = export_dev_handoff._validate_copied_files(copied, tmp_path)

    assert validation["status"] == ("ok" if include_frontend_lockfile else "failed")
    assert validation["missing_required_paths"] == (
        [] if include_frontend_lockfile else ["frontend/package-lock.json"]
    )


def test_export_dev_handoff_fails_when_current_evidence_is_missing(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("ADLOG_TOOLKIT_DISABLE_AUDIT", "1")
    monkeypatch.setattr(
        export_dev_handoff,
        "CURRENT_EVIDENCE_FILES",
        ("artifacts/stage9/evidence/does-not-exist.json",),
    )
    with pytest.raises(RuntimeError, match="Required current handoff evidence is missing"):
        build_dev_handoff(out_dir=tmp_path)


def test_known_report_names_are_registered() -> None:
    assert "collector-health" in REPORTS
    assert "system-health" in REPORTS


def test_dev_handoff_excludes_nested_build_artifacts() -> None:
    assert should_exclude_from_dev_handoff("tools/sqlite_initializer/bin/Release/app.dll") is True
    assert should_exclude_from_dev_handoff("tools/sqlite_initializer/obj/project.assets.json") is True
    assert should_exclude_from_dev_handoff("tools/sqlite_initializer/runtimes/win/native/sqlite.dll") is True
    assert should_exclude_from_dev_handoff("tools/example_source/Program.cs") is False


def test_analyst_handoff_has_one_canonical_frontend_source_tree() -> None:
    from scripts.maintenance.export_dev_handoff import (
        _should_exclude_from_analyst_handoff,
    )

    assert _should_exclude_from_analyst_handoff("frontend/src/main.tsx") is False
    assert _should_exclude_from_analyst_handoff("frontend/.sli-v4-stage6-r28/index.html") is True
    assert _should_exclude_from_analyst_handoff("web/app/react/index.html") is True
    assert _should_exclude_from_analyst_handoff("frontend/package-lock.json") is False


def test_export_dev_handoff_excludes_bin_obj_from_zip(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_TOOLKIT_DISABLE_AUDIT", "1")
    evidence_rel = "artifacts/test/evidence/synthetic-acceptance.json"
    evidence = tmp_path / evidence_rel
    evidence.parent.mkdir(parents=True)
    evidence.write_text('{"status":"synthetic"}\n', encoding="utf-8")
    monkeypatch.setattr(
        export_dev_handoff,
        "CURRENT_EVIDENCE_FILES",
        (evidence_rel,),
    )
    result = build_dev_handoff(out_dir=tmp_path, evidence_root=tmp_path)
    with zipfile.ZipFile(Path(result["zip_path"])) as zf:
        names = zf.namelist()
        assert not any("/bin/" in name or "/obj/" in name for name in names)
        assert not any(name.endswith((".dll", ".pdb", ".exe")) for name in names)
        manifest = json.loads(zf.read("_handoff_meta/MANIFEST.json").decode("utf-8"))
        assert manifest["validation"]["status"] == "ok"
