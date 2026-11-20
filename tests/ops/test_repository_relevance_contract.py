from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_environment_template_is_postgres_only_and_safe_by_default() -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")

    assert "ADLOG_DB_BACKEND=postgres" in text
    assert "ADLOG_PG_DSN=" in text
    assert "ADLOG_DB_PATH=" not in text
    assert "ADLOG_SQLITE_" not in text
    assert "ADLOG_DISABLE_COLLECTION=1" in text
    assert "ADLOG_DISABLE_SCHEDULER=1" in text
    assert "ADLOG_CONTINUOUS_RECOVERY=false" in text
    assert "ADLOG_SECURITY_MAX_EVENTS=50000" in text
    assert "ADLOG_SECURITY_RECOVERY_MAX_LIMIT=50000" in text
    assert "EXAMPLE" not in text
    assert "S-1-5-21-" not in text


def test_yaml_example_has_one_retention_section_and_no_sqlite_runtime_path() -> None:
    text = (ROOT / "config" / "adlog_config.example.yaml").read_text(encoding="utf-8")

    assert text.count("\nretention:\n") == 1
    assert "backend: postgres" in text
    assert "ad_logs.sqlite" not in text
    assert "sqlite_backup_days" not in text


def test_obsolete_duplicate_react_root_is_not_active() -> None:
    assert not (ROOT / "web" / "react").exists()


def test_active_login_assets_do_not_keep_duplicate_scene_files() -> None:
    active = ROOT / "web" / "app" / "assets" / "sli-login"
    assert {path.name for path in active.glob("*.svg")} == {
        "collector-server.svg",
        "feature-brain.svg",
        "feature-eye.svg",
        "feature-shield.svg",
        "sli-logo.svg",
    }
    # The parallel scene directory is retired, not merely unused.
    assert not (ROOT / "web" / "app" / "assets" / "sli-login-clean").exists()
