from __future__ import annotations

from pathlib import Path

import pytest


def test_explicit_db_path_is_refused_even_when_env_is_postgres(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_DB_BACKEND", "postgres")
    monkeypatch.setenv("ADLOG_PG_DSN", "postgresql://example/should-not-be-used")

    from server.sli.core.database import query_rows

    with pytest.raises(TypeError, match="db_path"):
        query_rows("select count(*) as count from events", db_path=tmp_path / "unit.db")
    assert not (tmp_path / "unit.db").exists()


def test_safe_pytest_env_uses_postgres_with_an_unreachable_dsn() -> None:
    from urllib.parse import urlparse

    from scripts.maintenance.bundle_common import safe_pytest_env

    env = safe_pytest_env()
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert urlparse(env["ADLOG_PG_DSN"]).hostname.endswith(".invalid")
    assert env["ADLOG_DISABLE_SCHEDULER"] == "1"
    assert env["ADLOG_CONTINUOUS_RECOVERY"] == "false"


def test_sanitized_pytest_env_drops_poisoned_production_settings() -> None:
    from scripts.maintenance.bundle_common import (
        PYTEST_UNREACHABLE_PG_DSN,
        sanitized_pytest_env,
    )

    poisoned = {
        "PATH": "trusted-path",
        "ADLOG_DB_BACKEND": "postgres",
        "ADLOG_PG_DSN": "postgresql://production/secret",
        "ADLOG_ENABLE_POSTGRES_COLLECTION": "1",
        "ADLOG_DC_CONNECT_MAP": "DC1=production",
        "PGPASSWORD": "secret",
        "PGHOST": "production-db",
        "PYTHONPATH": "C:/untrusted/injection",
        "PYTEST_ADDOPTS": "--lf",
    }

    env = sanitized_pytest_env(poisoned)

    assert env["PATH"] == "trusted-path"
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert env["ADLOG_PG_DSN"] == PYTEST_UNREACHABLE_PG_DSN
    assert env["ADLOG_DISABLE_SCHEDULER"] == "1"
    assert env["ADLOG_ENABLE_POSTGRES_COLLECTION"] == ""
    assert "ADLOG_DC_CONNECT_MAP" not in env
    assert "PGPASSWORD" not in env
    assert "PGHOST" not in env
    assert "PYTHONPATH" not in env
    assert "--lf" not in env["PYTEST_ADDOPTS"]
