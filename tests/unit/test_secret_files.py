from __future__ import annotations

import os

import pytest
from psycopg.conninfo import conninfo_to_dict

from deploy.linux.sli_core.secret_files import postgres_secret_parts, secret_value


def test_file_preserves_password_spaces_and_does_not_export(tmp_path, monkeypatch):
    secret = tmp_path / "password"
    secret.write_bytes(b"  synthetic password  \r\n")
    monkeypatch.delenv("TEST_SECRET", raising=False)
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret))
    assert secret_value("TEST_SECRET") == "  synthetic password  "
    assert "TEST_SECRET" not in os.environ


def test_existing_value_and_absent_setting():
    assert secret_value("TEST_SECRET", environ={"TEST_SECRET": "synthetic"}) == "synthetic"
    assert secret_value("TEST_SECRET", environ={}) is None


def test_conflicting_value_fails_without_disclosing_value_or_path():
    with pytest.raises(ValueError) as error:
        secret_value("TEST_SECRET", environ={"TEST_SECRET": "synthetic-private", "TEST_SECRET_FILE": "/private"})
    assert str(error.value) == "TEST_SECRET: value and file are mutually exclusive"


@pytest.mark.parametrize("content", [b"", b"\r\n", b"bad\x00value", b"\xff", b"x" * 65537],
                         ids=["empty", "line_endings", "nul", "invalid_utf8", "oversized"])
def test_invalid_file_fails_closed(tmp_path, content):
    secret = tmp_path / "private"
    secret.write_bytes(content)
    with pytest.raises(ValueError, match="^TEST_SECRET: secret file is unreadable or invalid$"):
        secret_value("TEST_SECRET", environ={"TEST_SECRET_FILE": str(secret)})


@pytest.mark.parametrize("kind", ["missing", "directory", "empty_path"])
def test_unreadable_file_fails_closed(tmp_path, kind):
    filename = {"missing": str(tmp_path / "missing"), "directory": str(tmp_path), "empty_path": ""}[kind]
    with pytest.raises(ValueError, match="unreadable or invalid"):
        secret_value("TEST_SECRET", environ={"TEST_SECRET_FILE": filename})


def test_config_password_file_and_dsn_file_are_loaded_without_env_secrets(tmp_path, monkeypatch):
    password = tmp_path / "password"
    password.write_text("synthetic 'quoted' \\ value\n", encoding="utf-8")
    dsn = tmp_path / "dsn"
    dsn.write_text("host=database dbname=stand user=runtime\n", encoding="utf-8")
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    monkeypatch.delenv("ADLOG_PG_PASSWORD", raising=False)
    monkeypatch.setenv("ADLOG_PG_DSN_FILE", str(dsn))
    monkeypatch.setenv("ADLOG_PG_PASSWORD_FILE", str(password))
    parts = postgres_secret_parts("ADLOG_PG_DSN")
    assert parts["user"] == "runtime"
    assert parts["password"] == "synthetic 'quoted' \\ value"
    assert "ADLOG_PG_PASSWORD" not in os.environ
    assert "ADLOG_PG_DSN" not in os.environ


def test_missing_file_is_rejected(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("database:\n  postgres_dsn: host=database\n", encoding="utf-8")
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    monkeypatch.setenv("ADLOG_PG_DSN_FILE", str(tmp_path / "absent"))
    with pytest.raises(ValueError, match="unreadable or invalid"):
        postgres_secret_parts("ADLOG_PG_DSN")


@pytest.mark.parametrize("name", ["ADLOG_SEMANTIC_WORKER_DSN", "ADLOG_STORAGE_V2_WORKER_DSN"])
def test_worker_dsn_and_separate_password_files(tmp_path, monkeypatch, name):
    password_name = name.removesuffix("_DSN") + "_PASSWORD"
    dsn = tmp_path / "dsn"
    password = tmp_path / "password"
    dsn.write_text("host=database dbname=stand user=worker\n", encoding="utf-8")
    password.write_text(" synthetic 'quoted' \\ password \n", encoding="utf-8")
    monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv(password_name, raising=False)
    monkeypatch.setenv(name + "_FILE", str(dsn))
    monkeypatch.setenv(password_name + "_FILE", str(password))
    parts = postgres_secret_parts(name)
    assert parts == {"host": "database", "dbname": "stand", "user": "worker",
                     "password": " synthetic 'quoted' \\ password "}
    assert name not in os.environ and password_name not in os.environ


def test_worker_password_file_cannot_override_password_in_dsn(tmp_path, monkeypatch):
    password = tmp_path / "password"
    password.write_text("synthetic-only", encoding="utf-8")
    monkeypatch.setenv("ADLOG_SEMANTIC_WORKER_DSN", "host=database password=synthetic-only")
    monkeypatch.setenv("ADLOG_SEMANTIC_WORKER_PASSWORD_FILE", str(password))
    with pytest.raises(ValueError, match="mutually exclusive"):
        postgres_secret_parts("ADLOG_SEMANTIC_WORKER_DSN")
