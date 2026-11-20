from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

from server.sli.access import auth


@pytest.fixture
def cursor(monkeypatch):
    cursor = Mock()
    connection = Mock(cursor=lambda: nullcontext(cursor))
    monkeypatch.setattr(auth, "_connect", lambda: nullcontext(connection))
    monkeypatch.setattr(auth, "PASSWORD_HASHER", Mock(verify=lambda *_: True, check_needs_rehash=lambda *_: False))
    # This file tests the previous-login baseline; account budgets have their
    # own transaction/concurrency tests.
    monkeypatch.setattr(auth, "AccountAttempt", Mock())
    cursor.fetchone.return_value = {"id": 11, "username": "synthetic-user", "role": "viewer", "is_active": True, "password_hash": "synthetic-hash"}
    return cursor


def test_migration_only_adds_nullable_baseline_and_records_version():
    sql = Path("config/postgres_migrations/223_home_previous_login.sql").read_text("utf-8")
    assert "alter table public.auth_users add column previous_login_at timestamptz;" in sql
    assert "version=222 and name='sigma_attack_coverage'" in sql
    assert "version>=223" in sql and "pg_advisory_xact_lock" in sql
    assert "values(223,'home_previous_login')" in sql
    assert "\nbegin;" in sql and sql.rstrip().endswith("commit;")
    assert "update auth_users" not in sql and "default" not in sql


def test_auth_schema_requires_the_versioned_baseline(monkeypatch):
    from server.sli.ops import postgres_schema_guard

    guard = Mock()
    monkeypatch.setattr(postgres_schema_guard, "require_table_columns", guard)
    auth.ensure_auth_schema()
    guard.assert_any_call("auth_users", ("previous_login_at",), minimum_schema_version=223)
    guard.assert_any_call("auth_users", ("is_service",), minimum_schema_version=280)


def test_successful_login_atomically_preserves_previous_login(cursor):
    principal = auth.authenticate_password("synthetic-user", "synthetic-input")
    assert principal["id"] == 11
    assert cursor.execute.call_args.args == (
        "update auth_users set previous_login_at=last_login_at, last_login_at=now() where id=%s", (11,),
    )


def test_failed_login_does_not_advance_baseline(cursor, monkeypatch):
    monkeypatch.setattr(auth.PASSWORD_HASHER, "verify", lambda *_: False)
    assert auth.authenticate_password("synthetic-user", "synthetic-input") is None
    assert len(cursor.execute.call_args_list) == 1


def test_baseline_reader_returns_stored_time_or_unknown(cursor):
    moment = datetime(2026, 10, 16, 18, 5, tzinfo=timezone.utc)
    cursor.fetchone.return_value = {"previous_login_at": moment}
    assert auth.previous_login({"type": "session", "id": 11}) == moment.isoformat()
    assert cursor.execute.call_args.args[1] == (11,)
    cursor.fetchone.return_value = {"previous_login_at": None}
    assert auth.previous_login({"type": "session", "id": 11}) is None
    cursor.execute.reset_mock()
    assert auth.previous_login({"type": "local"}) is None
    assert auth.previous_login({"type": "api_key", "id": 11}) is None
    cursor.execute.assert_not_called()
