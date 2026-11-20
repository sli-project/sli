from __future__ import annotations

import os
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from tests.conftest import (
    isolated_postgres_integration_database,
    postgres_semantic_worker_dsn,
)
from tests.postgres_integration_guard import assert_disposable_database


@pytest.mark.parametrize("mapping_row", [False, True])
@pytest.mark.parametrize("name,encoding,error", [
    ("sli_test_fixture", "UTF8", None),
    ("runtime", "UTF8", "non-disposable"),
    ("sli_test_fixture", "SQL_ASCII", "requires UTF8"),
])
def test_database_guard_accepts_cursor_row_factories(mapping_row, name, encoding, error):
    identity = {"name": name, "port": 5432, "encoding": encoding}

    class Cursor:
        description = tuple(SimpleNamespace(name=key) for key in identity)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement):
            assert "current_database()" in statement

        def fetchone(self):
            return identity if mapping_row else tuple(identity.values())

    connection = SimpleNamespace(cursor=Cursor)
    if error:
        with pytest.raises(AssertionError, match=error):
            assert_disposable_database(connection)
    else:
        assert assert_disposable_database(connection) == identity


@pytest.mark.parametrize("empty", [False, True])
@pytest.mark.parametrize("keyword_dsn", [False, True])
@pytest.mark.parametrize("body_fails", [False, True])
def test_integration_clone_selects_template_seeds_and_restores_environment(
    monkeypatch, request, empty, keyword_dsn, body_fails,
):
    migrated = "postgresql://postgres@127.0.0.1:5432/sli_test_ci"
    blank = "postgresql://postgres@127.0.0.1:5432/sli_test_empty_ci"
    if keyword_dsn:
        migrated, blank = make_conninfo(migrated), make_conninfo(blank)
    monkeypatch.setenv("ADLOG_TEST_PG_DSN", migrated)
    monkeypatch.setenv("ADLOG_TEST_PG_EMPTY_DSN", blank)
    monkeypatch.setenv("ADLOG_PG_DSN", "unreachable-runtime")
    statements = []
    connections = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement, parameters=None):
            rendered = statement if isinstance(statement, str) else statement.as_string(None)
            statements.append((rendered, parameters))

    def connect(dsn, **kwargs):
        connections.append(conninfo_to_dict(dsn))
        assert kwargs == {"autocommit": True}
        return Connection()

    monkeypatch.setattr(psycopg, "connect", connect)
    fake_request = SimpleNamespace(node=SimpleNamespace(
        get_closest_marker=lambda name: True if name == "postgres_integration" or (empty and name == "postgres_empty") else None,
    ))
    fixture = isolated_postgres_integration_database.__wrapped__(fake_request)
    request.addfinalizer(fixture.close)
    next(fixture)
    clone_dsn = os.environ["ADLOG_TEST_PG_DSN"]
    clone_name = conninfo_to_dict(clone_dsn)["dbname"]
    assert clone_name.startswith("sli_test_")
    assert clone_name not in ("sli_test_ci", "sli_test_empty_ci")
    assert os.environ["ADLOG_PG_DSN"] == clone_dsn
    expected_template = "sli_test_empty_ci" if empty else "sli_test_ci"
    assert statements[0][0] == f'create database "{clone_name}" with template "{expected_template}"'
    seeded = any("insert into event_catalog_revisions" in sql for sql, _ in statements)
    assert seeded is not empty
    assert all(connection["dbname"] in ("postgres", clone_name) for connection in connections)
    if body_fails:
        with pytest.raises(RuntimeError, match="synthetic failure"):
            fixture.throw(RuntimeError("synthetic failure"))
    else:
        with pytest.raises(StopIteration):
            next(fixture)
    assert os.environ["ADLOG_TEST_PG_DSN"] == migrated
    assert os.environ["ADLOG_PG_DSN"] == "unreachable-runtime"
    assert statements[-1][0] == f'drop database "{clone_name}"'
    assert statements[-2][1] == (clone_name,)


def test_schema_bootstrap_refuses_missing_empty_template(monkeypatch):
    monkeypatch.setenv("ADLOG_TEST_PG_DSN", "postgresql://postgres@127.0.0.1/sli_test_ci")
    monkeypatch.delenv("ADLOG_TEST_PG_EMPTY_DSN", raising=False)
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    request = SimpleNamespace(node=SimpleNamespace(
        get_closest_marker=lambda name: True if name in ("postgres_integration", "postgres_empty") else None,
    ))
    fixture = isolated_postgres_integration_database.__wrapped__(request)
    with pytest.raises(pytest.fail.Exception, match="ADLOG_TEST_PG_EMPTY_DSN"):
        next(fixture)


def test_integration_clone_refuses_runtime_template(monkeypatch):
    monkeypatch.setenv("ADLOG_TEST_PG_DSN", "postgresql://postgres@127.0.0.1/runtime")
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    request = SimpleNamespace(node=SimpleNamespace(
        get_closest_marker=lambda name: True if name == "postgres_integration" else None,
    ))
    fixture = isolated_postgres_integration_database.__wrapped__(request)
    with pytest.raises(pytest.fail.Exception, match="sli_test_ namespace"):
        next(fixture)


@pytest.mark.parametrize("body_fails", [False, True])
def test_worker_login_is_non_elevated_and_removed_after_use(monkeypatch, request, body_fails):
    dsn = "postgresql://postgres@127.0.0.1/sli_test_ci"
    monkeypatch.setenv("ADLOG_TEST_PG_DSN", dsn)
    monkeypatch.setattr("secrets.token_urlsafe", lambda _length: "synthetic-test-password")
    statements = []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, statement, parameters=None):
            rendered = statement if isinstance(statement, str) else statement.as_string(None)
            statements.append((rendered, parameters))

    def connect(actual_dsn, **kwargs):
        assert actual_dsn == dsn
        assert kwargs == {"autocommit": True}
        return Connection()

    monkeypatch.setattr(psycopg, "connect", connect)
    fixture = postgres_semantic_worker_dsn.__wrapped__(None)
    request.addfinalizer(fixture.close)
    worker = conninfo_to_dict(next(fixture))
    role = worker["user"]
    assert role.startswith("sli_test_worker_")
    assert worker["dbname"] == "sli_test_ci"
    assert worker["password"] == "synthetic-test-password"
    assert statements[0][0].endswith(
        "nosuperuser nocreatedb nocreaterole noinherit nobypassrls noreplication"
    )
    assert statements[1][0] == f'grant adlog_semantic_worker to "{role}"'
    if body_fails:
        with pytest.raises(RuntimeError, match="synthetic failure"):
            fixture.throw(RuntimeError("synthetic failure"))
    else:
        with pytest.raises(StopIteration):
            next(fixture)
    assert statements[-2][1] == (role,)
    assert statements[-1][0] == f'drop role "{role}"'


def test_worker_login_skips_without_disposable_database(monkeypatch):
    monkeypatch.delenv("ADLOG_TEST_PG_DSN", raising=False)
    monkeypatch.setattr(psycopg, "connect", lambda *_args, **_kwargs: pytest.fail("must not connect"))
    fixture = postgres_semantic_worker_dsn.__wrapped__(None)
    with pytest.raises(pytest.skip.Exception, match="ADLOG_TEST_PG_DSN"):
        next(fixture)
