"""Snapshot publication uses a dedicated worker login, never the API login."""
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from server.sli.agents import snapshot_publication_connection as publication


@pytest.mark.parametrize("file_secret", [False, True])
def test_snapshot_worker_connection_uses_its_own_credentials(tmp_path, monkeypatch, file_secret):
    import psycopg

    calls, statements = [], []
    connection = SimpleNamespace(cursor=lambda: nullcontext(SimpleNamespace(execute=statements.append)))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: calls.append(kwargs) or connection)
    monkeypatch.setattr(publication, "load_config", lambda: SimpleNamespace(postgres_connect_timeout_seconds=2))
    monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_DSN", "host=database dbname=synthetic user=synthetic_worker")
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN_FILE", raising=False)
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD", raising=False)
    if file_secret:
        secret = tmp_path / "worker-secret"
        secret.write_text("synthetic-password\n", encoding="utf-8")
        monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE", str(secret))
    else:
        monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD", "synthetic-password")
    monkeypatch.setattr(publication, "_import_connect", lambda: pytest.fail("dedicated login must take precedence"))

    assert publication.snapshot_import_connect() is connection
    assert calls[0]["user"] == "synthetic_worker"
    assert calls[0]["password"] == "synthetic-password"
    assert calls[0]["connect_timeout"] == 2
    assert calls[0]["application_name"] == "adlog_context_snapshot_import"
    assert statements == ["set role adlog_context_worker"]


def test_snapshot_worker_retains_legacy_connection_when_not_configured(monkeypatch):
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN", raising=False)
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN_FILE", raising=False)
    connection = object()
    monkeypatch.setattr(publication, "_import_connect", lambda: connection)
    assert publication.snapshot_import_connect() is connection


def test_snapshot_worker_configured_secret_fails_closed(monkeypatch):
    import psycopg

    monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_DSN", "host=database user=synthetic_worker")
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN_FILE", raising=False)
    monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE", "")
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD", raising=False)
    monkeypatch.setattr(publication, "_import_connect", lambda: pytest.fail("must not fall back to admin"))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: pytest.fail("invalid secret must not connect"))
    with pytest.raises(ValueError, match="secret file is unreadable or invalid"):
        publication.snapshot_import_connect()


def test_snapshot_worker_empty_dsn_does_not_fall_back_to_admin(monkeypatch):
    import psycopg

    monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_DSN", "")
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN_FILE", raising=False)
    monkeypatch.setattr(publication, "_import_connect", lambda: pytest.fail("must not fall back to admin"))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: pytest.fail("empty DSN must not connect"))
    with pytest.raises(RuntimeError, match="worker connection is required"):
        publication.snapshot_import_connect()


def test_snapshot_worker_closes_connection_if_role_selection_fails(monkeypatch):
    import psycopg

    closed = []
    def execute(statement):
        raise RuntimeError("synthetic-private-diagnostic")
    connection = SimpleNamespace(cursor=lambda: nullcontext(SimpleNamespace(execute=execute)), close=lambda: closed.append(True))
    monkeypatch.setenv("ADLOG_AD_CONTEXT_WORKER_DSN", "host=database user=synthetic_worker")
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_DSN_FILE", raising=False)
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("ADLOG_AD_CONTEXT_WORKER_PASSWORD", raising=False)
    monkeypatch.setattr(publication, "load_config", lambda: SimpleNamespace(postgres_connect_timeout_seconds=2))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: connection)
    with pytest.raises(RuntimeError):
        publication.snapshot_import_connect()
    assert closed == [True]
