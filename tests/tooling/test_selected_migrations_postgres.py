"""Selected-migration guard tests run only in the owned disposable PG CI lane."""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.maintenance import apply_selected_migrations as tool

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def disposable_connection(tmp_path):
    # tests/conftest.py clones the explicitly configured empty template per test.
    dsn = os.getenv("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("owned disposable PostgreSQL DSN is not configured")
    psql = shutil.which("psql")
    if not psql:
        pytest.skip("psql is not installed")
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn)
    assert parts["dbname"].startswith("sli_test_")
    parts.setdefault("password", "synthetic_unused_trust_password")
    with psycopg.connect(**parts, autocommit=True) as conn:
        conn.execute("create table schema_migrations(version integer primary key, name text)")
    migration = tmp_path / "synthetic.sql"
    migration.write_text(
        "BEGIN; CREATE TABLE selected_migration_probe(pid integer); "
        "INSERT INTO selected_migration_probe VALUES (pg_backend_pid()); "
        "INSERT INTO schema_migrations VALUES (999999, 'synthetic'); COMMIT;\n",
        encoding="utf-8",
    )
    args = SimpleNamespace(action="apply", bin_dir=Path(psql).parent)
    yield parts, args, {999999: SimpleNamespace(path=migration)}


def test_service_hostaddr_write_and_readback_share_contract(disposable_connection, tmp_path, monkeypatch):
    import psycopg

    parts, args, inventory = disposable_connection
    # The wrong DNS name must never be resolved in place of explicit hostaddr.
    parts["hostaddr"] = parts.get("hostaddr") or parts["host"]
    parts["host"] = "unresolvable.synthetic.invalid"
    service = tmp_path / "input-service.conf"
    service.write_text("[synthetic]\n" + "".join(f"{key}={value}\n" for key, value in parts.items()),
                       encoding="utf-8")
    monkeypatch.setenv("PGSERVICEFILE", str(service))
    with tool._connection_contract({"service": "synthetic", "password": parts["password"]}) as contract:
        assert tool._run_selected(args, [999999], inventory, contract) == 0
        with psycopg.connect(**contract) as conn:
            assert conn.execute("select count(*) from selected_migration_probe").fetchone()[0] == 1


def test_mismatched_write_session_cannot_execute_migration(disposable_connection, monkeypatch, capsys):
    import psycopg

    parts, args, inventory = disposable_connection
    ledger = tool._ledger

    def wrong_plan(connection, versions):
        result = ledger(connection, versions)
        result["target_identity"] = "0" * 32
        return result

    monkeypatch.setattr(tool, "_ledger", wrong_plan)
    with tool._connection_contract(parts) as contract:
        assert tool._run_selected(args, [999999], inventory, contract) == 1
        with psycopg.connect(**contract) as conn:
            assert conn.execute("select to_regclass('selected_migration_probe')").fetchone()[0] is None
            assert conn.execute("select count(*) from schema_migrations").fetchone()[0] == 0
    # The guard uses -c, whose SQL failure exits 1. ON_ERROR_STOP prevents
    # the following -f from running; exit 3 is for errors inside scripts.
    assert '"psql_exit_code": 1' in capsys.readouterr().out


def test_strict_tls_child_connection_is_not_downgraded(disposable_connection, tmp_path, monkeypatch, capsys):
    from unittest.mock import MagicMock

    import psycopg

    parts, args, inventory = disposable_connection
    real_connect = psycopg.connect
    # Capture a successful disposable connection, then require strict TLS for
    # the child path. Only the resolution connection and plan read are mocked;
    # the actual psql process must reject the frozen strict-TLS service contract.
    with real_connect(**parts) as conn:
        resolved = {item.keyword: item.val for item in conn.pgconn.info if item.val is not None}
    resolved[b"sslmode"] = b"verify-full"
    resolved[b"sslrootcert"] = str(tmp_path / "absent-ca.pem").encode()
    capture = MagicMock()
    capture.__enter__.return_value = capture
    capture.pgconn.info = [SimpleNamespace(keyword=key, val=value) for key, value in resolved.items()]
    plan_reads = []

    def planned(connection, versions):
        plan_reads.append((connection, versions))
        assert len(plan_reads) == 1, "failed psql must stop before readback"
        return {"applied": {}, "target_identity": "a" * 32}

    # Restore connection mocks before the autouse disposable-clone teardown,
    # which must reconnect with the real positional admin DSN to drop the clone.
    with monkeypatch.context() as patch:
        patch.setattr(psycopg, "connect", lambda **kwargs: capture)
        patch.setattr(tool, "_ledger", planned)
        with tool._connection_contract(parts) as contract:
            assert tool._run_selected(args, [999999], inventory, contract) == 1
    assert psycopg.connect is real_connect
    # psql exit 2 specifically proves connection failure rather than SQL/guard
    # failure (exit 1 for the -c guard) or weakened TLS success (exit 0).
    assert '\"psql_exit_code\": 2' in capsys.readouterr().out
    with real_connect(**parts) as conn:
        assert conn.execute("select to_regclass('selected_migration_probe')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations").fetchone()[0] == 0
