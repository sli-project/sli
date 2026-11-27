#!/usr/bin/env python3
"""W01 additive schema, runtime ACL and revision constraints on disposable PG."""
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/249_watch_registry.sql"
SQL = PATH.read_text("utf-8")


def test_watch_migration_is_additive_and_has_explicit_main_predecessor():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((249, "watch_registry")) - 1] == (248, "entity_context_history_reads")
    assert list(PATH.parent.glob("249_*.sql")) == [PATH]
    assert "version=248 and name='entity_context_history_reads'" in SQL and "version>=249" in SQL
    assert "grant update(valid_to)" in SQL and "grant select,insert" in SQL
    assert "watch_current_account" in SQL and "watch_interval_immutable" in SQL
    assert "'watch.manage'" in SQL and "'watch.registry'" in SQL
    assert "grant delete" not in SQL and "notification_outbox" not in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("markers", [
    [(244, "account_decoy")],
    [(247, "decoy_delivery_context")],
    [(247, "entity_context_history_reads")],
    [(248, "decoy_delivery_context")],
    [(248, "entity_context_history_reads"), (249, "watch_registry")],
    [(248, "entity_context_history_reads"), (250, "synthetic_later_migration")],
])
def test_watch_migration_rejects_inexact_predecessor_or_later_marker(markers):
    import psycopg

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        if not conn.execute("select 1 from pg_roles where rolname='adlog_storage_owner'").fetchone():
            conn.execute("create role adlog_storage_owner nologin")
        conn.execute("create table schema_migrations(version integer primary key,name text)")
        with conn.cursor() as cur:
            cur.executemany("insert into schema_migrations values(%s,%s)", markers)
        with pytest.raises(psycopg.errors.RaiseException, match="migration 249 prerequisites failed"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select to_regclass('public.watch_entry_versions')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations").fetchone()[0] == len(markers)
