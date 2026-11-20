#!/usr/bin/env python3
"""W01 additive schema, runtime ACL and revision constraints on disposable PG."""
import json
import os
from datetime import timedelta
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core import watch_entries as registry
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_watch_entries import ENTRY, IDENTITY, NOW, PRINCIPAL, access, body

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


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_watch_sql_applies_and_preserves_unique_current_account_and_history():
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        for role in ("adlog_storage_owner", "adlog_user"):
            if not conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(role)))
        conn.execute("""
            grant usage,create on schema public to adlog_storage_owner;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(248,'entity_context_history_reads');
            grant select,insert on schema_migrations to adlog_storage_owner;
            create table access_capabilities(id bigserial primary key,capability_key text,label text,description text);
            create table access_packages(id bigint primary key,package_key text);
            insert into access_packages values(1,'access_admin');
            create table access_package_capabilities(package_id bigint,capability_id bigint);
            create table report_datasets_v4(id bigserial primary key,dataset_key text,version integer,name text,
                object_type text,fields_json jsonb,filters_json jsonb,actions_json jsonb,status text);
            create table report_registry_v4(report_key text,version integer,name text,owner_name text,purpose text,
                dataset_id bigint,definition_json jsonb,sensitivity text,status text,published_at timestamptz);
            create table access_package_reports(package_id bigint,report_key text,field_categories text[],allowed_actions text[],scope_json jsonb);
        """)
        conn.execute(SQL)
        assert conn.execute("select name from schema_migrations where version=249").fetchone()["name"] == "watch_registry"
        conn.execute("set role adlog_user")
        insert = """insert into watch_entry_versions(id,revision,identity,entity_id,collection_scope_id,owner,reason,
            active,active_from,expires_at,valid_from,actor_type,actor_id)
            values(%s,%s,%s::jsonb,12,'ad-domain:1','fixture-team','fixture reason',true,%s,%s,%s,'session',1)"""
        params = (ENTRY, 1, json.dumps(IDENTITY), NOW, NOW + timedelta(days=7), NOW)
        conn.execute(insert, params)
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(insert, ("00000000-0000-4000-8000-000000000009", *params[1:]))
        with pytest.raises(psycopg.errors.CheckViolation):
            conn.execute("update watch_entry_versions set valid_to=%s where id=%s", (NOW - timedelta(seconds=1), ENTRY))
        for statement in ("update watch_entry_versions set reason='changed'", "delete from watch_entry_versions"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(statement)
        conn.execute("update watch_entry_versions set valid_to=%s where id=%s", (NOW + timedelta(minutes=1), ENTRY))
        conn.execute(insert, (ENTRY, 2, json.dumps(IDENTITY), NOW, NOW + timedelta(days=8), NOW + timedelta(minutes=1)))
        rows = conn.execute("select * from watch_entry_versions order by revision").fetchall()
        assert len(rows) == 2 and rows[0]["reason"] == "fixture reason" and rows[0]["valid_to"] is not None
        assert rows[1]["valid_to"] is None and rows[1]["expires_at"] == NOW + timedelta(days=8)
        with pytest.raises(psycopg.errors.RaiseException, match="watch_interval_immutable"):
            conn.execute("update watch_entry_versions set valid_to=null where revision=1")
        conn.execute("reset role")
        # Minimal retained-source fixtures exercise the actual scoped SQL and
        # service transaction, not just string assertions or a fake cursor.
        conn.execute("""
            create table storage_v2_entity_type(id integer primary key,value text);
            insert into storage_v2_entity_type values(1,'ad_user');
            create table entities_v2_active(id bigint primary key,domain_id bigint,entity_type_id integer);
            insert into entities_v2_active values(13,1,1),(14,2,1),(15,1,1);
            create table ad_context_runs(run_id integer primary key,domain_id bigint,status text);
            insert into ad_context_runs values(1,1,'completed'),(2,2,'completed');
            create table ad_context_entity_versions(entity_id bigint,source_run_id integer,
                source_section text,valid_to_utc timestamptz,attributes_json jsonb);
            grant select on storage_v2_entity_type,entities_v2_active,ad_context_runs,ad_context_entity_versions to adlog_user;
        """)
        for entity_id, domain_id in ((13, 1), (14, 2), (15, 1)):
            conn.execute("insert into ad_context_entity_versions values(%s,%s,'directory_accounts',null,%s::jsonb)",
                         (entity_id, domain_id, json.dumps({"identity": {"kind": "ad_user",
                          "object_sid": f"S-1-5-21-1-2-3-{entity_id}",
                          "object_guid": f"00000000-0000-4000-8000-{entity_id:012d}"}})))
        conn.execute("set role adlog_user")
        created = {}
        for entity_id in (13, 14):
            with conn.transaction(), conn.cursor() as cur:
                created[entity_id] = registry.save_entry(cur, access(), body(entity_id=entity_id),
                    principal=PRINCIPAL, audit=lambda *_: None, now=NOW)
        with conn.cursor() as cur:
            first = registry.list_entries(cur, access({"kind": "domain", "ids": [1]}), now=NOW)
            second = registry.list_entries(cur, access({"kind": "domain", "ids": [2]}), now=NOW)
            assert {row["identity"]["entity_id"] for row in first["items"]} == {12, 13}
            assert {row["identity"]["entity_id"] for row in second["items"]} == {14}
            assert registry.list_entries(cur, access({"kind": "domain", "ids": [2]}),
                entry_id=created[13]["id"], now=NOW)["items"] == []
            with pytest.raises(PermissionError):
                registry.save_entry(cur, access({"kind": "domain", "ids": [2]}), body(entity_id=13, revision=1),
                    principal=PRINCIPAL, audit=lambda *_: None, entry_id=created[13]["id"], now=NOW)

        def fail_audit(*_):
            raise RuntimeError("synthetic audit failure")

        with pytest.raises(RuntimeError, match="synthetic audit failure"), conn.transaction(), conn.cursor() as cur:
            registry.save_entry(cur, access(), body(entity_id=15), principal=PRINCIPAL, audit=fail_audit, now=NOW)
        assert conn.execute("select count(*) as n from watch_entry_versions where entity_id=15").fetchone()["n"] == 0
        conn.execute("reset role")
        # Applied migration rejects a second execution without changing rows.
        with pytest.raises(psycopg.errors.RaiseException, match="prerequisites failed"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select count(*) as n from watch_entry_versions").fetchone()["n"] == 4
