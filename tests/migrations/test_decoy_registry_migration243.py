"""D01 additive migration and isolated PostgreSQL ACL/interval contracts."""
from datetime import timedelta
import json
import os
from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_decoys import AGENT, LABEL, NOW, SOURCE, body

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/243_decoy_registry.sql"
SQL = PATH.read_text("utf-8")


def test_migration_is_additive_transactional_scoped_and_uses_main_predecessor():
    inventory = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    assert inventory.count((243, "decoy_registry")) == 1
    assert list(PATH.parent.glob("243_*.sql")) == [PATH]
    # D02 already shipped this prerequisite in main. Keep its applied SQL intact.
    assert "version=242 and name='gpo_plan_credentials'" in SQL and "where version>=243" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    assert "grant update(active_to)" in SQL and "grant select,insert" in SQL
    assert "decoy_interval_immutable" in SQL and "decoy_active_identity" in SQL
    assert "decoys.manage" in SQL and "array['view','manage_decoy']" in SQL
    assert "insert into public.finding_evidence_source_bindings" not in SQL
    assert "update public.sli_agents" not in SQL and "grant delete" not in SQL
    assert "set search_path=pg_catalog,pg_temp" in SQL


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_applies_and_preserves_versions_and_narrow_inventory_boundary():
    import psycopg
    from psycopg import sql
    from psycopg.rows import dict_row

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        for role in ("adlog_storage_owner", "adlog_file_audit_owner", "adlog_user"):
            if not conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(role)))
        conn.execute("""
            grant usage,create on schema public to adlog_storage_owner;
            create schema sli_plugin_file_audit authorization adlog_file_audit_owner;
            grant usage on schema sli_plugin_file_audit to adlog_user;
            create table schema_migrations(version integer primary key,name text);
            insert into schema_migrations values(242,'gpo_plan_credentials');
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
            set role adlog_file_audit_owner;
            create table sli_plugin_file_audit.access_snapshots(snapshot_id uuid primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,observed_at timestamptz,snapshot jsonb);
            reset role;
        """)
        conn.execute(SQL)
        conn.execute("set role adlog_user")
        # The label service is exercised with source fakes separately; this lane
        # verifies SQL storage, native inventory and privileges themselves.
        insert = """insert into decoy_label_versions(id,revision,kind,identity,owner,reason,active,active_from,
            actor_type,actor_id,readiness,plugin_id,source_instance_id,device_id,entity_id,collection_scope_id)
            values(%s,%s,'file',%s::jsonb,'fixture-owner','fixture reason',%s,%s,'session',1,
                   '{"state":"not_ready"}','sli.file-audit',%s,%s,null,'scope:one')"""
        identity = json.dumps(body()["identity"])
        conn.execute(insert, (LABEL, 1, identity, True, NOW, SOURCE, AGENT))
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(insert, ("00000000-0000-4000-8000-000000000009", 1, identity, True, NOW, SOURCE, AGENT))
        conn.execute("update decoy_label_versions set active_to=%s where id=%s", (NOW + timedelta(minutes=1), LABEL))
        conn.execute(insert, (LABEL, 2, identity, False, NOW + timedelta(minutes=1), SOURCE, AGENT))
        assert conn.execute("select revision,active from decoy_label_versions order by revision").fetchall() == [
            {"revision": 1, "active": True}, {"revision": 2, "active": False}]
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("update decoy_label_versions set active_to=null where id=%s and revision=1", (LABEL,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("update decoy_label_versions set reason='changed'")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("delete from decoy_label_versions")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from sli_plugin_file_audit.access_snapshots")
        conn.execute("reset role")
        from uuid import uuid4
        snapshot = {"policy_revision": "4", "scan_id": str(uuid4()), "objects": [{"path": "C:\\DECOYS\\bait.txt", "object_type": "file", "sacl_missing": False, "sacl_protected": False}]}
        conn.execute("insert into sli_plugin_file_audit.access_snapshots values(%s,%s,%s,'scope:one',now()-interval '1 minute',%s::jsonb)",
                     (uuid4(), AGENT, SOURCE, json.dumps(snapshot)))
        conn.execute("set role adlog_user")
        query = "select sli_plugin_file_audit.decoy_file_present(%s,%s,%s,%s,%s) as present"
        args = (AGENT, SOURCE, "scope:one", body()["identity"]["path"], "4")
        assert conn.execute(query, args).fetchone()["present"] is True
        for other in ((AGENT, SOURCE, "scope:two", args[3], "4"), (AGENT, SOURCE, "scope:one", args[3] + ".other", "4"),
                      (AGENT, SOURCE, "scope:one", args[3], "5")):
            assert conn.execute(query, other).fetchone()["present"] is False
        conn.execute("reset role")
        latest = {"policy_revision": "4", "scan_id": str(uuid4()), "objects": []}
        conn.execute("insert into sli_plugin_file_audit.access_snapshots values(%s,%s,%s,'scope:one',now(),%s::jsonb)",
                     (uuid4(), AGENT, SOURCE, json.dumps(latest)))
        conn.execute("set role adlog_user")
        # A rename/deletion in the latest scan cannot reuse an older exact path.
        assert conn.execute(query, args).fetchone()["present"] is False
