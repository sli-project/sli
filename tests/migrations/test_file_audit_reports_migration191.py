"""Real read functions on an isolated PostgreSQL database in sli-dev pg-test."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/191_file_audit_reports.sql"


def test_reports_migration_follows_predecessor_and_versions_are_unique():
    inventory = forward_migration_inventory(PATH.parent)
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((191, "file_audit_reports"))
    assert position > 0
    assert pairs[position - 1] == (190, "agent_semantic_source")
    assert max(version for version, _ in pairs[:position]) + 1 == 191
    assert len(pairs) == len({version for version, _ in pairs})
    assert inventory[position].path == PATH
    assert list(PATH.parent.glob("191_*.sql")) == [PATH]


def test_read_functions_have_pinned_privileges_and_no_audit_mutation():
    sql = PATH.read_text("utf-8")
    manifest = json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8"))
    entries = [entry for entry in manifest["data"]["migrations"] if entry["version"] == 191]
    assert entries == [{"version": 191, "name": "file_audit_reports",
        "core_prerequisites": [190], "path": PATH.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(PATH.read_bytes().replace(b"\r\n", b"\n")).hexdigest()}]
    assert "version=190 and name='agent_semantic_source'" in sql and "where version>=191" in sql
    assert "values(191,'file_audit_reports')" in sql
    assert "pg_advisory_xact_lock(hashtext('sli_file_audit_reports_v191'))" in sql
    assert sql.count("security definer set search_path=pg_catalog,pg_temp") == 2
    assert sql.count("from public;") == 2
    assert "grant execute on function" in sql
    assert not re.search(r"grant (select|insert|update|delete).*to adlog_user", sql, re.IGNORECASE)
    assert "delete from" not in sql.lower() and "grant adlog_file_audit" not in sql


def test_report_publication_uses_migration_session_before_storage_ledger_role():
    """The storage owner cannot update the runtime-owned report registry."""
    sql = PATH.read_text("utf-8")
    publication = sql.split("reset role;", 1)[1]
    datasets, registry = publication.split("update public.report_registry_v4", 1)
    assert "update public.report_datasets_v4" in datasets
    assert "set local role" not in datasets
    registry_update, ledger = registry.split("set local role adlog_storage_owner;", 1)
    assert "status='published'" in registry_update
    assert "insert into public.schema_migrations" in ledger


@pytest.fixture
def report_database():
    # No application DSN or shared template is opened; this fixture creates
    # its own database on the named, disposable dev Compose service only.
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from psycopg.rows import dict_row

    base = os.environ.get("ADLOG_TEST_PG_DSN", "")
    if not base:
        pytest.skip("ADLOG_TEST_PG_DSN required")
    if conninfo_to_dict(base).get("host") != "pg-test":
        pytest.skip("This migration integration fixture requires sli-dev pg-test")
    name = "sli_test_fsui_" + uuid4().hex
    with psycopg.connect(make_conninfo(base, dbname="postgres"), autocommit=True) as admin:
        for role in ("adlog_storage_owner", "adlog_file_audit_owner", "adlog_user"):
            if not admin.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                admin.execute(sql.SQL("create role {} nologin noinherit").format(sql.Identifier(role)))
        admin.execute(sql.SQL("create database {} encoding 'UTF8'").format(sql.Identifier(name)))
        try:
            with psycopg.connect(make_conninfo(base, dbname=name), autocommit=True, row_factory=dict_row) as conn:
                assert_disposable_database(conn)
                conn.execute("""create schema sli_plugin_file_audit authorization adlog_file_audit_owner;
                    grant usage on schema sli_plugin_file_audit to adlog_user;
                    create table public.schema_migrations(version integer primary key,name text);
                    insert into public.schema_migrations values(190,'agent_semantic_source');
                    create table public.findings(id bigint primary key);
                    grant references on public.findings to adlog_file_audit_owner;
                    create table public.report_datasets_v4(dataset_key text,version int,status text,filters_json jsonb);
                    create table public.report_registry_v4(report_key text,version int,status text,published_at timestamptz);
                    alter table public.schema_migrations owner to adlog_storage_owner;
                    alter table public.report_datasets_v4 owner to adlog_user;
                    alter table public.report_registry_v4 owner to adlog_user;
                    set role adlog_file_audit_owner;""")
                # Use the real predecessor DDL, with its evidence constraints.
                previous = (PATH.parent / "183_file_audit_contracts.sql").read_text("utf-8")
                for ddl in re.findall(r"create table sli_plugin_file_audit\.\w+ \(.*?\n\);", previous, re.DOTALL):
                    conn.execute(ddl)
                conn.execute("alter table sli_plugin_file_audit.actions add column denial_layer text")
                previous = (PATH.parent / "187_file_audit_rules.sql").read_text("utf-8")
                for ddl in re.findall(r"create table sli_plugin_file_audit\.\w+ \(.*?\n\);", previous, re.DOTALL):
                    conn.execute(ddl)
                conn.execute("reset role")
                from server.sli.plugins.file_audit.contracts import REPORT_KEYS
                for tab in REPORT_KEYS:
                    conn.execute("insert into public.report_datasets_v4 values(%s,1,'draft','[]')", (f"file-audit.{tab}",))
                    conn.execute("insert into public.report_registry_v4 values(%s,1,'draft',null)", (f"file-audit.{tab}",))
                # Match baseline ownership: the storage owner has no implicit
                # write access to the application-owned report registry.
                for table in ("report_datasets_v4", "report_registry_v4"):
                    privileges = conn.execute("""select pg_get_userbyid(relowner) as owner,
                        has_table_privilege('adlog_storage_owner', oid, 'UPDATE') as can_update
                        from pg_class where oid=to_regclass(%s)""", (f"public.{table}",)).fetchone()
                    assert privileges == {"owner": "adlog_user", "can_update": False}
                conn.execute(PATH.read_text("utf-8"))
                yield conn
        finally:
            admin.execute(sql.SQL("drop database {} with (force)").format(sql.Identifier(name)))


def test_actual_migration_scoped_counts_path_boundaries_and_cursor_pages(report_database):
    conn = report_database
    agent = "00000000-0000-4000-8000-000000000001"
    roots = [{"agent_id": agent, "source_instance_id": "synthetic-source", "collection_scope_id": "scope:one",
        "source_name": "Synthetic server", "share_name": "Synthetic share", "path": "C:\\Synthetic", "important": True}]
    conn.execute("""insert into sli_plugin_file_audit.policy_revisions values(%s,'synthetic-source',1,now(),
        'session',1,%s::jsonb,%s)""", (agent, json.dumps({"source_name": "Synthetic server", "roots": roots}), "a" * 64))
    for index, (source, scope, path, operation, outcome) in enumerate([
        ("synthetic-source", "scope:one", "C:\\Synthetic\\File", "read", "success"),
        ("synthetic-source", "scope:one", "C:\\Synthetic\\Folder\\Child", "delete", "success"),
        ("synthetic-source", "scope:one", "C:\\Synthetic-other\\File", "write", "failure"),
        ("other-source", "scope:one", "C:\\Synthetic\\Hidden", "read", "success"),
        ("synthetic-source", "scope:two", "C:\\Synthetic\\Hidden", "read", "success"),
    ]):
        conn.execute("""insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,
            collection_scope_id,observed_at,subject_sid,path,operation,outcome,correlation_state,projection_version)
            values(%s,1,%s,%s,%s,'2026-10-10T09:00Z','S-1-1-0',%s,%s,%s,'complete',1)""",
            (f"{index:064x}", agent, source, scope, path, operation, outcome))
    conn.execute("set role adlog_user")
    assert len(conn.execute("select sli_plugin_file_audit.report_roots() as roots").fetchone()["roots"]) == 1

    def read(tab="actions", path=None, nested=True, employee=None, operation=None, after=None, limit=1):
        return conn.execute("""select sli_plugin_file_audit.report_rows(%s::jsonb,%s,'2026-10-10T00:00Z',
            '2026-10-11T00:00Z',%s,%s,%s,%s,%s::jsonb,%s) as data""", (json.dumps(roots), tab,
            path, nested, employee, operation, json.dumps(after) if after else None, limit)).fetchone()["data"]

    first = read()
    assert first["filtered_count"] == 3 and first["has_more"]
    second = read(after=first["after"])
    third = read(after=second["after"])
    assert len({page["items"][0]["id"] for page in (first, second, third)}) == 3
    assert not third["has_more"]
    assert read(path="C:\\Synthetic")["filtered_count"] == 2
    assert read(path="c:\\synthetic\\file", nested=False)["filtered_count"] == 1
    assert read(path="C:\\Synthetic", nested=False)["filtered_count"] == 0
    assert read(employee="S-1-5-1")["filtered_count"] == 0
    assert read(operation="delete")["filtered_count"] == 1
    assert read(tab="access-denials")["filtered_count"] == 1
    for tab in ("mass-operations", "permission-changes", "out-of-hours", "permissions"):
        assert read(tab=tab)["filtered_count"] == 0
    for tab in ("overview", "audit-state"):
        row = read(tab=tab)["items"][0]
        assert row["snapshot_id"] is None and row["audit_state"] is None
    with pytest.raises(Exception, match="permission denied"):
        conn.execute("select * from sli_plugin_file_audit.actions")
    with pytest.raises(Exception, match="file_audit_report_parameters_invalid"):
        read(limit=101)
    conn.execute("reset role")

    from tools.e2e.file_audit import projection_ids
    expected = {"overview": {agent + ":synthetic-source:scope:one"},
                "audit-state": {agent + ":synthetic-source:scope:one"},
                "actions": {f"{0:064x}", f"{1:064x}", f"{2:064x}"},
                "access-denials": {f"{2:064x}"}, "permission-changes": set(),
                "mass-operations": set(), "out-of-hours": set(), "permissions": set()}
    for tab, ids in expected.items():
        assert projection_ids(conn, tab, agents=[agent], start=datetime(2026, 10, 10, tzinfo=timezone.utc),
                              end=datetime(2026, 10, 11, tzinfo=timezone.utc)) == ids
    assert conn.execute("select count(*) as n from public.report_registry_v4 where status='published'").fetchone()["n"] == 8


def test_retained_findings_inventory_and_confirmed_audit_readback(report_database):
    conn = report_database
    agent = "00000000-0000-4000-8000-000000000001"
    snapshot_id = "00000000-0000-4000-8000-000000000002"
    root = {"agent_id": agent, "source_instance_id": "synthetic-source", "collection_scope_id": "scope:one",
        "source_name": "Synthetic server", "share_name": "Synthetic share", "path": "C:\\Synthetic",
        "important": True, "policy_revision": 1}
    conn.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,'synthetic-source',1,now(),'session',1,%s::jsonb,%s)",
        (agent, json.dumps({"roots": [root]}), "a" * 64))
    snapshot = {"share": {"dacl": "D:(A;;FR;;;WD)", "complete": True},
        "local_groups": {"groups": [{"group_sid": "S-1-5-32-545"}]},
        "objects": [{"path": root["path"], "object_type": "directory", "dacl": "D:(A;;FR;;;WD)",
            "sacl_missing": False, "sacl_protected": False},
            {"path": root["path"] + "\\Protected", "object_type": "directory",
             "sacl_missing": False, "sacl_protected": True}]}
    conn.execute("insert into sli_plugin_file_audit.access_snapshots values(%s,%s,'synthetic-source','scope:one','2026-10-10T09:00Z',1,'complete',%s,%s::jsonb,0)",
        (snapshot_id, agent, "a" * 64, json.dumps(snapshot)))
    for index, operation in enumerate(("read", "permissions"), 1):
        conn.execute("""insert into sli_plugin_file_audit.actions(action_id,contract_version,agent_id,source_instance_id,
            collection_scope_id,observed_at,subject_sid,path,operation,outcome,correlation_state,projection_version)
            values(%s,1,%s,'synthetic-source','scope:one','2026-10-10T09:00Z','S-1-1-0',%s,%s,'success','complete',1)""",
            (f"{index:064x}", agent, root["path"] + "\\File", operation))
    conn.execute("""insert into sli_plugin_file_audit.observations values(%s,%s,'synthetic-source','scope:one',
        'Security','Microsoft-Windows-Security-Auditing','synthetic-generation',1,4663,0,'2026-10-10T09:00Z',1,
        'synthetic-native-reference',%s)""", ("b" * 64, agent, "c" * 64))
    conn.execute("insert into sli_plugin_file_audit.action_evidence values(%s,'synthetic-native-reference',%s,'primary')",
        (f"{1:064x}", "b" * 64))
    for index, rule in enumerate(("mass-read", "out-of-hours", "broad-write"), 1):
        row = {**root, "rule_code": "file-audit." + rule, "subject_sid": "S-1-1-0", "observed_at": "2026-10-10T09:00Z",
            "details": {"path": root["path"] + "\\File", "distinct_files": 1, "window_seconds": 60, "operation": "read"}}
        conn.execute("insert into public.findings values(%s)", (index,))
        conn.execute("insert into sli_plugin_file_audit.rule_results values(%s,%s,%s,'synthetic-source','scope:one',%s,1,'observed','2026-10-10T09:00Z',%s::jsonb,%s)",
            (f"{index + 10:064x}", index, agent, row["rule_code"], json.dumps(row), "a" * 64))
        if rule == "broad-write":
            conn.execute("insert into sli_plugin_file_audit.rule_snapshots values(%s,%s)", (f"{index + 10:064x}", snapshot_id))
        else:
            conn.execute("insert into sli_plugin_file_audit.rule_actions values(%s,%s)", (f"{index + 10:064x}", f"{1:064x}"))
    conn.execute("insert into sli_plugin_file_audit.audit_commands values('synthetic-command',%s,'synthetic-source',1,'check',ARRAY['scope:one'],now(),'session',1,%s)",
        (agent, "a" * 64))
    conn.execute("insert into sli_plugin_file_audit.audit_receipts values(%s,'synthetic-command',%s,'synthetic-source',1,'check','scope:one','verified','2026-10-10T09:00Z',%s,'ok')",
        (str(uuid4()), agent, "a" * 64))
    conn.execute("set role adlog_user")

    def read(tab, path=None):
        return conn.execute("""select sli_plugin_file_audit.report_rows(%s::jsonb,%s,'2026-10-10T00:00Z',
            '2026-10-11T00:00Z',%s,true,null,null,null,50) as data""", (json.dumps([root]), tab, path)).fetchone()["data"]

    for tab in ("mass-operations", "out-of-hours", "permissions", "permission-changes"):
        data = read(tab)
        assert data["filtered_count"] == 1 and data["items"]
        assert read(tab, "C:\\Unrelated")["filtered_count"] == 0
        if tab in ("mass-operations", "out-of-hours"):
            evidence = data["items"][0]["evidence"][0]
            assert evidence["reference"] == "synthetic-native-reference" and evidence["event_id"] == 4663
    assert len(read("permissions")["inventory"]) == 1
    assert read("permissions", "C:\\Unrelated")["inventory"] == []
    for tab in ("overview", "audit-state"):
        row = read(tab)["items"][0]
        assert row["audit_state"] == "verified" and row["folders_with_read_audit"] == 1
        assert row["audit_receipt"]["command_id"] == "synthetic-command"
    conn.execute("reset role")

    from tools.e2e.file_audit import projection_ids
    expected = {"overview": {agent + ":synthetic-source:scope:one"},
                "audit-state": {agent + ":synthetic-source:scope:one"},
                "actions": {f"{1:064x}", f"{2:064x}"}, "access-denials": set(),
                "permission-changes": {f"{2:064x}"}, "mass-operations": {f"{11:064x}"},
                "out-of-hours": {f"{12:064x}"}, "permissions": {f"{13:064x}"}}
    for tab, ids in expected.items():
        assert projection_ids(conn, tab, agents=[agent], start=datetime(2026, 10, 10, tzinfo=timezone.utc),
                              end=datetime(2026, 10, 11, tzinfo=timezone.utc)) == ids
