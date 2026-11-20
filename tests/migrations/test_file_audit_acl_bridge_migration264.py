"""Actual PostgreSQL canonical snapshot provenance; synthetic disposable DB only."""
import json
import os
from copy import deepcopy
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest

from sli_agent.envelope import canonical, digest
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "config/postgres_migrations/264_file_audit_acl_bridge.sql"
AGENT = "00000000-0000-4000-8000-000000000001"
INSTALLATION = "00000000-0000-4000-8000-000000000099"
COMMAND = "synthetic-command"
SOURCE = "synthetic-source"
SCOPE = "synthetic-root"


def inventory():
    item = {"contract_id": "sli.file-audit.inventory.v1", "collection_scope_id": SCOPE,
            "policy_revision": "1", "observed_at_utc": "2026-01-01T00:00:00+00:00",
            "scan_id": "00000000-0000-4000-8000-000000000002", "page_number": 0,
            "has_more": False, "completeness": "complete", "unread_objects": 0,
            "share": {"name": "synthetic", "path": "C:\\synthetic", "dacl": "D:(A;;FA;;;WD)", "complete": True},
            "local_groups": {"complete": True, "groups": []},
            "objects": [{"path": "C:\\synthetic\\Тест😀", "object_id": "synthetic-object",
                         "object_type": "file", "owner_sid": "S-1-5-18", "dacl": "D:(A;;FW;;;WD)",
                         "sacl": "S:", "sacl_protected": False, "sacl_missing": False}]}
    item["snapshot_sha256"] = digest(item)
    item["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + item["snapshot_sha256"]))
    return item


@pytest.fixture
def acl_pg():
    import psycopg
    from psycopg import sql
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL not configured")
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        for role in ("adlog_storage_owner", "adlog_semantic_worker", "adlog_user", "adlog_file_audit_owner"):
            if not conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(role)))
        conn.execute("create extension if not exists pgcrypto")
        conn.execute("grant usage,create on schema public to adlog_storage_owner")
        conn.execute("create schema sli_plugin_file_audit authorization adlog_file_audit_owner")
        conn.execute("set role adlog_storage_owner")
        conn.execute("""
            create table public.schema_migrations(version integer primary key,name text);
            insert into public.schema_migrations values(263,'native_source_lookup_index');
            create table public.sli_agents(id uuid primary key,host_id text,status text,assigned_modules jsonb,
                source_host_id uuid,source_agent_id uuid references public.sli_agents(id),
                runtime_resume jsonb not null default '{}'::jsonb check(jsonb_typeof(runtime_resume)='object'));
            create table public.servers(hostname text,is_active boolean,domain_id bigint);
            create table public.findings(id bigint primary key);
            create table public.finding_evidence_source_bindings(
                principal_oid oid,principal_name name,installation_id uuid,plugin_id text,
                source_instance_id text,source_generation text,collection_scope_id text,
                storage_kind text,log_source_id bigint,agent_key text,agent_id uuid,
                constraint finding_evidence_source_bindings_check check(storage_kind<>'file_audit_snapshot'));
            create table public.finding_evidence_refs(storage_kind text,plugin_id text,collection_scope_id text,native_id text,
                constraint finding_evidence_refs_check check(storage_kind<>'file_audit_snapshot'));
            create function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)
                returns boolean language sql stable as $$ select false $$;
            reset role;
            set role adlog_file_audit_owner;
            create table sli_plugin_file_audit.access_snapshots(snapshot_id uuid primary key,agent_id uuid,
                source_instance_id text,collection_scope_id text,snapshot_sha256 text,snapshot jsonb,
                observed_at timestamptz,completeness text,unread_objects integer,contract_version integer);
            create table sli_plugin_file_audit.audit_commands(command_id text primary key,agent_id uuid,
                source_instance_id text,policy_revision bigint,collection_scope_ids text[],action text,command_sha256 text);
            create table sli_plugin_file_audit.audit_receipts(command_id text,agent_id uuid,source_instance_id text,
                policy_revision bigint,collection_scope_id text,state text,observed_at timestamptz);
            create table sli_plugin_file_audit.policy_revisions(agent_id uuid,source_instance_id text,
                revision bigint,policy jsonb,policy_sha256 text);
            reset role;
        """)
        # Real product servers belongs to the application owner, not the
        # SECURITY DEFINER owner. A broad fixture ownership grant hid this ACL.
        conn.execute("alter table public.servers owner to adlog_user")
        assert not conn.execute(
            "select has_table_privilege('adlog_storage_owner','public.servers','SELECT')"
        ).fetchone()[0]
        conn.execute(MIGRATION.read_text("utf-8-sig"))
    return dsn


def seed(conn, *, partial=False):
    item = inventory()
    if partial:
        item.update(completeness="partial", has_more=True, page_number=1)
        item["snapshot_sha256"] = digest({k: v for k, v in item.items()
                                           if k not in ("snapshot_id", "snapshot_sha256")})
        item["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + item["snapshot_sha256"]))
    policy = {"policy_revision": "1", "source_name": "synthetic-server", "roots": [{
        "collection_scope_id": SCOPE, "path": "C:\\synthetic", "share_name": "synthetic", "important": True}]}
    conn.execute("insert into sli_agents(id,host_id,status,assigned_modules) values(%s,%s,'active',%s::jsonb)",
                 (AGENT, SOURCE, json.dumps([{"module_id": "sli.file-audit", "enabled": True, "config": policy}])))
    conn.execute("insert into servers values('synthetic-server',true,7)")
    conn.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,%s,1,%s::jsonb,'unused')",
                 (AGENT, SOURCE, json.dumps(policy)))
    conn.execute("update sli_plugin_file_audit.policy_revisions set policy_sha256=encode(sha256(convert_to(policy::text,'UTF8')),'hex')")
    conn.execute("insert into sli_plugin_file_audit.audit_commands values(%s,%s,%s,1,array[%s],'check','unused')",
                 (COMMAND, AGENT, SOURCE, SCOPE))
    conn.execute("""update sli_plugin_file_audit.audit_commands set command_sha256=encode(sha256(convert_to(
        jsonb_build_object('contract_id','sli.file-audit.audit-command.v1','command_id',command_id,
            'action',action,'policy_revision',policy_revision::text,'collection_scope_ids',to_jsonb(collection_scope_ids))::text,
        'UTF8')),'hex')""")
    conn.execute("insert into sli_plugin_file_audit.audit_receipts values(%s,%s,%s,1,%s,'verified',%s)",
                 (COMMAND, AGENT, SOURCE, SCOPE, item["observed_at_utc"]))
    conn.execute("insert into sli_plugin_file_audit.access_snapshots values(%s,%s,%s,%s,%s,%s::jsonb,%s,%s,0,1)",
                 (item["snapshot_id"], AGENT, SOURCE, SCOPE, item["snapshot_sha256"], json.dumps(item), item["observed_at_utc"], item["completeness"]))
    conn.execute("""insert into finding_evidence_source_bindings values(
        (select oid from pg_roles where rolname=session_user),session_user,%s,'sli.file-audit',%s,%s,%s,
        'file_audit_snapshot',null,null,%s)""", (INSTALLATION, SOURCE, "audit-command:" + COMMAND, SCOPE, AGENT))
    return item


def verified(conn, item):
    return conn.execute("select public.resolve_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s)", (
        INSTALLATION, "sli.file-audit", SOURCE, "audit-command:" + COMMAND, SCOPE,
        "file_audit_snapshot", item["snapshot_id"], item["snapshot_sha256"])).fetchone()[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_sql_canonical_unicode_escapes_uuidv5_and_bounded_inputs(acl_pg):
    import psycopg
    with psycopg.connect(acl_pg) as conn:
        values = [None, True, False, 0, -1, 9007199254740991, ["кириллица", "😀", '\\"\b\f\n\r\t\x01\x7f'],
                  {"я": "☃", "a": [1, {"z": "尾", "b": "𝄞"}]}]
        values.append("".join(chr(point) for point in range(1, 128)))
        for value in values:
            actual = conn.execute("select public.file_audit_snapshot_canonical_v264(%s::jsonb)",
                                  (json.dumps(value),)).fetchone()[0]
            assert actual.encode("ascii") == canonical(value)
        item = inventory()
        actual = conn.execute("select public.file_audit_snapshot_uuid_v264(%s,%s)",
                              (COMMAND, item["snapshot_sha256"])).fetchone()[0]
        assert str(actual) == item["snapshot_id"]
        for value in (1.5, {"a": 1.0}, "x" * 49153):
            with conn.transaction(force_rollback=True), pytest.raises(
                psycopg.errors.RaiseException, match="file_audit_snapshot_content_invalid"
            ):
                conn.execute("select public.file_audit_snapshot_canonical_v264(%s::jsonb)", (json.dumps(value),))
        nested = 1
        for _ in range(18):
            nested = [nested]
        with pytest.raises(psycopg.errors.RaiseException, match="file_audit_snapshot_content_invalid"):
            conn.execute("select public.file_audit_snapshot_canonical_v264(%s::jsonb)", (json.dumps(nested),))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("partial", [False, True])
def test_retained_content_command_domain_and_current_source_are_verified(acl_pg, partial):
    import psycopg
    with psycopg.connect(acl_pg) as conn:
        item = seed(conn, partial=partial)
        assert verified(conn, item)
        provenance = conn.execute("select public.file_audit_snapshot_provenance_v264(%s,%s)",
                                  (AGENT, item["snapshot_id"])).fetchone()[0]
        assert provenance["domain_id"] == 7 and provenance["important"] is True
        assert provenance["command_id"] == COMMAND
        for mutation in (
            "update sli_plugin_file_audit.access_snapshots set snapshot=jsonb_set(snapshot,'{share,dacl}','\"D:\"')",
            "update sli_plugin_file_audit.audit_commands set command_id='other-command'",
            "update sli_plugin_file_audit.audit_commands set command_sha256=repeat('a',64)",
            "update sli_plugin_file_audit.policy_revisions set policy_sha256=repeat('f',64)",
            "update sli_agents set status='inactive'",
            "update sli_agents set assigned_modules=jsonb_set(assigned_modules,'{0,enabled}','false')",
            "update sli_agents set assigned_modules=jsonb_set(assigned_modules,'{0,config,roots,0,path}','\"C:\\\\other\"')",
            "update servers set domain_id=null",
            "insert into servers values('synthetic-server',true,8)",
            "delete from sli_plugin_file_audit.audit_receipts",
            "update finding_evidence_source_bindings set principal_oid=0",
        ):
            with conn.transaction(force_rollback=True):
                conn.execute(mutation)
                assert not verified(conn, item)
        changed = deepcopy(item)
        changed["snapshot_sha256"] = "e" * 64
        assert not verified(conn, changed)
        assert not conn.execute("select public.resolve_finding_evidence_ref(%s,'sli.file-audit',%s,%s,%s,'file_audit_snapshot','not-uuid',%s)",
                                (INSTALLATION, SOURCE, "audit-command:" + COMMAND, SCOPE, item["snapshot_sha256"])).fetchone()[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_worker_cannot_read_native_tables_or_use_other_login_binding(acl_pg):
    import psycopg
    with psycopg.connect(acl_pg, autocommit=True) as conn:
        item = seed(conn)
        native_oid = conn.execute("select 'sli_plugin_file_audit.access_snapshots'::regclass::oid").fetchone()[0]
        # SET ROLE must not inherit a binding for the migration/test session.
        conn.execute("set session authorization adlog_semantic_worker")
        assert not verified(conn, item)
        assert not conn.execute("select has_table_privilege(current_user,%s,'select')", (native_oid,)).fetchone()[0]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select * from sli_plugin_file_audit.access_snapshots")
        conn.execute("reset session authorization")
        conn.execute("""insert into finding_evidence_source_bindings select oid,rolname,%s,'sli.file-audit',%s,%s,%s,
            'file_audit_snapshot',null,null,%s from pg_roles where rolname='adlog_semantic_worker'""",
                     (INSTALLATION, SOURCE, "audit-command:" + COMMAND, SCOPE, AGENT))
        conn.execute("set session authorization adlog_semantic_worker")
        assert verified(conn, item)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("select public.file_audit_snapshot_canonical_v264('{}'::jsonb)")
        conn.execute("reset session authorization")
        conn.execute("update finding_evidence_source_bindings set principal_name='nonmatching-login' where principal_name='adlog_semantic_worker'")
        conn.execute("set session authorization adlog_semantic_worker")
        assert not verified(conn, item)






def test_phase_one_migration_has_no_admission_publication_or_native_worker_grants():
    import re
    text = MIGRATION.read_text("utf-8-sig")
    assert "version=263 and name='native_source_lookup_index'" in text
    assert "values(264,'file_audit_acl_bridge')" in text
    assert "collnamespace='pg_catalog'::regnamespace and collname='pg_unicode_fast'" in text
    assert "collprovider='b' and collisdeterministic" in text
    assert 'collate pg_catalog."pg_unicode_fast"' in text
    assert not re.search(r"insert into (?:public\.)?(?:findings|finding_evidence|semantic_qw_signals|semantic_policy_admission)\b", text)
    assert not re.search(r"grant (?:select|insert|update|delete)[^;]+to adlog_(?:semantic_worker|user)", text, re.DOTALL)
    previous = (ROOT / "config/postgres_migrations/245_file_decoy.sql").read_text("utf-8")
    legacy = previous.split("    if p_kind='core_event' then", 1)[1].split("end $$;", 1)[0]
    assert legacy == text.split("    elsif p_kind='core_event' then", 1)[1].split("end $$;", 1)[0]


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("mutation", ["null-owner", "null-kind", "unknown-key", "path-escape", "duplicate-path", "deep", "oversize", "float"])
def test_even_rehashed_structurally_invalid_snapshot_fails_closed(acl_pg, mutation):
    import psycopg
    with psycopg.connect(acl_pg) as conn:
        original = seed(conn)
        item = deepcopy(original)
        if mutation == "null-owner":
            item["objects"][0]["owner_sid"] = None
        elif mutation == "null-kind":
            item["objects"][0]["object_type"] = None
        elif mutation == "unknown-key":
            item["invented"] = "synthetic"
        elif mutation == "path-escape":
            item["objects"][0]["path"] = "C:\\synthetic\\..\\outside"
        elif mutation == "duplicate-path":
            item["objects"].append(deepcopy(item["objects"][0]))
        elif mutation == "deep":
            nested = "x"
            for _ in range(20):
                nested = [nested]
            item["objects"][0]["object_id"] = nested
        elif mutation == "oversize":
            item["objects"][0]["dacl"] = "x" * 49153
        else:
            item["page_number"] = 0.5
        body = {key: value for key, value in item.items() if key not in ("snapshot_id", "snapshot_sha256")}
        item["snapshot_sha256"] = digest(body)
        item["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + item["snapshot_sha256"]))
        conn.execute("""update sli_plugin_file_audit.access_snapshots set snapshot_id=%s,
            snapshot_sha256=%s,snapshot=%s::jsonb""", (item["snapshot_id"], item["snapshot_sha256"], json.dumps(item)))
        assert not verified(conn, item)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_all_scope_dimensions_and_snapshot_constraint_are_enforced(acl_pg):
    import psycopg
    with psycopg.connect(acl_pg) as conn:
        item = seed(conn)
        params = [INSTALLATION, "sli.file-audit", SOURCE, "audit-command:" + COMMAND, SCOPE,
                  "file_audit_snapshot", item["snapshot_id"], item["snapshot_sha256"]]
        for index, changed in ((0, "00000000-0000-4000-8000-000000000088"), (1, "sli.workstations"),
                               (2, "other-source"), (3, "audit-command:other"), (4, "other-root")):
            altered = list(params)
            altered[index] = changed
            assert not conn.execute("select public.resolve_finding_evidence_ref(%s,%s,%s,%s,%s,%s,%s,%s)", altered).fetchone()[0]
        for kind, native, scope in (("file_audit_snapshot", "a" * 64, SCOPE),
                                    ("file_audit_snapshot", item["snapshot_id"], ""),
                                    ("file_audit_observation", item["snapshot_id"], SCOPE)):
            with conn.transaction(force_rollback=True), pytest.raises(psycopg.errors.CheckViolation):
                conn.execute("insert into finding_evidence_refs values(%s,'sli.file-audit',%s,%s)", (kind, scope, native))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_dropped_and_recreated_login_cannot_reuse_old_oid_binding(acl_pg):
    from uuid import uuid4

    import psycopg
    from psycopg import sql
    login = "acl_fixture_" + uuid4().hex
    with psycopg.connect(acl_pg, autocommit=True) as conn:
        item = seed(conn)
        conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(login)))
        try:
            conn.execute(sql.SQL("grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to {}").format(sql.Identifier(login)))
            conn.execute("""insert into finding_evidence_source_bindings select oid,rolname,%s,'sli.file-audit',%s,%s,%s,
                'file_audit_snapshot',null,null,%s from pg_roles where rolname=%s""",
                         (INSTALLATION, SOURCE, "audit-command:" + COMMAND, SCOPE, AGENT, login))
            conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
            assert verified(conn, item)
            conn.execute("reset session authorization")
            conn.execute(sql.SQL("revoke execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from {}").format(sql.Identifier(login)))
            conn.execute(sql.SQL("drop role {}").format(sql.Identifier(login)))
            conn.execute(sql.SQL("create role {} nologin").format(sql.Identifier(login)))
            conn.execute(sql.SQL("grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to {}").format(sql.Identifier(login)))
            conn.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
            assert not verified(conn, item)
        finally:
            conn.execute("reset session authorization")
            conn.execute(sql.SQL("revoke execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from {}").format(sql.Identifier(login)))
            conn.execute(sql.SQL("drop role {}").format(sql.Identifier(login)))

@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("path,root", [
    ("C:\\данные\\file", "C:\\ДАННЫЕ"),
    ("C:\\ος\\file", "C:\\ΟΣ"),
    ("C:\\i\u0307\\file", "C:\\İ"),
    ("C:\\𐐨\\file", "C:\\𐐀"),
    ("C:\\straße\\file", "C:\\STRASSE"),
    ("C:\\a\u030a\\file", "C:\\Å"),
    ("C:\\ДАННЫЕ-extra\\file", "C:\\данные"),
    ("C:\\данные\\..\\outside", "C:\\ДАННЫЕ"),
    ("C:\\данные\\file:stream", "C:\\ДАННЫЕ"),
])
def test_regression_unicode_path_containment_matches_python(acl_pg, path, root):
    import psycopg
    from sli_agent.file_audit_policy import path_in_root
    try:
        expected = path_in_root(path, root)
    except ValueError:
        expected = False
    with psycopg.connect(acl_pg) as conn:
        actual = conn.execute("select public.file_audit_path_in_root_v264(%s,%s)", (path, root)).fetchone()[0]
        assert actual is expected


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_regression_canonical_page_not_jsonb_presentation_defines_size(acl_pg):
    import psycopg
    from server.sli.plugins.file_audit.management import _snapshot
    item = inventory()
    template = deepcopy(item["objects"][0])
    item["objects"] = [{**template, "path": f"C:\\synthetic\\file-{i}", "object_id": f"object-{i}"}
                       for i in range(100)]
    assert len(canonical(item["objects"])) < 32768
    ace = "(A;;FR;;;S-1-5-21-1000000000-1000000000-1000000000-10000)"
    while len(canonical(item)) <= 49152:
        item["share"]["dacl"] += ace
    item["share"]["dacl"] = item["share"]["dacl"][:-len(ace)]
    item["snapshot_sha256"] = digest({key: value for key, value in item.items()
                                      if key not in ("snapshot_sha256", "snapshot_id")})
    item["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + item["snapshot_sha256"]))
    cfg = {"inventory_objects": 100000, "roots": [{"collection_scope_id": SCOPE,
           "share_name": "synthetic", "path": "C:\\synthetic"}]}
    command = {"policy_revision": "1", "collection_scope_ids": [SCOPE], "command_id": COMMAND}
    assert _snapshot(item, cfg, command) == item
    with psycopg.connect(acl_pg) as conn:
        seed(conn)
        presentation = conn.execute("select octet_length(%s::jsonb::text)", (json.dumps(item),)).fetchone()[0]
        assert len(canonical(item)) <= 49152 < presentation
        conn.execute("""update sli_plugin_file_audit.access_snapshots set snapshot_id=%s,
            snapshot_sha256=%s,snapshot=%s::jsonb""", (item["snapshot_id"], item["snapshot_sha256"], json.dumps(item)))
        assert verified(conn, item)

@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_regression_builtin_unicode_lower_matches_python_case_table(acl_pg):
    import psycopg
    from sli_agent.file_audit_policy import path_in_root
    # Every changing single-code-point lowercase mapping in the supported
    # Python runtime, plus context-sensitive final-sigma/ignorable sequences.
    values = [chr(point) for point in range(0x110000)
              if not 0xd800 <= point <= 0xdfff and chr(point).lower() != chr(point)]
    values += ["ΟΣ", "ΟΣΑ", "AΣ\u0301", "AΣ\u0345", "AΣ\u0345A", "AΣ'A", "AΣ\u00b7"]
    roots = ["C:\\" + value for value in values]
    paths = [root.lower() + "\\file" for root in roots]
    assert len(roots) > 1000
    assert all(path_in_root(path, root) for path, root in zip(paths, roots, strict=True))
    with psycopg.connect(acl_pg) as conn:
        rows = conn.execute("""select public.file_audit_path_in_root_v264(path,root)
            from unnest(%s::text[],%s::text[]) as inputs(path,root)""", (paths, roots)).fetchall()
        assert len(rows) == len(roots) and all(row[0] is True for row in rows)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("kind", ["string", "array", "object"])
def test_regression_canonical_exact_page_and_one_byte_over(acl_pg, kind):
    import psycopg
    overhead = {"string": 2, "array": 4, "object": 8}[kind]
    text = "x" * (49152 - overhead)
    wrap = {"string": lambda value: value, "array": lambda value: [value],
            "object": lambda value: {"a": value}}[kind]
    allowed, oversized = wrap(text), wrap(text + "x")
    assert len(canonical(allowed)) == 49152 and len(canonical(oversized)) == 49153
    with psycopg.connect(acl_pg) as conn:
        actual = conn.execute("select public.file_audit_snapshot_canonical_v264(%s::jsonb)",
                              (json.dumps(allowed),)).fetchone()[0]
        assert actual.encode("ascii") == canonical(allowed)
        with conn.transaction(force_rollback=True), pytest.raises(
            psycopg.errors.RaiseException, match="file_audit_snapshot_content_invalid"
        ):
            conn.execute("select public.file_audit_snapshot_canonical_v264(%s::jsonb)", (json.dumps(oversized),))


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_regression_unicode_root_accepted_with_retained_provenance(acl_pg):
    import psycopg
    from server.sli.plugins.file_audit.management import _snapshot
    root = "C:\\ДАННЫЕ"
    with psycopg.connect(acl_pg) as conn:
        item = seed(conn)
        item["share"]["path"] = root
        item["objects"][0]["path"] = "C:\\данные\\file"
        item["snapshot_sha256"] = digest({key: value for key, value in item.items()
                                          if key not in ("snapshot_sha256", "snapshot_id")})
        item["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + item["snapshot_sha256"]))
        config = {"inventory_objects": 100000, "roots": [{"collection_scope_id": SCOPE,
                  "share_name": "synthetic", "path": root}]}
        command = {"policy_revision": "1", "collection_scope_ids": [SCOPE], "command_id": COMMAND}
        assert _snapshot(item, config, command) == item
        conn.execute("update sli_agents set assigned_modules=jsonb_set(assigned_modules,'{0,config,roots,0,path}',%s::jsonb)",
                     (json.dumps(root),))
        conn.execute("update sli_plugin_file_audit.policy_revisions set policy=jsonb_set(policy,'{roots,0,path}',%s::jsonb)",
                     (json.dumps(root),))
        conn.execute("update sli_plugin_file_audit.policy_revisions set policy_sha256=encode(sha256(convert_to(policy::text,'UTF8')),'hex')")
        conn.execute("""update sli_plugin_file_audit.access_snapshots set snapshot_id=%s,
            snapshot_sha256=%s,snapshot=%s::jsonb""", (item["snapshot_id"], item["snapshot_sha256"], json.dumps(item)))
        assert verified(conn, item)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_regression_provenance_reads_only_required_server_columns_with_real_owner(acl_pg):
    import psycopg
    with psycopg.connect(acl_pg, autocommit=True) as conn:
        item = seed(conn)
        conn.execute("alter table public.servers add column private_note text")
        assert conn.execute("select pg_get_userbyid(relowner) from pg_class where oid='public.servers'::regclass").fetchone()[0] == "adlog_user"
        assert not conn.execute("select has_table_privilege('adlog_storage_owner','public.servers','SELECT')").fetchone()[0]
        for column in ("hostname", "is_active", "domain_id"):
            assert conn.execute("select has_column_privilege('adlog_storage_owner','public.servers',%s,'SELECT')", (column,)).fetchone()[0]
        assert not conn.execute("select has_column_privilege('adlog_storage_owner','public.servers','private_note','SELECT')").fetchone()[0]
        assert verified(conn, item)
        tables = [(table, conn.execute("select %s::regclass::oid", (table,)).fetchone()[0])
                  for table in ("public.servers", "sli_plugin_file_audit.access_snapshots")]
        conn.execute("set session authorization adlog_semantic_worker")
        try:
            for table, oid in tables:
                assert not conn.execute("select has_table_privilege(current_user,%s,'SELECT')", (oid,)).fetchone()[0]
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute("select * from " + table)
        finally:
            conn.execute("reset session authorization")
