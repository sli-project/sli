"""Real PostgreSQL and existing agent DDL/issuer; synthetic sources only.

This reduced fixture exercises migration296 and its direct agent contracts. It
does not claim a complete installation of the unrelated migration1-295 chain.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from psycopg.rows import dict_row

from server.sli.agent_ingest import PostgresLedger, receive_packet
from server.sli.agents import policies, registry, runtime_switch
from server.sli.agents.ca import AgentError, fingerprint
from server.sli.agents.provision import create_issuer_request, create_root, sign_issuer
from server.sli.agents.ca import IssuingCA
from sli_agent.ad_dc import ADDCModule
from sli_agent.envelope import make_packet
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_agent_registry import request

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
ROOT = Path(__file__).resolve().parents[2] / "config/postgres_migrations"
OLD, NEW, HOST, TRANSPORT = [str(uuid4()) for _ in range(4)]


def part(name, start, end):
    text = (ROOT / name).read_text("utf-8-sig")
    offset = text.index(start)
    return text[offset:text.index(end, offset)]


@pytest.fixture
def db():
    import psycopg
    from psycopg import sql
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable empty PostgreSQL required")
    with psycopg.connect(dsn, autocommit=True, row_factory=dict_row) as conn:
        assert_disposable_database(conn)
        for role in ("adlog_storage_owner", "adlog_user", "adlog_file_audit_owner", "adlog_file_audit_runtime", "adlog_storage_worker", "adlog_semantic_worker", "sli_workstation_inventory_owner"):
            if not conn.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                conn.execute(sql.SQL("create role {} nologin noinherit").format(sql.Identifier(role)))
        conn.execute("grant adlog_file_audit_owner to adlog_storage_owner")
        conn.execute("grant usage,create on schema public to adlog_storage_owner")
        conn.execute("create schema sli_plugin_file_audit authorization adlog_file_audit_owner")
        conn.execute("set role adlog_file_audit_owner")
        conn.execute(part("183_file_audit_contracts.sql", "create table sli_plugin_file_audit.settings", "reset role;"))
        conn.execute("reset role; set role adlog_storage_owner")
        conn.execute("create table schema_migrations(id bigint generated always as identity,version integer primary key,name text)")
        conn.execute(part("156_agent_registry.sql", "create table sli_agents", "insert into schema_migrations"))
        conn.execute(part("157_agent_packets.sql", "create table sli_agent_module_bindings", "insert into schema_migrations"))
        conn.execute(part("163_agent_policy_revisions.sql", "alter table public.sli_agents", "insert into public.schema_migrations"))
        conn.execute(part("169_agent_collection_control.sql", "alter table public.sli_agents", "insert into public.schema_migrations"))
        conn.execute(part("170_agent_snapshot_stream.sql", "create table public.sli_agent_snapshot_bindings", "reset role;"))
        conn.execute("alter table sli_agent_snapshot_cycles add column publication_state text not null default 'pending'")
        conn.execute(part("171_agent_windows_audit.sql", "alter table public.sli_agents", "insert into public.schema_migrations"))
        conn.execute("alter table sli_agents add column instance_name text, add column file_audit jsonb not null default '{}'::jsonb")
        conn.execute("alter table sli_agent_enrollment_tokens add column instance_name text")
        # Empty group-enrollment linkage; these are enrollment's unrelated lookup seams.
        conn.execute("create table sli_agent_group_approval_links(enrollment_token_id uuid,request_id uuid)")
        conn.execute("create table sli_agent_group_requests(id uuid,token_id uuid,computer_entity_id bigint,instance_name text)")
        conn.execute("create table sli_agent_group_tokens(id uuid,group_id uuid)")
        conn.execute("create table sli_agent_group_members(agent_id uuid,group_id uuid)")
        conn.execute("grant select on sli_agent_group_approval_links,sli_agent_group_requests,sli_agent_group_tokens to adlog_user")
        conn.execute("grant insert on sli_agent_group_members to adlog_user")
        conn.execute("grant update(file_audit,assigned_modules) on sli_agents to adlog_user")
        conn.execute(part("281_agent_registration_hostname.sql", "alter table public.sli_agents", "insert into public.schema_migrations"))
        conn.execute("alter table sli_agent_module_bindings drop constraint sli_agent_module_bindings_module_id_check")
        conn.execute("alter table sli_agent_module_bindings add column password_detection_domain_id bigint")
        conn.execute("create table semantic_default_installation(installation_id uuid)")
        conn.execute("insert into semantic_default_installation values(%s)", (uuid4(),))
        conn.execute("create function public.password_v2_scope_key(jsonb) returns bytea language sql as 'select sha256(convert_to($1::text,''UTF8''))'")
        conn.execute(part("274_agent_ad_binding_issuer.sql", "alter table public.sli_agent_policy_history", "insert into public.schema_migrations"))
        conn.execute("grant select(id,host_id,status,policy_revision,file_audit,assigned_modules) on sli_agents to adlog_file_audit_owner")
        conn.execute("""
            create table plugin_state(plugin_id text,installed boolean,enabled boolean);
            insert into plugin_state values('sli.workstations',true,true);
            create function read_plugin_states_v1() returns setof plugin_state language sql stable as 'select * from public.plugin_state';
            create table storage_v2_entity_type(id integer generated always as identity primary key,value text unique);
            create table storage_v2_entity_identity_allocations(id integer generated always as identity primary key,
                entity_type_id integer,natural_key text,unique(entity_type_id,natural_key));
            create table entities_v2(id integer primary key,entity_type_id integer,natural_key text,display_name text,
                first_seen_utc timestamptz,last_seen_utc timestamptz,source_core_sha256 bytea,unique(entity_type_id,natural_key));
            create table core_entity_identifiers(entity_id integer,entity_kind text,namespace text,scope_id text,
                value text,strength text,unique(entity_kind,namespace,scope_id,value,strength));
            create table core_entity_observations(observation_sha256 bytea primary key,plugin_id text,source_instance_id text,
                entity_kind text,entity_id integer,observed_at_utc timestamptz,identifiers_json jsonb,evidence_refs text[],
                resolution text,candidate_ids integer[],reason text);
            create table core_entity_associations(source_entity_id integer,target_entity_id integer,relation text);
        """)
        conn.execute(part("160_agent_workstation_dispatch.sql", "create function public.resolve_agent_workstation_v160", "insert into public.schema_migrations"))
        conn.execute(part("219_finding_evidence_refs.sql", "create table public.finding_evidence_source_bindings", "create function public.finding_evidence_scope_allowed"))
        conn.execute(part("273_password_attacks_v2.sql", "create function public.password_v2_configured_identity", "create function public.password_v2_coverage_execution"))
        conn.execute(part("264_file_audit_acl_bridge.sql", "create or replace function public.resolve_finding_evidence_ref", "revoke all on function public.resolve_finding_evidence_ref"))
        conn.execute("create table events_v2_core(id bigint,log_source_id bigint,normalized_hash bytea,raw_log_file_id bigint)")
        conn.execute("create table raw_log_files(id bigint,file_path text)")
        conn.execute("reset role; set role adlog_file_audit_owner")
        conn.execute(part("185_file_audit_management.sql", "create function sli_plugin_file_audit.enqueue_audit", "reset role;"))
        conn.execute("reset role; set role adlog_storage_owner")
        conn.execute("reset role; grant sli_workstation_inventory_owner to adlog_storage_owner")
        conn.execute("create schema sli_plugin_workstations authorization adlog_storage_owner")
        conn.execute("grant usage,create on schema sli_plugin_workstations to sli_workstation_inventory_owner")
        conn.execute("set role sli_workstation_inventory_owner")
        conn.execute(part("287_workstation_inventory_job.sql", "create function sli_plugin_workstations.inventory_inputs_v1", "create function sli_plugin_workstations.inventory_text_v1"))
        conn.execute("reset role; set role adlog_storage_owner")
        conn.execute("reset role; revoke create on schema sli_plugin_workstations from sli_workstation_inventory_owner; set role adlog_storage_owner")
        conn.execute("insert into schema_migrations(version,name) values(274,'agent_ad_binding_issuer'),(281,'agent_registration_hostname'),(287,'workstation_inventory_job')")
        conn.execute("reset role")
        conn.execute((ROOT / "296_agent_runtime_switch.sql").read_text("utf-8"))
        conn.execute("set role adlog_user")
        yield conn


def authorize_replacement(db, old=OLD, new=NEW):
    return db.execute("""insert into sli_agent_enrollment_tokens
        (id,token_hash,host_id,key_fingerprint,created_at,expires_at,used_at,replacement_for,enrolled_agent_id)
        select %s,%s,host_id,key_fingerprint,clock_timestamp(),clock_timestamp()+interval '15 minutes',
            clock_timestamp(),%s,id from sli_agents where id=%s returning id""",
        (uuid4(), uuid4().hex * 2, old, new)).fetchone()["id"]


def seed(db, *, module="sli.windows.ad-dc", hostname="host.example.invalid"):
    config = ADDCModule(HOST, {"source_name": hostname, "connect_address": hostname}).config
    modules = [{"module_id": module, "enabled": True, "config": config}] if module else []
    db.execute("reset role; set role adlog_storage_owner")
    for agent, host, assigned in ((OLD, HOST, modules), (NEW, TRANSPORT, [])):
        db.execute("insert into sli_agents(id,host_id,key_fingerprint,registration_host_name,assigned_modules) values(%s,%s,%s,%s,%s::jsonb)",
                   (agent, host, "a" * 64, hostname, json.dumps(assigned)))
        db.execute("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(%s,%s,%s,clock_timestamp(),clock_timestamp()+interval '1 day')",
                   (agent, "a" if agent == OLD else "b", ("a" if agent == OLD else "b") * 64))
    if module:
        db.execute("insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,source_name,channel,module_version,policy_revision,password_detection_domain_id) values(%s,%s,%s,%s,'ad-dc','1.0.0','1',42)",
                   (OLD, module, HOST, hostname))
    db.execute("reset role; set role adlog_user")
    authorize_replacement(db)
    return modules


def switch(db, phase):
    with db.transaction(), db.cursor() as cur:
        return runtime_switch.replace(cur, {"old_agent_id": OLD, "new_agent_id": NEW, "phase": phase, "confirm": True},
                                      actor="session:1", access={"platform_owner": True})


def drain(db):
    db.execute("update sli_agents set applied_policy_revision=policy_revision,applied_collection_state='paused' where id in(%s,%s)", (OLD, NEW))
    db.execute("update sli_agents set rights_probe=rights_probe||'{\"runtime_handoff_supported\":true}'::jsonb where id=%s", (NEW,))


def test_rollback_restores_capabilities_and_allows_reapply_with_neighbor_markers(db):
    seed(db, module=None)
    db.execute("reset role; set role adlog_storage_owner")
    saved = db.execute("select * from sli_agent_runtime_switch_restore_v296 order by object_key").fetchall()
    function_oids = [int(item["object_key"]) for item in saved if item["object_key"].isdigit()]
    function_oids.append(db.execute("select 'public.agent_ad_issue_binding()'::regprocedure::oid as id").fetchone()["id"])
    capability_sql = "select oid,proowner,proacl from pg_proc where oid=any(%s::oid[]) order by oid"
    capabilities = db.execute(capability_sql, (function_oids,)).fetchall()
    agents = db.execute("select id,status,host_id,assigned_modules from sli_agents order by id").fetchall()
    db.execute((ROOT / "296_agent_runtime_switch.rollback.sql").read_text("utf-8"))
    for item in saved:
        if item["object_key"] == "audit_constraint":
            restored = db.execute("select pg_get_expr(conbin,conrelid) as definition from pg_constraint "
                                  "where conrelid='sli_agent_audit'::regclass and conname='sli_agent_audit_action_check'").fetchone()
        else:
            signature = "public.agent_ad_issue_binding()" if item["object_key"] == "issuer" else item["object_key"]
            restored = db.execute("select pg_get_functiondef(%s::oid) as definition", (signature,)).fetchone() if signature.isdigit() else db.execute(
                "select pg_get_functiondef(%s::regprocedure) as definition", (signature,)).fetchone()
        assert restored["definition"] == item["definition"]
    assert db.execute(capability_sql, (function_oids,)).fetchall() == capabilities
    assert db.execute("select id,status,host_id,assigned_modules from sli_agents order by id").fetchall() == agents
    assert db.execute("select 1 from schema_migrations where version=296").fetchone() is None
    assert db.execute("select to_regclass('public.sli_agent_runtime_switch_restore_v296') as name").fetchone()["name"] is None
    assert db.execute("select to_regclass('public.sli_agent_runtime_switches') as name").fetchone()["name"] is None
    assert db.execute("select 1 from pg_attribute where attrelid='sli_agents'::regclass "
                      "and attname in ('source_host_id','source_agent_id','runtime_resume') and not attisdropped").fetchone() is None
    # Adjacent independent migrations are allowed, including the existing 287.
    db.execute("insert into schema_migrations(version,name) select v,'synthetic_neighbor' from generate_series(288,295) v")
    db.execute((ROOT / "296_agent_runtime_switch.sql").read_text("utf-8"))
    assert db.execute("select name from schema_migrations where version=296").fetchone()["name"] == "agent_runtime_switch"
    assert db.execute("select count(*) as n from schema_migrations where version between 287 and 295").fetchone()["n"] == 9
    db.execute("set role adlog_user")
    authorize_replacement(db)
    assert switch(db, "prepare")["state"] == "draining"
    drain(db)
    assert switch(db, "complete")["state"] == "completed"


@pytest.mark.parametrize("completed", [False, True])
def test_rollback_refuses_handoff_without_losing_data(db, completed):
    import psycopg

    seed(db, module=None)
    switch(db, "prepare")
    if completed:
        drain(db)
        switch(db, "complete")
    db.execute("reset role; set role adlog_storage_owner")
    before = db.execute("select to_jsonb(s) as row from sli_agent_runtime_switches s").fetchall()
    agents = db.execute("select to_jsonb(a) as row from sli_agents a order by id").fetchall()
    code = "replaced_agents" if completed else "handoff_exists"
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match=f"agent_runtime_switch_rollback_{code}"):
        db.execute((ROOT / "296_agent_runtime_switch.rollback.sql").read_text("utf-8"))
    db.execute("rollback")
    assert db.execute("select to_jsonb(s) as row from sli_agent_runtime_switches s").fetchall() == before
    assert db.execute("select to_jsonb(a) as row from sli_agents a order by id").fetchall() == agents
    assert db.execute("select name from schema_migrations where version=296").fetchone()["name"] == "agent_runtime_switch"


@pytest.mark.parametrize("denial", ["membership", "successor", "wrong_marker"])
def test_rollback_checks_prerequisites_before_dropping_objects(db, denial):
    import psycopg

    db.execute("reset role")
    if denial == "membership":
        db.execute("set session authorization adlog_user")
    elif denial == "successor":
        db.execute("insert into schema_migrations(version,name) values(297,'synthetic_successor')")
    else:
        db.execute("update schema_migrations set name='wrong' where version=296")
    try:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="agent_runtime_switch_rollback_preflight"):
            db.execute((ROOT / "296_agent_runtime_switch.rollback.sql").read_text("utf-8"))
    finally:
        db.execute("rollback; reset session authorization")
    assert db.execute("select to_regclass('public.sli_agent_runtime_switches') as name").fetchone()["name"]
    assert db.execute("select to_regprocedure('public.replace_agent_runtime_v296(uuid,uuid,text,text)') as name").fetchone()["name"]


def test_replacement_preserves_source_and_policy_and_revokes_after_drain(db):
    modules = seed(db)
    assert switch(db, "prepare")["state"] == "draining"
    with pytest.raises(AgentError, match="agent_replacement_not_ready"):
        switch(db, "complete")
    assert db.execute("select count(*) as n from sli_agent_certificates where revoked_at is not null").fetchone()["n"] == 0
    drain(db)
    assert switch(db, "complete")["state"] == "completed"
    new = db.execute("select * from sli_agents where id=%s", (NEW,)).fetchone()
    assert str(new["host_id"]) == TRANSPORT and str(new["source_host_id"]) == HOST
    assert str(new["source_agent_id"]) == OLD and new["assigned_modules"] == modules
    binding = db.execute("select * from sli_agent_module_bindings where agent_id=%s", (NEW,)).fetchone()
    assert binding["source_instance_id"] == HOST and binding["password_detection_domain_id"] == 42
    assert db.execute("select status from sli_agents where id=%s", (OLD,)).fetchone()["status"] == "replaced"
    assert db.execute("select revoked_at from sli_agent_certificates where agent_id=%s", (OLD,)).fetchone()["revoked_at"]
    assert switch(db, "complete")["state"] == "completed"
    with db.transaction(), db.cursor() as cur:
        # Subsequent ordinary policy changes retain the adopted source binding.
        policies.assign_module(cur, {"agent_id": NEW, "module_id": "sli.windows.ad-dc", "enabled": True,
            "expected_revision": new["policy_revision"], "config": {"source_name": "host.example.invalid", "connect_address": "host.example.invalid"}}, actor="session:1")
    assert db.execute("select source_instance_id from sli_agent_module_bindings where agent_id=%s", (NEW,)).fetchone()["source_instance_id"] == HOST


@pytest.mark.parametrize("reason", ["hostname", "late_failure", "policy_changed"])
def test_failed_switch_never_partially_transfers_or_revokes(db, reason):
    import psycopg
    seed(db)
    switch(db, "prepare")
    drain(db)
    if reason == "hostname":
        db.execute("reset role; set role adlog_storage_owner")
        db.execute("update sli_agents set registration_host_name='other.example.invalid' where id=%s", (NEW,))
        db.execute("reset role; set role adlog_user")
    elif reason == "late_failure":
        # Force a late failure AFTER copying authority to prove transaction rollback.
        db.execute("reset role; set role adlog_storage_owner")
        db.execute("alter table sli_agents add constraint late_failure check(status<>'replaced')")
        db.execute("reset role; set role adlog_user")
    else:
        db.execute("update sli_agents set policy_revision=policy_revision+1 where id=%s", (OLD,))
    with pytest.raises((AgentError, psycopg.errors.CheckViolation)):
        switch(db, "complete")
    assert db.execute("select source_host_id from sli_agents where id=%s", (NEW,)).fetchone()["source_host_id"] is None
    assert db.execute("select count(*) as n from sli_agent_module_bindings where agent_id=%s", (NEW,)).fetchone()["n"] == 0
    assert db.execute("select count(*) as n from sli_agent_certificates where revoked_at is not null").fetchone()["n"] == 0


def test_source_authority_cannot_be_forged_on_insert_or_update(db):
    import psycopg
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute("insert into sli_agents(id,host_id,key_fingerprint,source_host_id) values(%s,%s,%s,%s)",
                   (uuid4(), uuid4(), "a" * 64, uuid4()))
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        db.execute("insert into sli_agent_runtime_switches(old_agent_id,new_agent_id,state,old_revision,new_revision,old_control,actor) values(%s,%s,'draining',1,1,'{}','session:1')", (OLD, NEW))
    assert db.execute("select has_function_privilege('adlog_semantic_worker','public.replace_agent_runtime_v296(uuid,uuid,text,text)','EXECUTE') as allowed").fetchone()["allowed"] is False
    assert db.execute("select has_function_privilege('adlog_user','sli_plugin_file_audit.copy_runtime_v296(uuid,uuid,bigint)','EXECUTE') as allowed").fetchone()["allowed"] is False
    assert db.execute("select has_schema_privilege('sli_workstation_inventory_owner','sli_plugin_workstations','CREATE') as allowed").fetchone()["allowed"] is False


@pytest.mark.parametrize("kind", ["ordinary", "group", "wrong_old", "unlinked", "unused"])
@pytest.mark.parametrize("phase", ["prepare", "complete"])
def test_matching_hostname_cannot_replace_without_exact_replacement_token(db, kind, phase):
    seed(db, module=None)
    if phase == "complete":
        switch(db, "prepare")
        drain(db)
    db.execute("reset role; set role adlog_storage_owner")
    token = db.execute("select id from sli_agent_enrollment_tokens where enrolled_agent_id=%s", (NEW,)).fetchone()["id"]
    if kind == "ordinary":
        db.execute("update sli_agent_enrollment_tokens set replacement_for=null where id=%s", (token,))
    elif kind == "group":
        db.execute("insert into sli_agent_group_approval_links values(%s,%s)", (token, uuid4()))
    elif kind == "wrong_old":
        db.execute("update sli_agent_enrollment_tokens set replacement_for=%s where id=%s", (NEW, token))
    elif kind == "unlinked":
        db.execute("update sli_agent_enrollment_tokens set enrolled_agent_id=null where id=%s", (token,))
    else:
        db.execute("update sli_agent_enrollment_tokens set enrolled_agent_id=null,used_at=null where id=%s", (token,))
    # Even an audit claiming approval must not supply the missing authority.
    registry.audit(db.cursor(), "token_create", "session:1", str(token), replacement_for=OLD)
    before = db.execute("select to_jsonb(a) as row from sli_agents a order by id").fetchall()
    db.execute("reset role; set role adlog_user")
    with pytest.raises(AgentError, match="agent_replacement_token_mismatch"):
        switch(db, phase)
    assert db.execute("select to_jsonb(a) as row from sli_agents a order by id").fetchall() == before
    assert db.execute("select count(*) as n from sli_agent_certificates where revoked_at is not null").fetchone()["n"] == 0


@pytest.mark.parametrize("signature,before,after", [
    ("public.agent_ad_issue_binding()", "new.host_id::text", "(new.host_id)::text"),
    ("public.agent_ad_issue_binding()", "    -- OLD/NEW are actual locked rows", "    -- locked rows"),
    ("public.agent_ad_issue_binding()", "and agent_id<>new.id)", "and agent_id <> new.id)"),
    ("sli_plugin_file_audit.enqueue_audit(uuid,text,jsonb,jsonb,text,bigint)", "and host_id::text=p_source", "and host_id::text = p_source"),
    ("public.password_v2_configured_identity(uuid)", "a.host_id", "a .host_id"),
    ("public.password_v2_configured_identity(uuid)", "where id=p_agent;", "where id = p_agent;"),
    ("public.password_v2_configured_identity(uuid)", "where agent_id=p_agent and module_id=", "where agent_id = p_agent and module_id="),
    ("public.password_v2_configured_identity(uuid)", "f.agent_id=p_agent", "f.agent_id = p_agent"),
    ("public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)", "inbox.envelope->>'agent_id'=b.agent_id::text", "inbox.envelope->>'agent_id' = b.agent_id::text"),
    ("public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)", "o.agent_id=b.agent_id", "o.agent_id = b.agent_id"),
    ("public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)", "file_ransom_evidence_in_root(b.agent_id,", "file_ransom_evidence_in_root( b.agent_id,"),
    ("public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)", "file_decoy_evidence_in_root(b.agent_id,", "file_decoy_evidence_in_root( b.agent_id,"),
    ("sli_plugin_workstations.inventory_inputs_v1(bigint)", "a.id::text", "(a.id)::text"),
    ("sli_plugin_workstations.inventory_inputs_v1(bigint)", "from public.sli_agents a where exists(", "from public.sli_agents a where exists ("),
    ("public.resolve_agent_workstation_v160(uuid,uuid)", "v_host uuid;", "v_host  uuid;"),
    ("public.resolve_agent_workstation_v160(uuid,uuid)", "select a.host_id into v_host", "select a.host_id into  v_host"),
    ("public.resolve_agent_workstation_v160(uuid,uuid)", "p_agent::text", "(p_agent)::text"),
])
def test_each_definition_replacement_fails_closed_on_drift(db, signature, before, after):
    import psycopg

    db.execute("reset role")
    db.execute((ROOT / "296_agent_runtime_switch.rollback.sql").read_text("utf-8"))
    original = db.execute("select pg_get_functiondef(%s::regprocedure) as definition", (signature,)).fetchone()["definition"]
    assert before in original
    db.execute(original.replace(before, after))
    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="migration_296_definition_drift"):
        db.execute((ROOT / "296_agent_runtime_switch.sql").read_text("utf-8"))
    db.execute("rollback")
    assert db.execute("select 1 from schema_migrations where version=296").fetchone() is None
    assert db.execute("select to_regclass('public.sli_agent_runtime_switches') as name").fetchone()["name"] is None


@pytest.mark.parametrize("reason", ["client", "inbox", "snapshot"])
def test_completion_waits_for_supported_client_and_all_server_publications(db, reason):
    seed(db)
    switch(db, "prepare")
    drain(db)
    if reason == "client":
        db.execute("update sli_agents set rights_probe='{}' where id=%s", (NEW,))
        expected = "agent_replacement_client_unsupported"
    elif reason == "snapshot":
        from tests.unit.test_agent_snapshot_stream import config
        snapshot = config(source_instance_id=HOST)
        db.execute("insert into sli_agent_snapshot_bindings values(%s,'sli.ad-snapshot',%s::jsonb,default,true)", (OLD, json.dumps(snapshot)))
        db.execute("insert into sli_agent_snapshot_cycles(cycle_id,agent_id,module_id,slot_start_utc,domain_sid,policy) values(%s,%s,'sli.ad-snapshot','2026-10-29T00:00:00+00:00',%s,%s::jsonb)",
                   (uuid4(), OLD, snapshot["domain_sid"], json.dumps(snapshot)))
        expected = "agent_replacement_pending_import"
    else:
        from sli_agent.envelope import digest
        now = datetime.now(timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        sample = ADDCModule(HOST, {"source_name": "host.example.invalid", "connect_address": "host.example.invalid"}, reader=lambda *_: []).collect(now=now)
        packet = make_packet(key, agent_id=OLD, sequence=1, sample=sample, now=now)
        with db.cursor() as cur:
            PostgresLedger(cur).commit(packet, {"status": "committed"}, digest(packet["envelope"]), [])
        expected = "agent_replacement_pending_import"
    with pytest.raises(AgentError, match=expected):
        switch(db, "complete")
    assert db.execute("select status from sli_agents where id=%s", (OLD,)).fetchone()["status"] == "active"
    assert db.execute("select source_host_id from sli_agents where id=%s", (NEW,)).fetchone()["source_host_id"] is None


def test_replacement_token_enrolls_idle_without_retiring_old(db):
    seed(db, module=None)
    root_key, root = create_root()
    issuer_key, csr = create_issuer_request()
    ca = IssuingCA(root, sign_issuer(root, root_key, csr), issuer_key)
    key, host = ec.generate_private_key(ec.SECP256R1()), str(uuid4())
    with db.transaction(), db.cursor() as cur:
        token = registry.create_token(cur, {"host_id": host, "key_fingerprint": fingerprint(key.public_key()),
            "replacement_for": OLD, "registration_host_name": "host.example.invalid"}, actor="session:1")
        result = registry.enroll(cur, ca, {"token": token["token"], "csr_pem": request(key, host), "reported_hostname": "host.example.invalid"})
    agent = db.execute("select * from sli_agents where id=%s", (result["agent_id"],)).fetchone()
    assert agent["collection_policy"]["state"] == "drain" and agent["assigned_modules"] == []
    assert db.execute("select status from sli_agents where id=%s", (OLD,)).fetchone()["status"] == "active"
    link = db.execute("select replacement_for,enrolled_agent_id,used_at from sli_agent_enrollment_tokens where id=%s", (token["id"],)).fetchone()
    assert str(link["replacement_for"]) == OLD and str(link["enrolled_agent_id"]) == result["agent_id"]
    assert link["used_at"] is not None
    with db.transaction(), db.cursor() as cur:
        assert runtime_switch.replace(cur, {"old_agent_id": OLD, "new_agent_id": result["agent_id"], "phase": "prepare", "confirm": True},
            actor="session:1", access={"platform_owner": True})["state"] == "draining"


def test_signed_packets_continue_committed_cursor_and_exact_replay_never_duplicates(db, monkeypatch):
    from tests.unit.test_sli_agent_ad_dc import xml
    seed(db)
    now = datetime(2026, 10, 7, tzinfo=timezone.utc)
    root_key, root = create_root()
    issuer_key, csr = create_issuer_request()
    ca = IssuingCA(root, sign_issuer(root, root_key, csr), issuer_key)
    keys, ders = {}, {}
    db.execute("reset role; set role adlog_storage_owner")
    db.execute("delete from sli_agent_certificates")
    for agent, host in ((OLD, HOST), (NEW, TRANSPORT)):
        key = ec.generate_private_key(ec.SECP256R1())
        keys[agent] = key
        cert = ca.issue(registry.parse_csr(request(key, host), host), agent, host)
        ders[agent] = cert.public_bytes(serialization.Encoding.DER)
        with db.cursor() as cur:
            registry._store_cert(cur, cert, agent)
    db.execute("reset role; set role adlog_user")
    monkeypatch.setattr(PostgresLedger, "quota_error", lambda *args: None)
    def sample(record, captured=None):
        return ADDCModule(HOST, {"source_name": "host.example.invalid", "connect_address": "host.example.invalid"},
            reader=lambda channel, cursor, limit: [(xml(4624, record).replace("fixture-dc", "host.example.invalid"), f"bookmark-{record}")]
                if channel == "Security" and (cursor["record_id"] or 0) < record else []).collect(captured, now=now, channel="Security")
    first = make_packet(keys[OLD], agent_id=OLD, sequence=1, sample=sample(10), now=now)
    def deliver(agent, packet):
        with db.transaction(), db.cursor() as cur:
            identity = registry.authenticate(cur, ca, ders[agent])
            return receive_packet(PostgresLedger(cur), identity=identity, public_key=keys[agent].public_key(), value=packet, now=now)
    accepted = deliver(OLD, first)
    assert accepted["status"] == "committed", accepted
    db.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp()")
    switch(db, "prepare")
    drain(db)
    switch(db, "complete")
    with pytest.raises(AgentError, match="agent_certificate_rejected"):
        deliver(OLD, first)
    # A fresh sequence namespace; the data identity and multiplexed cursor are unchanged.
    second = make_packet(keys[NEW], agent_id=NEW, sequence=1, sample=sample(11, first["envelope"]), now=now)
    accepted = deliver(NEW, second)
    assert accepted["status"] == "committed", accepted
    assert deliver(NEW, second)["status"] == "duplicate"
    repeated = make_packet(keys[NEW], agent_id=NEW, sequence=2, sample=sample(10), now=now)
    assert deliver(NEW, repeated)["error_code"] == "agent_cursor_mismatch"
    assert db.execute("select count(*) as n from sli_agent_receipts").fetchone()["n"] == 2
    assert db.execute("select count(distinct envelope->>'source_instance_id') as n from sli_agent_packet_inbox").fetchone()["n"] == 1
    assert db.execute("select count(*) as n from sli_agent_packet_inbox cross join lateral jsonb_array_elements(event_rows)").fetchone()["n"] == 2
    # Native authority remains bound to the original source; both transports'
    # immutable core evidence stays verifiable without rewriting old bindings.
    db.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp()")
    db.execute("reset role; set role adlog_storage_owner")
    installation = db.execute("select installation_id from semantic_default_installation").fetchone()["installation_id"]
    db.execute("""insert into finding_evidence_source_bindings
        values((select oid from pg_roles where rolname=session_user),session_user,%s,'sli.windows.ad-dc',%s,%s,'','core_event',1,null,%s)""",
        (installation, HOST, HOST, OLD))
    for index, packet in enumerate((first, second), 1):
        db.execute("insert into raw_log_files values(%s,%s)", (index, "agent-packet:" + packet["envelope"]["packet_id"]))
        db.execute("insert into events_v2_core values(%s,1,decode(%s,'hex'),%s)", (index, "a" * 64, index))
        assert db.execute("select resolve_finding_evidence_ref(%s,'sli.windows.ad-dc',%s,%s,'','core_event',%s,%s) as valid",
                          (installation, HOST, HOST, str(index), "a" * 64)).fetchone()["valid"] is True
    for agent in (OLD, NEW):
        context = db.execute("select password_v2_configured_identity(%s) as context", (agent,)).fetchone()["context"]
        assert context["scope"]["source_instance_id"] == HOST and context["domain_id"] == 42


def test_workstation_identity_and_report_population_stay_single(db):
    from server.sli.plugins.workstations.scope import REGISTERED
    from sli_agent.workstations import WorkstationsModule
    from sli_agent.envelope import digest
    seed(db, module=None)
    modules = [{"module_id": "sli.workstations", "enabled": True, "config": WorkstationsModule(HOST).policy}]
    db.execute("update sli_agents set assigned_modules=%s::jsonb where id=%s", (json.dumps(modules), OLD))

    def receipt(agent):
        packet = str(uuid4())
        envelope = {"agent_id": agent, "module_id": "sli.workstations", "source_instance_id": HOST,
                    "channel": "workstations", "generation": HOST, "cursor_after": {"strategy": "bookmark", "token": ""}}
        db.execute("insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt) values(%s,'sli.workstations',1,%s,%s,%s::jsonb,%s::jsonb)",
                   (agent, packet, digest(envelope), json.dumps(envelope), '{"status":"committed"}'))
        return db.execute("select * from resolve_agent_workstation_v160(%s,%s)", (agent, packet)).fetchone()

    first = receipt(OLD)
    switch(db, "prepare")
    drain(db)
    switch(db, "complete")
    second = receipt(NEW)
    assert first == second and first["entity_id"]
    population = db.execute(REGISTERED).fetchall()
    assert len(population) == 1
    assert population[0]["agent_key"] == OLD and population[0]["source_instance_id"] == HOST
    db.execute("reset role; set role adlog_storage_owner")
    assert db.execute("select count(*) as n from entities_v2").fetchone()["n"] == 1


def test_snapshot_bindings_and_file_audit_settings_keep_original_scopes(db):
    from tests.unit.test_agent_snapshot_stream import config as snapshot_config
    from tests.unit.test_file_audit_contracts import settings
    from sli_agent.file_audit_policy import policy as file_policy
    seed(db, module=None)
    snapshot = snapshot_config(source_instance_id=HOST)
    gpo = snapshot_config("sli.gpo-snapshot", source_instance_id=HOST)
    file = file_policy(settings())
    modules = [{"module_id": module, "enabled": True, "config": config} for module, config in
               (("sli.ad-snapshot", snapshot), ("sli.gpo-snapshot", gpo), ("sli.file-audit", file))]
    command = {"contract_id": "sli.file-audit.audit-command.v1", "command_id": str(uuid4()), "action": "apply",
               "policy_revision": "1", "collection_scope_ids": ["scope:one"]}
    db.execute("update sli_agents set assigned_modules=%s::jsonb,file_audit=%s::jsonb where id=%s",
               (json.dumps(modules), json.dumps({"request": {"config": file, "command": command}, "may_own_audit": True}), OLD))
    for module, config in (("sli.ad-snapshot", snapshot), ("sli.gpo-snapshot", gpo)):
        db.execute("insert into sli_agent_snapshot_bindings(agent_id,module_id,config,enabled) values(%s,%s,%s::jsonb,true)", (OLD, module, json.dumps(config)))
        db.execute("insert into sli_agent_snapshot_policies(agent_id,module_id,config,enabled) values(%s,%s,%s::jsonb,true)", (OLD, module, json.dumps(config)))
    db.execute("reset role; set role adlog_file_audit_owner")
    db.execute("insert into sli_plugin_file_audit.policy_revisions values(%s,%s,1,clock_timestamp(),'session',1,%s::jsonb,%s)", (OLD, HOST, json.dumps(file), "a" * 64))
    db.execute("insert into sli_plugin_file_audit.audit_commands values(%s,%s,%s,1,'apply',array['scope:one'],clock_timestamp(),'session',1,%s)", (command["command_id"], OLD, HOST, "a" * 64))
    db.execute("reset role; set role adlog_user")
    switch(db, "prepare")
    drain(db)
    result = switch(db, "complete")
    assert db.execute("select count(*) as n from sli_agent_snapshot_bindings where enabled").fetchone()["n"] == 2
    new_bindings = db.execute("select config from sli_agent_snapshot_bindings where agent_id=%s order by module_id", (NEW,)).fetchall()
    assert all(b["config"]["source_instance_id"] == HOST for b in new_bindings)
    agent = db.execute("select * from sli_agents where id=%s", (NEW,)).fetchone()
    assert agent["file_audit"]["request"]["config"]["roots"] == file["roots"]
    assert agent["file_audit"]["request"]["command"]["command_id"] != command["command_id"]
    assert agent["file_audit"]["may_own_audit"] is True
    # Existing cross-owner command issuer must accept the retained source ID.
    with db.transaction():
        revision = result["policy_revision"] + 1
        following = {**command, "command_id": str(uuid4()), "policy_revision": str(revision)}
        db.execute("select sli_plugin_file_audit.enqueue_audit(%s,%s,%s::jsonb,%s::jsonb,'session',1)",
                   (NEW, HOST, json.dumps({**file, "policy_revision": str(revision)}), json.dumps(following)))


def test_nps_continues_same_source_generation_and_bookmark(db, monkeypatch):
    from sli_agent.nps import NPSModule
    from tests.unit.test_sli_agent_nps import CONFIG, event, NOW
    seed(db, module=None)
    config = NPSModule(HOST, CONFIG).policy
    modules = [{"module_id": "sli.vpn-nps", "enabled": True, "config": config}]
    db.execute("update sli_agents set assigned_modules=%s::jsonb where id=%s", (json.dumps(modules), OLD))
    monkeypatch.setattr(PostgresLedger, "quota_error", lambda *args: None)
    key = ec.generate_private_key(ec.SECP256R1())

    def capture(record, previous=None):
        return NPSModule(HOST, config, reader=lambda *_: [(event(record_id=record), f"bookmark-{record}")]).collect(previous, now=NOW)

    def deliver(agent, sample):
        packet = make_packet(key, agent_id=agent, sequence=1, sample=sample, now=NOW)
        with db.transaction(), db.cursor() as cur:
            identity = db.execute("select * from sli_agents where id=%s for update", (agent,)).fetchone()
            receipt = receive_packet(PostgresLedger(cur), identity=identity, public_key=key.public_key(), value=packet, now=NOW)
            assert receipt["status"] == "committed", receipt
        return packet

    first = deliver(OLD, capture(1))
    db.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp()")
    switch(db, "prepare")
    drain(db)
    switch(db, "complete")
    second = deliver(NEW, capture(2, first["envelope"]))
    assert second["envelope"]["source_instance_id"] == first["envelope"]["source_instance_id"] == CONFIG["source_instance_id"]
    assert second["envelope"]["generation"] == HOST
    assert second["envelope"]["cursor_before"] == first["envelope"]["cursor_after"]


def test_second_replacement_before_capture_keeps_inherited_cursor_and_canonical_device(db):
    from sli_agent.envelope import digest
    seed(db)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    sample = ADDCModule(HOST, {"source_name": "host.example.invalid", "connect_address": "host.example.invalid"}, reader=lambda *_: []).collect(now=now)
    packet = make_packet(key, agent_id=OLD, sequence=1, sample=sample, now=now)
    with db.cursor() as cur:
        PostgresLedger(cur).commit(packet, {"status": "committed"}, digest(packet["envelope"]), [])
    db.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp()")
    switch(db, "prepare")
    drain(db)
    switch(db, "complete")
    third = str(uuid4())
    db.execute("insert into sli_agents(id,host_id,key_fingerprint,registration_host_name) values(%s,%s,%s,'host.example.invalid')", (third, uuid4(), "c" * 64))
    db.execute("insert into sli_agent_certificates(agent_id,serial,fingerprint,not_before,not_after) values(%s,'c',%s,clock_timestamp(),clock_timestamp()+interval '1 day')", (third, "c" * 64))
    authorize_replacement(db, NEW, third)
    with db.transaction():
        db.execute("select replace_agent_runtime_v296(%s,%s,'prepare','session:1')", (NEW, third))
    db.execute("update sli_agents set applied_policy_revision=policy_revision,applied_collection_state='paused',rights_probe='{\"runtime_handoff_supported\":true}' where id in(%s,%s)", (NEW, third))
    with db.transaction():
        result = db.execute("select replace_agent_runtime_v296(%s,%s,'complete','session:1') as result", (NEW, third)).fetchone()["result"]
        assert result["state"] == "completed"
    final = db.execute("select * from sli_agents where id=%s", (third,)).fetchone()
    assert str(final["source_agent_id"]) == OLD and str(final["source_host_id"]) == HOST
    assert final["runtime_resume"]["sli.windows.ad-dc"]["cursor_after"] == packet["envelope"]["cursor_after"]
