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

from tests.postgres_integration_guard import assert_disposable_database

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


def drain(db):
    db.execute("update sli_agents set applied_policy_revision=policy_revision,applied_collection_state='paused' where id in(%s,%s)", (OLD, NEW))
    db.execute("update sli_agents set rights_probe=rights_probe||'{\"runtime_handoff_supported\":true}'::jsonb where id=%s", (NEW,))


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
