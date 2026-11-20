"""Additive privilege contract and optional PostgreSQL identity-function exercise."""
import hashlib
import json
import os
from pathlib import Path
import re
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/160_agent_workstation_dispatch.sql").read_text("utf-8")


def test_exact_predecessor_and_disabled_bundled_package():
    assert "version=159 and name='workstation_security'" in SQL
    header, _ = SQL.split("set local role adlog_storage_owner;", 1)
    assert "or exists(select 1 from public.schema_migrations where version>=160)" in header
    assert "raise exception 'migration 160 requires exact migration 159 workstation_security'" in header
    assert "values(160,'agent_workstation_dispatch')" in SQL
    assert "'1.0.0','registered','disabled','unknown','stopped','drained',1,1" in SQL
    # Applied SQL attests the historical package, including its original reports.
    # A separate guard checks current overview additions against this snapshot.
    manifest = json.loads((ROOT / "tests/fixtures/workstations/package-before-overview.v3.json").read_text("utf-8"))
    manifest["data"]["migrations"] = [item for item in manifest["data"]["migrations"] if item["version"] < 160]
    original_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    assert hashlib.sha256(original_bytes).hexdigest() in SQL


def test_runtime_has_only_assignment_update_and_narrow_identity_capability():
    runtime_grants = [s for s in re.findall(r"grant[^;]+;", SQL) if "to adlog_user" in s]
    assert runtime_grants == [
        "grant update(assigned_modules) on public.sli_agents to adlog_user;",
        "grant execute on function public.resolve_agent_workstation_v160(uuid,uuid) to adlog_user;",
    ]
    assert "security definer set search_path=pg_catalog,public" in SQL
    assert "revoke all on function public.resolve_agent_workstation_v160(uuid,uuid) from public" in SQL
    assert "and r.module_id='sli.workstations'" in SQL and "a.status='active'" in SQL
    assert "s.installed and s.enabled" in SQL
    assert "delete from" not in SQL.lower()
    assert "'module_assign'" in SQL
    assert "sli.agent.key" in SQL and "agent-registry" in SQL
    assert "count(distinct a.target_entity_id)=1" in SQL


@pytest.mark.postgres_integration
def test_identity_function_allocates_once_and_is_fail_closed_in_postgresql():
    """Run the function in a private disposable schema, with a capability-only role.

    This checks SQL execution/allocation, not full migration application against
    an installed baseline. All fixture objects and roles roll back on exit.
    """
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL DSN is not configured")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    from tests.postgres_integration_guard import assert_disposable_database
    from server.sli.entities.core_identity import EntityIdentifier

    schema = "agent_dispatch_" + uuid4().hex
    role = "agent_dispatch_" + uuid4().hex
    agent, host, packet = (str(uuid4()) for _ in range(3))
    conn = psycopg.connect(dsn, row_factory=dict_row)
    try:
        assert_disposable_database(conn)
        with conn.cursor() as cur:
            cur.execute(f"create schema {schema}; create role {role} nologin noinherit")
            cur.execute(f"""
                create table {schema}.sli_agents(id uuid primary key,host_id uuid,status text,assigned_modules jsonb,
                    source_host_id uuid,source_agent_id uuid references {schema}.sli_agents(id),
                    runtime_resume jsonb not null default '{{}}'::jsonb check(jsonb_typeof(runtime_resume)='object'));
                create table {schema}.sli_agent_receipts(packet_id uuid primary key,agent_id uuid,module_id text,received_at timestamptz);
                create table {schema}.plugin_state(plugin_id text,installed boolean,enabled boolean);
                create function {schema}.read_plugin_states_v1() returns setof {schema}.plugin_state
                    language sql stable as 'select * from {schema}.plugin_state';
                create table {schema}.storage_v2_entity_type(id integer generated always as identity primary key,value text unique);
                create table {schema}.storage_v2_entity_identity_allocations(id integer generated always as identity primary key,
                    entity_type_id integer,natural_key text,unique(entity_type_id,natural_key));
                create table {schema}.entities_v2(id integer primary key,entity_type_id integer,natural_key text,display_name text,
                    first_seen_utc timestamptz,last_seen_utc timestamptz,source_core_sha256 bytea,unique(entity_type_id,natural_key));
                create table {schema}.core_entity_identifiers(entity_id integer,entity_kind text,namespace text,scope_id text,
                    value text,strength text,unique(entity_kind,namespace,scope_id,value,strength));
                create table {schema}.core_entity_observations(observation_sha256 bytea primary key,plugin_id text,
                    source_instance_id text,entity_kind text,entity_id integer,observed_at_utc timestamptz,
                    identifiers_json jsonb,evidence_refs text[],resolution text,candidate_ids integer[],reason text);
                create table {schema}.core_entity_associations(source_entity_id integer,target_entity_id integer,relation text);
            """)
            function = SQL.split("create function public.resolve_agent_workstation_v160", 1)[1].split("revoke all on function", 1)[0]
            function = "create function public.resolve_agent_workstation_v160" + function
            cur.execute(function.replace("public.", schema + ".").replace("search_path=pg_catalog,public", "search_path=pg_catalog," + schema))
            cur.execute(f"grant usage on schema {schema} to {role}; grant execute on function {schema}.resolve_agent_workstation_v160(uuid,uuid) to {role}")
            cur.execute(f"insert into {schema}.sli_agents(id,host_id,status,assigned_modules) values(%s,%s,'active',%s::jsonb)",
                        (agent, host, json.dumps([{"module_id": "sli.workstations", "enabled": True}])))
            cur.execute(f"insert into {schema}.sli_agent_receipts values(%s,%s,'sli.workstations',now())", (packet, agent))
            cur.execute(f"insert into {schema}.plugin_state values('sli.workstations',true,false)")

            def resolve():
                cur.execute(f"set local role {role}")
                cur.execute(f"select * from {schema}.resolve_agent_workstation_v160(%s,%s)", (agent, packet))
                result = cur.fetchone()
                cur.execute("reset role")
                return result

            assert resolve() is None
            cur.execute(f"update {schema}.plugin_state set enabled=true")
            first = resolve()
            assert first["entity_id"] > 0 and first["ad_computer_id"] is None
            assert resolve() == first
            cur.execute(f"select count(*) as n from {schema}.entities_v2")
            assert cur.fetchone()["n"] == 1
            cur.execute(f"select natural_key from {schema}.entities_v2")
            assert cur.fetchone()["natural_key"] == EntityIdentifier("sli.agent.key", "agent-registry", agent, "stable").identity_key("device")
            cur.execute(f"update {schema}.sli_agents set assigned_modules='[]'::jsonb")
            assert resolve() is None
            cur.execute(f"set local role {role}")
            with pytest.raises(psycopg.errors.InsufficientPrivilege), conn.transaction():
                cur.execute(f"select * from {schema}.core_entity_identifiers")
    finally:
        conn.rollback()
        conn.close()
