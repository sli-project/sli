"""WR04 -> existing WR05 job -> overview, without pre-seeded inventory."""
from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.historical_postgres import historical_connection

pytestmark = pytest.mark.postgres_integration
ROOT = Path(__file__).resolve().parents[2]



@pytest.fixture
def historical_inventory_connection(tmp_path, monkeypatch):
    with historical_connection(tmp_path, monkeypatch, (287, "workstation_inventory_job")) as conn:
        yield conn


def _install(conn, manifest_sha):
    conn.execute("""insert into public.plugin_installations_v1
        (plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,desired_activation,
         observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
        values('sli.workstations','fixture',%s,'1.0.0','registered','enabled_manual',
               'unknown','running','drained',1,1)
        on conflict(plugin_id) do update set package_version='1.0.0',package_lifecycle='registered',
            desired_activation='enabled_manual',component_runtime='running'""", (manifest_sha,))


def _directory(conn):
    kind = conn.execute("insert into storage_v2_entity_type(value) values('ad_computer') "
                        "on conflict(value) do update set value=excluded.value returning id").fetchone()[0]
    first = conn.execute("select coalesce(max(id),0)+1000 from entities_v2").fetchone()[0]
    for number, domain in ((first, 11), (first + 1, 22)):
        conn.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256) "
                     "values(%s,%s,%s,%s,%s,%s)",
                     (number, kind, f"synthetic-t031-{number}", f"synthetic-station-{number}", domain, bytes(32)))
    return first, first + 1


def _device(conn, targets):
    agent, host = str(uuid4()), str(uuid4())
    conn.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name) "
                 "values(%s,%s,%s,%s::jsonb,'synthetic-linked-agent')", (agent, host, "a" * 64,
                 '[{"module_id":"sli.workstations"}]'))
    natural = "core:" + sha256(f'["device","sli.agent.key","agent-registry","{agent}"]'.encode()).hexdigest()
    kind = conn.execute("insert into storage_v2_entity_type(value) values('device') "
                        "on conflict(value) do update set value=excluded.value returning id").fetchone()[0]
    entity = conn.execute("select max(id)+1 from entities_v2").fetchone()[0]
    conn.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,source_core_sha256) "
                 "values(%s,%s,%s,'synthetic-device',%s)", (entity, kind, natural, sha256(agent.encode()).digest()))
    conn.execute("""insert into core_entity_observations(observation_sha256,plugin_id,source_instance_id,
        entity_kind,entity_id,observed_at_utc,identifiers_json,evidence_refs,resolution)
        values(%s,'sli.workstations',%s,'device',%s,clock_timestamp(),'[{}]',array['synthetic'],'resolved')""",
                 (sha256(host.encode()).digest(), host, entity))
    actor = conn.execute("insert into auth_users(username,password_hash,role) "
                         "values(%s,'synthetic','viewer') returning id", (uuid4().hex,)).fetchone()[0]
    for target in targets:
        conn.execute("insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs) "
                     "values(%s,%s,'directory_computer',%s,array['synthetic'])", (entity, target, actor))
    return agent, entity


@pytest.fixture
def historical_producer_connection(tmp_path, monkeypatch):
    with historical_connection(tmp_path, monkeypatch, (325, "t109_workstation_path")) as conn:
        yield conn


@pytest.mark.parametrize("state", ["exact", "foreign", "foreign_filter", "foreign_health", "foreign_runtime", "future"])
def test_producer_fixture_restores_inventory_or_refuses_before_partial_reset(request, state):
    from psycopg.rows import dict_row

    from tests.migrations import test_report_producer_migration285 as producer

    # The exact round trip covers real successors without crossing 326's
    # final-catalog rollback guard. Unknown markers are still refused on the current schema.
    fixture = "historical_producer_connection" if state == "exact" else "profile_connection"
    conn = request.getfixturevalue(fixture)
    conn.row_factory = dict_row
    before = conn.execute("select * from schema_migrations where version<=284 order by version").fetchall()
    successors = conn.execute("select version,name from schema_migrations where version>285 order by version").fetchall()
    if state == "exact":
        producer.reapply(conn)
        assert conn.execute("select version,name from schema_migrations where version>285 order by version").fetchall() == successors
        assert conn.execute("select name from schema_migrations where version=287").fetchone() == {
            "name": "workstation_inventory_job"}
        assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)') as f").fetchone()["f"]
        definition = conn.execute("select pg_get_functiondef('sli_plugin_workstations.inventory_inputs_v1(bigint)'::regprocedure) as ddl").fetchone()["ddl"]
        assert 'source_agent_id' in definition
    else:
        if state == "foreign":
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=287")
        elif state == "foreign_filter":
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=288")
        elif state == "foreign_health":
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=297")
        elif state == "foreign_runtime":
            conn.execute("update schema_migrations set name='synthetic_foreign' where version=296")
        else:
            conn.execute("insert into schema_migrations(version,name) values(999999,'synthetic_future')")
        ledger = conn.execute("select * from schema_migrations order by version").fetchall()
        with pytest.raises(ValueError, match="producer_fixture_successor_invalid"):
            producer.predecessor(conn)
        conn.execute("rollback")
        assert conn.execute("select * from schema_migrations order by version").fetchall() == ledger
    assert conn.execute("select * from schema_migrations where version<=284 order by version").fetchall() == before
    assert conn.execute("select name from schema_migrations where version=285").fetchone() == {"name": "report_producer"}
    assert conn.execute("select to_regclass('public.report_producer_claims') as t").fetchone()["t"]
    assert conn.execute("select to_regclass('public.sli_agent_stream_import_health') as t").fetchone()["t"]
    assert conn.execute("select to_regprocedure('public.replace_agent_runtime_v296(uuid,uuid,text,text)') as f").fetchone()["f"]


def test_reused_owner_with_unexpected_login_membership_is_denied_without_partial_grants(historical_inventory_connection):
    from psycopg import sql
    from psycopg.errors import RaiseException

    conn = historical_inventory_connection
    backward = (ROOT / "config/postgres_migrations/287_workstation_inventory_job.rollback.sql").read_text("utf-8")
    forward = (ROOT / "config/postgres_migrations/287_workstation_inventory_job.sql").read_text("utf-8")
    # A real second database keeps the shared owner alive when this one rolls back.
    conn.execute(sql.SQL("create database sli_test_inventory_peer template {}").format(sql.Identifier(conn.info.dbname)))
    owner_oid = conn.execute("select oid from pg_roles where rolname='sli_workstation_inventory_owner'").fetchone()
    assert owner_oid
    conn.execute(backward)
    assert conn.execute("select oid from pg_roles where rolname='sli_workstation_inventory_owner'").fetchone() == owner_oid
    guest = "sli_test_inventory_guest_" + uuid4().hex
    conn.execute(sql.SQL("create role {} login noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication").format(sql.Identifier(guest)))
    try:
        conn.execute(sql.SQL("grant sli_workstation_inventory_owner to {}").format(sql.Identifier(guest)))
        with pytest.raises(RaiseException, match="workstation_inventory_owner_invalid"):
            try:
                conn.execute(forward)
            finally:
                conn.execute("rollback")
        assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)')").fetchone()[0] is None
        assert not conn.execute("select has_column_privilege(%s,'public.sli_agents','assigned_modules','SELECT')", (guest,)).fetchone()[0]
    finally:
        conn.execute(sql.SQL("revoke sli_workstation_inventory_owner from {}").format(sql.Identifier(guest)))
        conn.execute(sql.SQL("drop role {}").format(sql.Identifier(guest)))
