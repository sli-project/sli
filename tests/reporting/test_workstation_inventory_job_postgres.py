"""WR04 -> existing WR05 job -> overview, without pre-seeded inventory."""
from __future__ import annotations

import json
import os
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest

from server.sli.core import job_queue
from server.sli.plugins.workstations import inventory, overview, projection_jobs
from server.sli.plugins.workstations.reports import FIELDS
from server.sli.reporting.v2.definition import QueryContext
from tests.migrations.historical_postgres import historical_connection
from tests.migrations.test_core_job_profiles_postgres_integration import (
    profile_connection as profile_connection,  # noqa: PLC0414 - pytest fixture re-export
)

pytestmark = pytest.mark.postgres_integration
ROOT = Path(__file__).resolve().parents[2]



@pytest.fixture
def historical_inventory_connection(tmp_path, monkeypatch):
    with historical_connection(tmp_path, monkeypatch, (287, "workstation_inventory_job")) as conn:
        yield conn


def _job(conn, domain=11):
    from psycopg.types.json import Jsonb

    manifest = json.loads((ROOT / projection_jobs.MANIFEST).read_text("utf-8"))
    handler = manifest["handlers"][0]
    source = f"workstations:inventory:{domain}"
    spec = {
        "plugin_id": "sli.workstations", "plugin_version": "1.0.0",
        "handler_id": handler["handler_id"], "handler_version": handler["handler_version"],
        "job_type": "reconcile", "resource_profile": "light", "rights_profile": handler["rights_profile"],
        "input_contract": handler["input_contract"], "result_contract": handler["result_contract"],
        "source_instance_id": source, "partition_key": source,
        "manifest_sha256": job_queue.digest(manifest), "budget": handler["budget"],
        "access_scope": {"mode": "restricted", "clauses": [{
            "source_instance_ids": [source], "collection_scope_ids": [f"ad-domain:{domain}"],
            "device_ids": [], "entity_ids": []}],
            "decision_id": "core-workstation-inventory-v1", "policy_revision": "1"},
    }
    job_id, token = str(uuid4()), str(uuid4())
    _install(conn, job_queue.digest(manifest))
    conn.execute("""insert into sli_jobs.jobs
        (job_id,spec,idempotency_key,plugin_id,source_instance_id,partition_key,resource_profile,
         rights_profile,state,priority,max_attempts,available_at,deadline_at,lease_token,lease_generation,lease_until)
        values(%s,%s,%s,'sli.workstations',%s,%s,
               'light','workstations-projection','leased',1,3,clock_timestamp(),
               clock_timestamp()+interval '5 minutes',%s,1,clock_timestamp()+interval '5 minutes')""",
                 (job_id, Jsonb(spec), job_queue.digest(job_id), source, source, token))
    return {**spec, "job_id": job_id, "lease_token": token, "lease_generation": 1}


def _install(conn, manifest_sha):
    conn.execute("""insert into public.plugin_installations_v1
        (plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,desired_activation,
         observed_health,component_runtime,queue_state,revision,immutable_evidence_count)
        values('sli.workstations','fixture',%s,'1.0.0','registered','enabled_manual',
               'unknown','running','drained',1,1)
        on conflict(plugin_id) do update set package_version='1.0.0',package_lifecycle='registered',
            desired_activation='enabled_manual',component_runtime='running'""", (manifest_sha,))


def test_directory_and_agent_sources_reach_overview_through_fenced_job(profile_connection, monkeypatch):
    """Missing inventory publication leaves a successfully finished job with no stations."""
    import psycopg
    from psycopg.rows import dict_row

    conn = profile_connection
    type_id = conn.execute("insert into storage_v2_entity_type(value) values('ad_computer') "
                           "on conflict(value) do update set value=excluded.value returning id").fetchone()[0]
    first = conn.execute("select coalesce(max(id),0)+1000 from entities_v2").fetchone()[0]
    for entity, domain, name in ((first, 11, "synthetic-own-station"), (first + 1, 22, "synthetic-foreign-station")):
        conn.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256) "
                     "values(%s,%s,%s,%s,%s,%s)",
                     (entity, type_id, f"synthetic-t031-{entity}", name, domain, bytes(32)))
    agent = str(uuid4())
    conn.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name) "
                 "values(%s,%s,%s,%s::jsonb,'synthetic-agent-only')",
                 (agent, str(uuid4()), "a" * 64, '[{"module_id":"sli.workstations"}]'))
    expected = {f"ws:ad:{first}", f"ws:ad:{first + 1}", f"ws:agent:{agent}"}
    # Prove that trusted sources can build the union. Do not insert its result:
    # publication must be performed by the real job under its existing identity.
    with conn.cursor(row_factory=dict_row) as cur:
        source_rows = inventory.inventory_source(cur)
    assert expected <= {row["station_id"] for row in source_rows}
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0
    for domain in (11, 22, 0):
        job = _job(conn, domain)
        with conn.transaction():
            conn.execute("set local session authorization sli_job_executor_light")
            staged = projection_jobs.stage(conn, job)
        with conn.transaction():
            conn.execute("set local session authorization sli_job_publisher_light")
            assert job_queue.publish(conn, job, staged, projection_jobs.apply) == "committed"
            assert job_queue.publish(conn, job, staged, projection_jobs.apply) == "duplicate"

    dsn = os.environ["ADLOG_TEST_PG_DSN"]
    monkeypatch.setattr(overview, "connect", lambda: psycopg.connect(dsn, row_factory=dict_row,
                                                                  options="-c role=adlog_user"))
    access = {"capabilities": ["workstations.read"], "reports": [{
        "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
        "grants": [{"scope": {"kind": "all"}, "allowed_actions": ["view"], "field_categories": sorted(FIELDS)}]}]}
    definition = overview.make_report()
    body = definition.query(QueryContext(access=access, params={}, limit=50))
    assert expected <= {row["station_id"] for row in body["items"]}, {
        "input_stations": sorted(expected), "staged_work": staged,
        "inventory_stations": conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0],
        "overview_stations": [row["station_id"] for row in body["items"]],
    }
    own = definition.query(QueryContext(access=access, params={"domain": 11}, limit=50))
    assert [row["station_id"] for row in own["items"]] == [f"ws:ad:{first}"]
    assert body["coverage"]["completeness"] == "not_proven"


def test_existing_job_roles_have_no_inventory_input_or_publication_authority(profile_connection):
    from psycopg.errors import InsufficientPrivilege

    conn = profile_connection
    with conn.transaction():
        conn.execute("set local session authorization sli_job_executor_light")
        with pytest.raises(InsufficientPrivilege), conn.transaction(), conn.cursor() as cur:
            inventory.inventory_source(cur)
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        with pytest.raises(InsufficientPrivilege), conn.transaction():
            conn.execute("insert into sli_plugin_workstations.station_inventory(station_id,agent_key) "
                         "values('ws:synthetic-t031','synthetic-t031-agent')")


def _directory(conn):
    kind = conn.execute("insert into storage_v2_entity_type(value) values('ad_computer') "
                        "on conflict(value) do update set value=excluded.value returning id").fetchone()[0]
    first = conn.execute("select coalesce(max(id),0)+1000 from entities_v2").fetchone()[0]
    for number, domain in ((first, 11), (first + 1, 22)):
        conn.execute("insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256) "
                     "values(%s,%s,%s,%s,%s,%s)",
                     (number, kind, f"synthetic-t031-{number}", f"synthetic-station-{number}", domain, bytes(32)))
    return first, first + 1


def _stage(conn, job):
    with conn.transaction():
        conn.execute("set local session authorization sli_job_executor_light")
        return projection_jobs.stage(conn, job)


def _publish(conn, job, staged, apply=projection_jobs.apply):
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        return job_queue.publish(conn, job, staged, apply)


def test_foreign_domain_and_forged_scope_are_rejected_before_inventory_write(profile_connection):
    from psycopg.errors import RaiseException
    from psycopg.types.json import Jsonb

    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    own, foreign = _directory(conn)
    job = _job(conn, 11)
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        snapshot = inventory_jobs._read(conn, job)
        assert [row["ad_computer_id"] for row in snapshot["sources"]["directory"]] == [own]
        assert str(foreign) not in json.dumps(snapshot["sources"]["directory"])
        row = snapshot["page"]["rows"][0]
        row.update(station_id=f"ws:ad:{foreign}", ad_computer_id=foreign, domain_id=22)
        with pytest.raises(RaiseException, match="workstation_inventory_canonical_page_required"), conn.transaction():
            conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)",
                         (*job_queue.fence(job), snapshot["source_sha256"], Jsonb([row]), ""))
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0
    # A signed-looking source string cannot substitute the recorded scope.
    conn.execute("update sli_jobs.jobs set spec=jsonb_set(spec,'{access_scope,clauses,0,collection_scope_ids}',"
                 "'[\"ad-domain:22\"]'::jsonb) where job_id=%s", (job["job_id"],))
    with pytest.raises(RaiseException, match="workstation_inventory_access_denied"):
        _stage(conn, job)


@pytest.mark.parametrize("role", ["adlog_user", "sli_job_executor_heavy"])
def test_foreign_role_cannot_read_leased_domain_inputs(profile_connection, role):
    from psycopg import sql
    from psycopg.errors import InsufficientPrivilege

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    with conn.transaction():
        conn.execute(sql.SQL("set local session authorization {}").format(sql.Identifier(role)))
        with pytest.raises(InsufficientPrivilege), conn.transaction():
            conn.execute("select public.read_workstation_inventory_input_v1(%s,%s,%s)", job_queue.fence(job))
    assert not conn.execute("select rolcanlogin or rolsuper or rolbypassrls or rolcreaterole "
                            "from pg_roles where rolname='sli_workstation_inventory_owner'").fetchone()[0]
    assert not conn.execute("select has_column_privilege('sli_workstation_inventory_owner',"
                            "'public.sli_agents','key_fingerprint','SELECT')").fetchone()[0]


def test_publication_rollback_and_lost_lease_leave_no_inventory_effects(profile_connection):
    from psycopg.errors import RaiseException

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    staged = _stage(conn, job)

    def fail_after_publication(connection, value, result):
        projection_jobs.apply(connection, value, result)
        raise RuntimeError("synthetic rollback")

    with pytest.raises(RuntimeError, match="synthetic rollback"):
        _publish(conn, job, staged, fail_after_publication)
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0
    assert conn.execute("select count(*) from sli_plugin_workstations.inventory_checkpoints").fetchone()[0] == 0
    conn.execute("update sli_jobs.jobs set lease_generation=lease_generation+1 where job_id=%s", (job["job_id"],))
    with pytest.raises(RaiseException, match="workstation_inventory_access_denied"):
        _stage(conn, job)
    with pytest.raises(job_queue.LeaseLost):
        _publish(conn, job, staged)
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


def test_changed_source_cannot_publish_the_older_staged_inventory(profile_connection):
    conn = profile_connection
    own, _ = _directory(conn)
    job = _job(conn)
    staged = _stage(conn, job)
    conn.execute("update entities_v2 set display_name='synthetic-renamed' where id=%s", (own,))
    with pytest.raises(ValueError, match="workstation_inventory_input_changed"):
        _publish(conn, job, staged)
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


def test_empty_unknown_inventory_and_bounded_continuation_preserve_replay(profile_connection):
    conn = profile_connection
    empty = _job(conn, 0)
    staged = _stage(conn, empty)
    assert staged["inventory_ids"] == [] and staged["coverage_state"] == "not_proven"
    assert _publish(conn, empty, staged) == "committed"
    for number in range(101):
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name) "
                     "values(%s,%s,%s,%s::jsonb,%s)", (uuid4(), uuid4(), "a" * 64,
                     '[{"module_id":"sli.workstations"}]', f"synthetic-agent-{number}"))
    first = _job(conn, 0)
    page = _stage(conn, first)
    assert len(page["inventory_ids"]) == 80 and page["status"] == "partial"
    assert _publish(conn, first, page) == "committed"
    second = _job(conn, 0)
    page = _stage(conn, second)
    assert len(page["inventory_ids"]) == 21 and page["status"] == "success"
    assert _publish(conn, second, page) == "committed"
    replay = _job(conn, 0)
    assert _publish(conn, replay, _stage(conn, replay)) == "committed"
    rows = conn.execute("select domain_id,station_type,quality->>'status',revision "
                        "from sli_plugin_workstations.station_inventory").fetchall()
    assert rows == [(None, "unknown", "not_collected", 1)] * 101


def test_real_dispatcher_enqueues_domain_scopes_and_claimed_jobs_publish(profile_connection, monkeypatch):
    from server.sli.core import job_registry
    from server.sli.plugins.workstations import jobs

    conn = profile_connection
    first, second = _directory(conn)
    manifest = json.loads((ROOT / projection_jobs.MANIFEST).read_text("utf-8"))
    _install(conn, job_queue.digest(manifest))
    monkeypatch.setenv(projection_jobs.FLAG, "1")
    monkeypatch.delenv(jobs.FLAG, raising=False)
    registry = job_registry.pilot_registry()
    with conn.transaction():
        conn.execute("set local session authorization sli_job_dispatcher_light")
        with conn.cursor() as cur:
            jobs.schedule(cur, registry, "light")
            jobs.schedule(cur, registry, "light")
    queued = conn.execute("select source_instance_id,partition_key,spec->'access_scope' "
                          "from sli_jobs.jobs where state='queued' order by source_instance_id").fetchall()
    assert len(queued) == 4  # Three inventory domains plus the unchanged WR05 evaluator.
    for source, partition, scope in queued:
        if source.startswith("workstations:inventory:"):
            assert partition == source
            assert scope["clauses"][0]["collection_scope_ids"] == [f"ad-domain:{source.rsplit(':', 1)[1]}"]
    for _ in range(4):
        with conn.transaction():
            conn.execute("set local session authorization sli_job_dispatcher_light")
            with conn.cursor() as cur:
                job = job_queue.claim(cur, "light", "synthetic-t031", registry.identities("light"))
        assert job is not None
        assert _publish(conn, job, _stage(conn, job)) == "committed"
    assert conn.execute("select station_id from sli_plugin_workstations.station_inventory "
                        "order by station_id").fetchall() == [(f"ws:ad:{first}",), (f"ws:ad:{second}",)]


def test_migration_rollback_refuses_active_jobs_then_reapplies_without_data_loss(historical_inventory_connection):
    from psycopg.errors import InsufficientPrivilege, RaiseException

    conn = historical_inventory_connection
    _directory(conn)
    job = _job(conn)
    rollback = (ROOT / "config/postgres_migrations/287_workstation_inventory_job.rollback.sql").read_text("utf-8")
    forward = (ROOT / "config/postgres_migrations/287_workstation_inventory_job.sql").read_text("utf-8")
    with pytest.raises(RaiseException, match="rollback prerequisites failed"):
        try:
            conn.execute(rollback)
        finally:
            conn.execute("rollback")
    assert _publish(conn, job, _stage(conn, job)) == "committed"
    before = conn.execute("select station_id,revision from sli_plugin_workstations.station_inventory").fetchall()
    conn.execute(rollback)
    assert conn.execute("select to_regprocedure('public.read_workstation_inventory_input_v1(uuid,uuid,bigint)'),"
                        "to_regclass('sli_plugin_workstations.inventory_checkpoints')").fetchone() == (None, None)
    assert conn.execute("select station_id,revision from sli_plugin_workstations.station_inventory").fetchall() == before
    conn.execute(forward)
    replay = _job(conn)
    assert _publish(conn, replay, _stage(conn, replay)) == "committed"
    assert conn.execute("select station_id,revision from sli_plugin_workstations.station_inventory").fetchall() == before
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        with pytest.raises(InsufficientPrivilege), conn.transaction():
            conn.execute("select * from sli_plugin_workstations.inventory_checkpoints")


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


def test_explicit_linked_ownership_and_ambiguous_input_never_mix_domains(profile_connection):
    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    own, foreign = _directory(conn)
    own_agent, own_device = _device(conn, [own])
    foreign_agent, _ = _device(conn, [foreign])
    ambiguous, _ = _device(conn, [own, foreign])
    jobs = [_job(conn, domain) for domain in (11, 22, 0)]
    for job, expected in zip(jobs, ([own_agent], [foreign_agent], [ambiguous]), strict=True):
        with conn.transaction():
            conn.execute("set local session authorization sli_job_executor_light")
            snapshot = inventory_jobs._read(conn, job)
            assert [row["agent_key"] for row in snapshot["sources"]["agents"]] == expected
            if expected == [ambiguous]:
                assert snapshot["sources"]["directory"] == []
                assert snapshot["sources"]["devices"] == []
        assert _publish(conn, job, _stage(conn, job)) == "committed"
    rows = conn.execute("select agent_key,entity_id,ad_computer_id,domain_id,association_status,station_type,quality->>'status' "
                        "from sli_plugin_workstations.station_inventory").fetchall()
    assert (own_agent, own_device, own, 11, "unique", "unknown", "not_collected") in rows
    assert (ambiguous, None, None, None, "ambiguous", "unknown", "partial") in rows


@pytest.mark.parametrize("payload", [None, {}, [None], [{}]])
def test_malformed_publication_has_no_effect(profile_connection, payload):
    from psycopg.errors import RaiseException
    from psycopg.types.json import Jsonb

    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        snapshot = inventory_jobs._read(conn, job)
        with pytest.raises(RaiseException, match="workstation_inventory_canonical_page_required"), conn.transaction():
            conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)",
                         (*job_queue.fence(job), snapshot["source_sha256"], Jsonb(payload), ""))
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


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


def test_source_overflow_fails_without_silent_population_truncation(profile_connection):
    from psycopg.errors import RaiseException

    conn = profile_connection
    conn.execute("""insert into sli_agents(id,host_id,key_fingerprint,assigned_modules,instance_name)
        select gen_random_uuid(),gen_random_uuid(),repeat('a',64),'[{"module_id":"sli.workstations"}]'::jsonb,
            'synthetic-overflow-'||i::text from generate_series(1,10001) i""")
    job = _job(conn, 0)
    with pytest.raises(RaiseException, match="workstation_inventory_source_limit"):
        _stage(conn, job)
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


def test_two_persisted_station_ids_defer_without_rewriting_history_or_blocking_other_rows(profile_connection):
    conn = profile_connection
    own, _ = _directory(conn)
    agent, device = _device(conn, [])
    for domain in (0, 11):
        job = _job(conn, domain)
        assert _publish(conn, job, _stage(conn, job)) == "committed"
    before = conn.execute("select station_id,agent_key,ad_computer_id,revision "
                          "from sli_plugin_workstations.station_inventory order by station_id").fetchall()
    old_agent_id = next(row[0] for row in before if row[1] == agent)
    history_id = sha256(old_agent_id.encode()).hexdigest()
    conn.execute("insert into sli_plugin_workstations.station_summary(station_id,as_of_utc) values(%s,now())", (old_agent_id,))
    conn.execute("""insert into sli_plugin_workstations.station_changes
        (id,station_id,change_kind,detected_at,reason_code,evidence_refs)
        values(%s,%s,'synthetic',now(),'synthetic_preserve','[{"kind":"synthetic","id":"unchanged"}]')""",
                 (history_id, old_agent_id))
    history = conn.execute("select to_jsonb(c) from sli_plugin_workstations.station_changes c where id=%s", (history_id,)).fetchone()[0]
    actor = conn.execute("insert into auth_users(username,password_hash,role) "
                         "values(%s,'synthetic','viewer') returning id", (uuid4().hex,)).fetchone()[0]
    conn.execute("insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs) "
                 "values(%s,%s,'directory_computer',%s,array['synthetic'])", (device, own, actor))
    control = own + 100
    conn.execute("""insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select %s,entity_type_id,%s,'synthetic-new-control',11,%s from entities_v2 where id=%s""",
                 (control, f"synthetic-control-{control}", bytes(32), own))
    joined = _job(conn, 11)
    staged = _stage(conn, joined)
    assert staged['status'] == 'partial'
    assert staged['inventory_deferred'] == [{'station_id': f'ws:ad:{own}', 'reason': 'identity_owner_conflict'}]
    assert _publish(conn, joined, staged) == 'committed'
    assert conn.execute("select station_id,agent_key,ad_computer_id,revision "
                        "from sli_plugin_workstations.station_inventory where station_id=any(%s) order by station_id",
                        ([row[0] for row in before],)).fetchall() == before
    assert any(row[1] == agent for row in before)
    assert conn.execute("select revision from sli_plugin_workstations.station_inventory where station_id=%s",
                        (f'ws:ad:{control}',)).fetchone() == (1,)
    assert conn.execute("select state,attempts from sli_plugin_workstations.inventory_deferred").fetchone() == ('pending', 1)
    conn.execute("update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'")
    retry = _job(conn, 11)
    assert _publish(conn, retry, _stage(conn, retry)) == 'committed'
    assert conn.execute("select state,attempts from sli_plugin_workstations.inventory_deferred").fetchone() == ('pending', 2)
    assert conn.execute("select result_payload->>'status' from sli_jobs.jobs where job_id=%s", (retry['job_id'],)).fetchone() == ('partial',)
    assert conn.execute("select to_jsonb(c) from sli_plugin_workstations.station_changes c where id=%s", (history_id,)).fetchone()[0] == history
    assert conn.execute("select count(*) from sli_plugin_workstations.station_summary where station_id=%s", (old_agent_id,)).fetchone()[0] == 1
    # A changed current source binding can remove the conflict without merging
    # either persisted ID. The old core association/evidence remains immutable.
    conn.execute('update sli_agents set host_id=%s where id=%s', (uuid4(), agent))
    conn.execute("update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'")
    resolved = _job(conn, 11)
    resolved_result = _stage(conn, resolved)
    assert resolved_result['status'] == 'success' and resolved_result['inventory_deferred'] == []
    assert _publish(conn, resolved, resolved_result) == 'committed'
    assert conn.execute('select state from sli_plugin_workstations.inventory_deferred').fetchone()[0] == 'resolved'
    assert conn.execute("select to_jsonb(c) from sli_plugin_workstations.station_changes c where id=%s", (history_id,)).fetchone()[0] == history


def test_direct_sql_publication_cannot_commit_without_the_exact_core_receipt(profile_connection):
    from psycopg.errors import RaiseException
    from psycopg.types.json import Jsonb

    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    with pytest.raises(RaiseException, match="workstation_inventory_core_receipt_required"), conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        snapshot = inventory_jobs._read(conn, job)
        conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)",
                     (*job_queue.fence(job), snapshot["source_sha256"],
                      Jsonb(snapshot["page"]["rows"]), snapshot["page"]["next_cursor"]))
    for table in ("station_inventory", "inventory_publications", "inventory_checkpoints"):
        assert conn.execute(f"select count(*) from sli_plugin_workstations.{table}").fetchone()[0] == 0
    assert conn.execute("select state from sli_jobs.jobs where job_id=%s", (job["job_id"],)).fetchone()[0] == "leased"


def test_one_lease_cannot_publish_two_pages_even_before_receipt_commit(profile_connection):
    from psycopg.errors import RaiseException
    from psycopg.types.json import Jsonb

    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        with pytest.raises(RaiseException, match="workstation_inventory_page_already_published"), conn.transaction():
            snapshot = inventory_jobs._read(conn, job)
            args = (*job_queue.fence(job), snapshot["source_sha256"],
                    Jsonb(snapshot["page"]["rows"]), snapshot["page"]["next_cursor"])
            conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)", args)
            conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)", args)
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


@pytest.mark.parametrize("tamper", ["operating_system", "ou_path", "ip_addresses", "station_type", "quality", "subset", "cursor"])
def test_direct_sql_cannot_fabricate_canonical_facts_or_choose_page(profile_connection, tamper):
    from copy import deepcopy

    from psycopg.errors import RaiseException
    from psycopg.types.json import Jsonb

    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    with conn.transaction():
        conn.execute("set local session authorization sli_job_publisher_light")
        snapshot = inventory_jobs._read(conn, job)
        rows = deepcopy(snapshot["page"]["rows"])
        cursor = snapshot["page"]["next_cursor"]
        if tamper in {"operating_system", "ou_path"}:
            rows[0]["metadata"][tamper] = "fabricated"
        elif tamper == "ip_addresses":
            rows[0]["metadata"][tamper] = ["192.0.2.123"]
        elif tamper == "station_type":
            rows[0][tamper] = "server"
        elif tamper == "quality":
            rows[0][tamper] = {"status": "complete", "reasons": []}
        elif tamper == "subset":
            rows = []
        else:
            cursor = rows[-1]["station_id"]
        with pytest.raises(RaiseException, match="workstation_inventory_canonical_page_required"), conn.transaction():
            conn.execute("select public.publish_workstation_inventory_v1(%s,%s,%s,%s,%s,%s)",
                         (*job_queue.fence(job), snapshot["source_sha256"], Jsonb(rows), cursor))
    assert conn.execute("select count(*) from sli_plugin_workstations.station_inventory").fetchone()[0] == 0


def test_current_agent_scope_cannot_read_a_different_saved_directory_identity(profile_connection, monkeypatch):
    import psycopg
    from psycopg.rows import dict_row

    conn = profile_connection
    old, current = _directory(conn)
    agent, device = _device(conn, [current])
    # Historical negative fixture, not a shortcut in the positive producer test.
    station = f"ws:ad:{old}"
    conn.execute("""insert into sli_plugin_workstations.station_inventory
        (station_id,entity_id,ad_computer_id,agent_key,domain_id,metadata)
        values(%s,%s,%s,%s,11,'{"display_name":"private-A","ou_path":"private-OU-A"}')""",
                 (station, device, old, agent))
    conn.execute("insert into sli_plugin_workstations.station_inventory(station_id,ad_computer_id,domain_id) values(%s,%s,22)",
                 (f'ws:ad:{current}', current))
    finding = sha256(station.encode()).hexdigest()
    conn.execute("""insert into sli_plugin_workstations.check_findings
        (id,station_id,check_id,rule_version,episode_id,condition_sha256,status,severity,
         first_detected_at,last_observed_at,materially_changed_at,reason_code)
        values(%s,%s,'C05',1,%s,%s,'active','medium',now(),now(),now(),'synthetic_private_A')""",
                 (finding, station, "e" * 64, "c" * 64))
    dsn = os.environ["ADLOG_TEST_PG_DSN"]
    monkeypatch.setattr(overview, "connect", lambda: psycopg.connect(dsn, row_factory=dict_row,
                                                                  options="-c role=adlog_user"))
    definition = overview.make_report()
    for domain in (11, 22):
        access = {"capabilities": ["workstations.read"], "reports": [{
            "report_key": "workstations.overview", "allowed": True, "allowed_actions": ["view"],
            "grants": [{"scope": {"kind": "domain", "ids": [domain]}, "allowed_actions": ["view"],
                        "field_categories": sorted(FIELDS)}]}]}
        ctx = QueryContext(access=access, params={}, limit=50)
        body = definition.query(ctx)
        assert [row['station_id'] for row in body['items']] == ([f'ws:ad:{current}'] if domain == 22 else [])
        assert body["filter_options"]["ou"] == []
        assert body['metrics'][0]['value'] == (1 if domain == 22 else 0)
        assert body['metrics'][1]['value'] == 0
        with pytest.raises(PermissionError, match="workstation_access_denied"):
            definition.detail.query(ctx, station)
        with pytest.raises(PermissionError, match="workstation_access_denied"):
            definition.detail.query(QueryContext(access=access, params={"finding_id": finding, "evidence_index": 1}, limit=50), station)


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


@pytest.mark.parametrize('attributes,observed', [
    ({}, None),
    ({'operating_system': ' Windows Server 2022 ', 'operating_system_version': 'v1',
      'organizational_unit': 'OU=Blue,DC=synthetic,DC=invalid',
      'ip_addresses': ['192.0.2.10', 'bad', '2001:0db8::1', '192.0.2.10']}, '2026-10-27T00:00:00Z'),
    ({'operating_system': 'Windows', 'distinguished_name': r'CN=Desktop\,One, OU=Blue, DC=synthetic,DC=invalid',
      'ip_addresses': ['192.0.2.10']}, '2026-10-27T00:00:00Z'),
    ({'operating_system': 'Windows', 'organizational_unit': 'OU=Blue',
      'ip_addresses': ['fe80::1%Eth0', '::ffff:192.0.2.128', '::', '::192.0.2.1', '192.00.2.1', '1']},
     '2026-10-27T00:00:00Z'),
])
def test_database_canonical_values_match_trusted_builder_controls(profile_connection, attributes, observed):
    from psycopg.types.json import Jsonb

    source = {'directory': [{'ad_computer_id': 123, 'domain_id': 11, 'display_name': ' Synthetic ',
                            'attributes': attributes, 'metadata_observed_at': observed}],
              'agents': [], 'devices': [], 'associations': [], 'existing': [], 'ambiguous_agents': []}
    # Private codec is exercised as the disposable schema administrator; no
    # extra EXECUTE or source/table grants are added to worker fixtures.
    page = profile_connection.execute('select sli_plugin_workstations.inventory_page_v1(%s)',
        (Jsonb({'sources': source, 'cursor': '', 'deferred': []}),)).fetchone()[0]
    expected = inventory.build_inventory(*(source[key] for key in ('directory', 'agents', 'devices', 'associations', 'existing')))
    assert page['rows'] == expected
    assert page['deferred'] == [] and page['more'] is False


@pytest.mark.parametrize('immediate', [False, True])
def test_final_core_fence_and_atomic_receipt_do_not_promise_outer_commit_wall_clock(profile_connection, immediate):
    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    staged = _stage(conn, job)
    expires = conn.execute("update sli_jobs.jobs set lease_until=clock_timestamp()+interval '15 seconds' "
                           "where job_id=%s returning lease_until", (job['job_id'],)).fetchone()[0]
    with conn.transaction():
        conn.execute('set local session authorization sli_job_publisher_light')
        assert job_queue.publish(conn, job, staged, projection_jobs.apply) == 'committed'
        if immediate:
            conn.execute('set constraints all immediate')
        conn.execute('select pg_sleep_until(%s)', (expires,))
    assert conn.execute('select count(*) from sli_plugin_workstations.station_inventory').fetchone()[0] == 1
    assert conn.execute('select state from sli_jobs.jobs where job_id=%s', (job['job_id'],)).fetchone()[0] == 'completed'
    assert conn.execute('select lease_until<clock_timestamp() from sli_plugin_workstations.inventory_publications where job_id=%s',
                        (job['job_id'],)).fetchone()[0] is True


def test_database_retry_quota_is_twenty_and_unattempted_pending_stays_partial(profile_connection):
    from psycopg.types.json import Jsonb

    directory = [{'ad_computer_id': i, 'domain_id': 11, 'display_name': str(i)} for i in range(1000, 1081)]
    pending = [{'station_id': f'ws:ad:{i}', 'reason': 'identity_owner_conflict', 'due': True} for i in range(1000, 1025)]
    snapshot = {'sources': {'directory': directory, 'agents': [], 'devices': [], 'associations': [], 'existing': [],
                           'ambiguous_agents': []}, 'cursor': '', 'deferred': pending}
    page = profile_connection.execute('select sli_plugin_workstations.inventory_page_v1(%s)', (Jsonb(snapshot),)).fetchone()[0]
    assert len(page['attempted_ids']) == 76 and len(page['rows']) == 76
    assert len(set(page['attempted_ids']) & {q['station_id'] for q in pending}) == 20
    assert page['more'] is True and page['next_cursor'] == ''


def test_conflict_at_normal_page_boundary_does_not_stall_next_page(profile_connection):
    conn = profile_connection
    own, _ = _directory(conn)
    ids = [own, *range(own + 100, own + 180)]
    for number in ids[1:]:
        conn.execute("""insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select %s,entity_type_id,%s,'synthetic-boundary',11,%s from entities_v2 where id=%s""",
                     (number, f'synthetic-boundary-{number}', bytes(32), own))
    for _ in range(2):
        job = _job(conn, 11)
        assert _publish(conn, job, _stage(conn, job)) == 'committed'
    agent, device = _device(conn, [])
    job = _job(conn, 0)
    assert _publish(conn, job, _stage(conn, job)) == 'committed'
    target = sorted(ids, key=lambda value: f'ws:ad:{value}')[79]
    actor = conn.execute("insert into auth_users(username,password_hash,role) values(%s,'synthetic','viewer') returning id",
                         (uuid4().hex,)).fetchone()[0]
    conn.execute("insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs) "
                 "values(%s,%s,'directory_computer',%s,array['synthetic'])", (device, target, actor))
    control = int(str(max(ids, key=str)) + '9')
    conn.execute("""insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
        select %s,entity_type_id,%s,'synthetic-next-page',11,%s from entities_v2 where id=%s""",
                 (control, f'synthetic-control-{control}', bytes(32), own))
    first = _job(conn, 11)
    staged = _stage(conn, first)
    assert len(staged['inventory_ids']) == 80
    assert staged['inventory_deferred'] == [{'station_id': f'ws:ad:{target}', 'reason': 'identity_owner_conflict'}]
    assert _publish(conn, first, staged) == 'committed'
    assert conn.execute('select last_key from sli_plugin_workstations.inventory_checkpoints where domain_id=11').fetchone()[0] == f'ws:ad:{target}'
    second = _job(conn, 11)
    assert _publish(conn, second, _stage(conn, second)) == 'committed'
    assert conn.execute('select count(*) from sli_plugin_workstations.station_inventory where ad_computer_id=%s', (control,)).fetchone()[0] == 1
    assert conn.execute('select station_id from sli_plugin_workstations.station_inventory where agent_key=%s', (agent,)).fetchone()[0] == f'ws:agent:{agent}'
    assert conn.execute('select state from sli_plugin_workstations.inventory_deferred').fetchone()[0] == 'pending'


def _pending_conflict(conn):
    own, _ = _directory(conn)
    agent, device = _device(conn, [])
    for domain in (0, 11):
        job = _job(conn, domain)
        assert _publish(conn, job, _stage(conn, job)) == 'committed'
    actor = conn.execute("insert into auth_users(username,password_hash,role) values(%s,'synthetic','viewer') returning id",
                         (uuid4().hex,)).fetchone()[0]
    conn.execute("insert into core_entity_associations(source_entity_id,target_entity_id,relation,actor_id,evidence_refs) "
                 "values(%s,%s,'directory_computer',%s,array['synthetic'])", (device, own, actor))
    deferred = _job(conn, 11)
    result = _stage(conn, deferred)
    assert result['status'] == 'partial'
    assert _publish(conn, deferred, result) == 'committed'
    return own, agent, deferred


def test_disappeared_scoped_source_stays_deferred_without_foreign_metadata(profile_connection):
    from server.sli.plugins.workstations import inventory_jobs

    conn = profile_connection
    own, _, _ = _pending_conflict(conn)
    conn.execute('update entities_v2 set domain_id=22 where id=%s', (own,))
    conn.execute("update sli_plugin_workstations.inventory_deferred set next_retry_at='epoch'")
    with conn.transaction():
        conn.execute('set local session authorization sli_job_dispatcher_light')
        sources = [row[0] for row in conn.execute('select public.read_workstation_inventory_job_sources_v1()').fetchall()]
    assert any(row['source_instance_id'] == 'workstations:inventory:11' for row in sources)
    retry = _job(conn, 11)
    with conn.transaction():
        conn.execute('set local session authorization sli_job_executor_light')
        snapshot = inventory_jobs._read(conn, retry)
        assert snapshot['sources']['directory'] == [] and snapshot['sources']['agents'] == []
    result = _stage(conn, retry)
    assert result['status'] == 'partial'
    assert result['inventory_deferred'] == [{'station_id': f'ws:ad:{own}', 'reason': 'source_identity_unavailable'}]
    assert _publish(conn, retry, result) == 'committed'
    assert conn.execute('select state,reason from sli_plugin_workstations.inventory_deferred').fetchone() == ('pending', 'source_identity_unavailable')
    assert conn.execute('select domain_id from sli_plugin_workstations.station_inventory where ad_computer_id=%s', (own,)).fetchone()[0] == 11


def test_pending_queue_is_rebuilt_after_rollback_while_ids_and_core_receipts_survive(historical_inventory_connection):
    conn = historical_inventory_connection
    own, _, previous_job = _pending_conflict(conn)
    before = conn.execute('select station_id,revision from sli_plugin_workstations.station_inventory order by station_id').fetchall()
    receipt = conn.execute('select result_payload from sli_jobs.jobs where job_id=%s', (previous_job['job_id'],)).fetchone()[0]
    backward = (ROOT/'config/postgres_migrations/287_workstation_inventory_job.rollback.sql').read_text('utf-8')
    forward = (ROOT/'config/postgres_migrations/287_workstation_inventory_job.sql').read_text('utf-8')
    conn.execute(backward)
    assert conn.execute("select to_regclass('sli_plugin_workstations.inventory_deferred')").fetchone()[0] is None
    assert conn.execute('select station_id,revision from sli_plugin_workstations.station_inventory order by station_id').fetchall() == before
    assert conn.execute('select result_payload from sli_jobs.jobs where job_id=%s', (previous_job['job_id'],)).fetchone()[0] == receipt
    conn.execute(forward)
    assert conn.execute('select count(*) from sli_plugin_workstations.inventory_deferred').fetchone()[0] == 0
    rebuilt = _job(conn, 11)
    result = _stage(conn, rebuilt)
    assert result['inventory_deferred'] == [{'station_id': f'ws:ad:{own}', 'reason': 'identity_owner_conflict'}]
    assert _publish(conn, rebuilt, result) == 'committed'
    assert conn.execute('select state,attempts from sli_plugin_workstations.inventory_deferred').fetchone() == ('pending', 1)
    assert conn.execute('select station_id,revision from sli_plugin_workstations.station_inventory order by station_id').fetchall() == before


@pytest.mark.parametrize('expires', ['lease', 'deadline'])
def test_final_core_fence_rejects_expiry_after_effects_before_finish(profile_connection, expires):
    conn = profile_connection
    _directory(conn)
    job = _job(conn)
    staged = _stage(conn, job)
    field = 'lease_until' if expires == 'lease' else 'deadline_at'
    conn.execute("update sli_jobs.jobs set available_at=clock_timestamp()-interval '1 minute' where job_id=%s",
                 (job['job_id'],))
    expired_after_effects = False

    def expire_after_effects(connection, value, result):
        nonlocal expired_after_effects
        projection_jobs.apply(connection, value, result)
        connection.execute('set local session authorization default')
        expired = connection.execute(f"update sli_jobs.jobs set {field}=clock_timestamp()-interval '1 second' "
                                     'where job_id=%s', (value['job_id'],))
        assert expired.rowcount == 1
        connection.execute('set local session authorization sli_job_publisher_light')
        expired_after_effects = True

    with pytest.raises(job_queue.LeaseLost):
        _publish(conn, job, staged, expire_after_effects)
    assert expired_after_effects
    assert conn.execute('select count(*) from sli_plugin_workstations.station_inventory').fetchone()[0] == 0
    assert conn.execute('select count(*) from sli_plugin_workstations.inventory_publications').fetchone()[0] == 0
    assert conn.execute('select state,result_payload from sli_jobs.jobs where job_id=%s', (job['job_id'],)).fetchone() == ('leased', None)
