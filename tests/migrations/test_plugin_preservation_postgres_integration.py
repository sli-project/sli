"""VP04/VP08/VP09 against the migrated, per-test disposable PostgreSQL clone.

The agent VPN adapter and package detach executor are not shipped. Their
fail-closed refusals are tested, not represented as successful cutovers.
"""
from dataclasses import replace
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from psycopg import connect, sql
from psycopg.errors import CheckViolation, RaiseException, UniqueViolation
from psycopg.rows import dict_row

from server.sli.core import job_executor, job_queue
from server.sli.core.job_registry import pilot_registry, schedule_jobs
from server.sli.sources import plugin_state
from server.sli.sources.plugin_lifecycle import (
    PluginLifecycleError,
    execute_plugin_lifecycle,
    initial_remote_access_state,
    plan_plugin_lifecycle,
)
from server.sli.sources.plugin_runtime_admission import ACQUISITION, CONSUMER
from server.sli.sources.plugin_runtime_admission_executor import (
    acquire_component_lease,
    release_component_lease,
)
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration
PLUGIN = "sli.remote-access"
SOURCE = "fixture-vpn-source"
SUBSCRIPTION = "fixture-vpn-subscription"
PRESERVED = (
    "acquisition_source_instances", "acquisition_stream_cursors",
    "acquisition_consumer_subscriptions", "core_evidence_manifests",
    "radius_accounting_session_observations", "acquisition_delivery_outbox",
    "radius_session_projection_receipts", "radius_vpn_session_projection",
    "access_capability_assignments", "access_report_assignments",
    "access_subject_packages", "access_audit_v4",
    "sli_agent_module_bindings", "sli_agent_receipts", "sli_agent_audit",
)


def snapshot(conn, table):
    return conn.execute(sql.SQL("select to_jsonb(t) from {} t order by to_jsonb(t)::text").format(
        sql.Identifier(*table.split(".")))).fetchall()


@pytest.fixture
def database(monkeypatch):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN", "").strip()
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for disposable PostgreSQL tests")
    with connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        # Install defaults from 073; reset only the registry fixture, never
        # history, audit, source state, receipts or grants in the cloned DB.
        conn.execute("""insert into plugin_installations_v1(
            plugin_id,manifest_id,manifest_sha256,package_version,package_lifecycle,
            desired_activation,observed_health,component_runtime,queue_state,
            revision,immutable_evidence_count)
            values(%s,'sli.remote-access.package.v1',%s,'0.1.0','validated',
                'disabled','unknown','stopped','drained',1,1)
            on conflict(plugin_id) do update set package_lifecycle='validated',
                desired_activation='disabled',component_runtime='stopped',
                queue_state='drained',revision=1""",
            (PLUGIN, "78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf"))
        for component in (ACQUISITION, CONSUMER):
            conn.execute("""insert into plugin_component_admission_v1(plugin_id,component_id,admission_mode)
                values(%s,%s,'closed') on conflict(plugin_id,component_id)
                do update set admission_mode='closed'""", (PLUGIN, component))
        conn.execute("insert into plugin_state_v1(plugin_id) values(%s) on conflict do nothing", (PLUGIN,))
        monkeypatch.setattr(plugin_state, "connect", lambda: connect(dsn, row_factory=dict_row))
        monkeypatch.setattr(plugin_state, "remote_access_configured", lambda: True)
        yield conn


def install(conn):
    digest = "a" * 64
    return conn.execute("""select * from execute_bundled_plugin_install_v1(
        %s,%s,1,%s,%s,'local_operator','fixture-owner')""",
        (uuid4(), PLUGIN, digest, "PLUGIN-INSTALL-SLI-REMOTE-ACCESS-R1-" + digest[:12].upper())).fetchone()


def transition(conn, action):
    revision = conn.execute("select revision from plugin_installations_v1 where plugin_id=%s", (PLUGIN,)).fetchone()[0]
    digest = "b" * 64
    return conn.execute("""select * from execute_plugin_runtime_transition_v1(
        %s,%s,%s,%s,%s,'local_operator','fixture-owner')""",
        (uuid4(), action, revision, digest,
         f"PLUGIN-{action.upper()}-SLI-REMOTE-ACCESS-R{revision}-{digest[:12].upper()}")).fetchone()


def seed_source(conn):
    epoch = uuid4()
    conn.execute("""insert into acquisition_source_instances(source_instance_id,organization_scope,
        source_kind,endpoint_identity,adapter_binding,display_name,configuration_sha256)
        values(%s,'example.test','windows.nps.radius','fixture-endpoint','fixture-adapter','Fixture',%s)""",
        (SOURCE, "c" * 64))
    conn.execute("""insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,
        cursor_epoch,file_generation,byte_offset,last_record_sha256,revision)
        values(%s,'fixture-stream','fixture-transport',%s,'fixture-generation',4096,%s,7)""",
        (SOURCE, epoch, "d" * 64))
    conn.execute("""insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,
        stream_id,transport_binding,consumer_id,consumer_component_id,consumer_component_version,
        routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,
        selector_json,selector_sha256,authority_mode,partition_key)
        values(%s,%s,'fixture-stream','fixture-transport','sli.windows.vpn-radius',
        'radius-session-observation','1.0.0','fixture-route','1.0.0','no_replay',
        'fixture-profile','{}',%s,'authoritative','fixture-partition')""", (SUBSCRIPTION, SOURCE, "e" * 64))
    return epoch


def seed_delivery(conn, epoch, ordinal, *, delivered=False):
    evidence, observation = uuid4(), uuid4()
    conn.execute("""insert into core_evidence_manifests(evidence_uid,source_instance_id,
        stream_id,transport_binding,cursor_epoch,file_generation,cursor_start_byte_offset,
        batch_record_ordinal,canonical_record_sha256,object_reference,object_sha256,
        object_size_bytes,verified_at_utc) values(%s,%s,'fixture-stream','fixture-transport',
        %s,'fixture-generation',0,%s,%s,%s,%s,1,now())""",
        (evidence, SOURCE, epoch, ordinal, "a" * 64, f"evidence:fixture-{ordinal}", "b" * 64))
    conn.execute("""insert into radius_accounting_session_observations(observation_id,evidence_uid,
        lifecycle_event,identity_state,timestamp_state,session_confirmed_by_accounting,
        producer_contract_id,resource_groups,row_sensitivity,field_categories,
        evidence_access_requirement,label_policy_version,provenance_json)
        values(%s,%s,'start','unresolved','unresolved',true,'fixture-producer',
        '{vpn.sessions}','restricted','{fixture}','vpn.session.evidence.read','1','{}')""", (observation, evidence))
    delivery = conn.execute("""insert into acquisition_delivery_outbox(subscription_id,evidence_uid,
        observation_id,idempotency_key,delivery_state,delivered_at)
        values(%s,%s,%s,%s,%s,case when %s then now() end) returning delivery_id""",
        (SUBSCRIPTION, evidence, observation, f"{ordinal:064x}", "delivered" if delivered else "queued", delivered)).fetchone()[0]
    if delivered:
        conn.execute("""insert into radius_session_projection_receipts(delivery_id,observation_id,
            outcome,projected_row_count,consumer_contract_id)
            values(%s,%s,'identity_unresolved',0,'sli.radius-session-consumer.v1')""", (delivery, observation))
    return delivery


def test_disable_drain_reenable_preserve_history_cursors_and_audit(database):
    conn = database
    install(conn)
    epoch = seed_source(conn)
    seed_delivery(conn, epoch, 1, delivered=True)
    conn.execute("""insert into radius_vpn_session_projection(session_row_id,session_identity_key,
        exact_principal_key,generation,lifecycle_state,completeness,last_observed_at_utc,
        observation_count,read_model_contract_id) values(%s,%s,'fixture-principal',1,
        'partial_open','middle_only',now(),1,'sli.radius-session-read-model.v1')""",
        ("radius-session-row:" + "1" * 64, "radius-session:" + "2" * 64))
    before = {table: snapshot(conn, table) for table in PRESERVED}
    audit = snapshot(conn, "administrative_activity_v1")
    operations = snapshot(conn, "plugin_lifecycle_operations_v1")
    transition(conn, "enable")
    with conn.transaction():
        lease = acquire_component_lease(conn, lease_uid=uuid4(), component_id=CONSUMER, holder_key="fixture-legacy")
    transition(conn, "drain")
    assert conn.execute("select finish_remote_access_plugin_drain_v1()").fetchone() == (False,)
    with conn.transaction():
        with pytest.raises(RaiseException), conn.transaction():
            acquire_component_lease(conn, lease_uid=uuid4(), component_id=ACQUISITION, holder_key="fixture-acquisition")
        assert release_component_lease(conn, lease=lease, holder_key="fixture-legacy", outcome="completed")
    assert conn.execute("select finish_remote_access_plugin_drain_v1()").fetchone() == (True,)
    retained_rows = [{"id": row[0]} for row in conn.execute("select session_row_id from radius_vpn_session_projection").fetchall()]
    payload = {"state": "ok", "items": retained_rows}
    plugin_state.annotate_plugin_report("vpn.accounts", payload)
    assert payload["plugin"] == {"plugin_id": PLUGIN, "state": "disabled", "read_only": True}
    assert payload["state"] == "ok" and payload["items"] == retained_rows
    transition(conn, "enable")
    assert {table: snapshot(conn, table) for table in PRESERVED} == before
    assert all(row in snapshot(conn, "administrative_activity_v1") for row in audit)
    assert all(row in snapshot(conn, "plugin_lifecycle_operations_v1") for row in operations)
    assert len(snapshot(conn, "plugin_lifecycle_operations_v1")) == len(operations) + 4


def test_detach_is_refused_without_mutating_retained_state(database):
    conn = database
    install(conn)
    seed_delivery(conn, seed_source(conn), 1, delivered=True)
    before = {table: snapshot(conn, table) for table in (*PRESERVED,
        "plugin_installations_v1", "plugin_state_v1", "plugin_lifecycle_operations_v1", "administrative_activity_v1")}
    state = replace(initial_remote_access_state(), package_lifecycle="registered", revision=2)
    plan = plan_plugin_lifecycle(action="detach", state=state, actor_capabilities={"plugins.manage"})
    assert "detach_reader_and_parity_required" in plan["blockers"]
    with pytest.raises(PluginLifecycleError, match="plugin_lifecycle_execution_disabled"):
        execute_plugin_lifecycle(plan=plan, confirmation=plan["confirmation"])
    with pytest.raises(RaiseException), conn.transaction():
        transition(conn, "detach")
    assert {table: snapshot(conn, table) for table in before} == before


def test_legacy_to_core_guard_preserves_cursor_and_does_not_reimport(database):
    conn = database
    install(conn)
    epoch = seed_source(conn)
    old_delivery = seed_delivery(conn, epoch, 1, delivered=True)
    new_delivery = seed_delivery(conn, epoch, 2)
    cursor_before = snapshot(conn, "acquisition_stream_cursors")
    receipt_before = snapshot(conn, "radius_session_projection_receipts")
    transition(conn, "enable")
    registry = pilot_registry()
    with conn.cursor() as cur:
        cur.execute("select read_radius_job_source_v1(%s)", (SOURCE,))
        source = cur.fetchone()[0]
        assert source["delivery_ids"] == [new_delivery]
        schedule_jobs(cur, registry, "light", source)
        job = job_queue.claim(cur, "light", "fixture-core", registry.identities("light"))
    assert job is not None
    with conn.transaction():
        legacy = acquire_component_lease(conn, lease_uid=uuid4(), component_id=CONSUMER, holder_key="fixture-legacy")
    staged = job_executor.stage_radius(conn, job)
    assert staged["delivery_ids"] == [new_delivery]
    with pytest.raises(UniqueViolation):
        job_queue.publish(conn, job, staged, job_executor.apply_radius)
    assert snapshot(conn, "radius_session_projection_receipts") == receipt_before
    assert snapshot(conn, "acquisition_stream_cursors") == cursor_before
    with conn.transaction():
        assert release_component_lease(conn, lease=legacy, holder_key="fixture-legacy", outcome="completed")
    # Disable while a core result is staged. Preserve its pinned queue input
    # and audit, refuse effects, then resume the same job after explicit enable.
    jobs_before = snapshot(conn, "sli_jobs.jobs")
    audit_before = snapshot(conn, "sli_jobs.audit")
    transition(conn, "drain")
    assert conn.execute("select finish_remote_access_plugin_drain_v1()").fetchone() == (True,)
    with pytest.raises(RaiseException):
        job_queue.publish(conn, job, staged, job_executor.apply_radius)
    assert snapshot(conn, "sli_jobs.jobs") == jobs_before
    assert snapshot(conn, "sli_jobs.audit") == audit_before
    assert snapshot(conn, "radius_session_projection_receipts") == receipt_before
    transition(conn, "enable")
    # Use the actual publisher identity: it inherits the restricted consumer,
    # cannot SET ROLE, and must keep its queue-publication privileges.
    conn.execute("set session authorization sli_job_publisher_light")
    try:
        assert job_queue.publish(conn, job, staged, job_executor.apply_radius) == "committed"
    finally:
        conn.execute("reset session authorization")
    assert snapshot(conn, "acquisition_stream_cursors") == cursor_before
    assert conn.execute("select delivery_id from radius_session_projection_receipts order by delivery_id").fetchall() == [(old_delivery,), (new_delivery,)]
    assert all(row in snapshot(conn, "radius_session_projection_receipts") for row in receipt_before)
    assert conn.execute("select count(*) from plugin_component_leases_v1 where released_at_utc is null").fetchone() == (0,)
    with conn.cursor() as cur:
        assert job_queue.claim(cur, "light", "fixture-core", registry.identities("light")) is None
    assert conn.execute("select count(*) from core_evidence_manifests where source_instance_id=%s", (SOURCE,)).fetchone() == (2,)
    blocked = job_executor.stage_radius(None, {**job, "handler_id": ACQUISITION})
    assert blocked["error_code"] == "acquisition_disabled"


@pytest.mark.parametrize("binding", [
    "exact", "other_plugin", "other_source", "other_handler", "other_subscription",
    "expired_lease", "expired_deadline", "retry_wait", "unpinned", "leased_delivery",
    "quarantined_delivery", "failed_delivery", "extra_delivery", "active_component",
])
def test_core_drain_handoff_requires_live_exact_pin_and_unclaimed_delivery(database, binding):
    conn = database
    install(conn)
    seed_delivery(conn, seed_source(conn), 1)
    transition(conn, "enable")
    registry = pilot_registry()
    with conn.cursor() as cur:
        cur.execute("select read_radius_job_source_v1(%s)", (SOURCE,))
        schedule_jobs(cur, registry, "light", cur.fetchone()[0])
        job = job_queue.claim(cur, "light", "fixture-core", registry.identities("light"))
    assert job is not None
    if binding == "other_plugin":
        conn.execute("update sli_jobs.jobs set plugin_id='sli.core' where job_id=%s", (job["job_id"],))
    elif binding == "other_source":
        conn.execute("update sli_jobs.jobs set source_instance_id='fixture-other-source' where job_id=%s", (job["job_id"],))
    elif binding in {"other_handler", "other_subscription", "unpinned"}:
        path, value = {
            "other_handler": (["handler_id"], "fixture-other-handler"),
            "other_subscription": (["pinned_input", "subscription_id"], "fixture-other-subscription"),
            "unpinned": (["pinned_input", "delivery_ids"], []),
        }[binding]
        conn.execute("update sli_jobs.jobs set spec=jsonb_set(spec,%s,%s::jsonb) where job_id=%s",
                     (path, job_queue.canonical(value), job["job_id"]))
    elif binding == "expired_lease":
        conn.execute("update sli_jobs.jobs set lease_until=clock_timestamp()-interval '1 second' where job_id=%s", (job["job_id"],))
    elif binding == "expired_deadline":
        conn.execute("""update sli_jobs.jobs set available_at=clock_timestamp()-interval '2 seconds',
            deadline_at=clock_timestamp()-interval '1 second' where job_id=%s""", (job["job_id"],))
    elif binding == "retry_wait":
        conn.execute("update sli_jobs.jobs set state='retry_wait',lease_token=null,lease_until=null where job_id=%s", (job["job_id"],))
    elif binding == "leased_delivery":
        conn.execute("""update acquisition_delivery_outbox set delivery_state='leased',
            lease_token=%s,lease_until=clock_timestamp()+interval '1 minute' where subscription_id=%s""",
            (uuid4(), SUBSCRIPTION))
    elif binding == "quarantined_delivery":
        conn.execute("update acquisition_delivery_outbox set delivery_state='quarantined' where subscription_id=%s", (SUBSCRIPTION,))
    elif binding == "failed_delivery":
        conn.execute("update acquisition_delivery_outbox set delivery_state='failed' where subscription_id=%s", (SUBSCRIPTION,))
    elif binding == "extra_delivery":
        epoch = conn.execute("select cursor_epoch from acquisition_stream_cursors where source_instance_id=%s", (SOURCE,)).fetchone()[0]
        seed_delivery(conn, epoch, 2)
    elif binding == "active_component":
        with conn.transaction():
            acquire_component_lease(conn, lease_uid=uuid4(), component_id=CONSUMER, holder_key="fixture-legacy")
    preserved = {table: snapshot(conn, table) for table in (*PRESERVED, "sli_jobs.jobs", "sli_jobs.audit")}
    transition(conn, "drain")
    retained = binding in {"exact", "failed_delivery", "active_component"}
    expected = retained and binding != "active_component"
    assert conn.execute("select read_plugin_runtime_queue_nonterminal_v1()").fetchone() == (0 if retained else 1,)
    assert conn.execute("select finish_remote_access_plugin_drain_v1()").fetchone() == (expected,)
    assert {table: snapshot(conn, table) for table in preserved} == preserved


def test_two_collection_hosts_cannot_own_the_same_consumer(database):
    dsn = os.environ["ADLOG_TEST_PG_DSN"]
    key = "sli.remote-access:radius-session-observation:host:v1"
    with connect(dsn, autocommit=True) as other:
        assert_disposable_database(other)
        assert database.execute("select pg_try_advisory_lock(hashtext(%s))", (key,)).fetchone() == (True,)
        assert other.execute("select pg_try_advisory_lock(hashtext(%s))", (key,)).fetchone() == (False,)
        assert database.execute("select pg_advisory_unlock(hashtext(%s))", (key,)).fetchone() == (True,)
        assert other.execute("select pg_try_advisory_lock(hashtext(%s))", (key,)).fetchone() == (True,)


def test_fresh_install_has_no_new_grants_bindings_or_external_collection(database, monkeypatch):
    conn = database
    from server.api.routes import reports_v2
    from server.sli.access import access_control_v4 as access_control
    user_id = conn.execute("""insert into auth_users(username,password_hash,role)
        values('fixture-viewer','!disabled-fixture!','viewer') returning id""").fetchone()[0]
    monkeypatch.setattr(access_control, "_connect", lambda: connect(os.environ["ADLOG_TEST_PG_DSN"], row_factory=dict_row))
    principal = {"type": "session", "id": user_id, "role": "viewer"}
    preserved = {table: snapshot(conn, table) for table in PRESERVED}
    install(conn)
    assert conn.execute("select package_lifecycle,desired_activation,component_runtime,queue_state from plugin_installations_v1 where plugin_id=%s", (PLUGIN,)).fetchone() == ("registered", "disabled", "stopped", "drained")
    assert conn.execute("select admission_mode from plugin_component_admission_v1 where plugin_id=%s", (PLUGIN,)).fetchall() == [("closed",), ("closed",)]
    for component in (ACQUISITION, CONSUMER):
        with pytest.raises(RaiseException), conn.transaction():
            acquire_component_lease(conn, lease_uid=uuid4(), component_id=component, holder_key="fixture-worker")
    assert {table: snapshot(conn, table) for table in PRESERVED} == preserved
    access = access_control.effective_access(principal)
    assert not access_control.capability_decision(access, "vpn.sessions.view")["allowed"]
    sent = []
    handler = SimpleNamespace(_access_decision=lambda: access, _send_json=lambda payload, status=200: sent.append((payload, int(status))))
    assert reports_v2.try_handle_get(handler, "/api/v2/reports/vpn.connections/data", {})
    assert sent[-1] == ({"error": "report_access_denied"}, 403)
    assert conn.execute("select count(*) from plugin_component_leases_v1 where released_at_utc is null").fetchone() == (0,)
    payload = {"state": "empty", "items": []}
    plugin_state.annotate_plugin_report("vpn.connections", payload)
    assert payload["state"] == "unavailable" and payload["reason"] == "not_collected"
    transition(conn, "enable")
    with conn.transaction():
        admitted = acquire_component_lease(conn, lease_uid=uuid4(), component_id=CONSUMER, holder_key="fixture-owner-enabled")
        assert release_component_lease(conn, lease=admitted, holder_key="fixture-owner-enabled", outcome="completed")
    assert {table: snapshot(conn, table) for table in PRESERVED} == preserved


def test_agent_vpn_binding_is_refused_and_default_assignment_is_empty(database):
    conn = database
    agent = uuid4()
    conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)", (agent, uuid4(), "f" * 64))
    assert conn.execute("select assigned_modules from sli_agents where id=%s", (agent,)).fetchone() == ([],)
    before = {table: snapshot(conn, table) for table in ("sli_agent_module_bindings", "sli_agent_receipts", "sli_agent_packet_inbox", "sli_agent_audit")}
    with pytest.raises(CheckViolation), conn.transaction():
        conn.execute("""insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,
            source_name,channel,module_version,policy_revision)
            values(%s,'sli.remote-access',%s,'fixture-source','fixture-channel','1.0.0','1')""", (agent, SOURCE))
    assert {table: snapshot(conn, table) for table in before} == before


def test_agent_disable_preserves_binding_packet_cursor_and_audit(database):
    from datetime import datetime, timezone
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import PostgresLedger, receive_packet
    from server.sli.agents.registry import revoke
    from sli_agent.envelope import make_packet
    from sli_agent.modules import EventLogModule

    conn = database
    agent, host = uuid4(), uuid4()
    conn.execute("""insert into sli_agents(id,host_id,key_fingerprint,assigned_modules)
        values(%s,%s,%s,'["sli.windows-eventlog"]')""", (agent, host, "f" * 64))
    conn.execute("""insert into sli_agent_module_bindings(agent_id,module_id,source_instance_id,
        source_name,channel,module_version,policy_revision)
        values(%s,'sli.windows-eventlog','fixture-event-source','fixture-host','Security','1.0.0','1')""", (agent,))
    now = datetime.now(timezone.utc)
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><EventID>4624</EventID><EventRecordID>7</EventRecordID></System></Event>')
    module = EventLogModule(source_instance_id="fixture-event-source", source_name="fixture-host",
        channel="Security", generation="fixture-generation", reader=lambda after: [xml])
    key = ec.generate_private_key(ec.SECP256R1())
    packet = make_packet(key, agent_id=str(agent), sequence=1, sample=module.collect(None, now=now), now=now)
    identity = {"id": str(agent), "host_id": str(host), "assigned_modules": ["sli.windows-eventlog"]}
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        receipt = receive_packet(PostgresLedger(cur), identity=identity, public_key=key.public_key(), value=packet, now=now)
    assert receipt["status"] == "committed"
    tables = ("sli_agent_module_bindings", "sli_agent_receipts", "sli_agent_packet_inbox")
    before = {table: snapshot(conn, table) for table in tables}
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        assert receive_packet(PostgresLedger(cur), identity=identity, public_key=key.public_key(), value=packet, now=now)["status"] == "duplicate"
    assert {table: snapshot(conn, table) for table in tables} == before
    audit = snapshot(conn, "sli_agent_audit")
    with conn.transaction(), conn.cursor(row_factory=dict_row) as cur:
        assert revoke(cur, {"agent_id": str(agent)}, actor="fixture-owner", disable=True) == {"status": "disabled"}
    assert conn.execute("select status from sli_agents where id=%s", (agent,)).fetchone() == ("disabled",)
    assert {table: snapshot(conn, table) for table in tables} == before
    assert all(row in snapshot(conn, "sli_agent_audit") for row in audit)
    assert conn.execute("select receipt->'committed_cursor' from sli_agent_receipts where agent_id=%s", (agent,)).fetchone()[0] == {"strategy": "record_id", "token": "7"}
