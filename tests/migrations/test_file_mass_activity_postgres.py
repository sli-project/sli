"""T010 accepted-source conveyor on the fully migrated disposable database.

Synthetic accepted XML receipts and inventory replies, never OS file operations.
No replacement SQL, grants, fake authorization, seeded detector results/findings,
or threshold changes. Capture/mTLS and an installed LAB share are not exercised.
"""
import os
from copy import deepcopy
from datetime import timedelta
from uuid import NAMESPACE_URL, uuid4, uuid5

import pytest

from server.sli.access import access_control_v4
from server.sli.agents import policies
from server.sli.agents.ca import AgentError
from server.sli.core import notification_telegram as telegram
from server.sli.core import postgres_runtime_pipeline as pipeline
from server.sli.ops.postgres_schema_guard import clear_schema_guard_cache
from server.sli.plugins.file_audit import management, reports, rule_runtime
from server.sli.plugins.file_audit.correlation import observation_from_xml, project_actions
from server.sli.reporting.home_summary import home_summary
from server.sli.reporting.v2.access import ReportAccess
from server.sli.reporting.v2.definition import QueryContext, parse_params
from server.sli.semantic import default_detections as defaults
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from sli_agent.file_audit import CONTRACT, digest
from sli_agent.file_audit_policy import audit_requirements
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_file_audit_collection import xml
from tests.unit.test_file_audit_contracts import settings

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def mass_dsn(isolated_postgres_integration_database, monkeypatch, request, tmp_path):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Fully migrated disposable PostgreSQL required")
    if request.node.get_closest_marker("postgres_owned_cluster") is None:
        yield dsn
        return

    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    from tests.migrations.historical_postgres import historical_connection

    # The Python Home cohort witness reads the last pre-retirement event schema.
    with historical_connection(tmp_path, monkeypatch, (371, "password_domain_auto")) as historical:
        template_dsn, template = historical.info.dsn, historical.info.dbname
        historical.close()
        database = "sli_test_mass_home"
        # Match the regular per-case clone so its isolated worker can connect.
        with psycopg.connect(make_conninfo(template_dsn, dbname="postgres"), autocommit=True) as admin:
            admin.execute(sql.SQL("create database {} template {}").format(
                sql.Identifier(database), sql.Identifier(template),
            ))
        dsn = make_conninfo(template_dsn, dbname=database)
        monkeypatch.setenv("ADLOG_TEST_PG_DSN", dsn)
        monkeypatch.setenv("ADLOG_PG_DSN", dsn)
        yield dsn


@pytest.fixture
def mass_db(mass_dsn, monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(mass_dsn) as conn:
        assert_disposable_database(conn)

    def connect(role=None):
        conn = psycopg.connect(mass_dsn, row_factory=dict_row)
        if role:
            assert role in {"adlog_user", "adlog_notification_worker"}
            conn.execute("set session authorization " + role)
            assert conn.execute("select session_user as s,current_user as c").fetchone() == {
                "s": role, "c": role}
            conn.commit()  # Readers must own their isolation-setting transaction.
        return conn

    def no_transport(*_, **__):
        pytest.fail("Unexpected real Telegram credential/config/network access")

    for name in ("send", "_config", "read_notification_secret", "_connection"):
        monkeypatch.setattr(telegram, name, no_transport)
    clear_schema_guard_cache()
    monkeypatch.setattr(pipeline, "connect", lambda: connect("adlog_user"))
    monkeypatch.setattr(reports, "connect", lambda: connect("adlog_user"))
    yield connect
    clear_schema_guard_cache()


def _source(connect):
    agent, host = str(uuid4()), str(uuid4())
    with connect() as conn:
        unassigned_admin = conn.execute("""insert into auth_users(username,password_hash,role)
            values(%s,'synthetic-only','admin') returning id""", ("t010-" + uuid4().hex,)).fetchone()["id"]
        forest = conn.execute("insert into forests(name) values('t010.example.test') returning id").fetchone()["id"]
        domain = conn.execute("insert into domains(forest_id,fqdn) values(%s,'t010.example.test') returning id", (forest,)).fetchone()["id"]
        conn.execute("insert into servers(domain_id,hostname,fqdn) values(%s,'t010-files','t010-files.example.test')", (domain,))
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)", (agent, host, "0" * 64))
        at = conn.execute("select clock_timestamp()-interval '700 seconds' as at").fetchone()["at"]
        # Baseline152 intentionally excludes install-specific owner rows. Model
        # migration037's relationship for CI's actual bootstrap user explicitly,
        # only in this disposable clone. No SQL grant or fake access dictionary.
        conn.execute("""insert into access_platform_owners(user_id,owner_key,business_reason)
            select id,'primary','T010 synthetic install-specific ownership fixture'
            from auth_users where lower(username)='platform-owner' and is_active=true
            on conflict(user_id) do nothing""")
        owner_row, = conn.execute("""select u.id from access_platform_owners o
            join auth_users u on u.id=o.user_id
            where o.owner_key='primary' and u.is_active""").fetchall()
        owner = owner_row["id"]
    denied = access_control_v4.effective_access(None, preview_user_id=unassigned_admin)
    assert not access_control_v4.capability_decision(denied, "file-audit.audit.manage", resource={
        "plugin_id": "sli.file-audit", "device_id": agent,
        "source_instance_id": host, "collection_scope_id": "scope:one"})["allowed"]
    access = access_control_v4.effective_access(None, preview_user_id=owner)
    assert access["platform_owner"] is True
    config = settings() | {"source_name": "t010-files"}
    # A check request in a disposable clone; never dispatch it to an agent.
    command = {"contract_id": "sli.file-audit.audit-command.v1", "command_id": "t010-" + uuid4().hex,
               "policy_revision": "2", "action": "check", "collection_scope_ids": ["scope:one"]}
    with connect("adlog_user") as conn, pytest.raises(AgentError, match="file_audit_request_denied"):
        management.enqueue(conn.cursor(), {"agent_id": agent, "expected_revision": 1,
            "config": config, "command": command},
            principal=denied["subject"], access=denied)
    with connect() as conn:
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.audit_commands where agent_id=%s", (agent,)).fetchone()["n"] == 0
        assert conn.execute("select policy_revision from sli_agents where id=%s", (agent,)).fetchone()["policy_revision"] == 1
    with connect("adlog_user") as conn:
        management.enqueue(conn.cursor(), {"agent_id": agent, "expected_revision": 1,
            "config": config, "command": command}, principal=access["subject"], access=access)
        identity = policies._agent(conn.cursor(), agent)
    return identity, owner, domain, at, access


def _inventory(connect, identity, paths, at, *, tampered=False):
    request = identity["file_audit"]["request"]
    config, command = request["config"], request["command"]
    root = config["roots"][0]
    snapshot = {"contract_id": "sli.file-audit.inventory.v1", "collection_scope_id": "scope:one",
        "policy_revision": command["policy_revision"], "observed_at_utc": at.isoformat(),
        "scan_id": str(uuid4()), "page_number": 0, "has_more": False, "completeness": "complete",
        "unread_objects": 0, "share": {"name": root["share_name"], "path": root["path"], "dacl": "D:", "complete": True},
        "local_groups": {"complete": True, "groups": []}, "objects": [
            {"path": path, "object_id": str(index), "object_type": "file", "owner_sid": "S-1-5-18",
             "dacl": "D:", "sacl": "S:", "sacl_protected": False, "sacl_missing": False}
            for index, path in enumerate(sorted(set(paths)))]}
    checksum = digest(snapshot)
    snapshot.update(snapshot_sha256=checksum, snapshot_id=str(uuid5(NAMESPACE_URL, command["command_id"] + checksum)))
    masks = audit_requirements(config)
    body = {"contract_id": CONTRACT, **{key: command[key] for key in ("command_id", "policy_revision", "action")},
        "observed_at_utc": at.isoformat(), "ownership_remaining": False, "snapshots": [snapshot],
        "scopes": [{"collection_scope_id": "scope:one", "state": "verified", "reason_code": "ok",
                    "required_masks": masks, "actual_masks": masks}]}
    if tampered:
        body = deepcopy(body)
        body["snapshots"][0]["snapshot_sha256"] = "0" * 64
        with connect("adlog_user") as conn, pytest.raises(AgentError, match="file_audit_result_invalid"):
            management.ingest(conn.cursor(), identity, body)
    else:
        with connect("adlog_user") as conn:
            assert management.ingest(conn.cursor(), identity, body)["state"] == "verified"
    with connect() as conn:
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.access_snapshots").fetchone()["n"] == (0 if tampered else 1)
        assert conn.execute("select count(*) as n from sli_plugin_file_audit.audit_receipts").fetchone()["n"] == (0 if tampered else 1)


def _accepted_events(connect, identity, owner, paths, at, *, unknown=False, spread=False):
    """Start at accepted packet input, then use the importer's real projection calls."""
    from psycopg.types.json import Jsonb

    agent, host, packet = str(identity["id"]), str(identity["host_id"]), str(uuid4())
    with connect("adlog_user") as conn:
        policies.assign_module(conn.cursor(), {"agent_id": agent, "module_id": "sli.file-audit", "enabled": True,
            "expected_revision": 2, "config": identity["file_audit"]["request"]["config"]}, actor=f"session:{owner}")
        config = policies._agent(conn.cursor(), agent)["assigned_modules"][0]["config"]
    assert (config["mass_operation_files"], config["mass_operation_seconds"]) == (100, 300)
    generation = str(uuid4())
    envelope = {"agent_id": agent, "source_instance_id": host, "module_id": "sli.file-audit",
        "packet_id": packet, "generation": generation, "sequence": 1, "policy_revision": config["policy_revision"],
        "continuity_state": "complete"}
    observations, actions, payloads = [], [], []
    for number, path in enumerate(paths, 1):
        instant = at + timedelta(seconds=number * 4 if spread else number)
        raw = xml(number, path=path, keywords="0x8000000000000000" if unknown else "0x8020000000000000")
        raw = raw.replace("2026-01-01T00:00:00Z", instant.isoformat())
        observation = observation_from_xml(raw, agent_id=agent, source_instance_id=host, generation=generation,
            policy_revision=config["policy_revision"], core_evidence_ref=f"agent-event:{agent}:{generation}:{number}", config=config)
        # Exactly as importer.import_packet: do not manufacture object_type=file.
        actions.extend(project_actions(observation, observations))
        observations.append(observation)
        payloads.append({"record_id": number, "event_id": 4663, "xml": raw, "time_created": instant.isoformat(),
                         "computer_name": "t010-files", "channel": "Security"})
    with connect() as conn:
        conn.execute("""insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(%s,'sli.file-audit',1,%s,%s,%s,%s)""", (agent, packet, digest(envelope), Jsonb(envelope), Jsonb({"status": "committed"})))
        conn.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows)
            values(%s,%s,%s,%s)""", (packet, Jsonb(envelope), Jsonb({"contract": "sli.collection-packet.v1",
                "header": {"source": "t010-files", "channel": "Security"}}), Jsonb(payloads)))
    with connect("adlog_user") as conn:
        conn.execute("select sli_plugin_file_audit.store_collection(%s,%s,%s)",
                     (agent, packet, Jsonb({"observations": observations, "actions": actions})))
        count = rule_runtime.evaluate_packet(conn.cursor(), envelope=envelope, actions=actions, config=config)
    with connect() as conn:
        conn.execute("update sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=%s", (packet,))
    return count, observations, actions


def _produce(worker_dsn):
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(worker_dsn, autocommit=True, row_factory=dict_row) as worker:
        worker.execute("set role adlog_semantic_worker")
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        with worker.transaction():
            source, = worker.execute("select source from default_detection_sources()").fetchall()
            assert source["source"]["ransom_policy"]["state"] == "ready"
            now = worker.execute("select clock_timestamp() as at").fetchone()["at"]
            outcome = defaults.run_source(worker.cursor(), source["source"], now=now)
            assert not outcome.failed and not outcome.waiting
        with worker.transaction():
            jobs = runtime.claim_risk_evaluation_jobs(worker.cursor(), limit=32)
        results = []
        for job in jobs:
            with worker.transaction():
                work = runtime.load_risk_evaluation_work_item(worker.cursor(), job_id=job["job_id"], lease_token=job["lease_token"])
                results.append(runtime.execute_risk_evaluation(worker.cursor(), work=work, evaluation_ms=0, create_finding=True))
        return outcome, results


@pytest.mark.parametrize("case", [
    "below", "same_path", "outside_window", "unknown_outcome",
    "no_inventory", "bad_inventory", "positive",
    pytest.param("historical_home", marks=pytest.mark.postgres_owned_cluster),
])
def test_accepted_mass_activity_to_real_publication(mass_db, request, case):
    worker_dsn = request.getfixturevalue("postgres_semantic_worker_dsn")
    identity, owner, domain, at, access = _source(mass_db)
    count = 99 if case == "below" else 101
    paths = [rf"C:\synthetic\item-{0 if case == 'same_path' else index}" for index in range(count)]
    if case != "no_inventory":
        _inventory(mass_db, identity, paths, at, tampered=case == "bad_inventory")
    published, observations, actions = _accepted_events(mass_db, identity, owner, paths, at,
        unknown=case == "unknown_outcome", spread=case == "outside_window")
    positive = case in {"positive", "historical_home"}
    if positive:
        with mass_db() as conn:
            recipient = conn.execute("""insert into auth_users(username,password_hash,role)
                values(%s,'synthetic-only','admin') returning id""", ("t010-recipient-" + uuid4().hex,)).fetchone()["id"]
            conn.execute("""insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                values(%s,%s,%s,'telegram',true)""", (uuid4(), owner, recipient))
            conn.execute("update notification_channels set enabled=true where kind='telegram'")
    assert published == int(positive)
    assert all(action["object_type"] == "unknown" for action in actions)
    outcome, results = _produce(worker_dsn)
    assert outcome.jobs == len(results) == int(positive)
    with mass_db() as conn:
        refs = conn.execute("select * from finding_evidence_refs").fetchall()
        if not positive:
            assert not refs
            for table in ("findings", "semantic_qw_signals", "semantic_file_ransom_members", "notification_outbox"):
                assert conn.execute("select count(*) as n from " + table).fetchone()["n"] == 0
            return
        result, = results
        assert result.finding_created and result.risk_class.value == "high"
        finding = conn.execute("select * from findings where id=%s", (result.finding_id,)).fetchone()
        assert finding["rule_code"] == "semantic.qw.file-ransom" and finding["severity"] == "high"
        assert finding["evidence_count"] == len(refs) == len(observations) == 101
        assert {(ref["native_id"], ref["sha256"]) for ref in refs} == {
            (observation["evidence_key"], observation["payload_sha256"]) for observation in observations}
        assert all(ref["source_instance_id"] == str(identity["host_id"]) and ref["collection_scope_id"] == "scope:one" for ref in refs)
        assert conn.execute("select semantic_finding_in_domains_v262(%s,array[%s]::bigint[]) as v", (result.finding_id, domain)).fetchone()["v"]
    if case == "historical_home":
        home = home_summary(access, version="v3", query={"domain_id": [str(domain)], "tz": ["UTC"]})
        assert any("rule_code=semantic.qw.file-ransom" in group["href"] for group in home["groups"])
    definition = reports.REPORTS[reports.REPORT_KEYS.index("mass-operations")]
    params, paging = parse_params(definition, {"period": ["24h"], "tz": ["UTC"]})
    projection = ReportAccess(definition, access)
    context = QueryContext(access=access, params=params, scope=projection.restrict_request(params),
        principal=access["subject"], limit=paging["limit"], timezone="UTC")
    report = reports.query("mass-operations", context)
    row, = report["items"]
    assert row["rule_code"] == "file-audit.mass-write"
    assert row["details"]["distinct_files"] == 101
    assert row["details"]["threshold"] == 100 and row["details"]["window_seconds"] == 300
    # Durable source replay must not generate another high publication.
    outcome, results = _produce(worker_dsn)
    assert outcome.jobs == 0 and not results

    with mass_db() as conn:
        pending, = conn.execute("select * from notification_outbox").fetchall()
        assert pending["state"] == "pending" and pending["attempts"] == 0
        assert pending["object_kind"] == "semantic_finding" and pending["object_severity"] == "high"
        assert str(pending["publication_scenario_id"]) == str(result.scenario_id)
