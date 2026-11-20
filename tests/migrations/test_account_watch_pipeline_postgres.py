"""T016 watch registration through native classification and publication.

Full migrated per-test PostgreSQL only: no reduced tables, replacement evidence
resolver, extra GRANT, prebuilt signal/finding/outbox or real transport. Input is
synthetic imported receipt + retained directory metadata, not AD collection.
The short-event admission gate verifies that same receipt and native event.
Medium watch findings queue for SMTP; Telegram admits high/critical only.
The shipped .NET worker runs once: managed polling, capture authentication and
historical-replay processing are not covered. Reprocessing checks deduplication.
"""
import os
from datetime import timedelta
from hashlib import sha256
from uuid import uuid4

import pytest

from server.sli.access import access_control_v4 as acl
from server.sli.agents import policies
from server.sli.core import notification_smtp, notification_telegram
from server.sli.core import postgres_runtime_pipeline as pipeline, watch_entries
from server.sli.ops.postgres_schema_guard import clear_schema_guard_cache
from server.sli.semantic import account_watch, default_detections as defaults
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from server.sli.storage.evidence_ref import EvidenceScope
from tests.migrations.short_detection_fixture import run_semantic_worker, store_short_event
from tests.postgres_integration_guard import assert_disposable_database

pytestmark = pytest.mark.postgres_integration
SID = "S-1-5-21-100000001-200000002-300000003-9001"
PROVIDER = "Microsoft-Windows-Security-Auditing"


@pytest.fixture
def watch_db(isolated_postgres_integration_database, monkeypatch):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Fully migrated disposable PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row

    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)

    def connect(role=None):
        conn = psycopg.connect(dsn, row_factory=dict_row)
        if role:
            assert role == "adlog_user"
            conn.execute("set session authorization adlog_user")
            assert conn.execute("select session_user as s,current_user as c").fetchone() == {
                "s": "adlog_user", "c": "adlog_user"}
        return conn

    def no_delivery(*args, **kwargs):
        pytest.fail("Unexpected SMTP/Telegram delivery in the watch publication test")

    # PostgreSQL connections remain real; external delivery must never run.
    monkeypatch.setattr(notification_smtp, "send", no_delivery)
    monkeypatch.setattr(notification_telegram, "send", no_delivery)
    # The connection boundary is redirected to the disposable database.
    monkeypatch.setattr(pipeline, "connect", lambda: connect("adlog_user"))
    clear_schema_guard_cache()
    yield connect
    clear_schema_guard_cache()


def _source(connect, *, wrong_domain=False):
    from psycopg.types.json import Jsonb

    agent, host, packet, run, guid = (uuid4() for _ in range(5))
    data = {"TargetUserSid": SID, "TargetUserName": "fixture-account",
            "TargetDomainName": "T016", "LogonType": "3"}
    with connect() as conn:
        owner = conn.execute("insert into auth_users(username,password_hash,role) "
            "values(%s,'synthetic-only','admin') returning id", ("t016-" + uuid4().hex,)).fetchone()["id"]
        # Migration037 permits any unique owner_key; effective_access checks the
        # user_id relation, not the key. Synthetic app data only, no SQL GRANT.
        conn.execute("""insert into access_platform_owners(user_id,owner_key,business_reason)
            values(%s,%s,'T016 synthetic install-specific ownership fixture')""",
            (owner, "t016-" + uuid4().hex))
        denied_admin = conn.execute("insert into auth_users(username,password_hash,role) "
            "values(%s,'synthetic-only','admin') returning id", ("t016-denied-" + uuid4().hex,)).fetchone()["id"]
        # Coarse admin can inherit objects.view in the full schema. Make the
        # denied management contract explicit using the real application ACL.
        deny, = conn.execute("""insert into access_capability_assignments(
            subject_type,subject_id,capability_id,effect,scope_json,business_reason)
            select 'user',%s,id,'deny','{"kind":"all"}'::jsonb,'T016 synthetic watch-management denial'
            from access_capabilities where capability_key='watch.manage' returning id""",
            (denied_admin,)).fetchall()
        assert deny["id"] > 0
        forest = conn.execute("insert into forests(name) values('t016.example.test') returning id").fetchone()["id"]
        domain = conn.execute("insert into domains(forest_id,fqdn) values(%s,'t016.example.test') returning id", (forest,)).fetchone()["id"]
        account_domain = (conn.execute("insert into domains(forest_id,fqdn) values(%s,'other.t016.example.test') returning id", (forest,)).fetchone()["id"]
                          if wrong_domain else domain)
        server = conn.execute("insert into servers(domain_id,hostname,fqdn,role) values(%s,'t016-dc','t016-dc.example.test','domain_controller') returning id", (domain,)).fetchone()["id"]
        kind = conn.execute("insert into storage_v2_entity_type(value) values('ad_user') on conflict(value) do update set value=excluded.value returning id").fetchone()["id"]
        at = conn.execute("select clock_timestamp()-interval '5 seconds' as at").fetchone()["at"]
        entity = conn.execute("""insert into entities_v2(entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            values(%s,%s,'fixture-account',%s,%s) returning id""", (kind, "sid:" + SID, account_domain, bytes(32))).fetchone()["id"]
        conn.execute("""insert into ad_context_runs(run_id,source_pack_id,source_pack_version,domain_id,mode,
            observed_at_utc,bundle_sha256,status,completed_at) values(%s,'windows-ad-dc','1',%s,'full',%s,%s,'completed',%s)""",
            (run, account_domain, at-timedelta(hours=1), bytes(32), at-timedelta(hours=1)))
        conn.execute("""insert into ad_context_entity_versions(entity_id,source_section,valid_from_utc,
            last_observed_at_utc,content_sha256,attributes_json,source_run_id)
            values(%s,'directory_accounts',%s,%s,%s,%s,%s)""", (entity, at-timedelta(hours=1), at-timedelta(hours=1),
            bytes(32), Jsonb({"identity": {"kind": "ad_user", "object_sid": SID, "object_guid": str(guid)}}), run))
        conn.execute("insert into sli_agents(id,host_id,key_fingerprint) values(%s,%s,%s)", (agent, host, "0"*64))
        digest = sha256(b"t016-synthetic-native-event").digest()
        envelope = {"agent_id": str(agent), "source_instance_id": str(host), "generation": str(host)}
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
               f'<Provider Name="{PROVIDER}"/><EventID>4624</EventID><EventRecordID>1</EventRecordID>'
               f'<TimeCreated SystemTime="{at.isoformat()}"/><Channel>Security</Channel><Computer>fixture-collector</Computer>'
               '</System><EventData>' + ''.join(f'<Data Name="{key}">{value}</Data>' for key, value in data.items()) + '</EventData></Event>')
        row = {"record_id": 1, "event_id": 4624, "time_created": at.isoformat(),
               "computer_name": "fixture-collector", "channel": "Security", "xml": xml}
        conn.execute("""insert into sli_agent_receipts(agent_id,module_id,sequence,packet_id,envelope_sha256,envelope,receipt)
            values(%s,'sli.windows.ad-dc',1,%s,%s,%s,%s)""", (agent, packet, digest.hex(), Jsonb(envelope), Jsonb({"status": "committed"})))
        conn.execute("""insert into sli_agent_packet_inbox(packet_id,envelope,packet,event_rows,imported_at)
            values(%s,%s,%s,%s,clock_timestamp())""", (packet, Jsonb(envelope), Jsonb({
            "contract": "sli.collection-packet.v1", "header": {"source": "fixture-collector", "channel": "Security"}}), Jsonb([row])))
        # Migration261 intentionally suppresses medium Telegram findings. Seed
        # both existing channels to prove SMTP admission and Telegram suppression.
        for delivery_channel in ("smtp", "telegram"):
            conn.execute("""insert into notification_subscriptions(id,owner_user_id,recipient_user_id,channel,enabled)
                values(%s,%s,%s,%s,true)""", (uuid4(), owner, owner, delivery_channel))
    with connect("adlog_user") as web, web.cursor() as cur:
        policies.assign_module(cur, {"agent_id": str(agent), "module_id": "sli.windows.ad-dc",
            "expected_revision": 1, "enabled": True,
            "config": {"source_name": "t016-dc.example.test", "connect_address": "t016-dc.example.test"}}, actor=f"session:{owner}")
    with connect() as admin:
        event = store_short_event(admin, server=server, domain=domain, packet=packet, row=row, digest=digest)
        assert admin.execute("select count(*) as n from notification_subscriptions where enabled").fetchone()["n"] == 2
    return dict(owner=owner, denied_admin=denied_admin, entity=entity, domain=domain, event=event, at=at, xml=xml, digest=digest.hex())


def _register(connect, item, case):
    access = acl.effective_access(None, preview_user_id=item["owner"])
    assert access["platform_owner"] is True
    assert {"objects.view", "watch.manage", "workspace.view"} <= set(access["capabilities"])
    watch_entries.require_access(access)
    # Access DTO uses coarse_role; authenticated service principals use role.
    principal = {**access["subject"], "role": access["subject"]["coarse_role"]}
    at = item["at"]
    start = at + timedelta(seconds=1) if case == "before_start" else at-timedelta(seconds=1)
    expires = at if case == "expiry_boundary" else at+timedelta(hours=1)
    body = {"entity_id": item["entity"], "owner": "fixture-team", "reason": "fixture-private-reason",
            "expires_at": expires.isoformat(), "active": True, "revision": 0}

    def audit(cur, details):
        acl.record_access_audit_with_cursor(cursor=cur, actor=principal, action="watch_entry_update",
            target_type="watch_entry", target_key=details["id"], details=details)

    denied = acl.effective_access(None, preview_user_id=item["denied_admin"])
    assert denied["platform_owner"] is False
    assert "watch.manage" not in denied["capabilities"]
    assert acl.capability_decision(denied, "watch.manage") == {
        "allowed": False, "reason": "explicit_deny", "capability": "watch.manage", "diagnostics": []}
    denied_principal = {**denied["subject"], "role": denied["subject"]["coarse_role"]}

    def denied_audit(cur, details):
        acl.record_access_audit_with_cursor(cursor=cur, actor=denied_principal, action="watch_entry_update",
            target_type="watch_entry", target_key=details["id"], details=details)

    with pytest.raises(PermissionError), connect("adlog_user") as web, web.cursor() as cur:
        watch_entries.save_entry(cur, denied, body, principal=denied_principal, audit=denied_audit, now=start)
    with connect() as admin:
        assert admin.execute("select count(*) as n from watch_entry_versions where entity_id=%s", (item["entity"],)).fetchone()["n"] == 0
        assert admin.execute("select count(*) as n from access_audit_v4 where action='watch_entry_update' and actor_id=%s", (item["denied_admin"],)).fetchone()["n"] == 0

    with connect("adlog_user") as web, web.cursor() as cur:
        saved = watch_entries.save_entry(cur, access, body, principal=principal, audit=audit, now=start)
        if case == "disabled_after_event":
            watch_entries.save_entry(cur, access, body | {"active": False, "revision": saved["revision"]},
                principal=principal, audit=audit, entry_id=saved["id"], now=at+timedelta(seconds=1))
    return access, saved


@pytest.mark.parametrize("case,expected", [
    ("active", 1), ("disabled_after_event", 1), ("before_start", 0),
    ("expiry_boundary", 0), ("wrong_domain", 0), ("bad_evidence", 0), ("admin_disabled", 0),
])
def test_registered_watch_native_event_publication_and_reprocessing(watch_db, postgres_semantic_worker_dsn, tmp_path, case, expected):
    """Catches dropped source-producer dispatch, widened event-time matching and forced re-enabling."""
    import psycopg
    from psycopg.rows import dict_row

    item = _source(watch_db, wrong_domain=case == "wrong_domain")
    access, saved = _register(watch_db, item, case)
    with psycopg.connect(postgres_semantic_worker_dsn, autocommit=True, row_factory=dict_row) as worker:
        worker.execute("set role adlog_semantic_worker")
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        with worker.transaction():
            source, = worker.execute("select source from default_detection_sources()").fetchall()
            source = source["source"]
            rule = account_watch.WatchRule(scope=EvidenceScope(**source["scope"]), evaluation_mode="enabled")
            policy = account_watch.risk_policy(rule, policy_id=defaults.policy_id(rule.execution))
            assert defaults._admit(worker.cursor(), policy)
        if case == "admin_disabled":
            with watch_db() as admin:
                admin.execute("update semantic_policy_admission set enabled=false,updated_by='fixture-admin' where policy_id=%s", (policy.policy_id,))
        if case == "bad_evidence":
            with watch_db() as admin:
                admin.execute("update event_hot set source_sha256=null where event_id=%s", (item["event"],))
        run_semantic_worker(postgres_semantic_worker_dsn, tmp_path)
        with watch_db() as admin:
            assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == expected
            assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs where evaluation_status='completed'").fetchone()["n"] == expected
        # Replaying the shipped worker must not enqueue or publish another job.
        run_semantic_worker(postgres_semantic_worker_dsn, tmp_path)
        with watch_db() as admin:
            assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == expected
    with watch_db() as admin:
        assert admin.execute("select count(*) as n from findings").fetchone()["n"] == expected
        assert admin.execute("select count(*) as n from normalized_events").fetchone()["n"] == 0
        assert admin.execute("select count(*) as n from event_hot where source_sha256 is not null").fetchone()["n"] == int(case != "bad_evidence")
        queue_diagnostics = admin.execute("""select
            (select count(*) from notification_subscriptions where enabled) as enabled_subscriptions,
            (select count(*) from semantic_finding_publications) as publications,
            (select array_agg(distinct job.source_kind) from semantic_finding_publications p
                join semantic_risk_evaluation_jobs job on job.job_id=p.first_job_id) as published_source_kinds,
            (select array_agg(distinct coalesce(document_json->>'processing_mode','live'))
                from semantic_qw_signals) as signal_modes,
            (select max(extract(epoch from clock_timestamp()-(document_json->>'occurred_at_utc')::timestamptz))
                from semantic_qw_signals) as oldest_signal_seconds,
            md5(pg_get_functiondef('public.enqueue_qw_finding_notifications(uuid)'::regprocedure)) as enqueue_definition_md5
            """).fetchone()
        assert admin.execute("select count(*) as n from notification_outbox").fetchone()["n"] == expected, queue_diagnostics
        assert admin.execute("select count(*) as n from notification_outbox where channel='telegram'").fetchone()["n"] == 0
        audit_rows = admin.execute("select details_json from access_audit_v4 where action='watch_entry_update' and target_key=%s", (saved["id"],)).fetchall()
        assert len(audit_rows) == (2 if case == "disabled_after_event" else 1)
        assert "fixture-private-reason" not in str(audit_rows) and SID not in str(audit_rows)
        if case == "admin_disabled":
            assert admin.execute("select enabled,updated_by from semantic_policy_admission where policy_id=%s", (policy.policy_id,)).fetchone() == {"enabled": False, "updated_by": "fixture-admin"}
        if expected:
            finding, = admin.execute("select * from findings").fetchall()
            assert finding["rule_code"] == "semantic.qw.account-watch" and finding["severity"] == "medium"
            assert finding["evidence_count"] == 1
            ref, = admin.execute("select * from finding_evidence_refs where finding_id=%s", (finding["id"],)).fetchall()
            assert ref["native_id"] == str(item["event"]) and ref["sha256"] == item["digest"]
            assert ref["plugin_id"] == "sli.windows.ad-dc" and ref["source_generation"] == rule.scope.source_generation
            pending, = admin.execute("select * from notification_outbox").fetchall()
            assert pending["channel"] == "smtp"
            assert pending["state"] == "pending" and pending["attempts"] == 0 and pending["object_severity"] == "medium"
            signal, = admin.execute("select document_json from semantic_qw_signals").fetchall()
            assert signal["document_json"]["watch_context"]["entry_id"] == saved["id"]
            assert signal["document_json"]["watch_context"]["entry_revision"] == 1
    with watch_db("adlog_user") as web:
        priority = web.execute("select account_watch_event_priority(%s,%s) as p", (item["event"], item["digest"])).fetchone()["p"]
        assert priority == ({"base_severity": "low", "effective_severity": "medium", "reason": "watch"} if expected else None)
        assert web.execute("select account_watch_event_priority(%s,%s) as p", (item["event"], "c"*64)).fetchone()["p"] is None
    with watch_db() as admin:
        counts = admin.execute("select report_security_candidate_counts('{}','UTC',%s,%s) as value",
                               (item["at"]-timedelta(days=1), item["at"]+timedelta(days=1))).fetchone()["value"]
        assert counts["counts"]["individual"]["total"] == expected
