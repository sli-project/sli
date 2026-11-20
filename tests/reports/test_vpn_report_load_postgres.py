"""T042 native SQL/load gate. Only the existing disposable PostgreSQL CI fixture.

No copied production data: 300 generated accounts, 90 days, 108,000 NPS facts,
108,000 Windows facts and 54,000 Accounting sessions. No schema shortcuts.
"""
from datetime import datetime, timedelta, timezone
import os
import json
from time import monotonic
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from tests.postgres_integration_guard import assert_disposable_database
from tests.reports.test_vpn_authorization_timeline_syntax import _seed_fixture

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_historical(371, "password_domain_auto")]
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
ACCESS = {"platform_owner": True, "capabilities": ["vpn.sessions.view", "events.view"],
          "capability_policies": [], "reports": [{"report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"],
          "grants": [{"allowed_actions": ["view"], "field_categories": ["identity_basic", "technical", "security", "privilege"],
                      "scope": {"kind": "all"}}]}]}


@pytest.fixture
def generated_vpn_data():
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("ADLOG_TEST_PG_DSN is required for the disposable PostgreSQL load gate")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    with psycopg.connect(dsn, row_factory=dict_row) as conn, conn.cursor() as cur:
        assert_disposable_database(conn)
        ids = _seed_fixture(cur)
        cur.execute("insert into servers(domain_id,hostname,role) values (%s,'dc-load.example.invalid','domain_controller') returning id",
                    (ids["domain_id"],))
        dc_id = cur.fetchone()["id"]
        cur.execute("insert into storage_v2_entity_type(value) values ('ad_user') on conflict(value) do update set value=excluded.value returning id")
        entity_type = cur.fetchone()["id"]
        cur.execute("""insert into entities_v2(id,entity_type_id,natural_key,display_name,domain_id,source_core_sha256)
            select 98000000+i,%s,'synthetic-vpn-'||i,'Synthetic account '||i,%s,decode(repeat('ab',32),'hex')
            from generate_series(1,300) i""", (entity_type, ids["domain_id"]))
        cur.execute("""insert into acquisition_source_instances(source_instance_id,organization_scope,source_kind,
            endpoint_identity,adapter_binding,display_name,configuration_sha256)
            values ('synthetic-vpn-load','nps-hotfix.example.invalid','windows.nps.radius',
                    'radius.example.invalid','synthetic','Synthetic source',repeat('a',64))""")
        # One explicit unresolved delivery keeps source coverage honestly partial;
        # generated session rows never prove complete Accounting ingestion.
        epoch, evidence, observation = uuid4(), uuid4(), uuid4()
        cur.execute("""insert into acquisition_stream_cursors(source_instance_id,stream_id,transport_binding,
            cursor_epoch,file_generation,byte_offset,last_record_sha256,revision)
            values('synthetic-vpn-load','load-stream','load-transport',%s,'load-generation',1,repeat('d',64),1)""", (epoch,))
        cur.execute("""insert into acquisition_consumer_subscriptions(subscription_id,source_instance_id,
            stream_id,transport_binding,consumer_id,consumer_component_id,consumer_component_version,
            routing_contract_id,consumer_contract_version,replay_policy,resource_profile_id,
            selector_json,selector_sha256,authority_mode,partition_key)
            values('synthetic-vpn-load-sub','synthetic-vpn-load','load-stream','load-transport',
            'sli.windows.vpn-radius','radius-session-observation','1.0.0','load-route','1.0.0','no_replay',
            'load-profile','{}',repeat('e',64),'authoritative','load-partition')""")
        cur.execute("""insert into core_evidence_manifests(evidence_uid,source_instance_id,stream_id,
            transport_binding,cursor_epoch,file_generation,cursor_start_byte_offset,batch_record_ordinal,
            canonical_record_sha256,object_reference,object_sha256,object_size_bytes,verified_at_utc)
            values(%s,'synthetic-vpn-load','load-stream','load-transport',%s,'load-generation',0,1,
            repeat('a',64),'evidence:synthetic-load',repeat('b',64),1,%s)""", (evidence, epoch, START))
        cur.execute("""insert into radius_accounting_session_observations(observation_id,evidence_uid,
            lifecycle_event,identity_state,timestamp_state,session_confirmed_by_accounting,
            producer_contract_id,resource_groups,row_sensitivity,field_categories,
            evidence_access_requirement,label_policy_version,provenance_json)
            values(%s,%s,'start','unresolved','unresolved',true,'synthetic-load',
            '{vpn.sessions}','restricted','{fixture}','vpn.session.evidence.read','1','{}')""", (observation, evidence))
        cur.execute("""insert into acquisition_delivery_outbox(subscription_id,evidence_uid,observation_id,
            idempotency_key,delivery_state,delivered_at) values('synthetic-vpn-load-sub',%s,%s,
            repeat('f',64),'delivered',%s) returning delivery_id""", (evidence, observation, START))
        delivery_id = cur.fetchone()["delivery_id"]
        cur.execute("""insert into radius_session_projection_receipts(delivery_id,observation_id,outcome,
            projected_row_count,consumer_contract_id) values(%s,%s,'identity_unresolved',0,'sli.radius-session-consumer.v1')""",
            (delivery_id, observation))
        cur.execute("""insert into radius_vpn_session_projection(session_row_id,session_identity_key,exact_principal_key,
            generation,lifecycle_state,completeness,started_at_utc,stopped_at_utc,last_observed_at_utc,
            duration_seconds,observation_count,read_model_contract_id)
            select 'radius-session-row:'||lpad(to_hex(i),64,'0'),'radius-session:'||lpad(to_hex(i),64,'0'),
                'entity:'||(98000001+((i-1) %% 600)/2),1,'closed','complete',
                %s::timestamptz+((i-1)/600)*interval '1 day'+((i-1) %% 2)*interval '30 minutes',
                %s::timestamptz+((i-1)/600)*interval '1 day'+((i-1) %% 2)*interval '30 minutes'+interval '1 hour',
                %s::timestamptz+((i-1)/600)*interval '1 day'+((i-1) %% 2)*interval '30 minutes'+interval '1 hour',
                3600,2,'synthetic-load-v1' from generate_series(1,54000) i""", (START, START, START))
        for offset, server_id, codes in ((90000000, ids["server_id"], [6272, 6273]), (91000000, dc_id, [4624, 4625])):
            cur.execute("""insert into events_v2_core(id,server_id,domain_id,log_source_id,event_record_id,event_id,
                provider_id,channel_id,time_created_utc,subject_user_sid,target_user_sid,ip_address,
                normalized_at,normalized_hash,source_core_sha256)
                select %s+i,%s,%s,1,%s+i,(%s::integer[])[1+(i %% 2)],%s,%s,
                    %s::timestamptz+((i-1)/1200)*interval '1 day'+((i-1) %% 1200)*interval '60 seconds',
                    'S-1-5-21-100-'||(2001+(i %% 300)), 'S-1-5-21-100-'||(2001+(i %% 300)),
                    '198.51.100.'||(1+(i %% 200)),now(),decode(repeat('ab',32),'hex'),decode(repeat('cd',32),'hex')
                from generate_series(1,108000) i""",
                (offset, server_id, ids["domain_id"], offset, codes, ids["provider_id"], ids["channel_id"], START))
        cur.execute("analyze events_v2_core")
        cur.execute("analyze radius_vpn_session_projection")
        cur.execute("analyze entities_v2")
    return ids


def request(domain_id, days, tab):
    from server.api.http_server import RequestHandler
    from server.api.routes import reports_v2
    sent = []
    handler = object.__new__(RequestHandler)
    handler.path = "/api/v2/reports/vpn.connections/data"
    handler._admit_request = lambda: True
    handler._access_decision = lambda: ACCESS
    handler._send_json = lambda payload, status=200: sent.append((payload, int(status)))
    handler.server = SimpleNamespace(request_slots=SimpleNamespace(release=Mock()))
    query = {"domain": [str(domain_id)], "period": ["custom"], "from": [START.isoformat()],
             "to": [(START + timedelta(days=days)).isoformat()], "tab": [tab]}
    handler._do_GET = lambda: reports_v2.try_handle_get(handler, handler.path, query)
    started = monotonic()
    handler.do_GET()
    elapsed = monotonic() - started
    assert len(sent) == 1
    return *sent[0], elapsed


def _native_plan_summary(plan):
    """Bounded structural evidence only: never print SQL, filters or parameters."""
    document = plan[0]
    pending = [("0", document["Plan"])]
    nodes = []
    while pending and len(nodes) < 32:
        path, node = pending.pop()
        summary = {"path": path}
        for key in ("Node Type", "Relation Name", "Index Name"):
            if key in node:
                summary[key] = str(node[key])[:128]
        for key in ("Plan Rows", "Actual Rows", "Actual Loops", "Actual Total Time",
                    "Shared Hit Blocks", "Shared Read Blocks", "Temp Read Blocks", "Temp Written Blocks"):
            if key in node:
                summary[key] = node[key]
        nodes.append(summary)
        pending.extend((f"{path}.{index}", child) for index, child in reversed(list(enumerate(node.get("Plans", [])))))
    return {"planning_ms": document.get("Planning Time"), "execution_ms": document.get("Execution Time"),
            "nodes": nodes, "truncated": bool(pending)}


@pytest.fixture
def nps_query_plans(generated_vpn_data, monkeypatch, record_property, capsys, days):
    """Attach native plans for the changed NPS reads, outside the HTTP budget."""
    import psycopg
    original_connect = psycopg.connect
    statements = []

    class CaptureCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            if isinstance(query, str) and (
                query.startswith("with selected_events") or "window_success_6272_count" in query
            ):
                statements.append((query, params))
            return super().execute(query, params, **kwargs)

    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: original_connect(
        *args, **{**kwargs, "cursor_factory": CaptureCursor}))
    yield
    with original_connect(os.environ["ADLOG_TEST_PG_DSN"]) as conn:
        assert_disposable_database(conn)
        conn.execute("set transaction read only")
        conn.execute("set local statement_timeout='8s'")
        seen = set()
        for query, params in statements:
            identity = (query, repr(params))
            if identity in seen:
                continue
            seen.add(identity)
            plan = conn.execute("explain (analyze, buffers, format json) " + query, params).fetchone()[0]
            record_property(f"nps_native_plan_{len(seen)}", json.dumps(plan))
            with capsys.disabled():
                print("T042_NATIVE_PLAN " + json.dumps({"days": days, "query_number": len(seen),
                    "query_kind": "selected_events" if query.startswith("with selected_events") else "window_counts",
                    **_native_plan_summary(plan)}, sort_keys=True), flush=True)
        assert seen, "the real changed SQL must execute before plan evidence is recorded"


@pytest.mark.parametrize("days", [30, 90])
def test_all_five_sections_on_generated_postgresql_volume(generated_vpn_data, nps_query_plans, monkeypatch, days, record_property, capsys):
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    for tab, branch in (("session_overlap", "accounting"), ("failed", "nps"),
                        ("authorizations", "nps"), ("windows", "windows"), ("windows_heatmap", "windows_heatmap")):
        payload, status, elapsed = request(generated_vpn_data["domain_id"], days, tab)
        record_property(f"vpn_{tab}_{days}d_seconds", elapsed)
        with capsys.disabled():
            print("T042_NATIVE_TIMING " + json.dumps({"days": days, "tab": tab,
                "elapsed_seconds": elapsed, "http_status": status}, sort_keys=True), flush=True)
        assert status == 200, payload
        assert payload["branches"][branch]["state"] in {"ok", "partial"}, payload
        assert payload["collections"][tab], (tab, payload)
        assert payload["window"]["from_utc"].startswith("2026-01-01")
        if tab == "failed":
            assert {row["event_id"] for row in payload["collections"][tab]} == {6273}
        if tab in {"failed", "authorizations"}:
            assert len(payload["collections"][tab]) == 2000
            assert payload["branches"]["nps"]["state"] == "partial"
        if tab == "windows_heatmap":
            assert sum(row["failures"] for row in payload["collections"][tab]) == days * 600


def test_native_statement_cancellation_keeps_nps_rows_and_http_200(generated_vpn_data, monkeypatch):
    import psycopg
    original_connect = psycopg.connect
    canceled = []

    class CancelCoverageCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            if isinstance(query, str) and "window_success_6272_count" in query and not canceled:
                canceled.append(True)
                super().execute("set local statement_timeout='1ms'")
                super().execute("select pg_sleep(0.02)")
            return super().execute(query, params, **kwargs)

    def connect(*args, **kwargs):
        return original_connect(*args, **{**kwargs, "cursor_factory": CancelCoverageCursor})

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    payload, status, _elapsed = request(generated_vpn_data["domain_id"], 90, "authorizations")
    assert canceled and status == 200
    assert payload["state"] == "partial"
    assert payload["collections"]["authorizations"]
    assert payload["branches"]["nps"]["reason"] == "source_read_timeout"


def test_windows_policy_native_timeout_preserves_fetched_facts(generated_vpn_data, monkeypatch):
    from server.sli.reports import windows_authentication_reporting as windows

    def slow_policy(cursor, *_args):
        cursor.execute("set local statement_timeout='1ms'")
        cursor.execute("select pg_sleep(0.02)")

    monkeypatch.setattr(windows, "_read_manual_review_policy", slow_policy)
    payload, status, _elapsed = request(generated_vpn_data["domain_id"], 90, "windows")
    assert status == 200 and payload["state"] == "partial"
    assert payload["collections"]["windows"]
    assert payload["branches"]["windows"]["reason"] == "source_read_timeout"


def test_native_idle_watchdog_cannot_allow_policy_sql_after_eight_second_deadline(generated_vpn_data, monkeypatch):
    """Real PostgreSQL connection cancellation while idle must not buy a new read."""
    import time
    import psycopg
    from server.sli.core import platform_settings
    from server.sli.reporting.read_timeout import remaining_read_ms
    from server.sli.reports import windows_authentication_reporting as windows

    original_connect = psycopg.connect
    original_get_setting = windows.get_setting
    delayed = []
    policy_statements = []

    class CapturePolicyCursor(psycopg.Cursor):
        def execute(self, query, params=None, **kwargs):
            if isinstance(query, str) and "select event.id, event.time_created_utc as at" in query:
                policy_statements.append(query)
            return super().execute(query, params, **kwargs)

    def delayed_setting(key):
        if not delayed:
            delayed.append(key)
            # Let the real outer watchdog fire while the primary connection is
            # idle, then exercise the real _stored_row timeout/default fallback.
            time.sleep(remaining_read_ms() / 1000 + 0.05)
        return original_get_setting(key)

    platform_settings.clear_cache()
    monkeypatch.setenv("ADLOG_REPORT_READ_TIMEOUT_MS", "8000")
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: original_connect(
        *args, **{**kwargs, "cursor_factory": CapturePolicyCursor}))
    monkeypatch.setattr(windows, "get_setting", delayed_setting)
    payload, status, elapsed = request(generated_vpn_data["domain_id"], 90, "windows")
    assert delayed and status == 200 and payload["state"] == "partial"
    assert elapsed < 8.5
    assert payload["collections"]["windows"]
    assert payload["branches"]["windows"]["reason"] == "source_read_timeout"
    assert policy_statements == [], "no SELECT may start after the idle watchdog's deadline"
    platform_settings.clear_cache()
