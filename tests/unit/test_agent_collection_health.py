"""Agent readiness uses synthetic policies/queue clocks, without a database."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from psycopg.errors import InsufficientPrivilege, QueryCanceled

from server.sli.agents import collection_health as health

NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"


def agent(**updates):
    return {"id": AGENT, "host_id": HOST, "instance_name": "fixture-agent", "status": "active",
            "domain": "example.test", "last_seen": NOW, "last_packet_at": NOW,
            "created_at": NOW - timedelta(days=3), "policy_applied_at": NOW - timedelta(days=2),
            "policy_revision": 1, "applied_policy_revision": 1, "applied_collection_state": "active",
            "collection_policy": {"state": "active", "interval_seconds": 60},
            "assigned_modules": [{"module_id": "sli.windows.ad-dc", "enabled": True,
                                  "config": {"channels": {"Security": True, "System": False, "Directory Service": False}}}],
            **updates}


def stream(**updates):
    return {"agent_id": AGENT, "module_id": "sli.windows.ad-dc", "revision": "1", "channel": "Security",
            "last_packet_at": NOW - timedelta(seconds=60), "last_import_at": NOW - timedelta(seconds=30),
            "pending_since": None, "read_error": False, **updates}


def view(agents=None, streams=None):
    return health.collection_health_view(agents or [agent()], streams or [], now=NOW)


def test_empty_packets_confirm_collection_independently_of_event_age():
    result = view(streams=[stream()])
    assert result["state"] == "current"
    item = result["items"][0]
    assert item["connection"] == "online"
    assert item["domains"] == ["example.test"]
    assert item["modules"][0]["channels"][0]["state"] == "current"
    assert item["modules"][0]["channels"][0]["import_lag_seconds"] == 30
    assert "agent_id=" + AGENT in item["href"]
    assert item["href"].endswith("#agent-" + AGENT)


def test_only_assigned_current_revisions_are_requested():
    assignments = [
        {"module_id": "sli.windows.ad-dc", "enabled": True, "config": {
            "policy_revision": "4", "channels": {"Security": True, "System": False, "Directory Service": False}}},
        {"module_id": "sli.ad-snapshot", "enabled": True, "config": {"policy_revision": "5"}},
        {"module_id": "sli.file-audit", "enabled": False},
    ]
    assert health._requested_streams([agent(assigned_modules=assignments)]) == [
        {"agent_id": AGENT, "module_id": "sli.windows.ad-dc", "revision": "4", "channel": "Security", "snapshot": False},
        {"agent_id": AGENT, "module_id": "sli.ad-snapshot", "revision": "5", "channel": None, "snapshot": True},
    ]


def test_registration_name_is_display_metadata_when_ad_enrollment_is_absent():
    item = view(agents=[agent(instance_name=None, registration_host_name="fixture-host.example.test")])["items"][0]
    assert item["name"] == "fixture-host.example.test"
    assert view(agents=[agent(instance_name=None, registration_host_name=HOST)])["items"][0]["name"] == ""


def test_setup_uses_server_module_binding_when_optional_source_label_is_absent():
    bindings = health._setup_source_bindings([agent(source_bindings=[
        {"module_id": "sli.windows.ad-dc", "source_name": "fixture-dc"}])])
    assert bindings[0]["source_name"] == "fixture-dc" and bindings[0]["enabled"] is True


def test_collection_name_uses_enrolled_hostname_and_preserves_instance():
    assignment = agent()["assigned_modules"][0]
    assignment["config"]["source_name"] = "fixture-policy-name"
    item = view(agents=[agent(host_name="fixture-host.example.test", assigned_modules=[assignment])])["items"][0]
    assert item["name"] == "fixture-host.example.test · fixture-agent"
    assert HOST not in item["name"]
    assert item["domains"] == ["example.test"]


@pytest.mark.parametrize("source,expected", [
    ("fixture-dc", "fixture-dc · fixture-agent"), (HOST, "fixture-agent"),
])
def test_dc_policy_name_is_used_without_exposing_host_uuid(source, expected):
    assignment = agent()["assigned_modules"][0]
    assignment["config"]["source_name"] = source
    item = view(agents=[agent(assigned_modules=[assignment])])["items"][0]
    assert item["name"] == expected


def test_missing_host_metadata_does_not_turn_uuid_into_a_name():
    item = view(agents=[agent(instance_name=None)])["items"][0]
    assert item["name"] == ""
    assert item["host_id"] == HOST


def test_enrolled_host_metadata_is_projected_by_bounded_read(monkeypatch):
    def read(sql, params=(), **kwargs):
        assert kwargs == {"statement_timeout_ms": 3000, **({"jit": False} if sql == health._STREAMS_SQL else {})}
        if sql == health._AGENTS_SQL:
            assert "sli_agent_group_approval_links" in sql
            assert "v.id=r.computer_version_id" in sql
            return [agent(host_name="fixture-host.example.test")]
        assert sql == health._STREAMS_SQL
        return []
    monkeypatch.setattr(health, "query_rows_bounded", read)
    assert health.get_agent_collection_health()["items"][0]["name"] == "fixture-host.example.test · fixture-agent"


@pytest.mark.parametrize("change", [
    {"pending_since": NOW - timedelta(seconds=901)},
    {"last_packet_at": NOW - timedelta(seconds=901)}, {"read_error": True},
])
def test_enabled_channel_fails_for_real_data_or_import_failure(change):
    result = view(streams=[stream(**change)])
    assert result["state"] == result["items"][0]["state"] == "error"


@pytest.mark.parametrize("change,reason", [
    ({"pending_since": NOW - timedelta(days=8)}, "import_overdue"),
    ({"last_packet_at": NOW - timedelta(seconds=901)}, "packet_stale"),
    ({"last_packet_at": None}, "packet_missing"),
    ({"read_error": True, "pending_since": NOW - timedelta(days=8)}, "read_error"),
    ({}, None),
    ({"pending_since": NOW - timedelta(seconds=30)}, None),
])
def test_failure_reason_distinguishes_old_import_backlog_from_missing_packets(change, reason):
    result = view(streams=[stream(**change)])
    check = result["items"][0]["modules"][0]["channels"][0]
    assert check["failure_reason"] == reason
    if reason == "import_overdue":
        assert result["state"] == "error"
        assert result["items"][0]["connection"] == "online"
        assert check["last_import_at"] is not None
        assert check["last_packet_at"] is not None
        assert check["import_lag_seconds"] == 8 * 86400


def test_paused_channel_does_not_report_an_import_failure_reason():
    result = view(agents=[agent(collection_policy={"state": "paused"})],
                  streams=[stream(pending_since=NOW - timedelta(days=8))])
    check = result["items"][0]["modules"][0]["channels"][0]
    assert check["state"] == "paused" and check["failure_reason"] is None


@pytest.mark.parametrize("change,agent_change,expected_since", [
    ({"pending_since": NOW - timedelta(seconds=901)}, {}, "2026-10-10T11:59:59+00:00"),
    ({"last_packet_at": NOW - timedelta(seconds=901)}, {}, "2026-10-10T11:59:59+00:00"),
    ({"last_packet_at": None}, {}, "2026-10-08T12:15:00+00:00"),
    ({"last_packet_at": None}, {"policy_applied_at": None}, "2026-10-07T12:15:00+00:00"),
    ({"last_packet_at": NOW - timedelta(seconds=2000)},
     {"policy_applied_at": NOW - timedelta(seconds=1000)}, "2026-10-10T11:58:20+00:00"),
    ({"last_packet_at": NOW - timedelta(seconds=901)},
     {"policy_applied_at": None, "created_at": None}, "2026-10-10T11:59:59+00:00"),
    ({"last_import_at": NOW - timedelta(seconds=901)}, {}, "2026-10-10T11:59:59+00:00"),
    ({"pending_since": "2026-10-10T14:44:59+03:00"}, {}, "2026-10-10T11:59:59+00:00"),
    ({"pending_since": NOW - timedelta(seconds=2000)},
     {"applied_policy_revision": 0, "last_seen": None, "policy_applied_at": NOW - timedelta(seconds=1000)},
     "2026-10-10T11:58:20+00:00"),
])
def test_issue_since_dates_current_overdue_condition_not_contact_or_import(change, agent_change, expected_since):
    result = view(agents=[agent(**agent_change)], streams=[stream(**change)])
    check = result["items"][0]["modules"][0]["channels"][0]
    assert check["state"] == "error"
    assert check["issue_since_utc"] == expected_since
    assert check["issue_observed_at_utc"] == "2026-10-10T12:00:00+00:00"
    assert check["issue_since_utc"] not in (result["items"][0]["last_seen"], check["last_import_at"])


@pytest.mark.parametrize("packet_at,expected_observation", [
    (NOW - timedelta(seconds=60), "2026-10-10T11:59:00+00:00"),
    (None, None),
    (NOW + timedelta(seconds=60), None),
])
def test_read_error_receipt_is_observation_not_failure_start(packet_at, expected_observation):
    check = view(streams=[stream(read_error=True, last_packet_at=packet_at,
                                pending_since=NOW - timedelta(days=8))])["items"][0]["modules"][0]["channels"][0]
    assert check["failure_reason"] == "read_error"
    assert check["issue_since_utc"] is None
    assert check["issue_observed_at_utc"] == expected_observation


@pytest.mark.parametrize("agent_change,change,diagnostics_available", [
    ({"status": "disabled"}, {"read_error": True}, True),
    ({"collection_policy": {"state": "paused"}}, {"read_error": True}, True),
    ({}, {"read_error": True}, False),
    ({}, {}, True),
    ({}, {"pending_since": NOW - timedelta(seconds=900)}, True),
    ({}, {"last_packet_at": NOW - timedelta(seconds=900)}, True),
    ({}, {"last_import_at": None}, True),
    ({"applied_policy_revision": 0}, {"read_error": True}, True),
    ({"policy_applied_at": NOW}, {"last_packet_at": None}, True),
    ({"policy_applied_at": None, "created_at": None}, {"last_packet_at": None}, True),
])
def test_non_failure_states_have_no_issue_dates(agent_change, change, diagnostics_available):
    result = health.collection_health_view([agent(**agent_change)], [stream(**change)],
                                          now=NOW, diagnostics_available=diagnostics_available)
    check = result["items"][0]["modules"][0]["channels"][0]
    assert check["state"] != "error"
    assert check["issue_since_utc"] is None
    assert check["issue_observed_at_utc"] is None


@pytest.mark.parametrize("module", ["sli.ad-snapshot", "sli.gpo-snapshot"])
def test_snapshot_pending_deadline_includes_capture_allowance(module):
    assignment = {"module_id": module, "enabled": True,
                  "config": {"schedule": {"hours": [6, 18]}, "capture_seconds": 3600}}
    check = view(agents=[agent(assigned_modules=[assignment])], streams=[
        stream(module_id=module, channel=None, pending_since=NOW - timedelta(seconds=4501))
    ])["items"][0]["modules"][0]["channels"][0]
    assert check["failure_reason"] == "import_overdue"
    assert check["issue_since_utc"] == "2026-10-10T11:59:59+00:00"
    assert check["issue_observed_at_utc"] == "2026-10-10T12:00:00+00:00"


def test_recent_queue_is_waiting_and_unknown_import_is_not_success():
    result = view(streams=[stream(pending_since=NOW - timedelta(seconds=30), last_import_at=None)])
    assert result["items"][0]["state"] == "lagging"
    assert result["items"][0]["modules"][0]["channels"][0]["import_lag_seconds"] == 30
    assert view(streams=[stream(last_import_at=None)])["items"][0]["state"] == "unknown"


@pytest.mark.parametrize("change,state", [
    ({"status": "disabled"}, "disabled"),
    ({"collection_policy": {"state": "paused"}}, "paused"),
    ({"collection_policy": {"state": "drain"}}, "paused"),
    ({"applied_policy_revision": 0}, "waiting"),
    ({"applied_collection_state": "paused"}, "waiting"),
    ({"policy_applied_at": NOW}, "waiting"),
    ({"assigned_modules": []}, "waiting"),
])
def test_paused_disabled_or_unapplied_agents_do_not_raise_broken_banner(change, state):
    result = view(agents=[agent(**change)])
    assert result["items"][0]["state"] == state
    assert result["state"] != "error"


def test_heartbeat_contact_does_not_hide_missing_channel_or_old_policy_packets():
    assert view()["state"] == "error"
    assert view(streams=[stream(revision="0")])["state"] == "error"
    assignment = agent()["assigned_modules"][0]
    assignment["config"]["channels"]["System"] = True
    result = view(agents=[agent(assigned_modules=[assignment])], streams=[stream()])
    assert [check["state"] for check in result["items"][0]["modules"][0]["channels"]] == ["current", "error"]


def test_offline_agent_cannot_hide_missing_data_behind_unapplied_policy():
    result = view(agents=[agent(last_seen=None, applied_policy_revision=0)])
    assert result["items"][0]["connection"] == "never_seen"
    assert result["state"] == "error"


def test_all_channels_disabled_do_not_expect_data():
    assignment = agent()["assigned_modules"][0]
    assignment["config"]["channels"]["Security"] = False
    result = view(agents=[agent(assigned_modules=[assignment])])
    assert result["items"][0]["modules"][0]["channels"] == []
    assert result["state"] != "error"


@pytest.mark.parametrize("module,family,channel", [
    ("sli.vpn-nps", "nps", "Security"),
    ("sli.radius-accounting", "radius_accounting", "radius-accounting"),
])
@pytest.mark.parametrize("explicit_family", [False, True])
def test_enabled_nps_policy_reports_current_channel(module, family, channel, explicit_family):
    settings = {"families": {family: True}} if explicit_family else {}
    assignment = {"module_id": module, "enabled": True, "config": settings}
    result = view(agents=[agent(assigned_modules=[assignment])], streams=[
        stream(module_id=module, channel=channel)])
    assert result["state"] == result["items"][0]["state"] == "current"
    checks = result["items"][0]["modules"][0]["channels"]
    assert [check["channel"] for check in checks] == [channel]
    assert [check["state"] for check in checks] == ["current"]


@pytest.mark.parametrize("module,family,channel", [
    ("sli.vpn-nps", "nps", "Security"),
    ("sli.radius-accounting", "radius_accounting", "radius-accounting"),
])
@pytest.mark.parametrize("paused,state", [(True, "paused"), (False, None)])
def test_inactive_nps_policy_does_not_break_healthy_agent(module, family, channel, paused, state):
    settings = {"paused": True} if paused else {"families": {family: False}}
    assignment = {"module_id": module, "enabled": True, "config": settings}
    result = view(agents=[agent(assigned_modules=[*agent()["assigned_modules"], assignment])], streams=[stream()])
    assert result["state"] == result["items"][0]["state"] == "current"
    checks = result["items"][0]["modules"][1]["channels"]
    assert [check["channel"] for check in checks] == ([channel] if state else [])
    assert [check["state"] for check in checks] == ([state] if state else [])


def test_workstation_channels_follow_enabled_policy_families():
    assignment = {"module_id": "sli.workstations", "enabled": True, "config": {
        "families": {"logons": True, "processes": False, "usb": False, "local_admins": False, "protection": False}}}
    result = view(agents=[agent(assigned_modules=[assignment])])
    assert [check["channel"] for check in result["items"][0]["modules"][0]["channels"]] == ["Security"]


@pytest.mark.parametrize("module", ["sli.ad-snapshot", "sli.gpo-snapshot"])
def test_snapshot_import_uses_schedule_and_publication_clock(module):
    assignment = {"module_id": module, "enabled": True, "config": {
        "domain_dns": "snapshot.example.test", "schedule": {"hours": [6, 18]}, "capture_seconds": 3600}}
    snapshot = stream(module_id=module, channel=None, last_packet_at=NOW - timedelta(hours=6))
    result = view(agents=[agent(domain=None, assigned_modules=[assignment])], streams=[snapshot])
    assert result["state"] == "current"
    assert result["items"][0]["domains"] == ["snapshot.example.test"]
    snapshot.update(last_import_at=None, pending_since=NOW - timedelta(seconds=1000))
    assert view(agents=[agent(assigned_modules=[assignment])], streams=[snapshot])["state"] != "error"
    snapshot["pending_since"] = NOW - timedelta(hours=2)
    assert view(agents=[agent(assigned_modules=[assignment])], streams=[snapshot])["state"] == "error"


def test_all_registered_agents_are_grouped_without_legacy_inventory_or_truncation():
    agents = [agent(id=f"00000000-0000-4000-8000-{n:012d}", domain="b.example.test") for n in range(1, 105)]
    agents.append(agent(id="00000000-0000-4000-9000-000000000001", domain="a.example.test"))
    result = view(agents=agents)
    assert len(result["items"]) == result["active_agents"] == 105
    assert result["items"][0]["domains"] == ["a.example.test"]
    assert "assigned_modules" not in result["items"][0]


def test_read_failure_is_unavailable_and_exposes_no_exception(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-private-message")
    monkeypatch.setattr(health, "query_rows_bounded", fail)
    result = health.get_agent_collection_health()
    assert result["state"] == "unavailable"
    assert "synthetic-private-message" not in str(result)


def test_read_uses_bounded_queries_and_empty_inventory_skips_queue_scan(monkeypatch):
    calls = []
    def read(sql, params=(), **kwargs):
        calls.append((sql, kwargs))
        return []
    monkeypatch.setattr(health, "query_rows_bounded", read)
    assert health.get_agent_collection_health()["state"] == "unknown"
    assert len(calls) == 1
    assert calls[0][1] == {"statement_timeout_ms": 3000}


def test_bounded_read_keeps_old_pending_imports_with_latest_healthy_packets(monkeypatch):
    calls = []

    def read(sql, params=(), **kwargs):
        calls.append(sql)
        assert kwargs == {"statement_timeout_ms": 3000, **({"jit": False} if sql == health._STREAMS_SQL else {})}
        if sql == health._AGENTS_SQL:
            return [agent()]
        # Historical pending imports remain visible even when the latest packet
        # is healthy. Select its error flag in the same aggregate, without a
        # second history materialization/window and nullable-channel join.
        assert "latest.collection_read_error" in sql
        assert "array_agg" not in sql
        assert "min(r.received_at) filter(where historical.packet_id is null)" in sql
        assert "r.agent_id=wanted.agent_id and r.module_id=wanted.module_id" in sql
        assert "jsonb_to_recordset(?::jsonb)" in sql and "row_number" not in sql
        assert "interval '7 days'" in sql
        return [stream(last_packet_at=datetime.now(timezone.utc),
                       pending_since=datetime.now(timezone.utc) - timedelta(days=2))]

    monkeypatch.setattr(health, "query_rows_bounded", read)
    result = health.get_agent_collection_health()
    assert calls == [health._AGENTS_SQL, health._STREAMS_SQL]
    assert result["state"] == "error"
    assert result["items"][0]["modules"][0]["channels"][0]["import_lag_seconds"] >= 2 * 86400


def test_health_reads_compact_packet_metadata_without_decoding_history(monkeypatch):
    def read(sql, params=(), **kwargs):
        assert kwargs == {"statement_timeout_ms": 3000, **({"jit": False} if sql == health._STREAMS_SQL else {})}
        if sql == health._AGENTS_SQL:
            assert "order by received_at desc limit 1" in sql
            return [agent()]
        assert "i.collection_revision=wanted.revision" in sql
        assert "i.collection_channel is not distinct from wanted.channel" in sql
        assert "latest.collection_read_error" in sql
        assert "i.packet->" not in sql and "r.envelope->" not in sql
        assert "where i.imported_at is null" in sql
        assert "order by r.received_at desc,r.sequence desc limit 1" in sql
        assert "payload.packet#>" in sql
        return [stream(last_packet_at=datetime.now(timezone.utc), read_error=True)]

    monkeypatch.setattr(health, "query_rows_bounded", read)
    assert health.get_agent_collection_health()["state"] == "error"


@pytest.mark.parametrize("config", [{"paused": True}, {"families": {"nps": False}}])
def test_readiness_api_does_not_call_retired_collector(monkeypatch, config):
    from server.api.routes import operations
    from server.sli.reporting import ui_operations

    for name in ("get_collector_health", "get_collection_runtime_status"):
        monkeypatch.setattr(ui_operations, name, lambda: pytest.fail("retired collector must not be read"))
    monkeypatch.setattr(ui_operations, "get_postgres_operations_status", lambda **kwargs: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_operations_storage_summary", lambda postgres: {"status": "ok"})
    monkeypatch.setattr(ui_operations, "get_runtime_workers_overview", lambda: {"items": [
        {"worker_name": "collection", "status": "failed"}, {"worker_name": "agent_import", "state": "active"}]})
    assignment = {"module_id": "sli.vpn-nps", "enabled": True, "config": config}
    monkeypatch.setattr(ui_operations, "get_agent_collection_health", lambda: view(
        agents=[agent(assigned_modules=[*agent()["assigned_modules"], assignment])], streams=[stream()]))
    responses = []
    handler = SimpleNamespace(_send_json=responses.append)
    assert operations.try_handle_get(handler, "/api/v1/operations/overview", {"view": ["readiness"]})
    assert responses[0]["agent_collection"]["state"] == "current"
    assert [item["worker_name"] for item in responses[0]["workers"]["items"]] == ["agent_import"]
    assert not {"collector_health", "collection", "collection_progress"} & responses[0].keys()


@pytest.mark.parametrize("change", [
    {}, {"pending_since": NOW - timedelta(seconds=901)}, {"read_error": True},
])
def test_shell_api_serializes_same_agent_collection_contract(monkeypatch, change):
    from server.api.routes import workspace

    result = view(streams=[stream(**change)])
    monkeypatch.setattr(workspace, "get_agent_collection_health", lambda: result)
    monkeypatch.setattr(workspace, "get_overview_workspace_data", lambda **kwargs: pytest.fail("legacy snapshot must not be read"))
    responses = []
    handler = SimpleNamespace(_send_json=responses.append, storage_route_authorization=None)
    workspace._handle_v1_overview_api(handler, {"view": ["agents"]})
    assert responses[0]["agent_collection"] == result
    assert not {"sources", "collection_progress", "collection_freshness"} & responses[0].keys()


def test_historical_conflicts_are_visible_without_blocking_fresh_imports():
    result = view(streams=[stream(historical_unimported_packets=12, historical_error_at=NOW - timedelta(days=8))])
    assert result["state"] == "current"
    check = result["items"][0]["modules"][0]["channels"][0]
    assert check["historical_unimported_packets"] == 12
    assert check["historical_error_at"] == (NOW - timedelta(days=8)).isoformat()
    assert check["failure_reason"] is None


@pytest.mark.parametrize("change,reason", [
    ({"pending_since": NOW - timedelta(seconds=901)}, "import_overdue"),
    ({"last_import_at": NOW - timedelta(days=8)}, "import_overdue"),
    ({"last_packet_at": NOW - timedelta(days=8)}, "packet_stale"),
    ({"read_error": True}, "read_error"),
])
def test_historical_conflicts_do_not_hide_live_failures(change, reason):
    check = view(streams=[stream(historical_unimported_packets=12, **change)])["items"][0]["modules"][0]["channels"][0]
    assert check["state"] == "error"
    assert check["failure_reason"] == reason


def test_only_old_terminal_quarantine_is_excluded_from_pending_queue():
    sql = health._STREAMS_SQL
    assert "historical.reason_code in ('source_event_allocation_hash_mismatch','published_source_event_hash_mismatch')" in sql
    assert "r.received_at < now() - interval '7 days'" in sql
    assert "where i.imported_at is null" in sql and "filter(where historical.packet_id is null)" in sql
    assert "count(*) filter(where historical.packet_id is not null)" in sql
    assert "min(historical.quarantined_at)" in sql
    assert "left join sli_agent_packet_quarantine historical on historical.packet_id=r.packet_id" in sql


def test_current_delivery_preserves_known_historical_packet_loss():
    gap_at=NOW-timedelta(days=30)
    result=view(agents=[agent(last_accepted_gap_at=gap_at)],streams=[stream()])
    assert result['state']=='current'
    assert result['items'][0]['completeness']=={'state':'known_gaps','last_accepted_gap_at':gap_at.isoformat()}
    assert result['completeness']['state']=='known_gaps'


def test_no_recorded_loss_does_not_prove_completeness():
    result=view(streams=[stream()])
    assert result['items'][0]['completeness']=={'state':'not_assessed','last_accepted_gap_at':None}
    assert result['completeness']['state']=='not_assessed'


def test_disabled_agent_loss_remains_visible():
    result=view(agents=[agent(status='disabled',last_accepted_gap_at=NOW)])
    assert result['state']=='unknown'
    assert result['completeness']['state']=='known_gaps'


def test_loss_projection_uses_only_accepted_journal_and_bounded_latest():
    assert "action='sequence_gap_accepted'" in health._AGENTS_SQL
    assert "gap.occurred_at as last_accepted_gap_at" in health._AGENTS_SQL
    assert "action='sequence_gap_authorized'" not in health._AGENTS_SQL
    assert 'order by id desc limit 1\n) gap on true' in health._AGENTS_SQL



@pytest.mark.parametrize("error,reason", [
    (TimeoutError("synthetic-private-detail"), "timeout"),
    (health.QueryTimeoutError("synthetic-private-detail", timeout_ms=3000, cancelled=True), "timeout"),
    (QueryCanceled("synthetic-private-detail"), "timeout"),
    (InsufficientPrivilege("synthetic-private-detail"), "read_failed"),
    (RuntimeError("synthetic-private-detail"), "read_failed"),
])
def test_stream_failure_preserves_registry_evidence_without_claiming_collection(monkeypatch, error, reason):
    def read(sql, params=(), **kwargs):
        if sql == health._AGENTS_SQL:
            return [agent(last_accepted_gap_at=NOW)]
        raise error
    monkeypatch.setattr(health, "query_rows_bounded", read)
    result = health.get_agent_collection_health()
    assert result["state"] == "partial"
    assert result["diagnostics"] == {"state": "unavailable", "reason": reason}
    assert result["current_agents"] == 0
    item = result["items"][0]
    assert item["state"] == "unknown"
    expected_contact = health.collection_health_view(
        [agent(last_accepted_gap_at=NOW)], [], now=datetime.fromisoformat(result["checked_at_utc"])
    )["items"][0]["connection"]
    assert item["connection"] == expected_contact
    assert item["last_seen"] == NOW.isoformat()
    assert item["last_packet_at"] == NOW.isoformat()
    assert item["completeness"]["state"] == "known_gaps"
    assert item["modules"][0]["channels"][0]["state"] == "unknown"
    assert item["modules"][0]["channels"][0]["failure_reason"] is None
    assert "historical_unimported_packets" not in item["modules"][0]["channels"][0]
    assert "synthetic-private-detail" not in str(result)


def test_stream_authorization_denial_does_not_return_registry_fallback(monkeypatch):
    def read(sql, params=(), **kwargs):
        if sql == health._AGENTS_SQL:
            return [agent()]
        raise PermissionError("synthetic-private-detail")
    monkeypatch.setattr(health, "query_rows_bounded", read)
    result = health.get_agent_collection_health()
    assert result["state"] == "unavailable"
    assert result["items"] == []


def test_projection_failure_is_atomic_and_does_not_return_partial_agents(monkeypatch):
    monkeypatch.setattr(health, "query_rows_bounded", lambda sql, params=(), **kwargs:
                        [agent(), {"id": "invalid"}] if sql == health._AGENTS_SQL else [])
    result = health.get_agent_collection_health()
    assert result["state"] == "unavailable"
    assert result["items"] == []


@pytest.mark.parametrize("updates,state", [
    ({"status": "disabled"}, "disabled"),
    ({"collection_policy": {"state": "paused"}}, "paused"),
])
def test_diagnostic_failure_keeps_explicit_registry_disable_or_pause(monkeypatch, updates, state):
    def read(sql, params=(), **kwargs):
        if sql == health._AGENTS_SQL:
            return [agent(**updates)]
        raise TimeoutError()
    monkeypatch.setattr(health, "query_rows_bounded", read)
    result = health.get_agent_collection_health()
    item = result["items"][0]
    assert item["state"] == state
    expected_contact = health.collection_health_view(
        [agent(**updates)], [], now=datetime.fromisoformat(result["checked_at_utc"])
    )["items"][0]["connection"]
    assert item["connection"] == expected_contact
    assert item["modules"][0]["channels"][0]["state"] == state

