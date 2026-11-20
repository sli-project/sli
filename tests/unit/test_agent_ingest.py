"""Packet authorization, replay and durable receipts, with in-memory fakes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agent_ingest import receive_packet
from sli_agent.envelope import make_packet
from sli_agent.modules import EventLogModule, HeartbeatModule

NOW = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
AGENT = str(uuid4())
HOST = str(uuid4())


class Ledger:
    def __init__(self):
        self.rows = []
        self.imports = []
        self.binding_row = None
        self.quota = None

    def get(self, agent, module, sequence):
        return next((r for r in self.rows if r["envelope"]["agent_id"] == agent and
                     r["envelope"]["module_id"] == module and r["envelope"]["sequence"] == sequence), None)

    def packet_exists(self, packet_id):
        return any(r["envelope"]["packet_id"] == packet_id for r in self.rows)

    def latest(self, agent, module):
        rows = [r for r in self.rows if r["envelope"]["agent_id"] == agent and r["envelope"]["module_id"] == module]
        return rows[-1]["envelope"] if rows else None

    def binding(self, agent, module):
        return self.binding_row

    def quota_error(self, value, receipt, rows):
        return self.quota

    def workstation_counts(self, agent, window_seconds):
        from collections import Counter
        cutoff = NOW - timedelta(seconds=window_seconds)
        return Counter(str(row["event_id"]) for entry in self.rows
            if entry["envelope"]["agent_id"] == agent and entry["envelope"]["module_id"] == "sli.workstations"
            and entry["received_at"] >= cutoff for row in entry["event_rows"])

    def commit(self, value, receipt, envelope_hash, rows):
        self.rows.append({"envelope": deepcopy(value["envelope"]), "receipt": deepcopy(receipt),
                          "envelope_sha256": envelope_hash, "received_at": NOW, "event_rows": deepcopy(rows or [])})
        if rows is not None:
            self.imports.append(deepcopy(rows))


@pytest.fixture
def context():
    return Ledger(), {"id": AGENT, "host_id": HOST, "assigned_modules": []}, ec.generate_private_key(ec.SECP256R1())


def send(context, *, sequence=1, now=NOW, captured=None, sample=None):
    ledger, identity, key = context
    sample = sample or HeartbeatModule(HOST).collect(captured, now=now)
    value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=now)
    return value, receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)


def test_lost_ack_returns_same_receipt_without_second_import(context):
    value, result = send(context)
    assert result["status"] == "committed"
    ledger, identity, key = context
    retry = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW + timedelta(days=30))
    assert retry == {**result, "status": "duplicate"}
    assert len(ledger.rows) == 1


def test_quota_rejects_new_packet_but_allows_exact_accepted_replay(context):
    value, receipt = send(context)
    ledger, identity, key = context
    ledger.quota = "agent_inbox_agent_count_limit"
    retry = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert retry == {**receipt, "status": "duplicate"}
    _, rejected = send(context, sequence=2, captured=value["envelope"])
    assert rejected["status"] == "retry_later"
    assert rejected["error_code"] == ledger.quota
    assert rejected["committed_cursor"] is None
    assert rejected["evidence_ref"] is None
    assert len(ledger.rows) == 1
    # No reservation or sequence advance survives the denial.
    ledger.quota = None
    _, result = send(context, sequence=2, captured=value["envelope"])
    assert result["status"] == "committed"


def test_quota_denial_preserves_agent_spool(tmp_path):
    from sli_agent.spool import Spool

    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=1024 * 1024, max_age_seconds=86400)
    sample = HeartbeatModule(HOST).collect(None, now=NOW)
    value = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    ledger = Ledger()
    ledger.quota = "agent_inbox_storage_bytes_limit"
    receipt = receive_packet(ledger, identity={"id": AGENT, "host_id": HOST},
                             public_key=key.public_key(), value=value, now=NOW)
    assert not spool.acknowledge(value, receipt)
    assert (tmp_path / (value["envelope"]["packet_id"] + ".packet")).exists()
    assert not ledger.rows


def test_same_sequence_with_another_hash_is_rejected(context):
    send(context)
    _, result = send(context)
    assert result["status"] == "rejected" and result["error_code"] == "agent_sequence_conflict"
    assert result["committed_cursor"] is None


@pytest.mark.parametrize("offset", [-8 * 86400, 301])
def test_replay_window_for_new_packets(context, offset):
    _, result = send(context, now=NOW + timedelta(seconds=offset))
    assert result["error_code"] == "agent_replay_window"
    assert not context[0].rows


def test_sequence_gap_and_cursor_fork_are_not_committed(context):
    _, result = send(context, sequence=2)
    assert result["status"] == "retry_later" and result["error_code"] == "agent_sequence_gap"
    first, _ = send(context)
    _, result = send(context, sequence=2)
    assert result["error_code"] == "agent_cursor_mismatch"
    _, result = send(context, sequence=2, captured=first["envelope"])
    assert result["status"] == "committed"


def test_agent_identity_cannot_be_forged(context):
    context[1]["id"] = str(uuid4())
    _, result = send(context)
    assert result["error_code"] == "agent_identity_mismatch"
    assert not context[0].rows


def test_bad_signature_fails_before_ledger_access(context):
    from sli_agent.envelope import EnvelopeError
    ledger, identity, key = context
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    value["signature"] = "AA=="
    with pytest.raises(EnvelopeError, match="agent_signature_invalid"):
        receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert not ledger.rows


def event_sample(generation="fixture-generation", captured=None):
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><EventID>4624</EventID><EventRecordID>7</EventRecordID></System></Event>')
    return EventLogModule(source_instance_id="fixture-source", source_name="fixture-host", channel="Security",
                          generation=generation, reader=lambda after: [xml]).collect(captured, now=NOW)


def test_event_import_requires_assignment_and_exact_source_binding(context):
    _, result = send(context, sample=event_sample())
    assert result["error_code"] == "agent_module_not_assigned"
    context[1]["assigned_modules"] = ["sli.windows-eventlog"]
    _, result = send(context, sample=event_sample())
    assert result["error_code"] == "agent_source_not_bound"
    context[0].binding_row = {"source_instance_id": "fixture-source", "source_name": "fixture-host",
                            "channel": "Security", "module_version": "1.0.0", "policy_revision": "1"}
    value, result = send(context, sample=event_sample())
    assert result["status"] == "committed"
    assert context[0].imports[0][0]["record_id"] == 7
    other = deepcopy(context[0].binding_row)
    other["source_instance_id"] = "fixture-other-source"
    context[0].binding_row = other
    # An already committed packet remains acknowledgeable when policy changes.
    ledger, identity, key = context
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)["status"] == "duplicate"


def test_module_disable_detach_and_reenable_preserve_receipt_and_cursor(context):
    ledger, identity, key = context
    identity["assigned_modules"] = ["sli.windows-eventlog"]
    binding = {"source_instance_id": "fixture-source", "source_name": "fixture-host",
               "channel": "Security", "module_version": "1.0.0", "policy_revision": "1"}
    ledger.binding_row = binding
    first, committed = send(context, sample=event_sample())
    assert committed["status"] == "committed"
    before = deepcopy(ledger.rows)
    identity["assigned_modules"] = []
    ledger.binding_row = None
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(),
                          value=first, now=NOW)["status"] == "duplicate"
    sample = EventLogModule(source_instance_id="fixture-source", source_name="fixture-host", channel="Security",
        generation="fixture-generation", reader=lambda after: []).collect(first["envelope"], now=NOW)
    second = make_packet(key, agent_id=AGENT, sequence=2, sample=sample, now=NOW)
    rejected = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=second, now=NOW)
    assert rejected["error_code"] == "agent_module_not_assigned"
    assert ledger.rows == before
    identity["assigned_modules"] = ["sli.windows-eventlog"]
    ledger.binding_row = binding
    resumed = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=second, now=NOW)
    assert resumed["status"] == "committed"
    assert resumed["committed_cursor"] == committed["committed_cursor"]
    assert ledger.imports[1] == []
    assert ledger.rows[0] == before[0]


def test_pending_data_quota_denial_never_stages_receipt_or_evidence(context):
    ledger, identity, _ = context
    identity["assigned_modules"] = ["sli.windows-eventlog"]
    ledger.binding_row = {"source_instance_id": "fixture-source", "source_name": "fixture-host",
                         "channel": "Security", "module_version": "1.0.0", "policy_revision": "1"}
    ledger.quota = "agent_inbox_module_bytes_limit"
    _, result = send(context, sample=event_sample())
    assert result["status"] == "retry_later" and result["error_code"] == ledger.quota
    assert not ledger.rows and not ledger.imports


def test_reset_requires_explicit_gap_and_empty_start(context):
    ledger, identity, key = context
    identity["assigned_modules"] = ["sli.windows-eventlog"]
    ledger.binding_row = {"source_instance_id": "fixture-source", "source_name": "fixture-host",
                         "channel": "Security", "module_version": "1.0.0", "policy_revision": "1"}
    first, _ = send(context, sample=event_sample())
    next_sample = event_sample("fixture-new-generation", captured=first["envelope"])
    assert next_sample.continuity_state == "gap"
    _, result = send(context, sequence=2, sample=next_sample)
    assert result["status"] == "committed"


def test_postgres_ledger_stages_import_and_receipt_in_one_transaction(monkeypatch):
    from server.sli.agent_ingest import PostgresLedger
    from server.sli.sources import collection_packet_import
    calls = []
    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))
    monkeypatch.setattr(collection_packet_import, "store_agent_packet", lambda cur, **kw: calls.append(("import", kw)))
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=event_sample(), now=NOW)
    PostgresLedger(Cursor()).commit(value, {"status": "committed"}, "0" * 64, [])
    assert "insert into sli_agent_receipts" in calls[0][0]
    assert calls[1][0] == "import"
    assert calls[1][1]["packet"] == value["payload"]


def test_inbox_import_failure_keeps_packet_pending():
    from contextlib import nullcontext
    from server.sli.sources.collection_packet_import import consume_agent_packets
    updates = []
    class Cursor:
        def execute(self, sql, params=()):
            if sql.startswith("update"):
                updates.append(sql)
        def fetchall(self):
            return [{"packet_id": str(uuid4()), "event_rows": [{"record_id": 7}], "envelope": {}, "packet": {}}]
    connection = type("Connection", (), {"transaction": lambda self: nullcontext(),
        "cursor": lambda self: nullcontext(Cursor())})()
    def fail(*args, **kwargs):
        raise RuntimeError("fixture")
    with pytest.raises(RuntimeError):
        consume_agent_packets(connection, import_rows=fail)
    assert not updates


def test_inbox_progress_follows_same_connection_sink():
    from contextlib import contextmanager, nullcontext
    from server.sli.sources.collection_packet_import import consume_agent_packets
    events = []
    row = {"packet_id": str(uuid4()), "event_rows": [{"record_id": 7}], "envelope": {}, "packet": {}}
    class Cursor:
        def execute(self, sql, params=()):
            events.append("progress" if sql.startswith("update") else "select")
        def fetchall(self):
            return [row]
    class Connection:
        @contextmanager
        def transaction(self):
            events.append("begin")
            yield
            events.append("commit")
        def cursor(self):
            return nullcontext(Cursor())
    conn = Connection()
    def sink(connection, rows, **kwargs):
        assert connection is conn and rows == row["event_rows"]
        assert kwargs == {"packet": row["packet"], "envelope": row["envelope"]}
        events.append("sink")
    assert consume_agent_packets(conn, import_rows=sink) == 1
    assert events == ["begin", "select", "sink", "progress", "commit"]


def test_workstations_assignment_accepts_multiplexed_bookmarks(context):
    from sli_agent.workstations import WorkstationsModule

    ledger, identity, _ = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    collector = WorkstationsModule(HOST, reader=lambda *a: [])
    captured = None
    for sequence in range(1, 8):
        sample = collector.collect(captured, now=NOW)
        value, result = send(context, sequence=sequence, sample=sample)
        assert result["status"] == "committed"
        captured = value["envelope"]
    assert len(ledger.imports) == 7


@pytest.mark.parametrize("channel,batch_size,total,padding", [
    ("Security", 2, 5, 0),
    ("Security", 2, 4, 0),
    ("Security", 128, 20, 5000),
    ("Microsoft-Windows-Windows Defender/Operational", 2, 5, 0),
])
def test_workstation_catchup_packets_receive_durable_receipts(
        context, tmp_path, channel, batch_size, total, padding):
    from types import SimpleNamespace

    from sli_agent.runtime import capture_module, deliver_once
    from sli_agent.spool import Spool
    from sli_agent.workstations import CHANNEL_EVENTS, PROTECTION_COMPONENTS, WorkstationsModule

    ledger, identity, key = context
    config = {"batch_size": batch_size}
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": config}]
    provider, _ = CHANNEL_EVENTS[channel]
    event_id = 4688 if channel == "Security" else 5001
    events = [(record_id,
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        f'<EventRecordID>{record_id}</EventRecordID><Channel>{channel}</Channel>'
        '<TimeCreated SystemTime="2026-10-06T12:00:00Z"/></System>'
        f'<EventData><Data Name="CommandLine">{"x" * padding}</Data></EventData></Event>')
        for record_id in range(1, total + 1)]
    def reader(selected, cursor, limit):
        return [(text, f"bookmark-{record_id}") for record_id, text in events
                if selected == channel and (cursor["record_id"] is None or record_id > cursor["record_id"])][:limit]
    collector = WorkstationsModule(HOST, config, reader=reader,
        protection_reader=lambda: {"state": "available", "components": dict.fromkeys(PROTECTION_COMPONENTS, True)})
    spool = Spool(tmp_path, max_bytes=1024 * 1024, max_age_seconds=86400)
    # Reach the target channel through the normal rotation before its burst.
    while collector.enabled_channels()[collector._state(spool.captured(collector.module_id))["next"]] != channel:
        spool.capture(key, agent_id=AGENT, sample=collector.collect(spool.captured(collector.module_id), now=NOW), now=NOW)
    capture_module(collector, spool, SimpleNamespace(key=key, agent_id=AGENT), now=NOW)
    burst = [value for value in spool.pending(now=NOW) if value["payload"]["header"]["channel"] == channel]
    assert len(burst) > 1
    assert [record["record_id"] for value in burst for record in value["payload"]["records"]] == list(range(1, total + 1))
    assert deliver_once(spool, lambda value: receive_packet(
        ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW), now=NOW)
    assert not spool.pending(now=NOW)
    assert [row["record_id"] for rows in ledger.imports for row in rows] == list(range(1, total + 1))
    # The burst must leave the next normal channel available for admission.
    sample = collector.collect(spool.captured(collector.module_id), now=NOW)
    value = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    assert sample.payload["header"]["channel"] != channel
    assert spool.acknowledge(value, receive_packet(
        ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW))


def test_workstation_catchup_does_not_allow_skipping_to_another_channel(context):
    from sli_agent.workstations import CHANNELS, WorkstationsModule

    ledger, identity, _ = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    collector = WorkstationsModule(HOST, reader=lambda *args: [])
    first, result = send(context, sample=collector.collect(now=NOW))
    assert result["status"] == "committed"
    sample = collector.collect(first["envelope"], now=NOW, channel=CHANNELS[2])
    _, result = send(context, sequence=2, sample=sample)
    assert result["status"] == "rejected"
    assert result["error_code"] == "agent_workstations_packet_invalid"
    assert len(ledger.rows) == 1


def test_disabled_workstation_channels_are_skipped_by_ingress(context):
    from sli_agent.workstations import WorkstationsModule
    ledger, identity, _ = context
    config = {"families": {"usb": False, "protection": False}}
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": config}]
    collector = WorkstationsModule(HOST, config, reader=lambda *a: [])
    captured = None
    for sequence in range(1, 4):
        value, result = send(context, sequence=sequence, sample=collector.collect(captured, now=NOW))
        assert result["status"] == "committed"
        captured = value["envelope"]
    assert len(ledger.imports) == 3


def test_queued_old_revision_uses_only_this_agents_retained_policy(context):
    from sli_agent.workstations import WorkstationsModule
    ledger, identity, _ = context
    old = {"module_id": "sli.workstations", "enabled": True, "config": {"policy_revision": "2"}}
    identity["assigned_modules"] = [{**old, "config": {"policy_revision": "3", "families": {"usb": False}}}]
    def history(agent_id, module_id, revision):
        assert (agent_id, module_id, revision) == (AGENT, "sli.workstations", "2")
        return old
    ledger.policy_assignment = history
    value, result = send(context, sample=WorkstationsModule(HOST, old["config"], reader=lambda *a: []).collect(now=NOW))
    assert result["status"] == "committed"
    assert value["envelope"]["policy_revision"] == "2"
    ledger.quota = "agent_inbox_agent_count_limit"
    assert receive_packet(ledger, identity=identity, public_key=context[2].public_key(), value=value, now=NOW)["status"] == "duplicate"
    ledger.rows.clear()
    denied = receive_packet(ledger, identity=identity, public_key=context[2].public_key(), value=value, now=NOW)
    assert denied["status"] == "retry_later" and denied["error_code"] == ledger.quota
    assert denied["committed_cursor"] is None and not ledger.rows
    ledger.policy_assignment = lambda *args: None
    assert send(context, sample=WorkstationsModule(HOST, old["config"], reader=lambda *a: []).collect(now=NOW))[1]["status"] == "rejected"


@pytest.mark.parametrize("change", ["unassigned", "disabled", "host", "revision", "cursor", "counts", "context"])
def test_workstations_attestation_and_cursor_fail_closed(context, change):
    from dataclasses import replace
    from sli_agent.workstations import WorkstationsModule

    ledger, identity, _ = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True, "config": {}}]
    sample = WorkstationsModule(HOST, reader=lambda *a: []).collect(now=NOW)
    if change == "unassigned": identity["assigned_modules"] = ["sli.workstations"]
    elif change == "disabled": identity["assigned_modules"][0]["enabled"] = False
    elif change == "host": sample = replace(sample, source_instance_id=str(uuid4()))
    elif change == "revision": sample = replace(sample, policy_revision="2")
    elif change == "counts": sample = replace(sample, filtered_count=1)
    elif change == "context": sample.payload["context"]["workstations"] = None
    else:
        state = json.loads(sample.cursor_after["token"])
        state["next"] = 0
        sample = replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})
    _, result = send(context, sample=sample)
    assert result["status"] == "rejected"
    assert not ledger.imports


def workstation_rate_sample(record_id, *, captured=None, now=NOW, channel=None):
    from dataclasses import replace
    from sli_agent.workstations import WorkstationsModule

    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>'
           f'<EventRecordID>{record_id}</EventRecordID><Channel>Security</Channel>'
           '<TimeCreated SystemTime="2026-10-06T12:00:00Z"/></System></Event>')
    # Capture without client limits, then forge only the 4688 counter. Keep
    # the v1.1 window/4104 state valid so server-side limits are exercised.
    sample = WorkstationsModule(HOST, reader=lambda *a: [(xml, "fixture-bookmark")]).collect(
        captured, now=now, channel=channel)
    state = json.loads(sample.cursor_after["token"])
    state["rate"]["counts"]["4688"] = 0
    return replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})


def test_workstation_v11_rejects_forged_rate_window_before_quota(context):
    from dataclasses import replace
    from server.sli.agents.workstation_ingest import workstation_rows

    ledger, identity, key = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True,
                                     "config": {"rate_limits": {"4688": 1}}}]
    sample = workstation_rate_sample(1)
    state = json.loads(sample.cursor_after["token"])
    state["rate"]["window"] = -1
    sample = replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    with pytest.raises(ValueError, match="^agent_workstations_rate_invalid$"):
        workstation_rows(identity, value["envelope"], value["payload"])
    result = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert result["status"] == "rejected" and result["error_code"] == "agent_workstations_packet_invalid"
    assert not ledger.rows and not ledger.imports


def test_workstation_quota_denial_does_not_consume_rate_budget_and_replay_bypasses_both(context):
    ledger, identity, key = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True,
                                     "config": {"rate_limits": {"4688": 1}}}]
    ledger.quota = "agent_inbox_agent_count_limit"
    value, denied = send(context, sample=workstation_rate_sample(1))
    assert denied["status"] == "retry_later" and denied["error_code"] == ledger.quota
    assert denied["committed_cursor"] is None and denied["evidence_ref"] is None
    assert not ledger.rows and not ledger.imports
    assert not ledger.workstation_counts(AGENT, 60)

    ledger.quota = None
    accepted = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert accepted["status"] == "committed"
    assert ledger.workstation_counts(AGENT, 60) == {"4688": 1}
    ledger.quota = "agent_inbox_agent_count_limit"
    replay = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert replay == {**accepted, "status": "duplicate"}
    assert len(ledger.rows) == 1 and len(ledger.imports) == 1


def test_workstation_zero_limit_rejects_signed_forged_counters(context):
    context[1]["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True,
                                       "config": {"rate_limits": {"4688": 0}}}]
    _, result = send(context, sample=workstation_rate_sample(1))
    assert result["error_code"] == "agent_workstations_rate_limit"
    assert result["committed_cursor"] is None
    assert not context[0].rows and not context[0].imports


@pytest.mark.parametrize("client_time", [NOW, NOW - timedelta(minutes=1), NOW + timedelta(minutes=1)])
@pytest.mark.parametrize("catchup", [False, True])
def test_workstation_rate_budget_counts_multiple_packets_and_ignores_client_window(context, client_time, catchup):
    from sli_agent.workstations import WorkstationsModule

    ledger, identity, key = context
    identity["assigned_modules"] = [{"module_id": "sli.workstations", "enabled": True,
                                     "config": {"rate_limits": {"4688": 1}}}]
    first, result = send(context, sample=workstation_rate_sample(1))
    assert result["status"] == "committed"
    captured = first["envelope"]
    # Walk the multiplexed stream back to Security without admitting events.
    collector = WorkstationsModule(HOST, reader=lambda *a: [])
    second_sequence = 2 if catchup else len(collector.channels) + 1
    for sequence in range(2, second_sequence):
        value, result = send(context, sequence=sequence, sample=collector.collect(captured, now=NOW))
        assert result["status"] == "committed"
        captured = value["envelope"]
    second = make_packet(key, agent_id=AGENT, sequence=second_sequence,
        sample=workstation_rate_sample(2, captured=captured, now=client_time,
            channel="Security" if catchup else None), now=client_time)
    result = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=second, now=NOW)
    assert result["error_code"] == "agent_workstations_rate_limit"
    assert len(ledger.rows) == second_sequence - 1 and len(ledger.imports[0]) == 1
    assert result["committed_cursor"] is None
    # Expiration follows the receipt time on the server, not observed_at or
    # the signed client's bookmark counters.
    ledger.rows[0]["received_at"] = NOW - timedelta(seconds=61)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(),
                          value=second, now=NOW)["status"] == "committed"


def test_postgres_workstation_counts_use_server_receipt_time_and_retained_rows():
    from server.sli.agent_ingest import PostgresLedger

    calls = []
    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))
        def fetchall(self):
            return [{"event_id": "4688", "count": 2}]
    assert PostgresLedger(Cursor()).workstation_counts(AGENT, 60) == {"4688": 2}
    sql, params = calls[0]
    assert "r.received_at >= clock_timestamp()" in sql
    assert "jsonb_array_elements(i.event_rows)" in sql
    assert "imported_at" not in sql and "cursor" not in sql
    assert params == (AGENT, 60)


def test_retained_module_revision_is_scoped_to_agent_even_when_snapshot_revision_is_later():
    from server.sli.agent_ingest import PostgresLedger
    calls = []
    assignment = {"module_id": "sli.workstations", "enabled": True, "config": {"policy_revision": "2"}}
    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))
        def fetchone(self):
            return {"assignment": assignment}
    ledger = PostgresLedger(Cursor())
    assert ledger.policy_assignment(AGENT, "sli.workstations", "2") == assignment
    sql, params = calls[0]
    assert "h.agent_id=%s" in sql and "assignment->>'module_id'=%s" in sql
    assert "h.revision=%s" not in sql
    assert params == (AGENT, "sli.workstations", "2")
    assert ledger.policy_assignment(AGENT, "sli.workstations", "unissued") is None
    assert len(calls) == 1


@pytest.mark.parametrize("missing,structured,reason", [
    ("ad_agent_policy", True, "agent_source_not_bound"),
    ("ad_agent_rows", True, "agent_collection_packet_invalid"),
    ("ad_agent_rows", False, "agent_collection_packet_invalid"),
])
def test_missing_ad_hook_never_stages_evidence(context, monkeypatch, missing, structured, reason):
    from server.sli import agent_ingest
    from sli_agent.ad_dc import ADDCModule

    ledger, identity, _ = context
    config = {"source_name": "fixture-dc", "connect_address": "fixture-endpoint"}
    identity["assigned_modules"] = [{"module_id": "sli.windows.ad-dc", "enabled": True, "config": config}
                                     if structured else "sli.windows.ad-dc"]
    ledger.binding_row = {"source_instance_id": HOST, "source_name": config["source_name"],
                          "channel": "ad-dc", "module_version": "1.0.0", "policy_revision": "1"}
    real_hook = agent_ingest.plugin_hook
    monkeypatch.setattr(agent_ingest, "plugin_hook", lambda owner, name: None if name == missing else real_hook(owner, name))
    sample = ADDCModule(HOST, config, reader=lambda *_: []).collect(now=NOW)
    _, result = send(context, sample=sample)
    assert result["status"] == "rejected" and result["error_code"] == reason
    assert result["committed_cursor"] is None and result["evidence_ref"] is None
    assert not ledger.rows and not ledger.imports
