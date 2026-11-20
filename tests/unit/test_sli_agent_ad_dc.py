"""DC capture and ingress contracts with synthetic events and no database."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
from uuid import uuid4
from pathlib import Path
from types import SimpleNamespace
from xml.sax.saxutils import escape

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent.ad_dc import ADDCModule, CHANNELS, event_identities
from sli_agent.config import AgentConfig
from sli_agent.envelope import make_packet
from sli_agent.modules import configured_modules
from sli_agent.spool import Spool, SpoolFull
from server.sli.agent_ingest import receive_packet
from server.sli.sources.collection_packet_import import event_rows_from_packet

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
HOST = str(uuid4())
AGENT = str(uuid4())
SOURCE = "fixture-dc"
SECURITY = "Microsoft-Windows-Security-Auditing"
CONFIG = {"source_name": SOURCE, "connect_address": "fixture-endpoint"}


def test_native_security_query_keeps_catalog_and_legacy_anchor_without_file_noise(monkeypatch):
    import re
    from sli_agent import ad_dc

    calls = []
    monkeypatch.setattr(ad_dc, "read_bookmarked", lambda *args, **kwargs: calls.append((args, kwargs)) or [])
    cursor = {"record_id": 500, "bookmark": "legacy-file-anchor", "generation": HOST}
    assert ad_dc.read_local("Security", cursor, 32) == []
    selector = calls[-1][1]["system_filter"]
    # Interpret only the numeric ID predicates to check the query's catalog
    # coverage independently of Windows. Native seek/recovery has its own fake.
    singles = {int(n) for n in re.findall(r"EventID=(\d+)", selector)}
    ranges = [(int(a), int(b)) for a, b in re.findall(r"EventID >= (\d+) and EventID <= (\d+)", selector)]
    selected = lambda n: n in singles or any(a <= n <= b for a, b in ranges)
    assert all(selected(event) for channel, _, event in event_identities() if channel == "Security")
    assert not any(selected(event) for event in (4656, 4658, 4659, 4660, 4663, 4664, 4670, 5145))
    assert "EventRecordID=500" in selector
    assert calls[-1][0] == ("Security", cursor, 32)
    assert calls[-1][1]["recover_missing_bookmark"] is True
    assert selector.count("EventID") < 20
    ad_dc.read_local("System", cursor, 32)
    assert calls[-1][1]["system_filter"] is None
    ad_dc.read_local("Security", {**cursor, "bookmark": ""}, 32)
    assert "EventRecordID=" not in calls[-1][1]["system_filter"]


def xml(event_id, record_id, channel="Security", provider=SECURITY):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{escape(provider)}"/><EventID>{event_id}</EventID>'
            f'<EventRecordID>{record_id}</EventRecordID><Channel>{escape(channel)}</Channel>'
            '<Computer>fixture-dc</Computer><TimeCreated SystemTime="2026-10-07T00:00:00Z"/>'
            '</System><EventData><Data Name="TargetUserName">fixture-account</Data></EventData></Event>')


class Reader:
    def __init__(self, events):
        self.events = events
        self.calls = []

    def __call__(self, channel, cursor, limit):
        self.calls.append((channel, deepcopy(cursor)))
        return [(raw, f"bookmark-{n}") for n, raw in self.events.get(channel, [])
                if cursor["record_id"] is None or n > cursor["record_id"]][:limit]


def module(events=None, **config):
    return ADDCModule(HOST, {**CONFIG, **config}, reader=Reader(events or {}))


def checkpoint(sample):
    return {"generation": sample.generation, "cursor_after": sample.cursor_after}


def test_dc_backlog_drains_durable_bounded_packets_and_preserves_rotation(tmp_path):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4625, i)) for i in range(1, 11)]}, batch_size=2)
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    capture_module(collector, spool, identity, now=NOW, batch_size=3)
    packets = spool.pending(now=NOW)
    assert len(packets) == 3
    assert [r["record_id"] for value in packets for r in value["payload"]["records"]] == list(range(1, 7))
    assert spool.captured(collector.module_id)["cursor_after"] == packets[-1]["envelope"]["cursor_after"]
    # Unacknowledged packets cap the burst even on the next heartbeat.
    calls = len(collector.reader.calls)
    capture_module(collector, spool, identity, now=NOW, batch_size=3)
    assert len(collector.reader.calls) == calls
    ledger = Ledger()
    assigned = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": collector.module_id, "enabled": True, "config": collector.config}]}
    for value in packets:
        receipt = receive_packet(ledger, identity=assigned, public_key=identity.key.public_key(), value=value, now=NOW)
        assert receipt["status"] == "committed"
        assert spool.acknowledge(value, receipt)
    capture_module(collector, spool, identity, now=NOW, batch_size=3)
    assert collector.reader.calls[-1][0] == "System"
    assert len(spool.pending(now=NOW)) == 1


def test_dc_wire_limited_batch_resumes_without_consuming_omitted_row():
    def large(i):
        return xml(4625, i).replace("</EventData>",
            '<Data Name="Description">' + "x" * 7000 + "</Data></EventData>")
    collector = module({"Security": [(i, large(i)) for i in range(1, 9)]}, batch_size=128)
    first = collector.collect(now=NOW)
    assert collector.catch_up_channel == "Security"
    last = first.payload["header"]["cursor"]["last_record_id"]
    assert last < 8
    second = collector.collect(checkpoint(first), now=NOW, channel=collector.catch_up_channel)
    assert second.payload["records"][0]["record_id"] == last + 1
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger()
    assigned = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": collector.module_id, "enabled": True, "config": collector.config}]}
    for sequence, sample in enumerate((first, second), 1):
        value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        receipt = receive_packet(ledger, identity=assigned, public_key=key.public_key(), value=value, now=NOW)
        assert receipt["status"] == "committed"


def test_dc_filtered_full_batch_still_requests_catchup():
    collector = module({"Security": [(i, xml(65535, i)) for i in range(1, 4)]}, batch_size=2)
    first = collector.collect(now=NOW)
    assert first.payload["records"] == [] and first.filtered_count == 2
    assert collector.catch_up_channel == "Security"
    second = collector.collect(checkpoint(first), now=NOW, channel="Security")
    assert second.payload["header"]["cursor"] == {"after_record_id": 2, "last_record_id": 3}
    assert collector.catch_up_channel is None


def test_dc_recovery_burst_keeps_unknown_gap_attestation(tmp_path):
    from sli_agent.runtime import capture_module
    from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch

    reader = Reader({"Security": [(i, xml(4625, i)) for i in range(7, 13)]})
    def recovered_reader(channel, cursor, limit):
        rows = reader(channel, cursor, limit)
        return BookmarkRecoveryBatch(rows) if len(reader.calls) == 1 else rows
    collector = ADDCModule(HOST, {**CONFIG, "batch_size": 2}, reader=reader)
    initial = module({"Security": [(1, xml(4625, 1))]}).collect(now=NOW)
    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    spool.capture(key, agent_id=AGENT, sample=initial, now=NOW)
    # Resume Security after visiting the other channels in the prior cycle.
    for _ in CHANNELS[1:]:
        prior = collector.collect(spool.captured(collector.module_id), now=NOW)
        spool.capture(key, agent_id=AGENT, sample=prior, now=NOW)
    # Recovery describes the first catch-up read, after the prior cycle.
    reader.calls.clear()
    collector.reader = recovered_reader
    pending_before = len(spool.pending(now=NOW))
    capture_module(collector, spool, SimpleNamespace(key=key, agent_id=AGENT), now=NOW,
                   batch_size=pending_before + 3)
    packets = spool.pending(now=NOW)[pending_before:]
    assert len(packets) == 3
    assert packets[0]["envelope"]["continuity_state"] == "gap"
    assert packets[0]["envelope"]["lost_count"] is None
    assert packets[0]["payload"]["context"]["ad_dc"]["bookmark_recovered"] is True
    assert [r["record_id"] for value in packets for r in value["payload"]["records"]] == list(range(7, 13))
    assert all(value["envelope"]["lost_count"] == 0 for value in packets[1:])
    ledger = Ledger()
    assigned = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": collector.module_id, "enabled": True, "config": collector.config}]}
    for value in spool.pending(now=NOW):
        receipt = receive_packet(ledger, identity=assigned, public_key=key.public_key(), value=value, now=NOW)
        assert receipt["status"] == "committed"
        assert spool.acknowledge(value, receipt)


@pytest.mark.parametrize("mutation", ["disabled", "skip_channel", "other_progress", "next_channel"])
def test_dc_catchup_ingress_keeps_channel_ownership(mutation):
    from server.sli.plugins.ad.agent_policy import dc_event_rows

    collector = module({"Security": [(i, xml(4625, i)) for i in range(1, 5)]}, batch_size=2)
    first = collector.collect(now=NOW)
    second = collector.collect(checkpoint(first), now=NOW, channel="Security")
    policy = deepcopy(collector.config)
    if mutation == "disabled":
        policy["channels"]["Security"] = False
    elif mutation == "skip_channel":
        second = collector.collect(checkpoint(first), now=NOW, channel="Directory Service")
    else:
        state = json.loads(second.cursor_after["token"])
        if mutation == "other_progress":
            state["channels"]["System"] = {"record_id": 1, "bookmark": "foreign", "generation": HOST}
        else:
            state["next"] = 2
        second = replace(second, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=2, sample=second, now=NOW)
    with pytest.raises(ValueError, match="agent_collection_cursor_invalid"):
        dc_event_rows(value["envelope"], value["payload"], {"source_name": SOURCE}, policy)


def test_dc_history_ingress_still_requires_rotation():
    from datetime import timedelta
    from server.sli.plugins.ad.agent_policy import dc_event_rows
    from sli_agent.ad_dc import DCHistoryModule

    collector = DCHistoryModule(HOST, {**CONFIG, "batch_size": 2,
        "history_before_utc": (NOW + timedelta(hours=1)).isoformat()},
        reader=Reader({"Security": [(i, xml(4625, i)) for i in range(1, 5)]}))
    first = collector.collect(now=NOW)
    second = collector.collect(checkpoint(first), now=NOW, channel="Security")
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=2, sample=second, now=NOW)
    with pytest.raises(ValueError, match="agent_collection_cursor_invalid"):
        dc_event_rows(value["envelope"], value["payload"], {"source_name": SOURCE}, collector.config)


def test_dc_burst_stops_at_wall_budget(tmp_path):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4625, i)) for i in range(1, 9)]}, batch_size=2)
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    ticks = iter([0.0, 0.0, 6.0])
    capture_module(collector, spool, identity, now=NOW, batch_size=3, clock=lambda: next(ticks))
    assert len(collector.reader.calls) == len(spool.pending(now=NOW)) == 1


def test_dc_failed_spool_write_stops_before_next_read(tmp_path):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4625, i)) for i in range(1, 9)]}, batch_size=2)
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1, max_age_seconds=86400)
    with pytest.raises(SpoolFull):
        capture_module(collector, spool, identity, now=NOW, batch_size=3)
    assert len(collector.reader.calls) == 1
    assert spool.captured(collector.module_id) is None


def test_dc_read_error_clears_catchup_and_rejects_disabled_override():
    collector = module({"Security": [(1, xml(4625, 1))]}, batch_size=1,
                       channels={"System": False, "Directory Service": False})
    first = collector.collect(now=NOW)
    assert collector.catch_up_channel == "Security"
    def failed_reader(*args):
        raise OSError("fixture-read-failed")
    collector.reader = failed_reader
    failed = collector.collect(checkpoint(first), now=NOW, channel="Security")
    assert collector.catch_up_channel is None
    assert failed.lost_count is None and failed.continuity_state == "gap"
    with pytest.raises(ValueError, match="agent_ad_dc_channel_invalid"):
        collector.collect(checkpoint(failed), now=NOW, channel="System")


def test_explicit_assignment_only_and_conflicting_reader_rejected(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    for assignments in ([], ["sli.windows.ad-dc"],
                        [{"module_id": "sli.windows.ad-dc", "enabled": False}]):
        assert len(configured_modules(config, HOST, assignments)) == 1
    assignment = {"module_id": "sli.windows.ad-dc", "enabled": True, "config": CONFIG}
    modules = configured_modules(config, HOST, [assignment])
    assert modules[1].module_id == "sli.windows.ad-dc"
    with pytest.raises(ValueError, match="agent_module_config_invalid"):
        configured_modules(config, HOST, [assignment, assignment])
    with pytest.raises(ValueError, match="agent_channel_owner_conflict"):
        configured_modules(config, HOST, [assignment, {"module_id": "sli.workstations", "enabled": True}])


def test_catalog_filter_preserves_native_rows_and_consumes_filtered_cursor():
    raw = xml(4624, 1)
    sample = module({"Security": [(1, raw), (2, xml(65535, 2)),
                                  (3, xml(4624, 3, provider="fixture-other"))]}).collect(now=NOW)
    rows = event_rows_from_packet(sample.payload)
    assert len(rows) == 1 and rows[0]["xml"] == raw
    assert rows[0]["computer_name"] == SOURCE
    assert rows[0]["connect_address"] == CONFIG["connect_address"]
    assert sample.payload["header"]["cursor"] == {"after_record_id": None, "last_record_id": 3}
    assert sample.filtered_count == 2 and sample.lost_count == 0
    assert sample.continuity_state == "filtered"


def test_directory_attribute_change_is_retained_by_pack_and_signed_ingress():
    raw = xml(5136, 1)
    collector = module({"Security": [(1, raw)]})
    sample = collector.collect(now=NOW)
    assert [row["event_id"] for row in event_rows_from_packet(sample.payload)] == [5136]
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    ledger = Ledger()
    receipt = receive_packet(ledger, identity={"id": AGENT, "host_id": HOST,
        "assigned_modules": [{"module_id": collector.module_id, "enabled": True, "config": CONFIG}]},
        public_key=key.public_key(), value=value, now=NOW)
    assert receipt["status"] == "committed"
    assert ledger.imports[0][0]["xml"] == raw


def test_channel_switches_skip_readers_and_allowlist_keeps_pack_filter():
    collector = module({"Security": [(1, xml(4624, 1)), (2, xml(4625, 2))]},
                       channels={"System": False, "Directory Service": False}, allow_event_ids=[4624])
    first = collector.collect(now=NOW)
    assert [r["record_id"] for r in first.payload["records"]] == [1]
    collector.collect(checkpoint(first), now=NOW)
    assert [call[0] for call in collector.reader.calls] == ["Security", "Security"]
    disabled = module(channels=dict.fromkeys(CHANNELS, False))
    assert disabled.collect(checkpoint(first), now=NOW) is None
    assert not disabled.reader.calls


@pytest.mark.parametrize("config", [{"channels": {"Security": 1}}, {"channels": {"unknown": False}},
                                    {"allow_event_ids": [65535]}, {"allow_event_ids": [True]}])
def test_invalid_dc_channel_policy_is_rejected(config):
    with pytest.raises(ValueError, match="agent_ad_dc_config_invalid"):
        module(**config)


@pytest.mark.parametrize("channel,provider,event_id", sorted(event_identities()))
def test_every_pack_identity_in_the_three_channels_is_captured(channel, provider, event_id):
    collector = module({channel: [(1, xml(event_id, 1, channel, provider))]})
    captured = None
    for _ in CHANNELS:
        sample = collector.collect(captured, now=NOW)
        captured = checkpoint(sample)
        if sample.payload["header"]["channel"] == channel:
            assert len(sample.payload["records"]) == 1


def test_bookmarks_survive_spool_restart_and_failed_capture(tmp_path):
    reader = Reader({"Security": [(1, xml(4624, 1))]})
    collector = ADDCModule(HOST, CONFIG, reader=reader)
    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=1, max_age_seconds=3600)
    first = collector.collect(now=NOW)
    with pytest.raises(SpoolFull):
        spool.capture(key, agent_id=AGENT, sample=first, now=NOW)
    assert spool.captured(collector.module_id) is None
    assert collector.collect(now=NOW) == first
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    for _ in CHANNELS:
        spool.capture(key, agent_id=AGENT,
                      sample=collector.collect(spool.captured(collector.module_id), now=NOW), now=NOW)
    restarted = ADDCModule(HOST, CONFIG, reader=reader)
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    sample = restarted.collect(spool.captured(collector.module_id), now=NOW)
    assert sample.payload["records"] == []
    assert reader.calls[-1][1] == {"record_id": 1, "bookmark": "bookmark-1", "generation": HOST,
                                 "since_utc": "2026-10-06T00:00:00+00:00"}


def test_read_failure_rotates_channel_without_advancing_its_bookmark():
    def fail(*_):
        raise RuntimeError("fixture-private-diagnostic")
    sample = ADDCModule(HOST, CONFIG, reader=fail).collect(now=NOW)
    assert sample.continuity_state == "gap" and sample.lost_count is None
    assert sample.payload["context"]["ad_dc"]["read_error"] == "agent_ad_dc_read_failed"
    state = json.loads(sample.cursor_after["token"])
    assert state["next"] == 1 and state["channels"]["Security"]["record_id"] is None


@pytest.mark.parametrize("rows", [[], [(xml(4624, 9), "bookmark-9")],
                                 [(xml(65535, 9), "bookmark-9")]])
def test_missing_bookmark_recovery_is_attested_as_unknown_gap_and_resumes(rows):
    from server.sli.plugins.ad.agent_policy import dc_event_rows
    from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch

    collector = module({"Security": [(7, xml(4624, 7))]})
    captured = None
    for _ in CHANNELS:
        captured = checkpoint(collector.collect(captured, now=NOW))
    old = deepcopy(captured)
    collector.reader = lambda *_: BookmarkRecoveryBatch(rows)
    sample = collector.collect(captured, now=NOW)
    assert captured == old
    assert sample.continuity_state == "gap" and sample.lost_count is None
    assert sample.payload["context"]["ad_dc"]["bookmark_recovered"] is True
    assert sample.payload["context"]["ad_dc"]["channel_reset"] is False
    state = json.loads(sample.cursor_after["token"])
    previous = json.loads(captured["cursor_after"]["token"])
    assert state["channels"]["Security"]["record_id"] == (9 if rows else 7)
    assert state["channels"]["Security"]["generation"] == HOST
    for channel in CHANNELS[1:]:
        assert state["channels"][channel] == previous["channels"][channel]
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=4, sample=sample, now=NOW)
    binding = {"source_name": SOURCE}
    admitted = dc_event_rows(value["envelope"], value["payload"], binding, collector.config)
    assert len(admitted) == (1 if rows and "<EventID>4624" in rows[0][0] else 0)
    for mutation in ("lost_count", "continuity_state", "marker", "reset", "failed", "initial_cursor"):
        forged = deepcopy(value)
        context = forged["payload"]["context"]["ad_dc"]
        if mutation == "lost_count":
            forged["envelope"]["lost_count"] = 0
        elif mutation == "continuity_state":
            forged["envelope"]["continuity_state"] = "not_proven"
        elif mutation == "marker":
            context["bookmark_recovered"] = "true"
        elif mutation == "reset":
            context["channel_reset"] = True
        elif mutation == "failed":
            context["read_error"] = "agent_ad_dc_read_failed"
        else:
            forged["envelope"]["cursor_before"]["token"] = ""
        with pytest.raises(ValueError, match="agent_collection_cursor_invalid"):
            dc_event_rows(forged["envelope"], forged["payload"], binding, collector.config)
    collector.reader = Reader({"Security": [(10, xml(4624, 10))]})
    captured = checkpoint(sample)
    for _ in CHANNELS:
        resumed = collector.collect(captured, now=NOW)
        captured = checkpoint(resumed)
    assert [r["record_id"] for r in resumed.payload["records"]] == [10]
    assert resumed.continuity_state == "not_proven" and resumed.lost_count == 0


def test_channel_reset_is_explicit_and_other_channel_progress_is_unchanged():
    collector = module({"Security": [(1, xml(4624, 1))]})
    captured = None
    for _ in CHANNELS:
        captured = checkpoint(collector.collect(captured, now=NOW))
    reset = module(channel_generations={"Security": "fixture-next"}).collect(captured, now=NOW)
    assert reset.continuity_state == "gap" and reset.lost_count is None
    assert reset.payload["header"]["cursor"]["after_record_id"] is None
    assert reset.payload["context"]["ad_dc"]["channel_reset"] is True


@pytest.mark.parametrize("rows", [
    [(xml(4624, 2), "b"), (xml(4624, 1), "a")],
    [(xml(4624, 1, "System"), "a")], [(xml(4624, 1), "")],
])
def test_invalid_reader_output_never_advances_progress(rows):
    with pytest.raises(ValueError):
        ADDCModule(HOST, CONFIG, reader=lambda *_: rows).collect(now=NOW)


@pytest.mark.parametrize("config", [{}, {**CONFIG, "batch_size": True},
    {**CONFIG, "batch_size": 129}, {**CONFIG, "allow_event_ids": [65535]},
    {**CONFIG, "channel_generations": {"DNS Server": "fixture"}}])
def test_invalid_policy_is_rejected(config):
    with pytest.raises(ValueError, match="agent_ad_dc_config_invalid"):
        ADDCModule(HOST, config)


def test_oversized_evidence_pauses_without_consuming_bookmark():
    raw = xml(4624, 1).replace("fixture-account", "x" * 50000)
    collector = module({"Security": [(1, raw)]})
    with pytest.raises(ValueError, match="agent_ad_dc_event_size_limit"):
        collector.collect(now=NOW)
    collector.reader = Reader({"Security": [(1, xml(4624, 1))]})
    sample = collector.collect(now=NOW)
    assert sample.payload["records"][0]["record_id"] == 1


def test_packet_budget_defers_the_next_record_without_losing_it():
    events = {"Security": [(n, xml(4624, n).replace("fixture-account", "x" * 15000)) for n in (1, 2)]}
    collector = module(events)
    first = collector.collect(now=NOW)
    assert [r["record_id"] for r in first.payload["records"]] == [1]
    assert first.payload["header"]["cursor"]["last_record_id"] == 1
    captured = checkpoint(first)
    for _ in range(2):
        captured = checkpoint(collector.collect(captured, now=NOW))
    second = collector.collect(captured, now=NOW)
    assert [r["record_id"] for r in second.payload["records"]] == [2]


def test_ad_plugin_declares_dc_module_and_bundled_policy():
    from server.sli.core.job_registry import validate_shape
    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "config/plugin_architecture_v3.json").read_text("utf-8"))
    policy = json.loads((root / "config/agent_policies/ad_dc.json").read_text("utf-8"))
    manifest = json.loads((root / "config/plugin_packages/sli.ad.agent-v3.json").read_text("utf-8"))
    validate_shape(manifest, schema, schema)
    assert manifest["plugin_id"] == "sli.ad"
    assert manifest["handlers"] == [] and manifest["schedules"] == []
    declaration, history = manifest["agent_modules"]
    assert history["module_id"] == "sli.windows.ad-dc-history"
    assert declaration["module_id"] == "sli.windows.ad-dc"
    assert declaration["policy_schema_ref"] == policy["$id"]
    jobs_manifest = json.loads((root / "config/plugin_packages/sli.ad.jobs-v3.json").read_text("utf-8"))
    assert jobs_manifest["agent_modules"] == []
    configured = module(channels={"System": False}, allow_event_ids=[4624]).config
    validate_shape(configured, policy, policy)
    with pytest.raises(ValueError, match="manifest_shape_invalid"):
        validate_shape({**configured, "channels": {"Security": "false"}}, policy, policy)


class Ledger:
    def __init__(self):
        self.imports = []
        self.entries = []

    def binding(self, *_):
        return {"source_instance_id": HOST, "source_name": SOURCE, "channel": "ad-dc",
                "module_version": "1.0.0", "policy_revision": "1"}

    def get(self, _agent, _module, sequence):
        return next((item for item in self.entries if item["envelope"]["sequence"] == sequence), None)

    def latest(self, *_):
        return self.entries[-1]["envelope"] if self.entries else None

    def packet_exists(self, *_):
        return False

    def quota_error(self, *_):
        return None

    def commit(self, value, receipt, envelope_hash, rows):
        self.entries.append({"envelope": value["envelope"], "receipt": receipt,
                             "envelope_sha256": envelope_hash})
        self.imports.append(rows)


def test_signed_dc_stream_enters_inbox_and_replay_is_idempotent():
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": "sli.windows.ad-dc", "enabled": True, "config": CONFIG}]}
    collector = module({"Security": [(1, xml(4624, 1)), (2, xml(65535, 2))]})
    captured = None
    for sequence in range(1, 5):
        sample = collector.collect(captured, now=NOW)
        value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        receipt = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
        assert receipt["status"] == "committed"
        captured = value["envelope"]
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value,
                          now=NOW)["status"] == "duplicate"
    assert len(ledger.imports) == 4 and len(ledger.imports[0]) == 1


def test_revisioned_dc_policy_skips_channels_without_manual_binding_updates():
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger()
    config = {**CONFIG, "policy_revision": "3", "channels": {"System": False, "Directory Service": False},
              "allow_event_ids": [4624]}
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": "sli.windows.ad-dc", "enabled": True, "config": config}]}
    collector = module({"Security": [(1, xml(4624, 1)), (2, xml(4625, 2))]}, **config)
    captured = None
    for sequence in (1, 2):
        sample = collector.collect(captured, now=NOW)
        value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)["status"] == "committed"
        captured = value["envelope"]
    assert len(ledger.imports[0]) == 1


@pytest.mark.parametrize("mutation", ["other_channel", "filtered_count", "source", "foreign_cursor", "timestamp"])
def test_ingress_rejects_signed_but_inconsistent_dc_packet(mutation):
    key = ec.generate_private_key(ec.SECP256R1())
    sample = module({"Security": [(1, xml(4624, 1))]}).collect(now=NOW)
    if mutation == "other_channel":
        sample.payload["header"]["channel"] = "System"
    elif mutation == "filtered_count":
        sample = replace(sample, filtered_count=3)
    elif mutation == "source":
        sample.payload["header"]["source"] = "fixture-other"
    elif mutation == "timestamp":
        row = sample.payload["records"][0]["payload"]
        row["xml"] = row["xml"].replace(row["time_created"], "invalid")
        row["time_created"] = "invalid"
    else:
        state = json.loads(sample.cursor_after["token"])
        state["channels"]["System"] = {"record_id": 99, "bookmark": "foreign", "generation": HOST}
        sample = replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})
    ledger = Ledger()
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    result = receive_packet(ledger, identity={"id": AGENT, "host_id": HOST,
                            "assigned_modules": ["sli.windows.ad-dc"]},
                            public_key=key.public_key(), value=value, now=NOW)
    assert result["status"] == "rejected" and not ledger.imports


def test_disabled_assignment_cannot_deliver_new_packets():
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger()
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=module().collect(now=NOW), now=NOW)
    result = receive_packet(ledger, identity={"id": AGENT, "host_id": HOST,
        "assigned_modules": [{"module_id": "sli.windows.ad-dc", "enabled": False}]},
        public_key=key.public_key(), value=value, now=NOW)
    assert result["error_code"] == "agent_module_not_assigned" and not ledger.imports
