"""Workstation capture contracts with synthetic Windows API and no database."""
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4
from xml.sax.saxutils import escape

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.sources.collection_packet_import import event_rows_from_packet
from sli_agent.config import AgentConfig
from sli_agent.envelope import make_packet, verify_packet
from sli_agent.modules import configured_modules
from sli_agent.spool import Spool, SpoolFull
from sli_agent.workstations import CHANNELS, POWERSHELL_CHANNEL, WorkstationsModule

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)
HOST = str(uuid4())
AGENT = str(uuid4())
SECURITY = "Microsoft-Windows-Security-Auditing"
DEFENDER = "Microsoft-Windows-Windows Defender/Operational"
DRIVER = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
PNP = "Microsoft-Windows-Kernel-PnP/Configuration"
TASKS = "Microsoft-Windows-TaskScheduler/Operational"


def xml(event_id, record_id, *, channel="Security", provider=SECURITY, data=None):
    fields = "".join(f'<Data Name="{name}">{escape(value)}</Data>'
                     for name, value in (data or {}).items())
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f'<Provider Name="{escape(provider)}"/><EventID>{event_id}</EventID>'
            f'<EventRecordID>{record_id}</EventRecordID><Channel>{escape(channel)}</Channel>'
            f'<TimeCreated SystemTime="2026-10-06T00:00:00Z"/>'
            f'</System><EventData>{fields}</EventData></Event>')


class Reader:
    def __init__(self, events):
        self.events = events
        self.calls = []

    def __call__(self, channel, cursor, limit):
        self.calls.append((channel, deepcopy(cursor), limit))
        return [(xml_text, f"bookmark-{record_id}")
                for record_id, xml_text in self.events.get(channel, [])
                if cursor["record_id"] is None or record_id > cursor["record_id"]][:limit]


def module(events=None, **policy):
    return WorkstationsModule(HOST, policy, reader=Reader(events or {}))


def checkpoint(sample):
    return {"generation": sample.generation, "cursor_after": sample.cursor_after}


@pytest.mark.parametrize("batch_size,expected", [(1, 1), (3, 3), (128, 16)])
def test_full_channel_catches_up_with_durable_bounded_packets_and_keeps_rotation(tmp_path, batch_size, expected):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4688, i)) for i in range(1, 41)]}, batch_size=2)
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    capture_module(collector, spool, identity, now=NOW, batch_size=batch_size, clock=lambda: 0.0)
    packets = spool.pending(now=NOW)
    assert len(packets) == expected
    assert [r["record_id"] for value in packets for r in value["payload"]["records"]] == list(range(1, 2 * expected + 1))
    assert [cursor["record_id"] for _, cursor, _ in collector.reader.calls] == [None, *range(2, 2 * expected, 2)]
    assert spool.captured(collector.module_id)["cursor_after"] == packets[-1]["envelope"]["cursor_after"]
    # After the bound, the next tick visits System, not another Security burst.
    capture_module(collector, spool, identity, now=NOW, batch_size=batch_size, clock=lambda: 0.0)
    assert collector.reader.calls[-1][0] == "System"
    assert len(spool.pending(now=NOW)) == expected + 1


@pytest.mark.parametrize("read_seconds,expected", [(2.5, 2), (6.0, 1)])
def test_workstations_capture_stops_at_cycle_time_budget_and_resumes_rotation(tmp_path, read_seconds, expected):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4688, i)) for i in range(1, 41)]},
                       batch_size=2, families={"protection": False})
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    clock = SimpleNamespace(value=0.0)
    reader = collector.reader

    def timed_read(channel, cursor, limit):
        if cursor["record_id"] is not None:
            persisted = json.loads(spool.captured(collector.module_id)["cursor_after"]["token"])
            assert persisted["channels"][channel] == cursor
        rows = reader(channel, cursor, limit)
        clock.value += read_seconds
        return rows

    collector.reader = timed_read
    capture_module(collector, spool, identity, now=NOW, clock=lambda: clock.value)
    assert len(reader.calls) == expected
    packets = spool.pending(now=NOW)
    assert len(packets) == expected
    assert [r["record_id"] for value in packets for r in value["payload"]["records"]] == list(range(1, 2 * expected + 1))
    assert spool.captured(collector.module_id)["cursor_after"] == packets[-1]["envelope"]["cursor_after"]
    state = json.loads(packets[-1]["envelope"]["cursor_after"]["token"])
    assert state["next"] == 1
    assert state["channels"]["Security"]["record_id"] == 2 * expected

    # Each ordinary tick rotates; the next Security round resumes durable progress.
    for channel in collector.enabled_channels()[1:]:
        capture_module(collector, spool, identity, now=NOW, clock=lambda: clock.value)
        assert reader.calls[-1][0] == channel
    capture_module(collector, spool, identity, now=NOW, clock=lambda: clock.value)
    assert reader.calls[-expected][0:2] == ("Security", state["channels"]["Security"])
    packets = spool.pending(now=NOW)
    assert [r["record_id"] for value in packets for r in value["payload"]["records"]] == list(range(1, 4 * expected + 1))


def test_workstations_capture_spool_failure_does_not_read_past_unpersisted_cursor(tmp_path, monkeypatch):
    from sli_agent.runtime import capture_module

    collector = module({"Security": [(i, xml(4688, i)) for i in range(1, 11)]}, batch_size=2)
    identity = SimpleNamespace(key=ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT)
    spool = Spool(tmp_path, max_bytes=1000000, max_age_seconds=86400)
    capture = spool.capture

    def full(*args, **kwargs):
        if spool.captured(collector.module_id):
            raise SpoolFull("agent_spool_size_limit")
        return capture(*args, **kwargs)

    monkeypatch.setattr(spool, "capture", full)
    with pytest.raises(SpoolFull):
        capture_module(collector, spool, identity, now=NOW, clock=lambda: 0.0)
    assert [cursor["record_id"] for _, cursor, _ in collector.reader.calls] == [None, 2]
    assert len(spool.pending(now=NOW)) == 1
    state = json.loads(spool.captured(collector.module_id)["cursor_after"]["token"])
    assert state["channels"]["Security"]["record_id"] == 2


def test_wire_limited_batch_requests_catchup_without_consuming_the_omitted_row():
    collector = module({"Security": [(i, xml(4688, i, data={"CommandLine": "x" * 5000}))
                                     for i in range(1, 33)]}, batch_size=128)
    first = collector.collect(now=NOW)
    assert collector.catch_up_channel == "Security"
    last = first.payload["header"]["cursor"]["last_record_id"]
    assert last < 32
    second = collector.collect(checkpoint(first), now=NOW, channel=collector.catch_up_channel)
    assert second.payload["records"][0]["record_id"] == last + 1


def test_empty_defender_channel_still_captures_protection_state_and_observation_time():
    from sli_agent.workstations import PROTECTION_COMPONENTS

    state = {"state": "available", "components": dict.fromkeys(PROTECTION_COMPONENTS, True)}
    collector = WorkstationsModule(HOST, {}, reader=Reader({}), protection_reader=lambda: state)
    sample = collector.collect(now=NOW, channel=DEFENDER)
    assert sample.payload["records"] == []
    assert sample.payload["context"]["workstations"]["protection_state"] == state
    assert sample.payload["header"]["observed_at_utc"] == NOW.isoformat()
    collector.policy["families"]["protection"] = False
    with pytest.raises(ValueError, match="channel_invalid"):
        collector.collect(now=NOW, channel=DEFENDER)


def test_defender_catchup_freezes_one_state_per_observation_time():
    from sli_agent.workstations import PROTECTION_COMPONENTS

    calls = []
    def read_state():
        calls.append(True)
        return {"state": "available", "components": dict.fromkeys(PROTECTION_COMPONENTS, len(calls) == 1)}
    collector = WorkstationsModule(HOST, {}, reader=Reader({}), protection_reader=read_state)
    first = collector.collect(now=NOW, channel=DEFENDER)
    second = collector.collect(checkpoint(first), now=NOW, channel=DEFENDER)
    assert first.payload["context"]["workstations"]["protection_state"] == second.payload["context"]["workstations"]["protection_state"]
    assert len(calls) == 1
    third = collector.collect(checkpoint(second), now=NOW + timedelta(seconds=1), channel=DEFENDER)
    assert third.payload["context"]["workstations"]["protection_state"]["components"]["antivirus_enabled"] is False


@pytest.mark.parametrize("failure", ["timeout", "denied", "invalid"])
def test_defender_read_failure_is_unknown_and_redacted(monkeypatch, failure):
    import subprocess
    from sli_agent.workstations import read_protection_state

    def run(args, **kwargs):
        assert kwargs["timeout"] == 5 and kwargs["creationflags"] == 0x08000000
        assert "Get-MpComputerStatus" in args[-1]
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 5, output="fixture-private")
        return SimpleNamespace(returncode=1 if failure == "denied" else 0, stdout="fixture-private")

    monkeypatch.setattr(subprocess, "run", run)
    state = read_protection_state()
    assert state["state"] == "unavailable" and all(v is None for v in state["components"].values())
    assert "fixture-private" not in str(state)


def test_default_off_and_only_explicit_server_assignment_can_enable(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    assert [m.module_id for m in configured_modules(config, HOST)] == ["sli.heartbeat"]
    for assignments in (["sli.workstations"], [{"module_id": "sli.workstations", "enabled": False}],
                        [{"module_id": "unshipped.module", "enabled": True}]):
        assert [m.module_id for m in configured_modules(config, HOST, assignments)] == ["sli.heartbeat"]
    assignments = [{"module_id": "sli.workstations", "enabled": True,
                    "config": {"deny_event_ids": [4688], "policy_revision": "2"}}]
    enabled = configured_modules(config, HOST, assignments)[-1]
    enabled.reader = Reader({"Security": [(1, xml(4688, 1))]})
    sample = enabled.collect(now=NOW)
    assert sample.module_id == "sli.workstations" and sample.policy_revision == "2"
    assert not sample.payload["records"] and sample.filtered_count == 1


@pytest.mark.parametrize("assignments", [None,
    [{"module_id": "sli.workstations", "enabled": "true"}],
    [{"module_id": "sli.workstations", "enabled": True, "config": []}],
    [{"module_id": "sli.workstations"}, {"module_id": "sli.workstations"}]])
def test_malformed_or_duplicate_server_assignments_never_enable_collection(tmp_path, assignments):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    with pytest.raises(ValueError, match="^agent_module_config_invalid$"):
        configured_modules(config, HOST, assignments)


def test_event_allow_deny_and_case_insensitive_process_globs():
    events = {"Security": [(1, xml(4624, 1)), (2, xml(4625, 2)),
        (3, xml(4688, 3, data={"NewProcessName": r"C:\Fixture\keep.exe"})),
        (4, xml(4688, 4, data={"NewProcessName": r"c:/fixture/drop.exe"})),
        (5, xml(4688, 5, data={"NewProcessName": r"C:\Other\keep.exe"})),
        (6, xml(4688, 6))]}
    sample = module(events, allow_event_ids=[4624, 4625, 4688], deny_event_ids=[4625],
        allow_process_paths=["c:/fixture/*.exe"], deny_process_paths=["*/DROP.exe"]).collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [1, 3]
    assert sample.filtered_count == 4 and sample.lost_count == 0
    assert sample.payload["header"]["cursor"]["last_record_id"] == 6


def test_disabled_families_and_family_filters_never_admit_events():
    sample = module({"Security": [(1, xml(4624, 1)), (2, xml(4688, 2)), (3, xml(4625, 3))]},
                    families={"processes": False},
                    family_filters={"logons": {"deny_event_ids": [4625]}}).collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [1]
    assert sample.filtered_count == 2


@pytest.mark.parametrize("families,expected_channels", [
    ({"usb": False, "protection": False}, {"Security"}),
    ({"usb": False}, {"Security", "System", DEFENDER, TASKS, POWERSHELL_CHANNEL}),
])
def test_disabled_family_channels_are_not_read_and_bookmarks_are_preserved(families, expected_channels):
    events = {channel: [(record_id, xml(event_id, record_id, channel=channel, provider=provider))]
              for record_id, (channel, event_id, provider) in enumerate([
                  ("Security", 4624, SECURITY),
                  ("System", 7045, "Service Control Manager"),
                  (DEFENDER, 5001, "Microsoft-Windows-Windows Defender"),
                  (TASKS, 106, "Microsoft-Windows-TaskScheduler"),
                  (DRIVER, 2003, "Microsoft-Windows-DriverFrameworks-UserMode"),
                  (PNP, 400, "Microsoft-Windows-Kernel-PnP"),
              ], start=1)}
    initial = module(events)
    sample = None
    for _ in range(len(CHANNELS)):
        sample = initial.collect(checkpoint(sample) if sample else None, now=NOW)
    saved_channels = json.loads(sample.cursor_after["token"])["channels"]
    collector = module(events, families=families)
    for _ in range(10):
        sample = collector.collect(checkpoint(sample), now=NOW)
        channels = json.loads(sample.cursor_after["token"])["channels"]
        for channel in set(events) - expected_channels:
            assert channels[channel] == saved_channels[channel]
    # System, Defender and TaskScheduler belong to protection; the remaining
    # enabled families use only Security when protection and USB are disabled.
    assert {call[0] for call in collector.reader.calls} == expected_channels
    off = module(families=dict.fromkeys(("logons", "processes", "usb", "local_admins", "protection"), False))
    captured = checkpoint(sample)
    before = deepcopy(captured)
    assert off.collect(captured, now=NOW) is None
    assert not off.reader.calls
    assert captured == before
    resumed = module(events)
    for _ in range(len(CHANNELS)):
        sample = resumed.collect(checkpoint(sample), now=NOW)
        assert not sample.payload["records"]
    for channel, cursor, _ in resumed.reader.calls:
        assert cursor == saved_channels[channel]


@pytest.mark.parametrize("config", [{"families": {"usb": 1}}, {"families": {"unknown": False}},
    {"family_filters": {"processes": {"allow_process_paths": [""]}}},
    {"family_filters": {"logons": {"allow_process_paths": ["*"]}}},
    {"family_filters": {"usb": {"allow_event_ids": [4624]}}}])
def test_invalid_family_policies_are_rejected(config):
    with pytest.raises(ValueError, match="agent_workstations_config_invalid"):
        module(**config)


def test_local_administrators_requires_builtin_sid_and_provider_identity():
    events = {"Security": [(1, xml(4732, 1, data={"TargetSid": "S-1-5-32-544"})),
        (2, xml(4733, 2, data={"TargetSid": "S-1-5-32-545"})),
        (3, xml(4624, 3, provider="fixture-other-provider"))]}
    sample = module(events).collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [1]
    assert sample.filtered_count == 2


def test_rate_limit_is_durable_across_cycles_and_restart_and_counts_drops(tmp_path):
    events = {"Security": [(i, xml(4624, i)) for i in range(1, 5)]}
    collector = module(events, batch_size=2, rate_limits={"4624": 1}, rate_window_seconds=60)
    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    first = spool.capture(key, agent_id=AGENT, sample=collector.collect(now=NOW), now=NOW)
    assert first["envelope"]["lost_count"] == 1
    assert first["payload"]["context"]["workstations"]["dropped_by_event_id"] == {"4624": 1}
    restarted = module(events, batch_size=2, rate_limits={"4624": 1}, rate_window_seconds=60)
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    captured = spool.captured("sli.workstations")
    for _ in range(len(CHANNELS) - 1):
        sample = restarted.collect(captured, now=NOW)
        captured = spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)["envelope"]
    second = restarted.collect(captured, now=NOW)
    assert second.payload["records"] == [] and second.lost_count == 2
    assert second.payload["context"]["workstations"]["dropped_by_event_id"] == {"4624": 2}
    assert second.continuity_state == "gap"
    assert verify_packet(make_packet(key, agent_id=AGENT, sequence=8, sample=second, now=NOW),
                         key.public_key())["lost_count"] == 2
    later = restarted.collect(captured, now=NOW + timedelta(seconds=60))
    assert [r["record_id"] for r in later.payload["records"]] == [3]
    assert later.lost_count == 1


def test_spool_failure_does_not_consume_cursor_or_rate_quota(tmp_path):
    collector = module({"Security": [(1, xml(4624, 1))]}, rate_limits={"4624": 1})
    spool = Spool(tmp_path, max_bytes=1, max_age_seconds=3600)
    key = ec.generate_private_key(ec.SECP256R1())
    sample = collector.collect(now=NOW)
    with pytest.raises(SpoolFull):
        spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    assert spool.captured("sli.workstations") is None
    retry = collector.collect(spool.captured("sli.workstations"), now=NOW)
    assert retry == sample


def test_each_channel_resumes_record_id_and_bookmark_without_duplicates(tmp_path):
    events = {"Security": [(1, xml(4624, 1))], "System": [(7, xml(7045, 7,
        channel="System", provider="Service Control Manager"))]}
    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    collector = module(events)
    for _ in range(len(CHANNELS)):
        spool.capture(key, agent_id=AGENT,
            sample=collector.collect(spool.captured("sli.workstations"), now=NOW), now=NOW)
    restarted = module(events)
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    first = restarted.collect(spool.captured("sli.workstations"), now=NOW)
    assert not first.payload["records"]
    assert restarted.reader.calls[0][1] == {"record_id": 1, "bookmark": "bookmark-1", "generation": HOST}
    spool.capture(key, agent_id=AGENT, sample=first, now=NOW)
    second = restarted.collect(spool.captured("sli.workstations"), now=NOW)
    assert not second.payload["records"]
    assert restarted.reader.calls[-1][1] == {"record_id": 7, "bookmark": "bookmark-7", "generation": HOST}


@pytest.mark.parametrize("event_id,channel,provider,data", [
    *[(n, "Security", SECURITY, {"LogonType": "10"}) for n in (4624, 4625, 4634, 4647)],
    *[(n, "Security", SECURITY, {}) for n in (4688, 4697, 4698, 4699, 4700, 4701, 4702, 4719, 6416)],
    *[(n, "Security", SECURITY, {"TargetSid": "S-1-5-32-544"}) for n in (4732, 4733)],
    (7045, "System", "Service Control Manager", {}),
    *[(n, DEFENDER, "Microsoft-Windows-Windows Defender", {}) for n in (5001, 5010, 5012)],
    *[(n, PNP, "Microsoft-Windows-Kernel-PnP", {"DeviceId": r"USBSTOR\fixture"}) for n in (400, 410, 420)],
    *[(n, DRIVER, "Microsoft-Windows-DriverFrameworks-UserMode", {"DeviceId": r"USBSTOR\fixture"})
      for n in (2003, 2100, 2101)],
    (106, TASKS, "Microsoft-Windows-TaskScheduler", {}),
])
def test_stage7a_source_payload_fields_and_native_xml_are_preserved(event_id, channel, provider, data):
    raw = xml(event_id, 17, channel=channel, provider=provider, data=data)
    collector = module({channel: [(17, raw)]})
    captured = None
    for _ in range(len(CHANNELS)):
        sample = collector.collect(captured, now=NOW)
        captured = checkpoint(sample)
        if sample.payload["header"]["channel"] == channel:
            break
    rows = event_rows_from_packet(sample.payload)
    assert len(rows) == 1
    row = rows[0]
    assert (row["event_id"], row["record_id"], row["channel"], row["provider_name"], row["time_created"]) == (
        event_id, 17, channel, provider, "2026-10-06T00:00:00Z")
    assert row["xml"] == raw
    assert sample.payload["contract"] == "sli.collection-packet.v1"
    assert sample.payload["header"]["generation"] == HOST
    assert row["computer_name"] == HOST


@pytest.mark.parametrize("policy", [{"allow_event_ids": [True]}, {"deny_event_ids": "4624"},
    {"rate_limits": {"4624": -1}}, {"rate_window_seconds": 0}, {"batch_size": 0},
    {"allow_process_paths": [""]}, {"unknown_option": True}])
def test_bad_policy_fails_closed_with_safe_code(policy):
    with pytest.raises(ValueError, match="^agent_workstations_config_invalid$"):
        module(**policy)


def test_wrong_record_order_fails_without_advancing_cursor():
    collector = module()
    collector.reader = lambda *a: [(xml(4624, 2), "b2"), (xml(4624, 1), "b1")]
    with pytest.raises(ValueError, match="agent_workstations_range_invalid"):
        collector.collect(now=NOW)


def test_rate_counters_are_separate_by_event_id_and_deny_does_not_consume_quota():
    events = {"Security": [(1, xml(4624, 1)), (2, xml(4624, 2)),
        (3, xml(4625, 3)), (4, xml(4625, 4)), (5, xml(4688, 5))]}
    sample = module(events, rate_limits={"4624": 1, "4625": 0, "4688": 0},
                    deny_event_ids=[4688]).collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [1]
    assert sample.lost_count == 3 and sample.filtered_count == 1
    assert sample.payload["context"]["workstations"]["dropped_by_event_id"] == {"4624": 1, "4625": 2}


def test_channel_generation_reset_is_explicit_and_other_channel_progress_survives():
    events = {"Security": [(1, xml(4624, 1))], "System": [(7, xml(7045, 7,
        channel="System", provider="Service Control Manager"))]}
    original = module(events)
    captured = None
    for _ in range(len(CHANNELS)):
        captured = checkpoint(original.collect(captured, now=NOW))
    changed = module(events, channel_generations={"Security": "fixture-new-generation"})
    sample = changed.collect(captured, now=NOW)
    assert sample.continuity_state == "gap"
    assert sample.payload["header"]["generation"] == "fixture-new-generation"
    assert sample.payload["header"]["cursor"] == {"after_record_id": None, "last_record_id": 1}
    assert sample.payload["context"]["workstations"]["channel_reset"] is True
    other = changed.collect(checkpoint(sample), now=NOW)
    assert not other.payload["records"]
    assert other.payload["header"]["cursor"] == {"after_record_id": 7, "last_record_id": 7}


def test_packet_budget_defers_unconsumed_event_and_oversized_event_pauses():
    events = {"Security": [(i, xml(4688, i, data={"NewProcessName": "x" * 12000})) for i in (1, 2)]}
    collector = module(events)
    first = collector.collect(now=NOW)
    assert [r["record_id"] for r in first.payload["records"]] == [1]
    assert first.payload["header"]["cursor"]["last_record_id"] == 1
    captured = checkpoint(first)
    for _ in range(len(CHANNELS) - 1):
        captured = checkpoint(collector.collect(captured, now=NOW))
    next_sample = collector.collect(captured, now=NOW)
    assert [r["record_id"] for r in next_sample.payload["records"]] == [2]
    giant = module({"Security": [(1, xml(4688, 1, data={"NewProcessName": "x" * 50000}))]})
    with pytest.raises(ValueError, match="agent_workstations_event_size_limit"):
        giant.collect(now=NOW)


def test_corrupt_cursor_and_duplicate_named_fields_fail_closed():
    collector = module()
    with pytest.raises(ValueError, match="agent_workstations_cursor_invalid"):
        collector.collect({"generation": HOST, "cursor_after": {"strategy": "bookmark", "token": "{}"}}, now=NOW)
    raw = xml(4624, 1, data={"LogonType": "10"}).replace(
        "</EventData>", '<Data Name="LogonType">3</Data></EventData>')
    collector.reader = Reader({"Security": [(1, raw)]})
    with pytest.raises(ValueError, match="agent_workstations_duplicate_event_field"):
        collector.collect(now=NOW)


def test_unavailable_channel_reports_unknown_gap_and_does_not_starve_other_channels():
    collector = module({"Security": [(1, xml(4624, 1))], "System": [(7, xml(7045, 7,
        channel="System", provider="Service Control Manager"))]})
    reader = collector.reader
    sample = collector.collect(now=NOW)
    before = checkpoint(sample)
    collector.reader = lambda *args: (_ for _ in ()).throw(OSError("fixture-private-diagnostic"))
    failed = collector.collect(before, now=NOW)
    assert failed.continuity_state == "gap" and failed.lost_count is None
    assert failed.payload["header"]["cursor"] == {"after_record_id": None, "last_record_id": None}
    assert failed.payload["context"]["workstations"]["read_error"] == "agent_workstations_read_failed"
    assert "private-diagnostic" not in str(failed.payload)
    collector.reader = reader
    captured = checkpoint(failed)
    for _ in range(len(CHANNELS) - 1):
        captured = checkpoint(collector.collect(captured, now=NOW))
    recovered = collector.collect(captured, now=NOW)
    assert [r["record_id"] for r in recovered.payload["records"]] == [7]


def test_runtime_refreshes_assignment_and_stops_plugin_on_config_failure(tmp_path, monkeypatch):
    from sli_agent import runtime
    # This test isolates assignment refresh; rights have their own fake matrix.
    monkeypatch.setattr(runtime, "service_identity_verified", lambda config: True)
    monkeypatch.setattr(runtime, "probe", lambda *a, **kw: {"identity_verified": True, "ready": True, "checks": []})
    identity = SimpleNamespace(agent_id=AGENT, key=ec.generate_private_key(ec.SECP256R1()))
    monkeypatch.setattr(runtime, "IdentityStore", lambda config: SimpleNamespace(
        prepare=lambda: {"host_id": HOST}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    reader = Reader({"Security": [(1, xml(4624, 1))]})
    monkeypatch.setattr("sli_agent.workstations.read_local", reader)
    responses = iter([
        {"agent_id": AGENT, "assigned_modules": [{"module_id": "sli.workstations", "enabled": True}]},
        {"agent_id": AGENT, "assigned_modules": [{"module_id": "sli.workstations", "enabled": False}]},
        OSError("fixture-private-diagnostic"),
        {"agent_id": str(uuid4()), "assigned_modules": [{"module_id": "sli.workstations", "enabled": True}]},
    ])
    class Transport:
        def get(self, path, *, identity):
            assert path == "/api/v1/agent/identity" and identity.agent_id == AGENT
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response
        def post(self, path, body, *, identity):
            envelope = body["envelope"]
            return {"contract_id": "sli.agent-receipt.v1", "packet_id": envelope["packet_id"],
                "payload_sha256": envelope["payload_sha256"], "status": "committed",
                "committed_cursor": envelope["cursor_after"], "evidence_ref": "fixture",
                "committed_at_utc": NOW.isoformat(), "error_code": None}
    monkeypatch.setattr(runtime, "Transport", lambda config: Transport())
    class Stop:
        cycles = 0
        statuses = []
        def is_set(self):
            return self.cycles == 4
        def wait(self, delay):
            self.statuses.append(json.loads((tmp_path / "status.json").read_text()))
            self.cycles += 1
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    stop = Stop()
    runtime.run(config, stop)
    spool = Spool(tmp_path / "spool", max_bytes=100000, max_age_seconds=3600)
    assert spool.captured("sli.workstations")["sequence"] == 1
    assert len(reader.calls) == 1
    # An unavailable policy cannot authorize new spool writes; check-in is
    # still attempted in every cycle, and existing packets remain durable.
    assert spool.captured("sli.heartbeat")["sequence"] == 2
    assert stop.statuses[0]["collection_enabled"] is True
    assert stop.statuses[0]["enabled_modules"] == ["sli.heartbeat", "sli.workstations"]
    assert all(status["collection_enabled"] is False for status in stop.statuses[1:])
    status = json.loads((tmp_path / "status.json").read_text())
    assert status["error_code"] == "agent_module_config_unavailable"
    assert "private-diagnostic" not in str(status)


def test_native_reader_bookmark_seek_and_handle_cleanup(monkeypatch):
    import sys

    from sli_agent.workstations import read_local
    handles = []
    class Handle:
        def __init__(self, name):
            self.name, self.closed = name, False
            handles.append(self)
        def Close(self):
            self.closed = True
    query, event, bookmark = Handle("query"), Handle("event"), Handle("bookmark")
    anchor = Handle("anchor")
    seen = {}
    batches = iter([[anchor], [event]])
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
        EvtRenderEventXml=1, EvtRenderBookmark=2, EvtSeekRelativeToBookmark=4, EvtSeekStrict=8,
        EvtQuery=lambda channel, flags, xpath, session: seen.update(query=(channel, flags, xpath, session)) or query,
        EvtNext=lambda *a: next(batches), EvtCreateBookmark=lambda text: bookmark,
        EvtSeek=lambda query, position, **kw: seen.update(seek=(query, position, kw)),
        EvtUpdateBookmark=lambda *a: None,
        EvtRender=lambda handle, flags: xml(4624, 7 if handle is anchor else 8) if flags == 1 else "fixture-bookmark")
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    assert read_local("Security", {"record_id": 7, "bookmark": "previous"}, 2) == [
        (xml(4624, 8), "fixture-bookmark")]
    assert seen["query"] == ("Security", 3, "*", None)
    assert seen["seek"] == (query, 0, {"Flags": 12, "Bookmark": bookmark, "Timeout": 0})
    assert all(handle.closed for handle in handles)


@pytest.mark.parametrize("tail", [False, True])
@pytest.mark.parametrize("native_code,opt_in,recovered", [(1168, True, True),
    (1168, False, False), (5, True, False), (15011, True, False)])
def test_missing_bookmark_recovery_is_explicit_bounded_and_closes_handles(
        monkeypatch, native_code, opt_in, recovered, tail):
    import sys

    from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch, read_local
    closed, selectors = [], []
    class NativeError(Exception):
        winerror = native_code
    def query(channel, flags, xpath, session):
        selectors.append(xpath)
        name = "query-" + str(len(selectors))
        return SimpleNamespace(Close=lambda: closed.append(name))
    def seek(*args, **kwargs):
        raise NativeError("fixture-private-event")
    def next_events(*args):
        assert args[1:] == (2, 1000, 0)
        if tail:
            exc = NativeError("fixture-private-event")
            exc.winerror = 259
            raise exc
        return [event]
    bookmark = SimpleNamespace(Close=lambda: closed.append("bookmark"))
    event = SimpleNamespace(Close=lambda: closed.append("event"))
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
        EvtRenderEventXml=1, EvtRenderBookmark=2, EvtSeekRelativeToBookmark=4, EvtSeekStrict=8,
        error=NativeError, EvtQuery=query, EvtCreateBookmark=lambda text: bookmark,
        EvtSeek=seek, EvtNext=next_events, EvtUpdateBookmark=lambda *args: None,
        EvtRender=lambda handle, flags: xml(4624, 9) if flags == 1 else "bookmark-9")
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    cursor = {"record_id": 7, "bookmark": "bookmark-7"}
    if recovered:
        batch = read_local("Security", cursor, 2, recover_missing_bookmark=opt_in)
        assert isinstance(batch, BookmarkRecoveryBatch)
        assert batch == ([] if tail else [(xml(4624, 9), "bookmark-9")])
        assert selectors == ["*", "*[System[EventRecordID > 7]]"]
        assert closed == ["bookmark", "query-1", *([] if tail else ["event"]), "bookmark", "query-2"]
    else:
        with pytest.raises(RuntimeError) as failure:
            read_local("Security", cursor, 2, recover_missing_bookmark=opt_in)
        assert failure.value.diagnostic["stage"] == "seek"
        assert failure.value.diagnostic["winerror"] == native_code
        assert selectors == ["*"]
        assert closed == ["bookmark", "query-1"]
    assert cursor == {"record_id": 7, "bookmark": "bookmark-7"}


@pytest.mark.parametrize("retry_stage", ["query", "read"])
def test_missing_bookmark_retry_failure_preserves_diagnostic_and_checkpoint(monkeypatch, retry_stage):
    import sys

    from sli_agent.workstations import read_local
    closed, queries = [], []
    class NativeError(Exception):
        def __init__(self, code):
            self.winerror = code
    def fail(code):
        raise NativeError(code)
    def query(*args):
        queries.append(args[2])
        if len(queries) == 2 and retry_stage == "query":
            fail(5)
        name = "query-" + str(len(queries))
        return SimpleNamespace(Close=lambda: closed.append(name))
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
        EvtSeekRelativeToBookmark=4, EvtSeekStrict=8, error=NativeError, EvtQuery=query,
        EvtCreateBookmark=lambda text: SimpleNamespace(Close=lambda: closed.append("bookmark")),
        EvtSeek=lambda *args, **kwargs: fail(1168), EvtNext=lambda *args: fail(5))
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    cursor = {"record_id": 7, "bookmark": "bookmark-7"}
    with pytest.raises(RuntimeError) as failure:
        read_local("Security", cursor, 2)
    assert failure.value.diagnostic["stage"] == retry_stage
    assert failure.value.diagnostic["winerror"] == 5
    assert queries == ["*", "*[System[EventRecordID > 7]]"]
    assert cursor == {"record_id": 7, "bookmark": "bookmark-7"}
    assert closed == ["bookmark", "query-1", *(["bookmark", "query-2"] if retry_stage == "read" else [])]


@pytest.mark.parametrize("rows", [[], [(xml(4624, 9), "bookmark-9")],
    [(xml(9999, 9), "bookmark-9")]])
def test_recovered_bookmark_preserves_cursor_contract_and_unknown_gap(rows):
    from server.sli.agents.workstation_ingest import workstation_rows
    from sli_collect.bookmarked_eventlog import BookmarkRecoveryBatch
    collector = module({"Security": [(7, xml(4624, 7))]})
    captured = None
    for _ in range(len(CHANNELS)):
        captured = checkpoint(collector.collect(captured, now=NOW))
    old = deepcopy(captured)
    collector.reader = lambda *args: BookmarkRecoveryBatch(rows)
    sample = collector.collect(captured, now=NOW)
    assert captured == old
    assert sample.continuity_state == "gap" and sample.lost_count is None
    assert sample.payload["context"]["workstations"]["bookmark_recovered"] is True
    assert sample.payload["context"]["workstations"]["channel_reset"] is False
    state = json.loads(sample.cursor_after["token"])
    assert state["channels"]["Security"]["record_id"] == (9 if rows else 7)
    assert state["channels"]["System"] == json.loads(captured["cursor_after"]["token"])["channels"]["System"]
    key = ec.generate_private_key(ec.SECP256R1())
    packet = make_packet(key, agent_id=AGENT, sequence=8, sample=sample, now=NOW)
    identity = {"host_id": HOST, "assigned_modules": [{"module_id": "sli.workstations",
        "enabled": True, "config": {}}]}
    admitted = workstation_rows(identity, packet["envelope"], packet["payload"])
    assert len(admitted) == (1 if rows and "<EventID>4624" in rows[0][0] else 0)
    forged = deepcopy(packet)
    forged["envelope"]["lost_count"] = 0
    with pytest.raises(ValueError, match="agent_workstations_continuity_invalid"):
        workstation_rows(identity, forged["envelope"], forged["payload"])
    forged = deepcopy(packet)
    forged["payload"]["context"]["workstations"]["bookmark_recovered"] = "true"
    with pytest.raises(ValueError, match="agent_workstations_continuity_invalid"):
        workstation_rows(identity, forged["envelope"], forged["payload"])
    collector.reader = Reader({"Security": [(10, xml(4624, 10))]})
    captured = checkpoint(sample)
    for _ in range(len(CHANNELS) - 1):
        captured = checkpoint(collector.collect(captured, now=NOW))
    resumed = collector.collect(captured, now=NOW)
    assert [r["record_id"] for r in resumed.payload["records"]] == [10]
    assert resumed.continuity_state == "not_proven"


@pytest.mark.parametrize("error_code,bookmark_text", [(259, "previous"), (5, "previous"), (5, "")])
def test_native_reader_at_tail_or_access_failure_closes_handles_and_hides_diagnostics(
        monkeypatch, error_code, bookmark_text):
    import sys

    from sli_agent.workstations import read_local
    closed = []
    query = SimpleNamespace(Close=lambda: closed.append("query"))
    bookmark = SimpleNamespace(Close=lambda: closed.append("bookmark"))
    anchor = SimpleNamespace(Close=lambda: closed.append("anchor"))
    class WindowsError(Exception):
        winerror = error_code
    def next_events(*args):
        if args[1] == 1 and bookmark_text:
            return [anchor]
        raise WindowsError("fixture-private-diagnostic")
    backend = SimpleNamespace(EvtQueryChannelPath=1, EvtQueryForwardDirection=2,
        EvtRenderEventXml=1, EvtSeekRelativeToBookmark=4, EvtSeekStrict=8, error=WindowsError,
        EvtQuery=lambda *a: query, EvtCreateBookmark=lambda text: bookmark,
        EvtNext=next_events, EvtSeek=lambda *a, **kw: None, EvtRender=lambda *a: xml(4624, 7))
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    if error_code == 259:
        assert read_local("Security", {"record_id": 7, "bookmark": bookmark_text}, 2) == []
    else:
        with pytest.raises(RuntimeError, match="^agent_workstations_read_failed$") as failure:
            read_local("Security", {"record_id": 7 if bookmark_text else None, "bookmark": bookmark_text}, 2)
        assert failure.value.diagnostic == {
            "exception_class": "WindowsError", "winerror": 5, "hresult": None,
            "channel": "Security", "record_id": 7 if bookmark_text else None,
            "bookmark_present": bool(bookmark_text), "stage": "read",
        }
        assert "fixture-private-diagnostic" not in repr(failure.value.diagnostic)
    assert set(closed) == ({"query", "bookmark", "anchor"} if bookmark_text else {"query", "bookmark"})
