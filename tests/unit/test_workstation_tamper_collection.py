"""Synthetic T109c agent -> signed packet -> server -> retained rule evidence."""
import json
from copy import deepcopy
from contextlib import nullcontext
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agents.workstation_ingest import workstation_rows
from server.sli.agent_ingest import receive_packet
from server.sli.plugins.workstations.contracts import Workstation
from server.sli.sources.collection_packet_import import import_workstation_packet
from server.sli.sigma.windows_mapping import EventScope, map_windows_event
from server.sli.sigma.workstation_evidence import WorkstationEvidenceRef, read_workstation_evidence
from sli_agent.envelope import make_packet, verify_packet
from sli_agent.workstations import CHANNELS, POWERSHELL_CHANNEL, WorkstationsModule
from tests.unit.test_sli_agent_workstations import AGENT, HOST, NOW, Reader, checkpoint, xml
from tests.unit.test_workstations_plugin import Cursor, connection
from tests.unit.test_agent_dotnet_vectors import Ledger

SCM = "Service Control Manager"
PS = "Microsoft-Windows-PowerShell"
EVENTLOG = "Microsoft-Windows-Eventlog"


class WorkstationLedger(Ledger):
    def workstation_counts(self, *_):
        return {"4104": sum(r["payload"]["event_id"] == 4104 for entry in self.entries for r in entry["records"])}


def fixture(event_id, record_id, channel, provider, data):
    raw = xml(event_id, record_id, channel=channel, provider=provider, data=data)
    raw = raw.replace("</System>", f"<Version>{1 if event_id == 4104 else 0}</Version>"
                      "<Computer>fixture.test</Computer></System>")
    if event_id == 1102:
        raw = raw.replace("<EventData></EventData>", '<UserData><LogFileCleared '
            'xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
            '<SubjectUserName>fixture</SubjectUserName></LogFileCleared></UserData>')
    return raw


def samples(events, config=None):
    collector = WorkstationsModule(HOST, config or {}, reader=Reader(events),
        protection_reader=lambda: {"state": "unavailable", "components": dict.fromkeys(
            ("antivirus_enabled", "real_time_protection_enabled", "behavior_monitor_enabled",
             "ioav_protection_enabled", "nis_enabled", "tamper_protected"))})
    captured = None
    for _ in CHANNELS:
        sample = collector.collect(captured, now=NOW)
        captured = checkpoint(sample)
        yield sample


@pytest.mark.parametrize("event_id,channel,provider,data,fact,value", [
    (1102, "Security", EVENTLOG, {}, "log_cleared", True),
    (7036, "System", SCM, {"param1": "SLI Agent .NET", "param2": "stopped"}, "service_state", "stopped"),
    (7040, "System", SCM, {"param1": "fixture backup", "param2": "auto", "param3": "disabled",
                           "param4": "FixtureBackup"}, "start_type", "disabled"),
    (4104, POWERSHELL_CHANNEL, PS, {"ScriptBlockText": "fixture-script"}, "script_block_text", "fixture-script"),
])
def test_agent_packet_ingest_projection_and_sigma(event_id, channel, provider, data, fact, value):
    config = {"protected_services": ["FixtureBackup"]}
    raw = fixture(event_id, 1, channel, provider, data)
    key = ec.generate_private_key(ec.SECP256R1())
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [{"module_id": "sli.workstations", "enabled": True, "config": config}]}
    ledger = WorkstationLedger()
    cur = Cursor()
    station = Workstation(HOST, 17)
    for sequence, sample in enumerate(samples({channel: [(1, raw)]}, config), 1):
        signed = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        assert verify_packet(signed, key.public_key())["module_version"] == "1.1.0"
        rows = workstation_rows(identity, signed["envelope"], signed["payload"])
        receipt = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=signed, now=NOW)
        assert receipt["status"] == "committed", receipt["error_code"]
        if not rows:
            continue
        result = import_workstation_packet(connection(cur), sample.payload, agent_key=HOST,
            identity=SimpleNamespace(workstation=lambda *_: station))
        assert result == {"observed": 1, "inserted": 1, "ignored": 0}
        body = next(iter(cur.stored.values()))["observation"]
        assert body["family"] == "protection" and body["facts"][fact] == value
        event = map_windows_event(rows[0]["xml"], scope=EventScope("fixture", HOST, HOST))
        assert event.fields["EventID"] == event_id
        if event_id == 1102:
            assert event.fields["SubjectUserName"] == "fixture"
        else:
            assert all(event.fields[k] == v for k, v in data.items())
        observation_id, stored = next(iter(cur.stored.items()))
        hot = {**body, "id": observation_id, "observation": body,
               "observation_sha256": stored["observation_sha256"], "source_xml": rows[0]["xml"]}
        pg = SimpleNamespace(execute=lambda sql, params: None, fetchall=lambda: [hot])
        evidence = read_workstation_evidence(SimpleNamespace(cursor=lambda: nullcontext(pg)),
            ref=WorkstationEvidenceRef(observation_id, stored["observation_sha256"], body["source_sha256"]),
            scope=EventScope("fixture", HOST, HOST), agent_key=HOST,
            start=NOW - timedelta(minutes=1), end=NOW + timedelta(minutes=1), family="protection")
        assert evidence.event.fields["EventID"] == event_id
    assert len(cur.stored) == 1


@pytest.mark.parametrize("event_id", [7036, 7040])
def test_only_exact_protection_or_policy_services_are_collected(event_id):
    names = ["Spooler", "SLIAgentNet", "WinDefend", "Sense", "VSS", "wbengine", "FixtureBackup",
             "Теневое копирование тома", "SLIAgentNet-extra"]
    events = [(i, fixture(event_id, i, "System", SCM, {"param1": name, "param2": "stopped"}))
              for i, name in enumerate(names, 1)]
    sample = next(s for s in samples({"System": events}, {"protected_services": ["FixtureBackup"]})
                  if s.payload["header"]["channel"] == "System")
    assert [r["record_id"] for r in sample.payload["records"]] == list(range(2, 9))
    assert sample.filtered_count == 2


@pytest.mark.parametrize("text", ["x" * 30000, "Я" * 15000, "😀" * 10000, "<&\"" * 10000],
                         ids=["ascii", "cyrillic", "astral", "escaped"])
def test_script_is_bounded_in_all_packet_copies_and_marked(text):
    raw = fixture(4104, 1, POWERSHELL_CHANNEL, PS, {"ScriptBlockText": text})
    sample = next(s for s in samples({POWERSHELL_CHANNEL: [(1, raw)]})
                  if s.payload["header"]["channel"] == POWERSHELL_CHANNEL)
    row = sample.payload["records"][0]["payload"]
    event = map_windows_event(row["xml"], scope=EventScope("fixture", HOST, HOST))
    bounded = event.fields["ScriptBlockText"]
    assert text.startswith(bounded) and len(bounded.encode("utf-8")) <= 8192
    assert event.fields["ScriptBlockTextTruncated"] == "true"
    assert text not in json.dumps(sample.payload, ensure_ascii=False)
    assert row["properties"][0] == bounded
    assert len(json.dumps(sample.payload).encode()) < 44 * 1024


def test_hard_script_quota_survives_catchup_restart_and_cannot_be_raised():
    config = {"rate_limits": {"4104": 999}, "batch_size": 4}
    events = {POWERSHELL_CHANNEL: [(i, fixture(4104, i, POWERSHELL_CHANNEL, PS, {"ScriptBlockText": "fixture"}))
                                    for i in range(1, 25)]}
    position = None
    admitted = dropped = 0
    for _ in range(6):
        collector = WorkstationsModule(HOST, config, reader=Reader(events))
        sample = collector.collect(position, now=NOW, channel=POWERSHELL_CHANNEL)
        position = checkpoint(sample)
        admitted += len(sample.payload["records"])
        dropped += sample.lost_count
    assert (admitted, dropped) == (10, 14)
    assert json.loads(position["cursor_after"]["token"])["rate"]["counts"]["4104"] == 10
    assert sample.continuity_state == "gap"


@pytest.mark.parametrize("event_id", [4103, 4105, 4106])
def test_other_powershell_event_ids_are_never_collected(event_id):
    raw = fixture(event_id, 1, POWERSHELL_CHANNEL, PS, {})
    collector = WorkstationsModule(HOST, {}, reader=Reader({POWERSHELL_CHANNEL: [(1, raw)]}))
    sample = collector.collect(now=NOW, channel=POWERSHELL_CHANNEL)
    assert not sample.payload["records"] and sample.filtered_count == 1


def test_server_rejects_unbounded_script_and_unprotected_service():
    config = {}
    for event_id, channel, provider, original, forged in [
        (7036, "System", SCM, {"param1": "VSS"}, {"param1": "Spooler"}),
        (4104, POWERSHELL_CHANNEL, PS, {"ScriptBlockText": "fixture"}, {"ScriptBlockText": "x" * 9000}),
    ]:
        sample = next(s for s in samples({channel: [(1, fixture(event_id, 1, channel, provider, original))]})
                      if s.payload["header"]["channel"] == channel)
        signed = make_packet(ec.generate_private_key(ec.SECP256R1()), agent_id=AGENT, sequence=1, sample=sample, now=NOW)
        from sli_collect.eventlog import parse_event_xml
        bad = deepcopy(signed["payload"])
        bad["records"][0]["payload"] = parse_event_xml(fixture(event_id, 1, channel, provider, forged),
            source_name=HOST, connect_address="localhost", channel=channel)
        identity = {"host_id": HOST, "assigned_modules": [{"module_id": "sli.workstations", "enabled": True, "config": config}]}
        with pytest.raises(ValueError, match="agent_workstations_(policy_invalid|field_size_limit)"):
            workstation_rows(identity, signed["envelope"], bad)


def test_legacy_queue_rotation_and_upgrade_keep_their_cursors():
    legacy = WorkstationsModule(HOST, {}, reader=Reader({}))
    legacy.channels = CHANNELS[:-1]
    position = None
    identity = {"host_id": HOST, "assigned_modules": [{"module_id": "sli.workstations", "enabled": True, "config": {}}]}
    key = ec.generate_private_key(ec.SECP256R1())
    for sequence in range(1, 8):
        sample = replace(legacy.collect(position, now=NOW), module_version="1.0.0")
        signed = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        assert workstation_rows(identity, signed["envelope"], sample.payload) == []
        position = checkpoint(sample)
    upgraded = WorkstationsModule(HOST, {}, reader=Reader({}))
    sample = upgraded.collect(position, now=NOW)
    assert sample.payload["header"]["channel"] == "System"
    signed = make_packet(key, agent_id=AGENT, sequence=8, sample=sample, now=NOW)
    assert workstation_rows(identity, signed["envelope"], sample.payload) == []


def test_server_enforces_script_quota_across_catchup_and_other_channels():
    events = {POWERSHELL_CHANNEL: [(i, fixture(4104, i, POWERSHELL_CHANNEL, PS, {"ScriptBlockText": "fixture"}))
                                  for i in range(1, 17)]}
    config = {"batch_size": 4}
    identity = {"host_id": HOST, "assigned_modules": [{"module_id": "sli.workstations", "enabled": True, "config": config}]}
    key = ec.generate_private_key(ec.SECP256R1())
    collector = WorkstationsModule(HOST, config, reader=Reader(events))
    position = None
    for sequence in range(1, 11):
        sample = collector.collect(position, now=NOW, channel=POWERSHELL_CHANNEL if sequence > 7 else None)
        signed = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
        workstation_rows(identity, signed["envelope"], sample.payload)
        position = checkpoint(sample)
    assert sample.lost_count == 4
    next_sample = collector.collect(position, now=NOW)
    signed = make_packet(key, agent_id=AGENT, sequence=11, sample=next_sample, now=NOW)
    state = json.loads(signed["envelope"]["cursor_after"]["token"])
    state["rate"]["counts"]["4104"] = 0
    signed["envelope"]["cursor_after"]["token"] = json.dumps(state)
    with pytest.raises(ValueError, match="agent_workstations_rate_invalid"):
        workstation_rows(identity, signed["envelope"], next_sample.payload)
