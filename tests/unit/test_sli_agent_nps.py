"""NPS capture/ingress contracts, without Windows APIs or a database."""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import csv
import io
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from server.sli.agent_ingest import receive_packet
from server.sli.agents.assignments import validate_assignment
from sli_agent.config import AgentConfig
from sli_agent.envelope import make_packet
from sli_agent.modules import configured_modules
from sli_agent.spool import Spool
from sli_agent.nps import AccountingModule, NPSModule, ACCOUNTING_MODULE, NPS_MODULE, bookmark_state
from sli_collect.radius_accounting import DATABASE_COMPATIBLE_COLUMNS, parse_database_compatible_record
from sli_collect.radius_contract import initial_cursor
from sli_collect.radius_tail import RadiusTailBatch, derive_file_generation
from tests.unit.test_agent_ingest import Ledger

NOW = datetime(2026, 10, 8, tzinfo=timezone.utc)
HOST = str(uuid4())
AGENT = str(uuid4())
CONFIG = {"source_instance_id": "fixture-radius", "source_name": "fixture-nps",
          "connect_address": "fixture-endpoint"}


def event(event_id=6272, record_id=1, extra="", provider="Microsoft-Windows-Security-Auditing"):
    return (f'<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
        f'<Provider Name="{provider}"/><EventID>{event_id}</EventID><EventRecordID>{record_id}</EventRecordID>'
        '<Channel>Security</Channel><Computer>fixture-nps</Computer>'
        '<TimeCreated SystemTime="2026-10-08T00:00:00Z"/></System><EventData>'
        '<Data Name="SubjectUserName">fixture-account</Data><Data Name="SubjectDomainName">FIXTURE</Data>'
        '<Data Name="NetworkPolicyName">fixture-policy</Data><Data Name="ReasonCode">16</Data>'
        '<Data Name="NASIdentifier">fixture-gateway</Data>' + extra + '</EventData></Event>')


def accounting_line(status="1", packet_type="4", minute="00"):
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    for name, value in {"ComputerName": "fixture-nps", "ServiceName": "IAS", "Record-Date": "10/08/2026",
        "Record-Time": f"00:{minute}:00", "Packet-Type": packet_type, "Acct-Status-Type": status,
        "NAS-Identifier": "fixture-gateway", "Acct-Session-Id": "fixture-session", "Class": "fixture-class",
        "Fully-Qualified-Distinguished-Name": "CN=fixture-account,DC=fixture,DC=invalid"}.items():
        row[DATABASE_COMPATIBLE_COLUMNS.index(name)] = value
    output = io.StringIO()
    csv.writer(output).writerow(row)
    return output.getvalue().rstrip("\r\n")


def accounting_config(tmp_path, *, generation="fixture-generation"):
    cursor = initial_cursor(source_instance_id=CONFIG["source_instance_id"], transport_binding="fixture-tail",
                            file_generation=generation)
    return {"source_instance_id": cursor.source_instance_id, "accounting_directory": str(tmp_path),
            "initial_cursor": asdict(cursor), "subscription_id": "fixture-subscription",
            "source_timezone_id": "UTC", "source_utc_offset_minutes": 0}


def test_accounting_fixture_preserves_csv_columns_and_distinguished_name():
    line = accounting_line()
    assert len(next(csv.reader([line], strict=True))) == len(DATABASE_COMPATIBLE_COLUMNS)
    parsed = parse_database_compatible_record(line)
    assert parsed.distinguished_name == "CN=fixture-account,DC=fixture,DC=invalid"
    assert parsed.account_session_id == "fixture-session"
    assert parsed.accounting_status == "start"


def signed(sample, config, *, sequence=1, ledger=None):
    ledger = ledger or Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": sample.module_id, "enabled": True, "config": config}]}
    key = ec.generate_private_key(ec.SECP256R1())
    value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=NOW)
    return ledger, identity, key, value


def receive(context):
    ledger, identity, key, value = context
    return receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)


def test_default_disabled_explicit_opt_in_and_family_pause(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path)
    assert [m.module_id for m in configured_modules(config, HOST)] == ["sli.heartbeat"]
    assert len(configured_modules(config, HOST, [NPS_MODULE, ACCOUNTING_MODULE])) == 1
    assigned = [{"module_id": NPS_MODULE, "enabled": True, "config": CONFIG},
                {"module_id": ACCOUNTING_MODULE, "enabled": True, "config": accounting_config(tmp_path)}]
    assert [m.module_id for m in configured_modules(config, HOST, assigned)] == ["sli.heartbeat", NPS_MODULE, ACCOUNTING_MODULE]
    assigned[0]["config"] = {**CONFIG, "paused": True}
    assert [m.module_id for m in configured_modules(config, HOST, assigned)] == ["sli.heartbeat", ACCOUNTING_MODULE]
    for item in assigned:
        assert validate_assignment(item, HOST)["module_id"] == item["module_id"]
    assigned[0]["config"] = {**CONFIG, "families": {"nps": False}}
    assert [m.module_id for m in configured_modules(config, HOST, assigned)] == ["sli.heartbeat", ACCOUNTING_MODULE]


def test_nps_and_snapshot_assignments_keep_all_collectors(tmp_path):
    from tests.unit.test_agent_snapshot_stream import config as snapshot_config

    config = AgentConfig("https://core.invalid", tmp_path / "ca", tmp_path)
    assigned = [{"module_id": NPS_MODULE, "enabled": True, "config": CONFIG},
                {"module_id": ACCOUNTING_MODULE, "enabled": True, "config": accounting_config(tmp_path)},
                {"module_id": "sli.ad-snapshot", "enabled": True, "config": snapshot_config()},
                {"module_id": "sli.gpo-snapshot", "enabled": True, "config": snapshot_config("sli.gpo-snapshot")}]
    assert [module.module_id for module in configured_modules(config, HOST, assigned)] == [
        "sli.heartbeat", NPS_MODULE, ACCOUNTING_MODULE, "sli.ad-snapshot", "sli.gpo-snapshot"]


def test_bookmark_filters_native_identity_and_masks_before_signing():
    extra = '<Data Name="SharedSecret">fixture-private-secret</Data><Data Name="Password">fixture-private-password</Data>'
    module = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(4624, 1), "bookmark-1"),
        (event(6272, 2, extra), "bookmark-2"), (event(6273, 3), "bookmark-3")])
    sample = module.collect(now=NOW)
    assert sample.filtered_count == 1 and sample.continuity_state == "filtered"
    assert "fixture-private" not in json.dumps(sample.payload)
    assert [r["payload"]["event_id"] for r in sample.payload["records"]] == [6272, 6273]
    assert bookmark_state(sample.cursor_after, "1")["record_id"] == 3
    context = signed(sample, CONFIG)
    assert receive(context)["status"] == "committed"
    assert receive(context)["status"] == "duplicate"
    assert len(context[0].imports) == 1


def test_bookmark_resume_and_explicit_reset_preserve_gap():
    first = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(), "bookmark-1")]).collect(now=NOW)
    calls = []
    def reader(channel, cursor, limit):
        calls.append(cursor)
        return []
    module = NPSModule(HOST, CONFIG, reader=reader)
    context = signed(first, CONFIG)
    assert receive(context)["status"] == "committed"
    sample = module.collect(context[3]["envelope"], now=NOW)
    assert calls[0]["bookmark"] == "bookmark-1"
    state = bookmark_state(sample.cursor_after, "1")
    assert state["record_id"] == 1 and state["coverage_from_utc"] == NOW.isoformat()
    reset = NPSModule(HOST, {**CONFIG, "event_generation": "2"}, reader=lambda *_: [(event(), "new-bookmark")])
    sample = reset.collect(context[3]["envelope"], now=NOW)
    assert sample.continuity_state == "gap" and sample.lost_count is None
    next_context = signed(sample, reset.policy, sequence=2, ledger=context[0])
    assert receive(next_context)["status"] == "committed"


def test_nps_tail_coverage_survives_restart_and_is_admitted_as_signed_evidence():
    available = [(event(6273, 1), "bookmark-1")]
    def reader(channel, cursor, limit):
        return [row for row in available if cursor["record_id"] is None or
                int(row[1].rsplit("-", 1)[1]) > cursor["record_id"]][:limit]
    module = NPSModule(HOST, CONFIG, reader=reader)
    first = module.collect(now=NOW)
    assert first.payload["continuity"] == {"status": "not_proven"}
    assert first.payload["context"]["tail_drained"] is True
    context = signed(first, CONFIG)
    assert receive(context)["status"] == "committed"
    later = NOW + timedelta(minutes=10)
    # A new module instance resumes exactly the signed, durable cursor.
    sample = NPSModule(HOST, CONFIG, reader=reader).collect(context[3]["envelope"], now=later)
    assert sample.payload["continuity"] == {"status": "complete", "from_utc": NOW.isoformat(), "to_utc": later.isoformat()}
    ledger, identity, key, _ = context
    value = make_packet(key, agent_id=AGENT, sequence=2, sample=sample, now=later)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=later)["status"] == "committed"


@pytest.mark.parametrize("kind", ["gap", "backlog", "clock", "reset"])
def test_nps_incomplete_tail_never_attests_full_windows(kind):
    from sli_agent.nps import window_continuity

    previous = {"record_id": 1, "bookmark": "bookmark-1", "generation": "1", "coverage_from_utc": NOW.isoformat(),
                "anchor_sha256": "a" * 64}
    after = previous | {"record_id": 2, "bookmark": "bookmark-2"}
    result, proof = window_continuity(previous, after,
        observed=(NOW - timedelta(seconds=1) if kind == "clock" else NOW + timedelta(minutes=10)).isoformat(),
        drained=kind != "backlog", contiguous=kind != "gap", reset=kind == "reset")
    assert proof == {"status": "not_proven"}


def test_ingress_rejects_forged_nps_coverage_origin():
    from sli_agent.envelope import canonical

    module = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(), "bookmark-1")])
    sample = module.collect(now=NOW)
    state = bookmark_state(sample.cursor_after, "1") | {"coverage_from_utc": (NOW - timedelta(minutes=10)).isoformat()}
    sample = replace(sample, cursor_after={"strategy": "bookmark", "token": canonical(state).decode("ascii")})
    sample.payload["context"]["tail_drained"] = True
    sample.payload["continuity"] = {"status": "complete", "from_utc": state["coverage_from_utc"], "to_utc": NOW.isoformat()}
    assert receive(signed(sample, CONFIG))["error_code"] == "agent_nps_packet_invalid"


@pytest.mark.parametrize("change", ["pause", "revision", "source", "native", "cursor", "secret"])
def test_ingress_rejects_policy_cursor_and_native_xml_forgery(change):
    sample = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(), "bookmark-1")]).collect(now=NOW)
    config = deepcopy(CONFIG)
    if change in ("pause", "revision", "source"):
        config[{"pause": "paused", "revision": "policy_revision", "source": "source_instance_id"}[change]] = (
            True if change == "pause" else "fixture-other")
    elif change == "cursor":
        sample = replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(
            {"record_id": 2, "bookmark": "bookmark-2", "generation": "1"})})
    else:
        sample.payload["records"][0]["payload"]["xml"] = (event(4624) if change == "native"
            else event(extra='<Data Name="Password">fixture-private-password</Data>'))
    context = signed(sample, config)
    assert receive(context)["error_code"] == "agent_nps_packet_invalid"
    assert not context[0].rows


def test_retained_policy_allows_offline_backlog_but_never_rebinds_source():
    sample = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(), "bookmark-1")]).collect(now=NOW)
    context = signed(sample, {**CONFIG, "policy_revision": "2", "families": {"nps": False}})
    context[0].policy_assignment = lambda *_: {"module_id": NPS_MODULE, "enabled": True, "config": CONFIG}
    assert receive(context)["status"] == "committed"
    rejected = signed(sample, {**CONFIG, "source_instance_id": "fixture-other", "policy_revision": "2"})
    rejected[0].policy_assignment = context[0].policy_assignment
    assert receive(rejected)["error_code"] == "agent_nps_packet_invalid"


def test_real_file_offset_preserves_bom_crlf_partial_tail_and_replay(tmp_path):
    line = accounting_line()
    raw = b"\xef\xbb\xbf" + line.encode() + b"\r\n"
    path = tmp_path / "IN-fixture.log"
    path.write_bytes(raw + b"partial")
    generation = derive_file_generation(source_instance_id=CONFIG["source_instance_id"],
        file_name=path.name, file_creation_time_ns=path.stat().st_ctime_ns)
    config = accounting_config(tmp_path, generation=generation)
    module = AccountingModule(HOST, config)
    sample = module.collect(now=NOW)
    assert sample.cursor_before == {"strategy": "file_offset", "token": ""}
    assert json.loads(sample.cursor_after["token"])["byte_offset"] == len(raw)
    assert sample.payload["records"][0]["payload"] == line
    context = signed(sample, config)
    assert receive(context)["status"] == "committed"
    assert receive(context)["status"] == "duplicate"
    followup = module.collect(context[3]["envelope"], now=NOW)
    assert followup.cursor_after == sample.cursor_after and not followup.payload["records"]


def test_accounting_rotation_and_cursor_attestation(tmp_path):
    config = accounting_config(tmp_path)
    line = accounting_line()
    tail = RadiusTailBatch("fixture-rotated", 0, len(line) + 1, True, (line,), 2, len(line) + 1, 0)
    sample = AccountingModule(HOST, config, reader=lambda *_a, **_kw: tail).collect(now=NOW)
    assert json.loads(sample.cursor_after["token"])["file_generation"] == tail.file_generation
    assert receive(signed(sample, config))["status"] == "committed"
    sample.payload["header"]["cursor"]["start_offset"] = 1
    context = signed(sample, config)
    assert receive(context)["error_code"] == "agent_nps_packet_invalid" and not context[0].rows


@pytest.mark.parametrize("module_id", [NPS_MODULE, ACCOUNTING_MODULE])
def test_offline_restart_rotation_and_lost_ack_preserve_durable_cursors(tmp_path, module_id):
    if module_id == ACCOUNTING_MODULE:
        directory = tmp_path / "accounting"
        directory.mkdir()
        paths = [directory / f"IN-fixture-{i}.log" for i in range(3)]
        lines = [accounting_line(), accounting_line("3", minute="02"), accounting_line("2", minute="05")]
        for i, (path, line) in enumerate(zip(paths, lines)):
            path.write_bytes(line.encode() + b"\r\n")
            os.utime(path, ns=(1_000_000_000 * (i + 1), 1_000_000_000 * (i + 1)))
        generation = derive_file_generation(source_instance_id=CONFIG["source_instance_id"],
            file_name=paths[0].name, file_creation_time_ns=paths[0].stat().st_ctime_ns)
        config = accounting_config(directory, generation=generation)
        module = AccountingModule(HOST, config)
    else:
        config = CONFIG
        def reader(_channel, cursor, _limit):
            record_id = (cursor["record_id"] or 0) + 1
            return [(event(6272 if record_id != 2 else 6273, record_id), f"bookmark-{record_id}")]
        module = NPSModule(HOST, config, reader=reader)
    key = ec.generate_private_key(ec.SECP256R1())
    ledger = Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": module_id, "enabled": True, "config": config}]}
    def reopen():
        return Spool(tmp_path / "spool", max_bytes=256 * 1024, max_age_seconds=86400)
    spool = reopen()
    packets = []
    # No network during capture; every restart resumes the captured checkpoint.
    for _ in range(3):
        sample = module.collect(spool.captured(module_id), now=NOW)
        packets.append(spool.capture(key, agent_id=AGENT, sample=sample, now=NOW))
        spool = reopen()
        assert spool.captured(module_id) == packets[-1]["envelope"]
    assert spool.pending() == packets
    assert spool.state[module_id]["committed"] == 0
    assert [p["envelope"]["sequence"] for p in packets] == [1, 2, 3]
    assert all(current["envelope"]["cursor_before"] == previous["envelope"]["cursor_after"]
               for previous, current in zip(packets, packets[1:]))
    if module_id == ACCOUNTING_MODULE:
        assert [p["payload"]["records"][0]["payload"] for p in packets] == lines
        assert [p["payload"]["continuity"]["previous_generation_eof"] for p in packets] == [False, True, True]
        assert len({json.loads(p["envelope"]["cursor_after"]["token"])["file_generation"] for p in packets}) == 3
        # Delivery must use retained evidence even after the source goes away.
        for path in paths:
            path.unlink()
    else:
        assert [bookmark_state(p["envelope"]["cursor_after"], "1")["record_id"] for p in packets] == [1, 2, 3]
    for packet in packets:
        context = ledger, identity, key, packet
        assert receive(context)["status"] == "committed"
        # The response is lost: reopen and replay the exact durable packet.
        spool = reopen()
        assert spool.pending()[0] == packet
        receipt = receive(context)
        assert receipt["status"] == "duplicate"
        assert spool.acknowledge(packet, receipt)
    spool = reopen()
    assert not spool.pending() and len(ledger.rows) == 3
    assert spool.captured(module_id) == packets[-1]["envelope"]
    assert spool.state[module_id]["committed_cursor"] == packets[-1]["envelope"]["cursor_after"]


@pytest.mark.parametrize("module_id", [NPS_MODULE, ACCOUNTING_MODULE])
def test_source_failure_leaves_offline_packet_and_capture_checkpoint_intact(tmp_path, module_id):
    if module_id == ACCOUNTING_MODULE:
        config = accounting_config(tmp_path)
        line = accounting_line()
        tail = RadiusTailBatch("fixture-generation", 0, len(line) + 1, False, (line,), 1, len(line) + 1, 0)
        module = AccountingModule(HOST, config, reader=lambda *_a, **_kw: tail)
    else:
        module = NPSModule(HOST, CONFIG, reader=lambda *_: [(event(), "bookmark-1")])
    spool = Spool(tmp_path / "spool", max_bytes=65536, max_age_seconds=86400)
    key = ec.generate_private_key(ec.SECP256R1())
    packet = spool.capture(key, agent_id=AGENT, sample=module.collect(now=NOW), now=NOW)
    def fail(*_args, **_kwargs):
        raise OSError("fixture_source_unavailable")
    module.reader = fail
    with pytest.raises(OSError, match="fixture_source_unavailable"):
        module.collect(spool.captured(module_id), now=NOW)
    reopened = Spool(tmp_path / "spool", max_bytes=65536, max_age_seconds=86400)
    assert reopened.pending() == [packet]
    assert reopened.captured(module_id) == packet["envelope"]
    assert reopened.state[module_id]["committed"] == 0


def test_read_failure_or_oversize_never_advances_cursor(tmp_path):
    def fail(*_args):
        raise RuntimeError("agent_eventlog_read_failed")
    with pytest.raises(RuntimeError, match="agent_eventlog_read_failed"):
        NPSModule(HOST, CONFIG, reader=fail).collect(now=NOW)
    line = accounting_line() + "x" * 45000
    tail = RadiusTailBatch("fixture-generation", 0, len(line), False, (line,), 1, len(line), 0)
    with pytest.raises(ValueError):
        AccountingModule(HOST, accounting_config(tmp_path), reader=lambda *_a, **_kw: tail).collect(now=NOW)


@pytest.mark.parametrize("module,config", [(NPS_MODULE, CONFIG),
    (NPS_MODULE, {**CONFIG, "batch_size": True}), (NPS_MODULE, {**CONFIG, "paused": "yes"})])
def test_unknown_secret_config_or_invalid_limits_rejected(module, config):
    if config == CONFIG:
        config = {**config, "shared_secret": "fixture-secret"}
    with pytest.raises(ValueError, match="agent_nps_config_invalid"):
        NPSModule(HOST, config)
