"""Agent contracts use synthetic keys, clocks, transports and storage only."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent.config import AgentConfig
from sli_agent.envelope import EnvelopeError, make_packet, verify_packet
from sli_agent.modules import HeartbeatModule
from sli_agent.spool import Spool, SpoolFull

NOW = datetime(2026, 10, 6, 12, tzinfo=timezone.utc)
AGENT = str(uuid4())
HOST = str(uuid4())


@pytest.fixture
def key():
    return ec.generate_private_key(ec.SECP256R1())


def packet(key, sequence=1, now=NOW):
    sample = HeartbeatModule(HOST).collect(None, now=now)
    return make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=now)


def receipt(value, status="committed"):
    envelope = value["envelope"]
    return {"contract_id": "sli.agent-receipt.v1", "packet_id": envelope["packet_id"],
            "payload_sha256": envelope["payload_sha256"], "status": status,
            "committed_cursor": envelope["cursor_after"], "evidence_ref": "fixture-evidence",
            "committed_at_utc": NOW.isoformat(), "error_code": None}


def test_collection_is_off_and_https_is_required(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    assert config.collection_enabled is False
    with pytest.raises(ValueError, match="agent_config_invalid"):
        AgentConfig("http://core.invalid", tmp_path / "ca.pem", tmp_path)


def test_signed_envelope_fields_and_receipt_match_adr(key):
    import json

    schema = json.loads((Path(__file__).resolve().parents[2] /
                        "config/plugin_architecture_v3.json").read_text())
    value = packet(key)
    assert set(value["envelope"]) == set(schema["$defs"]["agent_envelope"]["required"])
    for name in ("cursor_before", "cursor_after"):
        assert set(value["envelope"][name]) == set(schema["$defs"]["cursor"]["required"])
        assert isinstance(value["envelope"][name]["token"], str)
    assert verify_packet(value, key.public_key())["agent_id"] == AGENT
    result = receipt(value)
    assert set(result) == set(schema["$defs"]["receipt"]["required"])
    assert result["status"] in schema["$defs"]["receipt"]["properties"]["status"]["enum"]


@pytest.mark.parametrize("field", ["payload", "sequence", "cursor_after", "agent_id"])
def test_tampering_is_rejected(key, field):
    value = packet(key)
    if field == "payload":
        value["payload"]["status"] = "changed"
    else:
        value["envelope"][field] = 99 if field == "sequence" else "changed"
    with pytest.raises(EnvelopeError):
        verify_packet(value, key.public_key())


def test_other_key_cannot_sign(key):
    with pytest.raises(EnvelopeError, match="agent_signature_invalid"):
        verify_packet(packet(key), ec.generate_private_key(ec.SECP256R1()).public_key())


def test_rsa_profile_can_sign_and_verify():
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert verify_packet(packet(key), key.public_key())["sequence"] == 1


def test_spool_restart_lost_ack_and_receipt_deletion(tmp_path, key):
    spool = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    value = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    restarted = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    assert list(restarted.pending(now=NOW)) == [value]
    for status in ("rejected", "retry_later"):
        assert restarted.acknowledge(value, receipt(value, status)) is False
    wrong = receipt(value)
    wrong["payload_sha256"] = "0" * 64
    assert restarted.acknowledge(value, wrong) is False
    assert restarted.acknowledge(value, receipt(value, "duplicate")) is True
    assert list(restarted.pending(now=NOW)) == []
    next_value = restarted.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(restarted.captured("sli.heartbeat"), now=NOW), now=NOW)
    assert next_value["envelope"]["sequence"] == 2


def test_out_of_order_receipt_cannot_advance_cursor(tmp_path, key):
    spool = Spool(tmp_path, max_bytes=20000, max_age_seconds=3600)
    first = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    second = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(spool.captured("sli.heartbeat"), now=NOW), now=NOW)
    assert not spool.acknowledge(second, receipt(second))
    assert len(list(spool.pending(now=NOW))) == 2
    assert spool.acknowledge(first, receipt(first))
    assert spool.acknowledge(second, receipt(second))


def test_restart_after_receipt_checkpoint_before_delete(tmp_path, key, monkeypatch):
    spool = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    first = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    original = Path.unlink
    def interrupted(path, *args, **kwargs):
        if path.suffix == ".packet":
            raise OSError("fixture")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "unlink", interrupted)
    with pytest.raises(OSError):
        spool.acknowledge(first, receipt(first))
    monkeypatch.setattr(Path, "unlink", original)
    restarted = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    assert restarted.pending(now=NOW) == []
    assert restarted.captured("sli.heartbeat")["sequence"] == 1


def test_malformed_receipt_is_not_authority_to_delete(tmp_path, key):
    spool = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    first = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    wrong = receipt(first)
    wrong["committed_at_utc"] = "invalid"
    assert not spool.acknowledge(first, wrong)
    assert spool.pending(now=NOW) == [first]


def test_spool_limits_pause_capture_without_destroying_evidence(tmp_path, key):
    spool = Spool(tmp_path, max_bytes=3000, max_age_seconds=60)
    first = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    with pytest.raises(SpoolFull, match="agent_spool_age_limit"):
        spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(spool.captured("sli.heartbeat"), now=NOW), now=NOW + timedelta(seconds=61))
    assert list(spool.pending(now=NOW + timedelta(seconds=61))) == [first]
    spool.max_bytes = 1
    with pytest.raises(SpoolFull, match="agent_spool_size_limit"):
        spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(spool.captured("sli.heartbeat"), now=NOW), now=NOW)


def test_capture_is_recovered_if_checkpoint_write_was_interrupted(tmp_path, key, monkeypatch):
    spool = Spool(tmp_path, max_bytes=20000, max_age_seconds=3600)
    original = spool._save_state
    monkeypatch.setattr(spool, "_save_state", lambda state: (_ for _ in ()).throw(OSError("fixture")))
    with pytest.raises(OSError):
        spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    monkeypatch.setattr(spool, "_save_state", original)
    restarted = Spool(tmp_path, max_bytes=20000, max_age_seconds=3600)
    assert restarted.captured("sli.heartbeat")["sequence"] == 1
    value = restarted.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(restarted.captured("sli.heartbeat"), now=NOW), now=NOW)
    assert value["envelope"]["sequence"] == 2


def test_delivery_retries_identical_packet_and_keeps_rejections(tmp_path, key):
    from sli_agent.runtime import deliver_once

    spool = Spool(tmp_path, max_bytes=10000, max_age_seconds=3600)
    value = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(HOST).collect(None, now=NOW), now=NOW)
    calls = []
    def upload(body):
        calls.append(deepcopy(body))
        if len(calls) == 1:
            raise OSError("fixture")
        return receipt(body, "duplicate")
    assert deliver_once(spool, upload, now=NOW) is False
    assert deliver_once(spool, upload, now=NOW) is True
    assert calls == [value, value]


def test_windows_reader_is_not_imported_when_disabled(tmp_path, monkeypatch):
    from sli_agent.modules import configured_modules

    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    assert [m.module_id for m in configured_modules(config, HOST)] == ["sli.heartbeat"]


def test_single_service_owner_and_no_windows_api_on_linux(tmp_path):
    import os
    from sli_agent.protection import directory_lock
    from sli_agent.service import service_class
    if os.name == "nt":
        pytest.skip("Linux service/import boundary")
    with pytest.raises(RuntimeError, match="agent_windows_required"):
        service_class()
    with directory_lock(tmp_path):
        with pytest.raises(OSError):
            with directory_lock(tmp_path):
                pytest.fail("a second writer acquired the lock")


def test_event_adapter_preserves_packet_and_generation():
    from sli_agent.modules import EventLogModule
    from server.sli.sources.collection_packet_import import event_rows_from_packet

    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           '<System><EventID>4624</EventID><EventRecordID>7</EventRecordID></System></Event>')
    module = EventLogModule(source_instance_id=HOST, source_name="fixture-host", channel="Security",
                            generation="fixture-generation", reader=lambda after: [xml])
    sample = module.collect(None, now=NOW)
    assert sample.cursor_after == {"strategy": "record_id", "token": "7"}
    assert event_rows_from_packet(sample.payload)[0]["record_id"] == 7
    assert sample.payload["header"]["generation"] == "fixture-generation"
    assert sample.continuity_state == "not_proven"
