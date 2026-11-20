"""Snapshot stream, ingress and completion contracts, with fakes and no DB."""
from __future__ import annotations

import base64
import json
import os
import threading
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from server.sli.agent_ingest import PostgresLedger, receive_packet
from server.sli.agents.snapshot_consumer import consume_snapshot_cycles, validate_cycle
from sli_agent.envelope import MAX_PACKET_BYTES, EnvelopeError, canonical, digest, make_packet, verify_packet
from sli_agent.modules import HeartbeatModule, configured_modules
from sli_agent.runtime import SnapshotCapture, deliver_once
from sli_agent.snapshot_stream import FRAGMENT_BYTES, SnapshotModule, SnapshotStream, due_slot, policy, validate_chunk
from sli_agent.spool import Spool, SpoolFull

AGENT = "00000000-0000-4000-8000-000000000001"
SOURCE = "00000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc)
MODULE = "sli.ad-snapshot"


def config(module=MODULE, **changes):
    return policy(module, {"source_instance_id": SOURCE, "domain_sid": "S-1-5-21-1-2-3",
        "domain_dns": "directory.invalid", "scope": "fixture-scope",
        "families": ["ad_context_base"] if module == MODULE else ["gpo_v2"], **changes})


def stream(tmp_path, *, size=1, module=MODULE, cfg=None):
    cfg = cfg or config(module)
    result = SnapshotStream(tmp_path, module)
    state = result.begin(cfg, now=NOW)
    result.freeze(state, {family: ({"fixture": "x" * size}, 1) for family in cfg["families"]})
    return result


def packets(result, key):
    captured = None
    values = []
    while (sample := result.next_sample(captured)) is not None:
        value = make_packet(key, agent_id=AGENT, sequence=len(values) + 1, sample=sample, now=NOW)
        values.append(value)
        captured = value["envelope"]
    return values


@pytest.fixture
def key():
    return ec.generate_private_key(ec.SECP256R1())


class Ledger:
    def __init__(self, cfg=None, module=MODULE):
        self.config = cfg or config(module)
        self.identity = {"id": AGENT, "host_id": SOURCE, "assigned_modules": [
            {"module_id": module, "enabled": True, "config": deepcopy(self.config)}]}
        self.rows = []
        self.cycles = {}
        self.quota = None
        self.conflict = False
        self.history = {}

    def get(self, agent, module, sequence):
        return next((row for row in self.rows if row["envelope"]["agent_id"] == agent
                     and row["envelope"]["module_id"] == module and row["envelope"]["sequence"] == sequence), None)

    def packet_exists(self, packet_id):
        return any(row["envelope"]["packet_id"] == packet_id for row in self.rows)

    def latest(self, agent, module):
        return self.rows[-1]["envelope"] if self.rows else None

    def binding(self, *args):
        return {"policy": self.config} if self.config else None

    def snapshot_cycle(self, cycle_id):
        return self.cycles.get(cycle_id)

    def snapshot_policy_revision(self, agent, module, revision):
        return self.history.get(revision)

    def snapshot_conflict(self, envelope, payload, cfg):
        return self.conflict or any(row["payload"]["cycle_id"] == payload["cycle_id"]
            and row["payload"]["family"] == payload["family"] and any(row["payload"][name] != payload[name]
                for name in ("chunk_count", "total_bytes", "total_objects", "family_sha256")) for row in self.rows)

    def quota_error(self, *args):
        return self.quota

    def commit(self, value, receipt, envelope_hash, rows):
        assert rows is None  # Never store snapshot bytes in the event inbox.
        envelope, payload = value["envelope"], value["payload"]
        self.cycles.setdefault(payload["cycle_id"], {"cycle_id": payload["cycle_id"], "agent_id": AGENT,
            "module_id": envelope["module_id"], "slot_start_utc": payload["slot_start_utc"],
            "policy": deepcopy(self.history.get(envelope["policy_revision"], {}).get("config", self.config)),
            "transport_state": "pending"})
        self.rows.append({"envelope": deepcopy(envelope), "payload": deepcopy(payload),
                          "envelope_sha256": envelope_hash, "receipt": deepcopy(receipt)})

    def receive(self, value, key, *, now=NOW):
        return receive_packet(self, identity=self.identity, public_key=key.public_key(), value=value, now=now)


@pytest.mark.parametrize("module", [MODULE, "sli.gpo-snapshot"])
@pytest.mark.parametrize("size", [0, FRAGMENT_BYTES - 14, FRAGMENT_BYTES, FRAGMENT_BYTES * 3])
def test_fragments_and_full_signed_packets_are_bounded(tmp_path, key, module, size):
    values = packets(stream(tmp_path, size=size, module=module), key)
    raw = bytearray()
    for value in values:
        envelope = verify_packet(value, key.public_key())
        raw += validate_chunk(envelope, value["payload"], config(module))
        assert envelope["record_count"] == 1
        assert envelope["continuity_state"] == "complete"
        assert len(canonical(value)) <= MAX_PACKET_BYTES
        assert len(base64.b64decode(value["payload"]["records"][0]["data_b64"])) <= FRAGMENT_BYTES
    assert json.loads(raw) == {"fixture": "x" * size}


def test_rsa_packet_limit_is_checked_after_signing(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    result = stream(tmp_path, size=FRAGMENT_BYTES)
    sample = result.next_sample(None)
    assert len(canonical(make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW))) <= MAX_PACKET_BYTES
    sample = replace(sample, payload={**sample.payload, "extra": "x" * MAX_PACKET_BYTES})
    with pytest.raises(EnvelopeError, match="agent_packet_size_limit"):
        make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)


def test_restart_and_lost_ack_reuse_exact_packet_then_resume(tmp_path, key):
    cfg = config()
    result = stream(tmp_path / "capture", size=FRAGMENT_BYTES * 2, cfg=cfg)
    spool = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    first = spool.capture(key, agent_id=AGENT, sample=result.next_sample(None), now=NOW)
    ledger = Ledger(cfg)
    committed = ledger.receive(first, key)
    assert committed["status"] == "committed"
    restarted = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    assert restarted.pending() == [first]
    replay = ledger.receive(first, key, now=NOW + timedelta(days=30))
    assert replay == {**committed, "status": "duplicate"}
    assert restarted.acknowledge(first, replay)
    resumed = SnapshotStream(tmp_path / "capture", MODULE)
    # A policy change does not replace the frozen bytes or revision.
    assert resumed.begin(config(policy_revision="2"), now=NOW)["policy"] == cfg
    second = restarted.capture(key, agent_id=AGENT, sample=resumed.next_sample(restarted.captured(MODULE)), now=NOW)
    assert second["payload"]["chunk_index"] == 1
    assert second["envelope"]["cursor_before"] == first["envelope"]["cursor_after"]
    assert second["envelope"]["generation"] == first["envelope"]["generation"]
    assert len(ledger.rows) == 1


def test_crash_after_packet_write_before_checkpoint_does_not_duplicate_chunk(tmp_path, key, monkeypatch):
    result = stream(tmp_path / "capture", size=FRAGMENT_BYTES)
    spool = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    monkeypatch.setattr(spool, "_save_state", lambda state: (_ for _ in ()).throw(OSError("fixture")))
    with pytest.raises(OSError):
        spool.capture(key, agent_id=AGENT, sample=result.next_sample(None), now=NOW)
    restarted = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    assert restarted.captured(MODULE)["sequence"] == 1
    assert result.next_sample(restarted.captured(MODULE)).payload["chunk_index"] == 1


@pytest.mark.parametrize("limit,code", [("max_bytes", "agent_snapshot_size_limit"),
    ("max_objects", "agent_snapshot_size_limit"), ("buffer_bytes", "agent_snapshot_buffer_limit")])
def test_family_and_buffer_limits_leave_frozen_capture_pending(tmp_path, limit, code):
    result = SnapshotStream(tmp_path, MODULE)
    state = result.begin(config(**{limit: 1}), now=NOW)
    with pytest.raises(ValueError, match=code):
        result.freeze(state, {"ad_context_base": ({"fixture": "xx"}, 2)})
    assert not result.read()["ready"]


def test_privacy_redaction_precedes_capture_file(tmp_path):
    result = SnapshotStream(tmp_path, MODULE)
    state = result.begin(config(), now=NOW)
    result.freeze(state, {"ad_context_base": ({"rows": [{"cpassword": "fixture-secret-marker",
        "msDS-ManagedPassword": "fixture-secret-marker", "msLAPS-Password": "fixture-secret-marker",
        "password_hash": "fixture-secret-marker", "token": "fixture-secret-marker"}]}, 1)})
    raw = base64.b64decode(result.read()["families"]["ad_context_base"]["data_b64"])
    assert b"fixture-secret-marker" not in raw
    assert list(json.loads(raw)["rows"][0].values()) == [{"redacted": True}] * 5
    with pytest.raises(ValueError):
        result.freeze(state, {"ad_context_base": ({"fixture": "<raw-xml/>"}, 1)})


def test_ready_capture_is_immutable_before_and_after_restart(tmp_path):
    result = SnapshotStream(tmp_path, MODULE)
    state = result.begin(config(), now=NOW)
    families = {"ad_context_base": ({"fixture": 1}, 1)}
    result.freeze(state, families)
    original = (result.root / "cycle.json").read_bytes()
    restarted = SnapshotStream(tmp_path, MODULE)
    restarted.freeze(state, families)
    with pytest.raises(ValueError, match="agent_snapshot_cycle_conflict"):
        restarted.freeze(state, {"ad_context_base": ({"fixture": 2}, 1)})
    assert (result.root / "cycle.json").read_bytes() == original


@pytest.mark.parametrize("module", [MODULE, "sli.gpo-snapshot"])
def test_default_policy_schedule_matches_legacy_coordinator(module):
    from server.sli.plugins.ad.snapshots.coordinator import latest_due_scheduled_slot

    cfg = config(module)
    assert cfg["schedule"] == {"timezone": "Asia/Novosibirsk", "hours": [6, 18]}
    for now in (NOW, NOW - timedelta(hours=8), NOW + timedelta(hours=12)):
        slot = latest_due_scheduled_slot(now)
        assert due_slot(cfg, now).replace("+00:00", "Z") == slot.slot_start_utc


@pytest.mark.parametrize("module", [MODULE, "sli.gpo-snapshot"])
def test_schedule_update_keeps_frozen_cycle_and_applies_to_next_capture(tmp_path, key, module):
    old = config(module)
    new = config(module, policy_revision="2", schedule={"timezone": "UTC", "hours": list(range(24))})
    result = stream(tmp_path, module=module, cfg=old)
    frozen = deepcopy(result.read())
    assert result.begin(new, now=NOW) == frozen
    values = packets(result, key)
    assert {value["envelope"]["policy_revision"] for value in values} == {"1"}
    assert {value["payload"]["slot_start_utc"] for value in values} == {frozen["slot_start_utc"]}
    next_cycle = result.begin(new, now=NOW)
    assert next_cycle["cycle_id"] != frozen["cycle_id"]
    assert next_cycle["policy"] == new
    assert next_cycle["slot_start_utc"] == "2026-10-08T12:00:00+00:00"


def test_schedule_and_cycle_transition_have_no_false_gap(tmp_path, key):
    cfg = config(families=["ad_context_base", "ad_domain_health"])
    assert due_slot(cfg, NOW) == "2026-10-08T11:00:00+00:00"
    result = stream(tmp_path, cfg=cfg)
    values = packets(result, key)
    ledger = Ledger(cfg)
    for value in values:
        assert ledger.receive(value, key)["status"] == "committed"
    assert result.begin(cfg, now=NOW) is None
    tomorrow = NOW + timedelta(days=1)
    state = result.begin(cfg, now=tomorrow)
    result.freeze(state, {family: ({"fixture": 2}, 1) for family in cfg["families"]})
    sample = result.next_sample(values[-1]["envelope"])
    assert sample.continuity_state == "complete"
    assert sample.generation == values[-1]["envelope"]["generation"]
    next_value = make_packet(key, agent_id=AGENT, sequence=3, sample=sample, now=tomorrow)
    assert ledger.receive(next_value, key, now=tomorrow)["status"] == "committed"


@pytest.mark.parametrize("change", ["disabled", "legacy_assignment", "domain", "scope", "revision", "source",
    "generation", "cursor", "family", "size", "base64", "contract", "slot", "extra"])
def test_snapshot_ingest_rejects_invalid_contracts_without_receipt(tmp_path, key, change):
    result = stream(tmp_path)
    sample = result.next_sample(None)
    ledger = Ledger()
    if change == "disabled": ledger.identity["assigned_modules"][0]["enabled"] = False
    elif change == "legacy_assignment": ledger.identity["assigned_modules"] = [MODULE]
    elif change == "domain": sample.payload["domain_sid"] = "S-1-5-21-4-5-6"
    elif change == "scope": sample.payload["scope"] = "other-fixture"
    elif change == "revision": sample = replace(sample, policy_revision="2")
    elif change == "source": sample = replace(sample, source_instance_id=str(uuid4()))
    elif change == "generation": sample = replace(sample, generation="fixture-reset")
    elif change == "cursor": sample = replace(sample, cursor_after={"strategy": "snapshot", "token": "{}"})
    elif change == "family": sample.payload["cycle_families"] = ["ad_domain_health"]
    elif change == "size": sample.payload["total_bytes"] = 64 * 1024**2
    elif change == "base64": sample.payload["records"][0]["data_b64"] = "!"
    elif change == "contract": sample.payload["contract"] = "sli.collection-packet.v1"
    elif change == "slot": sample.payload["slot_start_utc"] = "2026-10-08T10:00:00+00:00"
    else: sample.payload["extra"] = 1
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    receipt = ledger.receive(value, key)
    assert receipt["status"] == "rejected"
    assert receipt["committed_cursor"] is None
    assert not ledger.rows and not ledger.cycles


@pytest.mark.parametrize("committed_chunks", [0, 1])
def test_sequence_gap_retries_without_moving_receipt(tmp_path, key, committed_chunks):
    values = packets(stream(tmp_path, size=FRAGMENT_BYTES * 2), key)
    ledger = Ledger()
    for value in values[:committed_chunks]:
        assert ledger.receive(value, key)["status"] == "committed"
    accepted_rows, accepted_cycles = deepcopy(ledger.rows), deepcopy(ledger.cycles)
    later = values[committed_chunks + 1]
    receipt = ledger.receive(later, key)
    assert receipt["status"] == "retry_later"
    assert receipt["error_code"] == "agent_sequence_gap"
    assert receipt["committed_cursor"] is None
    assert ledger.rows == accepted_rows and ledger.cycles == accepted_cycles
    # The missing earlier chunk can still arrive, then the exact packet can retry.
    assert ledger.receive(values[committed_chunks], key)["status"] == "committed"
    receipt = ledger.receive(later, key)
    assert receipt["status"] == "committed"
    assert receipt["committed_cursor"] == later["envelope"]["cursor_after"]


@pytest.mark.parametrize("chunk_index", [0, 1])
def test_conflicting_chunk_is_rejected_without_moving_receipt(tmp_path, key, chunk_index):
    result = stream(tmp_path, size=FRAGMENT_BYTES)
    values = packets(result, key)
    ledger = Ledger()
    assert ledger.receive(values[0], key)["status"] == "committed"
    accepted_rows, accepted_cycles = deepcopy(ledger.rows), deepcopy(ledger.cycles)
    sample = replace(result_sample(values[chunk_index]),
                     payload={**values[chunk_index]["payload"], "family_sha256": "0" * 64})
    conflicting = make_packet(key, agent_id=AGENT, sequence=chunk_index + 1, sample=sample, now=NOW)
    receipt = ledger.receive(conflicting, key)
    assert receipt["status"] == "rejected"
    assert receipt["error_code"] == ("agent_sequence_conflict" if chunk_index == 0 else "agent_snapshot_chunk_conflict")
    assert receipt["committed_cursor"] is None
    assert ledger.rows == accepted_rows and ledger.cycles == accepted_cycles
    assert ledger.receive(values[1], key)["status"] == "committed"
    accepted_rows, accepted_cycles = deepcopy(ledger.rows), deepcopy(ledger.cycles)
    receipt = ledger.receive(conflicting, key)
    assert receipt["status"] == "rejected" and receipt["error_code"] == "agent_sequence_conflict"
    assert receipt["committed_cursor"] is None
    assert ledger.rows == accepted_rows and ledger.cycles == accepted_cycles


def result_sample(value):
    from sli_agent.modules import Sample
    e = value["envelope"]
    return Sample(e["module_id"], e["source_instance_id"], e["channel"], e["generation"],
                  e["cursor_before"], e["cursor_after"], deepcopy(value["payload"]),
                  policy_revision=e["policy_revision"], continuity_state=e["continuity_state"], lost_count=e["lost_count"])


def test_policy_change_allows_frozen_cycle_but_rejects_stale_new_cycle(tmp_path, key):
    values = packets(stream(tmp_path, size=FRAGMENT_BYTES), key)
    ledger = Ledger()
    assert ledger.receive(values[0], key)["status"] == "committed"
    ledger.config = config(policy_revision="2", max_objects=1)
    ledger.identity["assigned_modules"][0]["config"] = deepcopy(ledger.config)
    assert ledger.receive(values[1], key)["status"] == "committed"
    new = result_sample(values[0])
    new.payload["cycle_id"] = str(uuid4())
    from sli_agent.snapshot_stream import cursor
    new = replace(new, cursor_before=values[-1]["envelope"]["cursor_after"], cursor_after=cursor(new.payload))
    stale = make_packet(key, agent_id=AGENT, sequence=3, sample=new, now=NOW)
    assert ledger.receive(stale, key)["error_code"] == "agent_snapshot_chunk_invalid"


def test_frozen_policy_can_arrive_after_revision_changed_before_first_ack(tmp_path, key):
    from sli_agent.snapshot_stream import cursor
    cfg = config()
    values = packets(stream(tmp_path, cfg=cfg, size=FRAGMENT_BYTES), key)
    ledger = Ledger(config(policy_revision="2", families=["ad_context_base", "ad_domain_health"]))
    ledger.history["1"] = {"config": cfg, "enabled": True, "superseded_at": NOW}
    for value in values:
        assert ledger.receive(value, key)["status"] == "committed"
    assert next(iter(ledger.cycles.values()))["policy"] == cfg
    stale = result_sample(values[0])
    stale.payload["cycle_id"] = str(uuid4())
    stale.payload["slot_start_utc"] = due_slot(cfg, NOW + timedelta(days=1))
    stale = replace(stale, cursor_before=values[-1]["envelope"]["cursor_after"], cursor_after=cursor(stale.payload))
    future = make_packet(key, agent_id=AGENT, sequence=3, sample=stale, now=NOW + timedelta(days=1))
    assert ledger.receive(future, key, now=NOW + timedelta(days=1))["error_code"] == "agent_snapshot_chunk_invalid"


def test_backpressure_retains_capture_and_exact_replay(tmp_path, key):
    result = stream(tmp_path / "capture", size=FRAGMENT_BYTES)
    spool = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    first = spool.capture(key, agent_id=AGENT, sample=result.next_sample(None), now=NOW)
    ledger = Ledger()
    ledger.quota = "agent_snapshot_agent_bytes_limit"
    assert not spool.acknowledge(first, ledger.receive(first, key))
    assert not ledger.rows
    spool.max_bytes = 1
    with pytest.raises(SpoolFull):
        spool.capture(key, agent_id=AGENT, sample=result.next_sample(spool.captured(MODULE)), now=NOW)
    assert result.read()["ready"]
    assert result.next_sample(spool.captured(MODULE)).payload["chunk_index"] == 1


def test_modules_are_disabled_until_explicit_assignment(tmp_path):
    local = SimpleNamespace(collection_enabled=False)
    assert [m.module_id for m in configured_modules(local, SOURCE, [MODULE])] == ["sli.heartbeat"]
    assert [m.module_id for m in configured_modules(local, SOURCE, [{"module_id": MODULE, "enabled": False}])] == ["sli.heartbeat"]
    modules = configured_modules(local, SOURCE, [{"module_id": MODULE, "enabled": True, "config": config()}])
    assert [m.module_id for m in modules] == ["sli.heartbeat", MODULE]
    with pytest.raises(ValueError, match="agent_ad_capture_cancelled"):
        modules[1].capture(config(), deadline=0, stop=threading.Event())
    # Windows has no system IANA database; the agent package must ship it.
    requirements = (Path(__file__).resolve().parents[2] / "sli_agent/requirements.txt").read_text("utf-8")
    assert "tzdata>=2025.2,<2027" in requirements


def test_background_reader_keeps_heartbeat_delivery_running_and_single_worker(tmp_path, key):
    started, finish = threading.Event(), threading.Event()
    calls = []
    class Slow(SnapshotModule):
        def capture(self, cfg, *, deadline, stop):
            calls.append(cfg)
            started.set()
            finish.wait(10)
            return {"ad_context_base": ({"fixture": 1}, 1)}
    module = Slow(MODULE, config())
    spool = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    runner = SnapshotCapture(tmp_path / "capture")
    identity = SimpleNamespace(key=key, agent_id=AGENT)
    try:
        runner.tick([module], spool, identity, now=NOW)
        assert started.wait(1)
        for _ in range(3):
            runner.tick([module], spool, identity, now=NOW)
        assert len(calls) == 1
        heartbeat = spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(SOURCE).collect(now=NOW), now=NOW)
        uploads = []
        def upload(value):
            uploads.append(value)
            e = value["envelope"]
            return {"contract_id": "sli.agent-receipt.v1", "status": "committed", "packet_id": e["packet_id"],
                "payload_sha256": e["payload_sha256"], "committed_cursor": e["cursor_after"],
                "evidence_ref": "fixture", "committed_at_utc": NOW.isoformat(), "error_code": None}
        assert deliver_once(spool, upload, now=NOW)
        assert uploads == [heartbeat]
        runner.job["deadline"] = 0
        assert runner.tick([module], spool, identity, now=NOW) == "agent_snapshot_capture_timeout"
        assert len(calls) == 1
        finish.set()
        assert runner.job["done"].wait(1)
        runner.tick([module], spool, identity, now=NOW)
        assert not SnapshotStream(tmp_path / "capture", MODULE).read()["ready"]
    finally:
        finish.set()
        runner.close()


def test_completion_waits_for_every_family_and_validates_hashes(tmp_path, key):
    cfg = config(families=["ad_context_base", "ad_domain_health"])
    values = packets(stream(tmp_path, cfg=cfg, size=FRAGMENT_BYTES), key)
    ledger = Ledger(cfg)
    for value in values:
        assert ledger.receive(value, key)["status"] == "committed"
    cycle = ledger.cycles[values[0]["payload"]["cycle_id"]]
    assert not validate_cycle(cycle, ledger.rows[:-1])
    assert validate_cycle(cycle, ledger.rows)
    forged = deepcopy(ledger.rows)
    for row in forged[:2]:
        row["payload"]["family_sha256"] = "0" * 64
        row["envelope"]["payload_sha256"] = digest(row["payload"])
        row["envelope_sha256"] = digest(row["envelope"])
    with pytest.raises(ValueError, match="agent_snapshot_cycle_invalid"):
        validate_cycle(cycle, forged)
    other = deepcopy(ledger.rows)
    other[0]["payload"]["cycle_id"] = str(uuid4())
    with pytest.raises(ValueError, match="agent_snapshot_cycle_invalid"):
        validate_cycle(cycle, other)


def test_postgres_receipt_precedes_chunk_in_same_caller_transaction(tmp_path, key):
    value = packets(stream(tmp_path), key)[0]
    calls = []
    class Cursor:
        def execute(self, sql, params=()): calls.append((sql, params))
    PostgresLedger(Cursor()).commit(value, {"status": "committed"}, digest(value["envelope"]), None)
    assert "insert into sli_agent_receipts" in calls[0][0]
    assert "insert into sli_agent_snapshot_cycles" in calls[1][0]
    assert "insert into sli_agent_snapshot_chunks" in calls[2][0]
    assert all("commit" not in sql.lower() and "sli_agent_packet_inbox" not in sql for sql, _ in calls)


@pytest.mark.parametrize("module", [MODULE, "sli.gpo-snapshot"])
def test_postgres_cycle_timestamp_allows_remaining_chunks(tmp_path, key, module):
    cfg = config(module)
    values = packets(stream(tmp_path, size=FRAGMENT_BYTES, module=module), key)
    ledger = Ledger(cfg, module=module)
    assert ledger.receive(values[0], key)["status"] == "committed"
    cycle = next(iter(ledger.cycles.values()))
    stored = {**cycle, "slot_start_utc": datetime.fromisoformat(cycle["slot_start_utc"])}

    class Cursor:
        def execute(self, sql, params):
            assert "from sli_agent_snapshot_cycles" in sql
            assert params == (values[1]["payload"]["cycle_id"],)

        def fetchone(self):
            return stored

    ledger.cycles[cycle["cycle_id"]] = PostgresLedger(Cursor()).snapshot_cycle(cycle["cycle_id"])
    assert ledger.receive(values[1], key)["status"] == "committed"
    assert validate_cycle(ledger.cycles[cycle["cycle_id"]], ledger.rows)
    # Normalizing PostgreSQL's type must not admit a different scheduled slot.
    stored["slot_start_utc"] += timedelta(hours=6)
    changed = PostgresLedger(Cursor()).snapshot_cycle(cycle["cycle_id"])
    with pytest.raises(ValueError, match="agent_snapshot_cycle_invalid"):
        validate_cycle(changed, ledger.rows)


def test_gpo_invalid_source_contract_keeps_publication_pending_and_rechecks_lifecycle(tmp_path, key, monkeypatch):
    from server.sli.agents import snapshot_consumer
    from server.sli.agents.import_authorization import PacketPending
    module = "sli.gpo-snapshot"
    ledger = Ledger(config(module), module=module)
    for value in packets(stream(tmp_path, module=module), key):
        assert ledger.receive(value, key)["status"] == "committed"
    cycle = next(iter(ledger.cycles.values()))
    class Connection:
        def __init__(self): self.updates = []
        def cursor(self): return nullcontext(Cursor(self))
        @contextmanager
        def transaction(self):
            saved = deepcopy(self.updates)
            try: yield
            except Exception:
                self.updates = saved
                raise
    class Cursor:
        def __init__(self, conn): self.conn, self.rows = conn, []
        def execute(self, sql, params=()):
            if "from sli_agent_snapshot_chunks" in sql: self.rows = ledger.rows
            elif "select transport_state" in sql: self.rows = [{"transport_state": "pending", "publication_state": "pending"}]
            elif sql.lstrip().startswith("update"):
                self.conn.updates.append(sql)
                self.rows = []
            else: self.rows = [cycle]
        def fetchone(self): return self.rows[0] if self.rows else None
        def fetchall(self): return self.rows
    conn = Connection()
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", lambda *a, **k: ledger.identity)
    plugins = []
    monkeypatch.setattr(snapshot_consumer, "authorize_plugin", lambda cur, plugin: plugins.append(plugin))
    result = consume_snapshot_cycles(conn)
    assert result["completed"] == 1
    assert result["pending_reasons"] == {"agent_gpo_publication_failed": 1}
    assert plugins == ["sli.gpo"]
    assert len(conn.updates) == 1 and "transport_state='complete'" in conn.updates[0]
    conn.updates.clear()
    def denied(*a, **k): raise PacketPending("agent_disabled")
    monkeypatch.setattr(snapshot_consumer, "authorize_packet", denied)
    assert consume_snapshot_cycles(conn)["pending_reasons"] == {"agent_disabled": 1}
    assert not conn.updates


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_snapshot_scan_and_resume_follow_slot_time_instead_of_random_uuid():
    import psycopg
    from psycopg.rows import dict_row

    dsn = os.getenv("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("isolated PostgreSQL test DSN is required")
    oldest, middle, newest = (
        "ffffffff-ffff-4fff-8fff-ffffffffffff",
        "88888888-8888-4888-8888-888888888888",
        "00000000-0000-4000-8000-000000000001",
    )
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        # Temporary tables keep the query test independent of runtime migrations.
        conn.execute("""create temp table sli_agent_snapshot_cycles (
            cycle_id uuid, agent_id uuid, module_id text, slot_start_utc text,
            domain_sid text, policy jsonb, transport_state text, publication_state text)""")
        conn.execute("""create temp table sli_agent_snapshot_chunks (
            cycle_id uuid, packet_id uuid, payload jsonb)""")
        conn.execute("""create temp table sli_agent_receipts (
            packet_id uuid, envelope jsonb, envelope_sha256 text, sequence bigint)""")
        for cycle_id, slot in (
            (oldest, "2026-10-09T14:00:00+07:00"),
            (middle, "2026-10-09T08:00:00+00:00"),
            (newest, "2026-10-09T09:00:00+00:00"),
        ):
            conn.execute("""insert into sli_agent_snapshot_cycles values (
                %s,%s,'sli.gpo-snapshot',%s,'synthetic-domain','{}','pending','pending')""",
                (cycle_id, AGENT, slot))
        scanned = []
        assert consume_snapshot_cycles(conn, limit=2, on_scan=scanned.append)["scanned"] == 2
        assert scanned == [oldest, middle]
        resumed = []
        assert consume_snapshot_cycles(conn, after=scanned[-1], on_scan=resumed.append)["scanned"] == 1
        assert resumed == [newest]
        assert consume_snapshot_cycles(conn, after=newest)["scanned"] == 0


@pytest.mark.parametrize("module", [MODULE, "sli.gpo-snapshot"])
@pytest.mark.parametrize("control_state", ["active", "paused"])
def test_owner_policy_creates_bound_revision_and_one_collector(module, control_state):
    from server.sli.agents.policies import assign_module, update_control
    from server.sli.agents.ca import AgentError
    class Cursor:
        def __init__(self):
            self.agent = {"id": AGENT, "host_id": SOURCE, "status": "active", "policy_revision": 1,
                          "assigned_modules": ["sli.heartbeat"], "rights_probe": {},
                          "collection_policy": {"state": control_state}}
            self.old = None
            self.other = False
            self.calls = []
            self.rows = []
            self.history = {}
        def execute(self, sql, params=()):
            self.calls.append((sql, params))
            self.rows = []
            if "from sli_agents" in sql: self.rows = [deepcopy(self.agent)]
            elif sql.startswith("select config"): self.rows = [{"config": self.old}] if self.old else []
            elif "select agent_id from sli_agent_snapshot_bindings" in sql:
                self.rows = [{"agent_id": str(uuid4())}] if self.other else []
            elif "insert into sli_agent_snapshot_bindings" in sql: self.old = json.loads(params[2])
            elif sql.startswith("insert into sli_agent_policy_history"):
                self.history.setdefault(params[1], (json.loads(params[2]), json.loads(params[3])))
            elif sql.startswith("update sli_agents set collection_policy"):
                self.agent.update(collection_policy=json.loads(params[0]), policy_revision=params[1])
            elif sql.startswith("update sli_agents"):
                self.agent.update(assigned_modules=json.loads(params[0]), policy_revision=params[1])
        def fetchone(self): return self.rows[0] if self.rows else None
    cur = Cursor()
    body = {"agent_id": AGENT, "module_id": module, "enabled": True, "config": config(module)}
    first = assign_module(cur, body, actor="fixture-owner")
    assert first["policy_revision"] == 2
    assert first["assigned_modules"][0] == "sli.heartbeat"
    assert cur.old["policy_revision"] == "2"
    assert cur.history[1][0] == ["sli.heartbeat"]
    assert cur.history[2][0] == first["assigned_modules"]
    assert cur.history[2][1]["state"] == control_state
    oversized = {**body["config"], **{name: ["x" * 512] * 64 for name in ("dc", "search_bases", "groups")}}
    with pytest.raises(AgentError, match="agent_policy_size_limit"):
        assign_module(cur, {**body, "config": oversized}, actor="fixture-owner")
    assert cur.agent["policy_revision"] == 2 and 3 not in cur.history
    body["config"]["scope"] = "other-fixture"
    with pytest.raises(AgentError, match="agent_snapshot_binding_immutable"):
        assign_module(cur, body, actor="fixture-owner")
    body["config"]["scope"] = "fixture-scope"
    cur.other = True
    with pytest.raises(AgentError, match="agent_snapshot_collector_conflict"):
        assign_module(cur, body, actor="fixture-owner")
    assert cur.agent["policy_revision"] == 2
    disabled = assign_module(cur, {**body, "enabled": False}, actor="fixture-owner")
    assert disabled["policy_revision"] == 3
    assert disabled["assigned_modules"][-1]["enabled"] is False
    audits = [json.loads(params[3]) for sql, params in cur.calls if "insert into sli_agent_audit" in sql]
    assert all("config" not in audit and "domain_dns" not in audit and len(audit["policy_sha256"]) == 64 for audit in audits)
    update_control(cur, {"agent_id": AGENT, "expected_revision": 3,
                         "collection_policy": {"state": "active"}}, actor="fixture-owner")
    assert cur.agent["policy_revision"] == 4
    assert cur.history[4][0] == disabled["assigned_modules"]
    assert cur.history[4][1]["state"] == "active"
    with pytest.raises(AgentError, match="agent_policy_revision_conflict"):
        assign_module(cur, {**body, "enabled": False, "expected_revision": 3}, actor="fixture-owner")
    updated = assign_module(cur, {**body, "enabled": False, "expected_revision": 4}, actor="fixture-owner")
    assert updated["policy_revision"] == 5
    assert updated["assigned_modules"][-1]["config"]["policy_revision"] == "5"
    previous_config = deepcopy(cur.old)
    schedule = {"timezone": "Asia/Kathmandu", "hours": [0, 8, 23]}
    changed = assign_module(cur, {**body, "enabled": False, "expected_revision": 5,
        "config": {**body["config"], "schedule": schedule}}, actor="fixture-owner")
    assert changed["policy_revision"] == 6
    assert cur.old["schedule"] == schedule and cur.old["policy_revision"] == "6"
    assert cur.history[5][0][-1]["config"] == previous_config
    assert cur.history[6][0][-1]["config"] == cur.old
    assert all(cur.old[name] == previous_config[name] for name in
               ("source_instance_id", "domain_sid", "domain_dns", "scope"))


@pytest.mark.parametrize("changes", [{"password": "fixture-secret"}, {"capture_seconds": 0},
    {"max_bytes": 65 * 1024**2}, {"max_objects": 50001}, {"buffer_bytes": 129 * 1024**2},
    {"schedule": {"timezone": "UTC", "hours": [True]}}, {"domain_sid": "invalid"},
    {"source_instance_id": "invalid"}, {"families": ["gpo_v2"]}, {"expensive_flags": {"unknown": True}}])
def test_invalid_snapshot_policy_is_fixed_code_only(changes):
    with pytest.raises(ValueError, match="^agent_snapshot_policy_invalid$"):
        config(**changes)


@pytest.mark.parametrize("batch_size,limit,snapshot_sends,heartbeat_sends", [(16, None, 16, 1), (2, None, 2, 1), (16, 3, 3, 0), (16, 0, 0, 0)])
def test_delivery_burst_and_common_limits(tmp_path, key, batch_size, limit, snapshot_sends, heartbeat_sends):
    result = stream(tmp_path / "capture", size=FRAGMENT_BYTES * 18)
    spool = Spool(tmp_path / "spool", max_bytes=2 * 1024**2, max_age_seconds=86400)
    while (sample := result.next_sample(spool.captured(MODULE))) is not None:
        spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    spool.capture(key, agent_id=AGENT, sample=HeartbeatModule(SOURCE).collect(now=NOW), now=NOW)
    sent = []
    def upload(value):
        e = value["envelope"]
        sent.append(e["module_id"])
        return {"contract_id": "sli.agent-receipt.v1", "status": "committed", "packet_id": e["packet_id"],
            "payload_sha256": e["payload_sha256"], "committed_cursor": e["cursor_after"], "evidence_ref": "fixture",
            "committed_at_utc": NOW.isoformat(), "error_code": None}
    assert deliver_once(spool, upload, batch_size=batch_size, limit=limit)
    assert sent.count(MODULE) == snapshot_sends and sent.count("sli.heartbeat") == heartbeat_sends
    assert len(spool.pending()) == 20 - snapshot_sends - heartbeat_sends


def test_storage_failure_rolls_back_receipt_and_never_returns_ack(tmp_path, key):
    value = packets(stream(tmp_path), key)[0]
    writes = []
    class Cursor:
        def execute(self, sql, params=()):
            if "insert into sli_agent_snapshot_chunks" in sql:
                raise RuntimeError("fixture-storage-failed")
            writes.append(sql)
    @contextmanager
    def transaction():
        try: yield
        except RuntimeError:
            writes.clear()
            raise
    with pytest.raises(RuntimeError), transaction():
        PostgresLedger(Cursor()).commit(value, {"status": "committed"}, digest(value["envelope"]), None)
    assert not writes


@pytest.mark.parametrize("reason", ["slot", "metadata", "duplicate", "objects", "bytes", None])
def test_postgres_chunk_conflicts_and_aggregate_limits(tmp_path, key, reason):
    from server.sli.agents.snapshot_ingest import conflict
    value = packets(stream(tmp_path), key)[0]
    e, p = value["envelope"], value["payload"]
    class Cursor:
        def execute(self, sql, params=()):
            self.rows = []
            if "select cycle_id" in sql and reason == "slot": self.rows = [{"cycle_id": str(uuid4())}]
            elif "select payload" in sql and reason == "metadata":
                self.rows = [{"payload": {**p, "family_sha256": "0" * 64}}]
            elif "select packet_id" in sql and reason == "duplicate": self.rows = [{"packet_id": str(uuid4())}]
            elif "select distinct" in sql and reason in ("objects", "bytes"):
                self.rows = [{"family": "ad_domain_health", "objects": 50000 if reason == "objects" else 0,
                              "bytes": 25 * 1024**2 if reason == "bytes" else 0}]
        def fetchone(self): return self.rows[0] if self.rows else None
        def fetchall(self): return self.rows
    assert conflict(Cursor(), e, p, config()) == (reason is not None)


@pytest.mark.parametrize("budget", ["agent_count", "agent_bytes", "module_count", "module_bytes",
    "global_count", "global_bytes", "storage_bytes", None])
def test_snapshot_quota_covers_pending_chunks_and_retained_storage(tmp_path, key, budget):
    from server.sli.agents.inbox_quota import InboxLimits
    from server.sli.agents.snapshot_ingest import quota_error
    value = packets(stream(tmp_path), key)[0]
    class Cursor:
        def __init__(self): self.calls = []
        def execute(self, sql, params=()):
            self.calls.append(sql)
            if "as agent_count" in sql:
                self.row = dict.fromkeys(("agent_count", "agent_bytes", "module_count", "module_bytes", "global_count", "global_bytes"), 0)
                if budget in self.row: self.row[budget] = getattr(InboxLimits(), budget)
            elif "pg_total_relation_size" in sql:
                self.row = {"bytes": InboxLimits().storage_bytes if budget == "storage_bytes" else 0}
        def fetchone(self): return self.row
    cur = Cursor()
    code = quota_error(cur, value, {"status": "committed"})
    assert code == ("agent_snapshot_" + budget + "_limit" if budget else None)
    assert cur.calls[0] == "select pg_advisory_xact_lock(170,1)"
    assert all("sli_agent_packet_inbox" not in sql and "insert" not in sql for sql in cur.calls)


def test_unfinished_capture_restart_uses_original_revision(tmp_path, key):
    result = SnapshotStream(tmp_path / "capture", MODULE)
    state = result.begin(config(), now=NOW)
    captured_configs = []
    class Collector(SnapshotModule):
        def capture(self, cfg, *, deadline, stop):
            captured_configs.append(cfg)
            return {"ad_context_base": ({"fixture": 1}, 1)}
    module = Collector(MODULE, config(policy_revision="2", families=["ad_context_base", "ad_domain_health"]))
    runner = SnapshotCapture(tmp_path / "capture")
    spool = Spool(tmp_path / "spool", max_bytes=1024**2, max_age_seconds=86400)
    identity = SimpleNamespace(agent_id=AGENT, key=key)
    try:
        runner.tick([module], spool, identity, now=NOW)
        assert runner.job["done"].wait(1)
        runner.tick([module], spool, identity, now=NOW)
        assert captured_configs == [state["policy"]]
        assert spool.pending()[0]["envelope"]["policy_revision"] == "1"
        assert spool.pending()[0]["payload"]["cycle_id"] == state["cycle_id"]
    finally:
        runner.close()
