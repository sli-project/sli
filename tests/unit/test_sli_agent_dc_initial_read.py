"""Initial DC windows and independently retryable history, without Windows or a DB."""
from datetime import timedelta
import json

import pytest

from sli_agent.ad_dc import ADDCModule
from tests.unit.test_sli_agent_ad_dc import CONFIG, HOST, NOW, Reader, checkpoint, xml


def test_default_initial_read_freezes_24_hour_boundary_even_when_empty():
    reader = Reader({})
    collector = ADDCModule(HOST, CONFIG, reader=reader)
    first = collector.collect(now=NOW)
    since = (NOW - timedelta(hours=24)).isoformat()
    assert reader.calls[0][1]["since_utc"] == since
    state = json.loads(first.cursor_after["token"])
    assert state["channels"]["Security"]["since_utc"] == since
    captured = checkpoint(first)
    for _ in range(2):
        captured = checkpoint(collector.collect(captured, now=NOW))
    restarted = ADDCModule(HOST, CONFIG, reader=reader)
    restarted.collect(captured, now=NOW + timedelta(days=3))
    assert reader.calls[-1][1]["since_utc"] == since


@pytest.mark.parametrize("depth, expected", [(0, NOW.isoformat()), (48, (NOW - timedelta(hours=48)).isoformat()), ("all", None)])
def test_initial_read_modes(depth, expected):
    reader = Reader({})
    ADDCModule(HOST, {**CONFIG, "initial_read_hours": depth}, reader=reader).collect(now=NOW)
    assert reader.calls[0][1].get("since_utc") == expected


def test_legacy_bookmark_has_priority_over_changed_depth():
    old = ADDCModule(HOST, {**CONFIG, "initial_read_hours": "all",
                         "channels": {"System": False, "Directory Service": False}},
                     reader=Reader({"Security": [(1, xml(4624, 1))]})).collect(now=NOW)
    reader = Reader({})
    collector = ADDCModule(HOST, {**CONFIG, "initial_read_hours": 0,
                               "channels": {"System": False, "Directory Service": False}}, reader=reader)
    collector.collect(checkpoint(old), now=NOW + timedelta(days=3))
    assert reader.calls[0][1] == {"record_id": 1, "bookmark": "bookmark-1", "generation": HOST}


def test_existing_empty_all_history_cursor_is_not_reinitialized_by_policy_change():
    channels = {"System": False, "Directory Service": False}
    first = ADDCModule(HOST, {**CONFIG, "initial_read_hours": "all", "channels": channels}, reader=Reader({})).collect(now=NOW)
    reader = Reader({})
    ADDCModule(HOST, {**CONFIG, "initial_read_hours": 0, "channels": channels}, reader=reader).collect(
        checkpoint(first), now=NOW + timedelta(days=2))
    assert "since_utc" not in reader.calls[0][1]


def test_start_boundary_uses_capture_time_when_spool_write_occurs_later():
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import receive_packet
    from sli_agent.envelope import make_packet
    from tests.unit.test_sli_agent_ad_dc import AGENT, Ledger
    sample = ADDCModule(HOST, CONFIG, reader=Reader({})).collect(now=NOW)
    key = ec.generate_private_key(ec.SECP256R1())
    when = NOW + timedelta(seconds=1)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=when)
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": sample.module_id, "enabled": True, "config": CONFIG}]}
    assert receive_packet(Ledger(), identity=identity, public_key=key.public_key(), value=value, now=when)["status"] == "committed"


@pytest.mark.parametrize("depth", [-1, True, 1.5, "24", None])
def test_invalid_initial_depth_rejected(depth):
    with pytest.raises(ValueError, match="agent_ad_dc_config_invalid"):
        ADDCModule(HOST, {**CONFIG, "initial_read_hours": depth})


def test_history_stops_at_frozen_boundary_and_does_not_change_live_cursor():
    from sli_agent.ad_dc import DCHistoryModule
    live = ADDCModule(HOST, CONFIG, reader=Reader({})).collect(now=NOW)
    live_cursor = json.loads(live.cursor_after["token"])
    before = (NOW + timedelta(hours=1)).isoformat()
    history = DCHistoryModule(HOST, {**CONFIG, "history_before_utc": before,
                                   "channels": {"System": False, "Directory Service": False}},
                             reader=Reader({"Security": [(1, xml(4624, 1))]}))
    first = history.collect(now=NOW)
    assert first.module_id != live.module_id
    assert history.reader.calls[0][1]["before_utc"] == before
    assert first.payload["records"][0]["record_id"] == 1
    exhausted = history.collect(checkpoint(first), now=NOW)
    assert history.collect(checkpoint(exhausted), now=NOW) is None
    assert json.loads(live.cursor_after["token"]) == live_cursor
    assert history.config["batch_size"] == 4


def test_delivery_prioritizes_live_packets_even_with_failed_history():
    from types import SimpleNamespace
    from sli_agent.ad_dc import HISTORY_ID, PACK_ID
    from sli_agent.runtime import deliver_once
    history = {"envelope": {"module_id": HISTORY_ID}}
    live = {"envelope": {"module_id": PACK_ID}}
    calls = []
    spool = SimpleNamespace(pending=lambda **_: [history, live], acknowledge=lambda value, receipt: value is live)
    assert deliver_once(spool, lambda value: calls.append(value) or {}, limit=3)
    assert calls == [live, history]


def test_history_cannot_consume_last_rate_limit_slot():
    from types import SimpleNamespace
    from sli_agent.ad_dc import HISTORY_ID
    from sli_agent.runtime import deliver_once
    calls = []
    spool = SimpleNamespace(pending=lambda **_: [{"envelope": {"module_id": HISTORY_ID}}],
                            acknowledge=lambda *_: True)
    assert deliver_once(spool, lambda value: calls.append(value) or {}, limit=1)
    assert not calls


def test_signed_history_has_independent_receipts_and_rejects_out_of_window_rows():
    from dataclasses import replace
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import receive_packet
    from sli_agent.ad_dc import DCHistoryModule, HISTORY_ID
    from sli_agent.envelope import make_packet
    from tests.unit.test_sli_agent_ad_dc import AGENT, Ledger
    config = {**CONFIG, "history_before_utc": (NOW + timedelta(hours=1)).isoformat(),
              "channels": {"System": False, "Directory Service": False}}
    history = DCHistoryModule(HOST, config, reader=Reader({"Security": [(1, xml(4624, 1))]}))
    ledger = Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": HISTORY_ID, "enabled": True, "config": config}]}
    key = ec.generate_private_key(ec.SECP256R1())
    sample = history.collect(now=NOW)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)["status"] == "committed"
    assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)["status"] == "duplicate"
    boundary = NOW.isoformat()
    state = json.loads(sample.cursor_after["token"])
    state["channels"]["Security"]["before_utc"] = boundary
    bad = replace(sample, cursor_after={"strategy": "bookmark", "token": json.dumps(state)})
    bad_identity = {**identity, "assigned_modules": [{"module_id": HISTORY_ID, "enabled": True,
                                                    "config": {**config, "history_before_utc": boundary}}]}
    bad_value = make_packet(key, agent_id=AGENT, sequence=1, sample=bad, now=NOW)
    assert receive_packet(Ledger(), identity=bad_identity, public_key=key.public_key(), value=bad_value, now=NOW)["error_code"] == "agent_collection_packet_invalid"


def test_history_ingress_keeps_only_one_unimported_packet_per_agent():
    from server.sli.agent_ingest import PostgresLedger
    from sli_agent.ad_dc import HISTORY_ID
    class Cursor:
        def execute(self, sql, params):
            assert "imported_at is null" in sql and params[1] == HISTORY_ID
        def fetchone(self):
            return {"packet_id": "fixture-packet"}
    assert PostgresLedger(Cursor()).quota_error({"envelope": {"agent_id": HOST, "module_id": HISTORY_ID}}, {}, []) == "agent_history_pending"


def test_old_history_evidence_is_retained_without_pausing_current_capture(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent.ad_dc import DCHistoryModule, HISTORY_ID, PACK_ID
    from sli_agent.spool import Spool
    from tests.unit.test_sli_agent_ad_dc import AGENT
    key = ec.generate_private_key(ec.SECP256R1())
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    history = DCHistoryModule(HOST, {**CONFIG, "history_before_utc": NOW.isoformat()}, reader=Reader({}))
    old = NOW - timedelta(hours=2)
    old_packet = spool.capture(key, agent_id=AGENT, sample=history.collect(now=old), now=old)
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    live = ADDCModule(HOST, CONFIG, reader=Reader({})).collect(now=NOW)
    spool.capture(key, agent_id=AGENT, sample=live, now=NOW)
    assert old_packet in spool.pending()
    assert spool.captured(HISTORY_ID)["sequence"] == 1
    assert spool.captured(PACK_ID)["sequence"] == 1


def test_new_records_after_bookmark_are_not_dropped_when_source_clock_moves_back():
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import receive_packet
    from sli_agent.envelope import make_packet
    from tests.unit.test_sli_agent_ad_dc import AGENT, Ledger
    config = {**CONFIG, "initial_read_hours": 0, "channels": {"System": False, "Directory Service": False}}
    reader = Reader({"Security": [(1, xml(4624, 1))]})
    collector = ADDCModule(HOST, config, reader=reader)
    first = collector.collect(now=NOW)
    backwards = xml(4624, 2).replace("2026-10-07T00:00:00Z", "2026-10-06T23:00:00Z")
    reader.events["Security"].append((2, backwards))
    second = collector.collect(checkpoint(first), now=NOW + timedelta(hours=1))
    ledger = Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": collector.module_id, "enabled": True, "config": config}]}
    key = ec.generate_private_key(ec.SECP256R1())
    for sequence, sample, when in ((1, first, NOW), (2, second, NOW + timedelta(hours=1))):
        value = make_packet(key, agent_id=AGENT, sequence=sequence, sample=sample, now=when)
        assert receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=when)["status"] == "committed"


def test_history_capture_failure_does_not_back_off_live_loop(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent import runtime
    from sli_agent.ad_dc import DCHistoryModule, PACK_ID
    from sli_agent.config import AgentConfig
    from sli_agent.policies import AppliedPolicy
    from sli_agent.spool import Spool
    from tests.unit.test_sli_agent_ad_dc import AGENT
    identity = SimpleNamespace(agent_id=AGENT, key=ec.generate_private_key(ec.SECP256R1()))
    monkeypatch.setattr(runtime, "IdentityStore", lambda _: SimpleNamespace(
        prepare=lambda: {"host_id": HOST}, load=lambda: identity, renew_if_due=lambda *a, **k: False))
    monkeypatch.setattr(runtime, "configured_modules", lambda *_: [])
    live = ADDCModule(HOST, CONFIG, reader=Reader({}))
    history = DCHistoryModule(HOST, {**CONFIG, "history_before_utc": NOW.isoformat()},
                             reader=lambda *_: [("invalid", "fixture-bookmark")])
    monkeypatch.setattr(runtime, "apply_policy", lambda *a, **k: AppliedPolicy([live, history], None, None))
    def post(_path, value, **_):
        from tests.unit.test_sli_agent_v1 import receipt
        return receipt(value)
    monkeypatch.setattr(runtime, "Transport", lambda _: SimpleNamespace(
        get=lambda *a, **k: {"agent_id": AGENT, "assigned_modules": []}, post=post))
    class Stop:
        waits = []
        def is_set(self):
            return len(self.waits) == 2
        def wait(self, delay):
            self.waits.append(delay)
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    stop = Stop()
    monkeypatch.setattr(runtime.time, "monotonic", lambda: len(stop.waits) * 60.0)
    runtime.run(config, stop)
    assert stop.waits == [60, 60]
    state = json.loads((tmp_path / "status.json").read_bytes())
    assert state["error_code"] is None and state["history_error_code"] == "agent_history_capture_failed"
    assert Spool(tmp_path / "spool", max_bytes=100000, max_age_seconds=3600).captured(PACK_ID)["sequence"] == 2


def test_history_retry_preserves_live_delivery_and_both_cursors_after_restart(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import receive_packet
    from sli_agent.ad_dc import DCHistoryModule, HISTORY_ID, PACK_ID
    from sli_agent.runtime import deliver_once
    from sli_agent.spool import Spool
    from tests.unit.test_sli_agent_ad_dc import AGENT, Ledger
    class Streams(Ledger):
        history_pending = False
        def get(self, _agent, module, sequence):
            return next((entry for entry in self.entries if entry["envelope"]["module_id"] == module
                         and entry["envelope"]["sequence"] == sequence), None)
        def latest(self, _agent, module):
            return next((entry["envelope"] for entry in reversed(self.entries)
                         if entry["envelope"]["module_id"] == module), None)
        def quota_error(self, value, *_):
            if value["envelope"]["module_id"] == HISTORY_ID and self.history_pending:
                return "agent_history_pending"
            return None
        def commit(self, value, *args):
            super().commit(value, *args)
            if value["envelope"]["module_id"] == HISTORY_ID:
                self.history_pending = True
    config = {**CONFIG, "channels": {"System": False, "Directory Service": False}}
    history_config = {**config, "history_before_utc": (NOW + timedelta(hours=1)).isoformat()}
    live_reader = Reader({"Security": [(1, xml(4624, 1))]})
    live = ADDCModule(HOST, config, reader=live_reader)
    history = DCHistoryModule(HOST, history_config, reader=Reader({"Security": [(1, xml(4624, 1))]}))
    key = ec.generate_private_key(ec.SECP256R1())
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": PACK_ID, "enabled": True, "config": config},
        {"module_id": HISTORY_ID, "enabled": True, "config": history_config}]}
    ledger = Streams()
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    def upload(value):
        return receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    for module in (live, history):
        spool.capture(key, agent_id=AGENT, sample=module.collect(now=NOW), now=NOW)
    assert deliver_once(spool, upload, now=NOW, limit=3)
    assert not spool.pending()
    live_reader.events["Security"].append((2, xml(4624, 2)))
    for module in (live, history):
        sample = module.collect(spool.captured(module.module_id), now=NOW)
        spool.capture(key, agent_id=AGENT, sample=sample, now=NOW)
    assert deliver_once(spool, upload, now=NOW, limit=3)
    assert ledger.latest(AGENT, PACK_ID)["sequence"] == 2
    assert ledger.latest(AGENT, HISTORY_ID)["sequence"] == 1
    restarted = Spool(tmp_path, max_bytes=100000, max_age_seconds=3600)
    assert len(restarted.pending()) == 1
    assert restarted.pending()[0]["envelope"]["module_id"] == HISTORY_ID
    assert restarted.captured(PACK_ID)["cursor_after"] == spool.captured(PACK_ID)["cursor_after"]
    ledger.history_pending = False
    assert deliver_once(restarted, upload, now=NOW, limit=3)
    assert not restarted.pending()
    assert history.collect(restarted.captured(HISTORY_ID), now=NOW) is None
