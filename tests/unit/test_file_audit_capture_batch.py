"""File capture catches up using bounded, durable packets and fake readers."""
from dataclasses import replace
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent import runtime
from sli_agent.envelope import canonical
from sli_agent.spool import Spool, SpoolFull
from tests.unit.test_file_audit_collection import NOW, collector, xml
from tests.unit.test_file_audit_contracts import AGENT, settings


def setup_capture(tmp_path, *, clock=lambda: 0.0, reader=None):
    seen = []

    def read(_channel, cursor, _limit):
        seen.append(cursor["record_id"])
        record = (cursor["record_id"] or 0) + 1
        return [(xml(record), f"b{record}")]

    module = collector(settings(), reader=reader or read, path_check=lambda *_: "file", clock=clock)
    spool = Spool(tmp_path, max_bytes=100000, max_age_seconds=86400)
    identity = SimpleNamespace(agent_id=AGENT, key=ec.generate_private_key(ec.SECP256R1()))
    return module, spool, identity, seen


def test_file_capture_spools_multiple_packets_with_contiguous_cursors(tmp_path):
    module, spool, identity, seen = setup_capture(tmp_path)
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    packets = spool.pending()
    assert len(packets) == 4 and seen == [None, 1, 2, 3]
    assert [p["envelope"]["sequence"] for p in packets] == [1, 2, 3, 4]
    for previous, current in zip(packets, packets[1:]):
        assert current["envelope"]["cursor_before"] == previous["envelope"]["cursor_after"]
    # Backpressure prevents another burst while the outstanding batch remains.
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert len(spool.pending()) == 4 and len(seen) == 4


@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize("rejection", ["path", "account"])
def test_file_capture_continues_after_durable_finite_record_loss(tmp_path, monkeypatch, mixed, rejection):
    rejected_record = 2 if mixed else 1
    calls, order = [], []

    def read(_channel, cursor, _limit):
        # Reopen the real spool to verify durable progress before every read.
        durable = Spool(tmp_path, max_bytes=100000, max_age_seconds=86400)
        captured = durable.captured(module.module_id)
        assert len(durable.pending()) == len(calls)
        assert cursor == module.state(captured["cursor_after"] if captured else {"strategy": "bookmark", "token": ""})
        calls.append(cursor["record_id"])
        order.append("read")
        if cursor["record_id"] is None:
            rows = [(xml(1), "b1")] if mixed else []
            return rows + [(xml(rejected_record, path=r"C:\synthetic\rejected"), f"b{rejected_record}")]
        if cursor["record_id"] == rejected_record:
            return [(xml(rejected_record + 1), f"b{rejected_record + 1}")]
        return []

    module, spool, identity, _ = setup_capture(tmp_path, reader=read)

    def blocked_path(path, _root):
        if path.endswith("rejected"):
            raise ValueError("synthetic-private-diagnostic")
        return "file"

    account_calls = []

    def blocked_account(_account):
        account_calls.append(None)
        if len(account_calls) == rejected_record:
            raise RuntimeError("synthetic-private-diagnostic")
        return True

    if rejection == "path":
        module.path_check = blocked_path
    else:
        module.account_check = blocked_account
    capture = spool.capture

    def persist(*args, **kwargs):
        packet = capture(*args, **kwargs)
        order.append("capture")
        return packet

    monkeypatch.setattr(spool, "capture", persist)
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert calls == [None, rejected_record, rejected_record + 1]
    assert order == ["read", "capture"] * 3
    packets = spool.pending()
    assert len(packets) == 3
    first, following, tail = packets
    assert first["envelope"]["lost_count"] == first["payload"]["context"]["lost_count"] == 1
    assert first["envelope"]["continuity_state"] == "gap"
    assert first["payload"]["context"]["read_error"] is None
    assert first["envelope"]["cursor_after"] != first["envelope"]["cursor_before"]
    assert [row["record_id"] for row in first["payload"]["records"]] == ([1] if mixed else [])
    assert [row["record_id"] for row in following["payload"]["records"]] == [rejected_record + 1]
    assert tail["payload"]["records"] == [] and tail["envelope"]["lost_count"] == 0
    for previous, current in zip(packets, packets[1:]):
        assert current["envelope"]["cursor_before"] == previous["envelope"]["cursor_after"]
        assert current["envelope"]["generation"] == previous["envelope"]["generation"]
    assert b"rejected" not in canonical(packets) and b"synthetic-private" not in canonical(packets)


@pytest.mark.parametrize("stop", ["generation", "cursor", "unknown_loss", "zero_loss",
                                  "file_audit_read_failed", "file_audit_journal_gap"])
def test_file_capture_finite_loss_does_not_override_stop_conditions(tmp_path, monkeypatch, stop):
    module, spool, identity, _ = setup_capture(tmp_path)
    spool.capture(identity.key, agent_id=identity.agent_id, sample=module.collect(now=NOW), now=NOW)

    def blocked(*_):
        raise ValueError("synthetic-private-diagnostic")

    module.path_check = blocked
    sample = module.collect(spool.captured(module.module_id), now=NOW)
    assert sample.lost_count == 1 and sample.continuity_state == "gap"
    if stop == "generation":
        generation = AGENT + ":00000000-0000-4000-8000-000000000002"
        progress = {**module.state(sample.cursor_after), "generation": generation}
        sample = replace(sample, generation=generation,
                         cursor_after={"strategy": "bookmark", "token": canonical(progress).decode()})
        sample.payload["header"]["generation"] = generation
    elif stop == "cursor":
        sample = replace(sample, cursor_after=sample.cursor_before)
    elif stop in ("unknown_loss", "zero_loss"):
        sample = replace(sample, lost_count=None if stop == "unknown_loss" else 0)
        sample.payload["context"]["lost_count"] = sample.lost_count
    else:
        sample.payload["context"]["read_error"] = stop
    calls = []

    def collect(captured, **_):
        calls.append(captured["sequence"])
        return sample

    monkeypatch.setattr(module, "collect", collect)
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert calls == [1] and len(spool.pending()) == 2


@pytest.mark.parametrize("failure", ["read", "reset", "clear"])
def test_file_capture_stops_on_native_break_after_finite_loss(tmp_path, failure):
    from sli_agent.file_audit_journal import JournalGap

    calls = []

    def read(_channel, cursor, _limit):
        calls.append(cursor["record_id"])
        if cursor["record_id"] is None:
            return [(xml(1), "b1")]
        if failure == "read":
            raise RuntimeError("synthetic-private-diagnostic")
        if failure == "reset":
            raise JournalGap()
        clear = xml(2, 1102, path="").replace("Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Eventlog")
        return [(clear, "b2")]

    module, spool, identity, _ = setup_capture(tmp_path, reader=read)

    def blocked(*_):
        raise ValueError("synthetic-private-diagnostic")

    module.path_check = blocked
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert calls == [None, 1]
    first, broken = spool.pending()
    assert first["envelope"]["lost_count"] == 1 and first["envelope"]["continuity_state"] == "gap"
    assert broken["envelope"]["lost_count"] is None and broken["envelope"]["continuity_state"] == "gap"
    assert broken["payload"]["context"]["read_error"] == (
        "file_audit_read_failed" if failure == "read" else "file_audit_journal_gap")
    assert (broken["envelope"]["generation"] != first["envelope"]["generation"]) == (failure == "reset")


@pytest.mark.parametrize("state,expected", [("active", 4), ("paused", 0), ("drain", 0), ("unavailable", 0)])
def test_runtime_drains_file_backlog_only_in_active_controlled_cycle(tmp_path, monkeypatch, state, expected):
    from sli_agent.config import AgentConfig
    from sli_agent.control import collection_policy
    from sli_agent.policies import AppliedPolicy

    module, _, identity, seen = setup_capture(tmp_path / "fixture")
    control = collection_policy({"state": "active" if state == "unavailable" else state,
                                 "interval_seconds": 1, "batch_size": 4})
    monkeypatch.setattr(runtime.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(runtime, "IdentityStore", lambda _: SimpleNamespace(
        prepare=lambda: {"host_id": AGENT}, load=lambda: identity, renew_if_due=lambda *a, **k: None))
    monkeypatch.setattr(runtime, "configured_modules", lambda *a: [])
    monkeypatch.setattr(runtime, "apply_policy", lambda *a, **k: AppliedPolicy([module], control, None))
    def checkin(*args, **kwargs):
        if state == "unavailable":
            raise OSError("synthetic-private-diagnostic")
        return {"agent_id": AGENT, "assigned_modules": [], "policy_revision": 1}

    monkeypatch.setattr(runtime, "Transport", lambda _: SimpleNamespace(get=checkin, post=lambda *a, **k: {}))

    class Stop:
        done = False

        def is_set(self):
            return self.done

        def wait(self, _delay):
            self.done = True

    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state")
    monkeypatch.setattr(runtime, "service_identity_verified", lambda candidate: candidate is config)
    monkeypatch.setattr(runtime, "probe", lambda *args, **kwargs: {"identity_verified": True, "ready": True})
    runtime.run(config, Stop())
    spool = Spool(config.storage_dir / "spool", max_bytes=100000, max_age_seconds=86400)
    assert len(spool.pending()) == expected and seen == ([None, 1, 2, 3] if expected else [])


@pytest.mark.parametrize("batch_size,expected", [(1, 1), (128, 16)])
def test_file_capture_respects_control_and_hard_packet_limit(tmp_path, batch_size, expected):
    module, spool, identity, seen = setup_capture(tmp_path)
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=batch_size, clock=lambda: 0.0)
    assert len(spool.pending()) == expected and len(seen) == expected


@pytest.mark.parametrize("failure", [False, True])
@pytest.mark.parametrize("initial_read_hours", ["all", 0])
def test_file_capture_stops_on_empty_tail_or_read_failure(tmp_path, failure, initial_read_hours):
    def read(*_):
        if failure:
            raise RuntimeError("synthetic-private-diagnostic")
        return []
    module, spool, identity, _ = setup_capture(tmp_path, reader=read)
    module.policy["initial_read_hours"] = initial_read_hours
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert len(spool.pending()) == 1
    assert spool.pending()[0]["envelope"]["continuity_state"] == ("gap" if failure else "not_proven")


def test_file_capture_stops_at_cycle_time_budget(tmp_path):
    ticks = iter([0.0, 0.0, 30.0])
    module, spool, identity, seen = setup_capture(tmp_path)
    runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: next(ticks))
    assert len(spool.pending()) == 1 and seen == [None]


def test_file_capture_spool_failure_does_not_read_past_unpersisted_cursor(tmp_path, monkeypatch):
    module, spool, identity, seen = setup_capture(tmp_path)
    capture = spool.capture

    def full(*args, **kwargs):
        if spool.captured(module.module_id):
            raise SpoolFull("agent_spool_size_limit")
        return capture(*args, **kwargs)

    monkeypatch.setattr(spool, "capture", full)
    with pytest.raises(SpoolFull):
        runtime.capture_module(module, spool, identity, now=NOW, batch_size=4, clock=lambda: 0.0)
    assert seen == [None, 1] and len(spool.pending()) == 1
    assert spool.captured(module.module_id)["sequence"] == 1
