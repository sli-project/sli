"""Live per-agent control using synthetic identities, readers and durable spool."""
import json
import threading
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent import runtime
from sli_agent.config import AgentConfig
from sli_agent.modules import HeartbeatModule
from sli_agent.snapshot_stream import SnapshotModule, SnapshotStream
from sli_agent.snapshot_stream import policy as snapshot_policy
from sli_agent.spool import Spool

AGENT = "00000000-0000-4000-8000-000000000001"
HOST = "00000000-0000-4000-8000-000000000002"
NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def policy_report(revision, state):
    return {"applied_policy_revision": revision, "collection_state": state}


def receipt(value):
    envelope = value["envelope"]
    return {"contract_id": "sli.agent-receipt.v1", "packet_id": envelope["packet_id"],
            "payload_sha256": envelope["payload_sha256"], "status": "committed",
            "committed_cursor": envelope["cursor_after"], "evidence_ref": "fixture-evidence",
            "committed_at_utc": NOW.isoformat(), "error_code": None}


def exercise(tmp_path, monkeypatch, states, *, reject=False, ack_failure=False, limit=100, interval=5,
             instance=None, updating=False, snapshot_config=None, on_report=None, batch_size=4, msi_update=False,
             read_diagnostics=False, delivery_diagnostics=False):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state" if updating or msi_update else tmp_path,
        instance_name=instance, host_id=HOST if instance else None,
        **({"update_root": tmp_path / "releases", "update_trust_store": tmp_path / "trust.json",
            "service_python": tmp_path / "python.exe"} if updating else {}))
    identity = SimpleNamespace(agent_id=AGENT, key=ec.generate_private_key(ec.SECP256R1()))
    spool = Spool(config.storage_dir / "spool", max_bytes=100000, max_age_seconds=86400)
    sample = replace(HeartbeatModule(HOST).collect(now=NOW), module_id="sli.workstations")
    saved = spool.capture(identity.key, agent_id=AGENT, sample=sample)
    calls, collected, reports, delays, audit_reports, update_reports = [], [], [], [], [], []
    if msi_update:
        (tmp_path / ".msi-owned").write_text("sli-agent-msi-v1")
    audit_positions = []
    clock = [0.0]
    monkeypatch.setattr(runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(runtime, "service_identity_verified", lambda candidate: candidate is config)
    monkeypatch.setattr(runtime, "probe", lambda *args, **kwargs: {"identity_verified": True, "ready": True})
    class Collector:
        module_id = "sli.workstations"
        def collect(self, captured, *, now):
            if read_diagnostics:
                from sli_collect.eventlog_diagnostics import diagnostic
                self.read_observation = {"channel": "Security", "observed_at_utc": now.isoformat(),
                    "error": diagnostic(OSError("private-event"), "Security",
                        {"record_id": 42, "bookmark": "private-bookmark"}, "read")}
            collected.append(deepcopy(captured))
            return replace(HeartbeatModule(HOST).collect(captured, now=now), module_id=self.module_id)

    policies = iter(states)
    def get(*args, **kwargs):
        state = next(policies)
        calls.append("checkin")
        if isinstance(state, Exception):
            raise state
        return {"agent_id": AGENT, "policy_revision": state[1], "assigned_modules": [],
                **({"eventlog_diagnostics_supported": True} if read_diagnostics else {}),
                **({"delivery_diagnostics_supported": True} if delivery_diagnostics else {}),
                **({"agent_update": {"sha256": "a" * 64, "version": "1.1.0"}} if updating or msi_update else {}),
                "collection_policy": {"state": state[0], "interval_seconds": interval, "batch_size": batch_size,
                                      "rate_limit_per_minute": limit, "spool_max_bytes": 65536}}

    def post(path, body, **kwargs):
        if path.endswith("update-result"):
            assert kwargs["identity"] is identity
            calls.append("msi-update-result")
            update_reports.append(deepcopy(body))
            return {}
        if path.endswith("windows-audit-report"):
            assert kwargs["identity"] is identity
            audit_positions.append(len(calls))
            audit_reports.append(deepcopy(body))
            return {}
        if path.endswith("policy-report"):
            calls.append("report")
            reports.append(deepcopy(body))
            if on_report is not None:
                on_report(body)
            if ack_failure:
                raise OSError("fixture")
            return {}
        calls.append("send")
        return {**receipt(body), **({"status": "retry_later", **({"error_code": "agent_sequence_gap"} if delivery_diagnostics else {})} if reject else {})}

    monkeypatch.setattr(runtime, "IdentityStore", lambda cfg: SimpleNamespace(
        prepare=lambda: {"host_id": HOST}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    monkeypatch.setattr(runtime, "Transport", lambda cfg: SimpleNamespace(get=get, post=post))
    monkeypatch.setattr("sli_agent.policies.configured_modules", lambda *a: [HeartbeatModule(HOST), Collector()]
                        + ([SnapshotModule("sli.ad-snapshot", snapshot_config)] if snapshot_config else []))
    if updating:
        class Updates:
            def __init__(self, cfg):
                assert cfg is config
            def read(self):
                return {"pending": None}
            def report(self, transport, identity):
                calls.append("update-result")
            def offer(self, offer, transport, identity):
                assert offer["version"] == "1.1.0"
                calls.append("update-offer")
                return False
        monkeypatch.setattr("sli_agent.updates.Updates", Updates)
    class Stop:
        cycles = 0
        def is_set(self):
            return self.cycles >= len(states)
        def wait(self, delay):
            self.cycles += 1
            delays.append(delay)
            clock[0] += delay
    runtime.run(config, Stop(), release_directory="1.0.0-initial" if updating else None)
    spool = Spool(config.storage_dir / "spool", max_bytes=100000, max_age_seconds=86400)
    return SimpleNamespace(spool=spool, saved=saved, collected=collected, reports=reports, calls=calls,
                           status=json.loads((config.storage_dir / "status.json").read_bytes()), delays=delays,
                           audit_reports=audit_reports, audit_positions=audit_positions, update_reports=update_reports)


def test_read_diagnostics_heartbeat_survives_delivery_backpressure_and_pause(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("active", 2), ("active", 2), ("paused", 3)],
                      reject=True, read_diagnostics=True)
    assert result.reports[0]["eventlog_diagnostics"] == []
    assert result.reports[1]["eventlog_diagnostics"][0]["error"]["record_id"] == 42
    assert result.reports[2]["eventlog_diagnostics"] == result.reports[1]["eventlog_diagnostics"]
    assert result.status["eventlog_diagnostics"] == result.reports[2]["eventlog_diagnostics"]
    assert result.spool.pending(now=NOW)
    assert "private" not in str(result.reports)


def test_msi_reports_zip_offer_without_switching_files_or_disabling_collection(tmp_path, monkeypatch):
    from sli_agent import __version__
    result = exercise(tmp_path, monkeypatch, [("active", 2)], msi_update=True)
    assert result.update_reports == [{"sha256": "a" * 64, "status": "rejected",
                                      "reason": "agent_update_msi_required", "version": __version__}]
    assert result.calls.count("msi-update-result") == 1
    assert result.collected and result.status["error_code"] is None


@pytest.mark.parametrize("states", [[("paused", 2)], [("drain", 2)], [OSError("fixture-offline")]])
def test_snapshot_pause_drain_and_offline_preserve_frozen_cycle(tmp_path, monkeypatch, states):
    cfg = snapshot_policy("sli.ad-snapshot", {"source_instance_id": HOST, "domain_sid": "S-1-5-21-1-2-3",
        "domain_dns": "directory.invalid", "scope": "fixture", "families": ["ad_context_base"], "policy_revision": "2"})
    stream = SnapshotStream(tmp_path / "capture", "sli.ad-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), {"ad_context_base": ({"fixture": 1}, 1)})
    before = (stream.root / "cycle.json").read_bytes()
    result = exercise(tmp_path, monkeypatch, states, snapshot_config=cfg)
    assert result.spool.captured("sli.ad-snapshot") is None
    assert (stream.root / "cycle.json").read_bytes() == before


def test_snapshot_resume_keeps_frozen_revision_and_common_send_limit(tmp_path, monkeypatch):
    cfg = snapshot_policy("sli.ad-snapshot", {"source_instance_id": HOST, "domain_sid": "S-1-5-21-1-2-3",
        "domain_dns": "directory.invalid", "scope": "fixture", "families": ["ad_context_base"], "policy_revision": "2"})
    stream = SnapshotStream(tmp_path / "capture", "sli.ad-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), {"ad_context_base": ({"fixture": 1}, 1)})
    result = exercise(tmp_path, monkeypatch, [("paused", 2), ("active", 3), ("active", 3)],
                      snapshot_config={**cfg, "policy_revision": "3"}, limit=1)
    assert result.calls.count("send") == 1
    assert result.spool.captured("sli.ad-snapshot")["policy_revision"] == "2"
    assert any(value["envelope"]["module_id"] == "sli.ad-snapshot" for value in result.spool.pending())
    assert result.reports[-1] == policy_report(3, "active")


@pytest.mark.parametrize("state", ["paused", "drain"])
def test_snapshot_reader_is_stopped_before_pause_ack(tmp_path, monkeypatch, state):
    runner = runtime.SnapshotCapture(tmp_path / "capture")
    stopped = threading.Event()
    runner.job = {"module": "sli.ad-snapshot", "stop": stopped, "done": threading.Event(),
                  "deadline": float("inf"), "error": None}
    monkeypatch.setattr(runtime, "SnapshotCapture", lambda root: runner)
    def on_report(body):
        assert body["collection_state"] == "paused"
        assert stopped.is_set()
    result = exercise(tmp_path, monkeypatch, [(state, 2)], on_report=on_report)
    assert result.reports == [policy_report(2, "paused")]


def test_snapshot_spool_burst_respects_common_batch_limit(tmp_path, monkeypatch):
    cfg = snapshot_policy("sli.ad-snapshot", {"source_instance_id": HOST, "domain_sid": "S-1-5-21-1-2-3",
        "domain_dns": "directory.invalid", "scope": "fixture", "families": ["ad_context_base"], "policy_revision": "2"})
    stream = SnapshotStream(tmp_path / "capture", "sli.ad-snapshot")
    stream.freeze(stream.begin(cfg, now=NOW), {"ad_context_base": ({"fixture": "x" * 100000}, 1)})
    result = exercise(tmp_path, monkeypatch, [("active", 2)], snapshot_config=cfg, batch_size=1)
    pending = [value for value in result.spool.pending() if value["envelope"]["module_id"] == "sli.ad-snapshot"]
    assert len(pending) == 1
    assert pending[0]["payload"]["chunk_index"] == 0
    assert stream.read()["ready"]


def test_pause_on_reconnect_precedes_delivery_preserves_spool_and_cursors(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("paused", 2), ("paused", 2)])
    assert result.calls == ["checkin", "report", "checkin", "report"]
    assert not result.collected
    assert result.spool.pending() == [result.saved]
    assert result.spool.captured("sli.workstations") == result.saved["envelope"]
    assert result.reports == [policy_report(2, "paused")] * 2
    assert result.status["collection_state"] == "paused"
    assert result.delays == [5, 5]


def test_resume_applies_new_revision_without_restart_or_cursor_reset(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("paused", 2), ("active", 3)])
    assert len(result.collected) == 1
    assert result.collected[0] == result.saved["envelope"]
    assert result.spool.captured("sli.workstations")["sequence"] == 2
    assert result.reports[-1] == policy_report(3, "active")
    assert result.calls.index("checkin") < result.calls.index("send")


@pytest.mark.parametrize("reject", [True, False])
def test_drain_stops_readers_and_acknowledges_pause_only_after_receipts(tmp_path, monkeypatch, reject):
    result = exercise(tmp_path, monkeypatch, [("drain", 2)], reject=reject)
    assert not result.collected
    assert bool(result.spool.pending()) is reject
    assert result.reports == ([] if reject else [policy_report(2, "paused")])
    assert result.status["collection_state"] == ("draining" if reject else "paused")


def test_unavailable_policy_never_sends_old_spool_or_collects(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [OSError("fixture-offline"), ("paused", 2)])
    assert "send" not in result.calls and not result.collected
    assert result.spool.pending() == [result.saved]
    assert result.reports == [policy_report(2, "paused")]
    assert result.status["windows_audit"] == result.audit_reports[0]["windows_audit"]


@pytest.mark.parametrize("state", ["active", "paused", "drain"])
def test_audit_heartbeat_is_separate_and_follows_policy_and_update_requests(tmp_path, monkeypatch, state):
    result = exercise(tmp_path, monkeypatch, [(state, 2)], updating=True)
    assert result.reports == [policy_report(2, "paused" if state == "drain" else state)]
    assert result.audit_reports == [{"windows_audit": result.status["windows_audit"]}]
    assert result.status["windows_audit"]["policy_revision"] == 2
    assert result.calls.index("report") < result.calls.index("update-result")
    assert result.calls.index("update-result") < result.calls.index("update-offer")
    assert result.audit_positions == [result.calls.index("update-offer") + 1]


def test_ack_failure_cannot_resume_using_previous_modules(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("paused", 2)], ack_failure=True)
    assert "send" not in result.calls and not result.collected
    assert result.spool.pending() == [result.saved]


def test_common_rate_limit_spans_cycles_and_keeps_unacknowledged_evidence(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("active", 2), ("active", 2)], limit=1)
    assert result.calls.count("send") == 1
    assert len(result.spool.pending()) >= 2


def test_reduced_spool_limit_keeps_existing_packets(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("paused", 2)])
    assert result.spool.pending() == [result.saved]


def test_heartbeat_is_independent_of_a_long_collection_interval(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("active", 2)] * 3, interval=300)
    assert result.calls.count("checkin") == 3
    assert result.delays == [60, 60, 60]
    assert len(result.collected) == 1


def test_backpressure_keeps_heartbeat_retry_bounded(tmp_path, monkeypatch):
    result = exercise(tmp_path, monkeypatch, [("drain", 2)] * 10, reject=True)
    assert max(result.delays) <= 60
    assert result.calls.count("checkin") == 10
    assert result.spool.pending() == [result.saved]


@pytest.mark.parametrize("instance", [None, "dc"])
@pytest.mark.parametrize("state", ["paused", "drain"])
def test_updates_coexist_with_paused_or_draining_instance_spool(tmp_path, monkeypatch, instance, state):
    result = exercise(tmp_path, monkeypatch, [(state, 2)], reject=True, instance=instance, updating=True)
    assert not result.collected and result.spool.pending() == [result.saved]
    assert result.calls[-2:] == ["update-result", "update-offer"]
    if state == "paused":
        assert result.calls == ["checkin", "report", "update-result", "update-offer"]
    else:
        assert result.calls == ["checkin", "send", "update-result", "update-offer"]
        assert result.status["collection_state"] == "draining" and not result.reports
    if instance is not None:
        assert not (tmp_path / "state/spool").exists()
        assert not (tmp_path / "state/status.json").exists()
