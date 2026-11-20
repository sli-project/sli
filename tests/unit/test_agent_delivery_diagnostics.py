"""Delivery diagnostics use only synthetic envelopes and allowlisted metadata."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
import json

import pytest

from sli_agent import runtime
from sli_agent.transport import TransportError
from tests.unit.test_sli_agent_v1 import receipt, packet, key, NOW
from tests.unit.test_agent_policies import Cursor
from server.sli.agents import policies


def health(tmp_path):
    from sli_agent.delivery_diagnostics import DeliveryHealth
    return DeliveryHealth(tmp_path)


def rejection(value, code="agent_sequence_gap"):
    return {**receipt(value, "retry_later"), "error_code": code}


def test_actual_delivery_keeps_reason_through_spool_full_and_restart(tmp_path, key):
    from sli_agent.spool import Spool, SpoolFull
    from sli_agent.modules import HeartbeatModule
    value = packet(key)
    spool = Spool(tmp_path / "spool", max_bytes=65536, max_age_seconds=86400)
    saved = spool.capture(key, agent_id=value["envelope"]["agent_id"],
                          sample=HeartbeatModule(value["envelope"]["source_instance_id"]).collect(now=NOW), now=NOW)
    state = health(tmp_path)
    assert runtime.deliver_once(spool, lambda value: rejection(value), now=NOW, diagnostics=state) is False
    spool.max_bytes = 1
    with pytest.raises(SpoolFull):
        spool.capture(key, agent_id=saved["envelope"]["agent_id"], sample=HeartbeatModule(saved["envelope"]["source_instance_id"]).collect(spool.captured("sli.heartbeat"), now=NOW), now=NOW)
    fields = health(tmp_path).status_fields()
    assert fields["last_delivery_error_code"] == "agent_sequence_gap"
    assert fields["last_delivery_receipt_status"] == "retry_later"
    assert fields["last_delivery_http_status"] == 200
    assert fields["last_delivery_sequence"] == "1"
    assert len(spool.pending(now=NOW)) == 1


def test_other_stream_success_does_not_clear_failure(tmp_path, key):
    state = health(tmp_path)
    value = packet(key)
    state.observe(value, rejection(value), accepted=False, now=NOW)
    other = deepcopy(value)
    other["envelope"]["module_id"] = "sli.workstations"
    state.observe(other, receipt(other), accepted=True, now=NOW)
    assert state.observations()[0]["resolved_at_utc"] is None
    state.observe(value, receipt(value), accepted=True, now=NOW + timedelta(seconds=1))
    assert state.observations()[0]["error_code"] == "agent_sequence_gap"
    assert state.observations()[0]["resolved_at_utc"] is not None


def test_unknown_code_and_exception_text_never_persist(tmp_path, key):
    state = health(tmp_path)
    value = packet(key)
    state.observe(value, rejection(value, "SECRET_PAYLOAD\npassword=token"), accepted=False, now=NOW)
    assert state.observations()[0]["error_code"] == "agent_delivery_rejected"
    state.observe(value, None, accepted=False, error=OSError("SECRET_PAYLOAD"), now=NOW)
    assert state.observations()[0]["http_status"] is None
    assert "SECRET_PAYLOAD" not in json.dumps(state.status_fields())
    assert "payload" not in json.dumps(state.observations())


@pytest.mark.parametrize("change", [lambda x: x.update(payload="secret"), lambda x: x.update(error_code="secret"),
    lambda x: x.update(http_status=True), lambda x: x.update(sequence="01"), lambda x: x.update(packet_id="secret"),
    lambda x: x.update(module_id="secret\nmodule"), lambda x: x.update(observed_at_utc="yesterday"),
    lambda x: x.update(resolved_at_utc="2026-10-05T00:00:00+00:00")])
def test_report_validation_rejects_unsafe_or_ambiguous_metadata(tmp_path, key, change):
    from sli_agent.delivery_diagnostics import validate_observations
    state = health(tmp_path)
    value = packet(key)
    state.observe(value, rejection(value), accepted=False, now=NOW)
    item = state.observations()[0]
    change(item)
    with pytest.raises(ValueError):
        validate_observations([item])


def test_cap_and_canonical_sequence_preserve_precision(tmp_path, key):
    state = health(tmp_path)
    for n in range(30):
        value = packet(key)
        value["envelope"].update(module_id=f"sli.fixture{n}", sequence=9223372036854775807)
        state.observe(value, rejection(value), accepted=False, now=NOW)
    assert len(state.observations()) == 16
    assert state.observations()[-1]["sequence"] == "9223372036854775807"


def test_diagnostics_only_report_never_acknowledges_drain_or_policy(tmp_path, key):
    state = health(tmp_path)
    value = packet(key)
    state.observe(value, rejection(value), accepted=False, now=NOW)
    cur = Cursor()
    cur.agent.update(collection_policy={"state": "drain"}, applied_collection_state="active")
    cur.agent["rights_probe"] = {"pending": {"request_id": "keep"}, "eventlog_diagnostics": {"items": []}}
    before = deepcopy(cur.agent)
    result = policies.report(cur, deepcopy(cur.agent), {"delivery_diagnostics": state.observations()})
    assert result["delivery_diagnostics"]["items"][0]["error_code"] == "agent_sequence_gap"
    assert cur.agent["applied_policy_revision"] == before["applied_policy_revision"]
    assert cur.agent["applied_collection_state"] == "active"
    assert cur.agent["rights_probe"]["pending"] == before["rights_probe"]["pending"]
    assert cur.agent["rights_probe"]["eventlog_diagnostics"] == before["rights_probe"]["eventlog_diagnostics"]
    assert not cur.audits
    assert policies.check_in(cur.agent)["delivery_diagnostics_supported"] is True


def test_runtime_status_and_drain_report_preserve_failure_over_spool_full(tmp_path, monkeypatch):
    from tests.unit.test_sli_agent_control import exercise
    from sli_agent.spool import SpoolFull
    monkeypatch.setattr(runtime, "capture_module", lambda *args, **kwargs: (_ for _ in ()).throw(SpoolFull("agent_spool_size_limit")))
    result = exercise(tmp_path, monkeypatch, [("active", 2), ("drain", 3)], reject=True, delivery_diagnostics=True)
    assert result.status["last_delivery_error_code"] == "agent_sequence_gap"
    assert result.status["delivery_diagnostics"][0]["http_status"] == 200
    independent = [body for body in result.reports if set(body) == {"delivery_diagnostics"}]
    assert len(independent) == 2 and independent[-1]["delivery_diagnostics"][0]["error_code"] == "agent_sequence_gap"
    assert not any(body.get("collection_state") == "paused" for body in result.reports)
    assert result.spool.pending(now=NOW)


@pytest.mark.parametrize("status", [401, 429, 503])
def test_transport_keeps_only_safe_http_status(tmp_path, monkeypatch, status):
    from sli_agent import transport as module
    from sli_agent.config import AgentConfig
    class Connection:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return SimpleNamespace(status=status, read=lambda limit: b'SECRET BODY')
        def close(self):
            pass
    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    monkeypatch.setattr(module.Transport, "_context", lambda *args: object())
    with pytest.raises(TransportError, match="^agent_transport_failed$") as failure:
        module.Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)).post("/api/v1/agent/packets", {})
    assert failure.value.http_status == status
    assert "SECRET" not in repr(failure.value)


def test_server_rejection_log_is_allowlisted_authenticated_and_rate_limited(key, caplog):
    from server.sli.agents.delivery_diagnostics import log_rejection, RejectionLimiter
    value = packet(key)
    identity = {"id": "00000000-0000-4000-8000-000000000099"}
    limiter = RejectionLimiter()
    caplog.set_level("WARNING")
    value["payload"] = {"password": "SECRET_PAYLOAD"}
    assert log_rejection(identity, value, rejection(value), limiter=limiter, clock=lambda: 1)
    assert not log_rejection(identity, value, rejection(value), limiter=limiter, clock=lambda: 2)
    assert log_rejection(identity, value, rejection(value), limiter=limiter, clock=lambda: 62)
    assert len(caplog.records) == 2
    assert identity["id"] in caplog.text and "agent_sequence_gap" in caplog.text
    assert value["envelope"]["agent_id"] not in caplog.text
    assert "SECRET_PAYLOAD" not in caplog.text and "password" not in caplog.text


def test_server_log_ignores_bad_metadata_and_never_injects_unknown_codes(key, caplog):
    from server.sli.agents.delivery_diagnostics import log_rejection, RejectionLimiter
    value = packet(key)
    identity = {"id": value["envelope"]["agent_id"]}
    caplog.set_level("WARNING")
    assert not log_rejection({}, value, rejection(value), limiter=RejectionLimiter())
    assert log_rejection(identity, value, rejection(value, "SECRET\nCRITICAL"), limiter=RejectionLimiter())
    assert "SECRET" not in caplog.text and "CRITICAL" not in caplog.text
    assert "agent_delivery_rejected" in caplog.text
    value["envelope"]["module_id"] = "module\nINJECT"
    assert not log_rejection(identity, value, rejection(value), limiter=RejectionLimiter())


def test_route_logs_after_commit_without_changing_http_200(monkeypatch, key):
    from server.api.routes import agent_packets as route
    from tests.unit.test_agent_packets_api import fake_connect, handler
    events = []
    value = packet(key)
    request = handler(events)
    request._read_json_body = lambda: value
    identity = {"id": value["envelope"]["agent_id"]}
    monkeypatch.setattr(route, "_peer", lambda h: b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    monkeypatch.setattr(route, "_authenticate", lambda *args: (identity, object()))
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: rejection(value))
    monkeypatch.setattr(route, "log_rejection", lambda seen, body, result: events.append(("log", seen)))
    route.try_handle_post(request, "/api/v1/agent/packets")
    assert events.index("commit") < events.index(("log", identity)) < len(events) - 1
    assert events[-1][2] == 200 and events[-1][1]["error_code"] == "agent_sequence_gap"


def test_server_log_limiter_has_bounded_memory():
    from server.sli.agents.delivery_diagnostics import RejectionLimiter
    limiter = RejectionLimiter(capacity=4)
    for number in range(40):
        limiter.allow((str(number), "sli.heartbeat", "agent_sequence_gap"), 1)
    assert len(limiter.entries) == 4


def test_logging_failure_never_loses_committed_receipt(monkeypatch, key):
    from server.api.routes import agent_packets as route
    from tests.unit.test_agent_packets_api import fake_connect, handler
    events = []
    value = packet(key)
    request = handler(events)
    request._read_json_body = lambda: value
    monkeypatch.setattr(route, "_peer", lambda h: b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    monkeypatch.setattr(route, "_authenticate", lambda *args: ({"id": value["envelope"]["agent_id"]}, object()))
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: receipt(value))
    monkeypatch.setattr(route, "log_rejection", lambda *args: (_ for _ in ()).throw(OSError("SECRET_LOG_FAILURE")))
    assert route.try_handle_post(request, "/api/v1/agent/packets")
    assert "commit" in events and events[-1][2] == 200
    assert events[-1][1] == receipt(value)


@pytest.mark.parametrize("report", [
    {"delivery_diagnostics": [{}]},
    {"delivery_diagnostics": [], "applied_policy_revision": 1},
    {"delivery_diagnostics": [], "agent_id": "spoofed"},
])
def test_diagnostics_report_rejects_malformed_and_mixed_policy_fields(report):
    from server.sli.agents.ca import AgentError
    cur = Cursor()
    before = deepcopy(cur.agent)
    with pytest.raises(AgentError):
        policies.report(cur, deepcopy(cur.agent), report)
    assert cur.agent == before and not cur.audits


def test_rotating_rejection_keys_cannot_bypass_global_log_budget():
    from server.sli.agents.delivery_diagnostics import RejectionLimiter
    limiter = RejectionLimiter(capacity=4)
    assert sum(limiter.allow((str(i % 5), "sli.heartbeat", "agent_sequence_gap"), 1) for i in range(20)) == 4
    assert limiter.allow(("new", "sli.heartbeat", "agent_sequence_gap"), 62)


def test_history_pending_is_preserved_as_known_reason(tmp_path, key):
    state = health(tmp_path)
    value = packet(key)
    state.observe(value, rejection(value, "agent_history_pending"), accepted=False, now=NOW)
    assert state.observations()[0]["error_code"] == "agent_history_pending"
