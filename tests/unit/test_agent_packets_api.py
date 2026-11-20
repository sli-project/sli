"""Route authentication and commit ordering, without real TLS or PostgreSQL."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from server.api.routes import agent_packets as route
from sli_agent.envelope import EnvelopeError


def handler(events):
    return SimpleNamespace(_read_json_body=lambda: events.append("body") or {},
        _send_json=lambda result, status=200, **kw: events.append(("response", result, status)))


def fake_connect(events, *, fail_commit=False):
    @contextmanager
    def connection():
        events.append("connect")
        class Connection:
            @contextmanager
            def cursor(self):
                yield object()
            def commit(self):
                events.append("commit")
                if fail_commit:
                    raise OSError("fixture-private-data-must-not-escape")
        try:
            yield Connection()
        except Exception:
            events.append("rollback")
            raise
    return connection


def test_receipt_is_sent_after_commit(monkeypatch):
    events = []
    monkeypatch.setattr(route, "_peer", lambda h: events.append("tls") or b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    monkeypatch.setattr(route, "_authenticate", lambda cur, der: events.append("registry") or ({}, object()))
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: {"status": "committed"})
    assert route.try_handle_post(handler(events), "/api/v1/agent/packets")
    assert events == ["tls", "body", "connect", "registry", "commit", ("response", {"status": "committed"}, 200)]


def test_failed_commit_does_not_return_success_receipt(monkeypatch):
    events = []
    monkeypatch.setattr(route, "_peer", lambda h: b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events, fail_commit=True))
    monkeypatch.setattr(route, "_authenticate", lambda *a: ({}, object()))
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: {"status": "committed"})
    route.try_handle_post(handler(events), "/api/v1/agent/packets")
    assert events[-1] == ("response", {"error": "agent_service_unavailable"}, 503)
    assert "rollback" in events
    assert "private-data" not in str(events)


def test_unverified_transport_never_reads_body_or_database(monkeypatch):
    events = []
    error = type("AgentError", (ValueError,), {"__module__": "server.sli.agents.ca", "status": 401})
    def fail(handler):
        raise error("agent_mtls_required")
    monkeypatch.setattr(route, "_peer", fail)
    monkeypatch.setattr(route, "connect", lambda: pytest.fail("database must not be reached"))
    route.try_handle_post(handler(events), "/api/v1/agent/packets")
    assert events == [("response", {"error": "agent_authentication_failed"}, 401)]


def test_revoked_agent_never_reaches_ingest(monkeypatch):
    events = []
    error = type("AgentError", (ValueError,), {"__module__": "server.sli.agents.ca", "status": 401})
    monkeypatch.setattr(route, "_peer", lambda h: b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    def revoked(*args):
        raise error("agent_certificate_rejected")
    monkeypatch.setattr(route, "_authenticate", revoked)
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: pytest.fail("ingest must not be reached"))
    route.try_handle_post(handler(events), "/api/v1/agent/packets")
    assert events.index("body") < events.index("connect")
    assert "commit" not in events
    assert events[-1][2] == 401


def test_revocation_during_body_read_is_checked_before_ingest(monkeypatch):
    events = []
    revoked = [False]
    request = handler(events)
    def read_body():
        assert "connect" not in events
        # The administrative revoke remains free to finish during this read.
        revoked[0] = True
        events.append("revoke")
        return {}
    request._read_json_body = read_body
    error = type("AgentError", (ValueError,), {"__module__": "server.sli.agents.ca", "status": 401})
    def authenticate(*_args):
        assert revoked[0]
        events.append("registry")
        raise error("agent_certificate_rejected")
    monkeypatch.setattr(route, "_peer", lambda _handler: b"fixture-peer")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    monkeypatch.setattr(route, "_authenticate", authenticate)
    monkeypatch.setattr(route, "receive_packet", lambda *a, **kw: pytest.fail("revoked agent cannot ingest"))
    assert route.try_handle_post(request, "/api/v1/agent/packets")
    assert events[:3] == ["revoke", "connect", "registry"]
    assert "commit" not in events and events[-1][2] == 401


def test_bad_signature_rolls_back(monkeypatch):
    events = []
    monkeypatch.setattr(route, "_peer", lambda h: b"fixture")
    monkeypatch.setattr(route, "connect", fake_connect(events))
    monkeypatch.setattr(route, "_authenticate", lambda *a: ({}, object()))
    def invalid(*args, **kwargs):
        raise EnvelopeError("agent_signature_invalid")
    monkeypatch.setattr(route, "receive_packet", invalid)
    route.try_handle_post(handler(events), "/api/v1/agent/packets")
    assert events[-1] == ("response", {"error": "agent_signature_invalid"}, 400)
    assert "rollback" in events and "commit" not in events


def test_unrelated_route_is_ignored():
    events = []
    assert route.try_handle_post(handler(events), "/api/v1/agent/other") is False
    assert events == []
