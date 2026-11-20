"""Owner upload/policy, independently authenticated delivery and safe audit data."""
import io
from types import SimpleNamespace
from uuid import uuid4

import pytest

from server.api.routes import agents
from server.sli.agents import updates
from server.sli.agents.ca import AgentError
from tests.unit.test_agent_api import Handler, transaction
from tests.unit.test_sli_agent_updates import agent_package


class Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.calls = []
    def execute(self, sql, args=()):
        self.calls.append((sql, args))
    def fetchone(self):
        return self.rows.pop(0) if self.rows else None
    def fetchall(self):
        return self.rows.pop(0) if self.rows else []


def test_upload_verifies_signature_and_stores_exact_archive_with_audit(agent_package, monkeypatch):
    archive, trust = agent_package()
    monkeypatch.setenv("SLI_AGENT_UPDATE_TRUST_FILE", str(trust))
    cur = Cursor()
    result = updates.upload(cur, archive.read_bytes(), actor="session:1")
    assert result["version"] == "1.1.0"
    assert cur.calls[0][1][-1] == archive.read_bytes()
    assert cur.calls[1][1][:3] == ("update_upload", "session:1", result["sha256"])
    assert "archive" not in cur.calls[1][1][-1]


@pytest.mark.parametrize("failure", ["untrusted", "legacy", "payload"])
def test_upload_rejects_untrusted_legacy_or_unowned_payload_without_storing(agent_package, monkeypatch, failure):
    import json
    archive, trust = agent_package(legacy=failure == "legacy", extra="server/forbidden.py" if failure == "payload" else None)
    if failure == "untrusted":
        policy = json.loads(trust.read_text())
        policy["keys"][0]["revoked"] = True
        trust.write_text(json.dumps(policy))
    monkeypatch.setenv("SLI_AGENT_UPDATE_TRUST_FILE", str(trust))
    cur = Cursor()
    with pytest.raises(AgentError, match="agent_package_verification_failed"):
        updates.upload(cur, archive.read_bytes(), actor="session:1")
    assert not cur.calls


def test_policy_is_explicit_and_download_is_bound_to_authenticated_agent():
    agent_id = str(uuid4())
    cur = Cursor([{"sha256": "a" * 64}, {"id": agent_id}])
    assert updates.assign(cur, {"agent_id": agent_id, "sha256": "a" * 64}, actor="session:1") == {"status": "assigned"}
    assert cur.calls[-1][1][:3] == ("update_assign", "session:1", agent_id)
    cur = Cursor([{"sha256": "a" * 64, "version": "1.1.0"}, {"archive": b"synthetic"}])
    assert updates.advertisement(cur, {"id": agent_id}) == {"sha256": "a" * 64, "version": "1.1.0"}
    assert updates.download(cur, {"id": agent_id}, "a" * 64) == b"synthetic"
    assert cur.calls[-1][1] == (agent_id, "a" * 64)
    assert "a.agent_id=%s" in cur.calls[-1][0]
    with pytest.raises(AgentError, match="agent_package_not_assigned"):
        updates.download(Cursor(), {"id": agent_id}, "b" * 64)
    assert updates.advertisement(Cursor(), {"id": agent_id}) is None


def test_policy_clear_and_nonexistent_targets():
    agent_id = str(uuid4())
    cur = Cursor([{"id": agent_id}])
    updates.assign(cur, {"agent_id": agent_id, "sha256": None}, actor="session:1")
    assert cur.calls[-2][1] == (agent_id, None)
    for body in ({"agent_id": agent_id}, {"agent_id": agent_id, "sha256": "a" * 64},
                 {"agent_id": agent_id, "sha256": None}):
        with pytest.raises(AgentError):
            updates.assign(Cursor(), body, actor="session:1")


def test_list_is_audited_and_never_selects_archive():
    cur = Cursor([[{"sha256": "a" * 64}], [], []])
    assert updates.list_packages(cur, actor="session:1")["items"] == [{"sha256": "a" * 64}]
    assert "archive" not in cur.calls[0][0]
    assert cur.calls[-1][1][:3] == ("update_list", "session:1", "agent-packages")


def test_results_are_idempotent_and_do_not_accept_arbitrary_diagnostics():
    agent = {"id": str(uuid4())}
    body = {"sha256": "a" * 64, "status": "rolled_back", "reason": "agent_update_timeout", "version": "1.0.0"}
    cur = Cursor([{"sha256": "a" * 64}, {"agent_id": agent["id"]}])
    assert updates.report(cur, agent, body) == {"status": "recorded"}
    assert cur.calls[-2][1][0] == "update_result"
    assert cur.calls[1][1] == (body["sha256"], agent["id"], agent["id"])
    assert "a.action='update_assign'" in cur.calls[1][0]
    repeated = Cursor([{"sha256": "a" * 64}, None])
    updates.report(repeated, agent, body)
    assert len(repeated.calls) == 4
    for edit in ({"reason": "synthetic-private-diagnostic"}, {"reason": None}, {"status": "unknown"},
                 {"status": []}, {"version": "../state"}, {"details": "synthetic-private-diagnostic"}):
        cur = Cursor()
        with pytest.raises(AgentError, match="agent_update_result_invalid"):
            updates.report(cur, agent, {**body, **edit})
        assert not cur.calls
    with pytest.raises(AgentError, match="agent_package_not_assigned"):
        updates.report(Cursor(), agent, body)


def test_identity_advertises_only_after_mtls_authentication_and_commit(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"synthetic-peer")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    agent = {"id": str(uuid4()), "assigned_modules": [], "policy_revision": 3,
             "rights_probe": {"pending": {"request_id": "synthetic-request"}}}
    monkeypatch.setattr(agents.registry, "authenticate", lambda c, ca, der: events.append("authenticate") or agent)
    monkeypatch.setattr(agents.updates, "advertisement", lambda c, a: events.append("offer") or {"sha256": "a" * 64, "version": "1.1.0"})
    handler = Handler()
    agents.try_handle_get(handler, "/api/v1/agent/identity", {})
    assert events == ["authenticate", "offer", "commit"]
    assert handler.responses[-1][0]["agent_update"]["version"] == "1.1.0"
    assert handler.responses[-1][0]["agent_id"] == agent["id"]
    assert handler.responses[-1][0]["assigned_modules"] == []
    assert handler.responses[-1][0]["policy_revision"] == 3
    assert handler.responses[-1][0]["rights_probe_request"] == agent["rights_probe"]["pending"]


def test_download_commits_before_binary_response(monkeypatch):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"synthetic-peer")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())
    monkeypatch.setattr(agents.registry, "authenticate", lambda *a: {"id": str(uuid4())})
    monkeypatch.setattr(agents.updates, "download", lambda *a: b"synthetic-zip")
    handler = Handler()
    handler.send_response = lambda status: events.append("response")
    handler.send_header = lambda *a: None
    handler.end_headers = lambda: None
    handler.wfile = io.BytesIO()
    agents.try_handle_get(handler, "/api/v1/agent/package", {"sha256": ["a" * 64]})
    assert events == ["commit", "response"]
    assert handler.wfile.getvalue() == b"synthetic-zip"


@pytest.mark.parametrize("path,operation", [
    ("/api/v1/agent/package", "download"),
    ("/api/v1/agent/update-result", "report"),
])
def test_update_transport_rejects_unregistered_certificate_before_package_access(monkeypatch, path, operation):
    events = []
    transaction(monkeypatch, events)
    monkeypatch.setattr(agents, "peer_certificate", lambda h: b"verified-peer")
    monkeypatch.setattr(agents.IssuingCA, "from_environment", lambda: object())

    def authenticate(cur, ca, der):
        assert der == b"verified-peer"
        raise AgentError("agent_certificate_rejected", 401)

    monkeypatch.setattr(agents.registry, "authenticate", authenticate)
    monkeypatch.setattr(agents.updates, operation, lambda *a: pytest.fail("rejected agent must not access packages"))
    handler = Handler(authenticated=False, owner=False)
    if operation == "download":
        assert agents.try_handle_get(handler, path, {"sha256": ["a" * 64]})
    else:
        assert agents.try_handle_post(handler, path)
    assert events == ["rollback"]
    assert handler.responses[-1][0] == {"error": "agent_certificate_rejected"}
    assert handler.responses[-1][1] == 401


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "bad"}, {"Content-Length": str(updates.MAX_PACKAGE_BYTES+1)},
    {"Content-Length": "1", "Content-Type": "text/plain"},
    {"Content-Length": "1", "Content-Type": "application/zip", "Transfer-Encoding": "chunked"}])
def test_upload_body_is_bounded_before_read(monkeypatch, headers):
    events = []
    transaction(monkeypatch, events)
    handler = Handler()
    handler.headers = headers
    handler.rfile = SimpleNamespace(read=lambda *a: pytest.fail("invalid body must not be read"))
    agents.try_handle_post(handler, "/api/v1/admin/agent-packages")
    assert handler.responses[-1][0] == {"error": "agent_package_invalid"}
    assert handler.responses[-1][1] == 400


@pytest.mark.parametrize("owner,manage", [(True, False), (False, True)])
def test_upload_route_passes_exact_bytes_and_owner_actor_after_validation(monkeypatch, owner, manage):
    events = []
    transaction(monkeypatch, events)
    handler = Handler(owner=owner, manage=manage)
    handler.headers = {"Content-Length": "3", "Content-Type": "application/zip"}
    handler.rfile = io.BytesIO(b"zip")
    def upload(cur, raw, *, actor):
        assert raw == b"zip" and actor == "session:1"
        events.append("verified")
        return {"sha256": "a" * 64, "version": "1.1.0"}
    monkeypatch.setattr(agents.updates, "upload", upload)
    agents.try_handle_post(handler, "/api/v1/admin/agent-packages")
    assert events == ["verified", "commit"]
    assert handler.responses[-1][0]["version"] == "1.1.0"
