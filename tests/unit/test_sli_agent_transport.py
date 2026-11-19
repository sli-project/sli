"""Outbound transport uses verified HTTPS and never follows redirects."""
import json
import time
from types import SimpleNamespace

import pytest

from sli_agent.config import AgentConfig
from sli_agent.transport import Transport, TransportError


@pytest.mark.parametrize("change", [None, "certificate", "chain", "key", "ca", "origin", "idle", "server_close", "failure"])
def test_packet_connections_are_reused_only_for_current_mtls_identity(tmp_path, monkeypatch, change):
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent import transport as module

    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"fixture-ca")
    identity = SimpleNamespace(certificate_pem="fixture-cert", ca_chain_pem="fixture-chain",
                               key=ec.generate_private_key(ec.SECP256R1()))
    connections = []
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(Transport, "_context", lambda *args: object())
    class Connection:
        closed = False
        def __init__(self, *args, **kwargs):
            self.requests = []
            connections.append(self)
        def request(self, method, path, **kwargs):
            self.requests.append((method, path, kwargs))
        def getresponse(self):
            if change == "failure" and len(self.requests) == 2:
                raise OSError("fixture-private-diagnostic")
            return SimpleNamespace(status=200, will_close=change == "server_close",
                                   read=lambda _: b'{"status":"committed"}')
        def close(self):
            self.closed = True
    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    client = Transport(AgentConfig("https://core.invalid", ca, tmp_path))
    client.post("/api/v1/agent/packets", {"fixture": 1}, identity=identity)
    if change == "certificate":
        identity.certificate_pem = "fixture-renewed-cert"
    elif change == "chain":
        identity.ca_chain_pem = "fixture-renewed-chain"
    elif change == "key":
        identity.key = ec.generate_private_key(ec.SECP256R1())
    elif change == "ca":
        ca.write_bytes(b"fixture-new-ca")
    elif change == "origin":
        from dataclasses import replace
        client.config = replace(client.config, server_url="https://other.invalid")
    elif change == "idle":
        clock[0] += 10
    if change == "failure":
        with pytest.raises(TransportError, match="^agent_transport_failed$"):
            client.post("/api/v1/agent/packets", {"fixture": 2}, identity=identity)
        assert len(connections) == 1 and connections[0].closed
        # Ambiguous POST failures are not automatically replayed.
        assert len(connections[0].requests) == 2
        return
    client.post("/api/v1/agent/packets", {"fixture": 2}, identity=identity)
    assert len(connections) == (1 if change is None else 2)
    assert connections[0].requests[0][2]["headers"]["Connection"] == "keep-alive"
    if change is not None:
        assert connections[0].closed
    else:
        assert not connections[0].closed
    client.close()
    assert connections[-1].closed


def test_packet_connection_is_closed_before_a_non_packet_request(tmp_path, monkeypatch):
    from sli_agent import transport as module

    connections = []
    monkeypatch.setattr(Transport, "_packet_identity_key", lambda *args: b"fixture-identity")
    monkeypatch.setattr(Transport, "_context", lambda *args: object())
    class Connection:
        def __init__(self, *args, **kwargs):
            self.closed = False
            connections.append(self)
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return SimpleNamespace(status=200, will_close=False, read=lambda _: b'{"status":"committed"}')
        def close(self):
            self.closed = True
    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    client = Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    identity = object()
    client.post("/api/v1/agent/packets", {}, identity=identity)
    client.get("/api/v1/agent/identity", identity=identity)
    assert len(connections) == 2
    assert all(connection.closed for connection in connections)


def test_https_trust_and_response_without_real_network(tmp_path, monkeypatch):
    from sli_agent import transport as module
    context = SimpleNamespace(minimum_version=None)
    seen = {}
    monkeypatch.setattr(module.ssl, "create_default_context", lambda **kw: seen.update(kw) or context)
    class Connection:
        def __init__(self, host, port, **kwargs):
            seen["connection"] = host, port, kwargs
        def request(self, method, path, **kwargs):
            seen["request"] = method, path, kwargs
        def getresponse(self):
            return SimpleNamespace(status=200, read=lambda limit: b'{"status":"committed"}')
        def close(self):
            seen["closed"] = True
    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    config = AgentConfig("https://core.invalid:8443", tmp_path / "ca.pem", tmp_path)
    assert Transport(config).post("/api/v1/agent/enroll", {"fixture": True}) == {"status": "committed"}
    assert seen["cafile"] == str(config.ca_bundle)
    assert seen["connection"][:2] == ("core.invalid", 8443)
    assert seen["connection"][2]["context"] is context
    assert seen["request"][0] == "POST"
    assert seen["closed"]


def test_get_assignments_uses_mtls_without_request_body(tmp_path, monkeypatch):
    from sli_agent import transport as module
    identity = object()
    seen = {}
    monkeypatch.setattr(Transport, "_context", lambda self, value: seen.update(identity=value) or object())
    connection = SimpleNamespace(
        request=lambda method, path, **kw: seen.update(method=method, path=path, **kw),
        close=lambda: seen.update(closed=True),
        getresponse=lambda: SimpleNamespace(status=200, read=lambda limit: b'{"assigned_modules":[]}'))
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda *a, **kw: connection)
    result = Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)).get(
        "/api/v1/agent/identity", identity=identity)
    assert result == {"assigned_modules": []}
    assert seen["method"] == "GET" and seen["path"] == "/api/v1/agent/identity"
    assert seen["identity"] is identity and seen["body"] is None and seen["closed"]


def test_mtls_key_file_is_restricted_and_removed_before_network(tmp_path, monkeypatch):
    import os
    import stat
    from pathlib import Path
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent import transport as module
    if os.name == "nt":
        pytest.skip("POSIX file permissions; native Windows ACL covered separately")
    orphan = tmp_path / "tls-orphan"
    orphan.mkdir()
    (orphan / "private.pem").write_bytes(b"fixture")
    paths = []
    def load(cert, key):
        paths.extend([Path(cert), Path(key)])
        assert stat.S_IMODE(Path(key).stat().st_mode) == 0o600
        assert stat.S_IMODE(Path(key).parent.stat().st_mode) == 0o700
    context = SimpleNamespace(minimum_version=None, load_cert_chain=load)
    monkeypatch.setattr(module.ssl, "create_default_context", lambda **kw: context)
    identity = SimpleNamespace(certificate_pem="fixture-cert", ca_chain_pem="fixture-chain",
                               key=ec.generate_private_key(ec.SECP256R1()))
    assert Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))._context(identity) is context
    assert paths and all(not path.exists() for path in paths)
    assert not orphan.exists()


def test_named_tls_cleanup_and_temporary_key_stay_inside_instance(tmp_path, monkeypatch):
    from pathlib import Path
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent import transport as module
    from sli_agent.protection import directory_lock

    host = "00000000-0000-4000-8000-000000000001"
    first, second = [AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path,
                                 instance_name=name, host_id=host) for name in ("dc", "workstation")]
    orphans = []
    for config in (first, second):
        orphan = config.storage_dir / "tls-orphan"
        orphan.mkdir(parents=True)
        (orphan / "private.pem").write_bytes(b"fixture")
        orphans.append(orphan)
    paths = []
    def load(cert, key):
        paths.extend([Path(cert), Path(key)])
        assert Path(key).is_relative_to(first.storage_dir)
    context = SimpleNamespace(minimum_version=None, load_cert_chain=load)
    monkeypatch.setattr(module.ssl, "create_default_context", lambda **kw: context)
    identity = SimpleNamespace(certificate_pem="fixture-cert", ca_chain_pem="fixture-chain",
                               key=ec.generate_private_key(ec.SECP256R1()))
    with directory_lock(second.storage_dir / "transport-lock"):
        Transport(first)._context(identity)
    assert paths and all(not path.exists() for path in paths)
    assert not orphans[0].exists()
    assert (orphans[1] / "private.pem").read_bytes() == b"fixture"


@pytest.mark.parametrize("status, body", [(302, b"fixture-secret"), (503, b"fixture-secret"),
    (200, b"[]"), pytest.param(200, b"x" * (60 * 1024 + 1), id="oversized-response")])
def test_http_failures_do_not_follow_redirects_or_expose_response(tmp_path, monkeypatch, status, body):
    from sli_agent import transport as module
    monkeypatch.setattr(Transport, "_context", lambda *a: object())
    requests = []
    connection = SimpleNamespace(request=lambda *a, **kw: requests.append(a), close=lambda: None,
        getresponse=lambda: SimpleNamespace(status=status, read=lambda limit: body))
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda *a, **kw: connection)
    with pytest.raises(TransportError, match="^agent_transport_failed$"):
        Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)).post("/fixture", {})
    assert len(requests) == 1


def test_runtime_retries_with_backoff_and_safe_status(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    from sli_agent import runtime
    from sli_agent.spool import Spool
    from uuid import uuid4
    agent_id, host_id = str(uuid4()), str(uuid4())
    key = ec.generate_private_key(ec.SECP256R1())
    identity = SimpleNamespace(agent_id=agent_id, key=key)
    monkeypatch.setattr(runtime, "IdentityStore", lambda config: SimpleNamespace(
        prepare=lambda: {"host_id": host_id}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    class Offline:
        def get(self, *args, **kwargs):
            return {"agent_id": agent_id, "assigned_modules": []}
        def post(self, *args, **kwargs):
            raise OSError("fixture-private-exception")
    monkeypatch.setattr(runtime, "Transport", lambda config: Offline())
    monkeypatch.setattr(runtime.random, "uniform", lambda *a: 0)
    class Stop:
        def __init__(self):
            self.waits = []
        def is_set(self):
            return len(self.waits) == 3
        def wait(self, delay):
            self.waits.append(delay)
    stop = Stop()
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    monkeypatch.setattr(runtime, "service_identity_verified", lambda candidate: candidate is config)
    monkeypatch.setattr(runtime, "probe", lambda *args, **kwargs: {"identity_verified": True, "ready": True})
    runtime.run(config, stop)
    assert stop.waits == [60, 2, 4]
    status = json.loads((tmp_path / "status.json").read_bytes())
    assert status["retry_count"] == 2 and status["error_code"] == "agent_delivery_pending"
    assert "private-exception" not in json.dumps(status)
    assert len(Spool(tmp_path / "spool", max_bytes=10000, max_age_seconds=3600).pending()) == 3


def test_installer_skeleton_checks_permissions_and_leaves_service_stopped():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "tools/install-sli-agent.ps1").read_text(encoding="utf-8")
    assert "IsInRole" in source and "AreAccessRulesProtected" in source
    assert "agent_install_account_state_acl_missing" in source
    assert "Read-Host 'Service account:" in source
    assert "--startup manual install" in source
    assert "Start-Service" not in source and "--password" not in source and "Get-Credential" not in source


@pytest.mark.parametrize("failure", [None, "redirect", "hash", "oversize"])
def test_package_download_is_mtls_bounded_and_pinned_to_configured_origin(tmp_path, monkeypatch, failure):
    import hashlib
    import io
    from sli_agent import transport as module
    body = b"synthetic-package"
    expected = hashlib.sha256(body).hexdigest()
    seen = {}
    identity = object()
    monkeypatch.setattr(Transport, "_context", lambda self, value: seen.update(identity=value) or object())
    response = SimpleNamespace(status=302 if failure == "redirect" else 200,
        read=io.BytesIO(body + (b"extra" if failure == "hash" else b"")).read)
    connection = SimpleNamespace(request=lambda *a, **kw: seen.update(request=a),
        close=lambda: seen.update(closed=True), getresponse=lambda: response)
    monkeypatch.setattr(module.http.client, "HTTPSConnection", lambda host, port, **kw:
        seen.update(host=host, port=port) or connection)
    client = Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state"))
    destination = tmp_path / "download.zip"
    if failure:
        with pytest.raises(TransportError, match="^agent_download_failed$"):
            client.download(expected, destination, identity=identity, limit=2 if failure == "oversize" else 100)
    else:
        client.download(expected, destination, identity=identity)
        assert destination.read_bytes() == body
    assert seen["identity"] is identity
    assert seen["host"] == "core.invalid" and seen["port"] == 443
    assert seen["request"] == ("GET", "/api/v1/agent/package?sha256=" + expected)
    assert seen["closed"]


def test_package_download_rejects_foreign_paths_and_missing_identity(tmp_path):
    client = Transport(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state"))
    for digest, identity in (("https://foreign.invalid/package", object()), ("a" * 64, None)):
        with pytest.raises(TransportError, match="agent_download_failed"):
            client.download(digest, tmp_path / "download.zip", identity=identity)

def test_installer_preserves_utf8_without_bom():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2] / "tools/install-sli-agent.ps1").read_bytes()
    assert not source.startswith(b"\xef\xbb\xbf")
    source.decode("utf-8")
