"""Part-A enrollment/renewal wire contract, without a database or network."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sli_agent.config import AgentConfig
from sli_agent.enrollment import IdentityStore

NOW = datetime.now(timezone.utc)


class FakeServer:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.agent_id = str(uuid4())
        self.calls = []
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-issuer")])
        self.ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(minutes=1)).not_valid_after(NOW + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(self.key, hashes.SHA256()))

    def post(self, path, body, *, identity=None):
        self.calls.append((path, identity is not None))
        csr = x509.load_pem_x509_csr(body["csr_pem"].encode())
        assert csr.is_signature_valid and not list(csr.extensions)
        assert len(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)) == 1
        cert = (x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.agent_id)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-issuer")]))
            .public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(minutes=1)).not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:sli:agent:" + self.agent_id),
                x509.UniformResourceIdentifier("urn:sli:host:" + csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
            ]), False).sign(self.key, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        return {"agent_id": self.agent_id, "certificate_pem": pem,
                "ca_chain_pem": self.ca.public_bytes(serialization.Encoding.PEM).decode(),
                "serial": format(cert.serial_number, "x"), "expires_at": cert.not_valid_after_utc.isoformat()}


def test_prepare_enroll_restart_and_renew(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    store = IdentityStore(config)
    public = store.prepare()
    assert len(public["key_fingerprint"]) == 64
    assert store.prepare() == public
    server = FakeServer()
    identity = store.enroll("fixture-token", server)
    assert identity.agent_id == server.agent_id
    assert not any("fixture-token" in p.read_text(errors="ignore") for p in tmp_path.iterdir() if p.is_file())
    restarted = IdentityStore(config)
    assert restarted.load().agent_id == identity.agent_id
    assert not restarted.renew_if_due(server, now=NOW)
    assert restarted.renew_if_due(server, now=NOW + timedelta(days=29))
    assert server.calls == [("/api/v1/agent/enroll", False), ("/api/v1/agent/renew", True)]
    # Keeping the same protected key also keeps old signed spool packets deliverable.
    assert restarted.prepare()["key_fingerprint"] == public["key_fingerprint"]


@pytest.mark.parametrize("product_type,role", [
    ("WinNT", "workstation"), ("ServerNT", "workstation"), ("LanmanNT", "domain_controller"),
])
def test_enrollment_reports_local_windows_role(tmp_path, monkeypatch, product_type, role):
    import sys
    from contextlib import nullcontext
    from types import SimpleNamespace

    def open_key(root, path):
        assert path == r"SYSTEM\CurrentControlSet\Control\ProductOptions"
        return nullcontext("synthetic-key")

    def query_value(key, name):
        assert key == "synthetic-key" and name == "ProductType"
        return product_type, 1

    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(
        HKEY_LOCAL_MACHINE=1, REG_SZ=1, OpenKey=open_key, QueryValueEx=query_value))
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    server = FakeServer()
    post = server.post

    def respond(path, body, **kwargs):
        assert body["machine_role"] == role
        return post(path, body, **kwargs)

    server.post = respond
    assert store.enroll("synthetic-token", server) is not None


def test_enrollment_defaults_to_workstation_if_role_registry_is_unreadable(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    def denied(*args):
        raise PermissionError("synthetic denial")

    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_LOCAL_MACHINE=1, OpenKey=denied))
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    server = FakeServer()
    post = server.post

    def respond(path, body, **kwargs):
        assert body["machine_role"] == "workstation"
        return post(path, body, **kwargs)

    server.post = respond
    assert store.enroll("synthetic-token", server) is not None


def test_wrong_response_key_does_not_replace_identity(tmp_path):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    store = IdentityStore(config)
    store.prepare()
    server = FakeServer()
    original = server.post
    def bad(path, body, **kwargs):
        other = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "other"))
        other.prepare()
        body = {**body, "csr_pem": other.csr()}
        return original(path, body, **kwargs)
    server.post = bad
    with pytest.raises(ValueError, match="agent_certificate_invalid"):
        store.enroll("fixture-token", server)
    assert store.load() is None


def test_expired_certificate_is_not_used_for_renewal(tmp_path):
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    server = FakeServer()
    store.prepare()
    store.enroll("fixture-token", server)
    with pytest.raises(ValueError, match="agent_certificate_expired"):
        store.renew_if_due(server, now=NOW + timedelta(days=31))


def test_linux_key_permissions(tmp_path):
    import os
    import stat
    if os.name == "nt":
        pytest.skip("POSIX permissions")
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    store.prepare()
    assert stat.S_IMODE((tmp_path / "identity-key.json").stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


@pytest.mark.parametrize("approved", [False, True])
def test_group_enrollment_preserves_key_and_instance_without_persisting_tokens(tmp_path, approved, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "gethostname", lambda: "pc.example.invalid")
    host = "00000000-0000-4000-8000-000000000001"
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path,
                         instance_name="workstation", host_id=host)
    store = IdentityStore(config)
    public = store.prepare()
    assert public["host_id"] == host and public["instance_name"] == "workstation"
    server = FakeServer()
    post = server.post
    calls = []
    def respond(path, body, **kwargs):
        calls.append((path, body))
        if path.endswith("/group-enroll"):
            assert "reported_hostname" not in body
            assert body["instance_name"] == "workstation" and body["computer_entity_id"] == 3
            assert body["host_id"] == public["host_id"]
            return {"status": "approved", "token": "synthetic-single-use"} if approved else {"status": "pending"}
        assert body["reported_hostname"] == "pc.example.invalid"
        assert body["token"] == "synthetic-single-use" and body["instance_name"] == "workstation"
        return post(path, body, **kwargs)
    server.post = respond
    identity = store.enroll_group("synthetic-group-token", 3, server)
    assert (identity is not None) == approved
    assert store.prepare() == public
    assert len(calls) == (2 if approved else 1)
    assert (store.load().agent_id if approved else store.load()) == (identity.agent_id if approved else None)
    assert not any("synthetic-group-token" in file.read_text(errors="ignore") or "synthetic-single-use" in file.read_text(errors="ignore")
                   for file in config.storage_dir.rglob("*") if file.is_file())


@pytest.mark.parametrize("value", [None, True, 0, "3", 2**63])
def test_group_enrollment_rejects_invalid_computer_before_contact(tmp_path, value):
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    class NoContact:
        def post(self, *args, **kwargs):
            pytest.fail("invalid scope must not contact the server")
    with pytest.raises(ValueError, match="agent_group_scope_invalid"):
        store.enroll_group("synthetic", value, NoContact())


def test_group_enrollment_cli_reports_pending_without_printing_token(monkeypatch, capsys):
    from sli_agent import __main__ as cli
    seen = []
    monkeypatch.setattr("sys.argv", ["sli-agent", "--config", "fixture.json", "enroll-group", "--computer-entity-id", "3"])
    monkeypatch.setattr(cli.AgentConfig, "load", lambda path: object())
    monkeypatch.setattr(cli, "Transport", lambda config: object())
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: "synthetic-secret")
    class Store:
        def __init__(self, config):
            pass
        def enroll_group(self, token, computer, transport):
            seen.append((token, computer))
            return None
    monkeypatch.setattr(cli, "IdentityStore", Store)
    cli.main()
    assert seen == [("synthetic-secret", 3)]
    assert capsys.readouterr().out == "agent_approval_pending\n"


@pytest.mark.windows_only
@pytest.mark.skipif(__import__("os").name != "nt", reason="native DPAPI LocalMachine")
def test_windows_key_is_machine_protected(tmp_path):
    from sli_agent.protection import read_private_key
    store = IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path))
    store.prepare()
    assert read_private_key(tmp_path / "identity-key.json") is not None
    assert '"protection":"dpapi_local_machine"' in (tmp_path / "identity-key.json").read_text()


def test_named_instances_enroll_with_separate_certificates_and_same_host(tmp_path):
    host = "00000000-0000-4000-8000-000000000001"
    stores = [IdentityStore(AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path,
                                       instance_name=name, host_id=host)) for name in ("dc", "workstation")]
    identities = []
    for store in stores:
        server = FakeServer()
        post = server.post
        seen = []
        def enroll(path, body, **kwargs):
            seen.append(body["instance_name"])
            return post(path, body, **kwargs)
        server.post = enroll
        identities.append(store.enroll("fixture-token", server))
        assert seen == [store.config.instance_name]
    assert identities[0].agent_id != identities[1].agent_id
    assert identities[0].certificate_pem != identities[1].certificate_pem
    assert stores[0].prepare()["host_id"] == stores[1].prepare()["host_id"] == host
    assert stores[0].prepare()["key_fingerprint"] != stores[1].prepare()["key_fingerprint"]
    for store, identity in zip(stores, identities):
        assert IdentityStore(store.config).load().agent_id == identity.agent_id
        assert "fixture-token" not in (store.root / "identity.json").read_text()


def test_final_enrollment_reports_local_display_hostname_without_dns(tmp_path, monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'gethostname', lambda: 'pc.example.invalid')
    monkeypatch.setattr(socket, 'getfqdn', lambda *args: pytest.fail('No DNS'))
    store = IdentityStore(AgentConfig('https://core.invalid', tmp_path / 'ca.pem', tmp_path))
    server = FakeServer()
    original = server.post
    bodies = []
    def post(path, body, **kwargs):
        bodies.append((path, body))
        return original(path, body, **kwargs)
    server.post = post
    store.prepare()
    store.enroll('fixture-token', server)
    assert bodies[0][1]['reported_hostname'] == 'pc.example.invalid'
    csr = x509.load_pem_x509_csr(bodies[0][1]['csr_pem'].encode())
    assert not list(csr.extensions)
    assert csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != 'pc.example.invalid'


def test_unavailable_hostname_does_not_prevent_enrollment(tmp_path, monkeypatch):
    import socket
    def unavailable():
        raise OSError('hostname unavailable')
    monkeypatch.setattr(socket, 'gethostname', unavailable)
    store = IdentityStore(AgentConfig('https://core.invalid', tmp_path / 'ca.pem', tmp_path))
    server = FakeServer()
    store.prepare()
    assert store.enroll('fixture-token', server).agent_id == server.agent_id
