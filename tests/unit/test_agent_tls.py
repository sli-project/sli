"""Real TLS handshakes with temporary synthetic keys, without a database."""
import socket
import ssl
import threading
from datetime import timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from server.api.http_server import _load_server_tls_context
from server.sli.agents.ca import AgentError, IssuingCA, parse_csr, utcnow
from server.sli.agents.provision import create_root, create_issuer_request, sign_issuer
from server.sli.agents.transport import peer_certificate

HOST = "00000000-0000-4000-8000-000000000001"
AGENT = "00000000-0000-4000-8000-000000000002"


def authority():
    root_key, root = create_root()
    issuer_key, csr = create_issuer_request()
    return IssuingCA(root, sign_issuer(root, root_key, csr), issuer_key)


def private_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@pytest.mark.parametrize("client_mode", ["valid", "missing", "foreign"])
def test_existing_https_listener_verifies_client_chain(tmp_path, monkeypatch, client_mode):
    # The HTTPS server identity is independent from the internal agent CA.
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(utcnow() - timedelta(minutes=1)).not_valid_after(utcnow() + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)
        .sign(key, hashes.SHA256()))
    cert_file, key_file = tmp_path / "server.pem", tmp_path / "server.key"
    cert_file.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(private_pem(key))
    for name, path in (("ADLOG_TLS_CERT", cert_file), ("ADLOG_TLS_KEY", key_file)):
        monkeypatch.setenv(name + "_FILE", str(path))
        monkeypatch.delenv(name + "_PATH", raising=False)
    trusted = authority()
    trust_file = tmp_path / "agents.pem"
    trust_file.write_text(trusted.chain_pem())
    monkeypatch.setenv("SLI_AGENT_MTLS_CA_FILE", str(trust_file))
    server_context = _load_server_tls_context()
    assert server_context.verify_mode == ssl.CERT_OPTIONAL
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.load_verify_locations(cafile=str(cert_file))
    expected_der = None
    if client_mode != "missing":
        signer = trusted if client_mode == "valid" else authority()
        client_key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
            .sign(client_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
        client_cert = signer.issue(parse_csr(csr, HOST), AGENT, HOST)
        client_chain, client_key_file = tmp_path / "client.pem", tmp_path / "client.key"
        client_chain.write_bytes(client_cert.public_bytes(serialization.Encoding.PEM) + signer.chain_pem().encode())
        client_key_file.write_bytes(private_pem(client_key))
        client_context.load_cert_chain(str(client_chain), str(client_key_file))
        expected_der = client_cert.public_bytes(serialization.Encoding.DER)
    results = []
    server_socket, client_socket = socket.socketpair()
    server_socket.settimeout(5)
    client_socket.settimeout(5)

    def serve():
        try:
            with server_context.wrap_socket(server_socket, server_side=True) as connection:
                try:
                    results.append(peer_certificate(SimpleNamespace(connection=connection)))
                except AgentError as exc:
                    results.append(str(exc))
                connection.sendall(b"ok")
        except ssl.SSLError:
            results.append("tls_rejected")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        try:
            with client_context.wrap_socket(client_socket, server_hostname="localhost") as connection:
                assert connection.recv(2) == b"ok"
        except ssl.SSLError:
            assert client_mode == "foreign"
    finally:
        thread.join(timeout=6)
        server_socket.close()
        client_socket.close()
    assert not thread.is_alive()
    if client_mode == "valid":
        assert results == [expected_der]
    elif client_mode == "missing":
        assert results == ["agent_mtls_required"]
    else:
        assert results == ["tls_rejected"]
