from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from deploy.linux.sli_core import ca
from server.sli.agents import ca as legacy_ca, provision

HOST = "00000000-0000-4000-8000-000000000001"
AGENT = "00000000-0000-4000-8000-000000000002"


def csr_pem(key, host=HOST, *, extension=None):
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
    if extension:
        builder = builder.add_extension(extension, critical=True)
    algorithm = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.PEM).decode("ascii")


@pytest.fixture
def authority():
    root_key, root = provision.create_root()
    issuer_key, request = provision.create_issuer_request()
    issuer = provision.sign_issuer(root, root_key, request)
    return ca.IssuingCA(root, issuer, issuer_key)


def test_offline_root_and_issuer_have_constrained_chain(authority):
    assert authority.root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 1
    assert authority.issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length == 0
    authority.issuer.verify_directly_issued_by(authority.root)
    assert authority.key.public_key().public_numbers() == authority.issuer.public_key().public_numbers()


def test_issue_fixed_client_profile_default_thirty_days(authority):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = authority.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST)
    assert cert.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, AGENT)])
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier) == ["urn:sli:agent:" + AGENT, "urn:sli:host:" + HOST]
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    assert timedelta(days=30) <= cert.not_valid_after_utc - cert.not_valid_before_utc <= timedelta(days=30, minutes=2)
    assert authority.verify_client(cert.public_bytes(serialization.Encoding.DER)) == cert
    assert "PRIVATE KEY" not in authority.chain_pem()


@pytest.mark.parametrize("days", [1, 90])
def test_configured_lifetime(authority, days):
    authority.lifetime_days = days
    key = ec.generate_private_key(ec.SECP256R1())
    cert = authority.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST)
    assert cert.not_valid_after_utc <= ca.utcnow() + timedelta(days=days)


@pytest.mark.parametrize("days", [0, 91, True, "30"])
def test_invalid_lifetime_rejected(authority, days):
    with pytest.raises(ca.AgentError, match="agent_ca_unavailable"):
        ca.IssuingCA(authority.root, authority.issuer, authority.key, lifetime_days=days)


@pytest.mark.parametrize("key", [
    lambda: rsa.generate_private_key(public_exponent=65537, key_size=1024),
    lambda: ec.generate_private_key(ec.SECP521R1()),
    ed25519.Ed25519PrivateKey.generate,
])
def test_weak_or_unsupported_csr_key(key):
    with pytest.raises(ca.AgentError, match="unsupported_agent_key"):
        ca.parse_csr(csr_pem(key()), HOST)


@pytest.mark.parametrize("key", [
    lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    lambda: ec.generate_private_key(ec.SECP384R1()),
])
def test_supported_csr_key(key):
    assert ca.parse_csr(csr_pem(key()), HOST).is_signature_valid


def test_subject_binding_and_requested_extensions():
    key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ca.AgentError, match="agent_csr_subject_mismatch"):
        ca.parse_csr(csr_pem(key, AGENT), HOST)
    for extension in (x509.BasicConstraints(ca=True, path_length=0), x509.SubjectAlternativeName([x509.UniformResourceIdentifier("urn:sli:agent:" + AGENT)])):
        with pytest.raises(ca.AgentError, match="agent_csr_extensions_forbidden"):
            ca.parse_csr(csr_pem(key, extension=extension), HOST)


def test_duplicate_subject_and_bad_signature():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST), x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    with pytest.raises(ca.AgentError, match="agent_csr_subject_mismatch"):
        ca.parse_csr(csr.public_bytes(serialization.Encoding.PEM).decode(), HOST)
    csr = x509.load_pem_x509_csr(csr_pem(key).encode())
    raw = bytearray(csr.public_bytes(serialization.Encoding.DER))
    raw[-1] ^= 1
    damaged = x509.load_der_x509_csr(bytes(raw))
    with pytest.raises(ca.AgentError, match="invalid_agent_csr_signature"):
        ca.parse_csr(damaged.public_bytes(serialization.Encoding.PEM).decode(), HOST)


@pytest.mark.parametrize("pem", [None, "not a CSR", "é", "x" * 16385])
def test_malformed_csr_safe_errors(pem):
    with pytest.raises(ca.AgentError, match="invalid_agent_csr"):
        ca.parse_csr(pem, HOST)


def test_issuer_key_mismatch_and_missing_secrets(authority, monkeypatch):
    with pytest.raises(ca.AgentError, match="agent_ca_unavailable"):
        ca.IssuingCA(authority.root, authority.issuer, ec.generate_private_key(ec.SECP384R1()))
    for name in ("SLI_AGENT_CA_ROOT_CERT_FILE", "SLI_AGENT_CA_ISSUER_CERT_FILE", "SLI_AGENT_CA_ISSUER_KEY_FILE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SLI_AGENT_CA_ISSUER_KEY", "inline-values-are-ignored")
    with pytest.raises(ca.AgentError, match="agent_ca_unavailable"):
        ca.IssuingCA.from_environment()


def test_file_secrets_load_and_no_root_key_needed(authority, tmp_path, monkeypatch):
    contents = {
        "SLI_AGENT_CA_ROOT_CERT": authority.root.public_bytes(serialization.Encoding.PEM),
        "SLI_AGENT_CA_ISSUER_CERT": authority.issuer.public_bytes(serialization.Encoding.PEM),
        "SLI_AGENT_CA_ISSUER_KEY": authority.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
    }
    for name, data in contents.items():
        file = tmp_path / name
        file.write_bytes(data)
        monkeypatch.setenv(name + "_FILE", str(file))
    monkeypatch.setenv("SLI_AGENT_CERT_DAYS", "7")
    assert ca.IssuingCA.from_environment().lifetime_days == 7
    monkeypatch.setenv("SLI_AGENT_CA_ISSUER_KEY_FILE", str(tmp_path / "absent"))
    with pytest.raises(ca.AgentError, match="agent_ca_unavailable"):
        ca.IssuingCA.from_environment()


def test_expired_and_foreign_certificates_rejected(authority, monkeypatch):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = authority.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST)
    foreign_key, foreign_root = provision.create_root()
    foreign_issuer_key, request = provision.create_issuer_request()
    foreign_issuer = provision.sign_issuer(foreign_root, foreign_key, request)
    foreign = ca.IssuingCA(foreign_root, foreign_issuer, foreign_issuer_key)
    with pytest.raises(ca.AgentError, match="agent_certificate_rejected"):
        authority.verify_client(foreign.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST).public_bytes(serialization.Encoding.DER))
    monkeypatch.setattr(ca, "utcnow", lambda: cert.not_valid_after_utc + timedelta(seconds=1))
    with pytest.raises(ca.AgentError, match="agent_certificate_rejected"):
        authority.verify_client(cert.public_bytes(serialization.Encoding.DER))


def test_issuer_expiry_caps_certificate_and_blocks_expired_ca(authority, monkeypatch):
    monkeypatch.setattr(ca, "utcnow", lambda: authority.issuer.not_valid_after_utc - timedelta(days=2))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = authority.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST)
    assert cert.not_valid_after_utc == authority.issuer.not_valid_after_utc
    monkeypatch.setattr(ca, "utcnow", lambda: authority.issuer.not_valid_after_utc)
    with pytest.raises(ca.AgentError, match="agent_ca_unavailable"):
        authority.issue(ca.parse_csr(csr_pem(key), HOST), AGENT, HOST)


def test_provisioning_never_overwrites_private_files(tmp_path):
    path = tmp_path / "key"
    provision._write_new(str(path), b"synthetic", private=True)
    with pytest.raises(FileExistsError):
        provision._write_new(str(path), b"replacement", private=True)
    assert path.read_bytes() == b"synthetic"


def test_offline_signing_rejects_unapproved_subject():
    root_key, root = provision.create_root()
    key = ec.generate_private_key(ec.SECP384R1())
    csr = x509.load_pem_x509_csr(csr_pem(key).encode())
    with pytest.raises(legacy_ca.AgentError, match="invalid_issuer_request"):
        provision.sign_issuer(root, root_key, csr)
