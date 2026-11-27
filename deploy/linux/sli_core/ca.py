"""Internal issuing CA. Private material is read only from mounted files."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class AgentError(ValueError):
    """A safe error code, never an input value or crypto exception text."""

    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.status = status


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def uuid_text(value) -> str:
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise AgentError("invalid_agent_identity") from None


def fingerprint(key) -> str:
    raw = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    return digest.finalize().hex()


def validate_key(key, *, ca: bool = False) -> None:
    if isinstance(key, rsa.RSAPublicKey):
        if (3072 if ca else 2048) <= key.key_size <= 8192 and key.public_numbers().e == 65537:
            return
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1)):
        return
    raise AgentError("unsupported_agent_key")


def parse_csr(pem, host_id: str):
    if not isinstance(pem, str) or not 1 <= len(pem) <= 16384:
        raise AgentError("invalid_agent_csr")
    try:
        csr = x509.load_pem_x509_csr(pem.encode("ascii"))
        validate_key(csr.public_key())
        if not csr.is_signature_valid or not isinstance(csr.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise AgentError("invalid_agent_csr_signature")
        if csr.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uuid_text(host_id))]):
            raise AgentError("agent_csr_subject_mismatch")
        # Issue our fixed profile; never copy caller-controlled CA/SAN/EKU extensions.
        if list(csr.extensions):
            raise AgentError("agent_csr_extensions_forbidden")
        return csr
    except (ValueError, UnicodeError, UnsupportedAlgorithm, x509.DuplicateExtension) as exc:
        if isinstance(exc, AgentError):
            raise
        raise AgentError("invalid_agent_csr") from None


def _valid_ca(cert, now: datetime, *, root: bool) -> None:
    validate_key(cert.public_key(), ca=True)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    if not bc.ca or not ku.key_cert_sign or not ku.crl_sign or (not root and bc.path_length != 0) or (root and bc.path_length is not None and bc.path_length < 1):
        raise AgentError("agent_ca_unavailable", 503)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise AgentError("agent_ca_unavailable", 503)
    if not isinstance(cert.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
        raise AgentError("agent_ca_unavailable", 503)
    if cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value != x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]):
        raise AgentError("agent_ca_unavailable", 503)


class IssuingCA:
    def __init__(self, root, issuer, key, *, lifetime_days: int = 30):
        self.root, self.issuer, self.key = root, issuer, key
        if type(lifetime_days) is not int or not 1 <= lifetime_days <= 90:
            raise AgentError("agent_ca_unavailable", 503)
        self.lifetime_days = lifetime_days
        try:
            self.validate()
            if fingerprint(key.public_key()) != fingerprint(issuer.public_key()):
                raise AgentError("agent_ca_unavailable", 503)
        except (ValueError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
            raise AgentError("agent_ca_unavailable", 503) from None

    @classmethod
    def from_environment(cls):
        try:
            # No inline secret fallback and no runtime access to the offline root key.
            def read(name):
                return Path(os.environ[name + "_FILE"]).read_bytes()
            root = x509.load_pem_x509_certificate(read("SLI_AGENT_CA_ROOT_CERT"))
            issuer = x509.load_pem_x509_certificate(read("SLI_AGENT_CA_ISSUER_CERT"))
            key = serialization.load_pem_private_key(read("SLI_AGENT_CA_ISSUER_KEY"), password=None)
            return cls(root, issuer, key, lifetime_days=int(os.environ.get("SLI_AGENT_CERT_DAYS", "30")))
        except (OSError, KeyError, ValueError, UnsupportedAlgorithm):
            raise AgentError("agent_ca_unavailable", 503) from None

    def validate(self):
        now = utcnow()
        _valid_ca(self.root, now, root=True)
        _valid_ca(self.issuer, now, root=False)
        self.root.verify_directly_issued_by(self.root)
        self.issuer.verify_directly_issued_by(self.root)

    def issue(self, csr, agent_id: str, host_id: str):
        self.validate()
        now = utcnow()
        end = min(now + timedelta(days=self.lifetime_days), self.issuer.not_valid_after_utc, self.root.not_valid_after_utc)
        if end <= now + timedelta(hours=1):
            raise AgentError("agent_ca_unavailable", 503)
        return (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, uuid_text(agent_id))]))
            .issuer_name(self.issuer.subject).public_key(csr.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(end)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:sli:agent:" + uuid_text(agent_id)),
                x509.UniformResourceIdentifier("urn:sli:host:" + uuid_text(host_id)),
            ]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256()))

    def verify_client(self, der: bytes):
        try:
            self.validate()
            cert = x509.load_der_x509_certificate(der)
            cert.verify_directly_issued_by(self.issuer)
            now = utcnow()
            if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
                raise ValueError()
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError()
            if cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value != x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]):
                raise ValueError()
            if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                raise ValueError()
            validate_key(cert.public_key())
            return cert
        except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm, x509.ExtensionNotFound):
            raise AgentError("agent_certificate_rejected", 401) from None

    def chain_pem(self) -> str:
        return (self.issuer.public_bytes(serialization.Encoding.PEM) + self.root.public_bytes(serialization.Encoding.PEM)).decode("ascii")
