# SPDX-License-Identifier: Apache-2.0
"""Part-A CSR enrollment and renewal; one-time tokens are never persisted."""
from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from sli_agent.protection import (
    atomic_write,
    directory_lock,
    read_private_key,
    secure_directory,
    store_private_key,
)


def machine_role():
    """Local reader selection only; no domain lookup or authentication claim."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\ProductOptions") as key:
            value, kind = winreg.QueryValueEx(key, "ProductType")
        if kind == winreg.REG_SZ and value == "LanmanNT":
            return "domain_controller"
    except (ImportError, OSError):
        pass
    return "workstation"


def fingerprint(key):
    return hashlib.sha256(key.public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


@dataclass(frozen=True)
class Identity:
    agent_id: str
    certificate_pem: str
    ca_chain_pem: str
    key: object


class IdentityStore:
    def __init__(self, config):
        self.config = config
        self.root = config.storage_dir
        secure_directory(self.root)

    def prepare(self):
        with directory_lock(self.root):
            key_path = self.root / "identity-key.json"
            if not key_path.exists():
                store_private_key(key_path, ec.generate_private_key(ec.SECP256R1()))
            key = read_private_key(key_path)
            public_path = self.root / "host.json"
            if not public_path.exists():
                atomic_write(public_path, json.dumps({"host_id": self.config.host_id or str(uuid4())}).encode())
            try:
                host_id = str(UUID(json.loads(public_path.read_bytes())["host_id"]))
                if self.config.host_id is not None and host_id != self.config.host_id:
                    raise ValueError()
            except (ValueError, KeyError, TypeError):
                raise ValueError("agent_identity_invalid") from None
            public = {"host_id": host_id, "key_fingerprint": fingerprint(key.public_key())}
            if self.config.instance_name is not None:
                public["instance_name"] = self.config.instance_name
            return public

    def csr(self):
        public = self.prepare()
        key = read_private_key(self.root / "identity-key.json")
        csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, public["host_id"])]))
            .sign(key, hashes.SHA256()))
        return csr.public_bytes(serialization.Encoding.PEM).decode("ascii")

    def load(self):
        path = self.root / "identity.json"
        if not path.exists():
            return None
        try:
            body = json.loads(path.read_bytes())
            return Identity(body["agent_id"], body["certificate_pem"], body["ca_chain_pem"],
                            read_private_key(self.root / "identity-key.json"))
        except (OSError, ValueError, KeyError, TypeError):
            raise ValueError("agent_identity_invalid") from None

    def _accept(self, body, *, expected_agent=None):
        try:
            key = read_private_key(self.root / "identity-key.json")
            cert = x509.load_pem_x509_certificate(body["certificate_pem"].encode("ascii"))
            agent_id = str(UUID(body["agent_id"]))
            host_id = self.prepare()["host_id"]
            now = datetime.now(timezone.utc)
            if (expected_agent is not None and agent_id != expected_agent or
                    cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]) or
                    not cert.not_valid_before_utc <= now < cert.not_valid_after_utc or
                    fingerprint(cert.public_key()) != fingerprint(key.public_key()) or
                    cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or
                    cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value !=
                    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])):
                raise ValueError()
            expected_san = x509.SubjectAlternativeName([
                x509.UniformResourceIdentifier("urn:sli:agent:" + agent_id),
                x509.UniformResourceIdentifier("urn:sli:host:" + host_id)])
            if cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value != expected_san:
                raise ValueError()
            chain = body["ca_chain_pem"]
            issuers = x509.load_pem_x509_certificates(chain.encode("ascii"))
            if not issuers or len(issuers) > 4:
                raise ValueError()
            child = cert
            for issuer in issuers:
                if (not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or
                        not issuer.not_valid_before_utc <= now < issuer.not_valid_after_utc):
                    raise ValueError()
                child.verify_directly_issued_by(issuer)
                child = issuer
            child.verify_directly_issued_by(child)
            if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
                raise ValueError()
        except (ValueError, KeyError, TypeError, AttributeError, InvalidSignature, UnsupportedAlgorithm,
                x509.ExtensionNotFound, x509.DuplicateExtension):
            raise ValueError("agent_certificate_invalid") from None
        atomic_write(self.root / "identity.json", json.dumps({"agent_id": agent_id,
            "certificate_pem": body["certificate_pem"], "ca_chain_pem": chain}).encode())
        return self.load()

    def enroll(self, token, transport):
        if self.load() is not None:
            raise ValueError("agent_already_enrolled")
        body = {"token": token, "csr_pem": self.csr(), "machine_role": machine_role()}
        # Optional display metadata only. No DNS lookup or certificate changes.
        try:
            body["reported_hostname"] = socket.gethostname()
        except OSError:
            pass
        if self.config.instance_name is not None:
            body["instance_name"] = self.config.instance_name
        return self._accept(transport.post("/api/v1/agent/enroll", body))

    def enroll_group(self, token, computer_entity_id, transport):
        if self.load() is not None:
            raise ValueError("agent_already_enrolled")
        if type(computer_entity_id) is not int or not 1 <= computer_entity_id <= 2**63 - 1:
            raise ValueError("agent_group_scope_invalid")
        public = self.prepare()
        body = {"token": token, "computer_entity_id": computer_entity_id,
                "host_id": public["host_id"], "csr_pem": self.csr()}
        if self.config.instance_name is not None:
            body["instance_name"] = self.config.instance_name
        result = transport.post("/api/v1/agent/group-enroll", body)
        if result.get("status") == "pending":
            return None
        if result.get("status") != "approved" or not isinstance(result.get("token"), str):
            raise ValueError("agent_group_approval_invalid")
        return self.enroll(result["token"], transport)

    def renew_if_due(self, transport, *, now=None):
        identity = self.load()
        if identity is None:
            raise ValueError("agent_not_enrolled")
        cert = x509.load_pem_x509_certificate(identity.certificate_pem.encode("ascii"))
        now = now or datetime.now(timezone.utc)
        if cert.not_valid_after_utc <= now:
            raise ValueError("agent_certificate_expired")
        if now + timedelta(seconds=self.config.renew_before_seconds) < cert.not_valid_after_utc:
            return False
        # Same key: retries and old signed spool entries survive renewal/lost ACK.
        body = transport.post("/api/v1/agent/renew", {"csr_pem": self.csr()}, identity=identity)
        self._accept(body, expected_agent=identity.agent_id)
        return True
