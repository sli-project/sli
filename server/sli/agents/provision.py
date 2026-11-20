"""Offline CA ceremony: root, online issuer request, offline issuer signing."""
from __future__ import annotations

import argparse
import os
from datetime import timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from server.sli.agents.ca import AgentError, fingerprint, utcnow, validate_key


def ca_certificate(subject, public_key, issuer, signing_key, *, days: int, path_length: int):
    now = utcnow()
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
        .sign(signing_key, hashes.SHA256()))


def create_root():
    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SLI Agent Root CA")])
    return key, ca_certificate(name, key.public_key(), name, key, days=3650, path_length=1)


def create_issuer_request():
    key = ec.generate_private_key(ec.SECP384R1())
    csr = (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SLI Agent Issuing CA")]))
        .sign(key, hashes.SHA256()))
    return key, csr


def sign_issuer(root, root_key, csr):
    try:
        from server.sli.agents.ca import _valid_ca
        _valid_ca(root, utcnow(), root=True)
        root.verify_directly_issued_by(root)
        validate_key(csr.public_key(), ca=True)
        if fingerprint(root_key.public_key()) != fingerprint(root.public_key()) or not csr.is_signature_valid:
            raise ValueError()
        if not isinstance(csr.signature_hash_algorithm, (hashes.SHA256, hashes.SHA384, hashes.SHA512)):
            raise ValueError()
        expected = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SLI Agent Issuing CA")])
        if csr.subject != expected or list(csr.extensions):
            raise ValueError()
        # Do not create an intermediate outliving the offline root.
        days = min(365, (root.not_valid_after_utc - utcnow()).days)
        if days < 1:
            raise ValueError()
        return ca_certificate(csr.subject, csr.public_key(), root.subject, root_key, days=days, path_length=0)
    except Exception:
        raise AgentError("invalid_issuer_request") from None


def _write_new(path: str, data: bytes, *, private: bool = False):
    # Exclusive creation: never replace an existing CA key/certificate.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    root = sub.add_parser("root")
    root.add_argument("--key-out", required=True)
    root.add_argument("--cert-out", required=True)
    request = sub.add_parser("issuer-request")
    request.add_argument("--key-out", required=True)
    request.add_argument("--csr-out", required=True)
    sign = sub.add_parser("sign-issuer")
    sign.add_argument("--root-key", required=True)
    sign.add_argument("--root-cert", required=True)
    sign.add_argument("--csr", required=True)
    sign.add_argument("--cert-out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "root":
            key, cert = create_root()
            _write_new(args.key_out, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), private=True)
            _write_new(args.cert_out, cert.public_bytes(serialization.Encoding.PEM))
        elif args.command == "issuer-request":
            key, csr = create_issuer_request()
            _write_new(args.key_out, key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()), private=True)
            _write_new(args.csr_out, csr.public_bytes(serialization.Encoding.PEM))
        else:
            root_cert = x509.load_pem_x509_certificate(Path(args.root_cert).read_bytes())
            key = serialization.load_pem_private_key(Path(args.root_key).read_bytes(), password=None)
            csr = x509.load_pem_x509_csr(Path(args.csr).read_bytes())
            cert = sign_issuer(root_cert, key, csr)
            _write_new(args.cert_out, cert.public_bytes(serialization.Encoding.PEM))
    except Exception:
        parser.exit(1, "CA provisioning failed; check input files and output permissions.\n")


if __name__ == "__main__":
    main()
