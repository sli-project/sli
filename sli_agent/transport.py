# SPDX-License-Identifier: Apache-2.0
"""Direct outbound HTTPS/mTLS, with no redirects or proxy certificate headers."""
from __future__ import annotations

import http.client
import hashlib
import json
import ssl
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

from sli_agent.envelope import MAX_PACKET_BYTES, canonical
from sli_agent.protection import atomic_write, directory_lock, secure_directory


class TransportError(OSError):
    def __init__(self, code, *, http_status=None):
        super().__init__(code)
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None


class Transport:
    def __init__(self, config):
        self.config = config
        self._packet_connection = None
        self._packet_identity = None
        self._packet_used_at = 0.0

    def close(self):
        connection = self._packet_connection
        self._packet_connection = None
        self._packet_identity = None
        if connection is not None:
            connection.close()

    def _packet_identity_key(self, identity):
        # Re-read trust and compare the public identity before every reuse.
        # Renewal/key/CA replacement must create a new verified TLS session.
        return hashlib.sha256(canonical({
            "certificate": identity.certificate_pem, "chain": identity.ca_chain_pem,
            "key": identity.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo).hex(),
            "ca": hashlib.sha256(self.config.ca_bundle.read_bytes()).hexdigest(),
            "origin": self.config.server_url,
        })).digest()

    def _context(self, identity):
        context = ssl.create_default_context(cafile=str(self.config.ca_bundle))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if identity is not None:
            secure_directory(self.config.storage_dir)
            with directory_lock(self.config.storage_dir / "transport-lock"):
                # Recover only our fixed temporary files after a process crash.
                # Never traverse a symlink or recursively delete an unknown tree.
                state_root = self.config.storage_dir.resolve()
                for orphan in self.config.storage_dir.glob("tls-*"):
                    if not orphan.is_dir() or orphan.is_symlink() or not orphan.resolve().is_relative_to(state_root):
                        continue
                    for path in orphan.iterdir():
                        if path.name in ("private.pem", "certificate.pem") or path.name.startswith(".") and path.name.endswith(".tmp"):
                            if path.is_file() or path.is_symlink():
                                path.unlink()
                    if not any(orphan.iterdir()):
                        orphan.rmdir()
                with tempfile.TemporaryDirectory(prefix="tls-", dir=self.config.storage_dir) as folder:
                    root = Path(folder)
                    secure_directory(root)
                    cert = root / "certificate.pem"
                    key = root / "private.pem"
                    atomic_write(cert, (identity.certificate_pem + identity.ca_chain_pem).encode("ascii"))
                    atomic_write(key, identity.key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                    # OpenSSL's stdlib API requires a file; the short-lived
                    # plaintext file is removed before any network request.
                    context.load_cert_chain(str(cert), str(key))
        return context

    def post(self, path, body, *, identity=None):
        return self._request("POST", path, body, identity=identity)

    def get(self, path, *, identity):
        return self._request("GET", path, None, identity=identity)

    def download(self, sha256, destination, *, identity, limit=256 * 1024 * 1024):
        """Bounded download from the configured mTLS origin only."""
        import hashlib
        import re
        if identity is None or not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise TransportError("agent_download_failed")
        connection = None
        try:
            target = urlsplit(self.config.server_url)
            connection = http.client.HTTPSConnection(target.hostname, target.port or 443,
                context=self._context(identity), timeout=30)
            connection.request("GET", "/api/v1/agent/package?sha256=" + sha256)
            response = connection.getresponse()
            if response.status != 200:
                raise ValueError()
            digest, total = hashlib.sha256(), 0
            with Path(destination).open("xb") as stream:
                while chunk := response.read(min(1024 * 1024, limit - total + 1)):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError()
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                import os
                os.fsync(stream.fileno())
            if digest.hexdigest() != sha256:
                raise ValueError()
        except Exception:
            raise TransportError("agent_download_failed") from None
        finally:
            if connection is not None:
                connection.close()

    def _request(self, method, path, body, *, identity=None):
        connection = None
        keep = False
        http_status = None
        try:
            packet = method == "POST" and path == "/api/v1/agent/packets" and identity is not None
            key = self._packet_identity_key(identity) if packet else None
            if self._packet_connection is not None:
                if key != self._packet_identity or time.monotonic() - self._packet_used_at >= 2:
                    self.close()
                else:
                    connection = self._packet_connection
            target = urlsplit(self.config.server_url)
            if connection is None:
                connection = http.client.HTTPSConnection(target.hostname, target.port or 443,
                    context=self._context(identity), timeout=30)
            headers = {"Content-Type": "application/json"}
            if packet:
                headers["Connection"] = "keep-alive"
            connection.request(method, path, body=canonical(body) if body is not None else None,
                               headers=headers)
            response = connection.getresponse()
            http_status = response.status
            raw = response.read(MAX_PACKET_BYTES + 1)
            if response.status != 200 or len(raw) > MAX_PACKET_BYTES:
                raise TransportError("agent_transport_failed")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise TransportError("agent_transport_failed")
            if packet and not getattr(response, "will_close", True):
                self._packet_connection = connection
                self._packet_identity = key
                self._packet_used_at = time.monotonic()
                keep = True
            return result
        except Exception:
            self.close()
            # Do not log network exception text, tokens, certificate details or
            # server error bodies. Retry logic needs only a stable failure code.
            # Never automatically replay a POST with an ambiguous acknowledgement.
            raise TransportError("agent_transport_failed", http_status=http_status) from None
        finally:
            if connection is not None and not keep:
                if connection is self._packet_connection:
                    self._packet_connection = None
                    self._packet_identity = None
                connection.close()
