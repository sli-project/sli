"""AD password envelopes. Only the API consumer receives the inventory KEK.

Exceptions and reprs never contain secret material. This module authenticates
stored bytes, not AD accounts, and does not enable an AD operation.
"""
from __future__ import annotations

import base64
import json
import os
import stat
from collections.abc import Mapping

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from deploy.linux.sli_core.secret_files import secret_value

MASTER_KEY_REF = "ad_credentials_master_key"
MASTER_KEY_SETTING = "SLI_AD_CREDENTIALS_MASTER_KEY"
MASTER_KEY_SPEC = {"kind": "symmetric_key", "group": "ad_credentials", "backup": "exclude", "delivery": "api"}


class AdSecretError(ValueError):
    """Fixed diagnostics only."""


def decode_master_key(value: str) -> bytes:
    try:
        key = base64.b64decode(value, validate=True)
        if len(key) != 32 or base64.b64encode(key).decode("ascii") != value:
            raise ValueError
        return key
    except (ValueError, TypeError):
        raise AdSecretError("ad_master_key_invalid") from None


def read_master_key(*, environ: Mapping[str, str] | None = None) -> bytes:
    source = os.environ if environ is None else environ
    if MASTER_KEY_SETTING in source:
        raise AdSecretError("ad_master_key_plaintext_forbidden")
    path = source.get(MASTER_KEY_SETTING + "_FILE")
    if not path:
        raise AdSecretError("ad_master_key_not_configured")
    # File delivery is Linux-only: root-owned systemd credentials or a private
    # tmpfs copy owned by this one consumer. Pin the inode before reading.
    if os.name != "posix":
        raise AdSecretError("ad_master_key_unavailable")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid not in {0, os.geteuid()}
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
                    or info.st_size != 44
                    or any(name.startswith("system.posix_acl_") for name in os.listxattr(fd))):
                raise AdSecretError("ad_master_key_unprotected")
            # Reuse the canonical reader on the pinned descriptor, avoiding a
            # second lookup of an attacker-replaceable source pathname.
            value = secret_value(MASTER_KEY_SETTING, environ={MASTER_KEY_SETTING + "_FILE": f"/proc/self/fd/{fd}"})
            return decode_master_key(value or "")
        finally:
            os.close(fd)
    except AdSecretError:
        raise
    except (OSError, ValueError):
        raise AdSecretError("ad_master_key_unavailable") from None


def key_status() -> dict:
    try:
        read_master_key()
    except AdSecretError as exc:
        return {"available": False, "error_code": str(exc)}
    return {"available": True, "error_code": None}


def _aad(context: dict, purpose: str) -> bytes:
    if (set(context) != {"installation_id", "credential_id", "domain_id", "credential_revision"}
            or any(type(context[key]) is not int or context[key] <= 0 for key in ("domain_id", "credential_revision"))):
        raise AdSecretError("ad_envelope_invalid")
    from uuid import UUID

    try:
        for name in ("installation_id", "credential_id"):
            if str(UUID(context[name])) != context[name] or UUID(context[name]).int == 0:
                raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise AdSecretError("ad_envelope_invalid") from None
    return json.dumps({**context, "format_version": 1, "purpose": purpose}, sort_keys=True, separators=(",", ":")).encode()


def validate_password(password: str) -> None:
    if (type(password) is not str or not 1 <= len(password) <= 4096 or "\x00" in password
            or any(0xD800 <= ord(char) <= 0xDFFF for char in password)):
        raise AdSecretError("ad_password_invalid")


def encrypt_password(password: str, context: dict, master_key: bytes, *, key_version: int = 1) -> dict:
    validate_password(password)
    if type(key_version) is not int or key_version <= 0 or len(master_key) != 32:
        raise AdSecretError("ad_master_key_invalid")
    dek, nonce, wrap_nonce = os.urandom(32), os.urandom(12), os.urandom(12)
    aad = _aad(context, "password")
    wrap_aad = _aad(context, "dek") + str(key_version).encode("ascii")
    return {"format_version": 1, "key_version": key_version,
        **{key: base64.b64encode(value).decode("ascii") for key, value in {
            "nonce": nonce, "ciphertext": AESGCM(dek).encrypt(nonce, password.encode("utf-8"), aad),
            "wrap_nonce": wrap_nonce, "wrapped_dek": AESGCM(master_key).encrypt(wrap_nonce, dek, wrap_aad),
        }.items()}}


def _unwrap(envelope: dict, context: dict, master_key: bytes, key_version: int) -> tuple[bytes, bytes, bytes]:
    try:
        if (type(envelope) is not dict or set(envelope) != {"format_version", "key_version", "nonce", "ciphertext", "wrap_nonce", "wrapped_dek"}
                or type(envelope["format_version"]) is not int or envelope["format_version"] != 1
                or type(envelope["key_version"]) is not int or envelope["key_version"] != key_version):
            raise ValueError
        values = {name: base64.b64decode(envelope[name], validate=True)
                  for name in ("nonce", "ciphertext", "wrap_nonce", "wrapped_dek")}
        if (len(values["nonce"]) != 12 or len(values["wrap_nonce"]) != 12
                or len(values["wrapped_dek"]) != 48 or not 17 <= len(values["ciphertext"]) <= 16400):
            raise ValueError
        dek = AESGCM(master_key).decrypt(values["wrap_nonce"], values["wrapped_dek"],
            _aad(context, "dek") + str(key_version).encode("ascii"))
        return dek, values["nonce"], values["ciphertext"]
    except Exception:
        raise AdSecretError("ad_envelope_invalid") from None


def decrypt_password(envelope: dict, context: dict, master_key: bytes, *, key_version: int = 1) -> str:
    try:
        dek, nonce, ciphertext = _unwrap(envelope, context, master_key, key_version)
        password = AESGCM(dek).decrypt(nonce, ciphertext, _aad(context, "password")).decode("utf-8")
        validate_password(password)
        return password
    except Exception:
        raise AdSecretError("ad_envelope_invalid") from None


def rewrap(envelope: dict, context: dict, old_key: bytes, new_key: bytes, *, old_version: int, new_version: int) -> dict:
    """Authenticate the old envelope, then rotate its DEK without returning a password."""
    if type(new_version) is not int or new_version <= old_version or len(new_key) != 32:
        raise AdSecretError("ad_master_key_invalid")
    dek, nonce, ciphertext = _unwrap(envelope, context, old_key, old_version)
    try:
        AESGCM(dek).decrypt(nonce, ciphertext, _aad(context, "password"))
    except Exception:
        raise AdSecretError("ad_envelope_invalid") from None
    wrap_nonce = os.urandom(12)
    return {**envelope, "key_version": new_version,
        "wrap_nonce": base64.b64encode(wrap_nonce).decode("ascii"),
        "wrapped_dek": base64.b64encode(AESGCM(new_key).encrypt(wrap_nonce, dek,
            _aad(context, "dek") + str(new_version).encode("ascii"))).decode("ascii")}
