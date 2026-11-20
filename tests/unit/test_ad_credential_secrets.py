"""Synthetic passwords only; no AD, network or database access."""
import base64
from copy import deepcopy
import json
import os

import pytest

from server.sli.core import ad_credential_secrets as subject

CONTEXT = {"installation_id": "10000000-0000-4000-8000-000000000001",
    "credential_id": "10000000-0000-4000-8000-000000000002", "domain_id": 1, "credential_revision": 1}
PASSWORD = "synthetic-only-password-ключ"


def test_password_and_dek_are_encrypted_with_independent_random_material():
    key = os.urandom(32)
    first = subject.encrypt_password(PASSWORD, CONTEXT, key)
    second = subject.encrypt_password(PASSWORD, CONTEXT, key)
    assert PASSWORD not in json.dumps(first)
    assert subject.decrypt_password(first, CONTEXT, key) == PASSWORD
    assert first["nonce"] != first["wrap_nonce"]
    assert all(first[field] != second[field] for field in ("nonce", "wrap_nonce", "wrapped_dek", "ciphertext"))
    assert len(base64.b64decode(first["wrapped_dek"])) == 48


@pytest.mark.parametrize("field,value", [
    ("installation_id", "10000000-0000-4000-8000-000000000003"),
    ("credential_id", "10000000-0000-4000-8000-000000000004"),
    ("domain_id", 2), ("credential_revision", 2),
])
def test_row_domain_installation_and_revision_substitution_are_rejected(field, value):
    key = os.urandom(32)
    envelope = subject.encrypt_password(PASSWORD, CONTEXT, key)
    with pytest.raises(subject.AdSecretError, match="^ad_envelope_invalid$"):
        subject.decrypt_password(envelope, {**CONTEXT, field: value}, key)


@pytest.mark.parametrize("field", ["nonce", "ciphertext", "wrap_nonce", "wrapped_dek", "format_version", "key_version", "extra"])
def test_tampering_never_exposes_values(field):
    key = os.urandom(32)
    envelope = subject.encrypt_password(PASSWORD, CONTEXT, key)
    envelope[field] = PASSWORD
    with pytest.raises(subject.AdSecretError, match="^ad_envelope_invalid$") as error:
        subject.decrypt_password(envelope, CONTEXT, key)
    assert PASSWORD not in str(error.value)


def test_wrong_key_database_copy_and_unknown_version_fail_closed():
    key = os.urandom(32)
    envelope = subject.encrypt_password(PASSWORD, CONTEXT, key)
    for other_key, version in ((os.urandom(32), 1), (key, 2)):
        with pytest.raises(subject.AdSecretError, match="ad_envelope_invalid"):
            subject.decrypt_password(envelope, CONTEXT, other_key, key_version=version)


def test_rotation_rewraps_only_dek_and_authenticates_ciphertext():
    old, new = os.urandom(32), os.urandom(32)
    envelope = subject.encrypt_password(PASSWORD, CONTEXT, old)
    rotated = subject.rewrap(envelope, CONTEXT, old, new, old_version=1, new_version=2)
    assert subject.decrypt_password(rotated, CONTEXT, new, key_version=2) == PASSWORD
    assert rotated["ciphertext"] == envelope["ciphertext"] and rotated["nonce"] == envelope["nonce"]
    assert rotated["wrapped_dek"] != envelope["wrapped_dek"]
    assert envelope["key_version"] == 1
    corrupted = deepcopy(envelope)
    corrupted["ciphertext"] = base64.b64encode(b"x" * 32).decode()
    with pytest.raises(subject.AdSecretError, match="ad_envelope_invalid"):
        subject.rewrap(corrupted, CONTEXT, old, new, old_version=1, new_version=2)


@pytest.mark.parametrize("password", [None, "", "x\x00y", "\ud800", "x" * 4097])
def test_invalid_passwords_have_fixed_errors(password):
    with pytest.raises(subject.AdSecretError, match="^ad_password_invalid$"):
        subject.encrypt_password(password, CONTEXT, os.urandom(32))


def test_key_reader_requires_private_file_and_rejects_all_inline_values(tmp_path):
    key = os.urandom(32)
    path = tmp_path / subject.MASTER_KEY_REF
    path.write_bytes(base64.b64encode(key))
    path.chmod(0o600)
    env = {subject.MASTER_KEY_SETTING + "_FILE": str(path)}
    assert subject.read_master_key(environ=env) == key
    for value in ("", base64.b64encode(key).decode()):
        with pytest.raises(subject.AdSecretError, match="plaintext_forbidden"):
            subject.read_master_key(environ={**env, subject.MASTER_KEY_SETTING: value})
    path.chmod(0o640)
    with pytest.raises(subject.AdSecretError, match="unprotected"):
        subject.read_master_key(environ=env)
    path.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(subject.AdSecretError, match="unavailable"):
        subject.read_master_key(environ={subject.MASTER_KEY_SETTING + "_FILE": str(link)})
    os.link(path, tmp_path / "hardlink")
    with pytest.raises(subject.AdSecretError, match="unprotected"):
        subject.read_master_key(environ=env)


def test_missing_and_invalid_key_do_not_generate_replacement(tmp_path):
    with pytest.raises(subject.AdSecretError, match="not_configured"):
        subject.read_master_key(environ={})
    path = tmp_path / subject.MASTER_KEY_REF
    with pytest.raises(subject.AdSecretError, match="unavailable"):
        subject.read_master_key(environ={subject.MASTER_KEY_SETTING + "_FILE": str(path)})
    assert not path.exists()
    for value in ("x" * 44, "", base64.b64encode(b"x" * 31).decode(), "sensitive-marker"):
        with pytest.raises(subject.AdSecretError, match="^ad_master_key_invalid$"):
            subject.decode_master_key(value)
