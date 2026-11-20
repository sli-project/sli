"""Offline Windows DPAPI checks; every credential and store is disposable."""
from __future__ import annotations

import hmac
from contextlib import closing
import importlib
import json
import os
from pathlib import Path
import secrets

import pytest

pytestmark = pytest.mark.windows_only


def _module():
    return importlib.import_module("server.sli.sources.ad_source_credentials")


def test_profiles_have_separate_default_stores_and_bound_envelopes(tmp_path, monkeypatch):
    module = _module()
    ad_root, vpn_root = tmp_path / "ad", tmp_path / "vpn"
    monkeypatch.setattr(module, "STORE_DIR", ad_root)
    monkeypatch.setattr(module, "VPN_STORE_DIR", vpn_root, raising=False)
    module.store_credentials("ad@synthetic.invalid", "synthetic-ad")
    before = (ad_root / "credentials.dpapi").read_bytes()
    module.store_credentials("vpn@synthetic.invalid", "synthetic-vpn", profile="vpn")
    assert module.load_credentials().username == "ad@synthetic.invalid"
    assert module.load_credentials(profile="vpn").username == "vpn@synthetic.invalid"
    assert module.credentials_status(profile="vpn", expected_username="vpn@synthetic.invalid")["account_matches"] is True
    module.store_credentials("vpn@synthetic.invalid", "synthetic-replaced", profile="vpn", replace=True)
    assert (ad_root / "credentials.dpapi").read_bytes() == before
    assert module.credentials_status(root=vpn_root)["error_code"] == "invalid_payload"
    assert module.credentials_status(root=ad_root, profile="vpn")["error_code"] == "invalid_payload"
    _assert_acl(vpn_root, directory=True)
    _assert_acl(vpn_root / "credentials.dpapi", directory=False)


@pytest.mark.parametrize("profile", ["VPN", "other", "../ad", None, 1])
def test_invalid_profile_fails_closed_before_storage(tmp_path, profile):
    module = _module()
    root = tmp_path / "invalid-profile"
    with pytest.raises(module.AdCredentialStoreError, match="invalid_argument"):
        module.store_credentials("test@synthetic.invalid", "synthetic", root=root, profile=profile)
    with pytest.raises(module.AdCredentialStoreError, match="invalid_argument"):
        module.load_credentials(root=root, profile=profile)
    assert module.credentials_status(root=root, profile=profile)["error_code"] == "invalid_argument"
    assert not root.exists()


def test_cli_vpn_single_entry_preserves_ad(isolated_cli, monkeypatch, tmp_path, capsys):
    cli, ad_root = isolated_cli
    module = _module()
    vpn_root = tmp_path / "vpn-cli-store"
    monkeypatch.setattr(module, "VPN_STORE_DIR", vpn_root, raising=False)
    module.store_credentials("ad@synthetic.invalid", "synthetic-ad")
    before = (ad_root / "credentials.dpapi").read_bytes()
    calls = []
    def hidden(prompt):
        calls.append(prompt)
        return "synthetic-vpn-secret"
    monkeypatch.setattr(cli.getpass, "getpass", hidden)
    assert cli.main(["provision", "--profile", "vpn", "--single-entry", "--username", "vpn@synthetic.invalid"]) == 0
    assert len(calls) == 1
    assert cli.main(["check", "--profile", "vpn", "--username", "vpn@synthetic.invalid"]) == 0
    assert (ad_root / "credentials.dpapi").read_bytes() == before
    assert module.load_credentials(profile="vpn").password == "synthetic-vpn-secret"
    assert "synthetic-vpn-secret" not in capsys.readouterr().out


@pytest.mark.parametrize("cancelled", [False, True])
def test_cli_pause_retains_success_or_cancelled_outcome_without_reprompt(isolated_cli, monkeypatch, cancelled, capsys):
    import builtins
    cli, _ = isolated_cli
    calls, pauses = [], []
    def hidden(prompt):
        calls.append(prompt)
        if cancelled:
            raise KeyboardInterrupt
        return "synthetic-pause-secret"
    monkeypatch.setattr(cli.getpass, "getpass", hidden)
    monkeypatch.setattr(builtins, "input", lambda prompt: pauses.append(prompt))
    result = cli.main(["provision", "--username", "test@synthetic.invalid", "--single-entry", "--pause"])
    assert result == (1 if cancelled else 0)
    assert len(calls) == 1 and len(pauses) == 1
    assert "synthetic-pause-secret" not in capsys.readouterr().out


def _safe_assert(condition: bool, message: str) -> None:
    if not condition:
        pytest.fail(message, pytrace=False)


def _same(actual: str, expected: str) -> bool:
    return hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8"))


def _sid():
    import win32api
    import win32con
    import win32security

    with closing(win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)) as token:
        return win32security.GetTokenInformation(token, win32security.TokenUser)[0]


def _assert_acl(path: Path, directory: bool) -> None:
    import ntsecuritycon
    import win32security

    descriptor = win32security.GetFileSecurity(
        str(path), win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    )
    assert descriptor.GetSecurityDescriptorOwner() == _sid()
    assert descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED
    acl = descriptor.GetSecurityDescriptorDacl()
    assert acl is not None and acl.GetAceCount() == 2
    flags = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE if directory else 0
    expected = {
        win32security.ConvertSidToStringSid(_sid()),
        win32security.ConvertSidToStringSid(win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)),
    }
    actual = set()
    for index in range(acl.GetAceCount()):
        header, mask, sid = acl.GetAce(index)
        assert header == (win32security.ACCESS_ALLOWED_ACE_TYPE, flags)
        assert mask == ntsecuritycon.FILE_ALL_ACCESS
        actual.add(win32security.ConvertSidToStringSid(sid))
    assert actual == expected


def test_current_user_roundtrip_is_exact_encrypted_and_private(tmp_path: Path) -> None:
    module = _module()
    root = tmp_path / "isolated-ad-store"
    username = "SYNTHETIC.example.invalid\\Exact.Test"
    password = " synthetic-" + secrets.token_urlsafe(32) + "-пароль "
    result = module.store_credentials(username, password, root=root)
    loaded = module.load_credentials(root=root)
    _safe_assert(_same(loaded.username, username), "Username changed")
    _safe_assert(_same(loaded.password, password), "Password changed")
    _safe_assert(username not in repr(loaded) and password not in repr(loaded), "Credential repr leaked")
    assert result["status"] == "ready"
    status = module.credentials_status(expected_username=username, root=root)
    assert status["status"] == "ready"
    assert status["account_matches"] is True
    assert module.credentials_status(expected_username="Other@synthetic.invalid", root=root)["account_matches"] is False
    assert module.credentials_status(root=root)["account_matches"] is None
    _safe_assert(username not in json.dumps(status) and password not in json.dumps(status), "Status leaked")
    _safe_assert(username not in json.dumps(result) and password not in json.dumps(result), "Store result leaked")
    files = list(root.iterdir())
    assert len(files) == 1
    blob = files[0].read_bytes()
    _safe_assert(password.encode("utf-8") not in blob and username.encode("utf-8") not in blob, "Plaintext persisted")
    _assert_acl(root, directory=True)
    _assert_acl(files[0], directory=False)


@pytest.mark.parametrize("username", [
    "", "SYNTHETIC", "SYNTHETIC\\", "\\test", "a@", "@synthetic.invalid",
    "SYNTHETIC\\two words", " test@synthetic.invalid", "test@synthetic.invalid\n",
    "SYNTHETIC\\test\\extra", "a@@synthetic.invalid", "SYNTHETIC\\a@b",
    "SYNTHETIC/test", "a\x00b@synthetic.invalid", "a\u200bb@synthetic.invalid", None, 7,
], ids=lambda value: "malformed")
def test_rejects_malformed_username_before_writing(tmp_path: Path, username) -> None:
    module = _module()
    root = tmp_path / "invalid-store"
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials(username, "synthetic-only", root=root)
    assert caught.value.code == "invalid_username"
    assert not root.exists()


@pytest.mark.parametrize("password", ["", None, 7, "a\x00b"], ids=["empty", "none", "number", "nul"])
def test_rejects_invalid_password_before_writing(tmp_path: Path, password) -> None:
    module = _module()
    root = tmp_path / "invalid-store"
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials("test@synthetic.invalid", password, root=root)
    assert caught.value.code == "invalid_password"
    assert not root.exists()


def _provision(tmp_path: Path):
    module = _module()
    root = tmp_path / "synthetic-store"
    password = "synthetic-" + secrets.token_urlsafe(32)
    module.store_credentials("test@synthetic.invalid", password, root=root)
    return module, root, next(root.iterdir()), password


@pytest.mark.parametrize("mutation", [
    "list", "version_bool", "version_wrong", "purpose_wrong", "owner_wrong",
    "owner_type", "username_type", "password_type", "password_empty", "username_bare",
    "extra", "missing", "duplicate", "invalid_json", "invalid_utf8", "oversized_clear",
], ids=str)
def test_decrypted_envelope_is_strict_and_bound(tmp_path: Path, mutation: str) -> None:
    import win32crypt
    import win32security

    module, root, blob_path, _ = _provision(tmp_path)
    payload = {
        "version": 1, "purpose": module._PURPOSE,
        "owner_sid": win32security.ConvertSidToStringSid(_sid()),
        "username": "test@synthetic.invalid", "password": "synthetic-only",
    }
    if mutation == "list":
        payload = []
    elif mutation == "version_bool":
        payload["version"] = True
    elif mutation == "version_wrong":
        payload["version"] = 2
    elif mutation == "purpose_wrong":
        payload["purpose"] = "unrelated-payload"
    elif mutation == "owner_wrong":
        payload["owner_sid"] = "S-1-5-21-111-222-333-444"
    elif mutation == "owner_type":
        payload["owner_sid"] = 1
    elif mutation == "username_type":
        payload["username"] = []
    elif mutation == "password_type":
        payload["password"] = 7
    elif mutation == "password_empty":
        payload["password"] = ""
    elif mutation == "username_bare":
        payload["username"] = "SYNTHETIC\\"
    elif mutation == "extra":
        payload["extra"] = True
    elif mutation == "missing":
        del payload["username"]
    clear = json.dumps(payload).encode("utf-8")
    if mutation == "duplicate":
        clear = clear[:-1] + b',"version":1}'
    elif mutation == "invalid_json":
        clear = b'{broken'
    elif mutation == "invalid_utf8":
        clear = b'\xff'
    elif mutation == "oversized_clear":
        clear = b' ' * (module._MAX_CLEAR_BYTES + 1)
    blob_path.write_bytes(win32crypt.CryptProtectData(clear, module._PURPOSE, None, None, None, 1))
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.load_credentials(root=root)
    expected = "owner_mismatch" if mutation == "owner_wrong" else "invalid_payload"
    assert caught.value.code == expected
    status = module.credentials_status(expected_username="test@synthetic.invalid", root=root)
    assert status["status"] == "unreadable"
    assert status["error_code"] == expected
    if mutation == "owner_wrong":
        assert status["owner_matches"] is False


def test_status_missing_is_read_only_and_sanitized(tmp_path: Path) -> None:
    module = _module()
    root = tmp_path / "never-created"
    status = module.credentials_status(root=root)
    assert status == {
        "status": "missing", "dpapi_scope": "CurrentUser", "owner_matches": None,
        "account_matches": None, "error_code": "missing", "credential_values_exposed": False,
    }
    assert not root.exists()
    assert str(module.AdCredentialStoreError("untrusted input")) == "storage_failed"


def test_separate_process_current_user_roundtrip(tmp_path: Path) -> None:
    import hashlib
    import subprocess
    import sys

    _, root, _, password = _provision(tmp_path)
    # No clear password in arguments, environment, files or child output.
    expected = hashlib.sha256(password.encode("utf-8")).hexdigest()
    program = '''
import hashlib, hmac, json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from server.sli.sources.ad_source_credentials import load_credentials, credentials_status
root = Path(sys.argv[2])
try:
    value = load_credentials(root=root)
    matched = hmac.compare_digest(hashlib.sha256(value.password.encode("utf-8")).hexdigest(), sys.stdin.read())
    status = credentials_status(root=root, expected_username="test@synthetic.invalid")
    print(json.dumps({"password_matches": matched, "status": status}))
except Exception:
    print('{"failed":true}')
    raise SystemExit(1)
'''
    child = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program, str(Path(__file__).resolve().parents[2]), str(root)],
        input=expected, text=True, capture_output=True, timeout=30, cwd=tmp_path,
        check=False,
    )
    assert child.returncode == 0
    assert child.stderr == ""
    output = json.loads(child.stdout)
    assert output["password_matches"] is True
    assert output["status"]["status"] == "ready"
    assert output["status"]["account_matches"] is True
    assert output["status"]["owner_matches"] is True
    assert output["status"]["dpapi_scope"] == "CurrentUser"
    _safe_assert(password not in child.stdout + child.stderr, "Child output leaked")


def test_refuses_overwrite_and_explicit_replace_is_verified(tmp_path: Path) -> None:
    module, root, blob_path, original_password = _provision(tmp_path)
    original_blob = blob_path.read_bytes()
    new_password = "synthetic-" + secrets.token_urlsafe(32)
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials("changed@synthetic.invalid", new_password, root=root)
    assert caught.value.code == "already_exists"
    _safe_assert(blob_path.read_bytes() == original_blob, "Refused write changed ciphertext")
    _safe_assert(_same(module.load_credentials(root=root).password, original_password), "Original lost")
    result = module.store_credentials("changed@synthetic.invalid", new_password, root=root, replace=True)
    assert result["status"] == "ready"
    _safe_assert(_same(module.load_credentials(root=root).password, new_password), "Replacement not read back")
    assert len(list(root.iterdir())) == 1
    _assert_acl(blob_path, directory=False)


@pytest.mark.parametrize("corruption", ["empty", "truncated", "corrupt", "oversized"])
def test_ciphertext_corruption_is_unreadable(tmp_path: Path, corruption: str) -> None:
    module, root, blob_path, _ = _provision(tmp_path)
    blob = blob_path.read_bytes()
    if corruption == "empty":
        blob = b""
    elif corruption == "truncated":
        blob = blob[:16]
    elif corruption == "corrupt":
        blob = blob[:-1] + bytes([blob[-1] ^ 0x80])
    else:
        blob = b"x" * (module._MAX_BLOB_BYTES + 1)
    blob_path.write_bytes(blob)
    status = module.credentials_status(root=root)
    assert status["status"] == "unreadable"
    assert status["error_code"] in {"invalid_size", "dpapi_failed"}
    with pytest.raises(module.AdCredentialStoreError):
        module.load_credentials(root=root)


def test_existing_unrelated_directory_is_never_adopted(tmp_path: Path) -> None:
    import win32security

    module = _module()
    root = tmp_path / "unrelated"
    root.mkdir()
    unrelated = root / "unrelated.txt"
    unrelated.write_bytes(b"synthetic unrelated data")
    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    before = bytes(win32security.GetFileSecurity(str(root), info))
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials("test@synthetic.invalid", "synthetic-only", root=root)
    assert caught.value.code in {"unsafe_acl", "owner_mismatch"}
    after = bytes(win32security.GetFileSecurity(str(root), info))
    assert before == after
    assert list(root.iterdir()) == [unrelated]
    assert unrelated.read_bytes() == b"synthetic unrelated data"


@pytest.mark.parametrize("target", ["directory", "file"])
def test_acl_drift_is_rejected_without_repair(tmp_path: Path, target: str) -> None:
    import ntsecuritycon
    import win32security

    module, root, blob_path, _ = _provision(tmp_path)
    path = root if target == "directory" else blob_path
    info = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    descriptor = win32security.GetFileSecurity(str(path), info)
    acl = descriptor.GetSecurityDescriptorDacl()
    acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, 0, ntsecuritycon.FILE_GENERIC_READ,
                            win32security.CreateWellKnownSid(win32security.WinWorldSid))
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)
    before = bytes(win32security.GetFileSecurity(str(path), info))
    assert module.credentials_status(root=root)["error_code"] == "unsafe_acl"
    with pytest.raises(module.AdCredentialStoreError):
        module.store_credentials("test@synthetic.invalid", "synthetic-only", root=root, replace=True)
    after = bytes(win32security.GetFileSecurity(str(path), info))
    assert before == after


@pytest.mark.parametrize("target", ["root", "ancestor"])
def test_real_junction_paths_are_rejected(tmp_path: Path, target: str) -> None:
    import _winapi

    module, root, blob_path, _ = _provision(tmp_path)
    before = blob_path.read_bytes()
    junction = tmp_path / "junction"
    _winapi.CreateJunction(str(root if target == "root" else tmp_path), str(junction))
    alias = junction if target == "root" else junction / root.name
    try:
        status = module.credentials_status(root=alias)
        assert status["error_code"] == "unsafe_path"
        with pytest.raises(module.AdCredentialStoreError):
            module.store_credentials("test@synthetic.invalid", "synthetic-only", root=alias, replace=True)
        _safe_assert(blob_path.read_bytes() == before, "Junction changed target")
    finally:
        junction.rmdir()


def test_hard_linked_blob_is_rejected(tmp_path: Path) -> None:
    module, root, blob_path, _ = _provision(tmp_path)
    alias = root / "extra-link"
    os.link(blob_path, alias)
    assert module.credentials_status(root=root)["error_code"] == "unsafe_path"
    with pytest.raises(module.AdCredentialStoreError):
        module.store_credentials("test@synthetic.invalid", "synthetic-only", root=root, replace=True)


def test_dpapi_flags_are_current_user_and_failures_are_sanitized(tmp_path: Path, monkeypatch) -> None:
    import win32crypt

    module = _module()
    protect = win32crypt.CryptProtectData
    unprotect = win32crypt.CryptUnprotectData
    flags = []

    def recording_protect(*args):
        flags.append(args[-1])
        return protect(*args)

    def recording_unprotect(*args):
        flags.append(args[-1])
        return unprotect(*args)

    monkeypatch.setattr(win32crypt, "CryptProtectData", recording_protect)
    monkeypatch.setattr(win32crypt, "CryptUnprotectData", recording_unprotect)
    _, root, _, password = _provision(tmp_path)
    module.load_credentials(root=root)
    assert len(flags) >= 3 and set(flags) == {1}

    def fail(*args):
        raise RuntimeError(password)

    monkeypatch.setattr(win32crypt, "CryptUnprotectData", fail)
    status = module.credentials_status(root=root)
    assert status["error_code"] == "dpapi_failed"
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.load_credentials(root=root)
    _safe_assert(password not in str(caught.value) + repr(caught.value) + json.dumps(status), "Error leaked")
    assert caught.value.__suppress_context__


def test_interrupted_replace_preserves_old_blob_and_cleans_temporary(tmp_path: Path, monkeypatch) -> None:
    import win32file

    module, root, blob_path, password = _provision(tmp_path)
    before = blob_path.read_bytes()

    def fail(*args):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(win32file, "MoveFileEx", fail)
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials("test@synthetic.invalid", "synthetic-replacement", root=root, replace=True)
    assert caught.value.code == "storage_failed"
    assert list(root.iterdir()) == [blob_path]
    _safe_assert(before == blob_path.read_bytes(), "Atomic failure damaged old ciphertext")
    _safe_assert(_same(module.load_credentials(root=root).password, password), "Old value lost")


def test_replace_requires_an_actual_boolean(tmp_path: Path) -> None:
    module = _module()
    root = tmp_path / "never-created"
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials("test@synthetic.invalid", "synthetic-only", root=root, replace="yes")
    assert caught.value.code == "invalid_argument"
    assert not root.exists()


def test_remote_drive_is_rejected_before_file_access(tmp_path: Path, monkeypatch) -> None:
    import win32file

    module = _module()
    monkeypatch.setattr(win32file, "GetDriveType", lambda path: win32file.DRIVE_REMOTE)
    called = []

    def forbidden(*args):
        called.append(True)
        raise AssertionError("No file access allowed")

    monkeypatch.setattr(win32file, "CreateFile", forbidden)
    status = module.credentials_status(root=tmp_path / "remote-simulation")
    assert status["error_code"] == "unsafe_path"
    assert not called


@pytest.mark.parametrize("value", ["SYNTHETIC\\", 7, []], ids=["bare", "number", "list"])
def test_invalid_expected_account_is_rejected_before_read(tmp_path: Path, value) -> None:
    module = _module()
    status = module.credentials_status(root=tmp_path / "missing", expected_username=value)
    assert status["status"] == "unreadable"
    assert status["error_code"] == "invalid_username"


def test_changed_expected_local_owner_is_rejected(tmp_path: Path, monkeypatch) -> None:
    import win32security

    module, root, blob_path, _ = _provision(tmp_path)
    before = blob_path.read_bytes()
    other = win32security.CreateWellKnownSid(win32security.WinBuiltinGuestsSid)
    monkeypatch.setattr(module, "_current_sid", lambda: other)
    assert module.credentials_status(root=root)["error_code"] == "owner_mismatch"
    with pytest.raises(module.AdCredentialStoreError):
        module.store_credentials("test@synthetic.invalid", "synthetic-only", root=root, replace=True)
    _safe_assert(before == blob_path.read_bytes(), "Owner mismatch modified blob")


@pytest.mark.parametrize("field", ["username", "password"])
def test_input_limits_fail_before_any_store_write(tmp_path: Path, field: str) -> None:
    module = _module()
    root = tmp_path / "never-created"
    username = "x" * 1025 + "@synthetic.invalid" if field == "username" else "test@synthetic.invalid"
    password = "x" * 4097 if field == "password" else "synthetic-only"
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.store_credentials(username, password, root=root)
    assert caught.value.code == "invalid_" + field
    assert not root.exists()


@pytest.mark.parametrize("target", ["root", "blob"])
def test_unexpected_filesystem_object_type_is_rejected(tmp_path: Path, target: str) -> None:
    module = _module()
    if target == "root":
        root = tmp_path / "not-directory"
        root.write_bytes(b"synthetic unrelated data")
    else:
        _, root, blob_path, _ = _provision(tmp_path)
        blob_path.unlink()
        blob_path.mkdir()
    assert module.credentials_status(root=root)["error_code"] == "unsafe_path"


@pytest.fixture
def isolated_cli(tmp_path: Path, monkeypatch):
    import io
    import sys
    from scripts.maintenance import ad_source_credentials as cli

    root = tmp_path / "cli-only-store"
    monkeypatch.setattr(_module(), "STORE_DIR", root)

    class Console(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", Console())
    return cli, root


def test_cli_hidden_prompt_provision_and_check(isolated_cli, monkeypatch, capsys) -> None:
    cli, root = isolated_cli
    username = "Case.Keep@synthetic.invalid"
    password = "synthetic-" + secrets.token_urlsafe(32)
    prompts = []

    def hidden(prompt):
        prompts.append(prompt)
        return password

    monkeypatch.setattr(cli.getpass, "getpass", hidden)
    assert cli.main(["provision", "--username", username]) == 0
    assert len(prompts) == 2
    assert cli.main(["check", "--username", username]) == 0
    assert cli.main(["check", "--username", "other@synthetic.invalid"]) == 1
    output = capsys.readouterr()
    _safe_assert(password not in output.out + output.err, "CLI leaked password")
    metadata_lines = "\n".join(line for line in output.out.splitlines() if line.startswith("{"))
    _safe_assert(username not in metadata_lines, "CLI metadata leaked username")
    _safe_assert(_same(_module().load_credentials(root=root).password, password), "CLI did not save exact input")
    assert cli.main(["provision", "--username", username]) == 1
    assert len(prompts) == 2


@pytest.mark.parametrize("username", [
    "", "SYNTHETIC\\", "bare", "a b@synthetic.invalid",
    "a\u200bb@synthetic.invalid", "a/b@synthetic.invalid",
], ids=["empty", "bare-domain", "bare-login", "space", "hidden-format", "slash"])
def test_cli_rejects_invalid_username_before_prompt(isolated_cli, monkeypatch, capsys, username) -> None:
    cli, root = isolated_cli
    calls = []
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt: calls.append(prompt))
    assert cli.main(["provision", "--username", username]) == 1
    assert not calls
    assert not root.exists()
    assert "invalid_username" in capsys.readouterr().out


@pytest.mark.parametrize("mode", ["empty", "mismatch", "noninteractive", "warning", "cancelled"])
def test_cli_failed_secret_entry_never_writes(isolated_cli, monkeypatch, mode: str) -> None:
    import io
    import sys
    import warnings

    cli, root = isolated_cli
    answers = iter(["synthetic-only", "synthetic-different"])

    def hidden(prompt):
        if mode == "empty":
            return ""
        if mode == "warning":
            warnings.warn("synthetic console warning", cli.getpass.GetPassWarning)
        if mode == "cancelled":
            raise EOFError
        return next(answers)

    monkeypatch.setattr(cli.getpass, "getpass", hidden)
    if mode == "noninteractive":
        monkeypatch.setattr(sys, "stdin", io.StringIO())
    assert cli.main(["provision", "--username", "test@synthetic.invalid"]) == 1
    assert not root.exists()


def test_cli_rejects_password_and_root_arguments_without_echo(isolated_cli, capsys) -> None:
    cli, root = isolated_cli
    for flag in ("--password", "--root", "--input-file"):
        value = "synthetic-" + secrets.token_urlsafe(32)
        with pytest.raises(SystemExit) as caught:
            cli.main(["provision", "--username", "test@synthetic.invalid", flag, value])
        assert caught.value.code == 2
        output = capsys.readouterr()
        _safe_assert(value not in output.out + output.err, "Argument parser echoed value")
    assert not root.exists()


@pytest.mark.parametrize("username", ["SYNTHETIC.example.invalid\\Exact.User", "Exact.User@synthetic.invalid"])
def test_public_username_validator_preserves_input(username: str) -> None:
    module = _module()
    _safe_assert(module.validate_username(username) == username, "Validator changed input")
    with pytest.raises(module.AdCredentialStoreError) as caught:
        module.validate_username("SYNTHETIC\\")
    assert caught.value.code == "invalid_username"
