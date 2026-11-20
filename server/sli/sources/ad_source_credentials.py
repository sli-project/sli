"""Explicit local AD credential storage, never runtime/source activation.

Windows DPAPI CurrentUser protects the envelope; owner/SYSTEM-only protected
DACLs protect its dedicated directory and ciphertext. No environment discovery,
fallback credentials, authentication or network access is performed. ``root``
is the exact store directory override for isolated tests, not a runtime setting.
Python strings cannot promise in-memory zeroization. DPAPI readback proves only
this logon context, not source authentication or another service logon context.
"""
from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path
import secrets
import unicodedata

from server.sli.core.paths import DATA_DIR

STORE_DIR = DATA_DIR / "runtime" / "ad-source-credentials"
VPN_STORE_DIR = DATA_DIR / "runtime" / "vpn-source-credentials"
_BLOB_NAME = "credentials.dpapi"
_PURPOSE = "sli.ad-source-credentials"
_VERSION = 1
_DPAPI_UI_FORBIDDEN = 1  # Deliberately NOT CRYPTPROTECT_LOCAL_MACHINE.
_MAX_CLEAR_BYTES = 32768
_MAX_BLOB_BYTES = 65536
_CODES = frozenset({
    "missing", "already_exists", "invalid_username", "invalid_password",
    "invalid_argument", "unsafe_path", "unsafe_acl", "owner_mismatch",
    "invalid_payload", "invalid_size", "dpapi_failed", "windows_required",
    "storage_failed", "verification_failed",
})


class AdCredentialStoreError(RuntimeError):
    """Only an allowlisted code is safe to print; OS/DPAPI errors stay private."""

    def __init__(self, code: str):
        self.code = code if isinstance(code, str) and code in _CODES else "storage_failed"
        super().__init__(self.code)


@dataclass(frozen=True)
class AdSourceCredentials:
    username: str = field(repr=False)
    password: str = field(repr=False)


class CredentialProfile(str, Enum):
    AD = "ad"
    VPN = "vpn"


def _profile_settings(profile: CredentialProfile | str) -> tuple[Path, str]:
    try:
        selected = CredentialProfile(profile)
    except (ValueError, TypeError):
        raise AdCredentialStoreError("invalid_argument") from None
    if selected is CredentialProfile.AD:
        return STORE_DIR, _PURPOSE
    return VPN_STORE_DIR, "sli.vpn-source-credentials"


def validate_username(username: str) -> str:
    """Validate complete DOMAIN\\login or UPN syntax; return the exact input.

    This pure check does not resolve the domain or authenticate the account.
    Call it before prompting; store/load/status use this same validator.
    """
    if type(username) is not str or not 0 < len(username) <= 1024:
        raise AdCredentialStoreError("invalid_username")
    if any(ch.isspace() or unicodedata.category(ch).startswith("C") for ch in username):
        raise AdCredentialStoreError("invalid_username")
    if any(ch in username for ch in '/:"<>|?*;=,[]'):
        raise AdCredentialStoreError("invalid_username")
    if username.count("\\") == 1 and "@" not in username:
        domain, account = username.split("\\")
    elif username.count("@") == 1 and "\\" not in username:
        account, domain = username.split("@")
    else:
        raise AdCredentialStoreError("invalid_username")
    if not account or not domain or account in {".", ".."} or domain in {".", ".."}:
        raise AdCredentialStoreError("invalid_username")
    return username


def _validate_password(password: str) -> None:
    if type(password) is not str or not 0 < len(password) <= 4096:
        raise AdCredentialStoreError("invalid_password")
    if "\x00" in password or any(unicodedata.category(ch) == "Cs" for ch in password):
        raise AdCredentialStoreError("invalid_password")


def _windows():
    if os.name != "nt":
        raise AdCredentialStoreError("windows_required")
    import ntsecuritycon
    import win32api
    import win32con
    import win32crypt
    import win32file
    import win32security

    return win32api, win32con, win32crypt, win32file, win32security, ntsecuritycon


def _current_sid():
    api, con, _, _, security, _ = _windows()
    try:
        token = security.OpenThreadToken(api.GetCurrentThread(), con.TOKEN_QUERY, True)
    except Exception as exc:
        if getattr(exc, "winerror", None) != 1008:  # ERROR_NO_TOKEN
            raise
        token = security.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    with closing(token):
        return security.GetTokenInformation(token, security.TokenUser)[0]


def _security_attributes(sid, *, directory: bool):
    _, _, _, _, security, rights = _windows()
    system = security.CreateWellKnownSid(security.WinLocalSystemSid)
    flags = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if directory else 0
    acl = security.ACL()
    for principal in (sid,) if sid == system else (sid, system):
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, flags, rights.FILE_ALL_ACCESS, principal)
    descriptor = security.SECURITY_DESCRIPTOR()
    descriptor.SetSecurityDescriptorOwner(sid, False)
    descriptor.SetSecurityDescriptorDacl(True, acl, False)
    descriptor.SetSecurityDescriptorControl(security.SE_DACL_PROTECTED, security.SE_DACL_PROTECTED)
    attributes = security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def _verify_handle(handle, sid, *, directory: bool, enforce_acl: bool = True):
    _, con, _, files, security, rights = _windows()
    info = files.GetFileInformationByHandle(handle)
    attributes = info[0]
    if attributes & con.FILE_ATTRIBUTE_REPARSE_POINT:
        raise AdCredentialStoreError("unsafe_path")
    if bool(attributes & con.FILE_ATTRIBUTE_DIRECTORY) != directory:
        raise AdCredentialStoreError("unsafe_path")
    if not directory and info[7] != 1:  # Reject hard-linked credential files too.
        raise AdCredentialStoreError("unsafe_path")
    if enforce_acl:
        descriptor = security.GetSecurityInfo(
            handle, security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION,
        )
        if descriptor.GetSecurityDescriptorOwner() != sid:
            raise AdCredentialStoreError("owner_mismatch")
        acl = descriptor.GetSecurityDescriptorDacl()
        flags = security.OBJECT_INHERIT_ACE | security.CONTAINER_INHERIT_ACE if directory else 0
        system = security.CreateWellKnownSid(security.WinLocalSystemSid)
        expected = {security.ConvertSidToStringSid(principal) for principal in (sid, system)}
        actual = set()
        if not descriptor.GetSecurityDescriptorControl()[0] & security.SE_DACL_PROTECTED or acl is None:
            raise AdCredentialStoreError("unsafe_acl")
        if acl.GetAceCount() != len(expected):
            raise AdCredentialStoreError("unsafe_acl")
        for index in range(acl.GetAceCount()):
            ace = acl.GetAce(index)
            if len(ace) != 3 or ace[0] != (security.ACCESS_ALLOWED_ACE_TYPE, flags) or ace[1] != rights.FILE_ALL_ACCESS:
                raise AdCredentialStoreError("unsafe_acl")
            actual.add(security.ConvertSidToStringSid(ace[2]))
        if actual != expected:
            raise AdCredentialStoreError("unsafe_acl")
    return info


def _root_path(root: Path | None) -> Path:
    path = STORE_DIR if root is None else root
    if not isinstance(path, Path) or not path.is_absolute():
        raise AdCredentialStoreError("unsafe_path")
    # Local drive paths only: no UNC/device paths, ADS, dot traversal or aliases.
    if len(path.drive) != 2 or path.drive[1] != ":" or not path.drive[0].isalpha():
        raise AdCredentialStoreError("unsafe_path")
    if len(str(path)) > 32700 or len(path.parts) > 128:
        raise AdCredentialStoreError("unsafe_path")
    for part in path.parts[1:]:
        if part in {".", ".."} or part.endswith((" ", ".")) or any(ch in part for ch in ':<>"|?*'):
            raise AdCredentialStoreError("unsafe_path")
    _, _, _, files, _, _ = _windows()
    if files.GetDriveType(path.anchor) != files.DRIVE_FIXED:
        raise AdCredentialStoreError("unsafe_path")
    return path


@contextmanager
def _directory(root: Path, sid, *, create: bool):
    _, con, _, files, _, rights = _windows()
    # Pin every ancestor without FILE_SHARE_DELETE to prevent path replacement.
    # Do not repair/take ownership of any existing directory or inherited ACL.
    with ExitStack() as stack:
        for path in (*reversed(root.parents), root):
            try:
                handle = files.CreateFile(
                    str(path), rights.FILE_READ_ATTRIBUTES | (con.READ_CONTROL if path == root else 0),
                    con.FILE_SHARE_READ | con.FILE_SHARE_WRITE, None, con.OPEN_EXISTING,
                    con.FILE_FLAG_BACKUP_SEMANTICS | files.FILE_FLAG_OPEN_REPARSE_POINT, None,
                )
            except Exception as exc:
                if getattr(exc, "winerror", None) not in {2, 3}:
                    raise
                if path != root or not create:
                    raise AdCredentialStoreError("missing") from None
                try:
                    files.CreateDirectory(str(root), _security_attributes(sid, directory=True))
                except Exception as creation:
                    if getattr(creation, "winerror", None) != 183:
                        raise
                handle = files.CreateFile(
                    str(path), rights.FILE_READ_ATTRIBUTES | con.READ_CONTROL,
                    con.FILE_SHARE_READ | con.FILE_SHARE_WRITE, None, con.OPEN_EXISTING,
                    con.FILE_FLAG_BACKUP_SEMANTICS | files.FILE_FLAG_OPEN_REPARSE_POINT, None,
                )
            stack.enter_context(closing(handle))
            _verify_handle(handle, sid, directory=True, enforce_acl=path == root)
        yield


@contextmanager
def _blob_handle(path: Path, sid):
    _, con, _, files, _, _ = _windows()
    try:
        handle = files.CreateFile(
            str(path), con.GENERIC_READ | con.READ_CONTROL, con.FILE_SHARE_READ,
            None, con.OPEN_EXISTING, files.FILE_FLAG_OPEN_REPARSE_POINT | con.FILE_FLAG_BACKUP_SEMANTICS, None,
        )
    except Exception as exc:
        if getattr(exc, "winerror", None) in {2, 3}:
            raise AdCredentialStoreError("missing") from None
        raise
    with closing(handle):
        _verify_handle(handle, sid, directory=False)
        yield handle


def _read_blob(root: Path, sid) -> bytes:
    _, _, _, files, _, _ = _windows()
    with _blob_handle(root / _BLOB_NAME, sid) as handle:
        size = files.GetFileSize(handle)
        if not 0 < size <= _MAX_BLOB_BYTES:
            raise AdCredentialStoreError("invalid_size")
        _, data = files.ReadFile(handle, size)
        if len(data) != size or files.GetFileSize(handle) != size:
            raise AdCredentialStoreError("invalid_size")
        return bytes(data)


def _unique_object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AdCredentialStoreError("invalid_payload")
        result[key] = value
    return result


def _load(root: Path, sid, *, purpose: str = _PURPOSE) -> AdSourceCredentials:
    _, _, crypt, _, security, _ = _windows()
    blob = _read_blob(root, sid)
    try:
        description, clear = crypt.CryptUnprotectData(blob, None, None, None, _DPAPI_UI_FORBIDDEN)
    except Exception:
        raise AdCredentialStoreError("dpapi_failed") from None
    if description != purpose or not 0 < len(clear) <= _MAX_CLEAR_BYTES:
        raise AdCredentialStoreError("invalid_payload")
    try:
        payload = json.loads(bytes(clear).decode("utf-8"), object_pairs_hook=_unique_object)
        if type(payload) is not dict or set(payload) != {"version", "purpose", "owner_sid", "username", "password"}:
            raise ValueError
        if type(payload["version"]) is not int or payload["version"] != _VERSION or payload["purpose"] != purpose:
            raise ValueError
        if type(payload["owner_sid"]) is not str:
            raise ValueError
        validate_username(payload["username"])
        _validate_password(payload["password"])
    except Exception:
        raise AdCredentialStoreError("invalid_payload") from None
    if payload["owner_sid"] != security.ConvertSidToStringSid(sid):
        raise AdCredentialStoreError("owner_mismatch")
    return AdSourceCredentials(payload["username"], payload["password"])


def _metadata(status: str, *, matches: bool | None = None, owner: bool | None = None, code: str | None = None) -> dict:
    return {
        "status": status,
        "dpapi_scope": "CurrentUser",
        "owner_matches": owner,
        "account_matches": matches,
        "error_code": code,
        "credential_values_exposed": False,
    }


def store_credentials(username: str, password: str, *, root: Path | None = None, replace: bool = False,
                      profile: CredentialProfile | str = CredentialProfile.AD) -> dict:
    """Create the dedicated store, or replace a blob only with explicit consent.

    The parent directory must already exist. Existing unsafe directories/files
    are rejected, never adopted or repaired. Returns only allowlisted metadata.
    """
    try:
        profile_path, purpose = _profile_settings(profile)
        validate_username(username)
        _validate_password(password)
        if type(replace) is not bool:
            raise AdCredentialStoreError("invalid_argument")
        _, _, crypt, files, security, _ = _windows()
        sid = _current_sid()
        path = _root_path(profile_path if root is None else root)
        clear = json.dumps({
            "version": _VERSION, "purpose": purpose,
            "owner_sid": security.ConvertSidToStringSid(sid),
            "username": username, "password": password,
        }, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(clear) > _MAX_CLEAR_BYTES:
            raise AdCredentialStoreError("invalid_size")
        try:
            blob = bytes(crypt.CryptProtectData(clear, purpose, None, None, None, _DPAPI_UI_FORBIDDEN))
        except Exception:
            raise AdCredentialStoreError("dpapi_failed") from None
        if not 0 < len(blob) <= _MAX_BLOB_BYTES:
            raise AdCredentialStoreError("invalid_size")
        with _directory(path, sid, create=True):
            destination = path / _BLOB_NAME
            exists = False
            try:
                with _blob_handle(destination, sid):
                    exists = True
            except AdCredentialStoreError as exc:
                if exc.code != "missing":
                    raise
            if exists and not replace:
                raise AdCredentialStoreError("already_exists")
            temporary = path / (".pending-" + secrets.token_hex(16))
            created = False
            try:
                _, con, _, _, _, _ = _windows()
                with closing(files.CreateFile(
                    str(temporary), con.GENERIC_WRITE | con.READ_CONTROL, 0,
                    _security_attributes(sid, directory=False), con.CREATE_NEW,
                    con.FILE_ATTRIBUTE_NORMAL | files.FILE_FLAG_OPEN_REPARSE_POINT, None,
                )) as handle:
                    created = True
                    _verify_handle(handle, sid, directory=False)
                    _, written = files.WriteFile(handle, blob)
                    if written != len(blob):
                        raise AdCredentialStoreError("storage_failed")
                    files.FlushFileBuffers(handle)
                flags = files.MOVEFILE_WRITE_THROUGH | (con.MOVEFILE_REPLACE_EXISTING if replace else 0)
                try:
                    files.MoveFileEx(str(temporary), str(destination), flags)
                except Exception as exc:
                    if getattr(exc, "winerror", None) in {80, 183} and not replace:
                        raise AdCredentialStoreError("already_exists") from None
                    raise
                created = False
                loaded = _load(path, sid, purpose=purpose)
                if loaded.username != username or loaded.password != password:
                    raise AdCredentialStoreError("verification_failed")
            finally:
                if created:
                    files.DeleteFile(str(temporary))
        return _metadata("ready", matches=True, owner=True)
    except AdCredentialStoreError:
        raise
    except Exception:
        raise AdCredentialStoreError("storage_failed") from None


def load_credentials(*, root: Path | None = None,
                     profile: CredentialProfile | str = CredentialProfile.AD) -> AdSourceCredentials:
    """Return credentials only after local DPAPI, file and envelope validation."""
    try:
        profile_path, purpose = _profile_settings(profile)
        sid = _current_sid()
        path = _root_path(profile_path if root is None else root)
        with _directory(path, sid, create=False):
            return _load(path, sid, purpose=purpose)
    except AdCredentialStoreError:
        raise
    except Exception:
        raise AdCredentialStoreError("storage_failed") from None


def credentials_status(*, expected_username: str | None = None, root: Path | None = None,
                       profile: CredentialProfile | str = CredentialProfile.AD) -> dict:
    """Read-only storage readiness; never claim active/source authentication.

    Account comparison is exact, not case-folded or rewritten. Missing and
    unreadable stores have unknown (None) owner/account matching metadata.
    """
    try:
        if expected_username is not None:
            validate_username(expected_username)
        credentials = load_credentials(root=root, profile=profile)
        matches = None if expected_username is None else credentials.username == expected_username
        return _metadata("ready", matches=matches, owner=True)
    except AdCredentialStoreError as exc:
        return _metadata(
            "missing" if exc.code == "missing" else "unreadable", code=exc.code,
            owner=False if exc.code == "owner_mismatch" else None,
        )
