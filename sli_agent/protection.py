# SPDX-License-Identifier: Apache-2.0
"""DPAPI LocalMachine and restricted files; plaintext keys never reach logs."""
from __future__ import annotations

import base64
import json
import os
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization


def restrict_path(path: Path, *, directory: bool = False):
    if path.is_symlink():
        raise ValueError("agent_state_path_invalid")
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    # A machine-scoped DPAPI blob still needs an ACL: any local principal can
    # decrypt an accessible LocalMachine blob. Use the installing/service SID.
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()
    system = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
    acl = win32security.ACL()
    flags = win32con.OBJECT_INHERIT_ACE | win32con.CONTAINER_INHERIT_ACE if directory else 0
    allowed_sids = [sid, system]
    # MSI owns this machine-wide root and promises administrator cleanup/repair.
    # Preserve the narrower service-account/SYSTEM ACL of the manual installer.
    from sli_agent.config import machine_config_path
    managed_root = machine_config_path().parent
    if path.is_relative_to(managed_root) and (managed_root / ".msi-owned").is_file():
        allowed_sids.append(win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None))
    for allowed in allowed_sids:
        acl.AddAccessAllowedAceEx(win32security.ACL_REVISION, flags, win32con.GENERIC_ALL, allowed)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, acl, None)


def secure_directory(path: Path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    restrict_path(path, directory=True)


def sync_directory(path: Path):
    if os.name != "nt":
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def atomic_write(path: Path, data: bytes):
    secure_directory(path.parent)
    temporary = path.parent / ("." + uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        restrict_path(temporary)
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            move = kernel.MoveFileExW
            move.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
            move.restype = wintypes.BOOL
            if not move(str(temporary), str(path), 0x1 | 0x8):  # REPLACE_EXISTING | WRITE_THROUGH
                raise OSError("agent_state_write_failed")
        else:
            os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if fd is not None:
            os.close(fd)
        temporary.unlink(missing_ok=True)


@contextmanager
def directory_lock(root: Path):
    secure_directory(root)
    with (root / ".lock").open("a+b") as stream:
        restrict_path(root / ".lock")
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            if not stream.read(1):
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def store_private_key(path: Path, key):
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    protection = "restricted_file"
    if os.name == "nt":
        try:
            import win32crypt
        except ImportError:
            win32crypt = None
        if win32crypt is not None:
            # Existing server helpers are CurrentUser-only and cannot be reused
            # by a no-login service installed under a selectable account.
            try:
                raw = win32crypt.CryptProtectData(raw, "SLI agent key", None, None, None, 0x4 | 0x1)
            except Exception:
                raise ValueError("agent_key_protection_failed") from None
            protection = "dpapi_local_machine"
        # If the DPAPI binding is absent, atomic_write still requires the
        # protected service-account/SYSTEM DACL. An ACL failure is fatal.
    atomic_write(path, json.dumps({"protection": protection,
        "data": base64.b64encode(raw).decode("ascii")}, separators=(",", ":")).encode())


def read_private_key(path: Path):
    try:
        restrict_path(path)
        body = json.loads(path.read_bytes())
        raw = base64.b64decode(body["data"], validate=True)
        if body["protection"] == "dpapi_local_machine" and os.name == "nt":
            import win32crypt
            raw = win32crypt.CryptUnprotectData(raw, None, None, None, 0x1)[1]
        elif body["protection"] != "restricted_file":
            raise ValueError()
        return serialization.load_pem_private_key(raw, password=None)
    except Exception:
        raise ValueError("agent_key_unavailable") from None
