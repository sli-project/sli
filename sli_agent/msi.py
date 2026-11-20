# SPDX-License-Identifier: Apache-2.0
"""Local MSI provisioning and file-only enrollment. Never prints input values."""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from sli_agent.config import AgentConfig, machine_config_path

OWNER = "sli-agent-msi-v1"
MAX_TOKEN = 8192
BOOTSTRAP_TTL = 3600
GROUP_TTL = 604800


def decode_property(value):
    return "" if value == "-" else bytes.fromhex(value).decode("utf-16le")


def acl_sddl(sid="S-1-5-18", *, directory=True):
    if not isinstance(sid, str) or re.fullmatch(r"S-1-\d+(?:-\d+){1,15}", sid) is None:
        raise ValueError("agent_config_invalid")
    flags = "OICI" if directory else ""
    result = f"D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)"
    if sid not in ("S-1-5-18", "S-1-5-32-544"):
        result += f"(A;{flags};FA;;;{sid})"
    return result


def configuration(url, root, sid, ca_fingerprint=None):
    body = {"server_url": url, "ca_bundle": str(root / "server-ca.pem"),
            "state_dir": str(root / "state"), "service_identity_sid": sid,
            "collection_enabled": False, "event_channels": ()}
    if ca_fingerprint:
        body["ca_fingerprint"] = ca_fingerprint
    AgentConfig(**body)
    acl_sddl(sid)
    # The validated config uses tuples; agent.json stores JSON arrays.
    body["event_channels"] = list(body["event_channels"])
    return body


def no_reparse(path):
    for part in (path, *path.parents):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("agent_msi_path_unsafe")


def set_acl(path, sid="S-1-5-18", *, directory=False):
    no_reparse(path)
    if os.name != "nt":
        path.chmod(0o700 if directory else 0o600)
        return
    import win32security
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        acl_sddl(sid, directory=directory), win32security.SDDL_REVISION_1)
    win32security.SetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None, None, descriptor.GetSecurityDescriptorDacl(), None)


def private_descriptor(descriptor, sid, *, require_protected=True):
    import win32security
    if require_protected and not descriptor.GetSecurityDescriptorControl()[0] & win32security.SE_DACL_PROTECTED:
        raise ValueError("agent_msi_bootstrap_acl")
    allowed = {"S-1-5-18", "S-1-5-32-544", sid}
    if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in allowed:
        raise ValueError("agent_msi_bootstrap_acl")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise ValueError("agent_msi_bootstrap_acl")
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        # Reject object/callback ACEs rather than incorrectly decoding them.
        if ace[0][0] not in (win32security.ACCESS_ALLOWED_ACE_TYPE, win32security.ACCESS_DENIED_ACE_TYPE):
            raise ValueError("agent_msi_bootstrap_acl")
        if ace[0][0] == win32security.ACCESS_ALLOWED_ACE_TYPE and win32security.ConvertSidToStringSid(ace[2]) not in allowed:
            raise ValueError("agent_msi_bootstrap_acl")


def trusted_ancestors(path, sid="S-1-5-18", *, leaf=False):
    """Reject a writable/replaceable ancestor before opening privileged files."""
    if os.name != "nt":
        return
    import win32security
    trusted = {"S-1-5-18", "S-1-5-32-544", sid,
               # Windows Modules Installer (TrustedInstaller), a well-known service SID.
               "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}
    for parent in ((path, *path.parents) if leaf else path.parents):
        descriptor = win32security.GetNamedSecurityInfo(str(parent), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
        if win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner()) not in trusted:
            raise ValueError("agent_msi_path_unsafe")
        acl = descriptor.GetSecurityDescriptorDacl()
        if acl is None:
            raise ValueError("agent_msi_path_unsafe")
        for index in range(acl.GetAceCount()):
            kind, flags = acl.GetAce(index)[0]
            if flags & 0x8 or kind == win32security.ACCESS_DENIED_ACE_TYPE:  # INHERIT_ONLY_ACE
                continue
            if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
                raise ValueError("agent_msi_path_unsafe")
            _, mask, principal = acl.GetAce(index)
            # DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL/WRITE.
            # Read access and creating new children alone cannot replace the path.
            unsafe_mask = 0x500D0040 | (0x116 if leaf and parent == path else 0)
            if mask & unsafe_mask and win32security.ConvertSidToStringSid(principal) not in trusted:
                raise ValueError("agent_msi_path_unsafe")


def check_private_file(path, sid="S-1-5-18"):
    if os.name == "nt" and (not path.is_absolute() or path.drive.startswith("\\\\")):
        raise ValueError("agent_msi_bootstrap_acl")
    no_reparse(path)
    trusted_ancestors(path, sid)
    if not path.is_file():
        raise ValueError("agent_msi_bootstrap_acl")
    if os.name == "nt":
        import win32security
        private_descriptor(win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION), sid)
        # A protected file inside a publicly writable bootstrap directory can
        # still be replaced using DELETE_CHILD. Require a protected parent too.
        private_descriptor(win32security.GetNamedSecurityInfo(str(path.parent), win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION), sid)
    elif path.stat().st_mode & 0o077:
        raise ValueError("agent_msi_bootstrap_acl")


def consume_file(path, sid, *, check=check_private_file, retain=False):
    """Validate the same Windows handle we read; optionally retain group state."""
    check(path, sid) if check is check_private_file else check(path)
    if os.name != "nt":
        with path.open("rb") as stream:
            value = stream.read(MAX_TOKEN + 1)
        if not retain:
            path.unlink()
        return value
    import win32con
    import win32file
    import win32security
    handle = win32file.CreateFile(str(path), win32con.GENERIC_READ | win32con.DELETE | win32con.READ_CONTROL,
        0, None, win32con.OPEN_EXISTING, win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
    try:
        info = win32file.GetFileInformationByHandle(handle)
        if info[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT or info[7] != 1:
            raise ValueError("agent_msi_bootstrap_acl")
        private_descriptor(win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION), sid)
        if not retain:
            win32file.SetFileInformationByHandle(handle, win32file.FileDispositionInfo, True)
        size = min(win32file.GetFileSize(handle), MAX_TOKEN + 1)
        return win32file.ReadFile(handle, size)[1] if size else b""
    finally:
        handle.Close()


def token_text(raw):
    if not 0 < len(raw) <= MAX_TOKEN:
        raise ValueError("agent_msi_bootstrap_invalid")
    token = raw.decode("utf-8-sig").strip()
    if not token or any(char.isspace() or ord(char) < 32 for char in token):
        raise ValueError("agent_msi_bootstrap_invalid")
    return token


def expired_bootstrap(path, *, now=None):
    stamp = path.stat().st_mtime
    age = (time.time() if now is None else now) - stamp
    return age > BOOTSTRAP_TTL or age < -60


def group_bootstrap(raw):
    """TOKEN_FILE may contain a scoped group request instead of a one-use token.

    This file contains no AD credentials. Its expiry is only a local stop limit;
    the server rechecks its own immutable batch expiry on every request/issue.
    """
    if not 0 < len(raw) <= MAX_TOKEN:
        raise ValueError("agent_msi_bootstrap_invalid")
    if not raw.removeprefix(b"\xef\xbb\xbf").lstrip().startswith(b"{"):
        return None
    try:
        body = json.loads(raw)
        if (not isinstance(body, dict) or set(body) != {"kind", "token", "computer_entity_id", "expires_at"}
                or body["kind"] != "group" or type(body["computer_entity_id"]) is not int
                or not 1 <= body["computer_entity_id"] <= 2**63 - 1
                or not isinstance(body["token"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", body["token"])
                or not isinstance(body["expires_at"], str)):
            raise ValueError()
        expiry = datetime.fromisoformat(body["expires_at"].replace("Z", "+00:00"))
        if expiry.tzinfo is None or expiry.utcoffset().total_seconds() != 0:
            raise ValueError()
        return body, expiry.timestamp()
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError("agent_msi_bootstrap_invalid") from None


def enroll_group_once(config, store, transport, *, check=check_private_file):
    source = config.state_dir.parent / "enrollment.group"
    try:
        raw = consume_file(source, config.service_identity_sid, check=check, retain=True)
        if len(raw) > MAX_TOKEN or (parsed := group_bootstrap(raw)) is None:
            return "bootstrap_rejected"
        body, expires = parsed
        if store.load() is not None:
            consume_file(source, config.service_identity_sid, check=check)
            return "enrolled"
        now = time.time()
        if expires <= now or expires > now + GROUP_TTL + 60:
            consume_file(source, config.service_identity_sid, check=check)
            return "bootstrap_expired"
        identity = store.enroll_group(body["token"], body["computer_entity_id"], transport)
        if identity is None:
            return "agent_approval_pending"
        consume_file(source, config.service_identity_sid, check=check)
        return "enrolled"
    except Exception:
        # Retain the protected file/key for a retry after an offline/restart.
        # A server denial never falls back to one-time or service enrollment.
        return "group_enrollment_failed"


def enroll_once(config, store, transport, *, check=check_private_file):
    if (config.state_dir.parent / "enrollment.group").exists():
        return enroll_group_once(config, store, transport, check=check)
    source = config.state_dir.parent / "enrollment.token"
    if not source.exists():
        return "enrolled" if store.load() is not None else "pending_enrollment"
    try:
        expired = expired_bootstrap(source)
        raw = consume_file(source, config.service_identity_sid, check=check)
    except Exception:
        return "bootstrap_rejected"
    try:
        if expired:
            return "bootstrap_expired"
        token = token_text(raw)
        if store.load() is None:
            store.enroll(token, transport)
        return "enrolled"
    except Exception:
        return "enrollment_failed"


def ensure_ca(config):
    """Fingerprint-only bootstrap uses TLS certificates, never unauthenticated HTTP."""
    if config.ca_bundle.exists():
        return
    if not config.ca_fingerprint:
        raise ValueError("agent_msi_ca_missing")
    import socket
    import ssl
    from urllib.parse import urlsplit
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from sli_agent.protection import atomic_write
    target = urlsplit(config.server_url)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((target.hostname, target.port or 443), timeout=15) as sock:
        with context.wrap_socket(sock, server_hostname=target.hostname) as tls:
            for raw in tls.get_unverified_chain():
                cert = x509.load_der_x509_certificate(raw)
                if cert.fingerprint(hashes.SHA256()).hex() == config.ca_fingerprint:
                    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                        raise ValueError("agent_msi_ca_invalid")
                    from cryptography.hazmat.primitives.serialization import Encoding
                    atomic_write(config.ca_bundle, cert.public_bytes(Encoding.PEM))
                    return
    raise ValueError("agent_msi_ca_invalid")


def owned_tree(root):
    no_reparse(root)
    if not root.exists():
        return False
    marker = root / ".msi-owned"
    no_reparse(marker)
    if not marker.is_file() or marker.read_text("ascii") != OWNER:
        raise ValueError("agent_msi_state_unmanaged")
    # The default MSI must never remove separately provisioned named instances.
    for instances in (root / "instances", root / "state/instances"):
        no_reparse(instances)
        if instances.exists() and any(instances.iterdir()):
            raise ValueError("agent_msi_state_unmanaged")
    # Preflight the entire tree; shutil on Windows must never follow a junction.
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            no_reparse(Path(parent) / name)
    return True


def restore_owned(source, root):
    """Move the protected upgrade state back before MSI starts the service.

    A same-volume rename retains every byte and ACL, including spool/receipts
    and locally owned audit rollback records. No enrollment or network access.
    """
    no_reparse(root)
    if (not source.is_absolute() or source.parent != root.parent
            or not re.fullmatch(r"Agent\.upgrade-[0-9a-f]{32}", source.name)
            or root.exists() or not owned_tree(source) or (source / ".msi-pending").exists()):
        raise ValueError("agent_msi_state_unmanaged")
    validate_owned(source, root=root)
    source.rename(root)


def validate_owned(source, *, root=None):
    """Validate retained MSI state without provisioning, enrollment or writes."""
    root = source if root is None else root
    if not owned_tree(source) or (source / ".msi-pending").exists():
        raise ValueError("agent_msi_state_unmanaged")
    config = AgentConfig.load(source / "agent.json")
    if (config.state_dir != root / "state" or config.instance_name is not None
            or config.service_identity_sid != "S-1-5-18" or config.update_root is not None):
        raise ValueError("agent_msi_state_unmanaged")
    trusted_ancestors(source, leaf=True)
    if os.name == "nt":
        import win32security
        for parent, dirs, files in os.walk(source):
            for path in (Path(parent), *(Path(parent) / name for name in files)):
                descriptor = win32security.GetNamedSecurityInfo(str(path), win32security.SE_FILE_OBJECT,
                    win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION)
                # Legacy provisioning markers inherit their safe parent DACL.
                private_descriptor(descriptor, "S-1-5-18", require_protected=False)


def report_zip_offer(config, offer, transport, identity):
    """Server waves currently distribute ZIP payloads, never MSI distributions.

    Report a visible rejection so the wave's existing failure threshold works;
    a managed agent must never replace Windows Installer-owned files with ZIPs.
    """
    marker = config.state_dir.parent / ".msi-owned"
    if (config.instance_name is not None or config.update_root is not None
            or not marker.is_file() or marker.read_text("ascii") != OWNER
            or not isinstance(offer, dict) or not isinstance(offer.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", offer["sha256"]) is None):
        return False
    from sli_agent import __version__
    try:
        transport.post("/api/v1/agent/update-result", {"sha256": offer["sha256"],
            "status": "rejected", "reason": "agent_update_msi_required", "version": __version__}, identity=identity)
    except (OSError, ValueError):
        return False  # The next authenticated check-in can retry the report.
    return True


def remove_owned(root, *, rollback=False):
    no_reparse(root)
    if rollback and not (root / ".msi-pending").exists():
        return
    if not owned_tree(root):
        return
    # Keep the ownership marker until every other entry is gone so an
    # interrupted cleanup remains recognizable on the next MSI attempt.
    for child in root.iterdir():
        if child.name == ".msi-owned":
            continue
        no_reparse(child)
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()
    (root / ".msi-owned").unlink()
    root.rmdir()


def _service_account_present(sid):
    if sid is None:
        return False
    if os.name != "nt" or sid == "S-1-5-18":
        return True
    import pywintypes
    import win32security
    from winerror import ERROR_NONE_MAPPED

    try:
        win32security.LookupAccountSid(None, win32security.ConvertStringSidToSid(sid))
        return True
    except pywintypes.error as exc:
        if exc.winerror != ERROR_NONE_MAPPED:
            raise
        return False


def uninstall_owned(root, *, service_present=True):
    """Best-effort revocation online; offline cleanup never claims server success.

    MSI has already stopped/deleted its service. Keep TLS trust/identity only in
    memory for the final state-cleaned report; never recreate files after cleanup.
    """
    from sli_agent.enrollment import IdentityStore
    from sli_agent.transport import Transport
    from sli_agent.removal import validate_command
    if not owned_tree(root):
        return
    # agent.json can already be gone after a partial cleanup. The retained
    # ownership marker and complete path preflight still authorize this tree.
    config = AgentConfig.load(root / "agent.json") if (root / "agent.json").exists() else None
    if config is not None and (config.instance_name is not None or config.state_dir != root / "state"):
        raise ValueError("agent_msi_state_unmanaged")
    identity, transport, command_id = None, None, None
    try:
        if service_present and config is not None and _service_account_present(config.service_identity_sid):
            identity = IdentityStore(config).load()
        if identity is not None:
            transport = Transport(config)
            context = transport._context(identity)
            transport._context = lambda _: context
            command_id = validate_command(transport.post("/api/v1/agent/uninstall", {}, identity=identity), identity.agent_id)
    except (OSError, ValueError):
        pass
    # Restore only policy changes still owned by this agent, before erasing
    # their rollback state. A conflict/failure preserves state for a safe retry.
    try:
        file_audit_path = root / "state/file-audit/state.json"
        if file_audit_path.exists():
            from sli_agent.file_audit import FileAuditManager
            from sli_agent.windows_audit import AuditManager
            file_state = FileAuditManager(file_audit_path.parent, AuditManager(root / "state/windows-audit"))._load()
            if file_state["objects"] or file_state["masks"]:
                raise ValueError("agent_removal_cleanup_failed")
        audit_root = root / "state/windows-audit"
        if (audit_root / "state.json").exists():
            from sli_agent.windows_audit import AuditManager
            audit = AuditManager(audit_root)
            state = audit._read()
            if state["subcategories"] or state["command_line"] is not None:
                result = audit.reconcile([], {"manage_windows_audit": False, "audit_process_command_line": False}, 1)
                if result["management_state"] not in ("restored", "disabled"):
                    raise ValueError("agent_removal_cleanup_failed")
        remove_owned(root)
    except (OSError, ValueError):
        if command_id is not None:
            try:
                transport.post("/api/v1/agent/removal-result", {"command_id": command_id,
                               "state": "cleanup_failed", "reason": "agent_removal_cleanup_failed"}, identity=identity)
            except (OSError, ValueError):
                pass
        raise
    if command_id is not None:
        try:
            transport.post("/api/v1/agent/removal-result", {"command_id": command_id,
                           "state": "state_cleaned", "reason": None}, identity=identity)
        except (OSError, ValueError):
            pass  # Server retains the visible pending remainder.


def provision(url, ca_file, fingerprint, token_file, account, *, root=None):
    if os.name != "nt":
        raise ValueError("agent_windows_required")
    import win32security
    sid = "S-1-5-18" if account == "LocalSystem" else win32security.ConvertSidToStringSid(
        win32security.LookupAccountName(None, account)[0])
    root = root or machine_config_path().parent
    no_reparse(root)
    body = configuration(url, root, sid, fingerprint or None)
    if root.exists():
        raise ValueError("agent_msi_state_unmanaged")
    if not ca_file and not fingerprint:
        raise ValueError("agent_msi_ca_missing")
    ca_bytes = None
    if ca_file:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        source_ca = Path(ca_file)
        if not source_ca.is_absolute() or source_ca.drive.startswith("\\\\"):
            raise ValueError("agent_msi_ca_invalid")
        no_reparse(source_ca)
        trusted_ancestors(source_ca, leaf=True)
        with Path(ca_file).open("rb") as stream:
            ca_bytes = stream.read(1024 * 1024 + 1)
        if len(ca_bytes) > 1024 * 1024:
            raise ValueError("agent_msi_ca_invalid")
        certs = x509.load_pem_x509_certificates(ca_bytes)
        if not certs or any(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for cert in certs):
            raise ValueError("agent_msi_ca_invalid")
        if fingerprint and not any(cert.fingerprint(hashes.SHA256()).hex() == fingerprint for cert in certs):
            raise ValueError("agent_msi_ca_invalid")
    # Create with a protected descriptor atomically, before writing anything.
    import win32file
    import pywintypes
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        acl_sddl(sid), win32security.SDDL_REVISION_1)
    root.parent.mkdir(parents=True, exist_ok=True)
    no_reparse(root)
    trusted_ancestors(root, sid)
    win32file.CreateDirectory(str(root), attributes)
    (root / ".msi-owned").write_text(OWNER, encoding="ascii")
    (root / ".msi-pending").touch()
    for path in (root / "state",):
        win32file.CreateDirectory(str(path), attributes)
    (root / "agent.json").write_text(json.dumps(body), encoding="utf-8")
    set_acl(root / "agent.json", sid)
    if ca_bytes is not None:
        (root / "server-ca.pem").write_bytes(ca_bytes)
        set_acl(root / "server-ca.pem", sid)
    if token_file:
        source = Path(token_file)
        expired = expired_bootstrap(source)
        raw = consume_file(source, "S-1-5-18")
        group = group_bootstrap(raw)
        if group is not None:
            now = time.time()
            if not now < group[1] <= now + GROUP_TTL + 60:
                raise ValueError("agent_msi_bootstrap_invalid")
            destination = root / "enrollment.group"
        else:
            if expired:
                raise ValueError("agent_msi_bootstrap_invalid")
            token_text(raw)
            destination = root / "enrollment.token"
        destination.write_bytes(raw)
        set_acl(destination, sid)


def run_managed(config, stop):
    from sli_agent.enrollment import IdentityStore
    from sli_agent.protection import atomic_write
    from sli_agent.probe import service_identity_verified
    from sli_agent.transport import Transport
    from sli_agent.runtime import run
    if not service_identity_verified(config):
        raise ValueError("agent_service_identity_unverified")
    store = IdentityStore(config)
    store.prepare()
    while not stop.is_set():
        try:
            source = config.state_dir.parent / "enrollment.token"
            if source.exists() and expired_bootstrap(source):
                consume_file(source, config.service_identity_sid)
                status = "bootstrap_expired"
            else:
                ensure_ca(config)
                status = enroll_once(config, store, Transport(config))
        except Exception:
            status = "bootstrap_trust_failed"
        if status == "enrolled":
            return run(config, stop)
        atomic_write(config.storage_dir / "status.json", json.dumps(
            {"collection_enabled": False, "error_code": status}).encode())
        stop.wait(30)


def main():
    import sys
    # Arguments contain public values and paths encoded by the native MSI action.
    # No token is ever an MSI property, CustomActionData value or process argument.
    try:
        operation, *fields = sys.argv[1:]
        root = machine_config_path().parent
        if operation == "configure":
            provision(*(decode_property(value) for value in fields))
        elif operation == "restore" and len(fields) == 1:
            restore_owned(Path(decode_property(fields[0])), root)
        elif operation == "preserve" and not fields:
            validate_owned(root)
        elif operation == "remove" and (not fields or fields == ["no-service"]):
            uninstall_owned(root, service_present=not fields)
        elif operation == "rollback":
            remove_owned(root, rollback=True)
        elif operation == "commit":
            (root / ".msi-pending").unlink(missing_ok=True)
        else:
            raise ValueError("agent_msi_operation_invalid")
        return 0
    except Exception as exc:
        # Native MSI action maps this to a fixed human-readable error.
        return {"agent_config_invalid": 2, "agent_msi_ca_missing": 3,
                "agent_msi_ca_invalid": 3, "agent_msi_bootstrap_acl": 4,
                "agent_msi_bootstrap_invalid": 4, "agent_msi_state_unmanaged": 5,
                "agent_msi_path_unsafe": 5}.get(str(exc), 1)


if __name__ == "__main__":
    raise SystemExit(main())
