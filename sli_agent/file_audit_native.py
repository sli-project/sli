# SPDX-License-Identifier: Apache-2.0
"""Local Windows adapters. No services, DACL, SMB permissions or file contents are changed."""
from __future__ import annotations

import ctypes
import ntpath
import os
from contextlib import ExitStack, contextmanager

from sli_agent.file_audit_policy import local_path, path_in_root
from sli_agent.windows_audit_native import WindowsAuditAPI, security_privilege

SECURITY_CSE = "{827d319e-6eac-11d2-a4ea-00c04f79f83a}"


class LocalFileAuditAPI:
    def __init__(self):
        self.audit_api = WindowsAuditAPI()

    def preflight(self, roots=()):
        import pythoncom
        import win32com.client
        import win32evtlog
        audit = self.audit_api
        if not audit.is_system():
            return "system_required"
        owner = audit.ownership()
        # Audit-policy ownership is independent from per-object SACL ownership.
        # The shared AuditManager still refuses every auditpol write under GPO.
        if owner not in ("ok", "managed_by_gpo"):
            return owner
        with security_privilege():
            channel = win32evtlog.EvtQuery("Security", win32evtlog.EvtQueryChannelPath, "*")
            channel.Close()
            # Global object SACL is independent of per-object SACL. Fail closed
            # when it exists or the OS cannot prove its absence.
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            query = advapi.AuditQueryGlobalSaclW
            query.argtypes = (ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p))
            query.restype = ctypes.c_ubyte
            free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
            free.argtypes, free.restype = (ctypes.c_void_p,), ctypes.c_void_p
            acl = ctypes.c_void_p()
            if not query("File", ctypes.byref(acl)):
                return "global_sacl_unknown"
            try:
                if acl.value:
                    class ACL(ctypes.Structure):
                        _fields_ = [("revision", ctypes.c_ubyte), ("padding", ctypes.c_ubyte),
                                    ("size", ctypes.c_ushort), ("count", ctypes.c_ushort), ("reserved", ctypes.c_ushort)]
                    if ctypes.cast(acl, ctypes.POINTER(ACL)).contents.count:
                        return "global_sacl_present"
            finally:
                if acl.value:
                    free(acl)
        pythoncom.CoInitialize()
        try:
            rsop = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\RSOP\Computer")
            # Security CSE alone also covers password/service policy. Read the
            # effective file-security settings and compare their actual scope.
            for row in rsop.ExecQuery("SELECT * FROM RSOP_File"):
                path = local_path(os.path.expandvars(str(row.Path)))
                if not roots or any(path_in_root(root["path"], path) or path_in_root(path, root["path"]) for root in roots):
                    return "managed_by_gpo"
            return "ok"
        except Exception:  # noqa: BLE001 - absent ownership evidence blocks writes
            return "unknown"
        finally:
            pythoncom.CoUninitialize()

    @contextmanager
    def open(self, path, root):
        import ntsecuritycon
        import win32con
        import win32file
        path, root = local_path(path), local_path(root)
        if not path_in_root(path, root):
            raise ValueError("file_audit_scope_escape")
        # Pin every ancestor without FILE_SHARE_DELETE. No path component may
        # be replaced/renamed while a SACL is inspected or written by handle.
        drive, tail = ntpath.splitdrive(path)
        components = [drive + "\\"]
        for component in tail.strip("\\").split("\\"):
            if component:
                components.append(ntpath.join(components[-1], component))
        with ExitStack() as stack, security_privilege():
            handle = None
            for component in components:
                # Ancestors only need attribute reads. MAXIMUM_ALLOWED may
                # request DELETE on the volume root and conflict with existing
                # Windows handles. Keep the target's SACL/propagation contract.
                access = (win32con.MAXIMUM_ALLOWED | win32con.ACCESS_SYSTEM_SECURITY
                          if component == path else ntsecuritycon.FILE_READ_ATTRIBUTES)
                handle = win32file.CreateFile(component,
                    access,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE, None,
                    win32con.OPEN_EXISTING, win32con.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
                stack.callback(handle.Close)
                info = win32file.GetFileInformationByHandle(handle)
                if info[0] & win32con.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("file_audit_reparse_point")
            yield LocalObject(handle, path)

    def share(self, name, root):
        import win32net
        import win32security
        info = win32net.NetShareGetInfo(None, name, 502)
        if ntpath.normcase(local_path(info["path"])) != ntpath.normcase(root):
            raise ValueError("file_audit_share_root_mismatch")
        sd = info["security_descriptor"]
        acl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, win32security.DACL_SECURITY_INFORMATION)
        return {"name": name, "path": root, "dacl": acl, "complete": True}

    def local_groups(self, limit):
        import win32net
        import win32security
        rows, total, resume = win32net.NetLocalGroupEnum(None, 0, 0, 4096)
        result, complete, count = [], resume == 0, 0
        for row in rows:
            if count >= min(limit, 100):
                complete = False
                break
            name = row["name"]
            group_sid = win32security.ConvertSidToStringSid(win32security.LookupAccountName(None, name)[0])
            members, _, next_page = win32net.NetLocalGroupGetMembers(None, name, 0, 0, 4096)
            sids = []
            for member in members:
                if count >= min(limit, 100):
                    complete = False
                    break
                sids.append(win32security.ConvertSidToStringSid(member["sid"]))
                count += 1
            count += 1
            result.append({"group_sid": group_sid, "member_sids": sids})
            complete = complete and next_page == 0
        return {"complete": complete, "groups": result}


class LocalObject:
    def __init__(self, handle, path):
        self.handle, self.path = handle, path

    def _descriptor(self):
        import win32security as security
        return security.GetSecurityInfo(self.handle, security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION | security.SACL_SECURITY_INFORMATION)

    def describe(self):
        import win32con
        import win32file
        import win32security as security
        sd, info = self._descriptor(), win32file.GetFileInformationByHandle(self.handle)
        control, _ = sd.GetSecurityDescriptorControl()
        return {"object_id": f"{info[4]}:{info[8]}:{info[9]}",
                "object_type": "directory" if info[0] & win32con.FILE_ATTRIBUTE_DIRECTORY else "file",
                "owner_sid": security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner()),
                "dacl": security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.DACL_SECURITY_INFORMATION),
                "sacl": security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.SACL_SECURITY_INFORMATION),
                "sacl_protected": bool(control & security.SE_SACL_PROTECTED)}

    def plan(self, aces):
        import win32security as security
        sd = self._descriptor()
        acl = sd.GetSecurityDescriptorSacl() or security.ACL()
        current = [acl.GetAce(index) for index in range(acl.GetAceCount())]
        directory = self.describe()["object_type"] == "directory"
        for ace in aces:
            sid = security.ConvertStringSidToSid(ace["sid"])
            flags = ace["flags"] if directory else ace["flags"] & ~3
            # A combined Success/Failure or broader audit ACE already covers
            # the request. Do not claim ownership by adding redundant ACE.
            if any(row[0][0] == 2 and not row[0][1] & 0x0c
                   and row[0][1] & flags == flags and row[1] & ace["mask"] == ace["mask"]
                   and row[2] == sid for row in current):
                continue
            acl.AddAuditAccessAceEx(security.ACL_REVISION_DS, flags & 0x3f,
                ace["mask"], sid, int(bool(flags & 0x40)), int(bool(flags & 0x80)))
        sd.SetSecurityDescriptorSacl(True, acl, False)
        return self.expected_sacl(security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            sd, 1, security.SACL_SECURITY_INFORMATION))

    def expected_sacl(self, value):
        """Compute per-object inheritance while open() pins every ancestor."""
        import ntsecuritycon
        import win32security as security
        parent = security.GetNamedSecurityInfo(ntpath.dirname(self.path), security.SE_FILE_OBJECT,
            security.SACL_SECURITY_INFORMATION)
        current = security.GetSecurityInfo(self.handle, security.SE_FILE_OBJECT,
            security.OWNER_SECURITY_INFORMATION | security.GROUP_SECURITY_INFORMATION
            | security.DACL_SECURITY_INFORMATION | security.SACL_SECURITY_INFORMATION)
        proposed = security.ConvertStringSecurityDescriptorToSecurityDescriptor(value, 1)
        if bool(current.GetSecurityDescriptorControl()[0] & security.SE_SACL_PROTECTED) != bool(
                proposed.GetSecurityDescriptorControl()[0] & security.SE_SACL_PROTECTED):
            raise RuntimeError("file_audit_sacl_plan_failed")
        current.SetSecurityDescriptorSacl(True, proposed.GetSecurityDescriptorSacl(), False)
        class Mapping(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in ("read", "write", "execute", "all")]
        mapping = Mapping(ntsecuritycon.FILE_GENERIC_READ, ntsecuritycon.FILE_GENERIC_WRITE,
                          ntsecuritycon.FILE_GENERIC_EXECUTE, ntsecuritycon.FILE_ALL_ACCESS)
        dll = ctypes.WinDLL("advapi32", use_last_error=True)
        create = dll.CreatePrivateObjectSecurityEx
        create.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(Mapping))
        create.restype = ctypes.c_int
        parent_buffer = ctypes.create_string_buffer(bytes(memoryview(parent)))
        current_buffer = ctypes.create_string_buffer(bytes(memoryview(current)))
        result = ctypes.c_void_p()
        # Construct an in-memory descriptor; these flags never authorize writes.
        if not create(parent_buffer, current_buffer, ctypes.byref(result), None,
                      self.describe()["object_type"] == "directory", 2 | 8 | 16, None, ctypes.byref(mapping)):
            raise RuntimeError("file_audit_sacl_plan_failed")
        try:
            length = dll.GetSecurityDescriptorLength
            length.argtypes, length.restype = (ctypes.c_void_p,), ctypes.c_uint32
            size = length(result)
            if not 20 <= size <= 1024 * 1024:
                raise RuntimeError("file_audit_sacl_plan_failed")
            sd = security.SECURITY_DESCRIPTOR(ctypes.string_at(result, size))
            return security.ConvertSecurityDescriptorToStringSecurityDescriptor(sd, 1, security.SACL_SECURITY_INFORMATION)
        finally:
            destroy = dll.DestroyPrivateObjectSecurity
            destroy.argtypes, destroy.restype = (ctypes.POINTER(ctypes.c_void_p),), ctypes.c_int
            destroy(ctypes.byref(result))

    def set_sacl(self, value):
        import win32security as security
        if value:
            sd = security.ConvertStringSecurityDescriptorToSecurityDescriptor(value, 1)
        else:
            sd = security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorSacl(False, None, False)
        # SetSecurityInfo does not propagate ACE when the handle was opened
        # with MAXIMUM_ALLOWED. Visit existing descendants within our budget.
        security.SetSecurityInfo(self.handle, security.SE_FILE_OBJECT,
            security.SACL_SECURITY_INFORMATION, None, None, None, sd.GetSecurityDescriptorSacl())

    def inherited_from(self, previous, applied):
        from collections import Counter
        import win32security as security
        def aces(value):
            if not value:
                return []
            acl = security.ConvertStringSecurityDescriptorToSecurityDescriptor(value, 1).GetSecurityDescriptorSacl()
            return [acl.GetAce(index) for index in range(acl.GetAceCount())] if acl else []
        def key(ace):
            return (ace[0], ace[1], security.ConvertSidToStringSid(ace[2])) if ace[0][0] == 2 else repr(ace)
        added = Counter(key(ace) for ace in aces(applied)) - Counter(key(ace) for ace in aces(previous))
        current = self._descriptor().GetSecurityDescriptorSacl()
        for index in range(current.GetAceCount() if current else 0):
            ace = current.GetAce(index)
            if ace[0][0] != 2 or not ace[0][1] & 0x10:
                continue
            for item in added:
                if (isinstance(item, tuple) and item[0][1] & 3 and ace[0][1] & 0xc0 == item[0][1] & 0xc0
                        and ace[1] == item[1] and security.ConvertSidToStringSid(ace[2]) == item[2]):
                    return True
        return False

    def children(self):
        with os.scandir(self.path) as entries:
            for entry in entries:
                yield entry.name
