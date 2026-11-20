# SPDX-License-Identifier: Apache-2.0
"""Lazy native adapter. No Windows imports or calls during Linux unit tests."""
from __future__ import annotations

import ctypes
from contextlib import contextmanager
from uuid import UUID

from sli_agent.windows_audit import gpo_override

AUDIT_CSE = "{f3ccc681-b74c-4060-9f26-cd84525dca2a}"
COMMAND_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
COMMAND_VALUE = "ProcessCreationIncludeCmdLine_Enabled"


class GUID(ctypes.Structure):
    _fields_ = [("data1", ctypes.c_uint32), ("data2", ctypes.c_uint16),
                ("data3", ctypes.c_uint16), ("data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, value):
        return cls.from_buffer_copy(UUID(value).bytes_le)


class AuditPolicyInformation(ctypes.Structure):
    _fields_ = [("subcategory", GUID), ("mask", ctypes.c_uint32), ("category", GUID)]


@contextmanager
def security_privilege():
    import win32api
    import win32con
    import win32security
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
        win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES)
    previous = None
    try:
        luid = win32security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
        previous = win32security.AdjustTokenPrivileges(token, False, [(luid, win32con.SE_PRIVILEGE_ENABLED)])
        if win32api.GetLastError() != 0:
            raise OSError("agent_audit_privilege_unavailable")
        yield
    finally:
        if previous is not None:
            win32security.AdjustTokenPrivileges(token, False, previous)
        token.Close()


def read_dword(key, name):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            value, kind = winreg.QueryValueEx(handle, name)
        if kind != winreg.REG_DWORD:
            raise ValueError("agent_audit_registry_invalid")
        return value
    except FileNotFoundError:
        return None


def domain_audit_history():
    """Applied audit CSE history only, without resolving private SYSVOL paths."""
    import winreg
    root = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\" + AUDIT_CSE
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as handle:
            count = winreg.QueryInfoKey(handle)[0]
            if count > 1024:
                raise ValueError("agent_audit_gpo_limit")
            for index in range(count):
                with winreg.OpenKey(handle, winreg.EnumKey(handle, index)) as item:
                    try:
                        path, _ = winreg.QueryValueEx(item, "FileSysPath")
                    except FileNotFoundError:
                        continue
                    if isinstance(path, str) and path.startswith("\\\\"):
                        return True
    except FileNotFoundError:
        pass
    return False


def ownership():
    force = read_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy")
    if domain_audit_history():
        return "managed_by_gpo"
    # Advanced audit is not fully represented in RSoP. Use applied CSE history
    # above and RSoP extension IDs as corroboration, never localized gpresult.
    import pythoncom
    import win32com.client
    import win32net
    domain_joined = win32net.NetGetJoinInformation(None)[1] == 3
    pythoncom.CoInitialize()
    try:
        try:
            rsop = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\RSOP\Computer")
            domain_policy = any(row.enabled and not row.accessDenied and row.filterAllowed
                and str(row.fileSystemPath).startswith("\\\\")
                and AUDIT_CSE in str(row.extensionIds).lower()
                for row in rsop.ExecQuery("SELECT * FROM RSOP_GPO"))
            legacy = force != 1 and bool(list(rsop.ExecQuery("SELECT * FROM RSOP_AuditPolicy")))
            return gpo_override(force_subcategories=force, domain_audit_policy=domain_policy, legacy_policy=legacy)
        except Exception:  # noqa: BLE001 - no private COM exception diagnostics
            # A workgroup with forced advanced audit has no domain or basic
            # override. On domain hosts, missing evidence must fail closed.
            return gpo_override(force_subcategories=force, evidence_known=not domain_joined and force == 1)
    finally:
        pythoncom.CoUninitialize()


class WindowsAuditAPI:
    def __init__(self):
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.advapi.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(GUID), ctypes.c_uint32,
                                                     ctypes.POINTER(ctypes.POINTER(AuditPolicyInformation))]
        self.advapi.AuditQuerySystemPolicy.restype = ctypes.c_int
        self.advapi.AuditSetSystemPolicy.argtypes = [ctypes.POINTER(AuditPolicyInformation), ctypes.c_uint32]
        self.advapi.AuditSetSystemPolicy.restype = ctypes.c_int
        self.advapi.AuditFree.argtypes = [ctypes.c_void_p]
        self.advapi.AuditFree.restype = None

    def query(self, guids):
        if not guids:
            return {}
        ordered = sorted(guids)
        values = (GUID * len(ordered))(*(GUID.parse(value) for value in ordered))
        result = ctypes.POINTER(AuditPolicyInformation)()
        with security_privilege():
            if not self.advapi.AuditQuerySystemPolicy(values, len(values), ctypes.byref(result)):
                raise OSError("agent_audit_query_failed")
            try:
                policies = {}
                for index in range(len(values)):
                    item = result[index]
                    guid = str(UUID(bytes_le=bytes(item.subcategory)))
                    if item.mask not in (0, 1, 2, 3, 4) or guid not in ordered or guid in policies:
                        raise ValueError("agent_audit_query_invalid")
                    policies[guid] = item.mask & 3
                if set(policies) != set(ordered):
                    raise ValueError("agent_audit_query_invalid")
                return policies
            finally:
                self.advapi.AuditFree(result)

    def is_system(self):
        import win32api
        import win32con
        import win32security
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            return win32security.ConvertSidToStringSid(sid) == "S-1-5-18"
        finally:
            token.Close()

    def set(self, changes):
        if not self.is_system():
            raise OSError("agent_audit_system_required")
        values = (AuditPolicyInformation * len(changes))(*(AuditPolicyInformation(
            GUID.parse(guid), mask or 4, GUID()) for guid, mask in sorted(changes.items())))
        with security_privilege():
            if not self.advapi.AuditSetSystemPolicy(values, len(values)):
                raise OSError("agent_audit_set_failed")

    ownership = staticmethod(ownership)

    def powershell_logging(self):
        """Read only: AG-AUDIT never enables channels or Script Block Logging."""
        import win32evtlog

        config = win32evtlog.EvtOpenChannelConfig("Microsoft-Windows-PowerShell/Operational", 0)
        try:
            enabled = bool(win32evtlog.EvtGetChannelConfigProperty(config, win32evtlog.EvtChannelConfigEnabled))
        finally:
            config.Close()
        flag = read_dword(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging")
        if flag not in (None, 0, 1):
            raise ValueError("agent_audit_registry_invalid")
        return {"channel_enabled": enabled, "script_block_logging_enabled": flag == 1}

    def command_line(self):
        value = read_dword(COMMAND_KEY, COMMAND_VALUE)
        if value not in (None, 0, 1):
            raise ValueError("agent_audit_registry_invalid")
        return value

    def command_line_ownership(self):
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            rsop = win32com.client.GetObject(r"winmgmts:{impersonationLevel=impersonate}!\\.\root\RSOP\Computer")
            rows = rsop.ExecQuery("SELECT * FROM RSOP_RegistryPolicySetting WHERE valueName='ProcessCreationIncludeCmdLine_Enabled'")
            for row in rows:
                if str(row.keyName).lower().endswith(COMMAND_KEY.lower()):
                    return "managed_by_gpo"
            return "ok"
        except Exception:  # noqa: BLE001
            return "unknown"
        finally:
            pythoncom.CoUninitialize()

    def set_command_line(self, value):
        import winreg
        if not self.is_system():
            raise OSError("agent_audit_system_required")
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, COMMAND_KEY, 0,
                               winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as handle:
            if value is None:
                try:
                    winreg.DeleteValue(handle, COMMAND_VALUE)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(handle, COMMAND_VALUE, 0, winreg.REG_DWORD, value)
