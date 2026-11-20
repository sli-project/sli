"""Native API contracts with fake DLLs/pywin32; never touch a Windows object."""
import ctypes
import sys
from contextlib import nullcontext
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from sli_agent import file_audit_native as native


def preflight_api(monkeypatch, *, owner="ok", system=True, global_aces=0, gpos=(), files=(), rsop_failure=False):
    api = native.LocalFileAuditAPI.__new__(native.LocalFileAuditAPI)
    api.audit_api = SimpleNamespace(ownership=lambda: owner, is_system=lambda: system)
    memory = (ctypes.c_ubyte * 8)(2, 0, 8, 0, global_aces, 0, 0, 0)
    def query(kind, out):
        assert kind == "File"
        ctypes.cast(out, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(ctypes.addressof(memory))
        return True
    free = Mock()
    advapi = SimpleNamespace(AuditQueryGlobalSaclW=Mock(side_effect=query))
    monkeypatch.setattr(ctypes, "WinDLL", lambda name, **kw: advapi if name == "advapi32" else SimpleNamespace(LocalFree=free), raising=False)
    monkeypatch.setattr(native, "security_privilege", nullcontext)
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(CoInitialize=Mock(), CoUninitialize=Mock()))
    package, client = ModuleType("win32com"), ModuleType("win32com.client")
    rsop = SimpleNamespace(ExecQuery=Mock(side_effect=lambda sql: list(gpos) if "RSOP_GPO" in sql else list(files)))
    client.GetObject = Mock(return_value=rsop, side_effect=OSError("synthetic-private") if rsop_failure else None)
    package.client = client
    monkeypatch.setitem(sys.modules, "win32com", package)
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    channel = SimpleNamespace(Close=Mock())
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(EvtQuery=Mock(return_value=channel), EvtQueryChannelPath=1))
    return api, free, channel


@pytest.mark.parametrize("global_aces,expected", [(0, "ok"), (1, "global_sacl_present")])
def test_global_sacl_uses_localfree_and_never_changes_policy(monkeypatch, global_aces, expected):
    api, free, channel = preflight_api(monkeypatch, global_aces=global_aces)
    assert api.preflight() == expected
    free.assert_called_once()
    channel.Close.assert_called_once()


@pytest.mark.parametrize("owner,system,expected", [("unknown", True, "unknown"), ("ok", False, "system_required")])
def test_native_management_requires_system_and_proven_policy_ownership(monkeypatch, owner, system, expected):
    api, free, channel = preflight_api(monkeypatch, owner=owner, system=system)
    assert api.preflight() == expected
    free.assert_not_called()
    channel.Close.assert_not_called()


def test_gpo_audit_policy_does_not_replace_file_security_ownership_checks(monkeypatch):
    api, free, channel = preflight_api(monkeypatch, owner='managed_by_gpo')
    assert api.preflight([{'path': r'C:\synthetic'}]) == 'ok'
    free.assert_called_once()
    channel.Close.assert_called_once()
    api, _, _ = preflight_api(monkeypatch, owner='managed_by_gpo', files=[SimpleNamespace(Path=r'C:\synthetic')])
    assert api.preflight([{'path': r'C:\synthetic\child'}]) == 'managed_by_gpo'


def test_rsop_file_security_ownership_is_scoped_and_not_inferred_from_security_cse(monkeypatch):
    gpo = SimpleNamespace(enabled=True, accessDenied=False, filterAllowed=True,
                          fileSystemPath=r"\\synthetic.invalid\SYSVOL", extensionIds=[native.SECURITY_CSE.upper()])
    api, _, _ = preflight_api(monkeypatch, gpos=[gpo])
    assert api.preflight([{"path": r"C:\synthetic"}]) == "ok"
    api, _, _ = preflight_api(monkeypatch, files=[SimpleNamespace(Path=r"C:\synthetic")])
    assert api.preflight([{"path": r"C:\synthetic\child"}]) == "managed_by_gpo"
    assert api.preflight([{"path": r"C:\outside"}]) == "ok"
    api, _, _ = preflight_api(monkeypatch, rsop_failure=True)
    assert api.preflight() == "unknown"


def guarded_api(monkeypatch, reparse=None):
    constants = SimpleNamespace(MAXIMUM_ALLOWED=0x2000000, ACCESS_SYSTEM_SECURITY=0x1000000,
        FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, OPEN_EXISTING=3,
        FILE_FLAG_BACKUP_SEMANTICS=0x2000000,
        FILE_ATTRIBUTE_REPARSE_POINT=0x400)
    handles, calls = [], []
    def create(path, access, sharing, *args):
        calls.append((path, access, sharing))
        handle = SimpleNamespace(path=path, Close=Mock())
        handles.append(handle)
        return handle
    file_api = SimpleNamespace(FILE_FLAG_OPEN_REPARSE_POINT=0x200000, CreateFile=create, GetFileInformationByHandle=lambda handle:
        (0x400 if handle.path == reparse else 0x10,))
    monkeypatch.setitem(sys.modules, "win32con", constants)
    monkeypatch.setitem(sys.modules, "ntsecuritycon", SimpleNamespace(FILE_READ_ATTRIBUTES=128))
    monkeypatch.setitem(sys.modules, "win32file", file_api)
    monkeypatch.setattr(native, "security_privilege", nullcontext)
    return native.LocalFileAuditAPI.__new__(native.LocalFileAuditAPI), calls, handles


def test_handle_guard_pins_ancestors_and_disables_recursive_acl_propagation(monkeypatch):
    api, calls, handles = guarded_api(monkeypatch)
    with api.open(r"C:\synthetic\item", r"C:\synthetic") as obj:
        assert obj.handle is handles[-1]
        assert all(not handle.Close.called for handle in handles)
    assert [path for path, _, _ in calls] == ["C:\\", r"C:\synthetic", r"C:\synthetic\item"]
    assert [access for _, access, _ in calls] == [128, 128, 0x3000000]
    assert all(sharing == 3 for _, _, sharing in calls)
    assert all(handle.Close.call_count == 1 for handle in handles)


def test_reparse_ancestor_closes_handles_before_any_sacl_operation(monkeypatch):
    api, calls, handles = guarded_api(monkeypatch, reparse=r"C:\synthetic")
    with pytest.raises(ValueError, match="file_audit_reparse_point"), api.open(r"C:\synthetic\item", r"C:\synthetic"):
        pytest.fail("reparse point opened")
    assert len(calls) == 2 and all(handle.Close.call_count == 1 for handle in handles)
    with pytest.raises(ValueError, match="file_audit_scope_escape"), api.open(r"C:\outside", r"C:\synthetic"):
        pytest.fail("outside scope opened")
    assert len(calls) == 2


def test_sacl_write_uses_only_sacl_information_by_handle(monkeypatch):
    sd = SimpleNamespace(GetSecurityDescriptorSacl=lambda: "synthetic-acl")
    setter = Mock()
    security = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptor=lambda value, version: sd,
        SACL_SECURITY_INFORMATION=8, SE_FILE_OBJECT=1, SetSecurityInfo=setter)
    monkeypatch.setitem(sys.modules, "win32security", security)
    handle = object()
    native.LocalObject(handle, r"C:\synthetic").set_sacl("S:(AU;SA;0x2;;;WD)")
    setter.assert_called_once_with(handle, 1, 8, None, None, None, "synthetic-acl")


@pytest.mark.parametrize("flags,mask,sid,adds", [
    (0xc3, 0x7, "S-1-1-0", 0),  # combined outcomes and broader rights
    (0xd3, 0x7, "S-1-1-0", 0),  # inherited covering ACE
    (0x83, 0x7, "S-1-1-0", 1),  # missing success
    (0xc3, 0x1, "S-1-1-0", 1),  # missing write
    (0xcb, 0x7, "S-1-1-0", 1),  # inherit-only does not cover this object
    (0xc7, 0x7, "S-1-1-0", 1),  # no-propagate does not cover descendants
    (0xc3, 0x7, "S-1-5-18", 1),
])
def test_sacl_plan_preserves_covering_foreign_aces_without_claiming_them(monkeypatch, flags, mask, sid, adds):
    acl = SimpleNamespace(GetAceCount=lambda: 1, GetAce=lambda _: ((2, flags), mask, sid),
                          AddAuditAccessAceEx=Mock())
    sd = SimpleNamespace(GetSecurityDescriptorSacl=lambda: acl, SetSecurityDescriptorSacl=Mock())
    security = SimpleNamespace(ConvertStringSidToSid=lambda value: value, ACL=Mock(), ACL_REVISION_DS=4,
        SACL_SECURITY_INFORMATION=8, ConvertSecurityDescriptorToStringSecurityDescriptor=lambda *_: "unchanged")
    monkeypatch.setitem(sys.modules, "win32security", security)
    obj = native.LocalObject(object(), r"C:\synthetic")
    obj._descriptor = lambda: sd
    obj.describe = lambda: {"object_type": "directory"}
    obj.expected_sacl = lambda value: value
    assert obj.plan([{"sid": "S-1-1-0", "flags": 0x43, "mask": 0x2}]) == "unchanged"
    assert acl.AddAuditAccessAceEx.call_count == adds


@pytest.mark.parametrize("inherited,preexisting,expected", [(True, False, True), (False, False, False), (True, True, False)])
def test_inherited_ownership_guard_distinguishes_existing_and_explicit_aces(monkeypatch, inherited, preexisting, expected):
    added = ((2, 0x43), 0x2, "S-1-1-0")
    child = ((2, 0x50 if inherited else 0x40), 0x2, "S-1-1-0")
    def acl(rows):
        return SimpleNamespace(GetAceCount=lambda: len(rows), GetAce=lambda index: rows[index])
    descriptors = {"previous": acl([added] if preexisting else []), "applied": acl([added])}
    security = SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptor=lambda value, version:
        SimpleNamespace(GetSecurityDescriptorSacl=lambda: descriptors[value]), ConvertSidToStringSid=lambda sid: sid)
    monkeypatch.setitem(sys.modules, "win32security", security)
    obj = native.LocalObject(object(), r"C:\synthetic")
    obj._descriptor = lambda: SimpleNamespace(GetSecurityDescriptorSacl=lambda: acl([child]))
    assert obj.inherited_from("previous", "applied") is expected

@pytest.mark.parametrize('directory,size,failed', [(False,20,False),(True,20,False),(False,10,False),(False,20,True)])
def test_expected_sacl_uses_native_inheritance_and_frees_private_descriptor(monkeypatch,directory,size,failed):
    class Descriptor(bytearray):
        def GetSecurityDescriptorSacl(self):return 'synthetic-acl'
        def SetSecurityDescriptorSacl(self,*args):self.assigned=args
        def GetSecurityDescriptorControl(self):return (0,1)
    current=Descriptor(b'current');parent=Descriptor(b'parent');proposed=Descriptor(b'proposed')
    buffer=ctypes.create_string_buffer(b'x'*20);calls=[]
    def create(p,c,out,guid,is_dir,flags,token,mapping):
        calls.append((is_dir,flags,token,guid))
        if failed:return 0
        ctypes.cast(out,ctypes.POINTER(ctypes.c_void_p))[0]=ctypes.addressof(buffer)
        return 1
    free=Mock(return_value=1)
    dll=SimpleNamespace(CreatePrivateObjectSecurityEx=Mock(side_effect=create),
                        GetSecurityDescriptorLength=Mock(return_value=size),DestroyPrivateObjectSecurity=free)
    monkeypatch.setattr(ctypes,'WinDLL',lambda *a,**kw:dll,raising=False)
    security=SimpleNamespace(SE_FILE_OBJECT=1,SACL_SECURITY_INFORMATION=8,OWNER_SECURITY_INFORMATION=1,
        GROUP_SECURITY_INFORMATION=2,DACL_SECURITY_INFORMATION=4,SE_SACL_PROTECTED=0x2000,
        GetNamedSecurityInfo=Mock(return_value=parent),GetSecurityInfo=Mock(return_value=current),
        ConvertStringSecurityDescriptorToSecurityDescriptor=lambda *a:proposed,
        SECURITY_DESCRIPTOR=lambda b:Descriptor(b),
        ConvertSecurityDescriptorToStringSecurityDescriptor=lambda *a:'synthetic-effective-sacl')
    monkeypatch.setitem(sys.modules,'win32security',security)
    monkeypatch.setitem(sys.modules,'ntsecuritycon',SimpleNamespace(FILE_GENERIC_READ=1,FILE_GENERIC_WRITE=2,
        FILE_GENERIC_EXECUTE=4,FILE_ALL_ACCESS=7))
    obj=native.LocalObject(object(),r'C:\synthetic\item')
    obj.describe=lambda:{'object_type':'directory' if directory else 'file'}
    if failed or size<20:
        with pytest.raises(RuntimeError,match='sacl_plan_failed'):obj.expected_sacl('synthetic-proposed')
    else:assert obj.expected_sacl('synthetic-proposed')=='synthetic-effective-sacl'
    assert calls==[(directory,26,None,None)]
    assert free.call_count==int(not failed)
    assert current.assigned==(True,'synthetic-acl',False)
    security.GetNamedSecurityInfo.assert_called_once_with(r'C:\synthetic',1,8)
