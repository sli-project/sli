from __future__ import annotations

import json
import logging
import os
import sys
from types import SimpleNamespace

import pytest

from server.sli.ops import worker_supervisor_secrets as module

SID = "S-1-5-21-100000001-200000001-300000001-1000"
SOURCE = {
    "ADLOG_PG_DSN": "postgresql://example.invalid/example_db",
    "ADLOG_COLLECTION_PRINCIPAL": r"EXAMPLE\operator",
    "ADLOG_COLLECTION_PRINCIPAL_SID": SID,
}


@pytest.fixture
def fake_dpapi(monkeypatch):
    calls = []

    def protect(clear, description, _entropy, _reserved, _prompt, flags):
        calls.append((json.loads(clear), flags))
        return b"user:" + clear

    def unprotect(blob, _entropy, _reserved, _prompt, flags):
        assert flags == 1
        prefix, clear = blob.split(b":", 1)
        assert prefix in (b"machine", b"user")
        return "synthetic-description", clear

    monkeypatch.setitem(sys.modules, "win32crypt", SimpleNamespace(
        CryptProtectData=protect, CryptUnprotectData=unprotect,
    ))
    # Model this module's Windows boundary without changing pathlib's host OS.
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt", environ=os.environ))
    monkeypatch.setattr(module, "_current_user_sid", lambda: SID)
    monkeypatch.setattr(module, "_ensure_web_service_identity", lambda _sid: None)
    monkeypatch.setattr(module, "_write_protected_blob", lambda path, blob: path.write_bytes(blob))
    return calls


def legacy_blob(values=None):
    return b"machine:" + json.dumps({"version": 1, "environment": values or SOURCE}).encode()


def test_provision_uses_current_user_dpapi(tmp_path, fake_dpapi):
    path = tmp_path / "profile.dpapi"
    module.provision_supervisor_environment(source=SOURCE, path=path)
    payload, flags = fake_dpapi[0]
    assert flags == 1  # No LOCAL_MACHINE bit.
    assert payload["version"] == 2
    assert payload["owner_sid"] == SID
    assert path.read_bytes().startswith(b"user:")


def test_legacy_migration_is_once_and_preserves_all_values(tmp_path, fake_dpapi, caplog):
    path = tmp_path / "profile.dpapi"
    values = {**SOURCE, "ADLOG_SEMANTIC_PRODUCTION_ENABLED": "0", "UNRELATED": "synthetic-private"}
    path.write_bytes(legacy_blob(values))
    with caplog.at_level(logging.WARNING, logger=module.__name__):
        target = {}
        first = module.load_supervisor_environment(target=target, path=path, override_existing=True)
        second = module.load_supervisor_environment(target={}, path=path)
    assert first["migrated"] is True
    assert second["migrated"] is False
    assert len(fake_dpapi) == 1
    assert fake_dpapi[0][0]["environment"] == values
    assert target["ADLOG_PG_DSN"] == SOURCE["ADLOG_PG_DSN"]
    assert target["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] == "0"
    assert "UNRELATED" not in target
    assert len(caplog.records) == 1
    for value in values.values():
        assert value not in caplog.text


@pytest.mark.parametrize("failure", ["web_service", "protect", "write"])
def test_failed_migration_preserves_old_blob_and_target(tmp_path, fake_dpapi, monkeypatch, failure, caplog):
    path = tmp_path / "profile.dpapi"
    old = legacy_blob()
    path.write_bytes(old)

    def fail(*_args, **_kwargs):
        raise RuntimeError("synthetic-private-error")

    if failure == "web_service":
        monkeypatch.setattr(module, "_ensure_web_service_identity", fail)
    elif failure == "protect":
        monkeypatch.setattr(sys.modules["win32crypt"], "CryptProtectData", fail)
    else:
        monkeypatch.setattr(module, "_write_protected_blob", fail)
    target = {"UNCHANGED": "synthetic"}
    with pytest.raises(RuntimeError):
        module.load_supervisor_environment(target=target, path=path)
    assert target == {"UNCHANGED": "synthetic"}
    assert path.read_bytes() == old
    assert not caplog.records


@pytest.mark.parametrize("reader", ["S-1-5-18", "other-user", "owner_with_other_web_account"])
def test_legacy_readers_keep_working_until_accounts_are_aligned(
    tmp_path, fake_dpapi, monkeypatch, caplog, reader,
):
    path = tmp_path / "profile.dpapi"
    old = legacy_blob()
    path.write_bytes(old)
    if reader == "owner_with_other_web_account":
        def fail(_sid):
            raise module._MigrationDeferred("synthetic-private-error")

        monkeypatch.setattr(module, "_ensure_web_service_identity", fail)
    else:
        monkeypatch.setattr(module, "_current_user_sid", lambda: reader)
    target = {}
    with caplog.at_level(logging.WARNING, logger=module.__name__):
        result = module.load_supervisor_environment(target=target, path=path)
    assert target["ADLOG_PG_DSN"] == SOURCE["ADLOG_PG_DSN"]
    assert result["migrated"] is False
    assert result["migration_deferred"] is True
    assert path.read_bytes() == old
    assert not fake_dpapi
    assert len(caplog.records) == 1
    for value in (*SOURCE.values(), reader, "synthetic-private-error"):
        assert value not in caplog.text
    with pytest.raises(module._MigrationDeferred):
        module.reencrypt_supervisor_environment(path=path)
    assert path.read_bytes() == old
    assert not fake_dpapi


def test_current_user_profile_rejects_another_owner(tmp_path, fake_dpapi, monkeypatch):
    path = tmp_path / "profile.dpapi"
    module.provision_supervisor_environment(source=SOURCE, path=path)
    monkeypatch.setattr(module, "_current_user_sid", lambda: "other-user")
    with pytest.raises(RuntimeError, match="owner mismatch"):
        module.load_supervisor_environment(target={}, path=path)
    assert len(fake_dpapi) == 1


def test_provision_rejects_another_user_without_overwriting_profile(tmp_path, fake_dpapi, monkeypatch):
    path = tmp_path / "profile.dpapi"
    old = legacy_blob()
    path.write_bytes(old)
    monkeypatch.setattr(module, "_current_user_sid", lambda: "other-user")
    with pytest.raises(RuntimeError, match="configured user"):
        module.provision_supervisor_environment(source=SOURCE, path=path)
    assert path.read_bytes() == old
    assert not fake_dpapi


def test_decryption_failure_does_not_disclose_details_or_rewrite(tmp_path, fake_dpapi, monkeypatch):
    path = tmp_path / "profile.dpapi"
    old = legacy_blob()
    path.write_bytes(old)

    def fail(*_args):
        raise RuntimeError("synthetic-private-error")

    monkeypatch.setattr(sys.modules["win32crypt"], "CryptUnprotectData", fail)
    with pytest.raises(RuntimeError, match="decryption failed") as error:
        module.load_supervisor_environment(target={}, path=path)
    assert "synthetic-private-error" not in str(error.value)
    assert error.value.__suppress_context__
    assert path.read_bytes() == old
    assert not fake_dpapi


@pytest.mark.parametrize("clear", [b"[]", b"null", b"{}", b'{"version":9,"environment":{}}', b"invalid"])
def test_invalid_profile_is_not_rewritten(tmp_path, fake_dpapi, clear):
    path = tmp_path / "profile.dpapi"
    blob = b"machine:" + clear
    path.write_bytes(blob)
    with pytest.raises(RuntimeError):
        module.load_supervisor_environment(target={}, path=path)
    assert path.read_bytes() == blob
    assert not fake_dpapi


@pytest.mark.parametrize("account", [
    "missing", "owner", "LocalSystem", "other", "unreadable", "query_unreadable", "lookup_unreadable",
])
def test_web_service_preflight_checks_sid_and_closes_handles(monkeypatch, account):
    closed = []

    def open_service(*_args):
        if account in ("missing", "unreadable"):
            error = OSError("synthetic-private-error")
            error.winerror = 1060 if account == "missing" else 5
            raise error
        return "service"

    def query_config(_handle):
        if account == "query_unreadable":
            raise OSError("synthetic-private-error")
        return (None,) * 7 + (account,)

    def lookup_account(_system, name):
        if account == "lookup_unreadable":
            raise OSError("synthetic-private-error")
        return (SID if name == "owner" else "other-sid", None, None)

    monkeypatch.setitem(sys.modules, "win32service", SimpleNamespace(
        SC_MANAGER_CONNECT=1, SERVICE_QUERY_CONFIG=2,
        OpenSCManager=lambda *_args: "manager", OpenService=open_service,
        QueryServiceConfig=query_config,
        CloseServiceHandle=closed.append,
    ))
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(
        LookupAccountName=lookup_account,
        ConvertSidToStringSid=lambda sid: sid,
    ))
    if account in ("missing", "owner"):
        module._ensure_web_service_identity(SID)
    else:
        with pytest.raises(module._MigrationDeferred) as error:
            module._ensure_web_service_identity(SID)
        assert "synthetic-private-error" not in str(error.value)
    assert closed == (["manager"] if account in ("missing", "unreadable") else ["service", "manager"])


@pytest.mark.parametrize("current", [False, True])
def test_explicit_reencryption_does_not_import_environment(tmp_path, fake_dpapi, monkeypatch, current):
    path = tmp_path / "profile.dpapi"
    path.write_bytes(legacy_blob())
    if current:
        module.reencrypt_supervisor_environment(path=path)
        fake_dpapi.clear()
    monkeypatch.setenv("ADLOG_PG_DSN", "synthetic-inherited")
    result = module.reencrypt_supervisor_environment(path=path)
    assert result["dpapi_scope"] == "CurrentUser"
    assert result["migrated"] is (not current)
    assert len(fake_dpapi) == 1
    assert os.environ["ADLOG_PG_DSN"] == "synthetic-inherited"


def test_reencryption_cli_reports_only_safe_metadata(tmp_path, fake_dpapi, monkeypatch, capsys):
    from scripts.ops import reencrypt_worker_supervisor_secrets as cli

    path = tmp_path / "profile.dpapi"
    path.write_bytes(legacy_blob())
    monkeypatch.setattr(sys, "argv", ["reencrypt", "--path", str(path)])
    assert cli.main() == 0
    output = capsys.readouterr()
    assert json.loads(output.out)["migrated"] is True
    for value in SOURCE.values():
        assert value not in output.out + output.err

    def fail(**_kwargs):
        raise RuntimeError("synthetic-private-error")

    monkeypatch.setattr(cli, "reencrypt_supervisor_environment", fail)
    assert cli.main() == 1
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "failed"
    assert "synthetic-private-error" not in output.out + output.err


@pytest.mark.parametrize("failure", [None, "acl", "short_write", "flush", "replace"])
def test_private_file_is_created_with_exact_dacl_and_replaced_atomically(tmp_path, monkeypatch, failure):
    from server.sli.sources import ad_source_credentials as store

    events = []
    descriptors = {}

    class ACL:
        def __init__(self):
            self.aces = []

        def AddAccessAllowedAceEx(self, revision, flags, rights, sid):
            self.aces.append(((0, flags), rights, sid))

        def GetAceCount(self):
            return len(self.aces)

        def GetAce(self, index):
            return self.aces[index]

    class Descriptor:
        def SetSecurityDescriptorOwner(self, sid, defaulted):
            self.owner = sid

        def SetSecurityDescriptorDacl(self, present, acl, defaulted):
            self.acl = acl

        def SetSecurityDescriptorControl(self, mask, flags):
            self.control = flags

        def GetSecurityDescriptorOwner(self):
            return self.owner

        def GetSecurityDescriptorDacl(self):
            return self.acl

        def GetSecurityDescriptorControl(self):
            return (self.control, 1)

    class Handle:
        def __init__(self, path):
            self.path = path

        def close(self):
            events.append("close")

    con = SimpleNamespace(
        GENERIC_WRITE=1, READ_CONTROL=2, CREATE_NEW=3, FILE_ATTRIBUTE_NORMAL=128,
        MOVEFILE_REPLACE_EXISTING=1, FILE_ATTRIBUTE_REPARSE_POINT=1024,
        FILE_ATTRIBUTE_DIRECTORY=16,
    )
    security = SimpleNamespace(
        WinLocalSystemSid=22, OBJECT_INHERIT_ACE=1, CONTAINER_INHERIT_ACE=2,
        ACL_REVISION=2, SE_DACL_PROTECTED=4096, ACCESS_ALLOWED_ACE_TYPE=0,
        SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1, DACL_SECURITY_INFORMATION=4,
        ACL=ACL, SECURITY_DESCRIPTOR=Descriptor, SECURITY_ATTRIBUTES=SimpleNamespace,
        CreateWellKnownSid=lambda _kind: "S-1-5-18", ConvertSidToStringSid=lambda sid: sid,
        GetSecurityInfo=lambda handle, *_args: descriptors[handle.path],
    )

    def create(path, access, share, attributes, disposition, flags, template):
        from pathlib import Path

        assert access == con.GENERIC_WRITE | con.READ_CONTROL
        assert share == 0
        assert disposition == con.CREATE_NEW
        assert attributes.bInheritHandle is False
        descriptor = attributes.SECURITY_DESCRIPTOR
        assert descriptor.owner == SID
        assert descriptor.control == security.SE_DACL_PROTECTED
        assert descriptor.acl.aces == [((0, 0), 2032127, SID), ((0, 0), 2032127, "S-1-5-18")]
        events.append("create_private")
        descriptors[path] = descriptor
        if failure == "acl":
            descriptor.control = 0
        with Path(path).open("xb"):
            pass
        return Handle(path)

    def write(handle, blob):
        from pathlib import Path

        events.append("write")
        Path(handle.path).write_bytes(blob)
        return (0, len(blob) - (failure == "short_write"))

    def flush(handle):
        events.append("flush")
        if failure == "flush":
            raise OSError("synthetic-private-error")

    def replace(source, destination, flags):
        events.append("replace")
        assert events[-2] == "close"
        assert flags == 9  # WRITE_THROUGH | REPLACE_EXISTING
        if failure == "replace":
            raise OSError("synthetic-private-error")
        os.replace(source, destination)

    files = SimpleNamespace(
        FILE_FLAG_OPEN_REPARSE_POINT=2097152, MOVEFILE_WRITE_THROUGH=8,
        CreateFile=create, WriteFile=write, FlushFileBuffers=flush, MoveFileEx=replace,
        DeleteFile=os.unlink,
        GetFileInformationByHandle=lambda _handle: (128, 0, 0, 0, 0, 0, 0, 1),
    )
    monkeypatch.setattr(store, "_windows", lambda: (None, con, None, files, security, SimpleNamespace(FILE_ALL_ACCESS=2032127)))
    monkeypatch.setattr(store, "_current_sid", lambda: SID)
    path = tmp_path / "profile.dpapi"
    path.write_bytes(b"old-ciphertext")
    if failure:
        with pytest.raises((store.AdCredentialStoreError, RuntimeError, OSError)):
            module._write_protected_blob(path, b"new-ciphertext")
        assert path.read_bytes() == b"old-ciphertext"
        if failure == "acl":
            assert "write" not in events
    else:
        module._write_protected_blob(path, b"new-ciphertext")
        assert path.read_bytes() == b"new-ciphertext"
        assert events == ["create_private", "write", "flush", "close", "replace"]
    assert sorted(item.name for item in tmp_path.iterdir()) == ["profile.dpapi"]
