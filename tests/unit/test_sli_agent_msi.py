"""MSI provisioning contracts; no SCM, network or database in these tests."""
import json
from types import SimpleNamespace

import pytest

from sli_agent import msi
from sli_agent.config import AgentConfig


def test_config_is_disabled_and_contains_no_bootstrap_secret(tmp_path):
    config = config_at(tmp_path, url="https://example.invalid:8443")
    body = json.loads((tmp_path / "agent.json").read_text(encoding="utf-8"))
    assert body["collection_enabled"] is False
    assert body["event_channels"] == []
    assert body["service_identity_sid"] == "S-1-5-18"
    assert "token" not in json.dumps(body)
    assert "update_root" not in body
    assert config.server_url == "https://example.invalid:8443"
    assert config.ca_bundle == tmp_path / "server-ca.pem"
    assert config.state_dir == tmp_path / "state"
    assert config.collection_enabled is False
    assert config.event_channels == ()
    assert config.probe_modules == ()
    assert config.allow_missing_rights is False


@pytest.mark.parametrize("url", ["http://example.invalid", "https://u:p@example.invalid", "https://example.invalid/path"])
def test_invalid_endpoint_is_rejected_without_echo(url, tmp_path):
    with pytest.raises(ValueError, match="^agent_config_invalid$"):
        msi.configuration(url, tmp_path, "S-1-5-18")


def test_acl_is_protected_and_uses_only_system_and_admin_by_default():
    assert msi.acl_sddl() == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    assert msi.acl_sddl("S-1-5-80-123") == "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-123)"
    with pytest.raises(ValueError):
        msi.acl_sddl("bad)(A;;FA;;;WD)")


def config_at(root, *, url="https://example.invalid", ca_fingerprint=None):
    path = root / "agent.json"
    body = msi.configuration(url, root, "S-1-5-18", ca_fingerprint)
    path.write_text(json.dumps(body), encoding="utf-8")
    return AgentConfig.load(path)


def test_token_deleted_before_network_and_never_saved_in_config(tmp_path):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text("synthetic-test-token", encoding="utf-8")
    calls = []
    def enroll(token, transport):
        assert not source.exists()
        calls.append(token)
    store = SimpleNamespace(load=lambda: None, enroll=enroll)
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "enrolled"
    assert calls == ["synthetic-test-token"]
    assert list(tmp_path.glob("*.json")) == [tmp_path / "agent.json"]
    assert "synthetic-test-token" not in (tmp_path / "agent.json").read_text(encoding="utf-8")
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "pending_enrollment"


def test_failed_enrollment_consumes_token_without_exposing_exception(tmp_path):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text("synthetic-test-token")
    def fail(*args):
        raise ValueError("synthetic-private-detail")
    store = SimpleNamespace(load=lambda: None, enroll=fail)
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "enrollment_failed"
    assert not source.exists()


def test_unsafe_token_is_not_read_or_deleted(tmp_path):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text("synthetic-test-token")
    def denied(path):
        raise ValueError("unsafe_acl")
    store = SimpleNamespace(load=lambda: None)
    assert msi.enroll_once(config, store, object(), check=denied) == "bootstrap_rejected"
    assert source.exists()


@pytest.mark.parametrize("owner,protected,public_access,attributes,links,status", [
    ("S-1-5-32-544", True, False, 0x20, 1, "enrolled"),
    ("S-1-5-21-999", True, False, 0x20, 1, "bootstrap_rejected"),
    ("S-1-5-32-544", False, False, 0x20, 1, "bootstrap_rejected"),
    ("S-1-5-32-544", True, True, 0x20, 1, "bootstrap_rejected"),
    ("S-1-5-32-544", True, False, 0x400, 1, "bootstrap_rejected"),
    ("S-1-5-32-544", True, False, 0x20, 2, "bootstrap_rejected"),
])
def test_windows_enrollment_consumes_installer_token_only_when_private(
    tmp_path, monkeypatch, owner, protected, public_access, attributes, links, status,
):
    import sys

    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_bytes(b"t" * 43)

    def descriptor(owner, protected, principals):
        acl = SimpleNamespace(GetAceCount=lambda: len(principals),
            GetAce=lambda i: ((0, 0), 0x1f01ff, principals[i]))
        return SimpleNamespace(GetSecurityDescriptorControl=lambda: (0x1000 if protected else 0, 1),
            GetSecurityDescriptorOwner=lambda: owner, GetSecurityDescriptorDacl=lambda: acl)

    # FileSecurity from the installer: Administrators owner, protected DACL,
    # only SYSTEM/Administrators full control, no inherited ACEs.
    principals = ["S-1-5-18", "S-1-5-32-544"] + (["S-1-1-0"] if public_access else [])
    file_descriptor = descriptor(owner, protected, principals)
    parent_descriptor = descriptor("S-1-5-32-544", True, ["S-1-5-18", "S-1-5-32-544"])
    reads, enrollments = [], []

    class Handle:
        delete_on_close = False

        def Close(self):
            if self.delete_on_close:
                source.unlink()

    handle = Handle()

    def create_file(path, access, sharing, security, disposition, flags, template):
        assert path == str(source)
        assert (access, sharing, security, disposition, flags, template) == (
            0x80030000, 0, None, 3, 0x200000, None,
        )
        return handle

    def delete_on_close(opened, kind, value):
        assert opened is handle and kind == 4 and value is True
        handle.delete_on_close = True

    def read_file(opened, size):
        assert opened is handle and size == 43
        reads.append(source)
        return 0, source.read_bytes()

    def enroll(token, transport):
        assert not source.exists()
        enrollments.append(token)

    monkeypatch.setattr(msi, "os", SimpleNamespace(name="nt"))
    # pywin32 exposes FILE_FLAG_OPEN_REPARSE_POINT in win32file, not win32con.
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(GENERIC_READ=0x80000000,
        DELETE=0x10000, READ_CONTROL=0x20000, OPEN_EXISTING=3, FILE_ATTRIBUTE_REPARSE_POINT=0x400))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(FILE_FLAG_OPEN_REPARSE_POINT=0x200000,
        FileDispositionInfo=4, CreateFile=create_file,
        GetFileInformationByHandle=lambda h: (attributes, None, None, None, 0, 0, 43, links, 0, 1),
        SetFileInformationByHandle=delete_on_close,
        GetFileSize=lambda h: 43, ReadFile=read_file))
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(SE_DACL_PROTECTED=0x1000,
        ACCESS_ALLOWED_ACE_TYPE=0, ACCESS_DENIED_ACE_TYPE=1, SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4, OWNER_SECURITY_INFORMATION=1, ConvertSidToStringSid=lambda sid: sid,
        GetNamedSecurityInfo=lambda path, *a: file_descriptor if path == str(source) else parent_descriptor,
        GetSecurityInfo=lambda *a: file_descriptor))
    store = SimpleNamespace(load=lambda: None, enroll=enroll)

    assert msi.enroll_once(config, store, object()) == status
    assert source.exists() == (status == "bootstrap_rejected")
    assert reads == ([source] if status == "enrolled" else [])
    assert enrollments == (["t" * 43] if status == "enrolled" else [])


@pytest.mark.parametrize("value", ["", "x" * 8193, "token\nsecond-line"])
def test_invalid_bootstrap_is_consumed_without_enrollment(tmp_path, value):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text(value)
    enrollments = []

    def enroll(*args):
        enrollments.append(args)
        pytest.fail("invalid bootstrap reached enrollment")

    store = SimpleNamespace(load=lambda: None, enroll=enroll)
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "enrollment_failed"
    assert enrollments == []
    assert not source.exists()


@pytest.mark.parametrize("raw", [b"", b"x" * (msi.MAX_TOKEN + 1), b"token\nsecond-line"])
def test_token_text_rejects_invalid_bootstrap_with_exact_reason(raw):
    with pytest.raises(ValueError, match="^agent_msi_bootstrap_invalid$"):
        msi.token_text(raw)


@pytest.mark.parametrize("raw", [b"synthetic-token", b"\xef\xbb\xbfsynthetic-token\r\n"])
def test_token_text_accepts_valid_bootstrap(raw):
    assert msi.token_text(raw) == "synthetic-token"


def test_cleanup_rejects_reparse_points_and_preserves_neighbour(tmp_path):
    root = tmp_path / "Agent"
    root.mkdir()
    (root / ".msi-owned").write_text("sli-agent-msi-v1")
    outside = tmp_path / "other"
    outside.mkdir()
    secret = outside / "keep"
    secret.write_text("synthetic")
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="agent_msi_path_unsafe"):
        msi.remove_owned(root)
    assert secret.exists()
    (root / "link").unlink()
    msi.remove_owned(root)
    assert not root.exists() and secret.exists()


def test_cleanup_refuses_unmanaged_state(tmp_path):
    (tmp_path / "identity-key.json").write_text("synthetic")
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged"):
        msi.remove_owned(tmp_path)
    assert (tmp_path / "identity-key.json").exists()


def test_public_properties_hex_roundtrip_and_no_shell_interpretation():
    value = 'C:\\synthetic folder\\a"&.pem'
    encoded = value.encode("utf-16le").hex()
    assert msi.decode_property(encoded) == value
    assert msi.decode_property("-") == ""
    with pytest.raises(ValueError):
        msi.decode_property("not-hex")


def test_fingerprint_config_validation(tmp_path):
    assert config_at(tmp_path, ca_fingerprint="a" * 64).ca_fingerprint == "a" * 64
    for bad in ("a" * 63, "A" * 64, "x" * 64, 1):
        with pytest.raises(ValueError, match="agent_config_invalid"):
            msi.configuration("https://example.invalid", tmp_path, "S-1-5-18", bad)


def test_existing_enrollment_also_consumes_obsolete_bootstrap(tmp_path):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text("synthetic-test-token")
    store = SimpleNamespace(load=lambda: object(), enroll=lambda *a: pytest.fail("already enrolled"))
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "enrolled"
    assert not source.exists()


def test_expired_bootstrap_is_deleted_without_network(tmp_path, monkeypatch):
    config = config_at(tmp_path)
    source = tmp_path / "enrollment.token"
    source.write_text("synthetic-test-token")
    monkeypatch.setattr(msi.time, "time", lambda: source.stat().st_mtime + msi.BOOTSTRAP_TTL + 1)
    store = SimpleNamespace(load=lambda: None, enroll=lambda *a: pytest.fail("expired token"))
    assert msi.enroll_once(config, store, object(), check=lambda p: None) == "bootstrap_expired"
    assert not source.exists()


def test_rollback_removes_only_pending_new_installation(tmp_path):
    root = tmp_path / "Agent"
    root.mkdir()
    (root / ".msi-owned").write_text(msi.OWNER)
    (root / "agent.json").write_text("synthetic")
    msi.remove_owned(root, rollback=True)
    assert root.exists()
    (root / ".msi-pending").touch()
    msi.remove_owned(root, rollback=True)
    assert not root.exists()


def upgrade_state(tmp_path):
    root = tmp_path / "Agent"
    source = tmp_path / ("Agent.upgrade-" + "a" * 32)
    source.mkdir()
    (source / ".msi-owned").write_text(msi.OWNER)
    (source / "agent.json").write_text(json.dumps(msi.configuration("https://core.invalid", root, "S-1-5-18")))
    for name in ("identity.json", "identity-key.json", "host.json", "tls/certificate.pem",
                 "spool/packet.json", "receipts/receipt.json", "cursors.json", "capture/cycle.json",
                 "windows-audit/state.json", "file-audit/state.json"):
        path = source / "state" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic-preserved-" + name)
    return source, root


def test_upgrade_rename_preserves_all_bytes_acl_modes_and_rollback_state(tmp_path):
    source, root = upgrade_state(tmp_path)
    before = {p.relative_to(source): (p.read_bytes(), p.stat().st_mode) for p in source.rglob("*") if p.is_file()}
    msi.restore_owned(source, root)
    assert not source.exists()
    assert {p.relative_to(root): (p.read_bytes(), p.stat().st_mode) for p in root.rglob("*") if p.is_file()} == before
    msi.remove_owned(root, rollback=True)
    assert (root / "state/identity-key.json").exists()


@pytest.mark.parametrize("failure", ["destination", "unmanaged", "pending", "config", "instance", "zip", "outside", "symlink"])
def test_upgrade_restore_rejects_unsafe_state_without_mutation(tmp_path, failure):
    source, root = upgrade_state(tmp_path)
    if failure == "destination":
        root.mkdir()
    elif failure == "unmanaged":
        (source / ".msi-owned").unlink()
    elif failure == "pending":
        (source / ".msi-pending").touch()
    elif failure in ("config", "instance", "zip"):
        body = json.loads((source / "agent.json").read_text())
        if failure == "config":
            body["state_dir"] = str(tmp_path / "other")
        elif failure == "instance":
            (source / "state/instances/fixture").mkdir(parents=True)
        else:
            body.update(update_root=str(tmp_path / "releases"), update_trust_store=str(tmp_path / "trust.json"),
                        service_python=str(tmp_path / "python.exe"))
        (source / "agent.json").write_text(json.dumps(body))
    elif failure == "outside":
        root = tmp_path / "other/Agent"
    else:
        (source / "state/link").symlink_to(tmp_path / "other")
    before = (source / "state/identity-key.json").read_bytes()
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged|agent_msi_path_unsafe"):
        msi.restore_owned(source, root)
    assert (source / "state/identity-key.json").read_bytes() == before


def test_upgrade_restore_checks_windows_acl_before_rename(tmp_path, monkeypatch):
    import sys
    source, root = upgrade_state(tmp_path)
    checked = []
    monkeypatch.setattr(msi, "os", SimpleNamespace(name="nt", walk=__import__("os").walk))
    monkeypatch.setattr(msi, "trusted_ancestors", lambda *a, **kw: None)
    def reject(descriptor, sid, **kwargs):
        checked.append(descriptor)
        raise ValueError("agent_msi_bootstrap_acl")
    monkeypatch.setattr(msi, "private_descriptor", reject)
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4, OWNER_SECURITY_INFORMATION=1, GetNamedSecurityInfo=lambda path, *a: path))
    with pytest.raises(ValueError, match="agent_msi_bootstrap_acl"):
        msi.restore_owned(source, root)
    assert checked and source.exists() and not root.exists()


def test_direct_upgrade_validates_state_without_changing_registration(tmp_path):
    source, root = upgrade_state(tmp_path)
    source.rename(root)
    before = {p.relative_to(root): (p.read_bytes(), p.stat().st_mode) for p in root.rglob("*") if p.is_file()}
    msi.validate_owned(root)
    msi.remove_owned(root, rollback=True)
    assert {p.relative_to(root): (p.read_bytes(), p.stat().st_mode) for p in root.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("failure", ["unmanaged", "pending", "config", "instance", "symlink"])
def test_direct_upgrade_rejects_unsafe_state_without_changing_identity(tmp_path, failure):
    source, root = upgrade_state(tmp_path)
    source.rename(root)
    if failure == "unmanaged":
        (root / ".msi-owned").unlink()
    elif failure == "pending":
        (root / ".msi-pending").touch()
    elif failure == "config":
        body = json.loads((root / "agent.json").read_text())
        body["state_dir"] = str(tmp_path / "other")
        (root / "agent.json").write_text(json.dumps(body))
    elif failure == "instance":
        (root / "state/instances/fixture").mkdir(parents=True)
    else:
        (root / "state/link").symlink_to(tmp_path / "other")
    before = (root / "state/identity-key.json").read_bytes()
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged|agent_msi_path_unsafe"):
        msi.validate_owned(root)
    assert (root / "state/identity-key.json").read_bytes() == before


def test_preserve_cli_validates_machine_state_without_provisioning(tmp_path, monkeypatch):
    import sys

    calls = []
    monkeypatch.setattr(msi, "machine_config_path", lambda: tmp_path / "agent.json")
    monkeypatch.setattr(msi, "validate_owned", calls.append)
    monkeypatch.setattr(msi, "provision", lambda *a: pytest.fail("upgrade must not provision"))
    monkeypatch.setattr(sys, "argv", ["sli_agent.msi", "preserve"])
    assert msi.main() == 0
    assert calls == [tmp_path]


def test_preserve_cli_rejects_unexpected_arguments_and_keeps_validation_errors_private(tmp_path, monkeypatch, capsys):
    import sys

    monkeypatch.setattr(msi, "machine_config_path", lambda: tmp_path / "agent.json")
    def reject(root):
        raise ValueError("agent_msi_state_unmanaged")
    monkeypatch.setattr(msi, "validate_owned", reject)
    monkeypatch.setattr(sys, "argv", ["sli_agent.msi", "preserve"])
    assert msi.main() == 5
    monkeypatch.setattr(sys, "argv", ["sli_agent.msi", "preserve", "unexpected"])
    assert msi.main() == 1
    assert capsys.readouterr() == ("", "")


def test_msi_wave_zip_rejection_is_authenticated_and_never_downloads(tmp_path):
    from sli_agent import __version__
    config = config_at(tmp_path)
    (tmp_path / ".msi-owned").write_text(msi.OWNER)
    calls = []
    transport = SimpleNamespace(post=lambda *a, **kw: calls.append((a, kw)))
    assert msi.report_zip_offer(config, {"sha256": "a" * 64}, transport, "synthetic-identity")
    assert calls == [(("/api/v1/agent/update-result", {"sha256": "a" * 64, "status": "rejected",
                      "reason": "agent_update_msi_required", "version": __version__}), {"identity": "synthetic-identity"})]
    assert not msi.report_zip_offer(config, {"sha256": "invalid"}, transport, "synthetic-identity")
    (tmp_path / ".msi-owned").unlink()
    assert not msi.report_zip_offer(config, {"sha256": "a" * 64}, transport, "synthetic-identity")
    assert len(calls) == 1


def test_msi_wave_result_failure_can_retry_without_stopping_agent(tmp_path):
    config = config_at(tmp_path)
    (tmp_path / ".msi-owned").write_text(msi.OWNER)
    def offline(*a, **kw):
        raise OSError("synthetic-offline")
    assert not msi.report_zip_offer(config, {"sha256": "a" * 64}, SimpleNamespace(post=offline), "synthetic-identity")
    assert msi.report_zip_offer(config, {"sha256": "a" * 64}, SimpleNamespace(post=lambda *a, **kw: None), "synthetic-identity")


def test_managed_service_waits_without_running_collectors(tmp_path, monkeypatch):
    from sli_agent import enrollment, probe, runtime
    config = config_at(tmp_path)
    config.state_dir.mkdir()
    store = SimpleNamespace(prepare=lambda: {}, load=lambda: None)
    monkeypatch.setattr(enrollment, "IdentityStore", lambda c: store)
    monkeypatch.setattr(probe, "service_identity_verified", lambda c: True)
    monkeypatch.setattr(msi, "ensure_ca", lambda c: None)
    monkeypatch.setattr(runtime, "run", lambda *a: pytest.fail("collection before enrollment"))
    class Stop:
        stopped = False
        def is_set(self):
            return self.stopped
        def wait(self, seconds):
            assert seconds == 30
            self.stopped = True
    msi.run_managed(config, Stop())
    assert json.loads((config.state_dir / "status.json").read_text()) == {
        "collection_enabled": False, "error_code": "pending_enrollment"}


def test_managed_service_reboot_uses_existing_identity_without_bootstrap(tmp_path, monkeypatch):
    import threading

    from sli_agent import enrollment, probe, runtime, transport

    config = config_at(tmp_path)
    stop = threading.Event()
    identity = object()
    store = SimpleNamespace(prepare=lambda: {}, load=lambda: identity,
                            enroll=lambda *a: pytest.fail("reboot must retain enrollment"))
    monkeypatch.setattr(enrollment, "IdentityStore", lambda c: store)
    monkeypatch.setattr(probe, "service_identity_verified", lambda c: True)
    monkeypatch.setattr(msi, "ensure_ca", lambda c: None)
    monkeypatch.setattr(transport, "Transport", lambda c: object())
    calls = []
    monkeypatch.setattr(runtime, "run", lambda c, event: calls.append((c, event)))

    assert not (tmp_path / "enrollment.token").exists()
    msi.run_managed(config, stop)
    assert calls == [(config, stop)]
    assert not (tmp_path / "enrollment.token").exists()


def test_fingerprint_bootstrap_never_accepts_an_unmatched_ca(tmp_path, monkeypatch):
    import socket
    import ssl
    config = config_at(tmp_path, ca_fingerprint="a" * 64)
    class Connection:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def get_unverified_chain(self):
            return []
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: Connection())
    monkeypatch.setattr(ssl, "SSLContext", lambda *a: SimpleNamespace(wrap_socket=lambda *a, **kw: Connection()))
    with pytest.raises(ValueError, match="agent_msi_ca_invalid"):
        msi.ensure_ca(config)
    assert not config.ca_bundle.exists()


def test_file_cleanup_failure_prevents_network(tmp_path, monkeypatch):
    config = config_at(tmp_path)
    (tmp_path / "enrollment.token").write_text("synthetic-test-token")
    def fail(*args, **kwargs):
        raise OSError("synthetic-private-detail")
    monkeypatch.setattr(msi, "consume_file", fail)
    store = SimpleNamespace(load=lambda: None, enroll=lambda *a: pytest.fail("token not consumed"))
    assert msi.enroll_once(config, store, object()) == "bootstrap_rejected"


@pytest.mark.parametrize("protected,owner,aces,valid", [
    (True, "S-1-5-18", [(0, "S-1-5-18"), (0, "S-1-5-32-544")], True),
    (False, "S-1-5-18", [(0, "S-1-5-18")], False),
    (True, "S-1-5-21-999", [(0, "S-1-5-18")], False),
    (True, "S-1-5-18", [(0, "S-1-1-0")], False),
    (True, "S-1-5-18", [(5, "S-1-5-18")], False),
])
def test_bootstrap_descriptor_rejects_inheritance_unknown_owner_and_public_access(monkeypatch, protected, owner, aces, valid):
    import sys
    security = SimpleNamespace(SE_DACL_PROTECTED=0x1000, ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_DENIED_ACE_TYPE=1, ConvertSidToStringSid=lambda sid: sid)
    monkeypatch.setitem(sys.modules, "win32security", security)
    acl = SimpleNamespace(GetAceCount=lambda: len(aces),
        GetAce=lambda i: ((aces[i][0], 0), 0x1f01ff, aces[i][1]))
    descriptor = SimpleNamespace(GetSecurityDescriptorControl=lambda: (0x1000 if protected else 0, 1),
        GetSecurityDescriptorOwner=lambda: owner, GetSecurityDescriptorDacl=lambda: acl)
    if valid:
        msi.private_descriptor(descriptor, "S-1-5-18")
    else:
        with pytest.raises(ValueError, match="agent_msi_bootstrap_acl"):
            msi.private_descriptor(descriptor, "S-1-5-18")


@pytest.mark.parametrize("managed", [True, False])
def test_windows_state_acl_retains_admins_only_for_msi_state(tmp_path, monkeypatch, managed):
    import sys
    from sli_agent import protection
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    root = msi.machine_config_path().parent
    root.mkdir(parents=True)
    if managed:
        (root / ".msi-owned").write_text(msi.OWNER)
    allowed = []
    class Token:
        def Close(self):
            pass
    security = SimpleNamespace(WinLocalSystemSid=18, WinBuiltinAdministratorsSid=544,
        ACL_REVISION=2, TokenUser=1, SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4,
        PROTECTED_DACL_SECURITY_INFORMATION=0x80000000,
        OpenProcessToken=lambda *a: Token(), GetTokenInformation=lambda *a: ("service-sid",),
        CreateWellKnownSid=lambda kind, *a: "system" if kind == 18 else "administrators",
        ACL=lambda: SimpleNamespace(AddAccessAllowedAceEx=lambda revision, flags, mask, sid: allowed.append(sid)),
        SetNamedSecurityInfo=lambda *a: None)
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetCurrentProcess=lambda: 1))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(TOKEN_QUERY=8,
        OBJECT_INHERIT_ACE=1, CONTAINER_INHERIT_ACE=2, GENERIC_ALL=0x10000000))
    monkeypatch.setattr(protection, "os", SimpleNamespace(name="nt"))
    protection.restrict_path(root, directory=True)
    assert allowed == ["service-sid", "system"] + (["administrators"] if managed else [])


def fake_provisioning(monkeypatch):
    import sys
    created, secured = [], []
    def create(path, attributes):
        from pathlib import Path
        assert attributes.SECURITY_DESCRIPTOR == msi.acl_sddl()
        Path(path).mkdir(mode=0o700)
        created.append(path)
    monkeypatch.setattr(msi, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(SDDL_REVISION_1=1,
        ConvertStringSecurityDescriptorToSecurityDescriptor=lambda text, version: text))
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(CreateDirectory=create))
    monkeypatch.setitem(sys.modules, "pywintypes", SimpleNamespace(SECURITY_ATTRIBUTES=SimpleNamespace))
    monkeypatch.setattr(msi, "set_acl", lambda path, sid: secured.append((path, sid)))
    monkeypatch.setattr(msi, "trusted_ancestors", lambda *a: None)
    return created, secured


def test_provision_creates_its_config_and_state_with_acl_before_bootstrap(tmp_path, monkeypatch):
    created, secured = fake_provisioning(monkeypatch)
    root = tmp_path / "Agent"
    source = tmp_path / "protected.token"
    source.write_text("synthetic-test-token")
    def consume(path, sid):
        assert (root / "agent.json").exists() and (root / "state").is_dir()
        value = path.read_bytes()
        path.unlink()
        return value
    monkeypatch.setattr(msi, "consume_file", consume)
    msi.provision("https://example.invalid", "", "a" * 64, str(source), "LocalSystem", root=root)
    config = AgentConfig.load(root / "agent.json")
    assert config.state_dir == root / "state" and config.ca_fingerprint == "a" * 64
    assert not config.collection_enabled and config.update_root is None
    assert created == [str(root), str(root / "state")]
    assert secured == [(root / "agent.json", "S-1-5-18"), (root / "enrollment.token", "S-1-5-18")]
    assert not source.exists()
    assert (root / "enrollment.token").read_text() == "synthetic-test-token"
    assert "synthetic-test-token" not in (root / "agent.json").read_text()


def test_provision_refuses_existing_state_without_reading_token(tmp_path, monkeypatch):
    created, secured = fake_provisioning(monkeypatch)
    monkeypatch.setattr(msi, "consume_file", lambda *a: pytest.fail("existing identity must survive"))
    (tmp_path / "identity-key.json").write_text("synthetic")
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged"):
        msi.provision("https://example.invalid", "", "a" * 64, "synthetic-path", "LocalSystem", root=tmp_path)
    assert created == secured == []
    assert (tmp_path / "identity-key.json").exists()


@pytest.mark.parametrize("owner,mask", [
    ("S-1-5-21-999", 0x120089),  # creator owns the SLI parent
    ("S-1-5-32-544", 0x1f01ff),  # creator can replace children/change the DACL
])
def test_configure_rejects_unsafe_ca_parent_after_pilot_archived(tmp_path, monkeypatch, owner, mask):
    import sys
    from pathlib import Path

    trusted_ancestors = msi.trusted_ancestors
    created, secured = fake_provisioning(monkeypatch)
    monkeypatch.setattr(msi, "trusted_ancestors", trusted_ancestors)
    parent = tmp_path / "SLI"
    archive = parent / "Agent.pilot-synthetic"
    archive.mkdir(parents=True)
    identity = archive / "identity.json"
    identity.write_text("synthetic-preserved-identity")
    bootstrap = parent / "LocalBootstrap"
    bootstrap.mkdir()
    ca = bootstrap / "server-ca.pem"
    ca.write_text("synthetic-ca-not-read")
    root = parent / "Agent"
    checked = []

    def descriptor(path, *args):
        path = Path(path)
        checked.append(path)
        unsafe = path == parent
        acl = SimpleNamespace(GetAceCount=lambda: 1,
            GetAce=lambda i: ((0, 0), mask if unsafe else 0x1f01ff,
                             "S-1-5-21-999" if unsafe else "S-1-5-18"))
        return SimpleNamespace(GetSecurityDescriptorOwner=lambda: owner if unsafe else "S-1-5-18",
                               GetSecurityDescriptorDacl=lambda: acl)

    security = sys.modules["win32security"]
    for name, value in {"SE_FILE_OBJECT": 1, "DACL_SECURITY_INFORMATION": 4,
                        "OWNER_SECURITY_INFORMATION": 1, "ACCESS_ALLOWED_ACE_TYPE": 0,
                        "ACCESS_DENIED_ACE_TYPE": 1, "GetNamedSecurityInfo": descriptor,
                        "ConvertSidToStringSid": lambda sid: sid}.items():
        monkeypatch.setattr(security, name, value, raising=False)
    monkeypatch.setattr(msi, "machine_config_path", lambda: root / "agent.json")
    fields = ["https://example.invalid", str(ca), "", "", "LocalSystem"]
    monkeypatch.setattr(sys, "argv", ["msi", "configure", *[
        value.encode("utf-16le").hex() if value else "-" for value in fields
    ]])

    assert not root.exists()
    assert msi.main() == 5
    assert checked == [ca, bootstrap, parent]
    assert created == secured == []
    assert not root.exists()
    assert identity.read_text() == "synthetic-preserved-identity"
    assert ca.read_text() == "synthetic-ca-not-read"


@pytest.mark.parametrize("mask,flags,owner,safe", [
    (0x120089, 0, "S-1-5-18", True),  # public read-only parent
    (0x40, 0, "S-1-5-18", False),     # untrusted DELETE_CHILD
    (0x40000, 0, "S-1-5-18", False),  # untrusted WRITE_DAC
    (0x1f01ff, 8, "S-1-5-18", True), # inherit-only ACE
    (0x120089, 0, "S-1-5-21-999", False),
])
def test_ancestor_acl_rejects_replaceable_paths(monkeypatch, mask, flags, owner, safe):
    import sys
    acl = SimpleNamespace(GetAceCount=lambda: 1,
        GetAce=lambda i: ((0, flags), mask, "S-1-1-0"))
    descriptor = SimpleNamespace(GetSecurityDescriptorOwner=lambda: owner,
        GetSecurityDescriptorDacl=lambda: acl)
    security = SimpleNamespace(SE_FILE_OBJECT=1, DACL_SECURITY_INFORMATION=4,
        OWNER_SECURITY_INFORMATION=1, ACCESS_ALLOWED_ACE_TYPE=0, ACCESS_DENIED_ACE_TYPE=1,
        GetNamedSecurityInfo=lambda *a: descriptor, ConvertSidToStringSid=lambda sid: sid)
    monkeypatch.setitem(sys.modules, "win32security", security)
    monkeypatch.setattr(msi, "os", SimpleNamespace(name="nt"))
    path = SimpleNamespace(parents=["synthetic-parent"])
    if safe:
        msi.trusted_ancestors(path)
    else:
        with pytest.raises(ValueError, match="agent_msi_path_unsafe"):
            msi.trusted_ancestors(path)
