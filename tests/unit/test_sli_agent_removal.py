"""Fixed uninstall invocation and offline MSI cleanup using fakes only."""
import json
import sys
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import ANY, Mock

import pytest

from sli_agent import msi, removal, runtime
from sli_agent.config import AgentConfig

AGENT = "00000000-0000-4000-8000-000000000001"
COMMAND = "00000000-0000-4000-8000-000000000002"
OFFER = {"agent_id": AGENT, "agent_removal": {"command_id": COMMAND, "action": "uninstall"}}


def owned(root, *, service_identity_sid=None):
    root.mkdir()
    (root / ".msi-owned").write_text(msi.OWNER)
    config = AgentConfig("https://core.invalid", root / "ca.pem", root / "state")
    (root / "agent.json").write_text(json.dumps({"server_url": config.server_url,
        "ca_bundle": str(config.ca_bundle), "state_dir": str(config.state_dir),
        "service_identity_sid": service_identity_sid}))
    config.state_dir.mkdir()
    (config.state_dir / "identity-key.json").write_text("fixture-key")
    (config.state_dir / "spool").mkdir()
    (config.state_dir / "spool/packet.json").write_text("fixture-buffer")
    return config


def test_launch_uses_local_fixed_msi_command_and_never_reports_cleanup():
    transport, spawn = Mock(), Mock()
    identity = SimpleNamespace(agent_id=AGENT)
    args = ["fixture-msiexec.exe", "/x", "{00000000-0000-4000-8000-000000000003}", "/qn", "/norestart"]
    removal.launch(object(), OFFER, transport, identity, command=lambda _: args, spawn=spawn)
    assert spawn.call_args.args == (args,)
    assert "shell" not in spawn.call_args.kwargs
    transport.post.assert_not_called()


@pytest.mark.parametrize("offer", [None, {**OFFER, "agent_id": COMMAND},
    {**OFFER, "agent_removal": {"command_id": COMMAND, "action": "uninstall", "path": "fixture"}},
    {**OFFER, "agent_removal": {"command_id": "invalid", "action": "uninstall"}}])
def test_invalid_or_foreign_command_cannot_launch(offer):
    spawn = Mock()
    with pytest.raises(ValueError, match="agent_removal_invalid"):
        removal.launch(object(), offer, Mock(), SimpleNamespace(agent_id=AGENT), spawn=spawn)
    spawn.assert_not_called()


def test_native_launch_failure_is_bounded_and_private_error_is_not_reported():
    transport = Mock()
    removal.launch(object(), OFFER, transport, SimpleNamespace(agent_id=AGENT),
                   command=lambda _: [], spawn=Mock(side_effect=OSError("fixture-private-detail")))
    body = transport.post.call_args.args[1]
    assert body == {"command_id": COMMAND, "state": "cleanup_failed", "reason": "agent_removal_cleanup_failed"}
    assert "fixture-private-detail" not in repr(transport.mock_calls)


def native_msi(tmp_path, monkeypatch, *, admin=True, product="{00000000-0000-4000-8000-000000000003}"):
    root = tmp_path / "Agent"
    config = owned(root)
    monkeypatch.setattr(removal, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(removal, "machine_config_path", lambda: root / "agent.json")
    class Buffer:
        value = ""
        def __len__(self):
            return 32768
    buffer = Buffer()
    def system_directory(target, size):
        target.value = "C:\\Windows\\System32"
        return len(target.value)
    monkeypatch.setitem(sys.modules, "ctypes", SimpleNamespace(create_unicode_buffer=lambda n: buffer,
        windll=SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: admin),
                              kernel32=SimpleNamespace(GetSystemDirectoryW=system_directory))))
    monkeypatch.setitem(sys.modules, "winreg", SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_READ=1,
        KEY_WOW64_64KEY=256, REG_SZ=1, OpenKey=lambda *a: nullcontext(object()),
        QueryValueEx=lambda *a: (product, 1)))
    return config


def test_windows_command_uses_system_installer_and_registered_product(tmp_path, monkeypatch):
    config = native_msi(tmp_path, monkeypatch)
    assert removal.msi_command(config) == [r"C:\Windows\System32\msiexec.exe", "/x",
        "{00000000-0000-4000-8000-000000000003}", "/qn", "/norestart"]


def test_windows_command_refuses_non_admin_without_uac_or_process(tmp_path, monkeypatch):
    config = native_msi(tmp_path, monkeypatch, admin=False)
    with pytest.raises(ValueError, match="agent_removal_requires_admin"):
        removal.msi_command(config)


@pytest.mark.parametrize("product", ["fixture.exe", "{00000000-0000-4000-8000-000000000003} /x other"])
def test_windows_command_rejects_product_argument_injection(tmp_path, monkeypatch, product):
    config = native_msi(tmp_path, monkeypatch, product=product)
    with pytest.raises(ValueError, match="agent_removal_unmanaged"):
        removal.msi_command(config)


def test_offline_msi_uninstall_removes_owned_key_buffer_and_preserves_neighbour(tmp_path, monkeypatch):
    root = tmp_path / "Agent"
    owned(root, service_identity_sid="S-1-5-18")
    sibling = tmp_path / "other"
    sibling.mkdir()
    (sibling / "keep").write_text("fixture")
    load = Mock(side_effect=OSError("offline"))
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", lambda _: SimpleNamespace(load=load))
    msi.uninstall_owned(root)
    load.assert_called_once_with()
    assert not root.exists() and (sibling / "keep").exists()
    msi.uninstall_owned(root)  # An interrupted MSI retry is harmless.


def test_file_audit_ownership_blocks_uninstall_and_preserves_journal(tmp_path, monkeypatch):
    from sli_agent.file_audit import FileAuditManager
    from sli_agent.windows_audit import AuditManager
    root = tmp_path / "Agent"
    config = owned(root)
    journal = config.state_dir / "file-audit"
    journal.mkdir()
    state = {"masks": {"0cce921d-69ae-11d9-bed3-505054503030": 3}, "objects": {}, "commands": {},
             "active": None, "walks": {}, "pending_report": None, "scan_command": None, "completed_at": None}
    FileAuditManager(journal, AuditManager(config.state_dir / "windows-audit"))._save(state)
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", lambda _: SimpleNamespace(load=lambda: None))
    with pytest.raises(ValueError, match="agent_removal_cleanup_failed"):
        msi.uninstall_owned(root)
    assert (journal / "state.json").exists() and (config.state_dir / "identity-key.json").exists()


def test_online_cleanup_reports_after_deletion_without_recreating_identity(tmp_path, monkeypatch):
    root = tmp_path / "Agent"
    owned(root, service_identity_sid="S-1-5-18")
    identity = SimpleNamespace(agent_id=AGENT)
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", lambda _: SimpleNamespace(load=lambda: identity))
    calls = []
    class Transport:
        def __init__(self, config):
            pass
        def _context(self, value):
            assert value is identity and root.exists()
            return object()
        def post(self, path, body, **kwargs):
            calls.append(path)
            if path.endswith("/uninstall"):
                assert root.exists()
                return OFFER
            assert not root.exists() and body == {"command_id": COMMAND, "state": "state_cleaned", "reason": None}
            return {}
    monkeypatch.setattr("sli_agent.transport.Transport", Transport)
    msi.uninstall_owned(root)
    assert calls == ["/api/v1/agent/uninstall", "/api/v1/agent/removal-result"]
    assert not root.exists()


@pytest.mark.parametrize("location", ["instances", "state/instances"])
def test_uninstall_refuses_named_sibling_and_symlink_before_loading_identity(tmp_path, monkeypatch, location):
    root = tmp_path / "Agent"
    owned(root)
    (root / location).mkdir()
    (root / location / "SLI-Agent-fixture").mkdir()
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", Mock(side_effect=AssertionError("must not load")))
    with pytest.raises(ValueError, match="agent_msi_state_unmanaged"):
        msi.uninstall_owned(root)
    (root / location / "SLI-Agent-fixture").rmdir()
    (root / "linked").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="agent_msi_path_unsafe"):
        msi.uninstall_owned(root)
    assert (root / "state/identity-key.json").exists()


def test_audit_restore_failure_preserves_rollback_state_and_key(tmp_path, monkeypatch):
    root = tmp_path / "Agent"
    config = owned(root)
    audit = config.state_dir / "windows-audit"
    audit.mkdir()
    (audit / "state.json").write_text(json.dumps({
        "subcategories": {},
        "command_line": {"previous": 0, "applied": 1, "phase": "confirmed"},
    }))
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", lambda _: SimpleNamespace(load=lambda: None))
    reconcile = Mock(return_value={"management_state": "blocked"})
    monkeypatch.setattr("sli_agent.windows_audit.AuditManager.reconcile", reconcile)
    with pytest.raises(ValueError, match="agent_removal_cleanup_failed"):
        msi.uninstall_owned(root)
    reconcile.assert_called_once()
    assert (audit / "state.json").exists() and (config.state_dir / "identity-key.json").exists()


def test_interrupted_cleanup_retains_marker_and_retry_finishes_without_config(tmp_path, monkeypatch):
    root = tmp_path / "Agent"
    owned(root)
    monkeypatch.setattr("sli_agent.enrollment.IdentityStore", lambda _: SimpleNamespace(load=lambda: None))
    original = msi.shutil.rmtree
    monkeypatch.setattr(msi.shutil, "rmtree", Mock(side_effect=OSError("fixture-cleanup-failure")))
    with pytest.raises(OSError):
        msi.uninstall_owned(root)
    assert (root / ".msi-owned").read_text() == msi.OWNER
    (root / "agent.json").unlink(missing_ok=True)
    monkeypatch.setattr(msi.shutil, "rmtree", original)
    msi.uninstall_owned(root)
    assert not root.exists()


def test_runtime_removal_precedes_policy_collection_spool_delivery_and_updates(tmp_path, monkeypatch):
    config = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path / "state")
    identity = SimpleNamespace(agent_id=AGENT)
    monkeypatch.setattr(runtime, "IdentityStore", lambda _: SimpleNamespace(
        prepare=lambda: {"host_id": AGENT}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    post = Mock(side_effect=AssertionError("must not send data"))
    monkeypatch.setattr(runtime, "Transport", lambda _: SimpleNamespace(get=lambda *a, **kw: OFFER, post=post))
    monkeypatch.setattr(runtime, "configured_modules", lambda *a: [])
    monkeypatch.setattr(runtime, "apply_policy", Mock(side_effect=AssertionError("must not apply")))
    closed, launched = Mock(), Mock()
    monkeypatch.setattr(runtime, "SnapshotCapture", lambda _: SimpleNamespace(close=closed))
    monkeypatch.setattr(removal, "launch", launched)
    runtime.run(config, SimpleNamespace(is_set=lambda: False))
    closed.assert_called_once()
    launched.assert_called_once_with(config, OFFER, ANY, identity)
    post.assert_not_called()
    assert not (config.state_dir / "status.json").exists()
