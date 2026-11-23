from contextlib import nullcontext
from io import BytesIO
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from deploy.linux import native_backup as backup
from deploy.linux import native_backup_settings as settings
from deploy.linux import native_install as install


PATH = "/mnt/sli-archives"
IDENTITY = {"uuid": "archive-uuid", "target": "/mnt/sli-archives", "fsroot": "/"}


@pytest.fixture
def coordinator(monkeypatch):
    state, timer = {}, []
    monkeypatch.setattr(settings, "read_policy", lambda: state.copy() or None)
    monkeypatch.setattr(settings, "save_policy", state.update)
    monkeypatch.setattr(settings, "operation", nullcontext)
    monkeypatch.setattr(install, "backup_schedule", lambda: "disabled")
    monkeypatch.setattr(settings.clickhouse, "site_configuration", lambda: {})
    monkeypatch.setattr(settings, "storage_identity", lambda path, **kwargs: IDENTITY)
    monkeypatch.setattr(settings, "apply_schedule", timer.append)
    return state, timer


def save(revision, enabled, path=PATH):
    return settings.handle({"action": "set", "enabled": enabled, "path": path, "revision": revision})


def test_fresh_opt_in_and_revision_conflict(coordinator):
    state, timer = coordinator
    initial = settings.handle({"action": "get"})
    assert initial == {"ok": True, "enabled": False, "path": None, "revision": "0",
                       "storage_status": "unconfigured"}
    enabled = save(initial["revision"], True)
    assert enabled["enabled"] and enabled["storage_status"] == "ready"
    assert enabled["revision"] != initial["revision"]
    assert save(initial["revision"], False) == {"ok": False, "error": "backup_settings_revision_conflict"}
    assert state["enabled"] is True and timer == [True]


def test_disabling_retains_previous_path_when_volume_is_missing(coordinator, monkeypatch):
    state, timer = coordinator
    enabled = save("0", True)

    def missing(*args, **kwargs):
        raise settings.SettingsError("native_backup_root_invalid")

    monkeypatch.setattr(settings, "storage_identity", missing)
    assert settings.handle({"action": "get"})["storage_status"] == "unavailable"
    disabled = save(enabled["revision"], False, None)
    assert disabled["enabled"] is False and disabled["path"] == PATH
    assert disabled["storage_status"] == "unavailable"
    assert state["identity"] == IDENTITY and timer == [True, False]


def test_failed_scheduler_leaves_effective_policy(coordinator, monkeypatch):
    state, timer = coordinator
    enabled = save("0", True)

    def apply(enabled):
        timer.append(enabled)
        if not enabled:
            raise OSError("private systemd error")

    monkeypatch.setattr(settings, "apply_schedule", apply)
    assert save(enabled["revision"], False) == {"ok": False, "error": "backup_settings_unavailable"}
    assert timer == [True, False, True]
    assert state["enabled"] and state["revision"] == enabled["revision"]


def test_failed_durable_write_restores_old_policy_and_schedule(coordinator, monkeypatch):
    state, timer = coordinator
    enabled = save("0", True)

    def fail_after_replace(updated):
        state.update(updated)
        if not updated["enabled"]:
            raise OSError("directory sync failed")

    monkeypatch.setattr(settings, "save_policy", fail_after_replace)
    assert save(enabled["revision"], False) == {"ok": False, "error": "backup_settings_unavailable"}
    assert state["enabled"] and state["revision"] == enabled["revision"]
    assert timer == [True, False, True]


def test_legacy_copy_adopted_only_on_explicit_enabled_separate_root(coordinator, monkeypatch):
    state, timer = coordinator
    monkeypatch.setattr(install, "backup_schedule", lambda: "enabled")
    monkeypatch.setattr(settings.clickhouse, "site_configuration", lambda: {"backup_root": PATH})
    result = settings.handle({"action": "get"})
    assert result["path"] == PATH and result["enabled"]
    assert state["identity"] == IDENTITY
    assert not timer


def test_legacy_local_timer_is_disabled_without_an_eligible_volume(coordinator, monkeypatch):
    state, timer = coordinator
    monkeypatch.setattr(install, "backup_schedule", lambda: "enabled")
    assert settings.handle({"action": "get"})["storage_status"] == "unconfigured"
    assert not state["enabled"] and timer == [False]


def test_selection_rejects_a_separate_partition_of_the_database_disk(monkeypatch, tmp_path):
    selected = tmp_path / "volume"
    selected.mkdir()
    data = tmp_path / "database"
    data.mkdir()
    monkeypatch.setattr(settings, "canonical_path", lambda value: selected)
    monkeypatch.setattr(settings.native_host, "MOUNT", str(data))
    monkeypatch.setattr(settings.native_host, "Host", lambda: SimpleNamespace(backup_trusted=lambda path: None))
    monkeypatch.setattr(backup, "same_disk", lambda source, database: (source, database) == (selected, data))
    with pytest.raises(settings.SettingsError, match="native_backup_root_same_device"):
        settings.storage_identity(PATH)


def test_changed_mount_is_unavailable_without_selecting_or_creating_new_storage(coordinator, monkeypatch):
    state, timer = coordinator
    enabled = save("0", True)
    monkeypatch.setattr(settings, "storage_identity", lambda *args, **kwargs: dict(IDENTITY, uuid="new-volume"))
    assert settings.handle({"action": "get"})["storage_status"] == "unavailable"
    assert save(enabled["revision"], True) == {"ok": False, "error": "native_backup_root_mount_mismatch"}
    assert state["identity"] == IDENTITY and timer == [True]
    with pytest.raises(settings.SettingsError, match="native_backup_root_mount_mismatch"):
        with settings.selected_storage(state, create=True):
            pytest.fail("capture on replacement mount")


def test_enable_with_insufficient_space_never_changes_schedule(coordinator, monkeypatch):
    state, timer = coordinator

    def full(path, *, capacity):
        assert path == PATH and capacity
        raise settings.native_host.HostError("native_backup_root_insufficient_space")

    monkeypatch.setattr(settings, "storage_identity", full)
    assert save("0", True) == {"ok": False, "error": "native_backup_root_insufficient_space"}
    assert not state["enabled"] and not timer


@pytest.mark.parametrize("frame", [
    b'{"action":"get","path":null}\n',
    b'{"action":"get","action":"set"}\n',
    b'{"action":"get"}',
    b' ' * settings.MAX_FRAME + b'\n',
    b'\xff\n',
])
def test_protocol_rejects_invalid_frame(frame):
    with pytest.raises(settings.SettingsError, match="backup_settings_invalid"):
        settings.read_request(BytesIO(frame))


@pytest.mark.parametrize("uid", [1001, 1002])
def test_peer_uid_is_checked_before_reading(coordinator, monkeypatch, uid):
    monkeypatch.setattr(settings.socket, "SO_PEERCRED", 17, raising=False)
    wrote = []
    reads = []
    connection = SimpleNamespace(
        getsockopt=lambda *args: struct.pack("3i", 123, uid, 42),
        settimeout=lambda seconds: None,
        makefile=lambda mode: reads.append(mode) or BytesIO(b'{"action":"get"}\n'),
        sendall=wrote.append,
    )
    settings.serve_connection(connection, allowed_uid=1001)
    if uid == 1001:
        assert reads == ["rb"] and wrote[0].endswith(b"\n") and b'"storage_status":"unconfigured"' in wrote[0]
    else:
        assert not reads and not wrote


def test_disabled_capture_never_walks_or_writes_the_checkpoint_root(monkeypatch):
    from deploy.linux import backup as engine

    monkeypatch.setattr(engine, "backup_lock", lambda root: nullcontext())
    monkeypatch.setattr(settings, "read_policy", settings.initial_policy)
    monkeypatch.setattr(backup, "capture_locked", lambda *args, **kwargs: pytest.fail("capture called"))
    assert backup.capture() is None


def test_regular_capture_uses_selected_root_and_canonical_lock(monkeypatch):
    from deploy.linux import backup as engine

    seen = []
    root = Path("/mnt/sli-archives") / settings.ARCHIVES
    check = object()
    monkeypatch.setattr(engine, "backup_lock", lambda path: seen.append(path) or nullcontext())
    monkeypatch.setattr(settings, "read_policy", lambda: dict(settings.initial_policy(), enabled=True))
    monkeypatch.setattr(settings.native_host, "administrative_lock", nullcontext)
    monkeypatch.setattr(settings.native_runtime, "no_transaction", lambda: None)
    monkeypatch.setattr(settings, "selected_storage", lambda state, create: nullcontext((root, check)))
    monkeypatch.setattr(backup, "capture_locked", lambda path, *, storage_check: seen.append((path, storage_check)))
    backup.capture()
    assert seen == [backup.ROOT, (root, check)]


def test_authoritative_disabled_policy_is_never_started_by_old_transaction(monkeypatch):
    monkeypatch.setattr(settings, "read_policy", settings.initial_policy)
    monkeypatch.setattr(install, "command", lambda *args: pytest.fail("disabled timer restarted"))
    install.start_backup_schedule("enabled")
    install.start_backup_schedule(None)
