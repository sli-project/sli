"""File restore contracts on disposable trees, with POSIX ownership calls captured."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_host, native_runtime
from deploy.linux import restore_existing as restore


@pytest.fixture
def trees(tmp_path, monkeypatch):
    # Python 3.10 test runner; production Python provides file_digest.
    if not hasattr(hashlib, "file_digest"):
        monkeypatch.setattr(hashlib, "file_digest", lambda stream, algorithm: hashlib.new(algorithm, stream.read()), raising=False)
    source, target = tmp_path / "set", tmp_path / "data"
    (source / "files").mkdir(parents=True)
    target.mkdir()
    return source, target


@pytest.mark.parametrize("name", ["state", "recovery", "transactions", "drills", "backup-status"])
def test_replace_preserves_host_bytes_even_when_backup_contains_them(trees, name):
    source, target = trees
    for root, value in ((target, b"host state\x00"), (source / "files", b"old host state")):
        (root / name).mkdir()
        (root / name / "receipt").write_bytes(value)
    (target / "obsolete").write_bytes(b"remove me")
    (source / "files/payload").write_bytes(b"restored")
    restore.restore_files(source, target, replace_existing=True)
    assert (target / name / "receipt").read_bytes() == b"host state\x00"
    assert (target / "payload").read_bytes() == b"restored"
    assert not (target / "obsolete").exists()


@pytest.fixture
def native_file_permissions(monkeypatch):
    ownership = {}
    monkeypatch.setattr(native_host, "group", lambda name: SimpleNamespace(gr_gid=234) if name == "sli-data" else None)
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: ownership.update({Path(path): (uid, gid)}), raising=False)
    return ownership


def test_native_restore_repairs_docker_permissions_and_creates_unit_paths(trees, monkeypatch, native_file_permissions):
    source, target = trees
    (source / "files/logs").mkdir()
    (source / "files/logs/output").write_bytes(b"log")
    (target / "plugins").mkdir()
    (target / "plugins/active").write_bytes(b"installed plugin")
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    ownership, modes = native_file_permissions, {}
    monkeypatch.setattr(Path, "chmod", lambda path, mode: modes.update({path: mode}))
    restore.restore_files(source, target, replace_existing=True)
    assert modes[target] == 0o755
    for name, (mode, _) in native_runtime.DATA_DIRECTORIES.items():
        assert (target / name).is_dir()
        if name != "plugins":
            assert ownership[target / name] == (0, 234)
            assert modes[target / name] == mode == 0o2770
    assert ownership[target / "logs/output"] == (0, 234)
    assert modes[target / "logs/output"] == 0o660
    assert (target / "plugins/active").read_bytes() == b"installed plugin"
    assert target / "plugins/active" not in ownership


def test_native_files_validation_does_not_require_group_or_change_trees(trees, monkeypatch):
    source, target = trees
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setattr(native_host, "group", lambda name: pytest.fail("read-only validation must not resolve groups"))
    (source / "files/payload").write_bytes(b"restored")
    before = backup.content_inventory(source, exclude_manifest=False)
    restore.validate_files_destination(source, target, replace_existing=False)
    assert backup.content_inventory(source, exclude_manifest=False) == before
    assert not list(target.iterdir())


def test_native_restore_without_group_fails_before_changing_destination(trees, monkeypatch):
    source, target = trees
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setattr(native_host, "group", lambda name: None)
    (source / "files/payload").write_bytes(b"restored")
    (target / "payload").write_bytes(b"existing")
    with pytest.raises(native_runtime.RuntimeErrorCode, match="^native_data_group_missing$"):
        restore.restore_files(source, target, replace_existing=True)
    assert (target / "payload").read_bytes() == b"existing"
    assert (source / "files/payload").read_bytes() == b"restored"


def test_docker_restore_keeps_original_data_inventory(trees, monkeypatch):
    source, target = trees
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "docker")
    (source / "files/payload").write_bytes(b"restored")
    restore.restore_files(source, target, replace_existing=False)
    assert backup.content_inventory(target) == backup.content_inventory(source / "files")


def test_service_state_alone_does_not_require_replacement(trees):
    source, target = trees
    (target / "state").mkdir()
    (target / "state/installed.json").write_bytes(b"preserve")
    (source / "files/payload").write_bytes(b"restored")
    restore.restore_files(source, target, replace_existing=False)
    assert (target / "state/installed.json").read_bytes() == b"preserve"


def test_user_data_still_requires_replace(trees):
    source, target = trees
    (target / "payload").write_bytes(b"existing")
    with pytest.raises(RuntimeError, match="requires_empty_files"):
        restore.restore_files(source, target, replace_existing=False)
