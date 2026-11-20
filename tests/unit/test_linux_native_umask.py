"""Installer-created parents must not inherit the administrator's umask."""
import os
import stat
from types import SimpleNamespace

import pytest

from deploy.linux import native_host as host
from deploy.linux import native_preinstall as pre


@pytest.fixture
def directory_owner(tmp_path, monkeypatch):
    """Model ownership independently of the test runner's UID (including root)."""
    owner = [999, 999]
    original = type(tmp_path).stat

    def directory_stat(path, **kwargs):
        values = list(original(path, **kwargs))
        values[4:6] = owner
        return os.stat_result(values)

    monkeypatch.setattr(type(tmp_path), 'stat', directory_stat)
    return owner


def test_directory_sets_new_parent_permissions_without_touching_existing(tmp_path, monkeypatch, directory_owner):
    existing = tmp_path / 'usr'
    existing.mkdir()
    modes, owners = {}, {}
    chmod = type(tmp_path).chmod

    def record_mode(path, mode, **kwargs):
        modes[path] = mode
        chmod(path, mode, **kwargs)

    monkeypatch.setattr(type(tmp_path), 'chmod', record_mode)
    monkeypatch.setattr(os, 'chown', lambda path, uid, gid: owners.update({path: (uid, gid)}), raising=False)
    monkeypatch.setattr(host, 'pwd', SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=0)))
    monkeypatch.setattr(host, 'grp', SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=0)))
    before = os.umask(0o077)
    try:
        host.Host(tmp_path).directory('/usr/lib/sli', 0o755)
    finally:
        os.umask(before)
    assert modes[existing / 'lib'] == 0o755
    assert modes[existing / 'lib/sli'] == 0o755
    assert owners[existing / 'lib'] == (0, 0)
    assert existing not in modes and existing not in owners
    assert tmp_path not in modes and tmp_path not in owners


@pytest.mark.skipif(os.name == 'nt', reason='POSIX modes and ownership; Linux CI')
def test_preinstall_parents_ignore_umask(tmp_path, monkeypatch):
    monkeypatch.setattr(pre, 'trusted', lambda path: None)
    monkeypatch.setattr(os, 'chown', lambda *args: None)
    monkeypatch.setattr(pre, 'command', lambda argv: '' if '--listpackage' in argv else argv[-1])
    existing = tmp_path / 'etc'
    existing.mkdir(mode=0o711)
    before = os.umask(0o077)
    try:
        pre.prepare(tmp_path)
    finally:
        os.umask(before)
    for name, mode in {'var': 0o755, 'var/lib': 0o755, 'var/lib/sli': 0o755,
                       'var/lib/sli/state': 0o700, 'etc/postgresql-common': 0o755,
                       'var/lib/sli/state/createcluster.conf.before': 0o600,
                       'var/lib/sli/state/vendor-prepared.json': 0o600,
                       'etc/postgresql-common/createcluster.conf': 0o644}.items():
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == mode, name
    assert stat.S_IMODE(existing.stat().st_mode) == 0o711
    assert not (existing / 'systemd').exists()


@pytest.mark.parametrize('mode', [0o755, 0o750, 0o700, 0o711, 0o2770])
def test_created_directory_has_explicit_owner_and_mode(tmp_path, monkeypatch, directory_owner, mode):
    modes, owners = {}, {}
    chmod = type(tmp_path).chmod

    def record_mode(path, value, **kwargs):
        modes[path] = value
        chmod(path, value, **kwargs)

    monkeypatch.setattr(type(tmp_path), 'chmod', record_mode)
    monkeypatch.setattr(os, 'chown', lambda path, uid, gid: owners.update({path: (uid, gid)}), raising=False)
    target = tmp_path / 'created/leaf'
    previous = os.umask(0o077)
    try:
        pre.ensure_directory(target, mode, 123, 456)
    finally:
        os.umask(previous)
    assert modes == {target.parent: 0o755, target: mode}
    assert owners == {target.parent: (0, 0), target: (123, 456)}


@pytest.mark.skipif(os.name == 'nt', reason='POSIX symlink; Linux CI')
def test_directory_helper_refuses_symlink_parent(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (tmp_path / 'link').symlink_to(outside, target_is_directory=True)
    with pytest.raises(RuntimeError, match='native_symlink_forbidden'):
        pre.ensure_directory(tmp_path / 'link/child')
    assert list(outside.iterdir()) == []


def test_directory_helper_preserves_exclusive_creation(tmp_path):
    target = tmp_path / 'existing'
    target.mkdir()
    with pytest.raises(FileExistsError):
        pre.ensure_directory(target, exist_ok=False)
    with pytest.raises(RuntimeError, match='native_directory_required'):
        (tmp_path / 'file').touch()
        pre.ensure_directory(tmp_path / 'file/child')


@pytest.mark.parametrize('name', ['native_host.py', 'native_install.py', 'native_runtime.py',
                                 'native_backup.py', 'native_upgrade.py', 'native_setup.py'])
def test_installed_helpers_import_in_isolated_python(tmp_path, name):
    import shutil
    import subprocess
    import sys
    from pathlib import Path

    from deploy.linux import native_package

    source = Path(native_package.__file__).parent
    for filename in native_package.HELPERS:
        shutil.copyfile(source / filename, tmp_path / filename)
    result = subprocess.run([sys.executable, '-I', str(tmp_path / name), '--help'],
                            cwd=tmp_path, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('owner', [(0, 0), (123, 0), (0, 456)])
def test_directory_chowns_only_mismatched_owner(tmp_path, monkeypatch, directory_owner, owner):
    directory_owner[:] = owner
    calls = []
    monkeypatch.setattr(os, 'chown', lambda *args: calls.append(args), raising=False)
    target = tmp_path / 'created/leaf'
    pre.ensure_directory(target)
    assert calls == ([] if owner == (0, 0) else [(target.parent, 0, 0), (target, 0, 0)])


def test_directory_ownership_failure_is_not_suppressed(tmp_path, monkeypatch, directory_owner):
    def denied(*args):
        raise PermissionError('ownership denied')

    monkeypatch.setattr(os, 'chown', denied, raising=False)
    with pytest.raises(PermissionError, match='ownership denied'):
        pre.ensure_directory(tmp_path / 'created')
