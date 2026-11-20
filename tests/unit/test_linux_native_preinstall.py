"""Vendor autostart guard runs before dependency configuration."""

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_host as host
from deploy.linux import native_preinstall as pre


@pytest.fixture
def debian_tree(tmp_path, monkeypatch):
    """Synthetic Debian metadata; never chown host files or look up real users."""
    postgres_paths = {tmp_path / name for name in ('etc/postgresql', 'var/lib/postgresql')}
    for path in postgres_paths:
        path.mkdir(parents=True)
    config = tmp_path / 'etc/postgresql-common/createcluster.conf'
    config.parent.mkdir(parents=True)
    config.write_text('# Debian default\n')
    original_lstat = Path.lstat

    def metadata(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        return SimpleNamespace(st_uid=123 if path in postgres_paths else 0,
                               st_mode=stat.S_IFDIR | 0o755 if stat.S_ISDIR(info.st_mode)
                               else stat.S_IFREG | 0o644)

    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(pre, 'postgres_uid', lambda: 123)
    return tmp_path


def test_prepare_after_postgresql_common(debian_tree, monkeypatch):
    # Model only the POSIX mask operation on Windows; all guard checks run.
    # The temporary tree has no system ownership to provision.
    monkeypatch.setattr(pre, 'ensure_directory', lambda path, mode=0o755:
                        path.mkdir(mode=mode, parents=True, exist_ok=True))
    links = {}
    original_link = Path.is_symlink
    monkeypatch.setattr(Path, 'is_symlink', lambda path: path in links or original_link(path))
    monkeypatch.setattr(Path, 'symlink_to', lambda path, target: links.update({path: target}))
    diversions = {}

    def command(argv):
        source = argv[-1]
        if '--listpackage' in argv:
            return 'LOCAL' if source in diversions else ''
        if '--truename' in argv:
            return diversions.get(source, source)
        diversions[source] = argv[-2]
        return ''

    monkeypatch.setattr(pre, 'command', command)
    pre.prepare(debian_tree)
    state = debian_tree / 'var/lib/sli/state'
    assert (state / 'createcluster.conf.before').read_text() == '# Debian default\n'
    assert (state / 'vendor-prepared.json').is_file()
    assert links == {} and diversions == {}
    assert 'create_main_cluster = false\n' in (
        debian_tree / 'etc/postgresql-common/createcluster.conf').read_text()


@pytest.mark.parametrize('name', ['etc/postgresql-common/createcluster.conf',
                                  'etc/systemd/system', 'var/lib/sli/state'])
@pytest.mark.parametrize('case', ['postgres_owner', 'group_write', 'symlink'])
def test_administrative_paths_remain_strict(debian_tree, monkeypatch, name, case):
    path = debian_tree / name
    if not path.exists():
        path.mkdir(parents=True)
    original_lstat, original_link = Path.lstat, Path.is_symlink

    def metadata(item, *args, **kwargs):
        info = original_lstat(item, *args, **kwargs)
        if item == path:
            return SimpleNamespace(st_uid=123 if case == 'postgres_owner' else info.st_uid,
                                   st_mode=info.st_mode | (0o020 if case == 'group_write' else 0))
        return info

    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(Path, 'is_symlink', lambda item: item == path and case == 'symlink' or original_link(item))
    with pytest.raises(RuntimeError, match='native_path_untrusted|native_symlink_forbidden'):
        pre.prepare(debian_tree)
    assert not (debian_tree / 'var/lib/sli/state/vendor-prepared.json').exists()


@pytest.mark.parametrize('implementation', ['preinstall', 'host'])
@pytest.mark.parametrize('name', ['etc/postgresql', 'var/lib/postgresql', 'var/lib/clickhouse'])
@pytest.mark.parametrize('case', ['root', 'postgres', 'group_write', 'root_group_write', 'nonempty', 'world_write',
                                  'symlink', 'foreign_owner', 'nonsystem_postgres', 'file',
                                  'parent_owner', 'parent_write', 'parent_symlink', 'missing_postgres'])
def test_empty_vendor_directory_policy(tmp_path, monkeypatch, implementation, name, case):
    path = tmp_path / name
    path.mkdir(parents=True)
    if case == 'nonempty':
        (path / 'existing').touch()
    original_lstat = Path.lstat
    original_link = Path.is_symlink

    def metadata(item, *args, **kwargs):
        info = original_lstat(item, *args, **kwargs)
        uid, mode = 0, stat.S_IFDIR | 0o755
        if item == path:
            uid = 123 if case in {'postgres', 'group_write', 'nonsystem_postgres', 'missing_postgres'} else 234 if case == 'foreign_owner' else 0
            mode |= 0o020 if case in {'group_write', 'root_group_write'} else 0o002 if case == 'world_write' else 0
            if case == 'file':
                mode = stat.S_IFREG | 0o644
        if item == path.parent:
            uid = 123 if case == 'parent_owner' else uid
            mode |= 0o020 if case == 'parent_write' else 0
        return SimpleNamespace(st_uid=uid, st_mode=mode, st_size=info.st_size)

    monkeypatch.setattr(Path, 'lstat', metadata)
    monkeypatch.setattr(Path, 'is_symlink', lambda item: (
        item == path and case == 'symlink' or item == path.parent and case == 'parent_symlink' or original_link(item)))
    postgres = SimpleNamespace(pw_uid=1000 if case == 'nonsystem_postgres' else 123)
    monkeypatch.setattr(pre, 'postgres_uid', lambda: None if case == 'missing_postgres' else postgres.pw_uid)
    monkeypatch.setattr(host, 'account', lambda name: None if case == 'missing_postgres' else postgres)
    check = (lambda: pre.database_directory(path, '/' + name)) if implementation == 'preinstall' else (
        lambda: host.Host(tmp_path).database_directory('/' + name))
    allowed = case in {'root', 'root_group_write'} or case in {'postgres', 'group_write'} and 'postgresql' in name
    if allowed:
        check()
    else:
        code = 'native_existing_database' if case in {'nonempty', 'file'} else 'native_'
        with pytest.raises(RuntimeError, match=code):
            check()


def test_preinstall_diagnostic_identifies_path_reason_and_remedy(tmp_path, monkeypatch):
    monkeypatch.setattr(pre, 'trusted', lambda path: None)
    path = tmp_path / 'etc/postgresql'
    path.mkdir(parents=True)
    (path / 'existing').touch()
    with pytest.raises(RuntimeError) as caught:
        pre.prepare(tmp_path)
    message = pre.diagnostic(caught.value)
    assert '/etc/postgresql' in message
    assert 'empty directory' in message
    assert 'existing database' in message
    assert str(tmp_path) not in message
    assert 'Use a clean Debian' not in message


def test_vendor_guard_preserves_original_config_and_is_repeatable(tmp_path, monkeypatch):
    monkeypatch.setattr(pre, 'trusted', lambda path: None)
    monkeypatch.setattr(pre, 'ensure_directory', lambda path, mode=0o755:
                        path.mkdir(mode=mode, parents=True, exist_ok=True))
    config = tmp_path / 'etc/postgresql-common/createcluster.conf'
    config.parent.mkdir(parents=True)
    config.write_text('# existing setting\n')
    diversions = {}
    def command(argv):
        source = argv[-1]
        if '--listpackage' in argv:
            return 'LOCAL' if source in diversions else ''
        if '--truename' in argv:
            return diversions.get(source, source)
        diversions[source] = argv[-2]
        return ''
    monkeypatch.setattr(pre, 'command', command)
    if __import__('os').name == 'nt':
        pytest.skip('POSIX vendor mask symlink; Linux CI')
    pre.prepare(tmp_path)
    before = config.read_bytes()
    pre.prepare(tmp_path)
    assert config.read_bytes() == before
    assert 'create_main_cluster = false\n' in config.read_text()
    assert (tmp_path / 'var/lib/sli/state/createcluster.conf.before').read_text() == '# existing setting\n'


@pytest.mark.parametrize('name', ['etc/postgresql/18/main', 'var/lib/postgresql/18/main', 'var/lib/clickhouse'])
def test_preinstall_refuses_foreign_data_before_writes(tmp_path, name, monkeypatch):
    monkeypatch.setattr(pre, 'trusted', lambda path: None)
    path = tmp_path / name
    path.mkdir(parents=True)
    (path / 'existing').touch()
    with pytest.raises(RuntimeError, match='native_existing_database'):
        pre.prepare(tmp_path)
    assert not (tmp_path / 'var/lib/sli/state').exists()


def test_postinst_stages_fresh_install_instead_of_starting_database():
    from deploy.linux.native_package import scripts
    body = scripts('beta', '1.0-1~deb13')['postinst']
    assert 'sli-native-install stage beta' in body
    assert 'dispatch configure-package' in body
