"""Retained-data setup: synthetic inventories only, no host services or secrets."""
import hashlib
import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_host as host
from deploy.linux import native_install as install
from deploy.linux import native_package as package
from deploy.linux import native_preinstall as preinstall
from deploy.linux import native_runtime as runtime
from deploy.linux import native_setup as setup
from deploy.linux import native_upgrade as upgrade


@pytest.fixture
def retained(tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir()
    old, new = tmp_path / 'old', tmp_path / 'new'
    for root in (old, new):
        root.mkdir()
        (root / 'deploy/linux').mkdir(parents=True)
        (root / 'deploy/linux/native_upgrade.py').write_text('# synthetic coordinator')
    site = setup.settings(server='192.0.2.10', port=443, mode='docker')
    site_path = tmp_path / 'site.toml'
    site_path.write_text(setup.render_site(site))
    for name, value in {
        'installed.json': {'release': str(old), 'manifest_sha256': 'old-digest'},
        'pending-release.json': {'schema_version': 1, 'release': 'new'},
        'host-prepared.json': {'directory': '/retained/db'},
        'package-install.json': {'release': 'old', 'status': 'configured',
                                 'site_sha256': install.site_digest(site)},
    }.items():
        (state / name).write_text(json.dumps(value))
    calls = []
    monkeypatch.setattr(install, 'STATE', state)
    monkeypatch.setattr(install, 'SITE', site_path)
    monkeypatch.setattr(install, 'trusted', lambda path: b'docker' if path.name == 'clickhouse-package-mode' else path.read_bytes())
    monkeypatch.setattr(install, 'inventory', lambda release: (
        old if release == 'old' else new, {'python': '/verified/python'}, release + '-digest'))
    monkeypatch.setattr(install, 'environment', dict)
    monkeypatch.setattr(setup.platform, 'freedesktop_os_release', lambda: {'ID': 'debian', 'VERSION_ID': '13'})
    monkeypatch.setattr(setup.platform, 'machine', lambda: 'x86_64')
    monkeypatch.setattr(setup, 'wait_api', lambda: None)
    monkeypatch.setattr(host, 'Host', lambda: SimpleNamespace(
        receipt=lambda: calls.append('receipt'),
        prepare=lambda *a, **kw: pytest.fail('must not prepare storage'),
        configure=lambda: pytest.fail('must not bootstrap'),
        write=lambda *a: pytest.fail('must not publish fresh configuration or CA')))
    monkeypatch.setattr(host, 'administrative_lock', nullcontext)
    monkeypatch.setattr(upgrade, 'operation_lock', lambda root: nullcontext())
    transactions = tmp_path / 'transactions'
    transactions.mkdir()
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(upgrade, 'preflight', lambda: (old, tmp_path / 'recovery'))
    monkeypatch.setattr(runtime, 'no_transaction', lambda: None)
    monkeypatch.setattr(upgrade, 'package_metadata', lambda root: {'version': '1.0-1~deb13' if root == old else '2.0-1~deb13'})
    args = SimpleNamespace(reuse_existing=True, server=None, bind=None, port=None, clickhouse_mode=None,
                           uuid=None, directory=None, backup_root=None, non_interactive=True, new_owner_code=False)
    return SimpleNamespace(state=state, old=old, new=new, calls=calls, args=args)


def test_setup_reuse_selects_staged_candidate_and_only_new_coordinator(retained, monkeypatch):
    monkeypatch.setattr(setup.os, 'chdir', lambda root: retained.calls.append(('cwd', root)))
    monkeypatch.setattr(setup.os, 'execve', lambda *args: retained.calls.append(args))
    setup.configure(retained.args)
    executable, argv, env = retained.calls[1]
    assert executable == '/verified/python' and env == {}
    assert argv == ['/verified/python', '-I', '-B', str(retained.new / 'deploy/linux/native_upgrade.py'),
                    'reuse-existing', 'new']
    assert retained.calls[0] == ('cwd', retained.new)
    assert json.loads((retained.state / 'installed.json').read_text())['release'] == str(retained.old)


def test_reuse_without_saved_installation_never_enters_fresh_setup(retained):
    (retained.state / 'installed.json').unlink()
    with pytest.raises(RuntimeError, match='native_reuse_installation_required'):
        setup.configure(retained.args)


def test_reuse_missing_site_refuses_before_fresh_interactive_questions(retained, monkeypatch):
    install.SITE.unlink()
    retained.args.non_interactive = False
    monkeypatch.setattr('builtins.input', lambda prompt: pytest.fail('reuse must never ask fresh setup questions'))
    with pytest.raises(RuntimeError, match='native_reuse_installation_required'):
        setup.configure(retained.args)


def test_stage_retained_installation_keeps_accepted_registry(retained, monkeypatch, capsys):
    monkeypatch.setattr(install.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(install, 'atomic', lambda path, value: path.write_text(json.dumps(value)))
    before = (retained.state / 'installed.json').read_bytes()
    assert install.main(['stage', 'new']) == 0
    assert (retained.state / 'installed.json').read_bytes() == before
    assert json.loads((retained.state / 'pending-release.json').read_text())['release'] == 'new'
    output = capsys.readouterr().out
    assert 'sli-setup --reuse-existing' in output
    assert 'запустите' in output.lower()


def test_postinst_stages_removed_install_before_legacy_dispatch():
    body = package.scripts('new', '2.0-1~deb13')['postinst']
    assert body.index('test -e /var/lib/sli/state/reuse-package.json') < body.index('dispatch configure-package')
    assert body.index('sli-native-install stage new') < body.index('dispatch configure-package')


@pytest.mark.parametrize('action,installed,expected', [('install', True, True), ('install', False, False),
                                                      ('upgrade', True, False)])
def test_preinst_records_retained_install_independently_of_old_dpkg_version(tmp_path, monkeypatch, action, installed, expected):
    state = tmp_path / 'var/lib/sli/state'
    state.mkdir(parents=True)
    if installed:
        (state / 'installed.json').write_text('{}')
    monkeypatch.setattr(preinstall, 'trusted', lambda path: None)
    preinstall.package_install(action, 'new', root=tmp_path)
    marker = state / 'reuse-package.json'
    assert marker.exists() == expected
    if expected:
        assert json.loads(marker.read_text()) == {'schema_version': 1, 'release': 'new'}
        preinstall.package_install('upgrade', 'next', root=tmp_path)
        assert not marker.exists()


def test_reuse_enters_normal_transaction_with_new_candidate(retained, monkeypatch):
    monkeypatch.setattr(upgrade, 'prepare', lambda *a, **kw: retained.calls.append(('prepare', a, kw)))
    monkeypatch.setattr(upgrade, 'configure_package', lambda *a: retained.calls.append(('activate', a)))
    upgrade.reuse_existing('new')
    preparation, activation = retained.calls
    assert preparation[0] == 'prepare' and preparation[1][0] == 'new'
    assert preparation[2] == {'target_version': '2.0-1~deb13', 'previous_version': '1.0-1~deb13',
                              'reuse_existing': True}
    assert activation == ('activate', ('new', '2.0-1~deb13'))


@pytest.mark.parametrize('reason', ['native_transaction_pending', 'native_service_user_conflict'])
def test_reuse_refuses_unfinished_transaction_or_foreign_identity_before_changes(retained, monkeypatch, reason):
    def refuse():
        raise RuntimeError(reason)
    if reason == 'native_transaction_pending':
        monkeypatch.setattr(runtime, 'no_transaction', refuse)
    else:
        monkeypatch.setattr(upgrade, 'preflight', refuse)
    monkeypatch.setattr(upgrade, 'prepare', lambda *a, **kw: pytest.fail('must refuse before preparation'))
    with pytest.raises(RuntimeError, match=reason):
        upgrade.reuse_existing('new')
    assert not retained.calls


def test_reuse_same_accepted_release_is_idempotent(retained, monkeypatch):
    monkeypatch.setattr(upgrade, 'preflight', lambda: (retained.new, Path('/saved/recovery')))
    monkeypatch.setattr(install, 'configure_guarded', lambda release: retained.calls.append(('accept', release)))
    monkeypatch.setattr(upgrade, 'prepare', lambda *a, **kw: pytest.fail('no second checkpoint or migrations'))
    upgrade.reuse_existing('new')
    upgrade.reuse_existing('new')
    assert retained.calls == [('accept', 'new'), ('accept', 'new')]


def test_reuse_candidate_failure_uses_normal_rollback_entry(retained, monkeypatch):
    monkeypatch.setattr(upgrade, 'prepare', lambda *a, **kw: None)
    def activate(*args):
        raise RuntimeError('native_install_api_unready')
    monkeypatch.setattr(upgrade, 'configure_package', activate)
    with pytest.raises(RuntimeError, match='native_install_api_unready'):
        upgrade.reuse_existing('new')


def test_retained_readiness_uses_new_code_and_only_credential_paths(retained, monkeypatch):
    calls = []
    monkeypatch.setattr(install, 'command', lambda argv, **kw: calls.append((argv, kw)))
    upgrade.check_reused_databases('new')
    argv, options = calls[0]
    assert argv[:6] == ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=sli-reuse-check']
    assert argv[-5:] == ['-I', '-B', str(retained.new / 'deploy/linux/native_upgrade.py'), 'check-reuse', 'new']
    for name in ('postgres_password',):
        assert f'--property=LoadCredential={name}:{install.SECRETS / name}' in argv
    assert options['timeout'] is None  # Inner ready adapter owns the progress watch.


@pytest.mark.parametrize('reason', ['native_service_user_conflict', 'native_transaction_pending'])
def test_reuse_cli_preserves_public_refusal_code(retained, monkeypatch, capsys, reason):
    monkeypatch.setattr(upgrade, '__file__', str(retained.new / 'deploy/linux/native_upgrade.py'))
    monkeypatch.setattr(upgrade.sys, 'executable', '/verified/python')
    monkeypatch.setattr(upgrade.sys, 'path', list(upgrade.sys.path))
    monkeypatch.setattr(upgrade.os, 'geteuid', lambda: 0, raising=False)
    def refuse():
        raise RuntimeError(reason)
    monkeypatch.setattr(upgrade, 'preflight', refuse)
    assert upgrade.main(['reuse-existing', 'new']) == 1
    assert f'reason_code={reason}' in capsys.readouterr().err


@pytest.mark.parametrize('tampered', [False, True])
def test_resume_launcher_selects_hash_bound_new_coordinator(tmp_path, monkeypatch, tampered):
    helper = tmp_path / 'helpers/native_runtime.py'
    helper.parent.mkdir()
    helper.write_text('import json\n'
                      'def trusted(path): return path.read_bytes()\n'
                      'def document(path): return json.loads(trusted(path))\n')
    candidate = tmp_path / 'new'
    script = candidate / 'deploy/linux/native_upgrade.py'
    script.parent.mkdir(parents=True)
    script.write_bytes(b'# verified candidate')
    helper.with_name('native_install.py').write_text(
        'from pathlib import Path\n'
        f'def inventory(release):\n assert release == "new"\n return Path({str(candidate)!r}), '
        '{"python": "/verified/new-python"}, "new-digest"\n'
        'def environment(): return {"PATH": "/usr/bin"}\n')
    transactions = tmp_path / 'transactions'
    journal = transactions / ('a' * 32) / 'journal.json'
    journal.parent.mkdir(parents=True)
    journal.write_text(json.dumps({'target_version': '2.0-1~deb13', 'created_at_utc': '2026-11-01',
                                   'reuse_existing': True, 'coordinator_release': 'new',
                                   'coordinator_manifest_sha256': 'new-digest',
                                   'coordinator_sha256': hashlib.sha256(script.read_bytes()).hexdigest()}))
    if tampered:
        script.write_bytes(b'# modified after checkpoint')
    monkeypatch.setattr(upgrade, 'RUNTIME_HELPER', helper)
    monkeypatch.setattr(upgrade, 'TRANSACTIONS', transactions)
    monkeypatch.setattr(Path, 'lstat', lambda path: SimpleNamespace(st_uid=0, st_mode=0o755))
    calls = []
    monkeypatch.setattr(upgrade.os, 'execve', lambda *args: calls.append(args))
    if tampered:
        with pytest.raises(RuntimeError, match='native_reuse_coordinator_mismatch'):
            upgrade.launch(None, None, action='resume-package', arguments=['2.0-1~deb13'])
        assert calls == []
    else:
        upgrade.launch(None, None, action='resume-package', arguments=['2.0-1~deb13'])
        assert calls == [('/verified/new-python', ['/verified/new-python', '-I', '-B', str(script),
                                                  'resume-package', '2.0-1~deb13'], {'PATH': '/usr/bin'})]
