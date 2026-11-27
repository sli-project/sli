"""Inventory, root-only delivery and backup rejection, with local files/fakes."""
import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import backup, native_backup, native_runtime, sli_secrets
from deploy.linux.sli_core.ad_credential_secrets import MASTER_KEY_REF, MASTER_KEY_SETTING, MASTER_KEY_SPEC
from tests.unit.test_sli_secrets import ownership  # noqa: F401 -- shared filesystem fixture

ROOT = Path(__file__).resolve().parents[2]


def test_key_inventory_has_mandatory_backup_exclusion_and_api_delivery(tmp_path):
    manifest = sli_secrets.load_manifest()
    assert manifest[MASTER_KEY_REF] == MASTER_KEY_SPEC
    for field in ('backup', 'delivery', 'kind', 'group'):
        invalid = json.loads((ROOT / 'deploy/linux/secrets-manifest.json').read_text())
        invalid['secrets'][MASTER_KEY_REF].pop(field)
        path = tmp_path / 'manifest.json'
        path.write_text(json.dumps(invalid))
        with pytest.raises(sli_secrets.SecretError, match='manifest_invalid'):
            sli_secrets.load_manifest(path)


@pytest.mark.posix_only
def test_ensure_requires_explicit_protected_import_and_never_regenerates(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    with pytest.raises(sli_secrets.SecretError, match='protected_import_required'):
        sli_secrets.ensure(directory, names=[MASTER_KEY_REF])
    assert not (directory / MASTER_KEY_REF).exists()
    imported = tmp_path / 'imported'
    body = base64.b64encode(os.urandom(32))
    imported.write_bytes(body)
    imported.chmod(0o600)
    assert sli_secrets.ensure(directory, names=[MASTER_KEY_REF], imports={MASTER_KEY_REF: imported}) == 1
    target = directory / MASTER_KEY_REF
    assert target.read_bytes() == body and target.stat().st_mode & 0o777 == 0o600
    assert sli_secrets.ensure(directory, names=[MASTER_KEY_REF]) == 0
    imported.write_bytes(base64.b64encode(os.urandom(32)))
    with pytest.raises(sli_secrets.SecretError, match='rotation_required'):
        sli_secrets.ensure(directory, names=[MASTER_KEY_REF], imports={MASTER_KEY_REF: imported})
    assert target.read_bytes() == body
    with pytest.raises(sli_secrets.SecretError, match='single_import_required'):
        sli_secrets.ensure(directory, names=[MASTER_KEY_REF], imports={MASTER_KEY_REF: imported}, replace=True)


@pytest.mark.posix_only
def test_import_rejects_group_readable_key_without_changing_existing_files(tmp_path, ownership):
    imported = tmp_path / 'imported'
    imported.write_bytes(base64.b64encode(os.urandom(32)))
    imported.chmod(0o640)
    with pytest.raises(sli_secrets.SecretError, match='secret_unavailable_or_unprotected'):
        sli_secrets.ensure(tmp_path / 'secrets', names=[MASTER_KEY_REF], imports={MASTER_KEY_REF: imported})
    assert not (tmp_path / 'secrets' / MASTER_KEY_REF).exists()


def overlay():
    return yaml.safe_load((ROOT / 'deploy/linux/docker-compose.ad-credentials.yml').read_text())


@pytest.mark.legacy
@pytest.mark.parametrize('service', ['migrate', 'semantic', 'notification-delivery', 'backup'])
def test_workers_cannot_mount_master_key(service):
    config = overlay()
    config['services'][service] = config['services'].pop('api')
    with pytest.raises(sli_secrets.SecretError, match='api_only_mount_required'):
        sli_secrets.validate_compose(config)


@pytest.mark.legacy
@pytest.mark.parametrize('change', ['inline', 'empty_inline', 'user', 'entrypoint', 'tmpfs', 'target', 'file'])
def test_compose_rejects_plaintext_shared_mount_or_missing_private_delivery(change):
    config = overlay()
    sli_secrets.validate_compose(config)
    api = config['services']['api']
    if change in {'inline', 'empty_inline'}:
        api['environment'][MASTER_KEY_SETTING] = 'synthetic-value' if change == 'inline' else ''
    elif change == 'target':
        api['secrets'][0]['target'] = '/run/secrets/' + MASTER_KEY_REF
    elif change == 'file':
        api['environment'][MASTER_KEY_SETTING + '_FILE'] = '/run/secrets/' + MASTER_KEY_REF
    else:
        api.pop(change)
    with pytest.raises(sli_secrets.SecretError, match='ad_credentials:'):
        sli_secrets.validate_compose(config)


@pytest.mark.parametrize('enabled', [False, True])
def test_native_delivers_key_only_to_opted_in_api(enabled):
    config = {'profiles': ['light'], 'radius_pilot': False, 'bind': '192.0.2.1',
              'health_url': 'https://192.0.2.1:8443/api/health/ready', 'ad_credentials': enabled}
    for service in native_runtime.SERVICES | native_runtime.DOTNET_ONLY_SERVICES:
        env, selected = native_runtime.environment(service, config, dotnet=True)
        assert (MASTER_KEY_REF in selected) == (enabled and service == 'api')
        assert (MASTER_KEY_SETTING + '_FILE' in env) == (enabled and service == 'api')
    units = native_runtime.units(config) | native_runtime.dotnet_units('synthetic', config)
    consumers = {name for name, body in units.items() if MASTER_KEY_REF in body}
    assert consumers == ({'sli-dotnet-api.service'} if enabled else set())
    assert 'sli-api.service' not in units
    if enabled:
        assert 'LoadCredential=ad_credentials_master_key:/etc/sli/secrets/ad_credentials_master_key' in units['sli-dotnet-api.service']


def test_backup_rejects_actual_contaminated_tree_even_with_valid_checksums(tmp_path):
    tree = tmp_path / 'backup'
    (tree / 'companion/secrets').mkdir(parents=True)
    (tree / 'companion/secrets' / MASTER_KEY_REF).write_bytes(base64.b64encode(os.urandom(32)))
    with pytest.raises(ValueError, match='linux_backup_excluded_secret'):
        backup.content_inventory(tree)


def test_native_backup_rejects_manifest_that_reenables_key_backup(tmp_path, monkeypatch):
    from deploy.linux import native_install
    manifest = json.loads((ROOT / 'deploy/linux/secrets-manifest.json').read_text())
    manifest['secrets'][MASTER_KEY_REF]['backup'] = 'include'
    monkeypatch.setattr(native_install, 'trusted', lambda path: json.dumps(manifest).encode())
    with pytest.raises(RuntimeError, match='native_backup_inventory_invalid'):
        native_backup.secret_sources()


@pytest.mark.legacy
@pytest.mark.posix_only
def test_entrypoint_requires_private_tmpfs_before_publishing_key(tmp_path, monkeypatch):
    from deploy.linux import ad_credentials_entrypoint as entry
    destination = tmp_path / 'private' / MASTER_KEY_REF
    destination.parent.mkdir(mode=0o700)
    mounts = tmp_path / 'mounts'
    monkeypatch.setattr(entry, 'DESTINATION', destination)
    monkeypatch.setattr(entry, 'MOUNTS', mounts)
    monkeypatch.setattr(entry.os, 'geteuid', lambda: 0)
    monkeypatch.delenv(MASTER_KEY_SETTING, raising=False)
    monkeypatch.setenv(MASTER_KEY_SETTING + '_FILE', str(destination))
    body = base64.b64encode(os.urandom(32))
    monkeypatch.setattr(entry, '_read_master_key', lambda path: body)
    original = Path.lstat
    def info(path):
        found = original(path)
        return SimpleNamespace(st_mode=found.st_mode, st_uid=0) if path == destination.parent else found
    monkeypatch.setattr(Path, 'lstat', info)
    owners = []
    monkeypatch.setattr(entry.os, 'fchown', lambda fd, uid, gid: owners.append(('file', uid, gid)))
    monkeypatch.setattr(entry.os, 'chown', lambda path, uid, gid: owners.append(('directory', uid, gid)))
    mounts.write_text(f'none {destination.parent} ext4 rw 0 0\n')
    with pytest.raises(ValueError, match='delivery_rejected'):
        entry.deliver()
    assert not destination.exists()
    mounts.write_text(f'none {destination.parent} tmpfs rw 0 0\n')
    entry.deliver()
    assert destination.read_bytes() == body and destination.stat().st_mode & 0o777 == 0o600
    assert owners == [('file', 10001, 10001), ('directory', 10001, 10001)]
    with pytest.raises(FileExistsError):
        entry.deliver()


@pytest.mark.legacy
@pytest.mark.posix_only
def test_entrypoint_drops_groups_gid_uid_before_exec_and_preserves_api_arguments(monkeypatch):
    from deploy.linux import ad_credentials_entrypoint as entry
    events = []
    monkeypatch.setattr(entry.sys, 'argv', ['entrypoint', 'api', '--host', '0.0.0.0', '--port', '8443'])
    monkeypatch.setattr(entry, 'deliver', lambda: events.append('deliver'))
    monkeypatch.setattr(entry.os, 'setgroups', lambda groups: events.append(('groups', groups)))
    monkeypatch.setattr(entry.os, 'setgid', lambda gid: events.append(('gid', gid)))
    monkeypatch.setattr(entry.os, 'setuid', lambda uid: events.append(('uid', uid)))
    def execute(binary, argv):
        events.append(('exec', argv[1:]))
        raise SystemExit(0)
    monkeypatch.setattr(entry.os, 'execv', execute)
    with pytest.raises(SystemExit):
        entry.main()
    assert events == ['deliver', ('groups', []), ('gid', 10001), ('uid', 10001),
        ('exec', ['-m', 'deploy.linux.entrypoint', 'api', '--host', '0.0.0.0', '--port', '8443'])]


@pytest.mark.legacy
@pytest.mark.posix_only
def test_entrypoint_never_starts_consumer_after_delivery_failure(monkeypatch, capsys):
    from deploy.linux import ad_credentials_entrypoint as entry
    monkeypatch.setattr(entry.sys, 'argv', ['entrypoint', 'api'])
    def fail():
        raise ValueError('synthetic-secret-marker')
    monkeypatch.setattr(entry, 'deliver', fail)
    monkeypatch.setattr(entry.os, 'setuid', lambda _: pytest.fail('must not start consumer'))
    assert entry.main() == 1
    assert capsys.readouterr().err == 'ad_credentials_delivery_failed\n'
