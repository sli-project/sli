"""Fresh installation and adoption contracts; fake Docker and PostgreSQL only."""

# ruff: noqa: F811 -- imported pytest fixtures are intentionally named as parameters
from __future__ import annotations

import copy
import hashlib
import json
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import adoption_probe, sli_install, sli_update
from deploy.linux import installation as lifecycle
from scripts.maintenance import release_package as packages
from tests.unit.test_sli_update import (
    release,  # noqa: F401 -- shared signed-image fixture
)
from tools import build_update_package as builder
from tools.build_update_package import build


@pytest.fixture(autouse=True)
def fake_backup_volume_layout(monkeypatch):
    # These lifecycle tests fake Docker and physical host topology. Volume
    # identity/refusal is covered separately in test_linux_backup_policy.
    monkeypatch.setattr(lifecycle, 'restore_check_directory', lambda runtime, environment:
                        Path(environment.get('SLI_RESTORE_CHECK_DIR',
                             str(lifecycle.backup_directory(runtime, environment) / '.restore-check'))))


@pytest.fixture
def fresh(release, tmp_path, monkeypatch, fake_backup_volume_layout):
    updater, _, _, manifest, _, payload = release
    metadata = copy.deepcopy(manifest)
    metadata.update(package_type='core-install', from_version=None)
    del metadata['version'], metadata['to_version']
    metadata['compatibility']['from_version'] = None
    draft = tmp_path / 'install-manifest.json'
    draft.write_bytes(packages.canonical_json(metadata))
    archive = tmp_path / 'install.zip'
    build(draft, payload, tmp_path / 'offline.key', archive, key_id='test-only')
    monkeypatch.setattr(lifecycle.os, 'geteuid', lambda: 0, raising=False)
    monkeypatch.setattr(lifecycle.os, 'chown', lambda *args: None, raising=False)
    from deploy.linux import sli_secrets
    monkeypatch.setattr(sli_secrets, '_check_owner', lambda *args: None)
    tls = {}
    for name, body in sli_secrets._tls_bundle(['127.0.0.1']).items():
        tls[name] = tmp_path / name
        tls[name].write_bytes(body)

    class Host:
        def __init__(self):
            self.calls = []
            self.fail = None

        def fresh_config(self, runtime):
            self.override = runtime / 'state/install-compose.json'
            self.runtime = runtime
            self.config_data = {'name': 'sli', 'volumes': {'postgres-data': {'name': 'sli_postgres-data'}},
                                'services': {name: {} for name in
                                ['postgres', 'clickhouse', 'warm-tier', 'api', 'backup', 'migrate']},
                                'secrets': {name: {} for name in ['runtime_password', 'postgres_password',
                                             'tls_ca', 'tls_certificate', 'tls_key']}}
            self.config_data['services']['postgres'] = {'user': '999:999', 'group_add': ['10001']}
            return self.config_data, {'volumes': {'postgres-data': {'name': 'sli_postgres-data', 'external': False}}}

        def assert_unused(self, config):
            self.calls.append('unused')
            if self.fail == 'unused':
                raise lifecycle.UpdateError('install_volume_exists')

        def config(self):
            return self.config_data

        def stage(self, payload, manifest, tag):
            self.calls.append('stage')
            assert tag == 'sli-install:' + manifest['image']['digest'].replace(':', '-')
            assert not (self.runtime / 'state/installed.json').exists()

        def start_fresh(self, services):
            assert not any((self.runtime / 'state' / name).exists() for name in
                           ['update-journal.json', 'update-journal.key', 'updates'])
            self.calls.extend(['infra', 'migrate', 'activate', 'health'])
            if self.fail == 'health':
                raise lifecycle.UpdateError('update_health_timeout')

        def observe(self):
            return {'migration_ledger_max': 1, 'migration_ledger': [
                {'version': 1, 'name': 'example', 'sha256': next(iter(manifest['migrations'].values()))}],
                'plugins': [], 'services': {'api': {'version': manifest['to_version'],
                    'image_digest': manifest['image']['digest'], 'image_tag': manifest['image']['digest']}}}

        def publish_installed(self, previous, candidate, operation):
            pass

    return archive, updater.trust_store, tmp_path / 'fresh-runtime', Host(), tls


def test_install_commits_only_after_migrate_and_health(fresh, capsys):
    archive, trust, runtime, host, tls = fresh
    assert lifecycle.install(archive, trust, runtime, host, tls)['status'] == 'installed'
    installed = packages.read_json((runtime / 'state/installed.json').read_bytes())
    assert installed['version'] == builder.VERSION_FILE.read_text().strip()
    assert installed['compose_project'] == 'sli'
    assert installed['volumes'] == {'postgres-data': 'sli_postgres-data'}
    assert installed['source_commit'] == packages.verify_package(archive, trust).manifest['source_commit']
    assert installed['migrations'] == packages.verify_package(archive, trust).manifest['migrations']
    assert host.calls == ['unused', 'unused', 'stage', 'infra', 'migrate', 'activate', 'health']
    secret = (runtime / 'secrets/runtime_password').read_bytes()
    assert len(secret) >= 48 and secret != (runtime / 'secrets/postgres_password').read_bytes()
    assert secret.decode() not in capsys.readouterr().out
    assert (runtime / 'secrets/runtime_password').stat().st_mode & 0o777 == 0o640
    assert (runtime / 'secrets').stat().st_mode & 0o777 == 0o750
    override = json.loads(host.override.read_text())
    # The canonical saved Compose already sets the PostgreSQL identity/groups.
    # Compose 2.26 concatenates group_add across files and rejects duplicates.
    assert 'postgres' not in override['services']
    saved = json.loads((runtime / 'compose/compose.json').read_text())
    assert saved['services']['postgres'] == {'user': '999:999', 'group_add': ['10001']}


def test_install_never_reuses_runtime(fresh):
    archive, trust, runtime, host, tls = fresh
    runtime.mkdir()
    (runtime / 'history').write_bytes(b'preserved')
    with pytest.raises(lifecycle.UpdateError, match='install_runtime_not_empty'):
        lifecycle.install(archive, trust, runtime, host, tls)
    assert host.calls == [] and (runtime / 'history').read_bytes() == b'preserved'


@pytest.mark.parametrize('already_loaded', [False, True])
def test_install_preserves_an_older_image_tag_for_the_same_version(fresh, already_loaded):
    archive, trust, runtime, host, tls = fresh
    manifest = packages.verify_package(archive, trust).manifest
    digest = manifest['image']['digest']
    legacy = 'sli-install:v' + manifest['version']
    tag = 'sli-install:' + digest.replace(':', '-')
    images = {legacy: 'sha256:' + 'f' * 64}
    if already_loaded:
        images[tag] = digest

    def command(args):
        if args[:3] == ['docker', 'image', 'ls']:
            return images.get(args[-1], '')
        if args[:3] == ['docker', 'image', 'tag']:
            images[args[-1]] = args[-2]
        else:
            assert args[:3] == ['docker', 'image', 'load']
        return ''

    staging = SimpleNamespace(command=command, image_id=lambda reference: digest)
    host.stage = lambda payload, metadata, reference: sli_update.DockerHost.stage(
        staging, payload, metadata, reference)
    assert lifecycle.install(archive, trust, runtime, host, tls)['installed']
    assert images[legacy] == 'sha256:' + 'f' * 64
    assert images[tag] == digest


def test_install_existing_volumes_refused_before_secrets(fresh):
    archive, trust, runtime, host, tls = fresh
    host.fail = 'unused'
    with pytest.raises(lifecycle.UpdateError, match='install_volume_exists'):
        lifecycle.install(archive, trust, runtime, host, tls)
    assert not runtime.exists() and host.calls == ['unused']


def test_failed_install_fences_partial_runtime_without_deleting_volumes(fresh):
    archive, trust, runtime, host, tls = fresh
    host.fail = 'health'
    with pytest.raises(lifecycle.UpdateError, match='update_health_timeout'):
        lifecycle.install(archive, trust, runtime, host, tls)
    assert not (runtime / 'state/installed.json').exists()
    assert packages.read_json((runtime / 'state/install-status.json').read_bytes())['status'] == 'recovery_required'
    assert (runtime / 'secrets/runtime_password').exists()
    with pytest.raises(lifecycle.UpdateError, match='install_runtime_not_empty'):
        lifecycle.install(archive, trust, runtime, host, tls)


@pytest.mark.skipif(os.name == 'nt', reason='Linux ownership and modes')
def test_update_lock_requires_protected_state_even_without_prior_journal(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir(mode=0o777)
    runtime.chmod(0o777)
    state = runtime / 'state'
    with pytest.raises(lifecycle.UpdateError, match='update_unsafe_state'):  # noqa: SIM117 - assert refusal before body
        with sli_update.operation_lock(state):
            pytest.fail('Unsafe update state must be refused before acquiring the lock')
    assert not (state / 'update.lock').exists()
    assert not (state / 'update-journal.json').exists()


def test_install_rejects_invalid_signature_before_docker(fresh):
    archive, trust, runtime, host, tls = fresh
    archive.write_bytes(b'unsigned')
    with pytest.raises(packages.PackageError):
        lifecycle.install(archive, trust, runtime, host, tls)
    assert not host.calls and not runtime.exists()


def evaluation_kit(fresh):
    from deploy.linux import verify_offline_kit as verifier
    from tools import release_artifacts as artifacts
    archive, trust, runtime, _host, _tls = fresh
    signed = packages.verify_package(archive, trust)
    root = runtime.parent / 'evaluation-kit'
    root.mkdir()
    packages.extract_payload(signed, root)
    artifacts.write_json(root / 'manifests/install.unsigned.json', signed.manifest)
    from deploy.linux.evaluation_package import build
    build(root)
    artifacts.write_json(root / 'KIT_INVENTORY.json', {'files': verifier.file_inventory(root)})
    return root, verifier.digest(root / 'KIT_INVENTORY.json')


def test_evaluation_install_still_requires_explicit_flag(fresh):
    root, _ = evaluation_kit(fresh)
    _, trust, runtime, host, tls = fresh
    with pytest.raises(packages.PackageError):
        lifecycle.install(root / 'packages/install.zip', trust, runtime, host, tls)
    assert host.calls == [] and not runtime.exists()


def test_evaluation_install_checks_inventory_and_records_unsigned_state(fresh, monkeypatch):
    from deploy.linux import verify_offline_kit as verifier
    root, checksum = evaluation_kit(fresh)
    monkeypatch.setattr(verifier, 'verify', lambda *args, **kwargs: {'status': 'complete'})
    _, _, runtime, host, tls = fresh
    result = lifecycle.install(root / 'packages/install.zip', None, runtime, host, tls,
                               evaluation_kit=root, inventory_sha256=checksum)
    assert result['installed'] is True and result['authenticated'] is False
    assert result['signing'] == 'evaluation-unsigned'
    installed = packages.read_json((runtime / 'state/installed.json').read_bytes())
    assert installed['signing'] == 'evaluation-unsigned'


def test_evaluation_install_rejects_changed_package_before_docker(fresh, monkeypatch):
    from deploy.linux import verify_offline_kit as verifier
    root, checksum = evaluation_kit(fresh)
    monkeypatch.setattr(verifier, 'verify', lambda *args, **kwargs: {'status': 'complete'})
    with zipfile.ZipFile(root / 'packages/install.zip', 'a') as archive:
        archive.writestr('extra', b'changed')
    _, _, runtime, host, tls = fresh
    with pytest.raises(lifecycle.UpdateError, match='install_evaluation_package_mismatch'):
        lifecycle.install(root / 'packages/install.zip', None, runtime, host, tls,
                          evaluation_kit=root, inventory_sha256=checksum)
    assert host.calls == [] and not runtime.exists()


def test_evaluation_install_rejects_payload_hash_mismatch_before_docker(fresh, monkeypatch):
    from deploy.linux import verify_offline_kit as verifier
    from tools import release_artifacts as artifacts
    root, _ = evaluation_kit(fresh)
    monkeypatch.setattr(verifier, 'verify', lambda *args, **kwargs: {'status': 'complete'})
    path = root / 'packages/install.zip'
    with zipfile.ZipFile(path) as archive:
        content = {name: archive.read(name) for name in archive.namelist()}
    name = next(name for name in content if name.startswith('payload/'))
    content[name] = b'x' * len(content[name])
    with zipfile.ZipFile(path, 'w') as archive:
        for name, body in content.items():
            archive.writestr(name, body)
    artifacts.write_json(root / 'KIT_INVENTORY.json', {'files': verifier.file_inventory(root)})
    checksum = verifier.digest(root / 'KIT_INVENTORY.json')
    _, _, runtime, host, tls = fresh
    with pytest.raises(lifecycle.UpdateError, match='install_evaluation_payload_mismatch'):
        lifecycle.install(path, None, runtime, host, tls, evaluation_kit=root, inventory_sha256=checksum)
    assert host.calls == [] and not runtime.exists()


def test_evaluation_install_cli_passes_explicit_opt_in(monkeypatch, tmp_path, capsys):
    def install(*args, **kwargs):
        assert args[1] is None
        assert kwargs == {'evaluation_kit': tmp_path / 'kit', 'inventory_sha256': 'a' * 64}
        return {'status': 'installed', 'signing': 'evaluation-unsigned', 'authenticated': False}
    monkeypatch.setattr(sli_install, 'install', install)
    args = [item for flag in ['--package', '--compose', '--ca-file', '--tls-certificate', '--tls-key']
            for item in [flag, str(tmp_path / 'fixture')]]
    assert sli_install.main(args + ['--evaluation', '--kit', str(tmp_path / 'kit'),
                                   '--inventory-sha256', 'a' * 64]) == 0
    assert json.loads(capsys.readouterr().out)['authenticated'] is False


@pytest.mark.parametrize('extra', [[], ['--evaluation'], ['--kit', 'fixture']])
def test_install_cli_requires_complete_trust_or_evaluation_arguments(tmp_path, extra):
    args = [item for flag in ['--package', '--compose', '--ca-file', '--tls-certificate', '--tls-key']
            for item in [flag, str(tmp_path / 'fixture')]]
    with pytest.raises(SystemExit) as caught:
        sli_install.main(args + extra)
    assert caught.value.code == 2


def test_install_rejects_update_package(release, fresh):
    updater, _, archive, _, _, _ = release
    _, _, runtime, host, tls = fresh
    with pytest.raises(lifecycle.UpdateError, match='install_package_required'):
        lifecycle.install(archive, updater.trust_store, runtime, host, tls)
    assert not host.calls


@pytest.mark.parametrize('occupied,reason', [
    ('project', 'install_project_exists'), ('labelled-volume', 'install_project_volumes_exist'),
    ('unlabelled-volume', 'install_volume_exists'),
])
def test_docker_fresh_refuses_stopped_projects_and_orphan_volumes(occupied, reason):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    def command(args):
        if args[1] == 'ps':
            return 'stopped-container' if occupied == 'project' else ''
        if '--filter' in args:
            return 'orphan-volume' if occupied == 'labelled-volume' else ''
        return 'sli_postgres-data'
    host.command = command
    with pytest.raises(lifecycle.UpdateError, match=reason):
        host.assert_unused({'volumes': {'postgres-data': {'name': 'sli_postgres-data'}}})


@pytest.fixture
def adoption(tmp_path):
    secret = tmp_path / 'runtime_password'
    secret.write_bytes(b'synthetic-secret')
    digest = 'sha256:' + 'a' * 64
    names = ['postgres', 'clickhouse', 'warm-tier', 'api', 'backup']
    config = {'name': 'sli', 'services': {name: {'image': digest, 'healthcheck': {'test': ['CMD', 'true']},
                                 'volumes': [{'type': 'volume', 'source': 'data', 'target': '/var/lib/sli'}],
                                 'secrets': [{'source': 'runtime_password'}]} for name in names},
              'secrets': {'runtime_password': {'file': str(secret)}}, 'volumes': {'data': {'name': 'existing-data'}}}
    config['services']['migrate'] = {'image': digest}
    rows = [{'Service': name, 'ID': name, 'State': 'running', 'Health': 'healthy'} for name in names]
    containers = {name: {'Image': digest,
        'Config': {'Image': digest, 'Labels': {'com.docker.compose.project': 'sli', 'com.docker.compose.service': name}},
        'Mounts': [{'Type': 'volume', 'Name': 'existing-data', 'Destination': '/var/lib/sli'},
                   {'Source': str(secret), 'Destination': '/run/secrets/runtime_password'}]} for name in names}
    metadata = {'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Labels': {}}}
    database = {'migrations': {'config/postgres_migrations/001_example.sql': 'b' * 64},
                'migration_ledger_max_version': 1, 'plugin_state_sha256': 'c' * 64,
                'migration_ledger': [{'version': 1, 'name': 'example', 'sha256': 'b' * 64}], 'plugins': {}}
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    calls = []
    def command(args):
        calls.append(args)
        if args[1] == 'inspect':
            if '--format' in args:
                if 'Labels' in args[args.index('--format') + 1]:
                    return json.dumps(containers[args[-1]]['Config']['Labels'])
                return containers[args[-1]]['Image']
            return json.dumps([containers[args[-1]]])
        if args[1:3] == ['volume', 'inspect']:
            return json.dumps([{'Labels': {'com.docker.compose.project': 'sli'}}])
        if args[1:3] == ['image', 'inspect']:
            return digest if '--format' in args else json.dumps([metadata])
        if args[1] == 'exec':
            return json.dumps(database)
        if args[1] == 'ps':
            return '\n'.join(row['ID'] for row in rows)
        raise AssertionError(args)
    host.command = command
    host.config = lambda: copy.deepcopy(config)
    host.containers = lambda: copy.deepcopy(rows)
    host.compose = lambda args, override=None: json.dumps(config)
    host.observe = lambda: {'migration_ledger_max': database['migration_ledger_max_version'], 'plugins': [],
                          'migration_ledger': copy.deepcopy(database['migration_ledger']),
        'services': {name: {'version': metadata['Config']['Labels'].get('org.opencontainers.image.version'),
                            'image_digest': containers[name]['Image'], 'image_tag': containers[name]['Config']['Image']}
                     for name in ['api', 'backup']}}
    return host, tmp_path / 'runtime', config, rows, containers, metadata, database, calls


@pytest.mark.parametrize('version', [None, '1.0.0', '2026.10.1'])
def test_adoption_is_read_only_idempotent_and_preserves_data(adoption, version):
    host, runtime, _, _, _, metadata, _, calls = adoption
    if version:
        metadata['Config']['Labels']['org.opencontainers.image.version'] = version
    runtime.mkdir()
    for name in ['history', 'grants', 'credentials', 'settings', 'queue', 'cursors']:
        (runtime / name).write_bytes(b'preserve-exactly')
    before = {path: path.read_bytes() for path in runtime.iterdir()}
    result = lifecycle.adopt(runtime, host)
    assert result['status'] == 'adopted'
    assert result['package_version'] is None
    assert result['migration_ledger'] == {'max_version': 1}
    assert result['desired_activation']['version'] == (version or 'adopted-1')
    assert result['observed_runtime']['services']['api']['version'] == version
    installed = runtime / 'state/installed.json'
    assert packages.read_json(installed.read_bytes())['version'] == (version or 'adopted-1')
    assert packages.read_json(installed.read_bytes())['compose_project'] == 'sli'
    assert packages.read_json(installed.read_bytes())['volumes'] == {'data': 'existing-data'}
    first = installed.read_bytes(), installed.stat().st_mtime_ns
    assert lifecycle.adopt(runtime, host)['status'] == 'adopted'
    assert first == (installed.read_bytes(), installed.stat().st_mtime_ns)
    assert all(path.read_bytes() == value for path, value in before.items())
    assert all(args[1] in {'inspect', 'volume', 'image', 'exec', 'ps'} for args in calls)
    assert all(args[1] != 'image' or args[2] == 'inspect' for args in calls)


@pytest.mark.parametrize('failure,reason', [
    ('foreign', 'adopt_foreign_container'), ('mixed', 'adopt_mixed_images'),
    ('volume', 'adopt_volume_mismatch'), ('secret', 'adopt_secret_missing'),
    ('stopped', 'adopt_incomplete_installation'), ('label', 'adopt_invalid_version_metadata'),
    ('ledger', 'adopt_ledger_inconsistent'), ('code', 'adopt_code_mount_forbidden'),
])
def test_adoption_refuses_inconsistent_installation(adoption, failure, reason):
    host, runtime, config, rows, containers, metadata, database, _ = adoption
    if failure == 'foreign':
        containers['api']['Config']['Labels']['com.docker.compose.project'] = 'foreign'
    elif failure == 'mixed':
        containers['backup']['Image'] = 'sha256:' + 'd' * 64
        config['services']['backup']['image'] = containers['backup']['Image']
        original = host.image_id
        host.image_id = lambda tag: tag if tag == containers['backup']['Image'] else original(tag)
    elif failure == 'volume':
        containers['api']['Mounts'][0]['Name'] = 'foreign-data'
    elif failure == 'secret':
        Path(config['secrets']['runtime_password']['file']).unlink()
    elif failure == 'stopped':
        rows[0]['State'] = 'exited'
    elif failure == 'label':
        metadata['Config']['Labels']['org.opencontainers.image.version'] = 'invalid'
    elif failure == 'ledger':
        database['migration_ledger_max_version'] = 0
    elif failure == 'code':
        config['services']['api']['volumes'][0]['target'] = '/opt/sli'
    with pytest.raises(lifecycle.UpdateError, match=reason):
        lifecycle.adopt(runtime, host)
    assert not (runtime / 'state/installed.json').exists()


def test_adoption_dry_run_and_existing_registry_refusal(adoption):
    host, runtime, *_ = adoption
    assert lifecycle.adopt(runtime, host, dry_run=True)['status'] == 'dry_run'
    assert not (runtime / 'state/installed.json').exists()
    sli_update.atomic_json(runtime / 'state/installed.json', {'version': 'foreign'})
    before = (runtime / 'state/installed.json').read_bytes()
    with pytest.raises(lifecycle.UpdateError, match='adopt_installed_state_mismatch'):
        lifecycle.adopt(runtime, host)
    assert (runtime / 'state/installed.json').read_bytes() == before


@pytest.mark.parametrize('dry_run', [False, True])
def test_adoption_cli_preserves_lifecycle_and_tls_policy(adoption, monkeypatch, capsys, dry_run):
    host, runtime, *_ = adoption
    constructors = []

    def installation_host(*args):
        constructors.append(args)
        return host

    monkeypatch.setattr(lifecycle, 'InstallationHost', installation_host)
    args = ['adopt', '--runtime', str(runtime), '--compose', 'synthetic-compose.yml',
            '--tls-min-validity-seconds', '172800', '--json']
    assert sli_update.main([*args, *(['--dry-run'] if dry_run else [])]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['status'] == ('dry_run' if dry_run else 'adopted')
    assert result['desired_activation']['version'] == 'adopted-1'
    assert (runtime / 'state/installed.json').exists() == (not dry_run)
    assert constructors[0][-1] == 172800


def test_adoption_cli_reports_safe_rejection_without_registry(adoption, monkeypatch, capsys):
    host, runtime, _, _, containers, *_ = adoption
    containers['api']['Config']['Labels']['com.docker.compose.project'] = 'foreign'
    monkeypatch.setattr(lifecycle, 'InstallationHost', lambda *_: host)
    assert sli_update.main(['adopt', '--runtime', str(runtime), '--compose', 'synthetic-compose.yml', '--json']) == 1
    assert json.loads(capsys.readouterr().out)['reason_code'] == 'adopt_foreign_container'
    assert not (runtime / 'state/installed.json').exists()


def test_adoption_refuses_pending_update(adoption):
    host, runtime, *_ = adoption
    sli_update.atomic_json(runtime / 'state/update-journal.json', {'status': 'running'})
    with pytest.raises(lifecycle.UpdateError, match='adopt_update_in_progress'):
        lifecycle.adopt(runtime, host)


def test_adoption_refuses_install_recovery(adoption):
    host, runtime, *_ = adoption
    sli_update.atomic_json(runtime / 'state/install-status.json', {'status': 'recovery_required'})
    with pytest.raises(lifecycle.UpdateError, match='adopt_install_recovery_required'):
        lifecycle.adopt(runtime, host)


def test_adoption_refuses_volume_drift_without_rewriting_registry(adoption):
    host, runtime, config, _, containers, *_ = adoption
    lifecycle.adopt(runtime, host)
    before = (runtime / 'state/installed.json').read_bytes()
    config['volumes']['data']['name'] = 'replacement-data'
    for container in containers.values():
        container['Mounts'][0]['Name'] = 'replacement-data'
    with pytest.raises(lifecycle.UpdateError, match='adopt_installed_volumes_changed'):
        lifecycle.adopt(runtime, host)
    assert before == (runtime / 'state/installed.json').read_bytes()


def test_adoption_records_live_tag_and_supports_idle_status(adoption):
    host, runtime, config, _, containers, *_ = adoption
    for name in ['api', 'backup', 'migrate']:
        config['services'][name]['image'] = 'sli-running:local'
        if name in containers:
            containers[name]['Config']['Image'] = 'sli-running:local'
    lifecycle.adopt(runtime, host)
    installed = packages.read_json((runtime / 'state/installed.json').read_bytes())
    assert installed['image_tag'] == 'sli-running:local'
    result = sli_update.Updater(runtime, runtime / 'unused-trust.json', host).status()
    assert result['status'] == 'idle'
    assert result['package_version'] is None
    assert result['migration_ledger'] == {'max_version': 1}
    assert result['desired_activation']['version'] == 'adopted-1'
    assert result['observed_runtime']['services']['api']['version'] is None


@pytest.mark.parametrize('dry_run', [False, True])
def test_adoption_runs_shared_preflight_before_recording(adoption, monkeypatch, dry_run):
    host, runtime, *_ = adoption
    def refuse(installed, config):
        assert installed['compose_project'] == config['name'] == 'sli'
        assert installed['volumes'] == {'data': 'existing-data'}
        raise lifecycle.UpdateError('update_volume_ownership')
    monkeypatch.setattr(host, 'ownership_preflight', refuse)
    with pytest.raises(lifecycle.UpdateError, match='update_volume_ownership'):
        lifecycle.adopt(runtime, host, dry_run=dry_run)
    assert not (runtime / 'state/installed.json').exists()


@pytest.mark.parametrize('bad', ['ledger', 'version', 'tag', 'digest'])
def test_adoption_refuses_observed_runtime_drift(adoption, monkeypatch, bad):
    host, runtime, *_ = adoption
    observed = host.observe()
    if bad == 'ledger':
        observed['migration_ledger_max'] = 2
    else:
        key, value = {'version': ('version', '1.0.0'), 'tag': ('image_tag', 'foreign:local'),
                      'digest': ('image_digest', 'sha256:' + 'd' * 64)}[bad]
        observed['services']['api'][key] = value
    monkeypatch.setattr(host, 'observe', lambda: observed)
    with pytest.raises(lifecycle.UpdateError, match='adopt_ledger_inconsistent|adopt_running_version_mismatch'):
        lifecycle.adopt(runtime, host)
    assert not (runtime / 'state/installed.json').exists()


def test_u5_adoption_upgrades_only_verified_legacy_cache(adoption):
    host, runtime, *_ = adoption
    lifecycle.adopt(runtime, host)
    installed = runtime / 'state/installed.json'
    previous = packages.read_json(installed.read_bytes())
    previous.pop('migration_ledger')
    sli_update.atomic_json(installed, previous)
    before = installed.read_bytes()
    lifecycle.adopt(runtime, host, dry_run=True)
    assert installed.read_bytes() == before
    lifecycle.adopt(runtime, host)
    assert packages.read_json(installed.read_bytes())['migration_ledger'] == host.observe()['migration_ledger']


def test_u5_adoption_rejects_different_exact_ledger_with_same_max(adoption, monkeypatch):
    host, runtime, *_ = adoption
    lifecycle.adopt(runtime, host)
    original = (runtime / 'state/installed.json').read_bytes()
    observed = host.observe()
    observed['migration_ledger'][0]['sha256'] = 'f' * 64
    monkeypatch.setattr(host, 'observe', lambda: observed)
    with pytest.raises(lifecycle.UpdateError, match='adopt_ledger_inconsistent'):
        lifecycle.adopt(runtime, host)
    assert (runtime / 'state/installed.json').read_bytes() == original


def test_adopt_cli_preserves_fixed_refusal_code(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(lifecycle, 'adopt', lambda *a, **kw: (_ for _ in ()).throw(
        lifecycle.UpdateError('adopt_foreign_container')))
    assert sli_update.main(['adopt', '--compose', str(tmp_path / 'compose.yml'), '--json']) == 1
    assert json.loads(capsys.readouterr().out)['reason_code'] == 'adopt_foreign_container'


def test_adopt_cli_missing_compose_has_explicit_reason(capsys):
    assert sli_update.main(['adopt', '--json']) == 1
    assert json.loads(capsys.readouterr().out)['reason_code'] == 'adopt_compose_required'


def test_adopt_cli_keeps_tls_preflight_window(monkeypatch, tmp_path, capsys):
    def adopt(runtime, host, **kwargs):
        assert host.tls_min_validity == 172800
        assert kwargs['dry_run'] is True
        return {'status': 'dry_run'}
    monkeypatch.setattr(lifecycle, 'adopt', adopt)
    assert sli_update.main(['adopt', '--compose', str(tmp_path / 'compose.yml'), '--dry-run', '--json',
                            '--tls-min-validity-seconds', '172800']) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'dry_run'


def test_install_cli_sanitizes_private_errors(monkeypatch, tmp_path, capsys):
    def fail(*args, **kwargs):
        raise RuntimeError('synthetic-private-marker')
    monkeypatch.setattr(sli_install, 'install', fail)
    args = [item for flag in ['--package', '--trust-store', '--compose', '--ca-file', '--tls-certificate', '--tls-key']
            for item in [flag, str(tmp_path / 'fixture')]]
    assert sli_install.main(args) == 1
    output = capsys.readouterr().out
    assert 'synthetic-private-marker' not in output and json.loads(output)['reason_code'] == 'install_failed'


@pytest.mark.parametrize('failure,status', [(None, 'committed'), ('health', 'rolled_back')])
def test_signed_update_accepts_exact_synthetic_adoption_base(release, tmp_path, monkeypatch, failure, status):
    updater, host, _, manifest, _, payload = release
    metadata = copy.deepcopy(manifest)
    metadata['from_version'] = 'adopted-1'
    metadata['compatibility'].update(from_version='adopted-1', min_version='adopted-1', max_version='adopted-1')
    draft = tmp_path / 'adopted-manifest.json'
    draft.write_bytes(packages.canonical_json(metadata))
    archive = tmp_path / 'adopted-update.zip'
    build(draft, payload, tmp_path / 'offline.key', archive, key_id='test-only')
    installed = packages.read_json(updater.installed_path.read_bytes())
    installed['version'] = 'adopted-1'
    installed['adoption'] = {'project': 'sli'}
    host.installed = installed
    original_observe = host.observe
    def observe():
        result = original_observe()
        if host.active == 'previous':
            for service in result['services'].values():
                service['version'] = None
        return result
    monkeypatch.setattr(host, 'observe', observe)
    monkeypatch.setattr(host, 'runtime_matches', lambda journal, previous=False:
                        sli_update.DockerHost.runtime_matches(host, journal, previous))
    host.fail = failure
    assert packages.verify_package(archive, updater.trust_store, installed=installed,
                                   free_bytes=10**9).manifest['from_version'] == 'adopted-1'
    sli_update.atomic_json(updater.installed_path, installed)
    assert updater.apply(archive) == status
    assert packages.read_json(updater.installed_path.read_bytes())['version'] == (
        '1.1.0' if status == 'committed' else 'adopted-1')
    installed['version'] = 'adopted-2'
    with pytest.raises(packages.PackageError, match='update_incompatible_version'):
        packages.verify_package(archive, updater.trust_store, installed=installed, free_bytes=10**9)


def test_update_refuses_install_package(fresh):
    archive, trust, *_ = fresh
    installed = {'component': 'server'}
    with pytest.raises(packages.PackageError, match='update_install_package_forbidden'):
        packages.verify_package(archive, trust, installed=installed, free_bytes=10**9)


@pytest.mark.parametrize('bad', ['label', 'tag', 'digest', 'unregistered'])
def test_adopted_update_preflight_still_pins_the_runtime(release, monkeypatch, bad):
    updater, host, _, manifest, *_ = release
    installed = copy.deepcopy(host.installed)
    installed.update(version='adopted-1', adoption={'project': 'sli'})
    host.installed = installed
    observed = host.observe()
    for service in observed['services'].values():
        service['version'] = None
    if bad == 'unregistered':
        del installed['adoption']
    else:
        key, value = {'label': ('version', '1.0.0'), 'tag': ('image_tag', 'foreign:local'),
                      'digest': ('image_digest', 'sha256:' + 'd' * 64)}[bad]
        observed['services']['api'][key] = value
    monkeypatch.setattr(host, 'observe', lambda: observed)
    with pytest.raises(lifecycle.UpdateError, match='update_running_version_mismatch'):
        updater.preflight(installed, manifest)
    assert 'stage' not in host.calls


@pytest.mark.parametrize('failure,reason', [
    (None, None), ('ledger', 'adopt_ledger_inconsistent'), ('plugin', 'adopt_plugins_inconsistent'),
    ('missing_hash', 'adopt_ledger_inconsistent'),
])
@pytest.mark.parametrize('version', [1, 177, 178, 179])
def test_database_probe_uses_read_only_transaction(monkeypatch, tmp_path, failure, reason, version):
    root = tmp_path / 'image'
    directory = root / 'config/postgres_migrations'
    directory.mkdir(parents=True)
    (directory / f'{version:03d}_example.sql').write_bytes(b'SELECT 1;')
    checksum = hashlib.sha256(b'SELECT 1;').hexdigest()
    monkeypatch.setattr(adoption_probe, 'forward_migration_inventory',
                        lambda path: [SimpleNamespace(version=version, name='example', sha256=checksum)])
    monkeypatch.setattr(adoption_probe, 'base_schema_markers', lambda path: [])
    monkeypatch.setattr(adoption_probe.backup, 'read_secret', lambda key: 'synthetic-private-marker')
    calls = []
    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def execute(self, statement):
            calls.append(statement)
            if 'schema_migrations' in statement:
                observed_hash = None if version < 179 or failure == 'missing_hash' else checksum
                return SimpleNamespace(fetchall=lambda: [
                    (version, 'foreign' if failure == 'ledger' else 'example', observed_hash)])
            return SimpleNamespace(fetchall=lambda: [
                ('sli.synthetic', '1.0.0', 'invalid' if failure == 'plugin' else 'registered',
                 'disabled', 'stopped', 'drained')])

    def connect(**kwargs):
        assert kwargs['options'] == '-c default_transaction_read_only=on'
        return Connection()
    monkeypatch.setattr(adoption_probe.psycopg, 'connect', connect)
    if failure and (failure != 'missing_hash' or version == 179):
        with pytest.raises(ValueError, match=reason):
            adoption_probe.probe(root)
    else:
        result = adoption_probe.probe(root)
        assert result['migration_ledger_max_version'] == version
        assert result['ledger_source'] == ('deployed_image' if version < 179 else 'database')
        assert result['migration_ledger'][0]['sha256'] == checksum
        assert len(result['plugin_state_sha256']) == 64
        assert 'synthetic-private-marker' not in json.dumps(result)
    assert calls[0] == 'SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY'
    assert all(statement.lstrip().startswith('SELECT') for statement in calls[1:])


@pytest.mark.parametrize('source,expected', [
    ('D:\\synthetic\\secrets', 'd:/synthetic/secrets'),
    ('/run/desktop/mnt/host/d/synthetic/secrets', 'd:/synthetic/secrets'),
    ('/srv/SLI/secrets', '/srv/SLI/secrets'),
])
def test_docker_desktop_mount_translation(source, expected):
    assert lifecycle.mount_source(source) == expected


def test_fresh_configuration_replaces_external_volumes_and_fences_data_binds(tmp_path):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    runtime = tmp_path / 'new-runtime'
    config = {'services': {name: {} for name in ['postgres', 'clickhouse', 'warm-tier', 'api', 'backup', 'migrate']},
              'volumes': {'history-data': {'name': 'existing-history', 'external': True}},
              'secrets': {'runtime_password': {'file': str(runtime / 'secrets/runtime_password')}}}
    host.config = lambda: config
    _, override = host.fresh_config(runtime)
    assert override['volumes']['history-data'] == {'external': False, 'name': 'sli_history-data'}
    config['services']['postgres']['volumes'] = [
        {'type': 'bind', 'source': str(tmp_path / 'existing-history'), 'target': '/var/lib/postgresql'}]
    with pytest.raises(lifecycle.UpdateError, match='install_existing_data_bind_forbidden'):
        host.fresh_config(runtime)


def test_data_directory_moves_only_database_volumes_and_survives_saved_compose(tmp_path):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    runtime, data = tmp_path / 'runtime', tmp_path / 'fast'
    host.environment['SLI_DATA_DIR'] = str(data)
    names = ('postgres-data', 'history-data', 'warm-data', 'history-backups', 'sli-data', 'storage-evidence')
    config = {'services': {name: {} for name in ['postgres', 'clickhouse', 'warm-tier', 'api', 'backup', 'migrate']},
              'volumes': {name: {} for name in names}}
    host.config = lambda: config
    _, override = host.fresh_config(runtime)
    host.command = lambda args: ''
    host.assert_unused(override)
    for name in names:
        expected = {'external': False, 'name': 'sli_' + name}
        if name in ('postgres-data', 'history-data', 'warm-data'):
            expected.update(driver='local', driver_opts={'type': 'none', 'o': 'bind', 'device': str(data / name)})
        assert override['volumes'][name] == expected
    runtime.mkdir()
    lifecycle.preserve_compose(runtime, host, config)
    lifecycle.atomic_json(host.override, override)
    # Updates and the installed launcher read this host-owned file alongside the base Compose.
    assert json.loads(host.override.read_text())['volumes'] == override['volumes']
    altered = copy.deepcopy(override)
    altered['volumes']['postgres-data']['driver_opts']['device'] = str(tmp_path / 'unmanaged')
    with pytest.raises(lifecycle.UpdateError, match='install_volume_driver_forbidden'):
        host.assert_unused(altered)


@pytest.mark.parametrize('location', ['relative', '/', 'runtime', 'parent', 'backups'])
def test_data_directory_rejects_unsafe_paths(tmp_path, location):
    runtime = tmp_path / 'runtime'
    path = {'relative': 'relative', '/': '/', 'runtime': str(runtime), 'parent': str(tmp_path),
            'backups': str(runtime / 'backups')}[location]
    with pytest.raises(lifecycle.UpdateError, match='install_invalid_data_directory'):
        lifecycle.data_directory(runtime, {'SLI_DATA_DIR': path})


def test_data_directory_provisions_container_owners_without_reusing_data(tmp_path, monkeypatch):
    data = tmp_path / 'fast'
    owners = {}
    monkeypatch.setattr(lifecycle.os, 'chown', lambda path, uid, gid: owners.update({Path(path): (uid, gid)}))
    volumes = {'postgres-data': {}, 'history-data': {}, 'warm-data': {}, 'history-backups': {}}
    lifecycle.prepare_data_directories(data, volumes)
    assert owners == {data / 'postgres-data': (999, 999), data / 'history-data': (101, 101),
                      data / 'warm-data': (101, 101)}
    assert not (data / 'history-backups').exists()
    assert all(path.stat().st_mode & 0o777 == 0o750 for path in owners)
    preserved = data / 'postgres-data/existing'
    preserved.write_text('synthetic')
    with pytest.raises(lifecycle.UpdateError, match='install_data_directory_not_empty'):
        lifecycle.prepare_data_directories(data, volumes)
    assert preserved.read_text() == 'synthetic'
    preserved.unlink()
    (data / 'postgres-data').rmdir()
    (data / 'postgres-data').symlink_to(data / 'history-data', target_is_directory=True)
    with pytest.raises(lifecycle.UpdateError, match='install_data_directory_not_empty'):
        lifecycle.prepare_data_directories(data, volumes)


def test_install_cli_passes_data_directory(tmp_path, monkeypatch, capsys):
    def install(*args, **options):
        assert args[3].environment['SLI_DATA_DIR'] == str(tmp_path / 'fast')
        return {'status': 'installed'}

    monkeypatch.setattr(sli_install, 'install', install)
    args = [item for flag in ['--package', '--trust-store', '--compose', '--ca-file',
                             '--tls-certificate', '--tls-key'] for item in [flag, str(tmp_path / 'fixture')]]
    assert sli_install.main(args + ['--data-directory', str(tmp_path / 'fast')]) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'installed'


def test_install_prepares_data_directory_before_starting_containers(fresh):
    archive, trust, runtime, host, tls = fresh
    data = runtime.parent / 'fast'
    host.environment = {'SLI_DATA_DIR': str(data)}
    start = host.start_fresh

    def start_fresh(services):
        assert (data / 'postgres-data').is_dir()
        assert not (data / 'history-backups').exists()
        start(services)

    host.start_fresh = start_fresh
    assert lifecycle.install(archive, trust, runtime, host, tls)['status'] == 'installed'


def test_external_backup_directory_is_used_for_compose_and_created_with_container_access(tmp_path, monkeypatch):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    runtime, backups = tmp_path / 'runtime', tmp_path / 'independent-backups'
    host.environment['SLI_BACKUP_DIR'] = str(backups)
    config = {'services': {name: {} for name in ['postgres', 'clickhouse', 'warm-tier', 'api', 'backup', 'migrate']}}
    config['services']['backup']['volumes'] = [{'type': 'bind', 'source': str(backups), 'target': '/backups'}]
    host.config = lambda: config
    host.fresh_config(runtime)
    assert host.environment['SLI_BACKUP_DIR'] == str(backups)
    owners = []
    monkeypatch.setattr(lifecycle.os, 'chown', lambda *args: owners.append(args))
    lifecycle.prepare_backup_directory(backups)
    assert backups.stat().st_mode & 0o777 == 0o770
    assert owners == [(backups, 10001, 10001), (backups / '.status', 10001, 10001)]
    assert (backups / '.status').stat().st_mode & 0o777 == 0o755
    (backups / 'preserved').write_bytes(b'synthetic')
    with pytest.raises(lifecycle.UpdateError, match='backup_directory_not_empty'):
        lifecycle.prepare_backup_directory(backups)
    assert (backups / 'preserved').read_bytes() == b'synthetic'


@pytest.mark.parametrize('location', ['.', '/', 'secrets', 'relative'])
def test_backup_directory_rejects_unsafe_runtime_overlaps(tmp_path, location):
    runtime = tmp_path / 'runtime'
    path = 'relative' if location == 'relative' else str(runtime / location)
    with pytest.raises(lifecycle.UpdateError, match='invalid_backup_directory'):
        lifecycle.backup_directory(runtime, {'SLI_BACKUP_DIR': path})


@pytest.mark.parametrize("postgres_command", [
    ["postgres", "-c", "max_wal_size=4GB", "-c", "checkpoint_timeout=15min",
     "-c", "checkpoint_completion_target=0.9"],
    ["postgres", "-c", "max_wal_size=6GB", "-c", "checkpoint_timeout=10min",
     "-c", "checkpoint_completion_target=0.8", "-c", "log_checkpoints=on"],
])
def test_runtime_compose_survives_source_removal_and_keeps_flags(tmp_path, monkeypatch, postgres_command):
    import shutil
    import subprocess
    import sys
    if sys.platform == 'win32':
        pytest.skip('Linux runtime launcher')
    monkeypatch.setattr(lifecycle.os, 'chown', lambda *args: None)
    runtime, source = tmp_path / 'runtime', tmp_path / 'kit'
    runtime.mkdir()
    source.mkdir()
    (source / 'config.xml').write_text('<synthetic/>')
    (source / 'locks').mkdir()
    (source / 'locks/item.json').write_text('{}')
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    host.environment['SLI_CORE_JOB_RADIUS_PILOT'] = '1'
    host.environment.pop('SLI_AD_DC_AGENT_IMPORT_ENABLED', None)
    host.environment['SYNTHETIC_PASSWORD'] = 'must-not-be-saved'
    config = {'services': {'api': {'build': {'context': str(source)},
              'environment': {'SLI_CORE_JOB_RADIUS_PILOT': '1', 'SLI_AD_DC_AGENT_IMPORT_ENABLED': '1'},
              'volumes': [{'type': 'bind', 'read_only': True, 'source': str(source / name), 'target': target}
                          for name, target in [('config.xml', '/config.xml'), ('locks', '/locks')]]}},
              'secrets': {'agent_issuer_key': {'file': str(runtime / 'secrets/agent_issuer_key')}}}
    config['services']['postgres'] = {'command': list(postgres_command)}
    lifecycle.preserve_compose(runtime, host, config)
    shutil.rmtree(source)
    saved = json.loads((runtime / 'compose/compose.json').read_text())
    assert saved['services']['postgres']['command'] == postgres_command
    assert saved['secrets'] == config['secrets']
    assert 'build' not in saved['services']['api']
    assert all(Path(mount['source']).exists() for mount in saved['services']['api']['volumes'])
    assert saved['services']['api']['environment']['SLI_CORE_JOB_RADIUS_PILOT'] == '${SLI_CORE_JOB_RADIUS_PILOT:-1}'
    environment = (runtime / 'runtime.env').read_text()
    assert 'SLI_CORE_JOB_RADIUS_PILOT="1"' in environment
    assert 'SLI_AD_DC_AGENT_IMPORT_ENABLED="1"' in environment
    assert 'must-not-be-saved' not in environment
    commands = tmp_path / 'bin'
    commands.mkdir()
    docker = commands / 'docker'
    docker.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    docker.chmod(0o700)
    monkeypatch.setenv('PATH', str(commands) + os.pathsep + os.environ['PATH'])
    completed = subprocess.run([str(runtime / 'sli-compose'), 'config'], capture_output=True, check=True, text=True)
    assert completed.stdout.splitlines() == ['compose', '-p', 'sli', '--env-file', str(runtime / 'runtime.env'),
                                            '-f', str(host.files[0]), '-f', str(runtime / 'state/install-compose.json'),
                                            'config']


def test_copied_compose_binds_are_readable_with_private_umask(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'nested').mkdir()
    (source / 'nested/registry.json').write_text('{}')
    (source / 'config.xml').write_text('<synthetic/>')
    source_modes = {path: path.stat().st_mode for path in source.rglob('*')}
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    config = {'services': {'api': {'volumes': [
        {'type': 'bind', 'read_only': True, 'source': str(path), 'target': target}
        for path, target in [(source / 'config.xml', '/config.xml'), (source / 'nested', '/registry')]]}}}
    owners = {}
    monkeypatch.setattr(lifecycle.os, 'chown', lambda path, uid, gid: owners.update({Path(path): (uid, gid)}))
    previous = os.umask(0o077)
    try:
        lifecycle.preserve_compose(runtime, SimpleNamespace(environment={}), config)
    finally:
        os.umask(previous)
    saved = json.loads((runtime / 'compose/compose.json').read_text())
    for mount in saved['services']['api']['volumes']:
        assert mount['read_only']
        destination = Path(mount['source'])
        paths = [destination, *destination.rglob('*')] if destination.is_dir() else [destination]
        for path in paths:
            assert path.stat().st_mode & 0o777 == (0o750 if path.is_dir() else 0o640)
            assert owners[path] == (0, 10001)
    assert (source / 'config.xml').read_text() == '<synthetic/>'
    assert (source / 'nested/registry.json').read_text() == '{}'
    assert {path: path.stat().st_mode for path in source.rglob('*')} == source_modes


def test_agent_overlay_exposes_restored_trust_to_api_and_restore_only():
    import yaml
    config = yaml.safe_load((Path(__file__).parents[2] / 'deploy/linux/docker-compose.agent.yml').read_text())
    assert set(config['services']) == {'api', 'migrate'}
    for service in config['services'].values():
        assert set(service['secrets']) == set(config['secrets'])
        assert all(str(value).startswith('/run/secrets/agent_') for value in service['environment'].values())
    assert all('${SLI_SECRETS_DIR' in value['file'] for value in config['secrets'].values())
    assert 'agent_root_key' not in config['secrets']


def test_install_cli_passes_external_backup_path_and_existing_agent_bundle(tmp_path, monkeypatch, capsys):
    def install(*args, **options):
        host = args[3]
        assert host.environment['SLI_BACKUP_DIR'] == str(tmp_path / 'separate-backups')
        assert options == {'agent_secrets_from': tmp_path / 'agent-trust'}
        return {'status': 'installed'}

    monkeypatch.setattr(sli_install, 'install', install)
    args = [item for flag in ['--package', '--trust-store', '--compose', '--ca-file',
                               '--tls-certificate', '--tls-key'] for item in [flag, str(tmp_path / 'fixture')]]
    assert sli_install.main(args + ['--backup-directory', str(tmp_path / 'separate-backups'),
                                   '--agent-secrets-from', str(tmp_path / 'agent-trust')]) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'installed'


def test_preserving_runtime_rejects_non_boolean_flags(tmp_path):
    runtime = tmp_path / 'runtime'
    runtime.mkdir()
    host = SimpleNamespace(environment={'SLI_LEGACY_COLLECTION_DISABLED': 'synthetic-invalid'})
    with pytest.raises(lifecycle.UpdateError, match='invalid_runtime_flag'):
        lifecycle.preserve_compose(runtime, host, {'services': {}})


@pytest.mark.parametrize('explicit', [None, '1'])
def test_workstation_runtime_defaults_off_and_preserves_explicit_opt_in(tmp_path, explicit):
    flags = ('SLI_CORE_JOB_WORKSTATIONS_RETENTION', 'SLI_CORE_JOB_WORKSTATIONS_PROJECTION')
    host = SimpleNamespace(environment={} if explicit is None else dict.fromkeys(flags, explicit))
    lifecycle.preserve_compose(tmp_path, host, {'services': {}})
    saved = (tmp_path / 'runtime.env').read_text()
    for flag in flags:
        assert f'{flag}="{explicit or "0"}"' in saved


def test_service_specific_overlay_flags_are_preserved_without_global_override(tmp_path):
    host = SimpleNamespace(environment={'SLI_CORE_JOB_RADIUS_PILOT': '0'})
    config = {'services': {name: {'environment': {'SLI_CORE_JOB_RADIUS_PILOT': flag}}
                           for name, flag in [('api', '1'), ('worker', '0')]}}
    lifecycle.preserve_compose(tmp_path, host, config)
    saved = json.loads((tmp_path / 'compose/compose.json').read_text())
    assert saved['services'] == config['services']
    assert 'SLI_CORE_JOB_RADIUS_PILOT=' not in (tmp_path / 'runtime.env').read_text()


def test_fresh_host_runs_baseline_migration_before_apps_and_health(tmp_path):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    calls = []
    host.compose = lambda args: calls.append(args)
    host.health = lambda journal: calls.append(['health'])
    host.start_fresh(['api', 'backup'])
    assert calls[0][-3:] == ['clickhouse', 'postgres', 'warm-tier']
    assert calls[1] == ['run', '--rm', '--no-deps', '-T', 'migrate']
    assert '--pull' in calls[0] and '--pull' in calls[2]
    assert calls[2][-2:] == ['api', 'backup']
    assert calls[3] == ['health']


@pytest.mark.parametrize('failed', [False, True])
def test_transfer_install_restores_before_apps_without_fresh_migration(tmp_path, failed):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    host.restore_from = tmp_path / 'recovery-set'
    calls = []
    host.compose = lambda args: calls.append(args)
    host.health = lambda journal: calls.append(['health'])

    def restore():
        calls.append(['restore'])
        if failed:
            raise lifecycle.UpdateError('installation_docker_failed')

    host.restore_fresh = restore
    if failed:
        with pytest.raises(lifecycle.UpdateError, match='installation_docker_failed'):
            host.start_fresh(['api', 'backup'])
        assert len(calls) == 2
    else:
        host.start_fresh(['api', 'backup'])
        assert calls[2][-2:] == ['api', 'backup']
        assert calls[3] == ['health']
    assert calls[0][-3:] == ['clickhouse', 'postgres', 'warm-tier']
    assert calls[1] == ['restore']
    assert ['run', '--rm', '--no-deps', '-T', 'migrate'] not in calls


def test_transfer_restore_uses_readonly_set_and_canonical_restore_commands(tmp_path, monkeypatch):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    host.override = tmp_path / 'state/install-compose.json'
    host.override.parent.mkdir()
    host.restore_from = tmp_path / 'recovery-set'
    host.restore_from.mkdir()
    host.restore_roles_file = tmp_path / 'roles.sql'
    host.restore_roles_file.write_text('CREATE ROLE synthetic_role;\n')
    host.restore_sync_owner_password = True
    host.restore_check_agent_trust = True
    monkeypatch.setattr(lifecycle.os, 'chown', lambda *args: None)
    calls = []
    host.compose = lambda args: calls.append(args) or 'linux_restore_verified\n'
    host.restore_fresh()
    assert len(calls) == 2
    assert calls[0][-8:] == ['--component', 'history', '--component', 'warm', '--component', 'files',
                            '--files-root', '/var/lib/sli']
    assert f'{host.restore_from}:/backups/recovery-set:ro' in calls[0]
    assert calls[1][-4:] == ['--roles-file', '/roles.sql', '--sync-owner-password', '--check-agent-trust']
    assert f'{host.restore_roles_file}:/roles.sql:ro' in calls[1]
    assert 'restore' in calls[1] and '/restore/postgres' in calls[1]
    assert '--replace-existing' not in calls[1]
    assert (host.override.parent / 'restore/postgres.log').read_text() == 'linux_restore_verified\n'


def test_install_cli_passes_transfer_options(tmp_path, monkeypatch, capsys):
    def install(*args, **options):
        host = args[3]
        assert host.restore_from == tmp_path / 'recovery-set'
        assert host.restore_roles_file == tmp_path / 'roles.sql'
        assert host.restore_sync_owner_password
        assert host.restore_check_agent_trust
        return {'status': 'installed'}

    monkeypatch.setattr(sli_install, 'install', install)
    args = [item for flag in ['--package', '--trust-store', '--compose', '--ca-file',
                             '--tls-certificate', '--tls-key'] for item in [flag, str(tmp_path / 'fixture')]]
    assert sli_install.main(args + ['--restore-from', str(tmp_path / 'recovery-set'),
                                   '--roles-file', str(tmp_path / 'roles.sql'), '--sync-owner-password',
                                   '--agent-secrets-from', str(tmp_path / 'agent-trust')]) == 0
    assert json.loads(capsys.readouterr().out)['status'] == 'installed'


def test_transfer_component_failure_blocks_postgres_import(tmp_path, monkeypatch):
    host = lifecycle.InstallationHost([], 'https://127.0.0.1:8443/api/health/ready', None)
    host.override = tmp_path / 'install-compose.json'
    host.restore_from = tmp_path / 'recovery-set'
    host.restore_from.mkdir()
    monkeypatch.setattr(lifecycle.os, 'chown', lambda *args: None)
    calls = []

    def compose(args):
        calls.append(args)
        raise lifecycle.UpdateError('installation_docker_failed')

    host.compose = compose
    with pytest.raises(lifecycle.UpdateError, match='installation_docker_failed'):
        host.restore_fresh()
    assert len(calls) == 1 and 'backup' in calls[0]


@pytest.mark.parametrize('extra', [['--roles-file', '/protected/roles.sql'], ['--sync-owner-password']])
def test_install_restore_only_options_require_recovery_set(tmp_path, extra):
    args = [item for flag in ['--package', '--trust-store', '--compose', '--ca-file',
                             '--tls-certificate', '--tls-key'] for item in [flag, str(tmp_path / 'fixture')]]
    with pytest.raises(SystemExit) as error:
        sli_install.main(args + extra)
    assert error.value.code == 2


@pytest.mark.parametrize('failure,reason', [
    ('min', 'update_incompatible_version'), ('max', 'update_incompatible_version'),
])
def test_adopted_package_cannot_claim_a_version_range(release, failure, reason):
    metadata = copy.deepcopy(release[3])
    metadata['from_version'] = 'adopted-1'
    metadata['compatibility'].update(from_version='adopted-1', min_version='adopted-1', max_version='adopted-1')
    metadata['compatibility'][failure + '_version'] = '1.0.0'
    with pytest.raises(packages.PackageError, match=reason):
        packages.validate_manifest(metadata, packages.PackageLimits())
