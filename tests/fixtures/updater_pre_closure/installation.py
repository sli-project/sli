"""Separate fresh-install and non-disruptive adoption lifecycles for project sli."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from deploy.linux.sli_update import (
    DockerHost, INFRA, UpdateError, atomic_json, canonical, image_inventory,
    load_deltas, operation_lock, parse_json, require, runtime_version_matches,
)
from scripts.maintenance.release_package import _bounded_read, extract_payload, verify_package
from deploy.linux.sli_secrets import AGENT_FILE_SETTINGS, agent_imports, ensure, validate_compose


RUNTIME_FLAGS = ('SLI_CORE_JOB_RADIUS_PILOT', 'SLI_CORE_JOB_AD_GPO_PILOT',
                 'SLI_AD_DC_AGENT_IMPORT_ENABLED', 'SLI_LEGACY_COLLECTION_DISABLED',
                 'SLI_CORE_JOB_WORKSTATIONS_RETENTION', 'SLI_CORE_JOB_WORKSTATIONS_PROJECTION')
DATA_VOLUMES = {'postgres-data': (999, 999), 'history-data': (101, 101), 'warm-data': (101, 101)}


def backup_directory(runtime, environment):
    path = Path(environment.get('SLI_BACKUP_DIR', str(runtime / 'backups')))
    require(path.is_absolute() and path == path.resolve() and path != Path(path.anchor)
            and not runtime.is_relative_to(path)
            and (not path.is_relative_to(runtime) or path == runtime / 'backups'),
            'install_invalid_backup_directory')
    return path


def prepare_backup_directory(path):
    # A supplied recovery set must keep its contents and existing permissions.
    require(not path.exists() or (path.is_dir() and not path.is_symlink() and not any(path.iterdir())),
            'install_backup_directory_not_empty')
    path.mkdir(mode=0o770, parents=True, exist_ok=True)
    path.chmod(0o770)
    os.chown(path, 10001, 10001)


def data_directory(runtime, environment):
    value = environment.get('SLI_DATA_DIR')
    if value is None:
        return None
    path = Path(value)
    backups = backup_directory(runtime, environment)
    require(path.is_absolute() and path == path.resolve() and path != Path(path.anchor)
            and not path.is_relative_to(runtime) and not runtime.is_relative_to(path)
            and not path.is_relative_to(backups) and not backups.is_relative_to(path),
            'install_invalid_data_directory')
    return path


def data_volume_options(directory, name):
    return {'type': 'none', 'o': 'bind', 'device': str(directory / name)}


def prepare_data_directories(directory, volumes):
    if directory is None:
        return
    paths = {directory / name: owner for name, owner in DATA_VOLUMES.items() if name in volumes}
    require(not directory.exists() or (directory.is_dir() and not directory.is_symlink()),
            'install_invalid_data_directory')
    # Validate every destination before changing any permissions or creating children.
    require(all(not path.is_symlink() and (not path.exists() or (path.is_dir() and not any(path.iterdir())))
                for path in paths), 'install_data_directory_not_empty')
    directory.mkdir(mode=0o755, parents=True, exist_ok=True)
    for path, (uid, gid) in paths.items():
        path.mkdir(mode=0o750, exist_ok=True)
        path.chmod(0o750)
        os.chown(path, uid, gid)


def preserve_compose(runtime, host, config):
    """Install resolved Compose plus its config binds, independent of the kit."""
    environment = getattr(host, 'environment', {})
    saved = copy.deepcopy(config)
    values = {'SLI_SECRETS_DIR': str(runtime / 'secrets'),
              'SLI_BACKUP_DIR': str(backup_directory(runtime, environment))}
    for name in RUNTIME_FLAGS:
        observed = {str(service['environment'][name]) for service in saved['services'].values()
                    if name in service.get('environment', {})}
        require(observed <= {'0', '1'}, 'install_invalid_runtime_flag')
        if len(observed) > 1:
            # Service-specific overlay values must remain service-specific.
            continue
        value = next(iter(observed), environment.get(
            name, '1' if name == 'SLI_CORE_JOB_WORKSTATIONS_RETENTION' else '0'))
        require(value in {'0', '1'}, 'install_invalid_runtime_flag')
        values[name] = value
    directory = runtime / 'compose'
    directory.mkdir(mode=0o750)
    copied = {}
    for service_name, service in saved['services'].items():
        service.pop('build', None)
        for name in RUNTIME_FLAGS:
            if name in service.get('environment', {}):
                value = service['environment'][name]
                if name in values:
                    service['environment'][name] = '${' + name + ':-' + str(value) + '}'
        for mount in service.get('volumes', []):
            if mount['type'] != 'bind' or not mount.get('read_only'):
                continue
            if notification_mount(runtime, service_name, mount):
                continue
            if mount['target'] == '/opt/sli/plugins':
                mount['source'] = str(runtime / 'plugins')
                (runtime / 'plugins').mkdir(exist_ok=True)
                continue
            source = Path(mount['source'])
            if str(source) not in copied:
                destination = directory / f'bind-{len(copied)}'
                require(not source.is_symlink(), 'install_config_symlink_forbidden')
                if source.is_dir():
                    require(all(not item.is_symlink() and (item.is_file() or item.is_dir())
                                for item in source.rglob('*')), 'install_config_symlink_forbidden')
                    shutil.copytree(source, destination)
                else:
                    destination.write_bytes(_bounded_read(source, 16 * 1024 * 1024))
                # The installer may run with umask 077; container identities
                # still need read/traverse access to their read-only config binds.
                paths = [destination, *destination.rglob('*')] if destination.is_dir() else [destination]
                for path in paths:
                    os.chown(path, 0, 10001)
                    path.chmod(0o750 if path.is_dir() else 0o640)
                copied[str(source)] = str(destination)
            mount['source'] = copied[str(source)]
    atomic_json(directory / 'compose.json', saved)
    # JSON quoting is also valid Compose env-file quoting and prevents injection.
    (runtime / 'runtime.env').write_text(''.join(f'{key}={json.dumps(value)}\n' for key, value in values.items()),
                                       encoding='utf-8')
    wrapper = runtime / 'sli-compose'
    wrapper.write_text('#!/bin/sh\nset -eu\n'
                       'runtime=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
                       'exec docker compose -p sli --env-file "$runtime/runtime.env" '
                       '-f "$runtime/compose/compose.json" -f "$runtime/state/install-compose.json" "$@"\n',
                       encoding='utf-8')
    wrapper.chmod(0o750)
    host.files = [directory / 'compose.json']


def mount_source(path):
    """Compare host paths with Docker Desktop's translated bind sources."""
    path = str(path).replace('\\', '/')
    prefix = '/run/desktop/mnt/host/'
    if path.startswith(prefix) and re.match(r'[a-zA-Z]/', path[len(prefix):]):
        path = path[len(prefix)] + ':' + path[len(prefix) + 1:]
    return path.casefold() if re.match(r'[a-zA-Z]:/', path) else path


def notification_mount(runtime, service, mount):
    allowed = {
        ('notification-setup', '/var/lib/notification-secrets'): ('notifications', False),
        ('notification-setup', '/run/notification-setup'): ('notification-control', False),
        ('notification-delivery', '/var/lib/notification-secrets'): ('notifications', True),
        ('api', '/run/notification-setup'): ('notification-control', True),
    }
    expected = allowed.get((service, mount.get('target')))
    return bool(expected and mount.get('type') == 'bind'
                and mount.get('read_only', False) is expected[1]
                and Path(mount.get('source', '')).resolve() == (runtime / 'secrets' / expected[0]).resolve())


class InstallationHost(DockerHost):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.environment = dict(os.environ)
        self.data_root = None
        self.override = None
        self.restore_from = None
        self.restore_roles_file = None
        self.restore_sync_owner_password = False
        self.restore_check_agent_trust = False

    def command(self, args, *, stdin=None):
        result = subprocess.run(args, input=stdin, capture_output=True, timeout=21600, check=False, env=self.environment)
        require(result.returncode == 0, 'installation_docker_failed')
        return result.stdout.decode('utf-8')

    def compose(self, args, override=None, *, stdin=None):
        return super().compose(args, override or self.override, stdin=stdin)

    def config(self):
        return parse_json(self.compose(['config', '--format', 'json']))

    def assert_unused(self, config):
        # Look at all containers, including stopped/one-off containers not in
        # the supplied Compose files. Also fence orphaned and unlabelled volumes.
        require(not self.command(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=sli']).strip(),
                'install_project_exists')
        require(not self.command(['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=sli']).strip(),
                'install_project_volumes_exist')
        existing = set(self.command(['docker', 'volume', 'ls', '-q']).splitlines())
        for key, value in config.get('volumes', {}).items():
            require(not value.get('external') and value.get('name', 'sli_' + key) not in existing,
                    'install_volume_exists')
            require(not value.get('driver_opts') or (
                self.data_root is not None and key in DATA_VOLUMES
                and value.get('driver', 'local') == 'local'
                and value['driver_opts'] == data_volume_options(self.data_root, key)),
                'install_volume_driver_forbidden')

    def adoption_inventory(self):
        config = self.config()
        rows = self.containers()
        running = [row for row in rows if row['State'] == 'running']
        services = {row['Service'] for row in running}
        require(INFRA | {'api', 'backup'} <= services, 'adopt_incomplete_installation')
        require(len(services) == len(running), 'adopt_duplicate_service')
        require(not any(row['Service'] != 'migrate' and row['State'] != 'running' for row in rows),
                'adopt_stopped_service')
        required = {name for name, value in config['services'].items()
                    if name != 'migrate' and not value.get('profiles')}
        require(required <= services <= config['services'].keys() - {'migrate'}, 'adopt_service_inventory_mismatch')
        all_ids = set(self.command(['docker', 'ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=sli']).splitlines())
        require(all_ids == {row['ID'] for row in rows}, 'adopt_orphan_container')
        app = sorted(services - INFRA)
        digest = None
        image_tag = None
        volumes = set()
        for row in running:
            actual = parse_json(self.command(['docker', 'inspect', row['ID']]))[0]
            labels = actual['Config'].get('Labels', {})
            require(labels.get('com.docker.compose.project') == 'sli'
                    and labels.get('com.docker.compose.service') == row['Service'], 'adopt_foreign_container')
            require(actual['Image'] == self.image_id(config['services'][row['Service']]['image']),
                    'adopt_config_image_mismatch')
            if row['Service'] in app:
                digest = digest or actual['Image']
                require(actual['Image'] == digest, 'adopt_mixed_images')
                image_tag = image_tag or actual['Config']['Image']
                require(actual['Config']['Image'] == image_tag, 'adopt_mixed_image_tags')
            actual_mounts = {mount['Destination'].rstrip('/'): mount for mount in actual['Mounts']}
            for target in actual_mounts:
                require(not (target in {'', '/opt', '/opt/sli'} or target.startswith('/opt/sli/'))
                        or target in {'/opt/sli/data', '/opt/sli/artifacts'}, 'adopt_code_mount_forbidden')
            for mount in config['services'][row['Service']].get('volumes', []):
                target = mount['target'].rstrip('/')
                require(not (target in {'/', '/opt', '/opt/sli'} or target.startswith('/opt/sli/'))
                        or target in {'/opt/sli/data', '/opt/sli/artifacts'}, 'adopt_code_mount_forbidden')
                live = actual_mounts.get(target, {})
                if mount['type'] == 'volume':
                    name = config['volumes'][mount['source']]['name']
                    require(live.get('Type') == 'volume' and live.get('Name') == name, 'adopt_volume_mismatch')
                    volumes.add(name)
                else:
                    require(live.get('Type') == mount['type'] and mount_source(live.get('Source')) == mount_source(mount['source']),
                            'adopt_mount_mismatch')
            for secret in config['services'][row['Service']].get('secrets', []):
                source = config['secrets'][secret['source']].get('file')
                target = '/run/secrets/' + secret.get('target', secret['source'])
                require(source and Path(source).is_file() and Path(source).stat().st_size > 0,
                        'adopt_secret_missing')
                require(mount_source(actual_mounts.get(target, {}).get('Source')) == mount_source(source),
                        'adopt_secret_mount_mismatch')
        require(volumes, 'adopt_volumes_missing')
        # Validate the migrator and service health contracts without altering them.
        provisional = {'image_tag': image_tag, 'image_digest': digest}
        require(self.inspect_installation(provisional) == app, 'adopt_service_inventory_mismatch')
        require(self.image_id(config['services']['migrate']['image']) == digest, 'adopt_migrator_image_mismatch')
        for secret in config['services']['migrate'].get('secrets', []):
            source = config['secrets'][secret['source']].get('file')
            require(source and Path(source).is_file() and Path(source).stat().st_size > 0, 'adopt_secret_missing')
        metadata = parse_json(self.command(['docker', 'image', 'inspect', digest]))[0]
        label = (metadata['Config'].get('Labels') or {}).get('org.opencontainers.image.version')
        require(label is None or re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', label),
                'adopt_invalid_version_metadata')
        require(metadata['Os'] == 'linux' and metadata['Architecture'] in {'amd64', 'arm64'}, 'adopt_platform_mismatch')
        backup = next(row for row in running if row['Service'] == 'backup')
        source = Path(__file__).with_name('adoption_probe.py').read_text('utf-8')
        database = parse_json(self.command(['docker', 'exec', '-e', 'PYTHONDONTWRITEBYTECODE=1',
                                            backup['ID'], 'python', '-c', source]))
        if 'reason_code' in database:
            reason = database['reason_code']
            require(reason in {'adopt_ledger_inconsistent', 'adopt_plugins_inconsistent', 'adopt_database_probe_failed'},
                    'adopt_database_probe_failed')
            raise UpdateError(reason)
        require(database.get('migrations') and type(database.get('migration_ledger_max_version')) is int
                and database['migration_ledger_max_version'] > 0, 'adopt_ledger_inconsistent')
        return {'component': 'server', 'version': label or f"adopted-{database['migration_ledger_max_version']}",
                'os': metadata['Os'], 'architecture': metadata['Architecture'],
                'image_tag': image_tag, 'image_digest': digest, **database,
                'compose_project': 'sli', 'volumes': {key: value['name'] for key, value in config['volumes'].items()},
                'adoption': {'project': 'sli', 'volumes_sha256': hashlib.sha256(canonical(sorted(volumes))).hexdigest()}}

    def adoption_preflight(self, installed):
        from deploy.linux.installed_state import ledger_matches, plugins_match, registry_matches
        config = self.config()
        self.ownership_preflight(installed, config)
        self.secrets_preflight(config, {*INFRA, 'migrate', *self.inspect_installation(installed)})
        if self.ca_file:
            self.tls_preflight()
        observed = self.observe()
        registry = observed.get('installed_release')
        if registry and registry.get('inventory', {}).get('image_digest') == installed['image_digest']:
            for key in ('build_id', 'source_commit'):
                installed[key] = registry['inventory'].get(key)
        inventory_max = max(int(Path(path).name.split('_', 1)[0]) for path in installed['migrations'])
        require(observed['migration_ledger_max'] == installed['migration_ledger_max_version'] == inventory_max,
                'adopt_ledger_inconsistent')
        try:
            ledger_matches(installed, observed)
        except UpdateError:
            raise UpdateError('adopt_ledger_inconsistent') from None
        plugins_match(installed, observed)
        registry_matches(installed, observed)
        require(observed['services'] and all(runtime_version_matches(value['version'], installed)
                and value['image_digest'] == installed['image_digest'] and value['image_tag'] == installed['image_tag']
                for value in observed['services'].values()), 'adopt_running_version_mismatch')
        return observed

    def fresh_config(self, runtime):
        backups = backup_directory(runtime, self.environment)
        self.data_root = data_directory(runtime, self.environment)
        self.environment.update(SLI_SECRETS_DIR=str(runtime / 'secrets'), SLI_BACKUP_DIR=str(backups),
                                SLI_PLUGIN_DIR=str(runtime / 'plugins'))
        self.environment.update({setting: str(runtime / 'secrets' / name)
                                 for name, setting in AGENT_FILE_SETTINGS.items()})
        config = self.config()
        require(INFRA | {'api', 'backup', 'migrate'} <= config['services'].keys(), 'install_incomplete_compose')
        for name, value in config.get('secrets', {}).items():
            require(value.get('file') == str(runtime / 'secrets' / name), 'install_secret_layout_mismatch')
        # The supplied Compose files are host-owned. Rewrite external volumes to
        # fresh project-owned volumes; do not import production storage defaults.
        self.override = runtime / 'state/install-compose.json'
        override = {'volumes': {name: {'external': False, 'name': 'sli_' + name}
                                for name in config.get('volumes', {})}}
        if self.data_root is not None:
            for name in DATA_VOLUMES.keys() & override['volumes'].keys():
                override['volumes'][name].update(driver='local', driver_opts=data_volume_options(self.data_root, name))
        for service_name, service in config['services'].items():
            for mount in service.get('volumes', []):
                if mount['type'] == 'bind' and not mount.get('read_only'):
                    require(Path(mount['source']).resolve() == backups or notification_mount(runtime, service_name, mount),
                            'install_existing_data_bind_forbidden')
        return config, override

    def start_fresh(self, services):
        self.compose(['up', '-d', '--no-deps', '--no-build', '--pull', 'never', '--wait', *sorted(INFRA)])
        # Compose 2.26 lacks run --pull; the verified digest is already loaded.
        if self.restore_from is None:
            self.compose(['run', '--rm', '--no-deps', '-T', 'migrate'])
        else:
            self.restore_fresh()
        self.compose(['up', '-d', '--no-deps', '--no-build', '--pull', 'never', *services])
        self.health({'services': services})

    def restore_fresh(self):
        """Import a recovery set before any fresh migration or application start."""
        source = self.restore_from.resolve()
        require(source.is_dir() and ':' not in str(source), 'install_invalid_restore_source')
        if self.restore_roles_file is not None:
            roles = self.restore_roles_file.resolve()
            require(roles.is_file() and ':' not in str(roles), 'install_invalid_roles_file')
        evidence = self.override.parent / 'restore'
        evidence.mkdir(mode=0o750)
        os.chown(evidence, 10001, 10001)
        mounts = ['-v', f'{evidence}:/evidence']
        # Component restore verifies the complete recovery-set checksum inventory
        # before SQL import. Its writable staging stays in the NEW backup root.
        components = ['run', '--rm', '--no-deps', '-T', *mounts,
                      '-v', f'{source}:/backups/{source.name}:ro', '--entrypoint', 'python',
                      'backup', '-m', 'deploy.linux.restore_existing', f'/backups/{source.name}',
                      '--result-file', '/evidence/components-result.json',
                      '--component', 'history', '--component', 'warm', '--component', 'files',
                      '--files-root', '/var/lib/sli']
        (evidence / 'components.log').write_text(self.compose(components), encoding='utf-8')
        restore = ['run', '--rm', '--no-deps', '-T', *mounts, '-v', f'{source}:/restore:ro']
        if self.restore_roles_file is not None:
            restore += ['-v', f'{roles}:/roles.sql:ro']
        restore += ['migrate', 'restore', '/restore/postgres', '--jobs', '4',
                    '--result-file', '/evidence/result.json']
        if self.restore_roles_file is not None:
            restore += ['--roles-file', '/roles.sql']
        if self.restore_sync_owner_password:
            restore.append('--sync-owner-password')
        if self.restore_check_agent_trust:
            restore.append('--check-agent-trust')
        (evidence / 'postgres.log').write_text(self.compose(restore), encoding='utf-8')


def adopt(runtime, host, *, dry_run=False):
    runtime = Path(runtime)
    state = runtime / 'state'
    with operation_lock(state):
        require(not (state / 'install-status.json').exists() or
                parse_json((state / 'install-status.json').read_bytes()).get('status') == 'installed',
                'adopt_install_recovery_required')
        require(not (state / 'update-journal.json').exists() or
                parse_json((state / 'update-journal.json').read_bytes()).get('status') in
                {'committed', 'rolled_back', 'rejected'}, 'adopt_update_in_progress')
        detected = host.adoption_inventory()
        from deploy.linux.installed_state import pointers_match
        for plugin_id, value in detected.get('plugins', {}).items():
            require(re.fullmatch(r'sli\.[a-z0-9-]+', plugin_id), 'update_plugin_inventory_required')
            pointer = runtime / 'plugins' / plugin_id / 'active.json'
            if pointer.is_file():
                generation = parse_json(pointer.read_bytes()).get('generation')
                require(isinstance(generation, str) and re.fullmatch(r'[a-f0-9]{64}', generation),
                        'update_plugin_pointer_mismatch')
                release = runtime / 'plugins' / plugin_id / 'versions' / generation / 'release.json'
                manifest = parse_json(release.read_bytes())
                value.update(generation=generation, migrations=manifest['migrations'])
        pointers_match(runtime, detected)
        observed = host.adoption_preflight(detected)
        result = {'status': 'dry_run' if dry_run else 'adopted', 'installed': not dry_run, 'executed': False,
                  'operation': None, 'phase': None, 'package_version': None,
                  'migration_ledger': {'max_version': observed['migration_ledger_max']},
                  'desired_activation': {key: detected[key] for key in ('version', 'image_tag', 'image_digest')},
                  'observed_runtime': observed, 'reason_code': None}
        installed = state / 'installed.json'
        if installed.exists():
            previous = parse_json(installed.read_bytes())
            if previous.get('adoption'):
                require(previous['adoption'] == detected['adoption'], 'adopt_installed_volumes_changed')
            require(all(previous.get(key) == detected[key] for key in
                        ('component', 'version', 'os', 'architecture', 'image_tag', 'image_digest', 'migrations',
                         'compose_project', 'volumes')),
                    'adopt_installed_state_mismatch')
            for key in ('migration_ledger', 'plugins'):
                require(key not in previous or previous[key] == detected[key], 'adopt_installed_state_mismatch')
            if 'migration_ledger' not in previous and not dry_run:
                atomic_json(installed, detected)
            return {**result, 'status': 'adopted', 'installed': True}
        if not dry_run:
            atomic_json(installed, detected)
        return result


def notification_options(notification):
    """No environment proxy fallback; omission never changes retained setup."""
    if notification is None:
        return None
    from server.sli.core.telegram_setup import validate_proxy_url
    require(isinstance(notification, dict) and set(notification) == {'proxy_url'},
            'install_notification_invalid')
    return {'proxy_url': validate_proxy_url(notification['proxy_url'])}


def configure_notification(config, directory, notification):
    from deploy.linux.sli_secrets import _check_path, _publish
    from urllib.parse import urlsplit
    path = Path(directory) / 'notifications' / 'telegram.json'
    if path.exists() or path.is_symlink():
        _check_path(path)
        previous = parse_json(_bounded_read(path, 65536))
        require(isinstance(previous, dict), 'install_notification_invalid')
    else:
        public_url = config['services']['notification-setup'].get('environment', {}).get('SLI_PUBLIC_URL', '')
        url = urlsplit(public_url)
        require(url.scheme == 'https' and url.hostname and not url.username and not url.password,
                'install_notification_public_url_required')
        previous = {'base_url': f'https://{url.netloc}/app', 'recipients': {}, 'names': {}}
    value = {**previous, 'proxy_url': notification['proxy_url']}
    body = json.dumps(value, ensure_ascii=False).encode('utf-8')
    require(len(body) <= 65536, 'install_notification_invalid')
    _publish(path, body, replace=True)


def create_secrets(config, directory, tls_files, *, agent_secrets_from=None, notification=None):
    validate_compose(config)
    notification = notification_options(notification)
    require(notification is None or 'notification-setup' in config.get('services', {}),
            'install_notification_compose_required')
    imports = dict(tls_files)
    if agent_secrets_from is not None:
        imports.update(agent_imports(agent_secrets_from))
        require(imports.keys() - tls_files.keys() <= config.get('secrets', {}).keys(),
                'install_agent_compose_required')
    ensure(directory, names=config.get('secrets', {}), imports=imports)
    if 'notification-setup' in config.get('services', {}):
        from deploy.linux.sli_secrets import _directory
        _directory(Path(directory) / 'notifications')
        _directory(Path(directory) / 'notification-control')
        if notification is not None:
            configure_notification(config, directory, notification)


def install(package, trust_store, runtime, host, tls_files, *, evaluation_kit=None, inventory_sha256=None,
            agent_secrets_from=None, notification=None):
    notification = notification_options(notification)
    runtime = Path(runtime).resolve()
    if evaluation_kit is not None:
        from deploy.linux.evaluation_package import verify
        verified = verify(package, evaluation_kit, inventory_sha256)
    else:
        verified = verify_package(package, trust_store)
    manifest = verified.manifest
    require(manifest['schema_version'] == 2 and manifest['package_type'] == 'core-install'
            and manifest['component'] == 'server', 'install_package_required')
    require(os.name != 'nt' and os.geteuid() == 0, 'install_linux_root_required')
    require(not runtime.exists() or not any(runtime.iterdir()), 'install_runtime_not_empty')
    if evaluation_kit is None:
        require(not Path(trust_store).resolve().is_relative_to(runtime), 'install_external_trust_required')
    else:
        require(not Path(evaluation_kit).resolve().is_relative_to(runtime), 'install_external_kit_required')
    require(shutil.disk_usage(runtime.parent).free >= max(manifest['required_free_disk'], 3 * verified.total_bytes),
            'install_insufficient_disk')
    for name in ('tls_ca', 'tls_certificate', 'tls_key'):
        require(name in tls_files and _bounded_read(Path(tls_files[name]), 1024 * 1024), 'install_tls_required')
    # Verify the image and deltas before provisioning the runtime or Docker state.
    with tempfile.TemporaryDirectory() as temporary:
        payload = Path(temporary) / 'payload'
        extract_payload(verified, payload)
        image_inventory(payload / manifest['image']['path'], manifest, Path(temporary) / 'image.tar')
        delta = load_deltas(payload, manifest)
        config, override = host.fresh_config(runtime)
        host.assert_unused({'volumes': override['volumes']})
        services = sorted(name for name, value in config['services'].items()
                          if name not in INFRA | {'migrate'} and not value.get('profiles'))
        override['services'] = {name: {'image': manifest['image']['digest']} for name in [*services, 'migrate']}
        if delta:
            override['services']['backup']['environment'] = delta
        runtime.mkdir(parents=True, exist_ok=True)
        # Fresh bootstrap has no update journal or checkpoint to trust. Keep the
        # shared OS lock, reserving update-state validation for the updater.
        with operation_lock(runtime / 'state', protect_state=False):
            require(not any((runtime / name).exists() for name in ['secrets', 'backups', 'state/installed.json',
                                                                  'state/install-status.json']),
                    'install_runtime_not_empty')
            atomic_json(runtime / 'state/install-status.json', {'status': 'installing'})
            try:
                create_secrets(config, runtime / 'secrets', tls_files, agent_secrets_from=agent_secrets_from,
                               **({'notification': notification} if notification is not None else {}))
                environment = getattr(host, 'environment', {})
                prepare_backup_directory(backup_directory(runtime, environment))
                prepare_data_directories(data_directory(runtime, environment), config.get('volumes', {}))
                preserve_compose(runtime, host, config)
                atomic_json(host.override, override)
                resolved = host.config()
                host.assert_unused(resolved)
                # Rebuilt releases may share a version; preserve older image tags.
                host.stage(payload, manifest, 'sli-install:' + manifest['image']['digest'].replace(':', '-'))
                host.start_fresh(services)
                installed = {
                    'component': 'server', 'version': manifest['version'], 'os': manifest['compatibility']['os'],
                    'architecture': manifest['compatibility']['architecture'], 'image_tag': manifest['image']['digest'],
                    'image_digest': manifest['image']['digest'], 'migrations': manifest['migrations'],
                    'override': str(host.override), 'source_commit': manifest['source_commit'],
                    'build_id': manifest['build_id'],
                    'compose_project': 'sli', 'volumes': {key: value['name'] for key, value in resolved.get('volumes', {}).items()},
                }
                if evaluation_kit is not None:
                    installed.update(signing='evaluation-unsigned', authenticated=False)
                from deploy.linux.installed_state import validate
                observed = host.observe()
                installed['migration_ledger'] = observed.get('migration_ledger')
                installed['plugins'] = {row['plugin_id']: {'version': row['version'], 'migrations': {}}
                                        for row in observed['plugins'] if row['installed']}
                validate(installed, observed, runtime)
                host.publish_installed(installed, installed, secrets.token_hex(16))
                validate(installed, host.observe(), runtime)
                atomic_json(runtime / 'state/installed.json', installed)
                atomic_json(runtime / 'state/install-status.json', {'status': 'installed'})
            except Exception:
                # Never delete volumes or pretend an interrupted bootstrap is
                # empty. An operator can inspect this explicitly fenced runtime.
                atomic_json(runtime / 'state/install-status.json', {'status': 'recovery_required'})
                raise
    result = {'status': 'installed', 'installed': True, 'executed': True,
              'next_steps': 'Configure the platform-owner account using the protected platform_owner_password file.'}
    if evaluation_kit is not None:
        result.update(signing='evaluation-unsigned', authenticated=False)
    return result
