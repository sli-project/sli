"""Restore a verified native recovery set with writers fenced."""
from datetime import datetime, timezone
from itertools import chain
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from uuid import uuid4

from deploy.linux import backup, native_backup as native, native_host as host, native_install as install
from deploy.linux import native_runtime as runtime, native_upgrade as upgrade, operation_wait, restore_existing
from deploy.linux import sli_secrets
from deploy.linux.native_clickhouse_endpoint import parse_site
from deploy.linux.native_setup import render_site, replace_text, setup_lock
from deploy.linux.update_checkpoint import snapshot

NOTIFICATION_FILES = frozenset({'telegram.json', 'smtp.json', 'smtp.ready',
                                'notification_telegram_token', 'notification_smtp_password'})


def private_source(source):
    install.trusted_path(source / 'manifest.json')
    native.require(source == source.resolve(), 'native_restore_source_not_private')
    for path in chain((source,), source.rglob('*')):
        info = path.lstat()
        native.require(info.st_uid == 0 and not info.st_mode & 0o077
                       and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
                       'native_restore_source_not_private')
        operation_wait.made_progress()


def pending(kind):
    for path in upgrade.TRANSACTIONS.iterdir():
        journal = upgrade.Journal(path)
        if journal.value.get('kind') == kind and journal.value.get('services_restored') is not True:
            return journal
    return None


def begin(kind, **values):
    stamp = datetime.now(timezone.utc).isoformat()
    path = upgrade.TRANSACTIONS / uuid4().hex
    with tempfile.TemporaryDirectory(prefix='.restore-intent-', dir=path.parent.parent) as temporary:
        intent = Path(temporary) / path.name
        native.ensure_directory(intent, 0o700)
        install.atomic(intent / 'journal.json', {'schema_version': 1, 'transaction': path.name,
                       'kind': kind, 'status': 'recovering', 'step': 'before', 'created_at_utc': stamp, **values})
        upgrade.publish(upgrade.Journal(intent), 'recovering', terminal=False)
        intent.rename(path)
    upgrade.sync_tree(upgrade.TRANSACTIONS, recursive=False)
    return upgrade.Journal(path)


def save_current(journal):
    """Preserve all current data before replacement, outside scheduled retention."""
    directory = native.ROOT / 'before-restore' / journal.path.name
    if identifier := journal.value.get('safety_backup'):
        native.require(backup.BACKUP_NAME.fullmatch(identifier), 'native_restore_safety_backup_invalid')
        point = directory / identifier
        native.require(upgrade.digest(point / 'manifest.json') == journal.value['safety_backup_sha256'],
                       'native_restore_safety_backup_invalid')
        native.verify(point)
        return
    native.ensure_directory(directory, 0o700, parent_mode=0o700)
    print('Saving current data / Сохраняем текущие данные', flush=True)
    point = native.capture_locked(directory, writers_fenced=True)
    upgrade.sync_tree(directory)
    journal.value.update(safety_backup=point.name, safety_backup_sha256=upgrade.digest(point / 'manifest.json'))
    journal.write()
    print(f'Previous data / Прежние данные: {point}', flush=True)


def write_secret(destination, body):
    import grp

    gid = grp.getgrnam('sli-secrets').gr_gid
    if destination.exists() or destination.is_symlink():
        install.trusted_path(destination)
    native.ensure_directory(destination.parent, 0o750, gid=gid)
    fd, temporary = tempfile.mkstemp(dir=destination.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body)
            os.fchown(stream.fileno(), 0, gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        upgrade.sync_tree(destination.parent, recursive=False)
    finally:
        Path(temporary).unlink(missing_ok=True)


def secret_material(companion, config):
    manifest = sli_secrets.load_manifest()
    names = {name for name, spec in manifest.items() if spec['group'] in {'tls', 'agents', 'notifications'}}
    names.add('platform_owner_password')
    material = {}
    for name in names | {'notifications/' + name for name in NOTIFICATION_FILES}:
        path = companion / 'secrets' / name
        if not path.is_file():
            continue
        body = path.read_bytes()
        spec = manifest.get(path.name)
        if spec is not None:
            sli_secrets._validate(path.name, spec, body)
        material[name] = body
    required = {'tls_certificate', 'tls_key', 'tls_ca', 'platform_owner_password'}
    if config.get('agents'):
        required.update(install.AGENT_SECRETS)
    native.require(required <= material.keys(), 'native_restore_missing_credentials')
    sli_secrets._validate_bundles(material, manifest)
    return material


def restore(source):
    source = source.absolute()
    private_source(source)
    with setup_lock():
        fresh = not (install.STATE / 'installed.json').exists()
        if fresh:
            native.ensure_directory(upgrade.TRANSACTIONS, 0o700)
            native.ensure_directory(native.ROOT, 0o700, parent_mode=0o700)
        else:
            host.Host().require_backup_mount()
        with upgrade.operation_lock(native.ROOT):
            print('Verifying recovery set / Проверяем копию', flush=True)
            with snapshot(source.parent, source.name, temporary_root=native.ROOT,
                          progress=operation_wait.made_progress) as (private, _):
                restore_verified(private, source.name, fresh)


def restore_verified(private, identifier, fresh):
    _, data, data_manifest = native.verify(private, identifier)
    native.require(set(data_manifest['components']) == {'postgres', 'files'}, 'native_restore_components_unsupported')
    companion = private / 'companion'
    captured = json.loads((companion / 'state/installed.json').read_bytes())
    release = (runtime.document(install.STATE / 'pending-release.json')['release'] if fresh
               else runtime.release()[0].name)
    root, manifest, digest = install.inventory(release)
    native.require(captured.get('manifest_sha256') == digest, 'native_restore_version_mismatch')
    config = json.loads((companion / 'runtime.json').read_bytes())
    site = parse_site((companion / 'site.toml').read_text(encoding='utf-8'))
    local_site = {} if fresh else install.site_configuration()
    for key in ('backup_root', 'cold_tablespace_root'):
        site.pop(key, None)
        if key in local_site:
            site[key] = local_site[key]
    if config.get('ad_credentials'):
        native.require((install.SECRETS / 'ad_credentials_master_key').is_file(),
                       'native_restore_ad_key_required')
    material = secret_material(companion, config)
    checksum = upgrade.digest(private / 'manifest.json')
    journal = pending('restore')
    if journal is None:
        runtime.no_transaction()
        if fresh:
            native.require(not (install.STATE / 'package-install.json').exists()
                           and not (install.STATE / 'host-prepared.json').exists()
                           and not install.SITE.exists()
                           and all(path.name in runtime.PRESERVED_DATA_DIRECTORIES for path in native.DATA.iterdir())
                           and (not install.SECRETS.exists() or all(path.name == 'ad_credentials_master_key'
                                for path in install.SECRETS.iterdir())), 'native_restore_target_not_fresh')
        journal = begin('restore', input_sha256=checksum, fresh=fresh, previous=release)
    value = journal.value
    native.require(value['input_sha256'] == checksum and value['previous'] == release,
                   'native_restore_retry_same_backup')
    if not value['fresh']:
        upgrade.remember_backup_schedule(journal)
    if value['status'] != 'committed':
        if value['fresh']:
            prepare_host(journal, site)
        else:
            upgrade.fence()
            save_current(journal)
        if not value.get('data_restored'):
            apply_data(data, data_manifest, config, site, material, fresh=value['fresh'])
            upgrade.switch(root, manifest, digest)
            install.atomic(install.STATE / 'package-install.json', {'schema_version': 1, 'release': release,
                           'site_sha256': install.site_digest(site), 'status': 'configured', 'first_start_pending': False})
            native.configure()
            install.preserve_recovery(root, manifest, digest)
            value['data_restored'] = True
            journal.write()
        accept(journal, release)
    finish(journal, 'committed')


def prepare_host(journal, site):
    if not journal.value.get('host_configured'):
        machine = host.Host()
        machine.write(str(install.SITE), render_site(site))
        with host.administrative_lock():
            machine.prepare()
        machine.configure()
        journal.value['host_configured'] = True
        journal.write()
    install.command(['systemctl', 'start', *runtime.DATABASES])
    if not journal.value.get('postgres_bootstrapped'):
        install.command(['systemctl', 'start', 'sli-bootstrap-pg.service'])
        journal.value['postgres_bootstrapped'] = True
        journal.write()
    upgrade.fence()


def restore_credentials(material, config):
    for name, body in material.items():
        write_secret(install.SECRETS / name, body)
    # The fenced safety set holds the destination's current notification files.
    # A channel absent from the selected copy must not inherit later settings.
    notification_paths = {'notifications/' + name for name in NOTIFICATION_FILES}
    notification_paths.update(name for name in NOTIFICATION_FILES if name.startswith('notification_'))
    for relative in notification_paths - material.keys():
        path = install.SECRETS / relative
        if path.exists() or path.is_symlink():
            install.trusted_path(path)
            path.unlink()
            upgrade.sync_tree(path.parent, recursive=False)
    if config.get('agents'):
        sli_secrets.agent_imports(install.SECRETS)


def apply_data(data, manifest, config, site, material, *, fresh):
    if not fresh:
        replace_text(install.SITE, render_site(site), mode=0o640)
        replace_text(runtime.CONFIG, json.dumps(config, sort_keys=True) + '\n', mode=0o644)
    restore_credentials(material, config)
    runtime.configure(config)
    # The target PostgreSQL passwords remain bound to its local roles. The
    # dump contains role definitions and memberships, with passwords excluded.
    print('Restoring PostgreSQL / Восстанавливаем PostgreSQL', flush=True)
    with native.environment(native.settings()):
        restore_existing.restore_postgres(data, manifest, replace_existing=True,
                                          use_default_tablespace='cold_tablespace_root' not in site)
        print('Restoring files and settings / Восстанавливаем файлы и настройки', flush=True)
        restore_existing.restore_files(data, native.DATA, replace_existing=True)
    ca = native.DATA / 'tls-ca.crt'
    if ca.exists():
        os.chown(ca, 0, 0)
        ca.chmod(0o644)
    root = Path.cwd()
    install.command([sys.executable, '-B', '-m', 'deploy.linux.entrypoint', 'migrate'], cwd=root,
                    env=install.environment(), timeout=None)


def accept(journal, release, checked_runtime=None):
    print('Checking restored services / Проверяем восстановленные службы', flush=True)
    journal.value.update(status='candidate_testing', step='before', testing_release=release)
    journal.write()
    try:
        upgrade.testing_units(journal.path.name)
        upgrade.start_checked(checked_runtime)
    finally:
        upgrade.fence()
        upgrade.testing_units()
    journal.value.update(status='committed', step='after', accepted_release=release)
    journal.write()


def finish(journal, status, checked_runtime=None):
    schedule = None if journal.value.get('fresh') else upgrade.remember_backup_schedule(journal)
    upgrade.publish(journal, status, accepted_release=journal.value['accepted_release'])
    upgrade.start_checked(checked_runtime)
    install.command(['systemctl', 'enable', '--now', 'sli.target'])
    install.start_backup_schedule(schedule)
    journal.value['services_restored'] = True
    journal.write()
    upgrade.publish(journal, status, accepted_release=journal.value['accepted_release'], services_restored=True)


def previous_update(release):
    updates = []
    for path in upgrade.TRANSACTIONS.iterdir():
        journal = upgrade.Journal(path)
        value = journal.value
        if (not value.get('kind') and value['status'] == 'committed' and value.get('accepted_release') == release
                and value.get('previous_version') and upgrade.finished_transaction(journal)):
            updates.append(journal)
    native.require(updates, 'native_upgrade_no_previous_release')
    return max(updates, key=lambda journal: journal.value['created_at_utc'])


def rollback_packages(version, kit):
    native.require(re.fullmatch(r'[0-9][a-zA-Z0-9.+~]*-[0-9]+~deb13', version),
                   'native_upgrade_package_invalid')
    packages = ('sli', 'sli-host', 'sli-rollback-hold', 'sli-server-dotnet')
    if kit is None:
        return {package: f'{package}={version}' for package in packages}
    kit = kit.absolute()
    native.require(kit.is_dir() and kit.resolve() == kit, 'native_upgrade_previous_packages_unavailable')
    matches = {}
    for path in kit.glob('*.deb'):
        install.trusted_path(path)
        metadata = native.command(['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture']).decode()
        fields = dict(line.split(': ', 1) for line in metadata.splitlines() if ': ' in line)
        name = fields.get('Package')
        if name in packages and fields.get('Version') == version:
            native.require(name not in matches and fields.get('Architecture') in {'amd64', 'all'},
                           'native_upgrade_previous_packages_unavailable')
            matches[name] = str(path)
    native.require(set(matches) == set(packages), 'native_upgrade_previous_packages_unavailable')
    return matches


def apt_rollback(version, packages, *, download_only=False):
    options = ['--download-only'] if download_only else []
    try:
        install.command(['apt-get', '-y', '--allow-downgrades', '--no-remove', *options,
                         'install', *packages.values()], timeout=None)
    except (OSError, RuntimeError):
        reason = ('native_upgrade_previous_packages_unavailable' if download_only
                  else 'native_upgrade_rollback_package_failed')
        raise RuntimeError(reason) from None
    if not download_only:
        for package in packages:
            installed = native.command(['dpkg-query', '-W', '-f=${Status}\t${Version}', package]).decode()
            native.require(installed == 'install ok installed\t' + version, 'native_upgrade_package_mismatch')


def rollback(kit=None):
    with setup_lock():
        host.Host().require_backup_mount()
        with upgrade.operation_lock(native.ROOT):
            journal = pending('rollback')
            if journal is None:
                runtime.no_transaction()
                current = runtime.release()[0].name
                source = previous_update(current)
            else:
                source = upgrade.Journal(upgrade.TRANSACTIONS / journal.value['checkpoint_transaction'])
                current = journal.value['candidate']
            value = source.value
            release, version = value['previous'], value['previous_version']
            packages = rollback_packages(version, kit)
            root, manifest, digest = install.inventory(release)
            recovery, _ = upgrade.verify_recovery(release)
            if journal is None:
                upgrade.checkpoint_receipt(source)
                native.verify(upgrade.checkpoint_root(source) / value['checkpoint'])
                print('Checking the previous Debian kit / Проверяем предыдущий комплект Debian', flush=True)
                apt_rollback(version, packages, download_only=True)
                journal = begin('rollback', candidate=current, previous=release, checkpoint_transaction=source.path.name)
            schedule = upgrade.remember_backup_schedule(journal)
            if journal.value['status'] != 'rolled_back':
                if not journal.value.get('checkpoint_restored'):
                    upgrade.fence()
                    save_current(journal)
                    print('Restoring the pre-update copy / Восстанавливаем копию перед обновлением', flush=True)
                    upgrade.restore_checkpoint(journal, committed_source=source)
                upgrade.switch(root, manifest, digest)
                upgrade.testing_units()
                journal.value.update(status='rolled_back', step='after', accepted_release=release)
                journal.write()
                upgrade.publish(journal, 'rolled_back', accepted_release=release, package_reconciliation_required=True)
        # Maintainer scripts take the canonical lock themselves. They will see
        # the previous release already selected and must not prepare it again.
        print('Installing the previous packages / Устанавливаем предыдущие пакеты', flush=True)
        try:
            apt_rollback(version, packages)
        finally:
            install.undo_legacy_backup_enable(schedule)
        finish(journal, 'rolled_back', upgrade.retained_runtime(recovery))
