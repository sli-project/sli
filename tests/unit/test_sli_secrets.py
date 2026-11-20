"""Secret provisioning contracts; temporary files and fake ownership only."""

import json
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from deploy.linux import sli_secrets as subject
from server.sli.agents.ca import IssuingCA

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def ownership(monkeypatch):
    if os.name == 'nt':
        monkeypatch.setattr(subject, '_windows_acl', lambda *args, **kwargs: None)
    else:
        monkeypatch.setattr(subject.os, 'geteuid', lambda: 0)
        monkeypatch.setattr(subject.os, 'chown', lambda *args: None)
        monkeypatch.setattr(subject, '_check_owner', lambda *args: None)


def test_all_compose_secrets_are_in_manifest():
    manifest = subject.load_manifest()
    for path in (ROOT / 'deploy').rglob('*compose*.y*ml'):
        subject.validate_compose(yaml.safe_load(path.read_text('utf-8')), manifest)


@pytest.mark.parametrize('mounted', [[], ['runtime_password']])
def test_compose_rejects_secret_file_setting_without_its_service_mount(mounted):
    config = {'services': {'storage-lifecycle': {
        'environment': {'ADLOG_STORAGE_V2_WORKER_PASSWORD_FILE': '/run/secrets/storage_password'},
        'secrets': mounted,
    }}}
    with pytest.raises(subject.SecretError, match='secret_file_mount_missing'):
        subject.validate_compose(config)


def test_compose_checks_secret_file_target_against_manifest_source():
    config = {'services': {'worker': {
        'environment': ['PASSWORD_FILE=/run/secrets/worker_password'],
        'secrets': [{'source': 'storage_password', 'target': 'worker_password'}],
    }}}
    subject.validate_compose(config)
    config['services']['worker']['secrets'][0]['source'] = 'unregistered_password'
    with pytest.raises(subject.SecretError, match='manifest_missing'):
        subject.validate_compose(config)


@pytest.mark.parametrize('config', [
    {'secrets': {'unregistered_password': {'file': '/synthetic'}}},
    {'services': {'migrate': {'secrets': ['unregistered_password']}}},
    {'services': {'api': {'secrets': [{'source': 'unregistered_password'}]}}},
])
def test_compose_rejects_unregistered_secrets(config):
    with pytest.raises(subject.SecretError, match='manifest_missing'):
        subject.validate_compose(config)


def test_manifest_rejects_unsafe_name(tmp_path):
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps({'version': 1, 'secrets': {'../escape': {'kind': 'password', 'group': 'core'}}}))
    with pytest.raises(subject.SecretError, match='manifest_invalid'):
        subject.load_manifest(path)


def test_ensure_creates_passwords_without_newlines_and_preserves_files(tmp_path, ownership, capsys):
    directory = tmp_path / 'secrets'
    subject.ensure(directory, names=['context_password', 'runtime_password'])
    paths = list(directory.iterdir())
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    for body, _ in before.values():
        assert re.fullmatch(rb'[A-Za-z0-9_-]{64}', body)
        assert b'\r' not in body and b'\n' not in body
    assert len({body for body, _ in before.values()}) == 2
    subject.ensure(directory, names=['context_password', 'runtime_password'])
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
    assert not capsys.readouterr().out
    if os.name != 'nt':
        assert directory.stat().st_mode & 0o777 == 0o750
        assert all(path.stat().st_mode & 0o777 == 0o640 for path in paths)


def test_default_install_provisions_executor_credentials_for_compose_and_native(tmp_path, ownership, monkeypatch):
    from deploy.linux import native_install, native_runtime

    monkeypatch.delenv('SLI_CORE_JOB_WORKSTATIONS_PROJECTION', raising=False)
    directory = tmp_path / 'synthetic-install-secrets'
    subject.ensure(directory, tls_names=['localhost'])
    compose = yaml.safe_load((ROOT / 'deploy/linux/docker-compose.yml').read_text('utf-8'))
    native_env = native_install.environment()
    runtime_env, runtime_secrets = native_runtime.environment('executor-light', {'radius_pilot': False})
    values = []
    for purpose in ('dispatcher', 'executor', 'publisher'):
        name = f'job_{purpose}_light'
        setting = f'SLI_JOB_{purpose.upper()}_LIGHT_PASSWORD_FILE'
        values.append((directory / name).read_bytes())
        assert re.fullmatch(rb'[A-Za-z0-9_-]{64}', values[-1])
        assert native_env[setting] == str(native_install.SECRETS / name)
        assert name in runtime_secrets and runtime_env[setting] == '%d/' + name
        for service in ('migrate', 'executor-light'):
            assert name in compose['services'][service]['secrets']
            assert compose['services'][service]['environment'][setting] == '/run/secrets/' + name
    assert len(set(values)) == 3
    assert native_env['SLI_CORE_JOB_WORKSTATIONS_PROJECTION'] == '0'
    assert runtime_env['SLI_CORE_JOB_WORKSTATIONS_PROJECTION'] == '0'
    monkeypatch.setenv('SLI_CORE_JOB_WORKSTATIONS_PROJECTION', '1')
    assert native_install.environment()['SLI_CORE_JOB_WORKSTATIONS_PROJECTION'] == '1'
    assert native_runtime.environment('executor-light', {'radius_pilot': False})[0][
        'SLI_CORE_JOB_WORKSTATIONS_PROJECTION'] == '1'
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    subject.ensure(directory, tls_names=['localhost'])
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}


def test_directory_in_place_of_secret_fails_before_creating_other_files(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    (directory / 'context_password').mkdir()
    with pytest.raises(subject.SecretError, match='context_password: regular_file_required'):
        subject.ensure(directory, names=['runtime_password', 'context_password'])
    assert not (directory / 'runtime_password').exists()


def test_update_adds_context_password_and_preserves_legacy_password(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    existing = directory / 'runtime_password'
    existing.write_bytes(b'synthetic-existing-value')
    existing.chmod(0o640)
    before = existing.stat().st_mtime_ns
    assert subject.ensure(directory, names=['runtime_password', 'context_password']) == 1
    assert existing.read_bytes() == b'synthetic-existing-value'
    assert existing.stat().st_mtime_ns == before
    assert re.fullmatch(rb'[A-Za-z0-9_-]{64}', (directory / 'context_password').read_bytes())


@pytest.mark.skipif(os.name == 'nt', reason='POSIX modes')
@pytest.mark.parametrize('target,mode', [('directory', 0o777), ('file', 0o644), ('file', 0o660)])
def test_broad_permissions_refused_without_repair(tmp_path, ownership, target, mode):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    secret = directory / 'context_password'
    secret.write_bytes(b'synthetic-existing-value')
    secret.chmod(0o640)
    path = directory if target == 'directory' else secret
    path.chmod(mode)
    with pytest.raises(subject.SecretError, match='permissions_too_broad'):
        subject.ensure(directory, names=['context_password'])
    assert path.stat().st_mode & 0o777 == mode
    assert secret.read_bytes() == b'synthetic-existing-value'


@pytest.mark.parametrize('body', [b'', b'synthetic\n', b'synthetic\r', b'synthetic\x00'])
def test_invalid_existing_password_is_not_replaced(tmp_path, ownership, body):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    path = directory / 'context_password'
    path.write_bytes(body)
    path.chmod(0o640)
    with pytest.raises(subject.SecretError, match='invalid_format'):
        subject.ensure(directory, names=['context_password'])
    assert path.read_bytes() == body


@pytest.mark.skipif(os.name == 'nt', reason='POSIX symlinks')
def test_symlinks_are_refused(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    target = tmp_path / 'preserved'
    target.write_bytes(b'synthetic-existing-value')
    (directory / 'context_password').symlink_to(target)
    with pytest.raises(subject.SecretError, match='regular_file_required'):
        subject.ensure(directory, names=['context_password'])
    assert target.read_bytes() == b'synthetic-existing-value'


def test_tls_generation_and_existing_bundle_validation(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    names = ['tls_key', 'tls_certificate', 'tls_ca']
    subject.ensure(directory, names=names, tls_names=['127.0.0.1'])
    before = {name: (directory / name).read_bytes() for name in names}
    subject.ensure(directory, names=names)
    assert before == {name: (directory / name).read_bytes() for name in names}
    assert x509.load_pem_x509_certificate(before['tls_certificate']).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)
    (directory / 'tls_key').unlink()
    with pytest.raises(subject.SecretError, match='incomplete_bundle_restore_required'):
        subject.ensure(directory, names=names, tls_names=['127.0.0.1'])
    assert not (directory / 'tls_key').exists()


def test_tls_mismatched_key_refused_without_creating_password(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    names = ['tls_key', 'tls_certificate', 'tls_ca']
    subject.ensure(directory, names=names, tls_names=['127.0.0.1'])
    wrong_key = subject._tls_bundle(['127.0.0.1'])['tls_key']
    (directory / 'tls_key').write_bytes(wrong_key)
    with pytest.raises(subject.SecretError, match='invalid_certificate_bundle'):
        subject.ensure(directory, names=[*names, 'context_password'])
    assert (directory / 'tls_key').read_bytes() == wrong_key
    assert not (directory / 'context_password').exists()


def test_evaluation_tls_cli_covers_client_internal_and_host_health_addresses(tmp_path, ownership, capsys):
    directory = tmp_path / 'tls'
    assert subject.main(['ensure', '--directory', str(directory), '--tls-name', 'example.invalid',
                         '--tls-name', 'api', '--tls-name', '127.0.0.1']) == 0
    certificate = x509.load_pem_x509_certificate((directory / 'tls_certificate').read_bytes())
    ca = x509.load_pem_x509_certificate((directory / 'tls_ca').read_bytes())
    certificate.verify_directly_issued_by(ca)
    sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sans.get_values_for_type(x509.DNSName) == ['example.invalid', 'api']
    assert [str(address) for address in sans.get_values_for_type(x509.IPAddress)] == ['127.0.0.1']
    output = capsys.readouterr()
    assert 'PRIVATE KEY' not in output.out + output.err


def test_initial_tls_requires_name_before_any_password_is_written(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    with pytest.raises(subject.SecretError, match='names_required'):
        subject.ensure(directory)
    assert not list(directory.iterdir())


@pytest.mark.parametrize('target', ['directory', 'tls_bundle', 'tls_key'])
def test_cli_stat_permission_denied_is_not_missing_tls(tmp_path, ownership, monkeypatch, capsys, target):
    directory = tmp_path / 'secrets'
    tls_names = ['tls_ca', 'tls_certificate', 'tls_key']
    subject.ensure(directory, names=tls_names, tls_names=['127.0.0.1'])
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    denied = {directory} if target == 'directory' else {
        directory / name for name in (tls_names if target == 'tls_bundle' else ['tls_key'])}
    denied = {str(path) for path in denied}
    original_stat, original_lstat = os.stat, os.lstat

    def stat_path(path, *args, **kwargs):
        if str(path) in denied:
            raise PermissionError('synthetic-private-marker')
        return original_stat(path, *args, **kwargs)

    def lstat_path(path, *args, **kwargs):
        if str(path) in denied:
            raise PermissionError('synthetic-private-marker')
        return original_lstat(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(os, 'stat', stat_path)
        patch.setattr(os, 'lstat', lstat_path)
        assert subject.main(['ensure', '--directory', str(directory)]) == 1
    output = capsys.readouterr()
    assert 'permission_denied: cannot inspect secret paths' in output.err
    assert 'host ACLs' in output.err
    assert 'names_required' not in output.err and 'synthetic-private-marker' not in output.err
    assert 'Traceback' not in output.err and not output.out
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}


def test_cli_tls_read_permission_denied_preserves_bundle(tmp_path, ownership, monkeypatch, capsys):
    directory = tmp_path / 'secrets'
    subject.ensure(directory, names=['tls_ca', 'tls_certificate', 'tls_key'], tls_names=['127.0.0.1'])
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    original_open = Path.open

    def open_path(path, *args, **kwargs):
        if path == directory / 'tls_key':
            raise PermissionError('synthetic-private-marker')
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, 'open', open_path)
        assert subject.main(['ensure', '--directory', str(directory)]) == 1
    output = capsys.readouterr()
    assert 'tls_key: permission_denied' in output.err
    assert 'names_required' not in output.err and 'synthetic-private-marker' not in output.err
    assert 'Traceback' not in output.err and not output.out
    assert before == {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}


@pytest.mark.skipif(os.name == 'nt', reason='Docker Desktop POSIX mode projection')
@pytest.mark.parametrize('target', ['directory', 'tls_key'])
def test_cli_docker_desktop_modes_explain_permissions_without_generation(tmp_path, ownership, capsys, target):
    directory = tmp_path / 'secrets'
    subject.ensure(directory, names=['tls_ca', 'tls_certificate', 'tls_key'], tls_names=['127.0.0.1'])
    path = directory if target == 'directory' else directory / target
    path.chmod(0o777)
    before = {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in directory.iterdir()}
    assert subject.main(['ensure', '--directory', str(directory)]) == 1
    output = capsys.readouterr()
    assert f'{target}: permissions_too_broad (mode=0777;' in output.err
    assert 'Docker Desktop Windows bind mounts' in output.err and 'NTFS ACLs' in output.err
    assert 'names_required' not in output.err and not output.out
    assert path.stat().st_mode & 0o777 == 0o777
    assert before == {item.name: (item.read_bytes(), item.stat().st_mtime_ns) for item in directory.iterdir()}


@pytest.mark.parametrize('selection', ['default', 'tls', 'agents'])
def test_existing_bundles_with_new_manifest_password_only_create_password(
        tmp_path, ownership, monkeypatch, capsys, selection):
    directory = tmp_path / 'secrets'
    offline = tmp_path / 'offline'
    manifest = subject.load_manifest()
    names = [name for name, spec in manifest.items() if spec['group'] in {'core', 'tls', 'agents'}]
    subject.ensure(directory, names=names, tls_names=['127.0.0.1'], offline_root_dir=offline)
    before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in directory.iterdir()}
    root_before = (offline / 'agent_root_key').read_bytes()
    manifest['new_service_password'] = {'kind': 'password', 'group': 'core'}
    monkeypatch.setattr(subject, 'load_manifest', lambda: manifest)
    def unexpected_generation(*_args):
        pytest.fail('Existing certificate bundles must not be generated again')
    monkeypatch.setattr(subject, '_tls_bundle', unexpected_generation)
    monkeypatch.setattr(subject, '_agent_bundle', unexpected_generation)
    if selection == 'default':
        assert subject.main(['ensure', '--directory', str(directory)]) == 0
        assert 'created 1 files' in capsys.readouterr().out
    else:
        member = 'tls_ca' if selection == 'tls' else 'agent_mtls_ca'
        assert subject.ensure(directory, names=[member, 'new_service_password']) == 1
    assert {path.name for path in directory.iterdir()} == before.keys() | {'new_service_password'}
    assert before == {name: ((directory / name).read_bytes(), (directory / name).stat().st_mtime_ns)
                      for name in before}
    assert (offline / 'agent_root_key').read_bytes() == root_before
    assert re.fullmatch(rb'[A-Za-z0-9_-]{64}', (directory / 'new_service_password').read_bytes())


@pytest.mark.parametrize('group,member', [('tls', 'tls_ca'), ('agents', 'agent_mtls_ca')])
def test_partial_bundle_selection_refuses_invalid_existing_members_before_password(
        tmp_path, ownership, group, member):
    directory = tmp_path / 'secrets'
    names = [name for name, spec in subject.load_manifest().items() if spec['group'] == group]
    subject.ensure(directory, names=names, tls_names=['127.0.0.1'], offline_root_dir=tmp_path / 'offline')
    key = 'tls_key' if group == 'tls' else 'agent_issuer_key'
    (directory / key).write_bytes(b'synthetic-invalid-key')
    with pytest.raises(subject.SecretError, match='invalid_format'):
        subject.ensure(directory, names=[member, 'context_password'])
    assert not (directory / 'context_password').exists()
    assert (directory / key).read_bytes() == b'synthetic-invalid-key'


def test_explicit_tls_import_and_existing_files_take_precedence(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    imports = {}
    for name, body in subject._tls_bundle(['127.0.0.1']).items():
        path = tmp_path / name
        path.write_bytes(body)
        imports[name] = path
    subject.ensure(directory, names=imports, imports=imports)
    before = {name: (directory / name).read_bytes() for name in imports}
    subject.ensure(directory, names=imports, imports={name: tmp_path / 'missing' for name in imports})
    assert before == {name: (directory / name).read_bytes() for name in imports}


def test_windows_acl_failure_does_not_print_subprocess_diagnostics(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(subject.subprocess, 'run', lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout=b'synthetic-private-marker', stderr=b'synthetic-private-marker'))
    with pytest.raises(subject.SecretError, match='permissions_too_broad_or_acl_unavailable'):
        subject._windows_acl(tmp_path)
    output = capsys.readouterr()
    assert not output.out and not output.err


@pytest.mark.parametrize('uid,gid,offline', [(10001, 10001, False), (0, 0, False), (0, 10001, True)])
def test_wrong_owner_or_group_is_refused(uid, gid, offline):
    with pytest.raises(subject.SecretError, match='root_owner_and_container_group_required'):
        subject._check_owner(SimpleNamespace(st_uid=uid, st_gid=gid), offline)


def test_manifest_forbids_mounting_offline_root():
    with pytest.raises(subject.SecretError, match='offline_key_mount_forbidden'):
        subject.validate_compose({'services': {'api': {'secrets': ['agent_root_key']}}})


def test_compose_cli_checks_without_provisioning(tmp_path, capsys):
    path = tmp_path / 'compose.yml'
    path.write_text('services:\n  migrate:\n    secrets: [unregistered_password]\n')
    assert subject.main(['check-compose', '--compose', str(path)]) == 1
    assert 'manifest_missing' in capsys.readouterr().err
    assert sorted(item.name for item in tmp_path.iterdir()) == ['compose.yml']


def test_agent_ca_matches_runtime_contract_and_keeps_root_offline(tmp_path, ownership):
    directory = tmp_path / 'secrets'
    offline = tmp_path / 'offline'
    names = [name for name, spec in subject.load_manifest().items() if spec['group'] == 'agents']
    subject.ensure(directory, names=names, offline_root_dir=offline)
    root = x509.load_pem_x509_certificate((directory / 'agent_root_certificate').read_bytes())
    issuer = x509.load_pem_x509_certificate((directory / 'agent_issuer_certificate').read_bytes())
    key = serialization.load_pem_private_key((directory / 'agent_issuer_key').read_bytes(), password=None)
    IssuingCA(root, issuer, key).validate()
    assert (offline / 'agent_root_key').is_file()
    assert not (directory / 'agent_root_key').exists()
    # An established installation need not bring its offline root key online.
    subject.ensure(directory, names=names)


def test_generated_tls_identifiers_match_and_pass_strict_ssl_context(tmp_path, ownership):
    material = subject._tls_bundle(['127.0.0.1'])
    root = x509.load_pem_x509_certificate(material['tls_ca'])
    leaf = x509.load_pem_x509_certificate(material['tls_certificate'])
    ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert root.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == ski
    assert leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier == ski
    assert leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    subject._strict_tls(material)


def test_strict_tls_validation_failure_precedes_all_publication(tmp_path, ownership, monkeypatch):
    def reject(material):
        raise ValueError('synthetic strict TLS rejection')

    monkeypatch.setattr(subject, '_strict_tls', reject)
    directory = tmp_path / 'secrets'
    with pytest.raises(subject.SecretError, match='invalid_certificate_bundle'):
        subject.ensure(directory, tls_names=['127.0.0.1'])
    assert not list(directory.iterdir())


@pytest.mark.parametrize('conflict', [False, True])
def test_agent_bundle_transfer_preserves_trust_and_refuses_conflicts(tmp_path, ownership, conflict):
    source, destination = tmp_path / 'source', tmp_path / 'destination'
    names = [name for name, spec in subject.load_manifest().items() if spec['group'] == 'agents']
    subject.ensure(source, names=names, offline_root_dir=tmp_path / 'offline-source')
    imports = subject.agent_imports(source)
    if conflict:
        subject.ensure(destination, names=names, offline_root_dir=tmp_path / 'offline-other')
        before = {path.name: path.read_bytes() for path in destination.iterdir()}
        with pytest.raises(subject.SecretError, match='import_conflicts'):
            subject.ensure(destination, names=names, imports=imports)
        assert before == {path.name: path.read_bytes() for path in destination.iterdir()}
    else:
        subject.ensure(destination, names=names, imports=imports)
        assert {name: (destination / name).read_bytes() for name in names} == {
            name: (source / name).read_bytes() for name in names}
        assert not (destination / 'agent_root_key').exists()
        subject.ensure(destination, names=names, imports=imports)


def test_agent_transfer_cli_requires_complete_protected_bundle(tmp_path, ownership, capsys):
    source = tmp_path / 'source'
    source.mkdir(mode=0o750)
    assert subject.main(['ensure', '--directory', str(tmp_path / 'new'),
                         '--agent-secrets-from', str(source)]) == 1
    assert not (tmp_path / 'new').exists()
    assert 'PRIVATE KEY' not in capsys.readouterr().err


def test_agent_transfer_cli_needs_no_new_tls_or_offline_key(tmp_path, ownership, capsys):
    source, destination = tmp_path / 'source', tmp_path / 'new'
    names = [name for name, spec in subject.load_manifest().items() if spec['group'] == 'agents']
    subject.ensure(source, names=names, offline_root_dir=tmp_path / 'offline')
    assert subject.main(['ensure', '--directory', str(destination), '--agent-secrets-from', str(source)]) == 0
    assert {path.name for path in destination.iterdir()} == set(names)
    assert all((destination / name).read_bytes() == (source / name).read_bytes() for name in names)
    assert 'PRIVATE KEY' not in capsys.readouterr().out


def test_agent_overlay_provisioning_accepts_canonical_layout_and_rejects_foreign_override(
        tmp_path, ownership, monkeypatch, capsys):
    source, destination = tmp_path / 'source', tmp_path / 'new'
    names = list(subject.AGENT_FILE_SETTINGS)
    subject.ensure(source, names=names, offline_root_dir=tmp_path / 'offline')
    for setting in subject.AGENT_FILE_SETTINGS.values():
        monkeypatch.delenv(setting, raising=False)
    args = ['ensure', '--directory', str(destination), '--agent-secrets-from', str(source),
            '--compose', str(ROOT / 'deploy/linux/docker-compose.agent.yml')]
    assert subject.main(args) == 0
    monkeypatch.setenv('SLI_AGENT_CA_ISSUER_KEY_FILE', str(tmp_path / 'foreign'))
    assert subject.main(args) == 1
    assert 'secret_directory_layout_required' in capsys.readouterr().err


def test_restored_agent_bundle_is_checked_from_mounted_files(tmp_path, ownership, monkeypatch):
    source = tmp_path / 'source'
    names = [name for name, spec in subject.load_manifest().items() if spec['group'] == 'agents']
    subject.ensure(source, names=names, offline_root_dir=tmp_path / 'offline')
    settings = ('SLI_AGENT_CA_ROOT_CERT_FILE', 'SLI_AGENT_CA_ISSUER_CERT_FILE',
                'SLI_AGENT_CA_ISSUER_KEY_FILE', 'SLI_AGENT_MTLS_CA_FILE')
    members = ('agent_root_certificate', 'agent_issuer_certificate', 'agent_issuer_key', 'agent_mtls_ca')
    for setting, member in zip(settings, members):
        monkeypatch.setenv(setting, str(source / member))
    subject.check_agent_bundle()
    (source / 'agent_issuer_key').write_bytes(subject._tls_bundle(['127.0.0.1'])['tls_key'])
    with pytest.raises(subject.SecretError, match='invalid_certificate_bundle'):
        subject.check_agent_bundle()


def test_cli_reports_safe_error_without_secret_or_traceback(tmp_path, ownership, capsys):
    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    (directory / 'context_password').mkdir()
    assert subject.main(['ensure', '--directory', str(directory)]) == 1
    output = capsys.readouterr()
    assert 'context_password: regular_file_required' in output.err
    assert 'Traceback' not in output.err and not output.out


def test_installer_uses_manifest_and_rejects_unknown_secret(tmp_path, ownership):
    from deploy.linux.installation import create_secrets

    with pytest.raises(subject.SecretError, match='manifest_missing'):
        create_secrets({'secrets': {'unregistered_password': {}}}, tmp_path / 'secrets', {})
    assert not (tmp_path / 'secrets').exists()


def test_update_preflight_uses_manifest_without_creating_files(tmp_path):
    from deploy.linux.sli_update import DockerHost

    config = {'secrets': {'unregistered_password': {'file': str(tmp_path / 'missing')}},
              'services': {'migrate': {'secrets': [{'source': 'unregistered_password'}]}}}
    host = DockerHost([], 'https://127.0.0.1/api/health/ready', None)
    with pytest.raises(subject.SecretError, match='manifest_missing'):
        host.secrets_preflight(config, {'migrate'})
    assert not (tmp_path / 'missing').exists()


@pytest.mark.parametrize('new_secret', ['job_dispatcher_light', 'storage_password'])
def test_update_provisions_new_password_before_compose_can_mount_it(tmp_path, ownership, monkeypatch, new_secret):
    from deploy.linux.sli_update import DockerHost

    directory = tmp_path / 'secrets'
    names = ['tls_ca', 'tls_certificate', 'tls_key', 'runtime_password']
    subject.ensure(directory, names=names, tls_names=['127.0.0.1'])
    before = {name: ((directory / name).read_bytes(), (directory / name).stat().st_mtime_ns) for name in names}
    names.append(new_secret)
    config = {'secrets': {name: {'file': str(directory / name)} for name in names},
              'services': {'migrate': {'secrets': [{'source': name} for name in names]}}}
    host = DockerHost([], 'https://127.0.0.1/api/health/ready', None)
    monkeypatch.setattr(host, 'inspect_installation', lambda _: [])
    monkeypatch.setattr(host, 'ownership_preflight', lambda *_: None)
    calls = []
    def compose(args):
        calls.append(args)
        assert args == ['config', '--format', 'json']
        return json.dumps(config)
    monkeypatch.setattr(host, 'compose', compose)
    host.ensure_secrets({})
    host.secrets_preflight(config, {'migrate'})
    assert before == {name: ((directory / name).read_bytes(), (directory / name).stat().st_mtime_ns)
                      for name in before}
    assert re.fullmatch(rb'[A-Za-z0-9_-]{64}', (directory / new_secret).read_bytes())
    assert calls == [['config', '--format', 'json']]


@pytest.mark.parametrize('bad', ['directory', 'split_directory', 'wrong_name', 'unregistered', 'foreign'])
def test_update_ensure_refuses_unsafe_input_without_creating_password(tmp_path, ownership, monkeypatch, bad):
    from deploy.linux.sli_update import DockerHost, UpdateError

    directory = tmp_path / 'secrets'
    directory.mkdir(mode=0o750)
    config = {'secrets': {name: {'file': str(directory / name)}
                          for name in ['runtime_password', 'context_password']}}
    if bad == 'directory':
        (directory / 'context_password').mkdir()
    elif bad == 'split_directory':
        config['secrets']['context_password']['file'] = str(tmp_path / 'context_password')
    elif bad == 'wrong_name':
        config['secrets']['context_password']['file'] = str(directory / 'wrong')
    elif bad == 'unregistered':
        config['secrets']['unregistered_password'] = {'file': str(directory / 'unregistered_password')}
    host = DockerHost([], 'https://127.0.0.1/api/health/ready', None)
    monkeypatch.setattr(host, 'inspect_installation', lambda _: [])
    monkeypatch.setattr(host, 'compose', lambda _: json.dumps(config))
    def ownership_preflight(*_):
        if bad == 'foreign':
            raise UpdateError('update_foreign_installation')
    monkeypatch.setattr(host, 'ownership_preflight', ownership_preflight)
    with pytest.raises(UpdateError) as error:
        host.ensure_secrets({})
    if bad == 'directory':
        assert str(error.value) == 'update_secrets_ensure_failed'
    assert not (directory / 'runtime_password').exists()
