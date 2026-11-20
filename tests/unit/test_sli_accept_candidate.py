"""Explicit candidate acceptance; synthetic host, packages and private state only."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from deploy.linux import sli_update as update
from server.sli import release_package as package
from tests.unit.test_sli_update import PowerLoss, release  # noqa: F401


@pytest.fixture
def recovered_candidate(release, monkeypatch):
    updater, host, archive, *_ = release
    host.fail = 'health'
    monkeypatch.setattr(host, 'restore', lambda journal: (_ for _ in ()).throw(
        update.UpdateError('update_docker_failed')))
    assert updater.apply(archive) == 'recovery_required'
    journal = updater.operation()
    assert journal['completed'] == list(update.PHASES[:6])
    # An operator has independently brought the verified candidate back up.
    host.activate(journal)
    host.calls.clear()
    monkeypatch.setattr(host, 'acceptance_preflight', lambda value: host.call('acceptance_preflight'), raising=False)
    # Use the production exact ledger/runtime gate, not FakeHost's assertion-only adapter.
    runtime_matches = update.DockerHost.runtime_matches
    monkeypatch.setattr(host, 'runtime_matches', lambda value, previous=False:
                        runtime_matches(host, value, previous))
    return updater, host, journal


def test_accept_candidate_commits_exact_inventory_without_replaying_update(recovered_candidate):
    updater, host, journal = recovered_candidate
    previous_checkpoint = {key: journal[key] for key in ('backup_id', 'checkpoint_sha256', 'checkpoint_key')}
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    result = updater.operation()
    assert result['reason'] == 'operator_accepted_candidate'
    assert result['completed'] == list(update.PHASES)
    assert result['desired_activation'] == journal['desired_activation'] | {
        'version': journal['manifest']['to_version'], 'image_tag': journal['candidate_tag'],
        'image_digest': journal['manifest']['image']['digest']}
    assert package.read_json(updater.installed_path.read_bytes()) == updater.candidate(journal)
    assert {key: result[key] for key in previous_checkpoint} == previous_checkpoint
    assert Path(result['candidate_override']).is_file() and Path(result['previous_override']).is_file()
    assert result['candidate_acceptance']['status'] == 'committed'
    assert result['candidate_acceptance']['original_reason'] == journal['reason']
    assert not {'stage', 'drain', 'checkpoint', 'migrate', 'restore', 'activate', 'previous', 'fence'} & set(host.calls)
    before = updater.journal_path.read_bytes()
    calls = list(host.calls)
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    assert updater.journal_path.read_bytes() == before and host.calls == calls


@pytest.mark.parametrize('bad,reason', [
    ('wrong_operation', 'operation_not_active'), ('missing_operation', 'invalid_operation'),
    ('wrong_status', 'candidate_acceptance_required'), ('missing_activate', 'candidate_acceptance_required'),
    ('wrong_ledger', 'migration_ledger_mismatch'), ('wrong_tag', 'runtime_mismatch'),
    ('unhealthy', 'health_timeout'), ('forged', 'journal_authentication_failed'),
    ('foreign_registry', 'foreign_installation'), ('package_changed', 'package_changed'),
])
def test_accept_candidate_refuses_before_any_persistent_change(recovered_candidate, monkeypatch, bad, reason):
    updater, host, journal = recovered_candidate
    operation = journal['operation']
    if bad == 'wrong_operation':
        operation = 'f' * 32
    elif bad == 'missing_operation':
        operation = None
    elif bad == 'wrong_status':
        journal['status'] = 'rolling_back'
        updater.save(journal)
    elif bad == 'missing_activate':
        journal['completed'].remove('activate')
        updater.save(journal)
    elif bad == 'wrong_ledger':
        host.exact_ledger[0]['name'] = 'foreign'
    elif bad == 'wrong_tag':
        host.running_tag = 'same-image:unapproved-alias'
    elif bad == 'unhealthy':
        monkeypatch.setattr(host, 'health', lambda _: (_ for _ in ()).throw(update.UpdateError('update_health_timeout')))
    elif bad == 'forged':
        update.atomic_json(updater.journal_path, journal)
    elif bad == 'foreign_registry':
        host.installed_release = {'installation_key': 'f' * 64, 'inventory': {}}
    elif bad == 'package_changed':
        Path(journal['package']).write_bytes(b'changed')
    before = (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), copy.deepcopy(host.installed_release))
    with pytest.raises(update.UpdateError, match=reason):
        updater.accept_candidate(operation_id=operation)
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), host.installed_release)
    assert not {'publish', 'stage', 'drain', 'checkpoint', 'migrate', 'restore', 'activate', 'previous', 'fence'} & set(host.calls)


@pytest.mark.parametrize('after_db', [False, True])
def test_accept_candidate_interruption_requires_explicit_retry_never_rollback(recovered_candidate, monkeypatch, after_db):
    updater, host, journal = recovered_candidate
    publish = host.publish_installed
    def fail(*args):
        if after_db:
            publish(*args)
        raise PowerLoss()
    monkeypatch.setattr(host, 'publish_installed', fail)
    with pytest.raises(PowerLoss):
        updater.accept_candidate(operation_id=journal['operation'])
    pending = updater.operation()
    assert pending['status'] == 'recovery_required'
    assert pending['candidate_acceptance']['status'] == 'pending'
    with pytest.raises(update.UpdateError, match='candidate_acceptance_pending'):
        updater.resume(operation_id=journal['operation'])
    with pytest.raises(update.UpdateError, match='candidate_acceptance_pending'):
        updater.resume(operation_id=journal['operation'], rollback=True)
    assert not {'restore', 'drain', 'fence'} & set(host.calls)
    monkeypatch.setattr(host, 'publish_installed', publish)
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'


def compose_host(recovered_candidate, monkeypatch):
    """Real Docker acceptance adapter with command boundary replaced by immutable facts."""
    updater, fake, journal = recovered_candidate
    config = {'name': 'sli', 'services': {
        name: {'image': journal['candidate_tag'], 'healthcheck': {'test': ['CMD', 'true']}}
        for name in [*journal['services'], 'migrate']}, 'volumes': {}}
    real = update.DockerHost(fake.files, 'https://example.invalid/api/health/ready', Path('synthetic-ca.pem'))
    monkeypatch.setattr(real, 'configuration', lambda replacement=None: copy.deepcopy(config))
    monkeypatch.setattr(real, 'compose', lambda args, override=None, **kw: package.canonical_json(config).decode())
    monkeypatch.setattr(real, 'deployment_fingerprint', lambda: journal['deployment_fingerprint'])
    monkeypatch.setattr(real, 'validate_operation_overrides', lambda value: {})
    monkeypatch.setattr(real, 'ownership_preflight', lambda candidate, configuration: None)
    monkeypatch.setattr(real, 'inspect_installation', lambda candidate: journal['services'])
    monkeypatch.setattr(real, 'secrets_preflight', lambda configuration, required: None)
    monkeypatch.setattr(real, 'tls_preflight', lambda: None)
    rows = [{'ID': name + '-id', 'Service': name, 'State': 'running', 'Health': 'healthy'}
            for name in [*journal['services'], *update.INFRA]]
    monkeypatch.setattr(real, 'containers', lambda: copy.deepcopy(rows))
    # The original configuration renderer is a distinct host; only rendering/ownership are delegated.
    raw_compose = real.compose
    monkeypatch.setattr(real, 'compose', lambda args, override=None, **kw:
                        '\n'.join(f"{row['Service']} {'a' * 64}" for row in rows)
                        if '--hash' in args else raw_compose(args, override, **kw))
    monkeypatch.setattr(real, 'command', lambda args, **kw: 'a' * 64)
    original = copy.copy(real)
    expected = copy.deepcopy(config)
    original.compose = lambda *args, **kwargs: package.canonical_json(expected).decode()
    monkeypatch.setattr(update, 'DockerHost', lambda *args, **kwargs: original)
    return real, config, rows, original


def test_acceptance_preflight_checks_equivalent_manual_compose(recovered_candidate, monkeypatch, tmp_path):
    host, config, _, original = compose_host(recovered_candidate, monkeypatch)
    manual = tmp_path / 'manual-compose.json'
    manual.write_bytes(package.canonical_json(config))
    host.files = [manual]
    host.acceptance_preflight(recovered_candidate[2])
    assert original.files != host.files


@pytest.mark.parametrize('bad', ['environment', 'privileged', 'volumes', 'healthcheck', 'missing', 'duplicate', 'foreign', 'stopped'])
def test_acceptance_preflight_rejects_manual_configuration_or_container_drift(recovered_candidate, monkeypatch, bad):
    host, config, rows, _ = compose_host(recovered_candidate, monkeypatch)
    candidate = copy.deepcopy(config)
    monkeypatch.setattr(host, 'compose', lambda *args, **kw: package.canonical_json(candidate).decode())
    if bad in {'environment', 'privileged', 'volumes', 'healthcheck'}:
        config['services']['api'][bad] = {'changed': 'untrusted'}
    elif bad == 'missing':
        rows.pop(0)
    elif bad == 'duplicate':
        rows.append(dict(rows[0], ID='duplicate-id'))
    elif bad == 'foreign':
        rows.append(dict(rows[0], ID='foreign-id', Service='foreign'))
    else:
        rows[0]['State'] = 'exited'
    with pytest.raises(update.UpdateError, match='configuration_changed|runtime_mismatch'):
        host.acceptance_preflight(recovered_candidate[2])


def test_recovery_console_cannot_bypass_pending_acceptance(recovered_candidate, monkeypatch):
    from deploy.linux.update_recovery import recover_server
    updater, host, journal = recovered_candidate
    monkeypatch.setattr(host, 'publish_installed', lambda *args: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.accept_candidate(operation_id=journal['operation'])
    before = updater.journal_path.read_bytes()
    with pytest.raises(update.UpdateError, match='candidate_acceptance_pending'):
        recover_server(updater.runtime, updater.trust_store, host)
    assert updater.journal_path.read_bytes() == before
    assert not {'restore', 'drain', 'fence'} & set(host.calls)


@pytest.mark.parametrize('dry_run', [False, True])
def test_console_accept_candidate_uses_normal_host_and_exact_operation(recovered_candidate, monkeypatch, capsys, dry_run):
    updater, host, journal = recovered_candidate
    monkeypatch.setattr(update, 'DockerHost', lambda *args, **kwargs: host)
    before = updater.journal_path.read_bytes()
    args = ['recover', '--accept-candidate', '--operation-id', journal['operation'],
            '--runtime', str(updater.runtime), '--trust-store', str(updater.trust_store),
            '--compose', str(host.files[0]), '--ca-file', 'synthetic-ca.pem', '--json']
    if dry_run:
        args += ['--dry-run']
    assert update.main(args) == 0
    result = package.read_json(capsys.readouterr().out.encode())
    assert result['status'] == ('dry_run' if dry_run else 'committed')
    assert result['operation'] == journal['operation']
    if dry_run:
        assert updater.journal_path.read_bytes() == before
    assert not {'restore', 'drain', 'fence', 'activate'} & set(host.calls)


@pytest.mark.parametrize('where', ['cache_before', 'cache_after', 'final_save'])
def test_accept_candidate_io_failure_retains_intent_and_retries(recovered_candidate, monkeypatch, where):
    updater, host, journal = recovered_candidate
    atomic = update.atomic_json
    save = updater.save
    fired = False
    def write(path, value):
        nonlocal fired
        if path == updater.installed_path and where.startswith('cache_') and not fired:
            fired = True
            if where == 'cache_after':
                atomic(path, value)
            raise OSError('synthetic write failure')
        atomic(path, value)
    def persist(value, **kwargs):
        nonlocal fired
        if value['status'] == 'committed' and where == 'final_save' and not fired:
            fired = True
            raise OSError('synthetic write failure')
        save(value, **kwargs)
    monkeypatch.setattr(update, 'atomic_json', write)
    monkeypatch.setattr(updater, 'save', persist)
    with pytest.raises(OSError):
        updater.accept_candidate(operation_id=journal['operation'])
    pending = updater.operation()
    assert pending['candidate_acceptance']['status'] == 'pending'
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    assert not {'restore', 'drain', 'fence', 'activate'} & set(host.calls)


def test_accept_candidate_dry_run_honors_pending_configuration_pin(recovered_candidate, monkeypatch):
    updater, host, journal = recovered_candidate
    publish = host.publish_installed
    monkeypatch.setattr(host, 'publish_installed', lambda *args: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.accept_candidate(operation_id=journal['operation'])
    monkeypatch.setattr(host, 'publish_installed', publish)
    pending = updater.operation()
    pending['candidate_acceptance']['compose_files'] = {'different': 'f' * 64}
    updater.save(pending)
    with pytest.raises(update.UpdateError, match='compose_changed'):
        updater.accept_candidate(operation_id=journal['operation'], dry_run=True)


def test_accept_candidate_rechecks_runtime_after_health(recovered_candidate, monkeypatch):
    updater, host, journal = recovered_candidate
    def changed(_):
        host.running_tag = 'foreign:replaced-during-health'
    monkeypatch.setattr(host, 'health', changed)
    before = updater.journal_path.read_bytes()
    with pytest.raises(update.UpdateError, match='runtime_mismatch'):
        updater.accept_candidate(operation_id=journal['operation'])
    assert updater.journal_path.read_bytes() == before
    assert 'publish' not in host.calls


def test_accept_candidate_never_generates_missing_journal_key(recovered_candidate):
    updater, host, journal = recovered_candidate
    key = updater.state / 'update-journal.key'
    key.unlink()
    with pytest.raises((OSError, update.UpdateError)):
        updater.accept_candidate(operation_id=journal['operation'])
    assert not key.exists() and not host.calls


def test_acceptance_preflight_rejects_foreign_live_container_config(recovered_candidate, monkeypatch):
    host, _, _, _ = compose_host(recovered_candidate, monkeypatch)
    monkeypatch.setattr(host, 'command', lambda *args, **kwargs: 'f' * 64)
    with pytest.raises(update.UpdateError, match='configuration_changed'):
        host.acceptance_preflight(recovered_candidate[2])


@pytest.mark.parametrize('interrupt', [False, True])
def test_accept_candidate_preserves_managed_compose_and_recovers_switch(release, monkeypatch, interrupt):
    from tests.unit.test_sli_update import retained_volume_overlay
    updater, host, *_ = release
    target, definitions, _ = retained_volume_overlay(release, monkeypatch)
    updater, host, journal = recovered_candidate.__wrapped__(release, monkeypatch)
    original = update.atomic_json
    armed = interrupt
    def write(path, value):
        nonlocal armed
        original(path, value)
        if path == target and armed:
            armed = False
            raise PowerLoss()
    monkeypatch.setattr(update, 'atomic_json', write)
    if interrupt:
        with pytest.raises(PowerLoss):
            updater.accept_candidate(operation_id=journal['operation'])
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    assert package.read_json(target.read_bytes())['volumes'] == definitions
    result = updater.operation()
    assert result['notification_compose_switch']['acknowledged']
    assert Path(result['candidate_override']).is_file()


def test_accept_candidate_refuses_nonterminal_updater_transition(recovered_candidate):
    updater, host, journal = recovered_candidate
    update.atomic_json(updater.state / 'updater-journal.json', {'status': 'recovery_required'})
    before = updater.journal_path.read_bytes()
    with pytest.raises(update.UpdateError, match='updater_recovery_required'):
        updater.accept_candidate(operation_id=journal['operation'])
    assert not host.calls and updater.journal_path.read_bytes() == before


def test_accept_candidate_rechecks_foreign_registry_after_health(recovered_candidate, monkeypatch):
    updater, host, journal = recovered_candidate
    def changed(_):
        host.installed_release = {'installation_key': 'f' * 64, 'inventory': {}}
    monkeypatch.setattr(host, 'health', changed)
    before = updater.journal_path.read_bytes()
    with pytest.raises(update.UpdateError, match='foreign_installation'):
        updater.accept_candidate(operation_id=journal['operation'])
    assert updater.journal_path.read_bytes() == before and 'publish' not in host.calls


def test_bridge_rejects_candidate_acceptance_before_constructing_host(monkeypatch, capsys):
    monkeypatch.setattr(package, 'UPDATER_RELEASE_VERSION', '1.0.1')
    monkeypatch.setattr(update, 'DockerHost', lambda *args, **kwargs: pytest.fail('bridge must not construct host'))
    assert update.main(['recover', '--accept-candidate', '--operation-id', 'a' * 32, '--json']) == 1
    assert package.read_json(capsys.readouterr().out.encode())['reason_code'] == 'update_updater_transition_required'


def test_accept_candidate_manual_files_publish_managed_settings_with_original_host(recovered_candidate, monkeypatch, tmp_path):
    from types import SimpleNamespace
    updater, host, journal = recovered_candidate
    target = updater.state / 'install-compose.json'
    update.atomic_json(target, {'services': {'backup': {'environment': {}}}})
    journal['compose_files'][str(target)] = update.sha256(target)
    source = Path(journal['candidate_override'])
    overlay = package.read_json(source.read_bytes())
    overlay['services']['backup']['environment'] = {'SLI_BACKUP_RETENTION': '9'}
    update.atomic_json(source, overlay)
    journal['candidate_override_sha256'] = update.sha256(source)
    updater.save(journal)
    manual = tmp_path / 'operator-compose.json'
    update.atomic_json(manual, overlay)
    host.files = [manual]
    for name, value in {'health_url': 'https://example.invalid/api/health/ready', 'ca_file': Path('synthetic.pem'),
                        'timeout': 3, 'tls_min_validity': 60, 'drain_timeout': 3}.items():
        monkeypatch.setattr(host, name, value, raising=False)
    used = []
    original = SimpleNamespace(
        configuration=lambda replacement=None: (used.append('render-original'), overlay)[1],
        ownership_preflight=lambda previous, config: used.append('ownership-original'),
        deployment_fingerprint=lambda replacement=None: 'fingerprint')
    monkeypatch.setattr(update, 'DockerHost', lambda files, *args, **kwargs:
                        (used.append(tuple(files)), original)[1])
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    assert 'ownership-original' in used
    assert tuple(journal['compose_files']) in used
    assert package.read_json(target.read_bytes())['services']['backup']['environment']['SLI_BACKUP_RETENTION'] == '9'
    assert manual.read_bytes() == package.canonical_json(overlay)


def test_accept_candidate_allows_following_signed_update_and_archives_audit(recovered_candidate, release):
    from tests.unit.test_sli_update import make_image, build
    updater, host, journal = recovered_candidate
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    installed = package.read_json(updater.installed_path.read_bytes())
    host.installed, host.active = installed, 'previous'
    payload = release[5]
    image, migrations = make_image(payload / 'image.tar', label='1.2.0')
    manifest = copy.deepcopy(release[3])
    manifest.update(version='1.2.0', to_version='1.2.0', from_version='1.1.0', image=image, migrations=migrations)
    manifest['compatibility'].update(from_version='1.1.0', min_version='1.1.0', max_version='1.1.0')
    (updater.runtime.parent / 'VERSION').write_text('1.2.0\n')
    draft = updater.runtime.parent / 'next-manifest.json'
    draft.write_bytes(package.canonical_json(manifest))
    signed = updater.runtime.parent / 'next-package.zip'
    build(draft, payload, updater.runtime.parent / 'offline.key', signed, key_id='test-only')
    assert updater.apply(signed) == 'committed'
    archived = updater.operation(journal['operation'])
    assert archived['reason'] == 'operator_accepted_candidate'
    assert archived['candidate_acceptance']['status'] == 'committed'
    assert package.read_json(updater.installed_path.read_bytes())['version'] == '1.2.0'


@pytest.mark.parametrize('bad', ['checkpoint', 'override', 'revoked', 'ledger_hole', 'plugin', 'volume_intent'])
def test_accept_candidate_retains_all_existing_admission_boundaries(recovered_candidate, bad):
    updater, host, journal = recovered_candidate
    if bad == 'checkpoint':
        journal['backup_id'] = 'update-checkpoints/' + 'f' * 32 + '/20261006T010000.000000Z'
        updater.save(journal)
    elif bad == 'override':
        Path(journal['candidate_override']).write_text('{}')
    elif bad == 'revoked':
        trust = package.read_json(updater.trust_store.read_bytes())
        trust['keys'][0]['revoked'] = True
        updater.trust_store.write_bytes(package.canonical_json(trust))
    elif bad == 'ledger_hole':
        host.exact_ledger = [*host.exact_ledger, {'version': 2, 'name': 'unreviewed', 'sha256': 'f' * 64}]
        host.ledger = 2
    elif bad == 'plugin':
        host.plugins = [{'plugin_id': 'sli.foreign', 'version': '1.0.0', 'installed': True, 'enabled': True}]
    else:
        updater.save({'status': 'running'}, path=updater.state / 'volume-reconciliation.json')
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes()
    with pytest.raises(update.UpdateError):
        updater.accept_candidate(operation_id=journal['operation'])
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes())
    assert not {'publish', 'restore', 'activate', 'drain', 'fence'} & set(host.calls)


def test_accept_candidate_from_authenticated_closure_without_checkout_fallback(recovered_candidate, tmp_path):
    if not hasattr(package, 'UPDATER_CLOSURE_FILES'):
        pytest.skip('requires authenticated closure prerequisite PR833; exercised in isolated composition')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from tests.unit.test_updater_transition import materialize, signed_fixture, run_isolated
    import base64
    updater, _, _ = recovered_candidate
    payload = tmp_path / 'closure-payload'
    materialize(payload, '1.1.0')
    key = Ed25519PrivateKey.generate()
    trust = tmp_path / 'closure-trust.json'
    trust.write_bytes(package.canonical_json({'schema_version': 1, 'keys': [{
        'key_id': 'synthetic-only', 'public_key': base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(),
        'package_ids': ['sli.updater'], 'revoked': False}]}))
    archive = tmp_path / 'closure.zip'
    signed_fixture(payload, archive, '1.0.1', '1.1.0', key)
    authenticated = tmp_path / 'authenticated'
    package.extract_payload(package.verify_package(archive, trust), authenticated)
    neutral = tmp_path / 'neutral'
    neutral.mkdir()
    script = r'''
import copy
from deploy.linux import sli_update as update, installed_state
runtime, trust = Path(sys.argv[2]), Path(sys.argv[3])
updater = update.Updater(runtime, trust, None)
journal = updater.read_journal(updater.journal_path)
candidate = updater.candidate(journal)
class Host:
    files = [Path(p) for p in journal['compose_files']]
    registry = dict(installation_key=installed_state.installation_key(journal['previous']),
                    operation='b'*32, inventory=installed_state.inventory(journal['previous']))
    def observe(self):
        return dict(migration_ledger=copy.deepcopy(journal['candidate_ledger']),
            migration_ledger_max=max(r['version'] for r in journal['candidate_ledger']),
            installed_release_available=True, installed_release=copy.deepcopy(self.registry), plugins=[],
            services={name:{k:candidate[k] for k in ('version','image_tag','image_digest')}
                      for name in journal['services']})
    def runtime_matches(self, value):
        return update.DockerHost.runtime_matches(self,value)
    def acceptance_preflight(self, value):
        assert value['operation'] == journal['operation']
    def health(self, value):
        assert value['status'] == 'recovery_required'
    def publish_installed(self, previous, current, operation):
        self.registry = dict(installation_key=installed_state.installation_key(current),
                             operation=operation, inventory=installed_state.inventory(current))
updater.host = Host()
assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
assert update.parse_json(updater.installed_path.read_bytes()) == candidate
for name,module in sys.modules.copy().items():
    if name.split('.')[0] in {'deploy','scripts','server'} and getattr(module,'__file__',None):
        assert Path(module.__file__).resolve().is_relative_to(source), name
'''
    result = run_isolated(authenticated, script, [updater.runtime, updater.trust_store], neutral)
    assert result.returncode == 0, result.stderr


def test_acceptance_original_compose_order_is_not_lost_to_json_key_sorting(recovered_candidate, monkeypatch, tmp_path):
    host, config, _, original = compose_host(recovered_candidate, monkeypatch)
    first, second = tmp_path / 'z-base.json', tmp_path / 'a-override.json'
    for path in (first, second):
        update.atomic_json(path, config)
    journal = copy.deepcopy(recovered_candidate[2])
    # Authentication serializes mapping keys in lexical order, not Compose order.
    journal['compose_files'] = {str(second): update.sha256(second), str(first): update.sha256(first)}
    host.files = [first, second]
    received = []
    monkeypatch.setattr(update, 'DockerHost', lambda files, *args, **kwargs:
                        (received.append(files), original)[1])
    host.acceptance_preflight(journal)
    assert received == [[str(first), str(second)]]


def test_committed_acceptance_keeps_existing_explicit_rollback_and_terminal_semantics(recovered_candidate, monkeypatch):
    from deploy.linux.update_recovery import recover_server
    updater, host, journal = recovered_candidate
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    monkeypatch.setattr(host, 'restore', lambda value: type(host).restore(host, value))
    monkeypatch.setattr(host, 'recovery_health', lambda value: host.call('recovery_readback'), raising=False)
    assert recover_server(updater.runtime, updater.trust_store, host)['status'] == 'rolled_back'
    assert updater.resume(operation_id=journal['operation']) == 'rolled_back'
    assert recover_server(updater.runtime, updater.trust_store, host)['status'] == 'rolled_back'


@pytest.mark.parametrize('json_output', [False, True])
def test_console_reports_pending_publication_instead_of_claiming_no_execution(recovered_candidate, monkeypatch, capsys, json_output):
    updater, host, journal = recovered_candidate
    monkeypatch.setattr(update, 'DockerHost', lambda *args, **kwargs: host)
    monkeypatch.setattr(host, 'publish_installed', lambda *args: (_ for _ in ()).throw(OSError('private failure detail')))
    args = ['recover', '--accept-candidate', '--operation-id', journal['operation'],
            '--runtime', str(updater.runtime), '--trust-store', str(updater.trust_store),
            '--compose', str(host.files[0]), '--ca-file', 'synthetic-ca.pem']
    assert update.main([*args, *(['--json'] if json_output else [])]) == 1
    captured = capsys.readouterr()
    assert 'private failure detail' not in captured.out + captured.err
    if json_output:
        result = package.read_json(captured.out.encode())
        assert result['status'] == 'recovery_required'
        assert result['reason_code'] == 'update_candidate_acceptance_pending'
        assert result['executed'] is True and result['installed'] is False
    else:
        assert '--accept-candidate' in captured.out
        assert 'Работающая версия принята.' not in captured.out
    assert updater.operation()['candidate_acceptance']['status'] == 'pending'


@pytest.mark.parametrize('interrupted', [None, 'before_intent', 'after_intent', 'publication'])
def test_acceptance_invalidates_prior_restore_progress_before_durable_intent(release, monkeypatch, interrupted):
    from deploy.linux.update_recovery import recover_server
    updater, host, archive, *_ = release
    monkeypatch.setattr(host, 'health', lambda value: (_ for _ in ()).throw(update.UpdateError('update_health_timeout')))
    assert updater.apply(archive) == 'recovery_required'
    journal = updater.operation()
    assert journal['rollback_restored'] is True and journal['rollback_runtime'] == 'previous'
    journal['recovery_api_unchecked'] = True
    updater.save(journal)
    original = {key: journal[key] for key in ('rollback_restored', 'rollback_runtime', 'rollback_error', 'recovery_api_unchecked')}
    checkpoint = {key: journal[key] for key in ('backup_id', 'checkpoint_sha256', 'checkpoint_key')}
    # Independent operator action reactivates/migrates the candidate; old restore
    # progress is no longer evidence that a later rollback may skip restoration.
    monkeypatch.setattr(host, 'health', lambda value: type(host).health(host, value))
    host.activate(journal)
    host.exact_ledger = copy.deepcopy(journal['candidate_ledger'])
    monkeypatch.setattr(host, 'acceptance_preflight', lambda value: None, raising=False)
    monkeypatch.setattr(host, 'runtime_matches', lambda value, previous=False:
                        update.DockerHost.runtime_matches(host, value, previous))
    publish = host.publish_installed
    save = updater.save
    if interrupted:
        if interrupted == 'publication':
            monkeypatch.setattr(host, 'publish_installed', lambda *args: (_ for _ in ()).throw(PowerLoss()))
        else:
            def interrupted_save(value, **kwargs):
                if (value.get('candidate_acceptance') or {}).get('status') == 'pending':
                    if interrupted == 'after_intent':
                        save(value, **kwargs)
                    raise PowerLoss()
                save(value, **kwargs)
            monkeypatch.setattr(updater, 'save', interrupted_save)
        with pytest.raises(PowerLoss):
            updater.accept_candidate(operation_id=journal['operation'])
        pending = updater.operation()
        if interrupted == 'before_intent':
            assert 'candidate_acceptance' not in pending
            assert {key: pending[key] for key in original} == original
        else:
            assert pending['candidate_acceptance']['status'] == 'pending'
            assert not set(original) & pending.keys()
            assert pending['candidate_acceptance']['original_recovery'] == original
        monkeypatch.setattr(host, 'publish_installed', publish)
        monkeypatch.setattr(updater, 'save', save)
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    accepted = updater.operation()
    assert not set(original) & accepted.keys()
    assert accepted['candidate_acceptance']['original_recovery'] == original
    assert {key: accepted[key] for key in checkpoint} == checkpoint
    host.calls.clear()
    monkeypatch.setattr(host, 'recovery_health', lambda value: host.call('recovery_health'), raising=False)
    assert recover_server(updater.runtime, updater.trust_store, host)['status'] == 'rolled_back'
    assert host.calls.count('restore') == 1


@pytest.mark.parametrize('json_output', [False, True])
@pytest.mark.parametrize('readback_failed', [False, True])
def test_console_reports_post_replace_durability_failure_truthfully(recovered_candidate, monkeypatch, capsys,
                                                                   json_output, readback_failed):
    updater, host, journal = recovered_candidate
    original = update.atomic_json
    read_journal = update.Updater.read_journal
    failed = False
    def write_then_error(path, value):
        nonlocal failed
        original(path, value)
        if path == updater.journal_path and value.get('status') == 'committed':
            failed = True
            raise OSError('private synthetic directory fsync failure after replace')
    def unavailable_readback(self, path):
        if failed and readback_failed:
            raise OSError('private synthetic unreadable journal')
        return read_journal(self, path)
    monkeypatch.setattr(update, 'atomic_json', write_then_error)
    monkeypatch.setattr(update.Updater, 'read_journal', unavailable_readback)
    monkeypatch.setattr(update, 'DockerHost', lambda *args, **kwargs: host)
    args = ['recover', '--accept-candidate', '--operation-id', journal['operation'],
            '--runtime', str(updater.runtime), '--trust-store', str(updater.trust_store),
            '--compose', str(host.files[0]), '--ca-file', 'synthetic-ca.pem']
    assert update.main([*args, *(['--json'] if json_output else [])]) == 1
    captured = capsys.readouterr()
    assert 'private synthetic' not in captured.out + captured.err
    if json_output:
        result = package.read_json(captured.out.encode())
        assert result['status'] == 'recovery_required' and result['executed'] is True
        assert result['reason_code'] == 'update_candidate_acceptance_durability_unknown'
        assert result['durability'] == 'unverified'
        assert result['installed'] is (None if readback_failed else True)
        assert result['journal_status'] == ('unverified' if readback_failed else 'committed')
    else:
        assert '--accept-candidate' in captured.out and 'Не запускайте откат' in captured.out
        assert 'Работающая версия принята.' not in captured.out
    monkeypatch.setattr(update.Updater, 'read_journal', read_journal)
    assert updater.operation()['status'] == 'committed'
    monkeypatch.setattr(update, 'atomic_json', original)
    host.calls.clear()
    saved = []
    monkeypatch.setattr(update, 'atomic_json', lambda path, value: (saved.append(path), original(path, value))[1])
    assert update.main([*args, '--json']) == 0
    capsys.readouterr()
    assert updater.journal_path in saved and not host.calls


def test_committed_acceptance_dry_run_does_not_rewrite_journal(recovered_candidate, monkeypatch):
    updater, host, journal = recovered_candidate
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    monkeypatch.setattr(update, 'atomic_json', lambda *args: pytest.fail('dry-run wrote state'))
    host.calls.clear()
    assert updater.accept_candidate(operation_id=journal['operation'], dry_run=True) == 'dry_run'
    assert not host.calls


def test_failed_intent_write_does_not_claim_no_attempt(recovered_candidate, monkeypatch):
    from deploy.linux.update_recovery import accept_candidate
    updater, host, journal = recovered_candidate
    before = updater.journal_path.read_bytes()
    monkeypatch.setattr(update, 'atomic_json', lambda *args: (_ for _ in ()).throw(OSError('private write failure')))
    result = accept_candidate(updater.runtime, updater.trust_store, host, journal['operation'])
    assert result['status'] == 'recovery_required' and result['executed'] is True
    assert result['installed'] is None and result['durability'] == 'unverified'
    assert updater.journal_path.read_bytes() == before
    assert not {'publish', 'restore'} & set(host.calls)
