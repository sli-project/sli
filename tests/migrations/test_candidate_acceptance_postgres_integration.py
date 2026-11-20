"""Candidate acceptance publishes through real PostgreSQL; disposable CI DB only."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from deploy.linux import sli_update as update
from deploy.linux.installed_state import installation_key, inventory
from tests.unit.test_sli_accept_candidate import recovered_candidate  # noqa: F401
from tests.unit.test_sli_update import PowerLoss, release  # noqa: F401

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


@pytest.fixture
def postgres_acceptance(recovered_candidate, monkeypatch):
    # tests/conftest.py creates a unique sli_test_* clone of the empty template.
    dsn = os.environ.get('ADLOG_TEST_PG_DSN', '')
    if not dsn:
        pytest.skip('isolated PostgreSQL CI DSN is not configured')
    psycopg = pytest.importorskip('psycopg')
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.types.json import Jsonb

    assert conninfo_to_dict(dsn)['dbname'].startswith('sli_test_')
    updater, host, journal = recovered_candidate
    previous = journal['previous']
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute('CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text, sha256 text)')
        connection.execute('CREATE TABLE plugin_installations_v1 (plugin_id text PRIMARY KEY, package_version text, '
                           'package_lifecycle text, desired_activation text, revision bigint NOT NULL DEFAULT 0)')
        # Use the canonical real table contract, not a permissive fake registry.
        migration = (Path(__file__).resolve().parents[2] / 'config/postgres_migrations/179_installed_release.sql').read_text()
        definition = migration.split('create table public.installed_release_v1 (', 1)[1].split('\n);', 1)[0]
        connection.execute('CREATE TABLE public.installed_release_v1 (' + definition + '\n)')
        for row in journal['candidate_ledger']:
            connection.execute('INSERT INTO schema_migrations VALUES (%s,%s,%s)',
                               (row['version'], row['name'], row['sha256']))
        connection.execute('INSERT INTO installed_release_v1(singleton,installation_key,operation,inventory) '
                           'VALUES (true,%s,%s,%s)',
                           (installation_key(previous), 'b' * 32, Jsonb(inventory(previous))))

        observe_fake = host.observe
        def observe():
            result = observe_fake()
            result['installed_release_available'] = True
            ledger = connection.execute('SELECT version,name,sha256 FROM schema_migrations ORDER BY version').fetchall()
            result['migration_ledger'] = [dict(zip(('version', 'name', 'sha256'), row)) for row in ledger]
            result['migration_ledger_max'] = max(row[0] for row in ledger)
            row = connection.execute('SELECT installation_key,operation,inventory FROM installed_release_v1').fetchone()
            result['installed_release'] = dict(zip(('installation_key', 'operation', 'inventory'), row))
            return result
        def compose(args, **kwargs):
            if args == ['config', '--format', 'json']:
                return '{"name":"sli","volumes":{},"services":{}}'
            assert args[:3] == ['exec', '-T', 'postgres'] and args[-2:] == ['--file', '-']
            assert set(kwargs) == {'stdin'}
            connection.execute(kwargs['stdin'].decode())
            return ''
        monkeypatch.setattr(host, 'observe', observe)
        monkeypatch.setattr(host, 'compose', compose, raising=False)
        monkeypatch.setattr(host, 'ownership_preflight', lambda installed, config:
                            installation_key(installed) == installation_key(previous), raising=False)
        monkeypatch.setattr(host, 'publish_installed', lambda *args:
                            update.DockerHost.publish_installed(host, *args))
        yield updater, host, journal, connection


@pytest.mark.parametrize('interrupted', [False, True])
def test_accept_candidate_real_sql_publication_and_idempotent_cache_repair(postgres_acceptance, monkeypatch, interrupted):
    updater, host, journal, connection = postgres_acceptance
    expected = updater.candidate(journal)
    original_cache = updater.installed_path.read_bytes()
    publish = host.publish_installed
    def publish_then_interrupt(*args):
        publish(*args)
        raise PowerLoss()
    if interrupted:
        monkeypatch.setattr(host, 'publish_installed', publish_then_interrupt)
        with pytest.raises(PowerLoss):
            updater.accept_candidate(operation_id=journal['operation'])
        assert updater.installed_path.read_bytes() == original_cache
        assert connection.execute('SELECT inventory FROM installed_release_v1').fetchone()[0] == inventory(expected)
        monkeypatch.setattr(host, 'publish_installed', publish)
    assert updater.accept_candidate(operation_id=journal['operation']) == 'committed'
    row = connection.execute('SELECT operation,inventory FROM installed_release_v1').fetchone()
    assert row == (journal['operation'], inventory(expected))
    assert update.parse_json(updater.installed_path.read_bytes()) == expected
    assert updater.operation()['reason'] == 'operator_accepted_candidate'


@pytest.mark.parametrize('race', ['ledger', 'foreign_registry'])
def test_accept_candidate_real_sql_guard_refuses_publication_race(postgres_acceptance, monkeypatch, race):
    updater, host, journal, connection = postgres_acceptance
    before = updater.installed_path.read_bytes()
    publish = host.publish_installed
    def raced(*args):
        if race == 'ledger':
            connection.execute("UPDATE schema_migrations SET name='foreign-marker'")
        else:
            connection.execute("UPDATE installed_release_v1 SET installation_key=%s", ('f' * 64,))
        publish(*args)
    monkeypatch.setattr(host, 'publish_installed', raced)
    with pytest.raises(Exception, match='update_migration_ledger_mismatch|update_installed_registry_mismatch'):
        updater.accept_candidate(operation_id=journal['operation'])
    connection.execute('ROLLBACK')
    assert updater.installed_path.read_bytes() == before
    pending = updater.operation()
    assert pending['status'] == 'recovery_required' and pending['candidate_acceptance']['status'] == 'pending'
    assert connection.execute('SELECT inventory FROM installed_release_v1').fetchone()[0] == inventory(journal['previous'])
    assert not {'restore', 'migrate', 'drain', 'fence'} & set(host.calls)
