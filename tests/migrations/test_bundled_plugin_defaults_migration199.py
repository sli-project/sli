"""Bundled defaults on clean installation and upgrade, preserving owner stops."""
import json
import os
from pathlib import Path

import psycopg
import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core.job_queue import digest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'config/postgres_migrations/199_bundled_plugin_defaults.sql'
SQL = PATH.read_text('utf-8')
PLUGINS = ('sli.file-audit', 'sli.workstations', 'sli.remote-access')


def test_manifest_hashes_exact_predecessor_and_lifecycle_guards():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(PATH.parent)]
    assert pairs[pairs.index((199, 'bundled_plugin_defaults')) - 1] == (198, 'file_audit_admin_actions')
    assert len(pairs) == len({v for v, _ in pairs})
    for plugin in PLUGINS:
        path = (ROOT / 'tests/fixtures/workstations/package-before-overview.v3.json' if plugin == 'sli.workstations'
                else ROOT / f'config/plugin_packages/v3/{plugin}.json')
        manifest = json.loads(path.read_text('utf-8'))
        # Keep the applied migration's package attestation independent of later
        # additive schema entries, whose bytes are checked by their own tests.
        manifest['data']['migrations'] = [item for item in manifest['data']['migrations'] if item['version'] < 199]
        assert f"'{plugin}','{plugin}.package.v3','{digest(manifest)}'" in SQL
    for guard in ('plugin_lifecycle_operations_v1', 'plugin_component_admission_v1',
                  'plugin_component_leases_v1', "requested_action in ('drain','disable','detach')"):
        assert guard in SQL
    assert 'on conflict(plugin_id) do nothing' in SQL
    assert 'delete from' not in SQL.lower() and 'grant ' not in SQL.lower()


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize('existing', [False, True])
def test_real_postgres_defaults_and_preserves_explicit_owner_disable(existing):
    dsn = os.environ.get('ADLOG_TEST_PG_DSN')
    if not dsn:
        pytest.skip('isolated PostgreSQL template is not configured')
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute('create table schema_migrations(version int primary key,name text)')
        conn.execute("insert into schema_migrations values(198,'file_audit_admin_actions')")
        conn.execute('''create table plugin_installations_v1(plugin_id text primary key,manifest_id text,
            manifest_sha256 text,package_version text,package_lifecycle text,desired_activation text,
            observed_health text,component_runtime text,queue_state text,revision bigint,
            immutable_evidence_count bigint,updated_at_utc timestamptz default now())''')
        conn.execute('create table plugin_state_v1(plugin_id text primary key,configured boolean,updated_at_utc timestamptz)')
        conn.execute('create table plugin_lifecycle_operations_v1(plugin_id text,requested_action text,outcome text)')
        conn.execute('create table plugin_component_admission_v1(plugin_id text)')
        conn.execute('create table plugin_component_leases_v1(plugin_id text,released_at_utc timestamptz,expires_at_utc timestamptz)')
        for table in ('plugin_installations_v1', 'plugin_state_v1', 'plugin_lifecycle_operations_v1',
                      'plugin_component_admission_v1', 'plugin_component_leases_v1'):
            conn.execute(f'alter table {table} owner to adlog_plugin_lifecycle_owner')
        if existing:
            for plugin in PLUGINS:
                conn.execute("insert into plugin_installations_v1(plugin_id,package_lifecycle,desired_activation,"
                    "component_runtime,queue_state,revision) values(%s,'registered','disabled','stopped','drained',7)", (plugin,))
            conn.execute("insert into plugin_lifecycle_operations_v1 values('sli.workstations','disable','succeeded')")
        conn.execute(SQL)
        states = dict(conn.execute('select plugin_id,desired_activation from plugin_installations_v1').fetchall())
        assert states['sli.file-audit'] == states['sli.remote-access'] == 'enabled_manual'
        assert states['sli.workstations'] == ('disabled' if existing else 'enabled_manual')
        assert conn.execute('select count(*) from plugin_state_v1 where configured').fetchone()[0] == 3
        with pytest.raises(psycopg.errors.RaiseException, match='unused version 199'):
            conn.execute(SQL)
        conn.execute('rollback')
