"""Host-owned read-only probe executed inside the existing backup container."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import psycopg

from deploy.linux import backup
from scripts.maintenance.existing_postgres_bootstrap import base_schema_markers, forward_migration_inventory


def probe(root=Path('/opt/sli')):
    inventory = forward_migration_inventory(root / 'config/postgres_migrations')
    expected = dict(base_schema_markers(root / 'config/postgres_schema_v8.sql'))
    expected.update((item.version, item.name) for item in inventory)
    with psycopg.connect(host='postgres', port=5432, dbname='sli', user='postgres',
                         password=backup.read_secret('SLI_PG_ADMIN_PASSWORD'), connect_timeout=5,
                         options='-c default_transaction_read_only=on') as connection:
        connection.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        rows = connection.execute("SELECT version, name, to_jsonb(m)->>'sha256' FROM public.schema_migrations m ORDER BY version").fetchall()
        hashes = {version: hashlib.sha256((root / 'config/postgres_schema_v8.sql').read_bytes()).hexdigest()
                  for version, _ in base_schema_markers(root / 'config/postgres_schema_v8.sql')}
        hashes.update((item.version, item.sha256) for item in inventory)
        legacy = 179 not in expected
        if not rows or [(version, name) for version, name, _ in rows] != sorted(expected.items()) or any(
                checksum != hashes[version] and not (legacy and checksum is None) for version, _, checksum in rows):
            raise ValueError('adopt_ledger_inconsistent')
        ledger = [{'version': version, 'name': name, 'sha256': checksum or hashes[version]} for version, name, checksum in rows]
        # Store only a digest of plugin lifecycle metadata, never credentials,
        # installation identifiers, queue contents or cursor values.
        plugins = connection.execute('''SELECT plugin_id, package_version, package_lifecycle,
            desired_activation, component_runtime, queue_state
            FROM public.plugin_installations_v1 ORDER BY plugin_id''').fetchall()
        if any(row[2] not in {'validated', 'registered', 'detached'} or
               row[3] not in {'disabled', 'enabled_manual'} or
               row[5] not in {'drained', 'backlog', 'quarantined'} for row in plugins):
            raise ValueError('adopt_plugins_inconsistent')
    migrations = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in sorted((root / 'config/postgres_migrations').glob('*.sql'))}
    return {'migrations': migrations, 'migration_ledger_max_version': max(row['version'] for row in ledger),
            'migration_ledger': ledger,
            'ledger_source': 'deployed_image' if legacy else 'database',
            'plugins': {row[0]: {'version': row[1], 'migrations': {}} for row in plugins if row[2] == 'registered'},
            'plugin_state_sha256': hashlib.sha256(json.dumps(plugins, sort_keys=True).encode()).hexdigest()}


if __name__ == '__main__':
    try:
        print(json.dumps(probe()))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) and str(exc) in {
            'adopt_ledger_inconsistent', 'adopt_plugins_inconsistent'} else 'adopt_database_probe_failed'
        print(json.dumps({'reason_code': reason}))
