"""Real dump/restore on two test-owned clusters; no installed DSN is used."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_owned_cluster]


@pytest.fixture(autouse=True)
def hermetic_report_domain():
    # This test owns both complete clusters and never reads application settings.
    yield


def test_private_restore_keeps_source_unchanged_and_stops_cluster():
    psycopg = pytest.importorskip('psycopg')
    from deploy.linux import backup
    from deploy.linux import restore_sandbox as sandbox

    if os.name != 'posix' or os.geteuid() == 0 or not (sandbox.PG_BIN / 'initdb').is_file():
        pytest.skip('requires non-root Linux with PostgreSQL 18 server binaries')
    # Keep Unix socket names within the operating system limit.
    with tempfile.TemporaryDirectory(prefix='sli-pg-') as temporary:
        root = Path(temporary)
        with sandbox.postgres(root / 'source') as source:
            with psycopg.connect(**source, autocommit=True) as conn:
                conn.execute('CREATE DATABASE sli_check TEMPLATE template0')
            settings = source | {'dbname': 'sli_check'}
            with psycopg.connect(**settings, autocommit=True) as conn:
                conn.execute('CREATE TABLE schema_migrations (version integer)')
                conn.execute('INSERT INTO schema_migrations VALUES (7)')
                for name in (table for table in backup.KEY_TABLES if table != 'schema_migrations'):
                    conn.execute(psycopg.sql.SQL('CREATE TABLE {} (id bigint)').format(psycopg.sql.Identifier(name)))
                    conn.execute(psycopg.sql.SQL('INSERT INTO {} VALUES (1), (2)').format(psycopg.sql.Identifier(name)))
                expected = backup.row_counts(conn)
                assert expected == {table: 1 if table == "schema_migrations" else 2 for table in backup.KEY_TABLES}
                assert {"event_hot", "event_cold_facts", "event_cold_daily"} <= expected.keys()
                oid = conn.execute('SELECT oid FROM pg_database WHERE datname=current_database()').fetchone()[0]
            archive = root / 'dump'
            sandbox.command(['pg_dump', '--no-password', '--host=' + source['host'], '--username=sli_check',
                             '--dbname=sli_check', '--format=directory', '--file=' + str(archive)])
            assert sandbox.restore(root / 'checks', archive, expected, 7) is None
            assert list((root / 'checks').iterdir()) == []
            with psycopg.connect(**settings) as conn:
                assert backup.row_counts(conn) == expected
                assert conn.execute('SELECT oid FROM pg_database WHERE datname=current_database()').fetchone()[0] == oid
        assert list((root / 'source').iterdir()) == []
