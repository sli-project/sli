"""Build an attested historical test database in an owned PostgreSQL cluster."""

import os
import secrets
import shutil
from contextlib import contextmanager
from pathlib import Path

import pytest

from scripts.maintenance import existing_postgres_bootstrap as bootstrap
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_linux_native_pg_migrate import private_postgres

ROOT = Path(__file__).resolve().parents[2]


@contextmanager
def historical_connection(tmp_path, monkeypatch, last_migration: tuple[int, str]):
    import psycopg

    if not os.environ.get("SLI_UPGRADE_TEST_PG_BIN"):
        initdb = shutil.which("initdb")
        if initdb is None:
            if os.environ.get("ADLOG_TEST_PG_DSN"):
                pytest.fail("historical migration fixture requires PostgreSQL 18 binaries")
            pytest.skip("PostgreSQL 18 binaries are required for the owned historical fixture")
        monkeypatch.setenv("SLI_UPGRADE_TEST_PG_BIN", str(Path(initdb).parent))

    migrations = tuple(m for m in bootstrap.forward_migration_inventory(ROOT / "config/postgres_migrations")
                       if m.version <= last_migration[0])
    assert migrations and (migrations[-1].version, migrations[-1].name) == last_migration
    baseline = bootstrap.load_baseline(ROOT / "config/postgres_baseline", migrations)
    expected = sorted([*bootstrap.base_schema_markers(ROOT / "config/postgres_schema.sql"),
                       *((m.version, m.name) for m in migrations)])
    database = "sli_test_historical"
    runtime_password = secrets.token_urlsafe(32)
    with private_postgres(tmp_path / "cluster") as pg:
        address = {"host": "127.0.0.1", "hostaddr": "127.0.0.1", "port": pg.port, "user": "postgres",
                   "connect_timeout": 5, "options": ""}
        with psycopg.connect(**address, dbname="postgres", autocommit=True) as admin:
            assert int(admin.execute("show server_version_num").fetchone()[0]) // 10_000 == 18
            bootstrap.create_target_database(admin, database=database, runtime_password=runtime_password)
        with psycopg.connect(**address, dbname=database, autocommit=True) as conn:
            assert_disposable_database(conn)
            bootstrap.apply_baseline_sequence(
                baseline=baseline,
                rendered_schema_path=bootstrap.render_baseline_schema(baseline, "example.test", tmp_path / "baseline.sql"),
                migrations=migrations,
                psql=pg.tools / ("psql.exe" if os.name == "nt" else "psql"),
                host=address["host"], port=pg.port, database=database, admin_password="",
                runtime_password=runtime_password, platform_owner_password=secrets.token_urlsafe(32),
                admin_execute=conn.execute,
            )
            bootstrap.verify_exact_ledger(
                conn.execute("select version,name from public.schema_migrations order by version").fetchall(),
                expected,
            )
            yield conn
