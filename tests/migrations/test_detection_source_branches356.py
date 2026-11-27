"""Source authority and reversible upgrade on the actual fully migrated schema."""
import os
from pathlib import Path

import pytest

from deploy.linux.native_pg_inventory import expected_ledger

pytestmark = pytest.mark.postgres_integration
ROOT = Path(__file__).resolve().parents[2]


def test_previous_maximum_accepts_356_and_rollback_restores_definition(isolated_postgres_integration_database):
    import psycopg

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    assert dsn, "Disposable PostgreSQL 18 required"
    forward = (ROOT / "config/postgres_migrations/356_detection_source_branches.sql").read_text("utf-8")
    rollback = (ROOT / "config/postgres_migrations/356_detection_source_branches.rollback.sql").read_text("utf-8")
    with psycopg.connect(dsn, autocommit=True) as db:
        installed = {row[0] for row in db.execute("select version from schema_migrations")}
        ledger = expected_ledger(ROOT)
        for migration in reversed(ledger):
            if migration["version"] > 356 and migration["version"] in installed:
                path = ROOT / f"config/postgres_migrations/{migration['version']:03}_{migration['name']}.rollback.sql"
                db.execute(path.read_text("utf-8"))
        signature = "public.default_detection_sources_before_v301()"
        saved, = db.execute("select definition from detection_source_definitions356").fetchone()
        before = db.execute("select oid,proowner,proacl,prosecdef,proconfig from pg_proc where oid=%s::regprocedure", (signature,)).fetchone()
        previous = max(migration["version"] for migration in ledger if migration["version"] < 356)
        db.execute(rollback)
        assert db.execute("select max(version) from schema_migrations").fetchone()[0] == previous
        assert db.execute("select pg_get_functiondef(%s::regprocedure)", (signature,)).fetchone()[0] == saved
        db.execute(forward)
        assert db.execute("select oid,proowner,proacl,prosecdef,proconfig from pg_proc where oid=%s::regprocedure", (signature,)).fetchone() == before
        assert db.execute("select max(version) from schema_migrations").fetchone()[0] == 356
        for role in ("adlog_user", "adlog_semantic_worker"):
            assert not db.execute("select has_table_privilege(%s,'detection_source_definitions356','SELECT')", (role,)).fetchone()[0]
        db.execute(rollback)
        assert db.execute("select pg_get_functiondef(%s::regprocedure)", (signature,)).fetchone()[0] == saved
