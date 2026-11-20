"""Source authority and reversible upgrade on the actual fully migrated schema."""
import os
from pathlib import Path

import pytest

from deploy.linux.native_pg_inventory import expected_ledger
from tests.migrations.test_file_mass_activity_postgres import (
    _accepted_events,
    _source,
    mass_db as mass_db,
    mass_dsn as mass_dsn,
)

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


def test_file_source_requires_receipt_import_envelope_revision_and_assignment(mass_db, postgres_semantic_worker_dsn):
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict

    identity, owner, _, at, _ = _source(mass_db)
    _accepted_events(mass_db, identity, owner, [r"C:\synthetic\one"], at)
    login = conninfo_to_dict(postgres_semantic_worker_dsn)["user"]
    mutations = [
        "update sli_agent_packet_inbox set imported_at=null",
        "update sli_agent_receipts set module_id='sli.windows.ad-dc'",
        "update sli_agent_packet_inbox set envelope=envelope||'{\"generation\":\"forged\"}'",
        "update sli_plugin_file_audit.observations set policy_revision=policy_revision+1",
        "update sli_agents set status='disabled'",
    ]
    with mass_db() as admin:
        for mutation in [*mutations, None]:
            with admin.transaction(force_rollback=True):
                if mutation:
                    admin.execute(mutation)
                admin.execute(sql.SQL("set session authorization {}").format(sql.Identifier(login)))
                admin.execute("set role adlog_semantic_worker")
                sources = admin.execute("select source from default_detection_sources()").fetchall()
                assert len(sources) == int(mutation is None)
                if sources:
                    assert sources[0]["source"]["scope"]["plugin_id"] == "sli.file-audit"
