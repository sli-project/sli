"""W02 forward migration and actual SQL contracts on disposable PostgreSQL."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from uuid import uuid4

import pytest

from tests.migrations.test_qw_finding_notifications_migration229 import publication_pg as publication_pg

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.test_qw_semantic_input_migration228 import pg as pg

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/253_account_watch.sql"
SQL = PATH.read_text("utf-8")


def test_forward_migration_is_dormant_and_requires_w01_without_rewriting_it():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(PATH.parent)]
    # WR02 is the immediate inventory predecessor; W01 remains an explicit SQL prerequisite.
    assert pairs[pairs.index((253, "account_watch")) - 1] == (252, "workstation_overview_projections")
    assert list(PATH.parent.glob("253_*.sql")) == [PATH]
    assert "version=251 and name='workstation_access'" in SQL
    assert "sli_account_watch_v253" in SQL
    assert "version=249 and name='watch_registry'" in SQL
    assert "version=248 and name='entity_context_history_reads'" in SQL
    assert "where version>=253" in SQL and "values(253,'account_watch')" in SQL
    assert SQL.splitlines()[1] == "begin;" and SQL.strip().endswith("commit;")
    for table in ("finding_evidence_source_bindings", "semantic_risk_policies", "semantic_policy_admission",
                  "notification_channels", "notification_subscriptions", "watch_entry_versions"):
        assert "insert into public." + table not in SQL


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("markers", [
    [(248, "entity_context_history_reads"), (251, "workstation_access")],
    [(247, "entity_context_history_reads"), (249, "watch_registry"), (251, "workstation_access")],
    [(248, "entity_context_history_reads"), (249, "watch_registry")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"), (250, "workstation_access")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"), (251, "wrong_predecessor")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"),
     (251, "workstation_access"), (253, "account_watch")],
    [(248, "entity_context_history_reads"), (249, "watch_registry"),
     (251, "workstation_access"), (254, "later_migration")],
])
def test_forward_migration_rejects_inexact_prerequisites_without_schema_changes(pg, markers):
    import psycopg

    with psycopg.connect(pg, autocommit=True) as conn:
        # Keep the independent column prerequisite valid so each marker check is exercised.
        conn.execute("create table public.notification_outbox(delivery_reason text)")
        with conn.cursor() as cur:
            cur.executemany("insert into schema_migrations values(%s,%s)", markers)
        with pytest.raises(psycopg.errors.RaiseException, match="migration 253 prerequisites failed"):
            conn.execute(SQL)
        conn.execute("rollback")
        assert conn.execute("select to_regclass('public.semantic_account_watch_checks')").fetchone()[0] is None
        assert conn.execute("select count(*) from schema_migrations where version>=247").fetchone()[0] == len(markers)
