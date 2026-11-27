"""N09 forward migration and disposable PostgreSQL atomic release contracts."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/241_report_schedules.sql").read_text("utf-8")


def test_forward_migration_is_unique_and_does_not_change_previous_sql():
    pairs = [(m.version, m.name) for m in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    index = pairs.index((241, "report_schedules"))
    assert pairs[index - 1] == (240, "file_ransom_details")
    assert sum(n == 241 for n, _ in pairs) == 1
    assert "version=240 and name='file_ransom_details'" in SQL and "where version>=241" in SQL
    assert "sli_report_schedules_v241" in SQL and "values(241,'report_schedules')" in SQL
    assert "unique(schedule_id,schedule_revision,slot)" in SQL
    assert "grant select,insert on public.report_schedules,public.report_schedule_subscriptions,public.report_schedule_runs" in SQL
    assert "password" not in SQL and "token" not in SQL


def test_notification_constraints_extend_main_without_weakening_publication():
    assert "check(object_kind in ('test_problem','semantic_finding','report_schedule'))" in SQL
    assert "(object_kind in ('test_problem','report_schedule') and publication_scenario_id is null)" in SQL
    assert "(object_kind='semantic_finding' and publication_scenario_id is not null and object_id=publication_scenario_id)" in SQL
    assert SQL.count("drop constraint") == 2
    assert "notification_outbox_change" not in SQL
    assert "alter type" not in SQL.lower()


@pytest.fixture
def predecessor_pg(telegram_pg):
    import psycopg
    with psycopg.connect(telegram_pg.dsn, autocommit=True) as conn:
        # Apply the actual N07/N08 outbox DDL, including both publication checks
        # and severity-aware uniqueness. Unrelated semantic/GPO/file tables use markers.
        conn.execute("set role adlog_storage_owner")
        conn.execute("create table public.semantic_finding_publications(scenario_id uuid primary key)")
        n07 = (ROOT / "config/postgres_migrations/229_qw_finding_notifications.sql").read_text("utf-8")
        conn.execute("alter table public.notification_outbox" + n07.split(
            "alter table public.notification_outbox", 1)[1].split(";", 1)[0] + ";")
        n08 = (ROOT / "config/postgres_migrations/230_nps_threshold.sql").read_text("utf-8")
        conn.execute("alter table public.notification_outbox" + n08.split(
            "alter table public.notification_outbox", 1)[1].split("create or replace function", 1)[0])
        conn.execute("reset role")
        conn.execute("insert into schema_migrations values(228,'qw_semantic_input'),"
                     "(229,'qw_finding_notifications'),(230,'nps_threshold'),(231,'agent_gpo_plans'),"
                     "(232,'file_ransom'),(233,'ad_operation_credentials'),(235,'semantic_claim_order_index'),"
                     "(236,'file_audit_evidence'),(237,'entity_context_health'),(240,'file_ransom_details')")
    return telegram_pg


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
@pytest.mark.parametrize("marker", ["missing", "wrong_name", "already_applied", "future"])
def test_postgres_rejects_wrong_predecessor_or_later_marker_atomically(predecessor_pg, marker):
    import psycopg
    with psycopg.connect(predecessor_pg.dsn, autocommit=True) as conn:
        if marker == "missing":
            conn.execute("delete from schema_migrations where version=240")
        elif marker == "wrong_name":
            conn.execute("update schema_migrations set name='other' where version=240")
        else:
            conn.execute("insert into schema_migrations values(%s,'report_schedules')",
                         (241 if marker == "already_applied" else 242,))
        with pytest.raises(psycopg.errors.RaiseException, match="migration 241 prerequisites failed"):
            conn.execute(SQL)
        conn.rollback()
        assert conn.execute("select to_regclass('public.report_schedules')").fetchone()[0] is None
        assert conn.execute("select pg_get_constraintdef(oid) from pg_constraint "
                            "where conname='notification_outbox_object_kind_check'").fetchone()[0].find("report_schedule") == -1


    # Real delivery after disable/revision is exercised by migration285's
    # actual-login fixed-accessor tests, rather than the retired broad worker.


# Retry/revocation dispatch coverage moved to migration285's real-login worker
# test; N09-only fixtures cannot establish the new provenance/accessor contract.
