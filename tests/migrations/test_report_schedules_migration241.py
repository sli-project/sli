"""N09 forward migration and disposable PostgreSQL atomic release contracts."""

from pathlib import Path

import pytest

from deploy.linux.existing_postgres_bootstrap import forward_migration_inventory
from tests.migrations.historical_postgres import historical_connection

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
def predecessor_pg(tmp_path, monkeypatch):
    with historical_connection(tmp_path, monkeypatch, (240, "file_ransom_details")) as conn:
        yield conn


@pytest.mark.postgres_integration
@pytest.mark.postgres_owned_cluster
@pytest.mark.parametrize("marker", ["missing", "wrong_name", "already_applied", "future"])
def test_postgres_rejects_wrong_predecessor_or_later_marker_atomically(predecessor_pg, marker):
    import psycopg

    conn = predecessor_pg

    if marker == "missing":
        conn.execute("delete from schema_migrations where version=240")
    elif marker == "wrong_name":
        conn.execute("update schema_migrations set name='other' where version=240")
    else:
        conn.execute("insert into schema_migrations(version,name) values(%s,'report_schedules')",
                     (241 if marker == "already_applied" else 242,))
    with pytest.raises(psycopg.errors.RaiseException, match="migration 241 prerequisites failed"):
        conn.execute(SQL)
    conn.rollback()
    assert conn.execute("select to_regclass('public.report_schedules')").fetchone()[0] is None
    assert conn.execute("select pg_get_constraintdef(oid) from pg_constraint "
                        "where conname='notification_outbox_object_kind_check'").fetchone()[0].find("report_schedule") == -1
