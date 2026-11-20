"""N09 forward migration and disposable PostgreSQL atomic release contracts."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core import notification_outbox as outbox, report_schedules as schedules
from tests.migrations.test_notification_outbox_postgres import access, pg as pg, subscribe
from tests.migrations.test_notification_smtp_migration226 import smtp_pg as smtp_pg
from tests.migrations.test_notification_telegram_migration227 import telegram_pg as telegram_pg
from tests.unit.test_report_schedules import config, moment, sample_run

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


@pytest.fixture
def schedule_pg(predecessor_pg, monkeypatch):
    import psycopg
    with psycopg.connect(predecessor_pg.dsn, autocommit=True) as conn:
        conn.execute(SQL)
        # Current delivery readers also require the additive journal columns from
        # migration 247. Use its real DDL without unrelated semantic prerequisites;
        # the migration-241-only checks still use predecessor_pg directly.
        delivery_sql = (ROOT / "config/postgres_migrations/247_decoy_delivery_context.sql").read_text("utf-8")
        columns = delivery_sql.split("alter table public.notification_outbox", 1)[1].split(";", 1)[0]
        conn.execute("set role adlog_storage_owner")
        conn.execute("alter table public.notification_outbox" + columns + ";")
        conn.execute("reset role")
    monkeypatch.setattr(schedules, "report_access", lambda *_args, **_kwargs: None)
    def snapshot(row, slot, users, now):
        return {k: v for k, v in sample_run(schedule_id=str(row["id"]), schedule_revision=row["revision"],
            report_key=row["report_key"], slot=slot, period_from=slot-timedelta(days=row["period_days"]),
            period_to=slot, generated_at=now, delayed=now-slot>=timedelta(minutes=1)).items() if k in schedules.RUN_FIELDS}
    monkeypatch.setattr(schedules, "snapshot", snapshot)
    def query(sql, params=()):
        with predecessor_pg() as conn:
            # Match query_rows: project read binds are converted before psycopg.
            return conn.execute(outbox.database._pg_sql(sql), params).fetchall()
    monkeypatch.setattr(outbox.database, "query_rows", query)
    return predecessor_pg


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_preserves_existing_finding_and_nps_severity_jobs(predecessor_pg):
    import psycopg
    subscription = subscribe()
    scenario = str(uuid4())
    with psycopg.connect(predecessor_pg.dsn) as conn:
        conn.execute("set role adlog_storage_owner")
        conn.execute("insert into semantic_finding_publications values(%s)", (scenario,))
    insert = """insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
        publication_scenario_id,recipient_user_id,channel,change_key,object_severity)
        values(%s,%s,1,%s,%s,%s,2,'smtp',%s,%s)"""
    def add(kind, object_id, publication_id, change="initial", severity=None):
        with predecessor_pg() as conn:
            conn.execute(insert, (str(uuid4()), subscription["id"], kind, object_id, publication_id, change, severity))
    add("test_problem", str(uuid4()), None)
    add("semantic_finding", scenario, scenario, "medium", "medium")
    add("semantic_finding", scenario, scenario, "high", "high")
    constraints = """select conname,pg_get_constraintdef(oid) as definition from pg_constraint
        where conrelid='public.notification_outbox'::regclass
        and conname not in ('notification_outbox_object_kind_check','notification_outbox_publication')
        order by conname"""
    with predecessor_pg() as conn:
        before = conn.execute("select * from notification_outbox order by id").fetchall()
        previous_constraints = conn.execute(constraints).fetchall()
    with psycopg.connect(predecessor_pg.dsn, autocommit=True) as conn:
        conn.execute(SQL)
    with predecessor_pg() as conn:
        assert conn.execute("select * from notification_outbox order by id").fetchall() == before
        assert conn.execute(constraints).fetchall() == previous_constraints
    add("report_schedule", str(uuid4()), None)
    with pytest.raises(psycopg.errors.UniqueViolation):
        add("semantic_finding", scenario, scenario, "high", "high")
    for kind, object_id, publication_id in (
        ("semantic_finding", scenario, None), ("semantic_finding", str(uuid4()), scenario),
        ("report_schedule", scenario, scenario), ("test_problem", scenario, scenario),
        ("unknown", str(uuid4()), None),
    ):
        with pytest.raises(psycopg.errors.CheckViolation):
            add(kind, object_id, publication_id)


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


def create_schedule(pg):
    first, second = subscribe(), subscribe(channel="telegram")
    row = schedules.save(access(), 1, {**config(), "subscription_ids": [first["id"], second["id"]]}, audit=lambda *_: None)
    # Only private disposable fixture data; make a controlled calendar slot due.
    import psycopg
    with psycopg.connect(pg.dsn) as conn:
        conn.execute("set role adlog_storage_owner")
        conn.execute("update report_schedules set created_at=%s where id=%s", (moment("2026-01-01T00:00:00"), row["id"]))
    return row


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_legacy_slot_concurrency_restart_and_default_worker_exclusion(schedule_pg, monkeypatch):
    from server.sli.core import notification_smtp as smtp, notification_telegram as telegram
    row = create_schedule(schedule_pg)
    now = moment("2026-10-18T09:00:00")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: schedules.release(row["id"], now=now), range(2)))
    assert results.count(True) == 1
    assert not schedules.release(row["id"], now=now)
    received = []
    monkeypatch.setattr(smtp, "send", lambda job, _: received.append(job) or "accepted")
    monkeypatch.setattr(telegram, "send", lambda job, _: received.append(job) or telegram.Outcome("accepted"))
    # Legacy API-created runs have no producer provenance. The default worker
    # must leave them untouched; migration285 tests own real report dispatch.
    assert not outbox.process_one(smtp=True, telegram=True)
    assert received == []
    with schedule_pg() as conn:
        jobs = conn.execute('select channel,state from notification_outbox').fetchall()
        assert {job['channel'] for job in jobs} == {'smtp', 'telegram'}
        assert {job['state'] for job in jobs} == {'pending'}
    assert not schedules.release(row["id"], now=now)
    journal, more = outbox.journal(access())
    assert len(journal) == 2 and not more
    assert all(j["delivery_reason"] == "live" and j["delay_minutes"] == 0 for j in journal)
    assert all(j["period_from"] == now-timedelta(days=1) and j["period_to"] == now and j["quality"] == "partial" for j in journal)


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_catchup_releases_only_latest_slot_and_preserves_snapshots(schedule_pg):
    row = create_schedule(schedule_pg)
    assert schedules.release(row["id"], now=moment("2026-10-18T10:00:00"))
    assert schedules.release(row["id"], now=moment("2026-10-28T10:00:00"))
    with schedule_pg() as conn:
        runs = conn.execute("select slot,period_from,delayed from report_schedule_runs order by slot").fetchall()
        assert len(runs) == 2
        assert runs[-1] == {"slot": moment("2026-10-28T09:00:00"), "period_from": moment("2026-10-27T09:00:00"), "delayed": True}
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 4
    import psycopg
    with pytest.raises(psycopg.errors.InsufficientPrivilege), schedule_pg() as conn:
        conn.execute("update report_schedule_runs set quality='ok'")


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_atomic_rollback_on_queue_overflow(schedule_pg, monkeypatch):
    row = create_schedule(schedule_pg)
    monkeypatch.setattr(outbox, "MAX_PENDING", 1)
    with pytest.raises(ValueError, match="notification_queue_full"):
        schedules.release(row["id"], now=moment("2026-10-18T09:00:00"))
    with schedule_pg() as conn:
        assert conn.execute("select count(*) as n from report_schedule_runs").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 0


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_second_channel_failure_rolls_back_run_and_first_job(schedule_pg):
    import psycopg
    row = create_schedule(schedule_pg)
    with psycopg.connect(schedule_pg.dsn) as conn:
        conn.execute("set role adlog_storage_owner")
        conn.execute("""create function public.reject_test_channel() returns trigger language plpgsql as $$ begin
            if NEW.channel='telegram' then raise exception 'synthetic_channel_failure'; end if;
            return NEW; end $$;
            create trigger reject_test_channel before insert on notification_outbox
            for each row execute function public.reject_test_channel();""")
    with pytest.raises(psycopg.errors.RaiseException):
        schedules.release(row["id"], now=moment("2026-10-18T09:00:00"))
    with schedule_pg() as conn:
        assert conn.execute("select count(*) as n from report_schedule_runs").fetchone()["n"] == 0
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 0


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_schedule_update_revision_and_disable(schedule_pg):
    row = create_schedule(schedule_pg)
    assert schedules.release(row["id"], now=moment("2026-10-18T09:00:00"))
    with schedule_pg() as conn:
        ids = [str(r["subscription_id"]) for r in conn.execute(
            "select subscription_id from report_schedule_subscriptions where schedule_id=%s", (row["id"],)).fetchall()]
    body = {**config(), "subscription_ids": ids, "enabled": False, "revision": row["revision"]}
    updated = schedules.save(access(), 1, body, schedule_id=row["id"], audit=lambda *_: None)
    assert updated["revision"] == row["revision"] + 1
    with pytest.raises(LookupError):
        schedules.save(access(), 1, body, schedule_id=row["id"], audit=lambda *_: None)
    # Real delivery after disable/revision is exercised by migration285's
    # actual-login fixed-accessor tests, rather than the retired broad worker.


@pytest.mark.postgres_integration
@pytest.mark.postgres_empty
def test_postgres_disabled_subscription_does_not_stop_other_channel(schedule_pg):
    row = create_schedule(schedule_pg)
    with schedule_pg() as conn:
        conn.execute("update notification_subscriptions set enabled=false,revision=revision+1 where channel='smtp'")
    assert schedules.release(row["id"], now=moment("2026-10-18T09:00:00"))
    with schedule_pg() as conn:
        assert [r["channel"] for r in conn.execute("select channel from notification_outbox").fetchall()] == ["telegram"]


# Retry/revocation dispatch coverage moved to migration285's real-login worker
# test; N09-only fixtures cannot establish the new provenance/accessor contract.
