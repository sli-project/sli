"""Exercise deadline recovery against a synthetic, disposable job ledger."""
from datetime import datetime, timedelta, timezone
from contextlib import nullcontext
import os
from pathlib import Path

import pytest

from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "config/postgres_migrations/211_core_job_deadline_recovery.sql"
BASELINE = (ROOT / "config/postgres_migrations/154_core_job_queue.sql").read_text("utf-8")
pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
JOB_ID = "00000000-0000-4000-8000-000000000211"
TOKEN = "00000000-0000-4000-8000-000000000212"


def function_sql(name):
    body = BASELINE.split(f"create function public.{name}", 1)[1].split("end $$;", 1)[0]
    return f"create function public.{name}" + body + "end $$;"


@pytest.fixture
def ledger():
    import psycopg

    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("disposable PostgreSQL required")
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert_disposable_database(conn)
        conn.execute("""
            do $$ begin
                if not exists(select 1 from pg_roles where rolname='adlog_storage_owner') then
                    create role adlog_storage_owner nologin;
                end if;
                if not exists(select 1 from pg_roles where rolname='sli_job_owner') then
                    create role sli_job_owner nologin;
                end if;
            end $$;
            create table public.schema_migrations(version integer primary key,name text not null);
            alter table public.schema_migrations owner to adlog_storage_owner;
            insert into public.schema_migrations values(154,'core_job_queue'),(210,'vpn_session_indexed_identity');
            create schema sli_jobs authorization sli_job_owner;
            grant usage,create on schema public to sli_job_owner;
            set role sli_job_owner;
        """)
        # Keep the original queue constraints; only dependencies unrelated to
        # deadline recovery are stubbed in this synthetic database.
        conn.execute("create table sli_jobs.jobs (" + BASELINE.split("create table sli_jobs.jobs (", 1)[1].split("\n);", 1)[0] + "\n);")
        conn.execute("create table sli_jobs.audit (" + BASELINE.split("create table sli_jobs.audit (", 1)[1].split("\n);", 1)[0] + "\n);")
        conn.execute("""
            create function public.core_job_profile_v1(text,text) returns boolean
                language sql as 'select true';
            create function public.core_job_admitted_v1(jsonb) returns boolean
                language sql as 'select false';
        """)
        conn.execute(function_sql("claim_core_job_v1"))
        conn.execute(function_sql("fail_core_job_v1"))
        conn.execute("reset role; revoke create on schema public from sli_job_owner")
        yield conn


def seed(conn, *, state, deadline_seconds, attempts=1, max_attempts=3):
    now = datetime.now(timezone.utc)
    available = now - timedelta(minutes=5)
    conn.execute("""
        insert into sli_jobs.jobs(job_id,spec,idempotency_key,plugin_id,source_instance_id,
            partition_key,resource_profile,rights_profile,state,priority,attempts,max_attempts,
            available_at,deadline_at,lease_token,lease_until,lease_generation)
        values(%s,'{}',repeat('a',64),'sli.core','synthetic-source','synthetic-partition',
            'light','vpn-read',%s,1,%s,%s,%s,%s,%s,%s,1)
    """, (JOB_ID, state, attempts, max_attempts, available,
          now + timedelta(seconds=deadline_seconds), TOKEN if state == "leased" else None,
          now - timedelta(seconds=5) if state == "leased" else None))
    return available


def apply_fix(conn):
    conn.execute(MIGRATION.read_text("utf-8"))
    assert conn.execute("select name from public.schema_migrations where version=211").fetchone() == ("core_job_deadline_recovery",)
    assert conn.execute("select has_schema_privilege('sli_job_owner','public','CREATE')").fetchone() == (False,)


def test_original_reaper_reproduces_incident_without_source_data(ledger):
    from psycopg.errors import CheckViolation

    seed(ledger, state="leased", deadline_seconds=-60)
    with pytest.raises(CheckViolation) as caught:
        ledger.execute("select public.claim_core_job_v1('light','synthetic-executor','[]')")
    assert caught.value.sqlstate == "23514"
    assert caught.value.diag.constraint_name == "jobs_check1"
    assert ledger.execute("select state from sli_jobs.jobs").fetchone() == ("leased",)


@pytest.mark.parametrize("state,deadline,attempts,max_attempts,expected", [
    ("leased", -60, 1, 3, "quarantined"),
    ("queued", -60, 0, 3, "quarantined"),
    ("retry_wait", -60, 1, 3, "quarantined"),
    ("leased", 300, 3, 3, "quarantined"),
    ("leased", 300, 1, 3, "retry_wait"),
    ("leased", 10, 1, 3, "retry_wait"),
])
def test_reaper_preserves_deadline_constraint_and_audits_transition(ledger, state, deadline, attempts, max_attempts, expected):
    available = seed(ledger, state=state, deadline_seconds=deadline, attempts=attempts, max_attempts=max_attempts)
    apply_fix(ledger)
    assert ledger.execute("select public.claim_core_job_v1('light','synthetic-executor','[]')").fetchone() == (None,)
    row = ledger.execute("select state,available_at,deadline_at,lease_token,lease_until from sli_jobs.jobs").fetchone()
    assert row[0] == expected
    assert row[1] < row[2]
    assert row[3:] == (None, None)
    if expected == "quarantined":
        assert row[1] == available
    else:
        assert row[1] > available
    assert ledger.execute("select transition,error_code from sli_jobs.audit").fetchall() == [(expected, "lease_expired")]
    assert ledger.execute("select public.claim_core_job_v1('light','synthetic-executor','[]')").fetchone() == (None,)
    assert ledger.execute("select count(*) from sli_jobs.audit").fetchone() == (1,)


@pytest.mark.parametrize("permanent,attempts,deadline,expected", [
    (False, 1, 300, "retry_wait"), (False, 1, 10, "retry_wait"),
    (True, 1, 10, "quarantined"), (False, 3, 10, "quarantined"),
])
def test_failure_backoff_respects_deadline_and_lease_fence(ledger, permanent, attempts, deadline, expected):
    available = seed(ledger, state="leased", deadline_seconds=deadline, attempts=attempts)
    ledger.execute("update sli_jobs.jobs set lease_until=deadline_at")
    apply_fix(ledger)
    assert ledger.execute("select public.fail_core_job_v1(%s,%s,2,'job_execution_failed',%s)",
                          (JOB_ID, TOKEN, permanent)).fetchone() == (False,)
    assert ledger.execute("select public.fail_core_job_v1(%s,%s,1,'job_execution_failed',%s)",
                          (JOB_ID, TOKEN, permanent)).fetchone() == (True,)
    row = ledger.execute("select state,available_at,deadline_at,lease_token,lease_until from sli_jobs.jobs").fetchone()
    assert row[0] == expected and row[1] < row[2] and row[3:] == (None, None)
    if expected == "quarantined":
        assert row[1] == available
    assert ledger.execute("select transition,error_code from sli_jobs.audit").fetchall() == [(expected, "job_execution_failed")]


def test_migration_rejects_wrong_predecessor_atomically(ledger):
    from psycopg.errors import RaiseException

    ledger.execute("update public.schema_migrations set name='synthetic-wrong-predecessor' where version=210")
    with pytest.raises(RaiseException, match="migration 211 prerequisites failed"):
        ledger.execute(MIGRATION.read_text("utf-8"))
    ledger.execute("rollback")
    assert ledger.execute("select count(*) from public.schema_migrations where version=211").fetchone() == (0,)


def test_executor_startup_recovers_after_deadline_migration(ledger, monkeypatch, capsys):
    import json

    from server.sli.core import job_executor, job_registry
    from server.sli.plugins.workstations import jobs as workstation_jobs
    from server.sli.sources import ad_gpo_jobs

    seed(ledger, state="leased", deadline_seconds=-60)
    monkeypatch.setattr(job_executor, "connect", lambda *_: nullcontext(ledger))
    monkeypatch.setattr(job_executor, "pilot_enabled", lambda: False)
    monkeypatch.setattr(job_executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(job_executor, "pilot_registry", job_registry.HandlerRegistry)
    monkeypatch.setattr(ad_gpo_jobs, "enabled", lambda: True)
    monkeypatch.setattr(ad_gpo_jobs, "schedule", lambda *_: None)
    monkeypatch.setattr(workstation_jobs, "enabled", lambda: False)
    assert job_executor.main(["--profile", "light", "--once"]) == 1
    diagnostic = json.loads(capsys.readouterr().err.strip().split(" ", 1)[1])
    assert diagnostic == {"error_type": "CheckViolation", "error_code": "job_deadline_constraint", "sqlstate": "23514"}
    apply_fix(ledger)
    assert job_executor.main(["--profile", "light", "--once"]) == 0
    assert capsys.readouterr().err == ""
    assert ledger.execute("select state from sli_jobs.jobs").fetchone() == ("quarantined",)
