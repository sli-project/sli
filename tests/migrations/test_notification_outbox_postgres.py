"""Targeted N03 SQL checks, opt-in on a private disposable loopback PG18 cluster."""

import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from server.sli.core import notification_outbox as outbox
from tests.postgres_integration_guard import assert_disposable_database

ROOT = Path(__file__).resolve().parents[2]


def access():
    return {"subject": {"coarse_role": "admin"}, "capabilities": ["access.manage", "field.technical"],
            "reports": [{"report_key": "notifications.channels", "allowed": True,
                         "allowed_actions": ["view", "configure_channel"],
                         "grants": [{"allowed_actions": ["view", "configure_channel"],
                                     "field_categories": ["technical"], "scope": {"kind": "all"}}]}]}


@pytest.fixture
def pg(monkeypatch, request):
    # Marked schema tests already own an empty clone from tests/conftest.py.
    isolated = request.node.get_closest_marker("postgres_empty") is not None
    dsn = os.environ.get("ADLOG_TEST_PG_DSN" if isolated else "SLI_NOTIFY_TEST_PG_DSN")
    if not dsn:
        pytest.skip("private N03 disposable PostgreSQL cluster not configured")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    from psycopg.rows import dict_row

    parts = conninfo_to_dict(dsn)
    if not isolated:
        assert parts.get("host") == "127.0.0.1" and parts.get("port") == "55432"
    name = parts["dbname"] if isolated else "sli_test_notify_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        if isolated:
            assert_disposable_database(admin)
        assert int(admin.execute("show server_version_num").fetchone()[0]) // 10000 == 18
        for role in ("adlog_storage_owner", "adlog_user"):
            if not admin.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
                admin.execute(sql.SQL("create role {} nologin").format(sql.Identifier(role)))
        if not isolated:
            admin.execute(sql.SQL("create database {} template template0 encoding 'UTF8'").format(sql.Identifier(name)))
    test_dsn = make_conninfo(dsn, dbname=name)
    try:
        with psycopg.connect(test_dsn, autocommit=True, row_factory=dict_row) as admin:
            admin.execute("""
                grant usage,create on schema public to adlog_storage_owner;
                grant usage on schema public to adlog_user;
                create table schema_migrations(version integer primary key,name text not null);
                insert into schema_migrations values(223,'home_previous_login');
                create table report_datasets_v4(id bigserial primary key,dataset_key text,version integer,name text,
                    object_type text,fields_json jsonb,filters_json jsonb,actions_json jsonb,status text);
                create table report_registry_v4(report_key text,version integer,name text,owner_name text,purpose text,
                    dataset_id bigint references report_datasets_v4(id),definition_json jsonb,sensitivity text,
                    status text,published_at timestamptz);
                create table access_packages(id bigserial primary key,package_key text);
                insert into access_packages(package_key) values('access_admin');
                create table access_package_reports(package_id bigint,report_key text,field_categories text[],
                    allowed_actions text[],scope_json jsonb);
            """)
            admin.execute((ROOT / "config/postgres_migrations/224_notification_channels.sql").read_text("utf-8"))
            admin.execute((ROOT / "config/postgres_migrations/225_notification_outbox.sql").read_text("utf-8"))

        def connect():
            conn = psycopg.connect(test_dsn, row_factory=dict_row)
            conn.execute("set role adlog_user")
            conn.execute("set statement_timeout='5s'")
            conn.execute("set lock_timeout='1s'")
            return conn
        connect.dsn = test_dsn
        monkeypatch.setattr(outbox, "connect", connect)
        monkeypatch.setattr(outbox, "require_recipient", lambda _: None)
        yield connect
    finally:
        if not isolated:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute("select pg_terminate_backend(pid) from pg_stat_activity where datname=%s", (name,))
                admin.execute(sql.SQL("drop database {}").format(sql.Identifier(name)))


def subscribe(*, channel="smtp"):
    return outbox.save_subscription(access(), 1, {"recipient_user_id": 2, "channel": channel, "enabled": True}, audit=lambda *_: None)


def enqueue(subscription, problem=None):
    return outbox.enqueue_test_problem(access(), subscription["id"], {"problem_id": problem or str(uuid4())}, audit=lambda *_: None)


def test_sql_replay_dry_run_and_restart_after_expired_lease_keep_one_row(pg):
    subscription = subscribe()
    first = enqueue(subscription)
    assert enqueue(subscription, first["object_id"])["id"] == first["id"]
    abandoned = outbox.claim_job()
    assert str(abandoned["id"]) == first["id"] and outbox.claim_job() is None
    with pg() as conn:
        conn.execute("update notification_outbox set lease_until=clock_timestamp()-interval '1 second' where id=%s", (first["id"],))
    assert outbox.process_one()
    assert not outbox.process_one()
    assert enqueue(subscription, first["object_id"])["id"] == first["id"]
    # Two fresh processes reopen the durable queue without a warm dedup cache.
    for _ in range(2):
        restarted = subprocess.run(
            [sys.executable, "-m", "server.sli.core.notification_outbox", "--limit", "1"],
            cwd=ROOT, env={**os.environ, "ADLOG_DB_BACKEND": "postgres", "ADLOG_PG_DSN": pg.dsn},
            capture_output=True, text=True, timeout=30,
        )
        assert restarted.returncode == 0, "simulated worker restart failed"
    with pg() as conn:
        row = conn.execute("select state,result_code,attempts from notification_outbox").fetchone()
        assert row == {"state": "dry_run", "result_code": "simulated", "attempts": 2}
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 1
        assert conn.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 1


def test_sql_skip_locked_and_stale_worker_fencing(pg, monkeypatch):
    subscription = subscribe()
    first, second = enqueue(subscription), enqueue(subscription)
    with pg() as locked:
        locked.execute("select id from notification_outbox where id=%s for update", (first["id"],))
        other = outbox.claim_job()
        assert str(other["id"]) == second["id"]
    old = outbox.claim_job()
    with pg() as conn:
        conn.execute("update notification_outbox set lease_until=clock_timestamp()-interval '1 second' where id=%s", (first["id"],))
    new = outbox.claim_job()
    assert old["lease_token"] != new["lease_token"]
    monkeypatch.setattr(outbox, "claim_job", lambda: old)
    assert outbox.process_one(transport=lambda _: pytest.fail("stale SQL dispatch"))
    with pg() as conn:
        assert conn.execute("select lease_token from notification_outbox where id=%s", (first["id"],)).fetchone()["lease_token"] == new["lease_token"]
        assert conn.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 0


def test_sql_audit_failure_rolls_back_and_revision_cancels_work(pg):
    subscription = subscribe()
    def broken(*_):
        raise RuntimeError("synthetic audit failure")
    with pytest.raises(RuntimeError):
        outbox.enqueue_test_problem(access(), subscription["id"], {"problem_id": str(uuid4())}, audit=broken)
    with pg() as conn:
        assert conn.execute("select count(*) as n from notification_outbox").fetchone()["n"] == 0
    job = enqueue(subscription)
    outbox.claim_job()
    outbox.save_subscription(access(), 1, {"recipient_user_id": 2, "channel": "smtp", "enabled": False, "revision": 1},
                             subscription_id=subscription["id"], audit=lambda *_: None)
    assert not outbox.process_one()
    with pg() as conn:
        assert conn.execute("select state,lease_token from notification_outbox where id=%s", (job["id"],)).fetchone() == {
            "state": "cancelled", "lease_token": None,
        }


def test_sql_uniqueness_constraints_and_runtime_history_permissions(pg):
    import psycopg
    job = enqueue(subscribe())
    with pytest.raises(psycopg.errors.UniqueViolation), pg() as conn:
        conn.execute("""insert into notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
                     recipient_user_id,channel) select %s,subscription_id,subscription_revision,object_kind,object_id,
                     recipient_user_id,channel from notification_outbox where id=%s""", (str(uuid4()), job["id"]))
    with pytest.raises(psycopg.errors.CheckViolation), pg() as conn:
        conn.execute("update notification_outbox set state='sending' where id=%s", (job["id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), pg() as conn:
        conn.execute("delete from notification_outbox")
    with pytest.raises(psycopg.errors.InsufficientPrivilege), pg() as conn:
        conn.execute("update notification_outbox set object_id=%s", (str(uuid4()),))
    assert outbox.process_one()
    with pytest.raises(psycopg.errors.InsufficientPrivilege), pg() as conn:
        conn.execute("update notification_attempts set result_code='simulated'")
