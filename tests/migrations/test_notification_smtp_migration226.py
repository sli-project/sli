"""N04 forward-only migration contracts and opt-in disposable PostgreSQL checks."""

from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core import notification_outbox as outbox, notification_smtp as smtp
from tests.migrations.test_notification_outbox_postgres import enqueue, pg as pg, subscribe

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/226_notification_smtp.sql").read_text("utf-8")


def test_forward_only_smtp_migration_has_exact_predecessor_and_allowlisted_results():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((226, "notification_smtp"))
    assert pairs[position - 1] == (225, "notification_outbox")
    assert sum(version == 226 for version, _ in pairs) == 1
    assert SQL.startswith("-- N04") and SQL.strip().endswith("commit;")
    assert "version=225 and name='notification_outbox'" in SQL and "where version>=226" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL
    assert "values(226,'notification_smtp')" in SQL
    for code in smtp.RESULTS:
        assert "'" + code + "'" in SQL
    assert "grant " not in SQL and "password" not in SQL and "token" not in SQL


@pytest.fixture
def smtp_pg(pg):
    import psycopg
    with psycopg.connect(pg.dsn, autocommit=True) as conn:
        conn.execute(SQL)
    return pg


def test_postgres_acceptance_journal_replay_and_independent_channel(smtp_pg, monkeypatch):
    subscription = subscribe()
    first = enqueue(subscription)
    enqueue(subscribe(channel="telegram"), first["object_id"])
    with smtp_pg() as conn:
        conn.execute("update notification_channels set enabled=true where kind='smtp'")
    monkeypatch.setattr(smtp, "send", lambda job, channel: "accepted" if channel["enabled"] else "smtp_not_configured")
    while outbox.process_one(smtp=True):
        pass
    assert enqueue(subscription, first["object_id"])["id"] == first["id"]
    assert not outbox.process_one(smtp=True)
    with smtp_pg() as conn:
        jobs = conn.execute("select channel,state,result_code from notification_outbox order by channel").fetchall()
        assert jobs == [{"channel": "smtp", "state": "accepted", "result_code": "accepted"},
                        {"channel": "telegram", "state": "dry_run", "result_code": "simulated"}]
        assert conn.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 2


@pytest.mark.parametrize("state,code", [("accepted", "simulated"), ("failed", "accepted"), ("accepted", None)])
def test_postgres_acceptance_requires_matching_state_and_code(smtp_pg, state, code):
    import psycopg
    first = enqueue(subscribe())
    with pytest.raises(psycopg.errors.CheckViolation), smtp_pg() as conn:
        conn.execute("update notification_outbox set state=%s,result_code=%s where id=%s", (state, code, first["id"]))


def test_postgres_telegram_cannot_claim_smtp_acceptance_and_history_is_append_only(smtp_pg):
    import psycopg
    first = enqueue(subscribe(channel="telegram"))
    with pytest.raises(psycopg.errors.CheckViolation), smtp_pg() as conn:
        conn.execute("update notification_outbox set state='accepted',result_code='accepted' where id=%s", (first["id"],))
    with pytest.raises(psycopg.errors.InsufficientPrivilege), smtp_pg() as conn:
        conn.execute("update notification_attempts set result_code='accepted'")
    with pytest.raises(psycopg.errors.CheckViolation), smtp_pg() as conn:
        conn.execute("insert into notification_attempts(job_id,attempt,state,result_code) values(%s,1,'accepted','simulated')", (first["id"],))


def test_postgres_disable_before_retry_blocks_smtp_and_preserves_other_channel(smtp_pg, monkeypatch):
    first = enqueue(subscribe())
    enqueue(subscribe(channel="telegram"), first["object_id"])
    monkeypatch.setattr(smtp, "send", lambda job, channel: "smtp_unavailable" if channel["enabled"] else "smtp_not_configured")
    with smtp_pg() as conn:
        conn.execute("update notification_channels set enabled=true where kind='smtp'")
    while outbox.process_one(smtp=True):
        pass
    with smtp_pg() as conn:
        assert conn.execute("select state from notification_outbox where id=%s", (first["id"],)).fetchone()["state"] == "retry"
        conn.execute("update notification_channels set enabled=false where kind='smtp'")
        conn.execute("update notification_outbox set available_at=clock_timestamp() where id=%s", (first["id"],))
    assert outbox.process_one(smtp=True)
    with smtp_pg() as conn:
        assert conn.execute("select state,result_code from notification_outbox where id=%s", (first["id"],)).fetchone() == {
            "state": "blocked", "result_code": "smtp_not_configured",
        }
        assert conn.execute("select state from notification_outbox where channel='telegram'").fetchone()["state"] == "dry_run"
