"""N05 forward migration contracts and opt-in disposable PostgreSQL checks."""

from pathlib import Path

import pytest

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core import notification_outbox as outbox, notification_smtp as smtp, notification_telegram as telegram
from tests.migrations.test_notification_outbox_postgres import enqueue, pg as pg, subscribe
from tests.migrations.test_notification_smtp_migration226 import smtp_pg as smtp_pg

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/227_notification_telegram.sql").read_text("utf-8")


def test_forward_only_telegram_migration_has_exact_predecessor_safe_codes_and_narrow_grant():
    pairs = [(item.version, item.name) for item in forward_migration_inventory(ROOT / "config/postgres_migrations")]
    position = pairs.index((227, "notification_telegram"))
    assert pairs[position - 1] == (226, "notification_smtp")
    assert sum(version == 227 for version, _ in pairs) == 1
    assert SQL.startswith("-- N05") and SQL.strip().endswith("commit;")
    assert "version=226 and name='notification_smtp'" in SQL and "where version>=227" in SQL
    assert "pg_has_role(session_user,'adlog_storage_owner','MEMBER')" in SQL
    assert "set local role adlog_storage_owner" in SQL and "values(227,'notification_telegram')" in SQL
    assert "grant update(next_delivery_at) on public.notification_channels to adlog_user" in SQL
    assert "drop constraint notification_outbox_smtp_acceptance_check" in SQL
    assert "channel in ('smtp','telegram')" in SQL
    for code in telegram.RESULTS:
        assert "'" + code + "'" in SQL
    assert "https://" not in SQL and "password" not in SQL and "token" not in SQL


@pytest.fixture
def telegram_pg(smtp_pg):
    import psycopg
    with psycopg.connect(smtp_pg.dsn, autocommit=True) as conn:
        conn.execute(SQL)
    return smtp_pg


def test_postgres_telegram_acceptance_and_mail_are_independent_and_replay_is_stable(telegram_pg, monkeypatch):
    subscription = subscribe(channel="telegram")
    first = enqueue(subscription)
    enqueue(subscribe(), first["object_id"])
    monkeypatch.setattr(telegram, "send", lambda *_: telegram.Outcome("accepted"))
    monkeypatch.setattr(smtp, "send", lambda *_: "accepted")
    while outbox.process_one(smtp=True, telegram=True):
        pass
    assert enqueue(subscription, first["object_id"])["id"] == first["id"]
    with telegram_pg() as conn:
        assert conn.execute("select channel,state,result_code from notification_outbox order by channel").fetchall() == [
            {"channel": "smtp", "state": "accepted", "result_code": "accepted"},
            {"channel": "telegram", "state": "accepted", "result_code": "accepted"},
        ]
        assert conn.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 2


def test_postgres_chat_denial_preserves_smtp_acceptance(telegram_pg, monkeypatch):
    first = enqueue(subscribe(channel="telegram"))
    enqueue(subscribe(), first["object_id"])
    monkeypatch.setattr(telegram, "send", lambda *_: telegram.Outcome("telegram_chat_denied"))
    monkeypatch.setattr(smtp, "send", lambda *_: "accepted")
    while outbox.process_one(smtp=True, telegram=True):
        pass
    with telegram_pg() as conn:
        assert conn.execute("select channel,state from notification_outbox order by channel").fetchall() == [
            {"channel": "smtp", "state": "accepted"}, {"channel": "telegram", "state": "blocked"},
        ]


def test_postgres_retry_after_is_durable_bot_wide_and_allows_other_channels(telegram_pg, monkeypatch):
    subscription = subscribe(channel="telegram")
    first = enqueue(subscription)
    monkeypatch.setattr(telegram, "send", lambda *_: telegram.Outcome("telegram_rate_limited", 1200))
    assert outbox.process_one(telegram=True)
    second = enqueue(subscription)
    mail = enqueue(subscribe())
    monkeypatch.setattr(smtp, "send", lambda *_: "accepted")
    assert outbox.process_one(smtp=True, telegram=True)
    assert not outbox.process_one(telegram=True)
    with telegram_pg() as conn:
        row = conn.execute("select state,available_at>clock_timestamp()+interval '1190 seconds' as delayed "
                           "from notification_outbox where id=%s", (first["id"],)).fetchone()
        assert row == {"state": "retry", "delayed": True}
        assert conn.execute("select attempts from notification_outbox where id=%s", (second["id"],)).fetchone()["attempts"] == 0
        assert conn.execute("select state from notification_outbox where id=%s", (mail["id"],)).fetchone()["state"] == "accepted"
        conn.execute("update notification_channels set next_delivery_at=clock_timestamp() where kind='telegram'")
        conn.execute("update notification_outbox set available_at=clock_timestamp() where id=%s", (first["id"],))
    monkeypatch.setattr(telegram, "send", lambda *_: telegram.Outcome("accepted"))
    assert outbox.process_one(telegram=True)
    assert not outbox.process_one(telegram=True)


def test_postgres_racing_claim_respects_cooldown_without_spending_retry(telegram_pg, monkeypatch):
    first = enqueue(subscribe(channel="telegram"))
    claimed = outbox.claim_job(telegram=True)
    with telegram_pg() as conn:
        conn.execute("update notification_channels set next_delivery_at=clock_timestamp()+interval '5 minutes' where kind='telegram'")
    monkeypatch.setattr(outbox, "claim_job", lambda **_: claimed)
    monkeypatch.setattr(telegram, "send", lambda *_: pytest.fail("cooldown bypass"))
    assert outbox.process_one(telegram=True)
    with telegram_pg() as conn:
        assert conn.execute("select state,attempts,lease_token from notification_outbox where id=%s", (first["id"],)).fetchone() == {
            "state": "retry", "attempts": 0, "lease_token": None,
        }
        assert conn.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 0


@pytest.mark.parametrize("state,code", [("accepted", "simulated"), ("blocked", "accepted"), ("accepted", None),
    ("retry", "synthetic-private-value")])
def test_postgres_receipts_remain_allowlisted_and_acceptance_consistent(telegram_pg, state, code):
    import psycopg
    first = enqueue(subscribe(channel="telegram"))
    with pytest.raises(psycopg.errors.CheckViolation), telegram_pg() as conn:
        conn.execute("update notification_outbox set state=%s,result_code=%s where id=%s", (state, code, first["id"]))
