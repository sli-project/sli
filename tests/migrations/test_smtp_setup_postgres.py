"""Full-schema SMTP setup→test outbox→least-privilege worker, fake transport only.

Requires the T009 recipient schema-guard correction, without copying that fix or
adding SQL grants. No real credentials, config files or SMTP calls are used.
"""
import os
from uuid import uuid4

import pytest

from server.api import smtp_setup as setup_api
from server.api.routes import notification_channels as routes
from server.sli.access import access_control_v4
from server.sli.core import notification_outbox as outbox, notification_smtp as smtp
from server.sli.core import postgres_runtime_pipeline as pipeline
from server.sli.ops.postgres_schema_guard import clear_schema_guard_cache
from tests.postgres_integration_guard import assert_disposable_database
from tests.unit.test_notification_channels import Handler

pytestmark = pytest.mark.postgres_integration


@pytest.fixture
def smtp_db(isolated_postgres_integration_database, monkeypatch):
    dsn = os.environ.get("ADLOG_TEST_PG_DSN")
    if not dsn:
        pytest.skip("Fully migrated disposable PostgreSQL required")
    psycopg = pytest.importorskip("psycopg")
    from psycopg.rows import dict_row
    with psycopg.connect(dsn) as conn:
        assert_disposable_database(conn)

    def connect(role=None):
        conn = psycopg.connect(dsn, row_factory=dict_row)
        if role:
            assert role in {"adlog_user", "adlog_notification_worker"}
            conn.execute("set session authorization " + role)
            assert conn.execute("select session_user as s,current_user as c").fetchone() == {"s": role, "c": role}
        return conn

    monkeypatch.setattr(smtp, "_config", lambda *_: pytest.fail("real credential/config access"))
    clear_schema_guard_cache()
    yield connect
    clear_schema_guard_cache()


def bind(monkeypatch, connect, role):
    clear_schema_guard_cache()
    monkeypatch.setattr(pipeline, "connect", lambda: connect(role))
    monkeypatch.setattr(outbox, "connect", lambda: connect(role))
    monkeypatch.setattr(setup_api, "connect", lambda: connect(role))


@pytest.mark.parametrize("revoke", [False, True])
def test_first_run_setup_and_test_delivery_with_native_recipient_acl(smtp_db, monkeypatch, revoke):
    with smtp_db() as admin:
        user = admin.execute("insert into auth_users(username,password_hash,role) values(%s,'synthetic-only','admin') returning id",
                             ("t014-" + uuid4().hex,)).fetchone()["id"]
        revision = admin.execute("select revision from notification_channels where kind='smtp'").fetchone()["revision"]
    bind(monkeypatch, smtp_db, "adlog_user")
    access = access_control_v4.effective_access(None, preview_user_id=user)
    seen = []

    def fake_writer(action, actor, **values):
        assert action == "save" and actor == user
        assert values["recipients"] == {str(user): "fixture@example.invalid"}
        assert values["previous_revision"] == revision and values["revision"] == revision + 1
        with smtp_db() as admin:
            row = admin.execute("select enabled,revision from notification_channels where kind='smtp'").fetchone()
            assert row == {"enabled": False, "revision": revision + 1}
        seen.append(action)
        return {"secret_set": True, "needs_save": False}

    original_subscription_save = outbox.save_subscription
    gap_checks = []
    def bind_during_reserved_gap(*args, **kwargs):
        # The first transaction is committed and no channel row lock is held.
        # A second actual DB session must still fail the shared setup lock.
        observer = Handler(access, payload={})
        observer._principal = {"type": "session", "id": user, "role": "admin"}
        with pytest.raises(setup_api.smtp_setup.SMTPSetupError, match="smtp_setup_conflict"):
            setup_api.configure(observer, "status", lambda *_: None)
        assert not seen
        gap_checks.append(True)
        return original_subscription_save(*args, **kwargs)
    monkeypatch.setattr(outbox, "save_subscription", bind_during_reserved_gap)
    monkeypatch.setattr(setup_api.smtp_setup, "request", fake_writer)
    handler = Handler(access, payload={"host": "smtp.example.invalid", "port": 587, "tls_mode": "starttls",
        "username": "fixture", "password": "synthetic-only", "sender": "fixture@example.invalid",
        "recipients": [{"user_id": user, "mailbox": "fixture@example.invalid"}], "enabled": True, "revision": revision})
    handler._principal = {"type": "session", "id": user, "role": "admin"}
    assert routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.status == 200 and seen == ["save"] and gap_checks == [True]
    with smtp_db() as admin:
        saved = admin.execute("select enabled,tls_mode,revision from notification_channels where kind='smtp'").fetchone()
        assert saved == {"enabled": True, "tls_mode": "starttls", "revision": revision + 1}
    with smtp_db("adlog_user") as other:
        assert other.execute("select pg_try_advisory_lock(hashtext('sli_smtp_setup')) as locked").fetchone()["locked"]
        other.execute("select pg_advisory_unlock(hashtext('sli_smtp_setup'))")
    subscription, = outbox.list_subscriptions(access)
    job = outbox.enqueue_test_problem(access, subscription["id"], {"problem_id": str(uuid4())}, audit=lambda *_: None)
    held = outbox.enqueue_test_problem(access, subscription["id"], {"problem_id": str(uuid4())}, audit=lambda *_: None)
    with smtp_db() as admin:
        # Negative admission fixture only: no report producer is exercised here.
        admin.execute("update notification_outbox set object_kind='report_schedule' where id=%s", (held["id"],))
    if revoke:
        with smtp_db() as admin:
            admin.execute("update auth_users set is_active=false where id=%s", (user,))
    bind(monkeypatch, smtp_db, "adlog_notification_worker")
    delivered = []
    monkeypatch.setattr(smtp, "send", lambda item, channel: delivered.append((item, channel)) or "accepted")
    assert outbox.process_one(smtp=True, telegram=True, notification_only=True)
    assert len(delivered) == (0 if revoke else 1)
    with smtp_db() as admin:
        result = admin.execute("select state,result_code from notification_outbox where id=%s", (job["id"],)).fetchone()
        assert result == ({"state": "blocked", "result_code": "recipient_denied"} if revoke
                          else {"state": "accepted", "result_code": "accepted"})
    with smtp_db("adlog_notification_worker") as worker:
        assert not worker.execute("select has_column_privilege(current_user,'auth_users','password_hash','SELECT') as v").fetchone()["v"]
        assert not worker.execute("select has_column_privilege(current_user,'auth_users','is_service','SELECT') as v").fetchone()["v"]
    assert not outbox.process_one(smtp=True, telegram=True, notification_only=True)
    with smtp_db() as admin:
        untouched = admin.execute("select state,attempts from notification_outbox where id=%s", (held["id"],)).fetchone()
        assert untouched == {"state": "pending", "attempts": 0}


@pytest.mark.parametrize("failure", ["writer", "audit"])
def test_failed_setup_releases_real_session_lock_and_preserves_fence(smtp_db, monkeypatch, failure):
    with smtp_db() as admin:
        user = admin.execute("insert into auth_users(username,password_hash,role) values(%s,'synthetic-only','admin') returning id",
                             ("t014-failure-" + uuid4().hex,)).fetchone()["id"]
        revision = admin.execute("select revision from notification_channels where kind='smtp'").fetchone()["revision"]
    bind(monkeypatch, smtp_db, "adlog_user")
    access = access_control_v4.effective_access(None, preview_user_id=user)
    handler = Handler(access, payload={"host": "smtp.example.invalid", "port": 587, "tls_mode": "starttls",
        "username": "fixture", "password": "synthetic-only", "sender": "fixture@example.invalid",
        "recipients": [{"user_id": user, "mailbox": "fixture@example.invalid"}], "enabled": True, "revision": revision})
    handler._principal = {"type": "session", "id": user, "role": "admin"}
    def broken_writer(*_, **__):
        raise setup_api.smtp_setup.SMTPSetupError()
    monkeypatch.setattr(setup_api.smtp_setup, "request", broken_writer)
    if failure == "audit":
        def broken_audit(**kwargs):
            # Put the actual transaction in PostgreSQL's aborted state, not a
            # Python-only exception, to exercise rollback-before-unlock.
            kwargs["cursor"].execute("select 1/0")
        monkeypatch.setattr(routes, "record_access_audit_with_cursor", broken_audit)
    routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.status == 503
    with smtp_db() as admin:
        row = admin.execute("select enabled,revision from notification_channels where kind='smtp'").fetchone()
        assert row == {"enabled": False, "revision": revision + (1 if failure == "writer" else 0)}
    with smtp_db("adlog_user") as other:
        assert other.execute("select pg_try_advisory_lock(hashtext('sli_smtp_setup')) as locked").fetchone()["locked"]
        other.execute("select pg_advisory_unlock(hashtext('sli_smtp_setup'))")
        if failure == "writer":
            # An explicit generic enable cannot reuse the reserved generation
            # of a still-running timed-out writer.
            changed = other.execute("""update notification_channels set enabled=true,revision=revision+1
                where kind='smtp' returning revision""").fetchone()["revision"]
            assert changed == revision + 2
