"""SMTP setup keeps the existing admin/session/CSRF and recipient boundary."""
from unittest.mock import Mock

import pytest

from server.api import smtp_setup as api
from server.api.routes import notification_channels as routes
from tests.unit.test_notification_channels import Handler, access


def payload(**changes):
    return {"host": "smtp.example.invalid", "port": 587, "username": "fixture", "password": "synthetic-password",
            "sender": "from@example.invalid", "recipients": [{"user_id": 1, "mailbox": "to@example.invalid"}],
            "tls_mode": "starttls", "enabled": True, "revision": 1, **changes}


@pytest.mark.parametrize("decision", [access(role="viewer"), access(scope={"kind": "domain", "ids": [1]}), access(actions=("view",))])
def test_smtp_denied_before_body_database_or_writer(monkeypatch, decision):
    never = Mock(side_effect=AssertionError("unexpected I/O"))
    monkeypatch.setattr(api, "connect", never)
    monkeypatch.setattr(api.smtp_setup, "request", never)
    handler = Handler(decision, payload=payload())
    routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.status == 403 and handler.reads == 0


def test_smtp_csrf_and_session_required(monkeypatch):
    never = Mock(side_effect=AssertionError("unexpected I/O"))
    monkeypatch.setattr(api, "connect", never)
    monkeypatch.setattr(api.smtp_setup, "request", never)
    handler = Handler(mutation=False)
    routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.reads == 0
    handler = Handler(payload=payload())
    handler._principal = {"type": "api_key", "id": 1}
    routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.status == 403 and handler.reads == 0


@pytest.mark.parametrize("change", [{"user_id": 2}, {"tls_mode": "plain"}, {"port": True},
    {"recipients": [{"user_id": 2, "mailbox": "foreign@example.invalid"}]},
    {"recipients": [{"user_id": 1, "mailbox": "to@example.invalid"}, {"user_id": 1, "mailbox": "other@example.invalid"}]}])
def test_smtp_rejects_unbound_recipient_and_unknown_fields_before_write(monkeypatch, change):
    monkeypatch.setattr(api.outbox, "list_subscriptions", lambda _: [])
    never = Mock(side_effect=AssertionError("unexpected write"))
    monkeypatch.setattr(api, "connect", never)
    monkeypatch.setattr(api.smtp_setup, "request", never)
    handler = Handler(payload=payload(**change))
    routes.try_handle_post(handler, routes.PREFIX + "/smtp/setup/save")
    assert handler.status == 400
    assert "synthetic-password" not in str(handler.response)


class FenceConnection:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.events = []

    def __enter__(self):
        return self

    def __exit__(self, kind, *_):
        self.events.append("rollback" if kind else "exit")

    def cursor(self):
        return self

    def execute(self, sql, values=()):
        self.events.append((sql, values))

    def fetchone(self):
        return next(self.rows)

    def commit(self):
        self.events.append("commit")

    def rollback(self):
        self.events.append("rollback")


@pytest.fixture
def fenced(monkeypatch):
    conn = FenceConnection([{"locked": True}, {"revision": 2}, {"revision": 2, "enabled": False}, {"revision": 2}])
    monkeypatch.setattr(api, "connect", lambda: conn)
    monkeypatch.setattr(api.outbox, "list_subscriptions", lambda _: [{"id": "fixture", "recipient_user_id": 1,
        "owner_user_id": 1, "channel": "smtp", "enabled": True}])
    monkeypatch.setattr(api.outbox, "require_recipient", lambda _: None)
    return conn


def test_save_commits_disable_then_fences_writer_and_redacts_audit(monkeypatch, fenced):
    audit = Mock()
    def write(action, user, **values):
        assert action == "save" and user == 1 and values["password"] == "synthetic-password"
        assert values["revision"] == 2 and values["previous_revision"] == 1
        assert "commit" in fenced.events
        assert any(isinstance(event, tuple) and "for update" in event[0] for event in fenced.events)
        return {"secret_set": True, "needs_save": False}
    monkeypatch.setattr(api.smtp_setup, "request", write)
    result = api.configure(Handler(payload=payload()), "save", audit)
    assert result == {"secret_set": True, "needs_save": False, "revision": 2}
    assert fenced.events.count("commit") == 2
    assert "synthetic-password" not in str(result) + str(audit.call_args_list) + str(fenced.events)
    assert any(isinstance(event, tuple) and "pg_advisory_unlock(" in event[0] for event in fenced.events)


def test_audit_failure_prevents_writer_and_disable_commit(monkeypatch, fenced):
    monkeypatch.setattr(api.smtp_setup, "request", Mock(side_effect=AssertionError("writer reached")))
    with pytest.raises(RuntimeError):
        api.configure(Handler(payload=payload()), "save", Mock(side_effect=RuntimeError("synthetic")))
    assert "commit" not in fenced.events
    assert any(isinstance(event, tuple) and "pg_advisory_unlock(" in event[0] for event in fenced.events)


def test_concurrent_metadata_edit_prevents_file_write(monkeypatch, fenced):
    fenced.rows = iter([{"locked": True}, {"revision": 2}, {"revision": 3, "enabled": True}])
    monkeypatch.setattr(api.smtp_setup, "request", Mock(side_effect=AssertionError("writer reached")))
    with pytest.raises(api.smtp_setup.SMTPSetupError, match="smtp_setup_conflict"):
        api.configure(Handler(payload=payload()), "save", Mock())
    assert fenced.events.count("commit") == 1


def test_writer_failure_never_reenables_channel(monkeypatch, fenced):
    monkeypatch.setattr(api.smtp_setup, "request", Mock(side_effect=api.smtp_setup.SMTPSetupError()))
    with pytest.raises(api.smtp_setup.SMTPSetupError):
        api.configure(Handler(payload=payload()), "save", Mock())
    assert fenced.events.count("commit") == 1
    assert not any(isinstance(event, tuple) and "set enabled=%s" in event[0] for event in fenced.events)
    assert any(isinstance(event, tuple) and "pg_advisory_unlock(" in event[0] for event in fenced.events)


def test_status_excludes_unbound_destinations_and_never_returns_secret(monkeypatch):
    monkeypatch.setattr(api.outbox, "list_subscriptions", lambda _: [])
    conn = FenceConnection([{"locked": True}, {"revision": 7, "tls_mode": "tls", "enabled": True}])
    monkeypatch.setattr(api, "connect", lambda: conn)
    monkeypatch.setattr(api.smtp_setup, "request", lambda *args, **kwargs: {"host": "smtp.example.invalid", "port": 465,
        "username": "fixture", "sender": "from@example.invalid", "recipients": {"1": "to@example.invalid", "2": "hidden@example.invalid"},
        "secret_set": True, "needs_save": False})
    result = api.configure(Handler(payload={}), "status", Mock())
    assert result["recipients"] == [{"user_id": 1, "mailbox": "to@example.invalid"}]
    assert result["self_user_id"] == 1 and "password" not in result and "hidden" not in str(result)


def test_status_captures_writer_values_while_revision_share_lock_is_held(monkeypatch):
    conn = FenceConnection([{"locked": True}, {"revision": 7, "tls_mode": "tls", "enabled": True}])
    monkeypatch.setattr(api, "connect", lambda: conn)
    monkeypatch.setattr(api.outbox, "list_subscriptions", lambda _: [])
    def status(*args, **kwargs):
        assert "pg_try_advisory_lock_shared" in conn.events[0][0]
        assert "for share" in conn.events[1][0]
        assert "exit" not in conn.events and kwargs == {"revision": 7}
        return {"host": "old.example.invalid", "port": 465, "username": "fixture", "sender": "from@example.invalid",
                "recipients": {"1": "to@example.invalid"}, "secret_set": True, "needs_save": False}
    monkeypatch.setattr(api.smtp_setup, "request", status)
    result = api.configure(Handler(payload={}), "status", Mock())
    assert result["host"] == "old.example.invalid" and result["revision"] == 7
    assert "exit" in conn.events


def test_reserved_save_blocks_status_before_reading_files(monkeypatch):
    conn = FenceConnection([{"locked": False}])
    monkeypatch.setattr(api, "connect", lambda: conn)
    monkeypatch.setattr(api.outbox, "list_subscriptions", lambda _: [])
    monkeypatch.setattr(api.smtp_setup, "request", Mock(side_effect=AssertionError("writer reached")))
    with pytest.raises(api.smtp_setup.SMTPSetupError, match="smtp_setup_conflict"):
        api.configure(Handler(payload={}), "status", Mock())
    assert not any(isinstance(event, tuple) and "pg_advisory_unlock" in event[0] for event in conn.events)
