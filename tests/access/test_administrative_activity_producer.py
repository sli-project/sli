from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.sli.access import access_control_v4, auth
from server.sli.sources import administrative_activity_producer as producer


@pytest.mark.parametrize('actor_type,actor_id,actor_key', [
    ('session', 7, 'session:7'), ('anonymous', None, 'system:anonymous'),
])
@pytest.mark.parametrize('outcome,mapped_outcome', [('ok', 'succeeded'), ('failed', 'failed')])
def test_initial_owner_bridge_accepts_success_and_failure(
    monkeypatch, actor_type, actor_id, actor_key, outcome, mapped_outcome,
):
    # Exercise the real allowlist and validator, capturing only the final DB write.
    captured = []
    monkeypatch.setattr(producer, 'load_administrative_activity_contract', lambda: {'runtime_write_enabled': True})

    def append(activity, *, cursor):
        captured.append(activity)
        return {'activity_id': 19}

    monkeypatch.setattr(producer, 'append_administrative_activity_with_cursor', append)
    result = producer.mirror_auth_audit_if_enabled(
        cursor=object(), audit_id=7, created_at=datetime(2026, 10, 30, tzinfo=timezone.utc),
        actor_type=actor_type, actor_id=actor_id, action='initial_owner_claimed',
        outcome=outcome, remote_address='192.0.2.1',
    )
    assert result['journal_written'] is True
    activity = captured[0]
    assert activity.category == 'access_management'
    assert activity.action_key == 'auth.initial_owner.claimed'
    assert (activity.target_kind, activity.target_key) == ('platform_owner', 'platform_owner:primary')
    assert activity.actor_key == actor_key
    assert activity.outcome == mapped_outcome


def test_disabled_auth_bridge_validates_without_journal_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        producer,
        "append_administrative_activity_with_cursor",
        lambda *_args, **_kwargs: pytest.fail("journal write must stay disabled"),
    )
    result = producer.mirror_auth_audit_if_enabled(
        cursor=object(),
        audit_id=7,
        created_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
        actor_type="session",
        actor_id=3,
        action="user_updated:9:username-must-not-be-copied",
        outcome="ok",
        remote_address="127.0.0.1",
    )
    assert result == {
        "status": "disabled",
        "source": "auth_audit",
        "source_row_id": 7,
        "journal_written": False,
    }


def test_enabled_bridge_uses_deterministic_safe_activity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}
    monkeypatch.setattr(
        producer,
        "load_administrative_activity_contract",
        lambda: {"runtime_write_enabled": True},
    )

    def fake_append(activity, *, cursor):
        captured["activity"] = activity
        captured["cursor"] = cursor
        return {"activity_id": 19}

    monkeypatch.setattr(
        producer, "append_administrative_activity_with_cursor", fake_append
    )
    cursor = object()
    first = producer.mirror_auth_audit_if_enabled(
        cursor=cursor,
        audit_id=11,
        created_at=datetime(2026, 8, 2, tzinfo=timezone.utc),
        actor_type="anonymous",
        actor_id=None,
        action="login",
        outcome="throttled",
        remote_address="127.0.0.1",
    )
    assert first["journal_written"] is True
    activity = captured["activity"]
    assert activity.action_key == "auth.login"
    assert activity.outcome == "denied"
    assert activity.actor_key == "system:anonymous"
    assert activity.details == {"legacy_auth_audit_id": 11}
    assert captured["cursor"] is cursor


@pytest.mark.parametrize(
    "updates,error",
    [
        ({"action": "unknown"}, "auth_action_not_allowlisted"),
        ({"outcome": "maybe"}, "auth_outcome_not_allowlisted"),
        ({"actor_type": "unknown"}, "auth_actor_not_allowlisted"),
        ({"action": "user_updated:not-an-id"}, "auth_target_invalid"),
        ({"action": "initial_owner_claimed:7"}, "auth_target_invalid"),
    ],
)
def test_unknown_auth_shapes_fail_closed(updates: dict, error: str) -> None:
    kwargs = {
        "cursor": object(),
        "audit_id": 7,
        "created_at": datetime(2026, 8, 2, tzinfo=timezone.utc),
        "actor_type": "session",
        "actor_id": 3,
        "action": "login",
        "outcome": "ok",
        "remote_address": None,
    }
    kwargs.update(updates)
    with pytest.raises(ValueError, match=error):
        producer.mirror_auth_audit_if_enabled(**kwargs)


def test_existing_auth_audit_and_bridge_share_one_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class Cursor:
        def execute(self, query, params):
            calls.append((query, params))

        def fetchone(self):
            return {
                "id": 23,
                "created_at": datetime(2026, 8, 2, tzinfo=timezone.utc),
            }

    def fake_bridge(**kwargs):
        calls.append(("bridge", kwargs))
        return {"status": "disabled"}

    monkeypatch.setattr(
        producer, "mirror_auth_audit_if_enabled", fake_bridge
    )
    auth._audit(
        Cursor(),
        actor_type="session",
        actor_id=3,
        action="login",
        remote_address="127.0.0.1",
    )
    assert "returning id,created_at" in calls[0][0].lower()
    assert calls[1][0] == "bridge"
    assert calls[1][1]["audit_id"] == 23


def test_disabled_access_bridge_projects_only_safe_scalar_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        producer,
        "append_administrative_activity_with_cursor",
        lambda *_args, **_kwargs: pytest.fail("journal write must stay disabled"),
    )
    result = producer.mirror_access_audit_if_enabled(
        cursor=object(),
        audit_id=31,
        created_at=datetime(2026, 8, 3, tzinfo=timezone.utc),
        actor_type="session",
        actor_id=3,
        action="report_assignment_created",
        subject_type="user",
        subject_id=9,
        target_type="report",
        target_key="privileged.accounts",
        outcome="ok",
        remote_address="127.0.0.1",
    )
    assert result == {
        "status": "disabled",
        "source": "access_audit_v4",
        "source_row_id": 31,
        "journal_written": False,
    }


def test_disabled_access_bridge_accepts_exact_vpn_evidence_grant_from_local_maintenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The narrow audited grant must validate even while journal writes are off."""
    monkeypatch.setattr(
        producer,
        "append_administrative_activity_with_cursor",
        lambda *_args, **_kwargs: pytest.fail("journal write must stay disabled"),
    )

    result = producer.mirror_access_audit_if_enabled(
        cursor=object(),
        audit_id=35,
        created_at=datetime(2026, 9, 11, tzinfo=timezone.utc),
        actor_type="local",
        actor_id=None,
        action="vpn_session_evidence_grant_created",
        subject_type="user",
        subject_id=34,
        target_type="capability",
        target_key="vpn.session.evidence.read",
        outcome="ok",
        remote_address=None,
    )

    assert result == {
        "status": "disabled",
        "source": "access_audit_v4",
        "source_row_id": 35,
        "journal_written": False,
    }


def test_enabled_access_bridge_uses_deterministic_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}
    monkeypatch.setattr(
        producer,
        "load_administrative_activity_contract",
        lambda: {"runtime_write_enabled": True},
    )

    def fake_append(activity, *, cursor):
        captured["activity"] = activity
        captured["cursor"] = cursor
        return {"activity_id": 44}

    monkeypatch.setattr(
        producer, "append_administrative_activity_with_cursor", fake_append
    )
    cursor = object()
    result = producer.mirror_access_audit_if_enabled(
        cursor=cursor,
        audit_id=32,
        created_at=datetime(2026, 8, 3, tzinfo=timezone.utc),
        actor_type="session",
        actor_id=3,
        action="report_published",
        subject_type=None,
        subject_id=None,
        target_type="report",
        target_key="privileged.accounts",
        outcome="ok",
        remote_address="127.0.0.1",
    )
    assert result["journal_written"] is True
    activity = captured["activity"]
    assert activity.category == "report_publication"
    assert activity.action_key == "report.published"
    assert activity.target_key == "report:privileged.accounts"
    assert activity.details == {"legacy_access_audit_id": 32}
    assert captured["cursor"] is cursor


@pytest.mark.parametrize(
    "updates,error",
    [
        ({"action": "report_preference_updated"}, "access_action_not_allowlisted"),
        ({"target_type": "package"}, "access_target_invalid"),
        ({"subject_type": "computer"}, "access_subject_invalid"),
        ({"outcome": "maybe"}, "access_outcome_not_allowlisted"),
    ],
)
def test_unknown_access_shapes_fail_closed(updates: dict, error: str) -> None:
    kwargs = {
        "cursor": object(),
        "audit_id": 31,
        "created_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
        "actor_type": "session",
        "actor_id": 3,
        "action": "report_assignment_created",
        "subject_type": "user",
        "subject_id": 9,
        "target_type": "report",
        "target_key": "privileged.accounts",
        "outcome": "ok",
        "remote_address": None,
    }
    kwargs.update(updates)
    with pytest.raises(ValueError, match=error):
        producer.mirror_access_audit_if_enabled(**kwargs)


def test_existing_access_audit_and_bridge_share_one_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = []

    class Cursor:
        def execute(self, query, params):
            calls.append((query, params))

        def fetchone(self):
            return {
                "id": 33,
                "created_at": datetime(2026, 8, 3, tzinfo=timezone.utc),
            }

    def fake_bridge(**kwargs):
        calls.append(("bridge", kwargs))
        return {"status": "disabled"}

    monkeypatch.setattr(producer, "mirror_access_audit_if_enabled", fake_bridge)
    cursor = Cursor()
    access_control_v4.record_access_audit_with_cursor(
        cursor=cursor,
        actor={"type": "session", "id": 3},
        action="report_published",
        target_type="report",
        target_key="privileged.accounts",
    )
    assert "returning id,created_at" in calls[0][0].lower()
    assert calls[1][0] == "bridge"
    assert calls[1][1]["cursor"] is cursor
    assert calls[1][1]["audit_id"] == 33


class HookAuditCursor:
    def __init__(self):
        self.events = []

    def execute(self, sql, params):
        self.events.append(('execute', sql, params))

    def fetchone(self):
        self.events.append(('fetch',))
        return {'id': 71, 'created_at': datetime(2026, 10, 20, tzinfo=timezone.utc)}


@pytest.mark.parametrize('action', [
    'notification_channel_update', 'notification_schedule_update', 'notification_test_enqueue',
    'notification_subscription_update', 'decoy_label_update', 'watch_entry_update',
    'semantic_suppression_create', 'semantic_suppression_revoke', 'semantic_policy_admission',
])
def test_existing_unsupported_actions_keep_legacy_audit_without_optional_journal(monkeypatch, action):
    cursor = HookAuditCursor()
    monkeypatch.setattr(producer, 'load_administrative_activity_contract',
                        lambda: pytest.fail('unsupported legacy action must not enter optional producer'))
    row = access_control_v4.record_access_audit_with_cursor(
        cursor=cursor, actor={'type': 'session', 'id': 3}, action=action,
        target_type='notification_channel', target_key='telegram',
        details={'kind': 'telegram', 'operation': 'token', 'phase': 'requested'})
    assert row['id'] == 71
    assert len(cursor.events) == 2 and cursor.events[1] == ('fetch',)
    assert 'insert into access_audit_v4' in cursor.events[0][1]
    assert 'returning id,created_at' in cursor.events[0][1]
    assert cursor.events[0][2][2] == action
    assert cursor.events[0][2][9] == '{"kind": "telegram", "operation": "token", "phase": "requested"}'


@pytest.mark.parametrize('failure', ['shape', 'mirror'])
def test_supported_hook_failures_abort_caller_after_mandatory_legacy_row(monkeypatch, failure):
    cursor = HookAuditCursor()
    monkeypatch.setattr(producer, 'load_administrative_activity_contract', lambda: {'runtime_write_enabled': True})
    error = RuntimeError('synthetic mirror failure')
    def fail_append(activity, *, cursor):
        raise error
    monkeypatch.setattr(producer, 'append_administrative_activity_with_cursor', fail_append)
    events = []
    class CallerTransaction:
        def __enter__(self):
            return self
        def __exit__(self, kind, value, traceback):
            events.append('rollback' if kind else 'commit')
    with pytest.raises(ValueError if failure == 'shape' else RuntimeError) as actual, CallerTransaction():
        access_control_v4.record_access_audit_with_cursor(
            cursor=cursor, actor={'type': 'session', 'id': 3}, action=' report_published ',
            target_type='wrong' if failure == 'shape' else 'report', target_key='synthetic-report')
    assert events == ['rollback'] and cursor.events[1] == ('fetch',)
    if failure == 'shape':
        assert str(actual.value) == 'administrative_activity_access_target_invalid'
    else:
        assert actual.value is error
