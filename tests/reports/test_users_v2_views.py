"""Server-side port of the Users V2 reference rules (reasons, quality, changes)."""

from __future__ import annotations

import pytest

from server.sli.core import platform_settings
from server.sli.reports import users_v2_views as views

@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    monkeypatch.setattr(platform_settings, "_stored_row", lambda _key: None)


OBSERVED = "2026-09-15T00:00:00Z"


def _user(**overrides):
    user = {
        "id": "user:1", "entityId": 1, "objectGuid": "g1", "displayName": "Иванов", "samAccountName": "ivanov",
        "userPrincipalName": "ivanov@example.test", "enabled": True, "lockedOut": False,
        "passwordLastSet": "2026-09-10T00:00:00Z", "lastLogonTimestamp": "2026-09-10T00:00:00Z", "sourceStates": {"exact_last_logon": {"status": "observed"}},
        "memberships": {"status": "observed", "direct": [], "effective": [], "unresolved": []},
    }
    user.update(overrides)
    return user


def _keys(user):
    return [reason["key"] for reason in views.build_reasons(user, OBSERVED)]


def test_healthy_recent_user_has_no_reasons():
    assert _keys(_user()) == []


def test_reasons_are_ordered_like_the_reference():
    user = _user(lockedOut=True, accountExpirationDate="2026-01-01T00:00:00Z", passwordExpired=True, trustedForDelegation=True,
                 userPrincipalName=None, memberships={"status": "partial", "direct": [], "effective": [{"id": "g", "name": "Domain Admins", "watchGroup": True}], "unresolved": ["CN=x"]})
    assert _keys(user) == ["locked_out", "account_expired", "password_expired", "sensitive_uac_flag", "watch_group_membership"]
    assert views.user_row(user, OBSERVED)["information_keys"] == ["identity_key_missing", "group_graph_partial"]


def test_inactivity_uses_the_platform_threshold_and_only_enabled_accounts(monkeypatch):
    old = _user(lastLogonTimestamp="2026-06-01T00:00:00Z", sourceStates={})
    assert "inactive_threshold" in _keys(old)
    assert "inactive_threshold" not in _keys({**old, "enabled": False})
    reason = next(item for item in views.build_reasons(old, OBSERVED) if item["key"] == "inactive_threshold")
    assert "приблизительный реплицируемый атрибут" in reason["limitation"]
    monkeypatch.setattr(platform_settings, "_stored_row", lambda key: {"value": "180"} if key == "ad.inactivity_days" else None)
    assert "inactive_threshold" not in _keys(old)


def test_unknown_activity_is_information_not_a_verdict():
    user = _user(lastLogonTimestamp=None, exactLastLogon=None, sourceStates={})
    assert _keys(user) == []
    row = views.user_row(user, OBSERVED)
    assert row["reason_text"] is None and row["reason_keys"] == []
    assert row["information_keys"] == ["enabled_activity_unknown"]
    assert row["inactivity_policy"] == "unknown"
    assert "не доказательство отсутствия входов" in row["information_limitations"][0]["limitation"]
    assert row["review_details"][0]["category"] == "information"


def test_partial_exact_logon_uses_the_newest_candidate():
    user = _user(exactLastLogon="2026-09-12T00:00:00Z", lastLogonTimestamp="2026-09-01T00:00:00Z", sourceStates={"exact_last_logon": {"status": "partial"}})
    activity = views.best_activity(user)
    assert activity["status"] == "partial" and activity["value"].startswith("2026-09-12")


def test_quality_ignores_optional_manager_absence():
    user = _user(sourceStates={"manager_resolution": {"status": "no_record"}, "exact_last_logon": {"status": "failed", "detail": "DC2 недоступен"}})
    assert views.quality_issues(user) == [{"status": "failed", "kind": "Источник", "field": "exact_last_logon", "detail": "DC2 недоступен"}]


def test_compare_reports_lifecycle_state_and_group_changes():
    before = {"users": [
        _user(), _user(id="user:2", objectGuid="g2", displayName="Петров"),
    ]}
    after = {"users": [
        _user(lockedOut=True, memberships={"status": "observed", "direct": [{"id": "g:7", "name": "VPN"}], "effective": [{"id": "g:7", "name": "VPN"}], "unresolved": []}),
        _user(id="user:3", objectGuid="g3", displayName="Сидоров"),
    ]}
    rows = views.compare(after, before)
    kinds = sorted(row["type"] for row in rows)
    assert kinds == ["direct_group_added", "effective_group_added", "locked_changed", "missing_current", "new_object"]
    missing = next(row for row in rows if row["type"] == "missing_current")
    assert "Причина не установлена" in missing["note"]
    assert views.compare(after, None) == []
