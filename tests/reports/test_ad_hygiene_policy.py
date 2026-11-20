"""Account hygiene uses platform settings and synthetic facts, without a database."""
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.core import platform_settings
from server.sli.reporting import reporting_v4, reporting_v4_query
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports import users
from server.sli.reports import ad_hygiene_policy as policy
from server.sli.reports import users_reporting, users_v2_views

AT = datetime(2026, 10, 1, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def settings(monkeypatch):
    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [])
    yield
    platform_settings.clear_cache()


def _stored(monkeypatch, password=120, inactivity=100):
    values = {"ad.password_max_age_days": password, "ad.inactivity_days": inactivity}
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda _sql, params: [{"value": str(values[params[0]])}])


def test_absent_settings_use_accepted_defaults():
    assert policy.thresholds() == {"password_age": 365, "inactivity": 90}


@pytest.mark.parametrize("enabled,extra_seconds,expected", [
    (True, 0, set()), (True, 1, {"password_age", "inactive_threshold"}), (False, 1, {"password_age"}),
])
def test_owner_default_reasons_require_strict_age_and_enabled_inactivity(enabled, extra_seconds, expected):
    row = users_v2_views.user_row({"enabled": enabled,
        "passwordLastSet": AT - timedelta(days=365, seconds=extra_seconds),
        "lastLogonTimestamp": AT - timedelta(days=90, seconds=extra_seconds)}, AT)
    assert set(row["reason_keys"]) & {"password_age", "inactive_threshold"} == expected


@pytest.mark.parametrize("days", [90, 365])
def test_strict_boundary_includes_fractional_days(days):
    assert policy.evaluate(AT - timedelta(days=days), AT, days)["status"] == "within_policy"
    assert policy.evaluate(AT - timedelta(days=days, seconds=1), AT, days)["status"] == "exceeded"


@pytest.mark.parametrize("fact,observed,state,reason", [
    (None, AT, None, "fact_missing_or_invalid"),
    ("invalid", AT, None, "fact_missing_or_invalid"),
    ("2026-01-01T00:00:00", AT, None, "fact_missing_or_invalid"),
    (AT, None, None, "observation_time_missing_or_invalid"),
    (AT + timedelta(seconds=1), AT, None, "fact_after_observation"),
    (AT, AT, "partial", "source_untrustworthy"),
    (AT, AT, "failed", "source_untrustworthy"),
])
def test_untrustworthy_facts_are_unknown_with_a_reason(fact, observed, state, reason):
    evaluation = policy.evaluate(fact, observed, 60, source_state=state)
    assert evaluation["status"] == "unknown"
    assert evaluation["reason"] == reason


def test_both_user_readers_use_stored_policy(monkeypatch):
    _stored(monkeypatch)
    fact = (AT - timedelta(days=95)).isoformat()
    user = {"passwordLastSet": fact, "lastLogonTimestamp": fact, "enabled": True}
    row = users_v2_views.user_row(user, AT)
    assert row["password_age_policy"] == row["inactivity_policy"] == "within_policy"
    assert not {"password_age", "inactive_threshold"} & set(row["reason_keys"])
    old = users_reporting.evaluate_account_risks(
        {"password_last_set_utc": fact, "last_logon_utc": fact}, observed_at_utc=AT, direct_privilege_count=0,
    )
    for key, days in (("password_older_than_90_days", 120), ("inactive_over_60_days", 100)):
        risk = next(item for item in old if item["risk_key"] == key)
        assert risk["qualification"] == "not_matched"
        assert risk["evidence"]["threshold_days"] == days
        assert str(days) in risk["expected_condition"]


def test_missing_facts_are_visible_and_not_compliant():
    row = users_v2_views.user_row({"enabled": True}, AT)
    assert row["password_age_policy"] == row["inactivity_policy"] == "unknown"
    unknown_keys = {"password_age_unknown", "enabled_activity_unknown"}
    assert unknown_keys <= set(row["information_keys"])
    assert unknown_keys <= {item["key"] for item in row["information_limitations"]}
    assert unknown_keys.isdisjoint(row["reason_keys"])
    assert unknown_keys.isdisjoint(reason["key"] for reason in row["reasons"])
    assert all(value["status"] == "unknown" and value["reason"] for value in row["hygiene"].values())
    risks = users_reporting.evaluate_account_risks({}, observed_at_utc=AT, direct_privilege_count=0)
    assert all(risk["qualification"] == "not_evaluated" for risk in risks if risk["risk_key"] in {"password_older_than_90_days", "inactive_over_60_days"})


def test_partial_directory_and_future_facts_never_become_policy_failures():
    for user in (
        {"passwordLastSet": AT, "lastLogonTimestamp": AT, "sourceStates": {"directory": {"status": "partial"}}},
        {"passwordLastSet": AT + timedelta(days=1), "lastLogonTimestamp": AT + timedelta(days=1)},
    ):
        evaluations = policy.for_user(user, AT, policy.thresholds())
        assert all(value["status"] == "unknown" for value in evaluations.values())


def test_exact_logon_does_not_replace_the_policy_fact():
    user = {"exactLastLogon": AT, "sourceStates": {"exact_last_logon": {"status": "observed"}}}
    assert policy.for_user(user, AT, policy.thresholds())["inactivity"]["status"] == "unknown"


def test_account_observation_time_is_used_instead_of_newer_snapshot_time():
    user = {"passwordLastSet": AT, "lastLogonTimestamp": AT,
            "sourceStates": {"directory": {"status": "observed", "observed_at": (AT - timedelta(days=1)).isoformat()}}}
    values = policy.for_user(user, AT, policy.thresholds())
    assert all(value["status"] == "unknown" and value["reason"] == "fact_after_observation" for value in values.values())


def test_old_partial_domain_keeps_unknown_and_its_date_beside_a_new_publication():
    observed = "2026-09-15T00:00:00Z"
    user = {"enabled": True, "passwordLastSet": observed, "lastLogonTimestamp": observed,
            "sourceStates": {"directory": {"status": "partial", "observed_at": observed}}}
    row = users_v2_views.user_row(user, "2026-10-16T00:00:00Z")
    assert row["password_age_policy"] == row["inactivity_policy"] == "unknown"
    assert not {"password_age", "inactive_threshold"} & set(row["reason_keys"])
    assert all(value["reason"] == "source_untrustworthy" for value in row["hygiene"].values())
    assert all(value["observed_at"] == "2026-09-15T00:00:00+00:00" for value in row["hygiene"].values())


@pytest.mark.parametrize("fact", ["invalid", "2026-01-01T00:00:00", AT + timedelta(seconds=1)])
def test_legacy_reader_does_not_pass_untrustworthy_dates(fact):
    risks = users_reporting.evaluate_account_risks(
        {"password_last_set_utc": fact, "last_logon_utc": fact}, observed_at_utc=AT, direct_privilege_count=0,
    )
    assert all(risk["qualification"] == "not_evaluated" and risk["reason"] for risk in risks
               if risk["risk_key"] in {"password_older_than_90_days", "inactive_over_60_days"})


def test_policy_is_reapplied_to_saved_snapshot_and_request_cannot_override_it(monkeypatch):
    _stored(monkeypatch, password=10, inactivity=20)
    snapshot = {"metadata": {"observed_at": AT.isoformat()}, "users": [
        {"id": "user:1", "enabled": True, "passwordLastSet": (AT - timedelta(days=11)).isoformat(),
         "lastLogonTimestamp": (AT - timedelta(days=21)).isoformat()},
    ]}
    monkeypatch.setattr(users, "_snapshots", lambda *_a, **_k: {"current": snapshot, "state": "available"})
    context = QueryContext(access={}, params={"view": "all", "threshold": 365}, domain_ids=[1],
                           action="view", cursor=None, limit=100, timezone="UTC", tab="users")
    data = users._prepare(context)
    assert {"password_age", "inactive_threshold"} <= set(data["selected"][0]["reason_keys"])
    assert "threshold" not in {param.key for param in users.REPORT.params}


def test_vpn_predicates_and_summary_use_current_policy_not_collector_flag(monkeypatch):
    _stored(monkeypatch, inactivity=45)
    clauses, params = reporting_v4_query._compile_interactive_report_query("ad.accounts.vpn", {"activity_state": "inactive"})
    assert params == ["inactive"]
    assert "interval '45 days'" in clauses[0] and "is_inactive" not in clauses[0]
    assert "pg_input_is_valid" in clauses[0] and "then 'unknown'" in clauses[0]
    sqls = []
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda sql, *_a, **_k: sqls.append(sql) or [{"unknown_activity_users": 2}])
    monkeypatch.setattr(reporting_v4, "_context_section_coverage", lambda *_a: {})
    summary = reporting_v4._vpn_account_summary("", [], {"security"})
    assert summary["inactive_threshold_days"] == 45
    assert summary["unknown_activity_users"] == 2
    assert "interval '45 days'" in sqls[0] and "is_inactive" not in sqls[0]


@pytest.mark.parametrize("reader", [reporting_v4._ad_snapshot_summary, reporting_v4._privileged_account_summary])
def test_other_ad_user_aggregates_recompute_inactivity(monkeypatch, reader):
    _stored(monkeypatch, inactivity=45)
    sqls = []
    monkeypatch.setattr(reporting_v4, "query_rows_bounded", lambda sql, *_a, **_k: sqls.append(sql) or [{}])
    monkeypatch.setattr(reporting_v4, "_context_section_coverage", lambda *_a: {})
    reader("", [], {"security"})
    assert any("interval '45 days'" in sql for sql in sqls)
