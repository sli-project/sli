"""Semantic review hints and explicit, audited controls; no runtime database."""
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.semantic import semantic_governance as control

NOW = datetime(2026, 10, 6, tzinfo=timezone.utc)


@pytest.mark.parametrize("facts,bucket", [
    ({}, "unknown"),
    ({"subject_sid": "S-1-5-18"}, "system_account"),
    ({"subject_sid": "S-1-5-21-1-2-3-1001", "machine_account": True}, "machine_account"),
    ({"machine_account": True, "gpo_correlated": True}, "known_gpo_refresh"),
    ({"logon_type": "10", "privileged_session": True}, "interactive_admin"),
    ({"logon_type": "10"}, "unknown"),
    ({"process_name": "gpupdate.exe"}, "unknown"),
    ({"gpo_correlated": True, "process_name": "gpupdate.exe"}, "known_gpo_refresh"),
    ({"gpo_correlated": True, "process_name": "auditpol.exe"}, "unknown"),
    ({"subject_sid": "S-1-5-18", "mixed": True}, "unknown"),
    ({"subject_sid": "S-1-5-18", "has_audit_change": False}, "unknown"),
])
def test_classification_is_a_hint(facts, bucket):
    assert control.classify_audit_change(facts) == {"bucket": bucket, "kind": "hint", "verdict": False}


def rule(**updates):
    return {"semantic_type": "semantic.audit.policy.changed", "domain_id": 1,
            "scope_kind": "subject_sid", "scope_value": "S-1-5-21-1-2-3-1001",
            "reason": "Approved maintenance", "expires_at": (NOW + timedelta(days=1)).isoformat(), **updates}


@pytest.mark.parametrize("updates", [
    {"reason": " "}, {"domain_id": 0}, {"scope_value": "*"},
    {"semantic_type": "*"}, {"scope_kind": "all"},
    {"scope_kind": "bucket", "scope_value": "anything"},
    {"expires_at": NOW.isoformat()},
    {"expires_at": (NOW + timedelta(days=90, seconds=1)).isoformat()},
    {"expires_at": "2026-10-07T00:00:00"},
])
def test_suppression_requires_exact_scope_reason_and_bounded_expiry(updates):
    with pytest.raises(ValueError):
        control.validate_suppression(rule(**updates), now=NOW)


def test_maximum_expiry_and_bucket_are_allowed():
    value = control.validate_suppression(rule(scope_kind="bucket", scope_value="machine_account",
        expires_at=(NOW + timedelta(days=90)).isoformat()), now=NOW)
    assert value["scope_value"] == "machine_account"


class Cursor:
    def __init__(self, rows=()):
        self.rows = iter(rows)
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((sql, params))

    def fetchone(self):
        return next(self.rows, None)


def test_create_audits_with_same_cursor():
    cur = Cursor([{"id": 1}])
    events = []
    result = control.create_suppression(cur, rule(), actor="test-owner", now=NOW,
        audit=lambda cursor, action, target, details: events.append((cursor, action, target)))
    assert result == {"id": 1}
    assert events == [(cur, "semantic_suppression_create", "1")]


def test_revoke_audits_once_and_does_not_revoke_expired_rule():
    cur = Cursor([{"id": 1}])
    events = []
    control.revoke_suppression(cur, 1, actor=" test-owner ", reason=" Test revocation ", audit=lambda *args: events.append(args))
    assert events[0][1] == "semantic_suppression_revoke"
    assert events[0][3] == {"actor": "test-owner", "reason": "Test revocation"}
    assert "kind='suppression'" in cur.calls[-1][0]
    assert "state='active'" in cur.calls[-1][0]
    assert "expires_at > clock_timestamp()" in cur.calls[-1][0]
    assert cur.calls[-1][1] == ("test-owner", 1)
    with pytest.raises(LookupError):
        control.revoke_suppression(Cursor(), 1, actor="test-owner", reason="Test revocation", audit=lambda *args: pytest.fail("no audit"))


def test_governance_list_keeps_finding_risk_decisions_separate():
    class ListCursor(Cursor):
        def fetchall(self):
            return []
    cur = ListCursor()
    control.list_controls(cur)
    assert "kind='suppression'" in cur.calls[1][0]


def policy_rows(policy_id, version, state):
    # The policy writer now snapshots identity before acquiring its row lock.
    value = dict(policy_id=policy_id, policy_version=version, source_kind='canonical_action',
                 definition_json={}, definition_sha256=b'fixture', lifecycle_status=state)
    return [dict(value), dict(value)]


@pytest.mark.parametrize("state", ["draft", "validated", "test", "disabled", "deprecated"])
def test_admission_does_not_bypass_policy_readiness(state):
    with pytest.raises(ValueError):
        control.set_policy_admission(Cursor(policy_rows("test-policy", 1, state)),
            "test-policy", 1, True, actor="test-owner", reason="Test admission", audit=lambda *args: None)


def test_admission_is_versioned_and_audited():
    cur = Cursor(policy_rows("test-policy", 2, "shadow"))
    events = []
    control.set_policy_admission(cur, "test-policy", 2, True, actor="test-owner", reason="Test admission",
        audit=lambda *args: events.append(args))
    assert cur.calls[-1][1] == ("test-policy", 2, True, "test-owner")
    assert events[0][1:3] == ("semantic_policy_admission", "test-policy:2")
    assert events[0][3] == {"enabled": True, "actor": "test-owner", "reason": "Test admission"}


@pytest.mark.parametrize("operation", ["admission", "revocation"])
def test_human_control_decision_requires_reason_before_any_write(operation):
    cur = Cursor()
    with pytest.raises(ValueError, match="reason_required"):
        if operation == "admission":
            control.set_policy_admission(cur, "test-policy", 1, True, actor="test-owner", audit=lambda *args: None)
        else:
            control.revoke_suppression(cur, 1, actor="test-owner", audit=lambda *args: None)
    assert cur.calls == []


def test_owner_gate_rejects_admin_without_owner(monkeypatch):
    from server.api.routes import settings

    class Handler:
        def _authorize_mutation(self, **kwargs):
            return True

        def _access_decision(self):
            return {"platform_owner": False}

        def _send_json(self, body, status):
            assert status == 403
            assert body["error"] == "platform_owner_required"

    assert settings.try_handle_post(Handler(), "/api/v1/platform-settings/semantic-control")


def test_managed_policies_replace_the_all_or_nothing_production_guard(monkeypatch):
    from server.sli.semantic import semantic_production_runtime as runtime
    from tests.semantic.test_semantic_continuous_production import (
        _Connection,
        _enabled_settings,
        _findings_guard,
    )

    monkeypatch.setenv("ADLOG_SEMANTIC_PRODUCTION_ENABLED", "1")
    monkeypatch.setattr(runtime.SemanticFeatureSettings, "from_env", classmethod(lambda cls: _enabled_settings()))
    conn = _Connection(_findings_guard(enabled_policies=["l1-audit-policy-changed:2", "test-policy:3"],
        unmanaged_enabled_policies=["l1-audit-policy-changed:2"], admission_configured=True))
    assert runtime.prepare_production_connection(conn) == _enabled_settings()
    empty = _Connection(_findings_guard(enabled_policies=[], unmanaged_enabled_policies=[], admission_configured=True))
    assert runtime.prepare_production_connection(empty) == _enabled_settings()
    with pytest.raises(RuntimeError, match="enabled policy set differs"):
        runtime.prepare_production_connection(_Connection(_findings_guard(enabled_policies=[])))


def test_runtime_queries_apply_admission_before_claiming_and_enqueueing():
    from server.sli.semantic import semantic_risk_runtime_repository as runtime

    class RuntimeCursor(Cursor):
        def fetchall(self):
            return []

    cur = RuntimeCursor([{"source_id": "test-action", "selector_value": "audit.policy.changed"}])
    runtime.enqueue_canonical_action_risk_jobs(cur, canonical_action_id="test-action")
    assert "semantic_policy_mode_v160" in cur.calls[-1][0]
    runtime.claim_risk_evaluation_jobs(cur)
    assert "semantic_policy_mode_v160" in cur.calls[-1][0]


def test_suppression_filter_applies_to_population_and_summary(monkeypatch):
    from server.sli.semantic import findings

    monkeypatch.setattr(findings, "is_postgres_runtime_db", lambda: True)
    monkeypatch.setattr(findings, "resolve_storage_route", lambda **kwargs: {"route": "v2"})
    monkeypatch.setattr(findings, "_attach_postgres_finding_details", lambda *args, **kwargs: None)
    monkeypatch.setattr(findings, "get_findings_refresh_status", lambda **kwargs: {})
    calls = []
    monkeypatch.setattr(findings, "query_rows", lambda sql, *args, **kwargs: calls.append(sql) or [])
    findings.get_security_problems_data()
    queries = [sql for sql in calls if "from findings_active" in sql]
    assert len(queries) == 2
    assert all("not semantic_finding_suppressed_v160" in sql for sql in queries)
    calls.clear()
    findings.get_security_problems_data(show_suppressed=True)
    assert all("not semantic_finding_suppressed_v160" not in sql for sql in calls)


def test_publication_rechecks_admission_under_policy_lock():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding

    cur = Cursor()
    with pytest.raises(RuntimeError, match="observed enabled result"):
        publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert "semantic_policy_mode_v160" in cur.calls[0][0]
    assert "for share of policy" in cur.calls[0][0]


def test_worker_heartbeat_does_not_claim_a_hardcoded_policy_is_enabled():
    from scripts.runtime import semantic_production_worker as worker

    initial = worker._details(limit=1, runtime_mode="findings-v1")
    assert "enabled_policy" not in initial
    details = worker._details(limit=1, runtime_mode="findings-v1",
        result={"enabled_policies": ["test-policy:2", "test-policy:3"]})
    assert details["enabled_policies"] == ["test-policy:2", "test-policy:3"]


def test_queue_presents_hint_without_changing_lifecycle():
    from server.sli.reporting.v2.reports import security_problems

    hint = {"bucket": "machine_account", "kind": "hint", "verdict": False,
            "event_db_id": 900001, "unknown_field": "fixture-marker"}
    row = security_problems._row({"id": 1, "status": "confirmed", "review_hint": hint, "suppressed": True}, {})
    assert row["review_hint_text"] == "Учётная запись компьютера"
    assert row["status"] == "confirmed"
    # Only the public classification is projected; source metadata stays private.
    assert row["review_hint"] == {"bucket": "machine_account"}
    assert hint == {"bucket": "machine_account", "kind": "hint", "verdict": False,
                    "event_db_id": 900001, "unknown_field": "fixture-marker"}
    assert row["suppressed"] is True


def test_policy_list_projects_title_and_registration_date_only():
    class ListCursor(Cursor):
        def fetchall(self):
            return []
    cur = ListCursor()
    control.list_controls(cur)
    policy_sql = cur.calls[0][0]
    assert "definition_json->>'title' as title" in policy_sql
    assert "created_at::text as version_created_at" in policy_sql
    assert "updated_at" not in policy_sql
    assert "definition_sha256" not in policy_sql
