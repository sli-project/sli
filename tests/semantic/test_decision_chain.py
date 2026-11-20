"""Decision authority guards use only cursors and in-memory PostgreSQL fakes."""
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from server.sli.semantic import findings
from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
from tests.semantic.test_pg_product2_runtime_parity_lifecycle import _FakeFindingsPg


class PublicationCursor:
    def __init__(self, *, admitted=True, contributions=None):
        self.admitted = admitted
        self.contributions = contributions if contributions is not None else [{
            "admitted": True, "lifecycle_status": "shadow",
            "policy_sha256": b"a" * 32, "definition_sha256": b"a" * 32,
        }]
        self.calls = []
        self.rows = []

    def execute(self, sql, params=()):
        sql = " ".join(sql.split()).lower()
        self.calls.append((sql, params))
        self.rows = []
        if "from semantic_risk_evaluation_results" in sql:
            assert "join semantic_policy_admission" in sql
            assert "admission.enabled is true" in sql
            assert "for share of policy" in sql
            assert "for share of policy,admission" not in sql
            self.rows = [{"evaluation_mode": "enabled", "conclusion_state": "observed",
                          "scenario_id": "test-scenario", "policy_admitted": self.admitted}]
        elif "from semantic_risk_contributions" in sql:
            assert "for share of policy" in sql
            self.rows = self.contributions
        elif "from semantic_security_scenarios" in sql:
            self.rows = [{"scenario_key": b"test", "identity_key": b"test", "strict_keys_json": {},
                          "scenario_kind": "test.kind", "title": "Test observation",
                          "risk_class": "high", "confidence_score": 80,
                          "explanation": "Deterministic policy qualification",
                          "first_seen_utc": datetime(2026, 10, 7, tzinfo=timezone.utc),
                          "last_seen_utc": datetime(2026, 10, 7, tzinfo=timezone.utc)}]
        elif "insert into findings(" in sql:
            self.rows = [{"id": 1}]
        elif "select id,rule_code from findings" in sql:
            self.rows = [{"id": 1, "rule_code": "semantic.test.kind"}]
        elif "insert into finding_evidence" in sql:
            self.rows = [{"event_id": 1}]
        elif "select count(*)" in sql:
            self.rows = [{"count": 1, "max_event_id": 1}]
        elif "select finding_id,finding_fingerprint" in sql:
            self.rows = [{"finding_id": 1, "finding_fingerprint": "semantic:74657374"}]

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return list(self.rows)


@pytest.mark.parametrize("admitted", [None, False])
def test_enabled_lifecycle_without_explicit_admission_cannot_publish(admitted):
    cur = PublicationCursor(admitted=admitted)
    with pytest.raises(RuntimeError, match="observed enabled result"):
        publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert len(cur.calls) == 1


@pytest.mark.parametrize("overrides", [
    {"admitted": None}, {"admitted": False}, {"lifecycle_status": "test"},
    {"lifecycle_status": "disabled"}, {"policy_sha256": b"b" * 32},
])
def test_unadmitted_or_changed_contribution_cannot_supply_finding_risk(overrides):
    cur = PublicationCursor()
    cur.contributions.append({**cur.contributions[0], **overrides})
    with pytest.raises(RuntimeError, match="admitted policy contributions"):
        publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert not any("insert into findings" in sql for sql, _ in cur.calls)


def test_missing_contributions_cannot_supply_finding_risk():
    with pytest.raises(RuntimeError, match="admitted policy contributions"):
        publish_enabled_scenario_finding(PublicationCursor(contributions=[]),
                                        job_id="test-job", scenario_id="test-scenario")


def test_admitted_deterministic_policy_can_publish_with_exact_evidence():
    cur = PublicationCursor()
    result = publish_enabled_scenario_finding(cur, job_id="test-job", scenario_id="test-scenario")
    assert result["created"] is True
    assert result["evidence_count"] == 1
    insert = next(params for sql, params in cur.calls if "insert into findings(" in sql)
    assert insert[3] == "high"


@pytest.mark.parametrize("actor,reason,error", [
    ("", "manual review", "actor_required"),
    (" ", "manual review", "actor_required"),
    ("test-actor", None, "reason_required"),
    ("test-actor", " ", "reason_required"),
])
def test_lifecycle_rejects_missing_human_actor_or_reason(monkeypatch, actor, reason, error):
    fake = _FakeFindingsPg()
    fake.install(monkeypatch)
    with pytest.raises(findings.FindingLifecycleError) as exc:
        findings.update_finding_lifecycle(1, new_status="review", changed_by=actor, note=reason)
    assert exc.value.code == error
    assert fake.finding["status"] == "new"
    assert fake.history == []


def test_previous_automatic_reason_is_not_a_reason_for_a_new_human_transition(monkeypatch):
    fake = _FakeFindingsPg()
    fake.finding["status_reason"] = "created from enabled semantic scenario"
    fake.install(monkeypatch)
    with pytest.raises(findings.FindingLifecycleError, match="require a reason"):
        findings.update_finding_lifecycle(1, new_status="confirmed", changed_by="test-actor")
    assert fake.history == []


def test_assignment_decision_requires_its_own_reason(monkeypatch):
    fake = _FakeFindingsPg()
    fake.finding["status_reason"] = "created from enabled semantic scenario"
    fake.install(monkeypatch)
    with pytest.raises(findings.FindingLifecycleError, match="require a reason"):
        findings.update_finding_lifecycle(1, new_status="new", changed_by="test-actor", assigned_to="test-team")
    assert fake.finding["assigned_to"] is None
    assert fake.history == []


def test_lifecycle_records_actor_and_reason_in_same_transaction(monkeypatch):
    fake = _FakeFindingsPg()
    fake.install(monkeypatch)
    findings.update_finding_lifecycle(1, new_status="confirmed", changed_by="test-actor",
                                      status_reason="Exact evidence reviewed")
    assert fake.history == [{"old_status": "new", "new_status": "confirmed",
                             "changed_by": "test-actor", "note": "Exact evidence reviewed"}]


def test_lifecycle_api_does_not_invent_an_actor(monkeypatch):
    from server.api.routes import findings as route

    fake = _FakeFindingsPg()
    fake.install(monkeypatch)
    replies = []
    handler = SimpleNamespace(_principal={"type": "session"},
                              _read_json_body=lambda: {"status": "review", "note": "manual review"},
                              _send_json=lambda body, status: replies.append((body, status)))
    route._handle_finding_status_update(handler, "/api/findings/1/status")
    assert replies[0][0]["error"] == "actor_required"
    assert replies[0][1] == 400
    assert fake.history == []


@pytest.mark.parametrize("domains", [None, [1]])
def test_risk_revocation_persists_actor_and_reason_for_existing_audit(monkeypatch, domains):
    from server.sli.core import postgres_runtime_pipeline
    from server.sli.reports import users_reporting

    calls = []

    class Cursor:
        def execute(self, sql, params):
            calls.append((sql, params))
        def fetchone(self):
            return {"public_id": "00000000-0000-0000-0000-000000000001", "status": "revoked",
                    "revoked_by": calls[0][1][0], "revoke_reason": calls[0][1][1]}
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False

    class Connection(Cursor):
        def cursor(self):
            return Cursor()
        def commit(self):
            pass

    monkeypatch.setattr(postgres_runtime_pipeline, "connect", Connection)
    result = users_reporting.revoke_risk_acceptance(
        public_id="00000000-0000-0000-0000-000000000001", domain_ids=domains,
        actor=" test-actor ", reason=" Fresh evidence requires investigation ")
    assert result["revoked_by"] == "test-actor"
    assert result["revoke_reason"] == "Fresh evidence requires investigation"
    assert "revoke_reason=%s" in calls[0][0]
    if domains is not None:
        assert calls[0][1][-1] == domains


@pytest.mark.parametrize("actor,reason", [("", "manual review"), ("test-actor", " ")])
def test_risk_revocation_requires_actor_and_reason(actor, reason):
    from server.sli.reports.users_reporting import revoke_risk_acceptance

    with pytest.raises(ValueError):
        revoke_risk_acceptance(public_id="00000000-0000-0000-0000-000000000001",
                               domain_ids=None, actor=actor, reason=reason)


def test_risk_acceptance_requires_actor_before_reading_evidence(monkeypatch):
    from server.sli.reports import users_reporting

    monkeypatch.setattr(users_reporting, "get_users_report", lambda **kwargs: pytest.fail("no evidence read"))
    with pytest.raises(ValueError, match="actor_required"):
        users_reporting.create_risk_acceptance(entity_id=1, domain_ids=[1], risk_key="account_locked",
            reason="Accepted for review", responsible="test-role", valid_until_utc="2026-10-08T00:00:00Z", actor="")
