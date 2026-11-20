from datetime import datetime, timezone
from decimal import Decimal

import pytest

from server.sli.semantic import (
    semantic_risk_repository,
    semantic_risk_runtime_repository,
)
from server.sli.semantic.event_semantic_contract import MachineRisk
from server.sli.semantic.semantic_risk import ScenarioResultClass, ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import (
    RiskPolicyDefinition,
    compile_risk_policy,
)


def _definition() -> dict[str, object]:
    return {
        "type": "scenario_policy",
        "source_selector": {
            "relation_kind": "authentication.session.has_special_privileges"
        },
        "scenario_kind": "authentication.privileged_session",
        "result_class": "security_incident",
        "strict_roles": ["session_principal"],
        "merge_window_seconds": 1800,
        "title": "Privileged session requires review",
        "explanation": "Exact host and session identity matched",
        "expected_evidence_count": 2,
        "required_controls": ["security-audit-logon"],
        "risk": {
            "class": "critical",
            "raw_score": "80.5",
            "display_points": 90,
            "hard_critical": True,
            "rationale": "Privileged session policy matched",
        },
    }


def test_policy_compiles_to_bounded_semantic_contract() -> None:
    compiled = compile_risk_policy(
        RiskPolicyDefinition(
            policy_id="privileged-session-risk",
            policy_version=1,
            source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
            definition=_definition(),
        )
    )
    assert compiled.result_class is ScenarioResultClass.SECURITY_INCIDENT
    assert compiled.risk_class is MachineRisk.CRITICAL
    assert compiled.raw_score == Decimal("80.5")
    assert compiled.strict_roles == ("session_principal",)
    assert compiled.required_controls == ("security-audit-logon",)
    assert compiled.allowed_lateness_seconds is None


def test_policy_rejects_code_and_noncanonical_or_missing_strict_identity() -> None:
    malicious = _definition() | {"python": "print('unsafe')"}
    with pytest.raises(ValueError, match="forbidden"):
        RiskPolicyDefinition(
            policy_id="unsafe",
            policy_version=1,
            source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
            definition=malicious,
        )
    missing = _definition() | {"strict_roles": []}
    with pytest.raises(ValueError, match="requires strict_roles"):
        compile_risk_policy(
            RiskPolicyDefinition(
                policy_id="missing-key",
                policy_version=1,
                source_kind=ScenarioSourceKind.CORRELATION_CANDIDATE,
                definition=missing,
            )
        )


def test_control_health_policy_has_explicit_control_gap_class() -> None:
    definition = _definition() | {
        "source_selector": {"control_id": "security-audit-logon"},
        "result_class": "control_gap",
        "strict_roles": [],
    }
    compiled = compile_risk_policy(
        RiskPolicyDefinition(
            policy_id="audit-gap",
            policy_version=1,
            source_kind=ScenarioSourceKind.CONTROL_HEALTH,
            definition=definition,
        )
    )
    assert compiled.result_class is ScenarioResultClass.CONTROL_GAP
    assert compiled.selector_value == "security-audit-logon"


@pytest.mark.parametrize("missing,wrong_control", [(False, False), (True, False), (False, True)])
def test_control_health_proposal_and_evidence_use_select_privileges(missing, wrong_control):
    """Immutable observations need no row lock requiring worker UPDATE rights."""
    definition = _definition() | {
        "source_selector": {"control_id": "security-audit-logon"},
        "result_class": "control_gap",
        "strict_roles": [],
    }
    policy = compile_risk_policy(RiskPolicyDefinition(
        policy_id="audit-gap", policy_version=1,
        source_kind=ScenarioSourceKind.CONTROL_HEALTH, definition=definition,
    ))
    source_id = "00000000-0000-0000-0000-000000000010"
    observed = datetime(2026, 7, 19, tzinfo=timezone.utc)

    class Cursor:
        calls = 0

        def execute(self, sql, params):
            statement = " ".join(sql.lower().split())
            assert "from semantic_control_health_observations" in statement
            assert "for share" not in statement
            assert "for update" not in statement
            assert params == (source_id,)
            self.calls += 1

        def fetchone(self):
            return None if missing else {
                "observation_id": source_id,
                "control_id": "different-control" if wrong_control else "security-audit-logon",
                "partition_key": "1", "coverage_status": "unavailable",
                "reason": "Synthetic audit coverage gap", "observed_at_utc": observed,
            }

    cursor = Cursor()
    if missing or wrong_control:
        with pytest.raises(RuntimeError, match="selector no longer matches"):
            semantic_risk_runtime_repository._control_health_proposal(
                cursor, policy=policy, source_id=source_id,
            )
        return
    proposal = semantic_risk_runtime_repository._control_health_proposal(
        cursor, policy=policy, source_id=source_id,
    )
    semantic_risk_repository._verify_source_evidence(cursor, proposal=proposal)
    assert cursor.calls == 2
    assert proposal.step.normalized_event_ids == ()
    assert proposal.coverage[0].observed_at_utc == observed


def test_canonical_action_policy_uses_declared_action_kind() -> None:
    definition = _definition() | {
        "source_selector": {"action_kind": "eventlog.cleared"},
        "scenario_kind": "security.audit_log_cleared",
        "strict_roles": ["source_host"],
        "expected_evidence_count": 1,
    }
    compiled = compile_risk_policy(
        RiskPolicyDefinition(
            policy_id="audit-log-cleared",
            policy_version=1,
            source_kind=ScenarioSourceKind.CANONICAL_ACTION,
            definition=definition,
        )
    )
    assert compiled.selector_value == "eventlog.cleared"
    assert compiled.strict_roles == ("source_host",)


def test_canonical_action_policy_rejects_noncanonical_strict_role() -> None:
    definition = _definition() | {
        "source_selector": {"action_kind": "eventlog.cleared"},
        "strict_roles": ["windows_event_record"],
    }
    with pytest.raises(ValueError, match="canonical entity roles"):
        compile_risk_policy(
            RiskPolicyDefinition(
                policy_id="invalid-action-role",
                policy_version=1,
                source_kind=ScenarioSourceKind.CANONICAL_ACTION,
                definition=definition,
            )
        )
