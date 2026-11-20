import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition, compile_risk_policy
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from scripts.maintenance import semantic_l1_shadow_control as control


LOCAL_L1_STATE = Path(__file__).resolve().parents[2] / "artifacts/stage8/evidence/semantic-l1-shadow-state.json"


def test_l1_policies_compile_to_three_canonical_action_scenario_families() -> None:
    compiled = [
        compile_risk_policy(
            RiskPolicyDefinition(
                policy_id=policy_id,
                policy_version=1,
                source_kind=ScenarioSourceKind.CANONICAL_ACTION,
                definition=definition,
            )
        )
        for policy_id, definition in control.POLICIES
    ]
    assert len(compiled) == 4
    assert {item.selector_value for item in compiled} == set(
        control.TARGET_KINDS
    )
    assert {item.scenario_kind for item in compiled} == set(
        control.TARGET_KINDS.values()
    )


def test_canonical_action_id_is_evidence_not_scenario_merge_identity(
    monkeypatch,
) -> None:
    class Cursor:
        def __init__(self) -> None:
            self.rows = []

        def execute(self, sql, _params=()) -> None:
            normalized = " ".join(str(sql).split())
            if "from canonical_actions" in normalized:
                self.rows = [
                    {
                        "canonical_action_id": "action-1",
                        "action_kind": "audit.policy.changed",
                        "action_status": "observed",
                        "occurred_at_utc": datetime(
                            2026, 7, 30, tzinfo=timezone.utc
                        ),
                        "attributes_json": {
                            "material_identity": {"source_host": "dc-1"}
                        },
                    }
                ]
            elif "from canonical_action_evidence" in normalized:
                self.rows = [
                    {
                        "normalized_event_id": "normalized-1",
                        "roles_json": {
                            "source_host": "dc-1",
                            "actor": "sid:S-1-5-21-1",
                        },
                        "quality_json": {
                            "event_data_encoding": "named",
                            "identity_roles": {
                                "actor": {
                                    "key": "sid:S-1-5-21-1",
                                    "state": "resolved",
                                }
                            },
                        },
                        "semantic_type": "audit.policy.changed",
                    }
                ]
            else:
                raise AssertionError(normalized)

        def fetchone(self):
            return self.rows[0] if self.rows else None

        def fetchall(self):
            return self.rows

    policy_id, definition = control.POLICIES[1]
    policy = compile_risk_policy(
        RiskPolicyDefinition(
            policy_id=policy_id,
            policy_version=control.POLICY_VERSION,
            source_kind=ScenarioSourceKind.CANONICAL_ACTION,
            definition=definition,
        )
    )
    monkeypatch.setattr(runtime, "_coverage_for_policy", lambda *_args, **_kwargs: ())

    proposal = runtime._canonical_action_proposal(
        Cursor(), policy=policy, source_id="action-1"
    )

    assert proposal.strict_keys == {
        "source_host": "dc-1",
        "actor": "sid:S-1-5-21-1",
    }
    assert proposal.step.source_id == "action-1"


def test_l1_controller_is_manual_bounded_and_finding_creation_stays_off() -> None:
    source = Path(control.__file__).read_text(encoding="utf-8")
    assert control.APPLY_CONFIRM == "START-STAGE8-L1-BOUNDED-SHADOW"
    assert control.POLL_CONFIRM == "POLL-STAGE8-L1-BOUNDED-SHADOW"
    assert '"ADLOG_SEMANTIC_FINDING_CREATION_ENABLED": "0"' in source
    assert "order by core.id limit %s" in source
    assert "min(int(limit), 16)" in source
    assert "continuous_worker_started" in source


def test_l1_controller_requires_persisted_storage_authorization(monkeypatch) -> None:
    monkeypatch.setattr(
        control,
        "load_runtime_authorization_if_available",
        lambda _connect: None,
        raising=False,
    )

    with pytest.raises(RuntimeError, match="persisted Storage V2 authorization"):
        control._authorized_archive_reader(lambda: object())


@pytest.mark.skipif(
    not LOCAL_L1_STATE.is_file(),
    reason="local Stage 8 L1 production state is intentionally not versioned",
)
def test_l1_production_state_is_manual_shadow_without_findings() -> None:
    state = json.loads(control.STATE_PATH.read_text(encoding="utf-8"))
    assert state["status"] == "waiting_for_new_events"
    assert state["manual_runtime"] is True
    assert state["finding_creation_enabled"] is False
    assert state["production_findings_baseline"] == 0
    assert len(state["policy_ids"]) == 4
    assert int(state["last_snapshot"]["marker"]) >= 54
    assert all(
        item["lifecycle_status"] == "shadow"
        for item in state["last_snapshot"]["l1_policies"]
        if int(item["policy_version"]) == control.POLICY_VERSION
    )
    assert all(
        item["lifecycle_status"] == "disabled"
        for item in state["last_snapshot"]["l1_policies"]
        if int(item["policy_version"]) < control.POLICY_VERSION
    )
