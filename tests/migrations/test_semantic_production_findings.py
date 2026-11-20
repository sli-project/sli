from pathlib import Path
import sys

from scripts.maintenance import semantic_production_control as control


ROOT = Path(__file__).resolve().parents[2]


def test_production_controller_is_manual_exact_and_bounded() -> None:
    source = Path(control.__file__).read_text(encoding="utf-8")

    assert control.ACTIVATE_CONFIRM == "ACTIVATE-STAGE8-PRODUCTION-FINDINGS"
    assert control.POLL_CONFIRM == "POLL-STAGE8-PRODUCTION-FINDINGS"
    assert control.ENABLED_POLICY_ID == "l1-audit-policy-changed"
    assert control.MAX_LIMIT == 16
    assert "continuous_worker_started" in source
    assert "manual_production_poll_complete" in source
    assert "semantic_findings" in source
    assert "publications" in source


def test_migration_055_is_additive_idempotent_and_rollback_guarded() -> None:
    forward = (
        ROOT
        / "config/postgres_migrations/055_semantic_finding_publication.sql"
    ).read_text(encoding="utf-8").casefold()
    rollback = (
        ROOT
        / "config/postgres_migrations/055_semantic_finding_publication.rollback.sql"
    ).read_text(encoding="utf-8").casefold()

    assert "create table if not exists semantic_finding_publications" in forward
    assert "before update or delete on semantic_finding_publications" in forward
    assert "grant select,insert,update on table findings" in forward
    assert "grant usage,select on sequence" in forward
    assert "values (55,'semantic_finding_publication')" in forward
    assert "publication evidence exists" in rollback
    assert "revoke select,insert,update on table findings" in rollback


def test_enabled_evaluation_cannot_complete_without_finding_publication() -> None:
    source = (
        ROOT / "server/sli/semantic/semantic_risk_runtime_repository.py"
    ).read_text(encoding="utf-8")

    assert "enabled semantic evaluation requires finding publication" in source
    assert "publish_enabled_scenario_finding" in source
    assert "finding_created" in source


def test_production_deactivation_requires_stopped_worker_and_exact_policy() -> None:
    accepted = {
        "semantic_worker_live": False,
        "policies": [
            {
                "policy_id": control.ENABLED_POLICY_ID,
                "policy_version": control.POLICY_VERSION,
                "lifecycle_status": "enabled",
            }
        ],
    }

    control._assert_deactivation_preconditions(accepted)

    for changed in (
        {**accepted, "semantic_worker_live": True},
        {**accepted, "policies": []},
    ):
        import pytest

        with pytest.raises(RuntimeError):
            control._assert_deactivation_preconditions(changed)


def test_production_controller_requires_exact_deactivation_confirmation(
    monkeypatch,
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        control,
        "deactivate",
        lambda: calls.append("deactivate") or {"status": "deactivated"},
        raising=False,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "deactivate",
            "--confirm",
            "DEACTIVATE-STAGE8-PRODUCTION-FINDINGS",
        ],
    )

    assert control.main() == 0
    assert calls == ["deactivate"]


def test_production_controller_requires_exact_stop_confirmation(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        control,
        "request_stop",
        lambda: calls.append("stop") or {"status": "stopped"},
        raising=False,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "semantic_production_control.py",
            "stop",
            "--confirm",
            "STOP-CONTINUOUS-SEMANTIC-PRODUCTION",
        ],
    )

    assert control.main() == 0
    assert calls == ["stop"]
