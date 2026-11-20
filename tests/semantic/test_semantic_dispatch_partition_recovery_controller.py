from __future__ import annotations

from copy import deepcopy

import pytest


def _rows() -> list[dict[str, object]]:
    rows = [
        {
            "job_id": "e24572a7-159d-517c-a284-a0eff96ac007",
            "dispatch_status": "quarantined", "source_event_id": 6487797,
            "partition_key": "sid:S-1-5-21-6295", "trigger_identity": "6295",
            "normalized_at": "2026-09-20T10:00:00+00:00", "source_hash": "a" * 64,
            "semantic_contract_version": 1, "normalizer_id": "windows.named-eventdata", "normalizer_version": "1.4+identity-1.0",
            "rule_id": "investigation.account.unlock.after-lock", "rule_version": 2,
            "definition_sha256": "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e",
            "last_error_code": "UniqueViolation",
            "last_error_detail": 'duplicate key value violates unique constraint "semantic_correlation_candidate__candidate_id_evidence_order_key"',
            "lease_token": None, "lease_until": None, "heartbeat_at": None,
            "attempt_count": 5, "max_attempts": 5,
        },
        {
            "job_id": "75280b7d-4573-5bc9-9e0e-c1d3f6e897e3",
            "dispatch_status": "quarantined", "source_event_id": 6486534,
            "partition_key": "sid:S-1-5-21-6682", "trigger_identity": "6682",
            "normalized_at": "2026-09-20T10:00:00+00:00", "source_hash": "b" * 64,
            "semantic_contract_version": 1, "normalizer_id": "windows.named-eventdata", "normalizer_version": "1.4+identity-1.0",
            "rule_id": "investigation.account.unlock.after-lock", "rule_version": 2,
            "definition_sha256": "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e",
            "last_error_code": "UniqueViolation",
            "last_error_detail": 'duplicate key value violates unique constraint "semantic_correlation_candidate__candidate_id_evidence_order_key"',
            "lease_token": None, "lease_until": None, "heartbeat_at": None,
            "attempt_count": 5, "max_attempts": 5,
        },
        {
            "job_id": "10eac730-5285-5740-b605-577d3ef9f4c2",
            "dispatch_status": "quarantined", "source_event_id": 6943209,
            "partition_key": "sid:S-1-5-21-7291", "trigger_identity": "7291",
            "normalized_at": "2026-09-20T10:00:00+00:00", "source_hash": "c" * 64,
            "semantic_contract_version": 1, "normalizer_id": "windows.named-eventdata", "normalizer_version": "1.4+identity-1.0",
            "rule_id": "investigation.account.unlock.after-lock", "rule_version": 2,
            "definition_sha256": "5da40e8f5c05bcead8c3bb0175dfabf84fbcad74c5b669f5909dc50250e3a02e",
            "last_error_code": "UniqueViolation",
            "last_error_detail": 'duplicate key value violates unique constraint "semantic_correlation_candidate__candidate_id_evidence_order_key"',
            "lease_token": None, "lease_until": None, "heartbeat_at": None,
            "attempt_count": 5, "max_attempts": 5,
        },
    ]
    expected = {
        6487797: [{"trigger_source_event_id": 6487797, "source_event_ids": [6442170, 6487797], "contribution_key": "dispatch:2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"}],
        6486534: [{"trigger_source_event_id": 6486534, "source_event_ids": [6436767, 6486534], "contribution_key": "dispatch:9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"}],
        6943209: [
            {"trigger_source_event_id": 6943209, "source_event_ids": [6923513, 6943209], "contribution_key": "dispatch:5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"},
            {"trigger_source_event_id": 6943209, "source_event_ids": [6874055, 6943209], "contribution_key": "dispatch:b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb"},
        ],
    }
    for row in rows:
        row["accepted_relations"] = []
        row["repairable_relations"] = expected[int(row["source_event_id"])]
        row["blocking_relations"] = []
    return rows


def test_exact_three_plan_is_canonical_sealed_and_secret_free() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    first = build_sealed_plan(_rows(), normalized_before="2026-09-20T10:00:00+00:00")
    second = build_sealed_plan(list(reversed(_rows())), normalized_before="2026-09-20T10:00:00+00:00")

    assert first == second
    assert first["job_count"] == 3
    assert first["confirmation"] == "REPAIR-SEMANTIC-DISPATCH-PARTITION:" + first["plan_digest"]
    assert "last_error_detail" not in repr(first)
    assert "password" not in repr(first).lower()
    assert first["expected_relations"] == [
        {"trigger_source_event_id": 6487797, "source_event_ids": [6442170, 6487797], "contribution_key": "dispatch:2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4"},
        {"trigger_source_event_id": 6486534, "source_event_ids": [6436767, 6486534], "contribution_key": "dispatch:9dd99c4a7bf00789c02b297270df71260e79096577bc4b1e6ccdba437717c037"},
        {"trigger_source_event_id": 6943209, "source_event_ids": [6923513, 6943209], "contribution_key": "dispatch:5497fb27862a7026a64b5e77f41d8e0a3fa181d9429bffa34671b899eedebe23"},
        {"trigger_source_event_id": 6943209, "source_event_ids": [6874055, 6943209], "contribution_key": "dispatch:b17e18e9d9fd11eb218a0b20b24175a8cf1ec427038c7700114f323a36767cfb"},
    ]
    assert first["jobs"][0]["normalized_contract"] == {
        "semantic_contract_version": 1, "normalizer_id": "windows.named-eventdata", "normalizer_version": "1.4+identity-1.0",
    }


@pytest.mark.parametrize("field,value", [
    ("job_id", "00000000-0000-0000-0000-000000000000"),
    ("dispatch_status", "failed"), ("last_error_code", "IntegrityError"),
    ("source_hash", "not-a-hash"), ("rule_version", 3),
    ("normalizer_version", "1.5-drifted"),
])
def test_plan_fails_closed_for_any_exact_job_contract_drift(field: str, value: object) -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    rows[0][field] = value
    with pytest.raises(RuntimeError):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


def test_plan_fails_closed_for_count_error_or_expected_relation_drift() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    with pytest.raises(RuntimeError):
        build_sealed_plan(_rows()[:2], normalized_before="2026-09-20T10:00:00+00:00")
    rows = _rows()
    rows[0]["last_error_detail"] = 'duplicate key value violates unique constraint "other"'
    with pytest.raises(RuntimeError):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


def test_plan_accepts_exact_queued_after_requeue_state_and_binds_it() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    for row in rows:
        row.update({
            "dispatch_status": "queued", "lease_token": None, "lease_until": None,
            "heartbeat_at": None, "attempt_count": 5, "max_attempts": 5,
            "accepted_relations": [],
        })

    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    assert [item["job_id"] for item in plan["jobs"]] == sorted(row["job_id"] for row in rows)


def test_plan_accepts_only_expired_exact_recovery_lease_for_crash_resume() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    for row in rows:
        row.update({
            "dispatch_status": "leased", "lease_token": "recovery-lease",
            "lease_until": "2026-09-21T03:00:00+00:00",
            "lease_expired": True, "heartbeat_at": "2026-09-21T02:59:00+00:00",
            "attempt_count": 5, "max_attempts": 5, "accepted_relations": [],
        })

    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    assert plan["job_count"] == 3

    rows[0]["lease_expired"] = False
    with pytest.raises(RuntimeError, match="leased"):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


def test_plan_accepts_exact_controller_completion_constraint_failure() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    for row in rows:
        row.update({
            "dispatch_status": "quarantined",
            "heartbeat_at": "2026-09-21T04:04:26+00:00",
            "last_error_code": "CheckViolation",
            "last_error_detail": 'violates check constraint "semantic_correlation_dispatch_terminal"',
        })

    assert build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")["job_count"] == 3

    rows[0]["last_error_detail"] = 'violates check constraint "other"'
    with pytest.raises(RuntimeError, match="contract"):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


@pytest.mark.parametrize("field,value", [
    ("lease_token", "still-leased"), ("lease_until", "2026-09-21T00:00:00+00:00"),
    ("heartbeat_at", "2026-09-21T00:00:00+00:00"), ("attempt_count", 4),
    ("max_attempts", 7), ("accepted_relations", [{"unexpected": True}]),
])
def test_plan_rejects_queued_recovery_state_drift(field: str, value: object) -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    for row in rows:
        row.update({
            "dispatch_status": "queued", "lease_token": None, "lease_until": None,
            "heartbeat_at": None, "attempt_count": 5, "max_attempts": 5,
            "accepted_relations": [],
        })
    rows[0][field] = value

    with pytest.raises(RuntimeError):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


def test_plan_rejects_missing_legacy_relation_or_any_blocking_relation() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import build_sealed_plan

    rows = _rows()
    rows[0]["repairable_relations"] = []
    with pytest.raises(RuntimeError, match="relation"):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")

    rows = _rows()
    rows[0]["blocking_relations"] = [{"unexpected": True}]
    with pytest.raises(RuntimeError, match="relation"):
        build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")


def test_apply_revalidates_everything_before_requeue_and_dispatch() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    rows = _rows()
    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    calls: list[str] = []
    changed = deepcopy(rows)
    changed[1]["source_hash"] = "d" * 64
    controller = RecoveryController(
        snapshot=lambda: changed,
        worker_is_live=lambda: False,
        acquire_locks=lambda: True,
        requeue=lambda _plan: calls.append("requeue"),
        dispatch=lambda _plan: calls.append("dispatch") or {"completed": 3, "failed": 0, "relations": 4},
        verify=lambda _plan: {"completed": True, "relations_exact": True, "scenario_evidence_added": 0, "unrelated_status_unchanged": True},
        audit=lambda _result: calls.append("audit"),
    )

    with pytest.raises(RuntimeError, match="changed"):
        controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)
    assert calls == []


def test_apply_passes_only_plan_ids_and_boundary_and_failure_is_not_success() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    plan = build_sealed_plan(_rows(), normalized_before="2026-09-20T10:00:00+00:00")
    observed: dict[str, object] = {}
    controller = RecoveryController(
        snapshot=_rows, worker_is_live=lambda: False, acquire_locks=lambda: True,
        requeue=lambda _plan: None,
        dispatch=lambda current: observed.update(current) or {"completed": 2, "failed": 1, "relations": 3},
        verify=lambda _plan: pytest.fail("failed processing must not verify success"), audit=lambda _result: None,
    )

    with pytest.raises(RuntimeError, match="failed"):
        controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)
    assert observed["allowed_job_ids"] == [item["job_id"] for item in plan["jobs"]]
    assert observed["normalized_before"] == plan["normalized_before"]


def test_apply_refuses_competing_worker_and_completed_acceptance_is_noop() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    plan = build_sealed_plan(_rows(), normalized_before="2026-09-20T10:00:00+00:00")
    blocked = RecoveryController(snapshot=_rows, worker_is_live=lambda: True, acquire_locks=lambda: True)
    with pytest.raises(RuntimeError, match="live"):
        blocked.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)

    calls: list[str] = []
    completed_rows = _rows()
    expected_relations = plan["expected_relations"]
    for row in completed_rows:
        row["dispatch_status"] = "completed"
        row["accepted_relations"] = [item for item in expected_relations if item["trigger_source_event_id"] == row["source_event_id"]]
        row["repairable_relations"] = []
    complete = RecoveryController(
        snapshot=lambda: completed_rows, worker_is_live=lambda: False, acquire_locks=lambda: True,
        requeue=lambda _plan: calls.append("requeue"), dispatch=lambda _plan: calls.append("dispatch"),
    )
    result = complete.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)
    assert result["status"] == "already_complete"
    assert calls == []


def test_apply_resumes_only_the_remaining_quarantined_jobs_after_exact_completed_readback() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    rows = _rows()
    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    resumed = deepcopy(rows)
    resumed[0]["dispatch_status"] = "completed"
    resumed[0]["accepted_relations"] = [{
        "trigger_source_event_id": 6487797,
        "source_event_ids": [6442170, 6487797],
        "contribution_key": "dispatch:2dfdf2e4219e728fcab50c8a65139153c7bd1b410ed72c0493afdec8ca7df7c4",
    }]
    resumed[0]["repairable_relations"] = []
    seen: dict[str, object] = {}
    controller = RecoveryController(
        snapshot=lambda: resumed, worker_is_live=lambda: False, acquire_locks=lambda: True,
        requeue=lambda current: seen.update(requeue=current),
        dispatch=lambda current: seen.update(dispatch=current) or {"completed": 2, "failed": 0, "relations": 3},
        verify=lambda _plan: {"completed": True, "relations_exact": True, "scenario_evidence_added": 0, "unrelated_status_unchanged": True},
    )
    result = controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)
    assert result["status"] == "complete"
    assert seen["dispatch"]["allowed_job_ids"] == [item["job_id"] for item in plan["jobs"] if item["job_id"] != resumed[0]["job_id"]]


def test_apply_rejects_completed_job_without_its_exact_relation_readback() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    rows = _rows()
    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    rows[0]["dispatch_status"] = "completed"
    controller = RecoveryController(snapshot=lambda: rows, worker_is_live=lambda: False, acquire_locks=lambda: True)
    with pytest.raises(RuntimeError, match="completed"):
        controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)


def test_apply_rejects_completed_job_with_extra_relation_readback() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    rows = _rows()
    plan = build_sealed_plan(rows, normalized_before="2026-09-20T10:00:00+00:00")
    rows[0]["dispatch_status"] = "completed"
    rows[0]["accepted_relations"] = [
        item for item in plan["expected_relations"]
        if item["trigger_source_event_id"] == rows[0]["source_event_id"]
    ] + [{
        "trigger_source_event_id": rows[0]["source_event_id"],
        "source_event_ids": [1, rows[0]["source_event_id"]],
        "contribution_key": "unexpected-candidate-key:" + "0" * 64,
    }]
    controller = RecoveryController(snapshot=lambda: rows, worker_is_live=lambda: False, acquire_locks=lambda: True)
    with pytest.raises(RuntimeError, match="completed"):
        controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)


def test_apply_revalidates_frozen_baseline_before_any_requeue() -> None:
    from server.sli.semantic.semantic_dispatch_partition_recovery import RecoveryController, build_sealed_plan

    plan = build_sealed_plan(_rows(), normalized_before="2026-09-20T10:00:00+00:00")
    calls: list[str] = []
    controller = RecoveryController(
        snapshot=_rows, worker_is_live=lambda: False, acquire_locks=lambda: True,
        preflight=lambda _plan: False,
        requeue=lambda _plan: calls.append("requeue"),
        dispatch=lambda _scope: calls.append("dispatch") or {"completed": 3, "failed": 0},
    )

    with pytest.raises(RuntimeError, match="preflight"):
        controller.apply(plan_digest=plan["plan_digest"], confirmation=plan["confirmation"], plan=plan)
    assert calls == []
