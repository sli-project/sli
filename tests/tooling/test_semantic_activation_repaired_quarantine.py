from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.maintenance import semantic_production_control as control


SOURCE_HASH = "a" * 64
HISTORY_DIGEST = "c" * 64
ERROR_DETAIL = 'duplicate key value violates unique constraint "canonical_actions_pkey"'
APPROVED_REPAIR_DIGEST = "f83550b69c0423ffb3909440e5fd8d2ae1da469727b0e936fa70b1d8feb8a3b0"


def _manifest() -> dict[str, object]:
    return {
        "manifest_type": control.SECURITY_HISTORY_MANIFEST_TYPE_V2,
        "plan_digest": HISTORY_DIGEST,
        "database_identity": {"host": "db", "database": "sli", "role": "admin"},
        "events": {
            "4624": {
                "count": 260,
                "high_watermark": 999,
                "cohort_digest": "d" * 64,
                "semantic_expected_count": 260,
                "semantic_context_digest": "e" * 64,
                "semantic_context_reset_high_watermark": 777,
            },
        },
    }


def _row(source_event_id: int, source_hash: str) -> dict[str, object]:
    original_job_id = f"00000000-0000-0000-0000-{source_event_id:012d}"
    return {
        "source_event_id": source_event_id,
        "source_hash": source_hash,
        "original_job_count": 1,
        "original_job_id": original_job_id,
        "original_status": "quarantined",
        "original_attempt_count": 5,
        "original_max_attempts": 5,
        "original_error_code": "UniqueViolation",
        "original_error_detail": ERROR_DETAIL,
        "original_error_detail_sha256": sha256(ERROR_DETAIL.encode()).hexdigest(),
        "original_source_hash": source_hash,
        "repair_job_count": 1,
        "repair_status": "completed",
        "repair_processor_id": control.PROCESSOR_ID,
        "repair_processor_version": control.PROCESSOR_VERSION,
        "repair_source_hash": source_hash,
        "repair_payload_source_hash": source_hash,
        "repair_semantic_contract_version": control.SEMANTIC_CONTRACT_VERSION,
        "repair_original_job_id": original_job_id,
        "repair_history_plan_digest": HISTORY_DIGEST,
        "repair_plan_digest": "0" * 64,
        "repair_original_attempt_count": 5,
        "repair_original_max_attempts": 5,
        "repair_original_error_code": "UniqueViolation",
        "repair_original_error_detail_sha256": sha256(ERROR_DETAIL.encode()).hexdigest(),
        "normalized_current_count": 1,
        "normalized_proof_count": 1,
        "normalized_proof_hash": source_hash,
        "normalized_action_count": 1,
    }


def _eligible_coverage() -> tuple[dict[str, object], list[tuple[int, str]], list[dict[str, object]]]:
    manifest = _manifest()
    pairs = [(source_id, f"{source_id:064x}") for source_id in range(1, 261)]
    rows = [_row(source_id, source_hash) for source_id, source_hash in pairs]
    context = {
        "count": 260,
        "cohort_digest": control.security_history_cohort_digest(pairs),
        "reset_high_watermark": 777,
    }
    manifest["events"]["4624"]["semantic_context_digest"] = context["cohort_digest"]
    for row in rows:
        row["repair_plan_digest"] = APPROVED_REPAIR_DIGEST
    return manifest, pairs, rows


def _eligible_snapshot(**overrides: object) -> dict[str, object]:
    snapshot: dict[str, object] = {
        "semantic_worker_live": False,
        "processing_quarantined_total": 260,
        "processing_quarantined_covered": 260,
        "processing_quarantined_unresolved": 0,
        "dispatch_quarantined": 0,
        "risk_quarantined": 0,
        "policies": [{
            "policy_id": control.ENABLED_POLICY_ID,
            "policy_version": control.POLICY_VERSION,
            "lifecycle_status": "shadow",
        }],
        "calibration": {
            "completed_jobs": 16,
            "incomplete_jobs": 0,
            "scenario_count": 1,
            "evidence_count": 16,
            "contribution_count": 16,
            "min_scenario_evidence": 16,
        },
    }
    snapshot.update(overrides)
    return snapshot


def test_activation_coverage_accepts_exact_frozen_260_repaired_cohort() -> None:
    manifest, pairs, rows = _eligible_coverage()

    result = control._classify_activation_v2_repair_coverage(
        manifest=manifest,
        pairs=pairs,
        rows=rows,
        migration_name="semantic_v2_quarantine_repair",
    )

    assert result == {"total": 260, "covered": 260, "unresolved": 0}


@pytest.mark.parametrize("mutation", (
    "out_of_cohort", "wrong_history_digest", "wrong_terminal_error",
    "wrong_output_hash", "wrong_output_status", "unknown_output_type", "wrong_action_output",
    "duplicate_repair", "incomplete_repair",
))
def test_activation_coverage_keeps_nonexact_repair_lineage_unresolved(mutation: str) -> None:
    manifest, pairs, rows = _eligible_coverage()
    if mutation == "out_of_cohort":
        pairs[-1] = (261, f"{261:064x}")
    elif mutation == "wrong_history_digest":
        rows[0]["repair_history_plan_digest"] = "f" * 64
    elif mutation == "wrong_terminal_error":
        rows[0]["original_error_code"] = "IntegrityError"
    elif mutation == "wrong_output_hash":
        rows[0]["normalized_proof_hash"] = "f" * 64
    elif mutation == "wrong_output_status":
        rows[0]["repair_status"] = "failed"
    elif mutation == "unknown_output_type":
        rows[0]["normalized_proof_count"] = 0
    elif mutation == "wrong_action_output":
        rows[0]["normalized_action_count"] = 0
    elif mutation == "duplicate_repair":
        rows[0]["repair_job_count"] = 2
    else:
        rows[0]["repair_status"] = "queued"
        rows[0]["normalized_current_count"] = 0
        rows[0]["normalized_proof_count"] = 0
        rows[0]["normalized_proof_hash"] = None

    result = control._classify_activation_v2_repair_coverage(
        manifest=manifest,
        pairs=pairs,
        rows=rows,
        migration_name="semantic_v2_quarantine_repair",
    )

    assert result["total"] == 260
    assert result["covered"] < 260
    assert result["unresolved"] > 0


def test_activation_coverage_rejects_wrong_migration_and_repair_plan_digest() -> None:
    manifest, pairs, rows = _eligible_coverage()

    assert control._classify_activation_v2_repair_coverage(
        manifest=manifest, pairs=pairs, rows=rows, migration_name="wrong",
    )["unresolved"] == 260
    rows[0]["repair_plan_digest"] = "f" * 64
    assert control._classify_activation_v2_repair_coverage(
        manifest=manifest, pairs=pairs, rows=rows,
        migration_name="semantic_v2_quarantine_repair",
    )["unresolved"] == 1


class _RepairCoverageCursor:
    """Cursor-shaped fixture for the activation-only repair lineage reads."""

    def __init__(self, rows: list[dict[str, object]]) -> None:
        self.rows = rows
        self.executions: list[tuple[str, object]] = []
        self._last_sql = ""

    def execute(self, sql: str, params: object = None) -> None:
        if "with selected(source_event_id,source_hash)" in sql:
            assert params is not None
            assert sql.count("%s") == len(params)
        self.executions.append((sql, params))
        self._last_sql = sql

    def fetchone(self) -> dict[str, object]:
        assert "schema_migrations" in self._last_sql
        return {"name": "semantic_v2_quarantine_repair"}

    def fetchall(self) -> list[dict[str, object]]:
        assert "with selected(source_event_id,source_hash)" in self._last_sql
        return self.rows


@pytest.mark.parametrize("mutation", ("wrong_history_digest", "wrong_terminal_error", "wrong_output_hash", "wrong_output_status", "unknown_output_type", "wrong_action_output", "duplicate_repair", "incomplete_repair"))
def test_cursor_coverage_query_uses_authoritative_contract_and_fails_closed(
    tmp_path, monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    manifest, pairs, rows = _eligible_coverage()
    frozen = tmp_path / "retained-security-history-vocabulary.json"
    frozen.write_text(__import__("json").dumps(manifest), encoding="utf-8")
    if mutation == "wrong_history_digest":
        rows[0]["repair_history_plan_digest"] = "f" * 64
    elif mutation == "wrong_terminal_error":
        rows[0]["original_error_code"] = "IntegrityError"
    elif mutation == "wrong_output_hash":
        rows[0]["normalized_proof_hash"] = "f" * 64
    elif mutation == "wrong_output_status":
        rows[0]["repair_status"] = "failed"
    elif mutation == "unknown_output_type":
        rows[0]["normalized_proof_count"] = 0
    elif mutation == "wrong_action_output":
        rows[0]["normalized_action_count"] = 0
    elif mutation == "duplicate_repair":
        rows[0]["repair_job_count"] = 2
    else:
        rows[0]["normalized_current_count"] = 0
        rows[0]["normalized_proof_count"] = 0
        rows[0]["normalized_action_count"] = 0
    monkeypatch.setattr(control, "_read_approved_frozen_security_history_manifest", lambda: manifest)
    monkeypatch.setattr(control, "_security_history_v2_quarantine_snapshot", lambda _cur, _manifest: (pairs, {}))

    cursor = _RepairCoverageCursor(rows)
    result = control._activation_v2_repair_coverage(cursor)

    assert result["total"] == 260
    assert result["covered"] < 260
    assert result["unresolved"] > 0
    repair_sql, repair_params = cursor.executions[-1]
    assert "canonical_action_evidence" in repair_sql
    assert "normalized.processing_status='normalized'" in repair_sql
    assert "normalized.semantic_type<>'event.unknown'" in repair_sql
    assert repair_params[0] == [source_id for source_id, _ in pairs]
    assert repair_params[1] == [source_hash for _, source_hash in pairs]


def test_cursor_coverage_query_accepts_only_the_exact_frozen_260_rows(
    tmp_path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest, pairs, rows = _eligible_coverage()
    frozen = tmp_path / "retained-security-history-vocabulary.json"
    frozen.write_text(__import__("json").dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(control, "_read_approved_frozen_security_history_manifest", lambda: manifest)
    monkeypatch.setattr(control, "_security_history_v2_quarantine_snapshot", lambda _cur, _manifest: (pairs, {}))

    assert control._activation_v2_repair_coverage(_RepairCoverageCursor(rows)) == {
        "total": 260, "covered": 260, "unresolved": 0,
    }


def test_calibration_accepts_only_completed_payload_bound_repaired_quarantines() -> None:
    control._assert_calibration(_eligible_snapshot())


def test_calibration_blocks_every_unresolved_repaired_quarantine() -> None:
    with pytest.raises(RuntimeError, match="quarantined work"):
        control._assert_calibration(_eligible_snapshot(
            processing_quarantined_covered=259,
            processing_quarantined_unresolved=1,
        ))


def test_calibration_keeps_unrelated_dispatch_quarantines_as_a_blocker() -> None:
    with pytest.raises(RuntimeError, match="quarantined work"):
        control._assert_calibration(_eligible_snapshot(dispatch_quarantined=3))


def test_calibration_requirements_other_than_processing_eligibility_are_unchanged() -> None:
    with pytest.raises(RuntimeError, match="accepted SHADOW collapse"):
        control._assert_calibration(_eligible_snapshot(calibration={
            "completed_jobs": 16, "incomplete_jobs": 1, "scenario_count": 1,
            "evidence_count": 16, "contribution_count": 16,
            "min_scenario_evidence": 16,
        }))


def test_calibration_accepts_only_the_complete_authorised_shadow_window() -> None:
    accepted = _eligible_snapshot(calibration={
        "completed_jobs": 16, "incomplete_jobs": 0, "scenario_count": 1,
        "evidence_count": 16, "contribution_count": 16,
        "min_scenario_evidence": 16,
    })

    control._assert_calibration(accepted)

    accepted["calibration"] = {
        "completed_jobs": 15, "incomplete_jobs": 0, "scenario_count": 1,
        "evidence_count": 15, "contribution_count": 15,
        "min_scenario_evidence": 15,
    }
    with pytest.raises(RuntimeError, match="accepted SHADOW collapse"):
        control._assert_calibration(accepted)

    accepted["calibration"] = {
        "completed_jobs": 17, "incomplete_jobs": 0, "scenario_count": 1,
        "evidence_count": 17, "contribution_count": 17,
        "min_scenario_evidence": 17,
    }
    with pytest.raises(RuntimeError, match="accepted SHADOW collapse"):
        control._assert_calibration(accepted)


class _SnapshotCursor(_RepairCoverageCursor):
    """Cursor-shaped integration fixture for the aggregate and repair reads."""

    def __init__(self, rows: list[dict[str, object]], *, processing_quarantined: int) -> None:
        super().__init__(rows)
        self.processing_quarantined = processing_quarantined

    def fetchone(self) -> dict[str, object]:
        if "coalesce((select max(version)" in self._last_sql:
            return {
                "marker": 143, "max_event_id": 999, "findings": 0,
                "semantic_findings": 0, "semantic_worker_live": False,
                "processing_quarantined": self.processing_quarantined,
                "dispatch_quarantined": 0, "risk_quarantined": 0,
            }
        if "schema_migrations" in self._last_sql:
            return {"name": "semantic_v2_quarantine_repair"}
        if "to_regclass" in self._last_sql:
            return {"publication_table": None}
        if "from accepted" in self._last_sql:
            return {
                "completed_jobs": 16, "incomplete_jobs": 0, "scenario_count": 1,
                "evidence_count": 16, "contribution_count": 16,
                "min_scenario_evidence": 16,
            }
        raise AssertionError(self._last_sql)

    def fetchall(self) -> list[dict[str, object]]:
        if "with selected(source_event_id,source_hash)" in self._last_sql:
            return self.rows
        if "from semantic_risk_policies" in self._last_sql:
            return [{
                "policy_id": control.ENABLED_POLICY_ID,
                "policy_version": control.POLICY_VERSION,
                "lifecycle_status": "shadow",
                "definition_sha256": "a" * 64,
            }]
        raise AssertionError(self._last_sql)


def _approved_manifest_bytes() -> bytes:
    # Unit tests must not depend on the ignored production evidence artifact.
    manifest = _manifest()
    manifest["plan_digest"] = control.APPROVED_SECURITY_HISTORY_MANIFEST_PLAN_DIGEST
    manifest["selection_fingerprint"] = control.APPROVED_SECURITY_HISTORY_MANIFEST_SELECTION_FINGERPRINT
    return json.dumps(manifest, sort_keys=True).encode("utf-8")


def _install_approved_frozen_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    frozen = tmp_path / "artifacts/stage8/evidence/retained-security-history-vocabulary.json"
    frozen.parent.mkdir(parents=True)
    raw = _approved_manifest_bytes()
    frozen.write_bytes(raw)
    monkeypatch.setattr(control, "APPROVED_SECURITY_HISTORY_MANIFEST_SHA256", sha256(raw).hexdigest())
    monkeypatch.setattr(control, "_main_checkout_root", lambda: tmp_path)


def test_pinned_frozen_manifest_accepts_only_the_approved_raw_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_approved_frozen_manifest(tmp_path, monkeypatch)

    manifest = control._read_approved_frozen_security_history_manifest()

    assert manifest["plan_digest"] == control.APPROVED_SECURITY_HISTORY_MANIFEST_PLAN_DIGEST
    assert (
        manifest["selection_fingerprint"]
        == control.APPROVED_SECURITY_HISTORY_MANIFEST_SELECTION_FINGERPRINT
    )


@pytest.mark.parametrize(("processing_quarantined", "expected"), (
    (260, {"total": 260, "covered": 260, "unresolved": 0}),
    (261, {"total": 261, "covered": 260, "unresolved": 1}),
))
def test_snapshot_derives_unresolved_from_global_quarantine_total(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, processing_quarantined: int,
    expected: dict[str, int],
) -> None:
    _install_approved_frozen_manifest(tmp_path, monkeypatch)
    manifest, pairs, rows = _eligible_coverage()
    monkeypatch.setattr(
        control, "_read_approved_frozen_security_history_manifest", lambda: manifest,
    )
    monkeypatch.setattr(
        control, "_security_history_v2_quarantine_snapshot", lambda _cur, _manifest: (pairs, {}),
    )

    snapshot = control._snapshot(
        _SnapshotCursor(rows, processing_quarantined=processing_quarantined)
    )

    assert snapshot["processing_quarantined"] == processing_quarantined
    assert snapshot["dispatch_quarantined"] == 0
    assert snapshot["risk_quarantined"] == 0
    assert snapshot["calibration"] == {
        "completed_jobs": 16, "incomplete_jobs": 0, "scenario_count": 1,
        "evidence_count": 16, "contribution_count": 16,
        "min_scenario_evidence": 16,
    }
    assert {
        "total": snapshot["processing_quarantined_total"],
        "covered": snapshot["processing_quarantined_covered"],
        "unresolved": snapshot["processing_quarantined_unresolved"],
    } == expected
    if processing_quarantined == 260:
        control._assert_calibration(snapshot)
    else:
        with pytest.raises(RuntimeError, match="quarantined work"):
            control._assert_calibration(snapshot)


def test_snapshot_cannot_erase_an_unrelated_global_processing_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_approved_frozen_manifest(tmp_path, monkeypatch)
    manifest, pairs, rows = _eligible_coverage()
    monkeypatch.setattr(
        control, "_read_approved_frozen_security_history_manifest", lambda: manifest,
    )
    monkeypatch.setattr(
        control, "_security_history_v2_quarantine_snapshot", lambda _cur, _manifest: (pairs, {}),
    )

    snapshot = control._snapshot(_SnapshotCursor(rows, processing_quarantined=261))

    assert snapshot["processing_quarantined_covered"] == 260
    assert snapshot["processing_quarantined_unresolved"] == 1
    with pytest.raises(RuntimeError, match="quarantined work"):
        control._assert_calibration(snapshot)


@pytest.mark.parametrize("artifact", ("missing", "digest_mismatch"))
def test_snapshot_fails_closed_when_pinned_frozen_artifact_is_unavailable_or_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, artifact: str,
) -> None:
    frozen = tmp_path / "artifacts/stage8/evidence/retained-security-history-vocabulary.json"
    frozen.parent.mkdir(parents=True)
    if artifact == "digest_mismatch":
        frozen.write_bytes(_approved_manifest_bytes() + b"\n")
    monkeypatch.setattr(control, "_main_checkout_root", lambda: tmp_path)
    _manifest, pairs, rows = _eligible_coverage()
    monkeypatch.setattr(
        control, "_security_history_v2_quarantine_snapshot", lambda _cur, _manifest: (pairs, {}),
    )

    snapshot = control._snapshot(_SnapshotCursor(rows, processing_quarantined=260))

    assert snapshot["processing_quarantined_covered"] == 0
    assert snapshot["processing_quarantined_unresolved"] > 0
    with pytest.raises(RuntimeError, match="quarantined work"):
        control._assert_calibration(snapshot)
