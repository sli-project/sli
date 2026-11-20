from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import server.sli.storage.tier_retention_delete_executor_runtime as executor
import server.sli.storage.tier_retention_delete_plan_runtime as plan_runtime


def _row(event_id: int, value: int) -> dict[str, object]:
    return {
        "id": event_id,
        "normalized_hash": bytes([value]) * 32,
        "time_created_utc": datetime(2026, 7, 1, tzinfo=timezone.utc),
    }


def _promotion(archive_requirement: str = "no_archive") -> dict:
    return {
        "archive_requirement": archive_requirement,
        "post_promotion_disposition": "delete_source",
        "read_representation": (
            "derived_only" if archive_requirement == "no_archive" else "archived_atomic"
        ),
        "executable_lifecycle": "existing_warm_then_retention_executor",
    }


def _resolution(archive_requirement: str = "no_archive") -> SimpleNamespace:
    return SimpleNamespace(
        policy_fingerprint="a" * 64,
        rollup="authentication_session",
        rollup_role="open",
        promotion=_promotion(archive_requirement),
    )


def _lifecycle(rows: list[dict[str, object]], archive_requirement: str) -> dict:
    promotion = _promotion(archive_requirement)
    descriptor_policies = [{
        "event_key": "4624", "rollup_role": "open", "policy_fingerprint": "a" * 64,
    }]
    policy_fingerprint = hashlib.sha256(json.dumps({
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "descriptor_policies": descriptor_policies,
        "promotion": promotion,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    candidate_ids = [int(row["id"]) for row in rows]
    candidate_identity = hashlib.sha256(
        json.dumps(candidate_ids, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    progress = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": [22],
        "scope_identity": "sli.source-capture-continuity.v1:22:" + "b" * 64,
        "declaration_sha256": "b" * 64,
        "candidate_identity_sha256": candidate_identity,
    }
    progress["digest"] = hashlib.sha256(json.dumps(
        progress, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return {
        "source": "sli.windows.ad-dc",
        "stream": "Security",
        "event_keys": ["4624"],
        "candidate_ids": candidate_ids,
        "candidate_identity_sha256": candidate_identity,
        "rollup": "authentication_session",
        "archive_requirement": archive_requirement,
        "read_representation": promotion["read_representation"],
        "post_promotion_disposition": promotion["post_promotion_disposition"],
        "executable_lifecycle": promotion["executable_lifecycle"],
        "descriptor_policies": descriptor_policies,
        "policy_fingerprint": policy_fingerprint,
        "continuity_declaration_scope_identity": "sli.source-capture-continuity.v1:22:" + "b" * 64,
        "continuity_declaration_sha256": "b" * 64,
        "declaration_progress": progress,
    }


def _derived_row(
    *,
    state: str = "closed",
    quality_reason: str = "complete",
    logoff_time_utc: str | None = "2026-07-01T00:05:00+00:00",
    duration_seconds: int | None = 300,
    logoff_source_event_id: int | None = 11,
    logoff_normalized_hash: str | None = "02" * 32,
) -> dict[str, object]:
    return {
        "session_uid": "session-1",
        "state": state,
        "quality_reason": quality_reason,
        "logoff_time_utc": logoff_time_utc,
        "duration_seconds": duration_seconds,
        "logoff_source_event_id": logoff_source_event_id,
        "logoff_normalized_hash": logoff_normalized_hash,
    }


def _evidence(
    rows: list[dict[str, object]], *, derived: list[dict[str, object]] | None = None,
    archive_requirement: str = "no_archive",
) -> dict:
    references = [
        {"id": int(row["id"]), "sha256": bytes(row["normalized_hash"]).hex()}
        for row in rows
    ]
    digest = plan_runtime.source_reference_digest(references)
    evidence = {
        "descriptor_lifecycle": _lifecycle(rows, archive_requirement),
        "derived_publication": {
            "batch_identity": "f" * 64,
            "source_references": references,
            "derived": derived or [_derived_row()],
            "derived_output_digest": "c" * 64,
            "manifest": {
                "source_reference_digest": digest,
                "derived_output_digest": "c" * 64,
                "policy_fingerprint": _lifecycle(rows, archive_requirement)["policy_fingerprint"],
                "declaration_progress_digest": _lifecycle(rows, archive_requirement)["declaration_progress"]["digest"],
                "manifest_digest": "b" * 64,
            },
        },
        "readback": {
            "status": "verified_persisted_readback",
            "verified": True,
            "promotion_eligible": True,
            "output_identity": "d" * 64,
            "derived_output_digest": "c" * 64,
            "published_at_utc": "2026-08-24T10:00:00.000000+00:00",
        },
    }
    from server.sli.storage.warm_tier_incremental_copy_runtime import (
        _expected_derived_output_row,
    )

    evidence["derived_publication"]["descriptor_lifecycle"] = evidence[
        "descriptor_lifecycle"
    ]
    manifest = evidence["derived_publication"]["manifest"]
    manifest.update({
        "contract": "sli.warm-derived-publication.v1",
        "archive_requirement": archive_requirement,
        "read_representation": evidence["descriptor_lifecycle"]["read_representation"],
        "source_ids": [int(row["id"]) for row in rows],
        "candidate_identity_sha256": evidence["descriptor_lifecycle"]["candidate_identity_sha256"],
        "readback_required": True,
    })
    manifest["manifest_digest"] = hashlib.sha256(json.dumps(
        {key: value for key, value in manifest.items() if key != "manifest_digest"},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    expected = _expected_derived_output_row(evidence["derived_publication"])
    evidence["readback"]["output_identity"] = expected["output_identity"]
    return evidence


def _resolver(*_args, **_kwargs):
    return _resolution()


def test_no_archive_promotion_requires_a_durable_continuity_identity() -> None:
    rows = [_row(10, 1)]
    evidence = _evidence(rows)
    evidence["descriptor_lifecycle"].pop("continuity_declaration_sha256")

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=evidence,
    )

    assert result["status"] == "blocked"
    assert "durable_continuity_declaration_missing" in result["blockers"]


def _build_absent_exact_retry(monkeypatch, tmp_path: Path, evidence: dict) -> dict:
    cutoff = datetime(2026, 7, 27, tzinfo=timezone.utc)
    copy_evidence = tmp_path / "copy-evidence.json"
    copy_evidence.write_text(json.dumps({"status": "verified", "checks": {}}), encoding="utf-8")

    class Cursor:
        def __init__(self, name=None):
            self.name = name
            self.row = {}

        def __enter__(self): return self
        def __exit__(self, *_args): return False

        def execute(self, query, _params=None):
            if "select now()" in query:
                self.row = {"cutoff": cutoff}
            elif "candidate_count" in query:
                self.row = {
                    "candidate_count": 0, "min_id": None, "max_id": None,
                    "oldest_utc": None, "newest_candidate_utc": None,
                    "checked_at_utc": cutoff,
                }

        def fetchone(self): return self.row
        def fetchmany(self, _size): return []

    class Conn:
        def __enter__(self): return self
        def __exit__(self, *_args): return False
        def execute(self, _query): return None
        def cursor(self, name=None): return Cursor(name)

    monkeypatch.setattr(plan_runtime, "load_storage_policy", plan_runtime.StoragePolicy)
    monkeypatch.setattr(plan_runtime, "verify_backup", lambda: {"valid": True})
    monkeypatch.setattr(plan_runtime, "COPY_EVIDENCE", copy_evidence)
    monkeypatch.setattr(plan_runtime, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(plan_runtime, "_http_query", lambda *_args: b"0\n")
    monkeypatch.setattr(plan_runtime, "_connect", Conn)
    monkeypatch.setattr(plan_runtime, "_restrictive_references", lambda *_a: {
        "rows": 0, "event_ids": [], "tables": [],
    })
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)
    return plan_runtime.build_full_plan(
        cutoff_utc=cutoff,
        candidate_manifest=tmp_path / "candidates.bin",
        promotion_evidence=evidence,
    )


def test_exact_absent_retry_returns_bound_processed_package_checkpoint(
    monkeypatch, tmp_path: Path,
) -> None:
    evidence = _evidence([_row(10, 1), _row(11, 2)])

    result = _build_absent_exact_retry(monkeypatch, tmp_path, evidence)

    assert result["status"] == "no_candidates"
    assert result["processed_package_checkpoint"] == {
        "declaration_progress": evidence["descriptor_lifecycle"]["declaration_progress"],
        "progress_digest": evidence["descriptor_lifecycle"]["declaration_progress"]["digest"],
        "promotion_output_identity": evidence["readback"]["output_identity"],
    }


def test_malformed_evidence_cannot_become_clean_absent_retry(
    monkeypatch, tmp_path: Path,
) -> None:
    evidence = _evidence([_row(10, 1), _row(11, 2)])
    evidence["descriptor_lifecycle"]["declaration_progress"]["declaration_ids"] = [99]

    result = _build_absent_exact_retry(monkeypatch, tmp_path, evidence)

    assert result["status"] == "blocked"
    assert "processed_package_checkpoint" not in result


def test_verified_no_archive_promotion_allows_exact_old_source_ids(monkeypatch) -> None:
    rows = [_row(10, 1), _row(11, 2)]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=_evidence(rows),
    )

    assert result["status"] == "ready_for_owner_authorization"
    assert result["candidate_ids"] == [10, 11]
    assert result["promotion_gate"]["read_availability"] == "derived_only_available"


def test_verified_no_archive_missing_close_preserves_source(
    monkeypatch,
) -> None:
    rows = [_row(10, 1)]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=_evidence(
            rows,
            derived=[
                _derived_row(
                    state="incomplete",
                    quality_reason="incomplete_missing_close",
                    logoff_time_utc=None,
                    duration_seconds=None,
                    logoff_source_event_id=None,
                    logoff_normalized_hash=None,
                )
            ],
        ),
    )

    assert result["status"] == "blocked"
    assert result["candidate_ids"] == []
    assert "incomplete_or_gap_derived_output_not_deletable" in result["blockers"]


def test_verified_no_archive_gap_preserves_source(monkeypatch) -> None:
    rows = [_row(10, 1)]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=_evidence(
            rows,
            derived=[
                _derived_row(
                    state="incomplete",
                    quality_reason="incomplete_coverage_gap",
                    logoff_time_utc=None,
                    duration_seconds=None,
                    logoff_source_event_id=None,
                    logoff_normalized_hash=None,
                )
            ],
        ),
    )

    assert result["status"] == "blocked"
    assert result["candidate_ids"] == []
    assert "incomplete_or_gap_derived_output_not_deletable" in result["blockers"]


def test_unverified_or_unsafe_incomplete_output_keeps_source(monkeypatch) -> None:
    rows = [_row(10, 1)]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=_evidence(
            rows,
            derived=[
                _derived_row(
                    state="incomplete",
                    quality_reason="incomplete_coverage_unproven",
                    logoff_time_utc=None,
                    duration_seconds=None,
                    logoff_source_event_id=None,
                    logoff_normalized_hash=None,
                )
            ],
        ),
    )

    assert result["status"] == "blocked"
    assert result["candidate_ids"] == []
    assert "incomplete_or_gap_derived_output_not_deletable" in result["blockers"]


def test_archive_required_promotion_needs_archive_proof(monkeypatch) -> None:
    rows = [_row(10, 1)]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)
    evidence = _evidence(rows, archive_requirement="archive_required")
    monkeypatch.setattr(
        plan_runtime, "resolve_descriptor_retention",
        lambda *_args, **_kwargs: _resolution("archive_required"),
    )

    blocked = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=evidence,
    )
    ready = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=evidence,
        archive_proof={"verified": True},
    )

    assert "archive_proof_not_verified" in blocked["blockers"]
    assert ready["status"] == "ready_for_owner_authorization"
    assert ready["promotion_gate"]["read_availability"] == "source_archived"


def test_promotion_gate_rejects_oversized_source_reference_set(monkeypatch) -> None:
    rows = [_row(index + 1, 1) for index in range(plan_runtime.MAX_PROMOTION_REFERENCES + 1)]
    evidence = _evidence(rows[:1])
    evidence["derived_publication"]["source_references"] = [
        {"id": int(row["id"]), "sha256": bytes(row["normalized_hash"]).hex()}
        for row in rows
    ]
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=rows,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=evidence,
    )

    assert result["status"] == "blocked"
    assert "promotion_source_reference_count_out_of_bounds" in result["blockers"]


def test_promotion_evidence_reader_rejects_oversized_file(tmp_path: Path) -> None:
    evidence = tmp_path / "promotion.json"
    evidence.write_bytes(b" " * (plan_runtime.MAX_PROMOTION_EVIDENCE_BYTES + 1))

    with pytest.raises(RuntimeError, match="promotion_evidence_too_large"):
        plan_runtime.load_promotion_evidence(evidence)


def test_copy_evidence_reader_rejects_oversized_file(tmp_path: Path) -> None:
    evidence = tmp_path / "copy.json"
    evidence.write_bytes(b" " * (plan_runtime.MAX_COPY_EVIDENCE_BYTES + 1))

    with pytest.raises(RuntimeError, match="copy_evidence_too_large"):
        plan_runtime.load_copy_evidence(evidence)


@pytest.mark.parametrize(
    ("mutate", "backup_valid", "status", "published"),
    [
        (lambda evidence: None, True, "ready_for_owner_authorization", True),
        (
            lambda evidence: evidence["readback"].update(verified=False),
            True,
            "blocked",
            False,
        ),
        (
            lambda evidence: evidence["derived_publication"]["source_references"].__setitem__(
                1, {"id": 12, "sha256": "02" * 32},
            ),
            True,
            "blocked",
            False,
        ),
        (
            lambda evidence: evidence["derived_publication"]["derived"].__setitem__(
                0,
                _derived_row(
                    state="incomplete",
                    quality_reason="incomplete_missing_close",
                    logoff_time_utc=None,
                    duration_seconds=None,
                    logoff_source_event_id=None,
                    logoff_normalized_hash=None,
                ),
            ),
            True,
            "blocked",
            False,
        ),
        (lambda evidence: None, False, "ready_for_owner_authorization", True),
        (
            lambda evidence: evidence["derived_publication"]["derived"].__setitem__(
                0,
                _derived_row(
                    state="incomplete",
                    quality_reason="incomplete_coverage_unproven",
                    logoff_time_utc=None,
                    duration_seconds=None,
                    logoff_source_event_id=None,
                    logoff_normalized_hash=None,
                ),
            ),
            True,
            "blocked",
            False,
        ),
    ],
    ids=(
        "verified_no_archive",
        "failed_persisted_readback",
        "reference_mismatch",
        "verified_no_archive_missing_close",
        "no_archive_bypasses_durable_backup",
        "unsafe_no_archive_incomplete_keeps_source",
    ),
)
def test_full_plan_binds_no_archive_promotion_before_publishing_manifest(
    monkeypatch, tmp_path: Path, mutate, backup_valid: bool, status: str, published: bool,
) -> None:
    rows = [_row(10, 1), _row(11, 2)]
    evidence = _evidence(rows)
    mutate(evidence)
    cutoff = datetime(2026, 7, 27, tzinfo=timezone.utc)
    copy_evidence = tmp_path / "copy-evidence.json"
    copy_evidence.write_text(json.dumps({"status": "verified", "checks": {}}), encoding="utf-8")
    manifest = tmp_path / "candidates.bin"

    class Cursor:
        def __init__(self, name=None) -> None:
            self.name = name
            self._page = False
            self._row = {}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, _params=None):
            if "select now()" in query:
                self._row = {"cutoff": cutoff}
            elif "candidate_count" in query:
                self._row = {
                    "candidate_count": len(rows),
                    "min_id": 10,
                    "max_id": 11,
                    "oldest_utc": rows[0]["time_created_utc"],
                    "newest_candidate_utc": rows[-1]["time_created_utc"],
                    "checked_at_utc": cutoff,
                }

        def fetchone(self):
            return self._row

        def fetchmany(self, _size):
            if self._page:
                return []
            self._page = True
            return rows

    class Conn:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, _query):
            return None

        def cursor(self, name=None):
            return Cursor(name)

    monkeypatch.setattr(plan_runtime, "load_storage_policy", plan_runtime.StoragePolicy)
    backup_calls = 0

    def verify_backup():
        nonlocal backup_calls
        backup_calls += 1
        return {"valid": backup_valid}

    monkeypatch.setattr(plan_runtime, "verify_backup", verify_backup)
    monkeypatch.setattr(plan_runtime, "COPY_EVIDENCE", copy_evidence)
    monkeypatch.setattr(plan_runtime, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(plan_runtime, "_http_query", lambda *_args: b"0\n")
    monkeypatch.setattr(plan_runtime, "_connect", Conn)
    monkeypatch.setattr(
        plan_runtime,
        "_restrictive_references",
        lambda *_args: {"rows": 0, "event_ids": [], "tables": []},
    )
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_full_plan(
        cutoff_utc=cutoff,
        candidate_manifest=manifest,
        promotion_evidence=evidence,
    )

    assert result["status"] == status
    assert backup_calls == 0
    assert result["backup"] == {"required": False, "valid": True}
    assert result["candidate_manifest"]["published"] is published
    assert manifest.exists() is published
    if published:
        package = tmp_path / "plan.json"
        package.write_text(json.dumps(result, default=str), encoding="utf-8")
        monkeypatch.setattr(executor, "_windows_account", lambda: executor.APPROVED_OWNER)
        monkeypatch.setattr(executor, "resolve_descriptor_retention", _resolver)
        validated = executor.validate_package(package)
        assert validated["status"] == "ready", validated["blockers"]
    if not published:
        assert result["candidate_manifest"]["rows"] == 2
        assert result["promotion_gate"]["archive_requirement"] == "no_archive"
