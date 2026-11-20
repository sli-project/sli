from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

from tests.storage.test_tier_retention_promotion_gate import _evidence, _resolution, _resolver, _row

import server.sli.storage.tier_retention_delete_plan_runtime as plan_runtime


def test_full_plan_excludes_unrelated_mature_rows_from_a_promoted_manifest(
    monkeypatch, tmp_path: Path,
) -> None:
    """A descriptor gate may authorize only the exact immutable source set."""
    promoted = [_row(10, 1), _row(11, 2)]
    unrelated = _row(12, 3)
    all_rows = [*promoted, unrelated]
    cutoff = datetime(2026, 7, 27, tzinfo=timezone.utc)
    copy_evidence = tmp_path / "copy-evidence.json"
    copy_evidence.write_text(json.dumps({"status": "verified", "checks": {}}), encoding="utf-8")
    manifest = tmp_path / "candidates.bin"

    class Cursor:
        def __init__(self, name=None) -> None:
            self.name = name
            self._page = False
            self._row = {}
            self.rows = all_rows

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def execute(self, query, params=None):
            if "select now()" in query:
                self._row = {"cutoff": cutoff}
            elif "candidate_count" in query:
                count = len(params[0]) if len(params or ()) > 1 else len(all_rows)
                self._row = {
                    "candidate_count": count, "min_id": 10, "max_id": 12,
                    "oldest_utc": cutoff, "newest_candidate_utc": cutoff,
                    "checked_at_utc": cutoff,
                }
            elif "from events_v2_core" in query and "normalized_hash" in query:
                requested = set(params[0]) if len(params or ()) > 1 else set()
                self.rows = [row for row in all_rows if int(row["id"]) in requested]

        def fetchone(self):
            return self._row

        def fetchmany(self, _size):
            if self._page:
                return []
            self._page = True
            return self.rows

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
    monkeypatch.setattr(plan_runtime, "verify_backup", lambda: {"valid": True})
    monkeypatch.setattr(plan_runtime, "COPY_EVIDENCE", copy_evidence)
    monkeypatch.setattr(plan_runtime, "_container_port", lambda _container: 8123)
    monkeypatch.setattr(plan_runtime, "_http_query", lambda *_args: b"0\n")
    monkeypatch.setattr(plan_runtime, "_connect", Conn)
    monkeypatch.setattr(
        plan_runtime, "_restrictive_references",
        lambda *_args: {"rows": 0, "event_ids": [], "tables": []},
    )
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_full_plan(
        cutoff_utc=cutoff,
        candidate_manifest=manifest,
        promotion_evidence=_evidence(promoted),
    )

    assert result["status"] == "ready_for_owner_authorization"
    assert result["candidate_count"] == 2
    assert result["candidate_manifest"]["rows"] == 2
    assert manifest.read_bytes() == (
        (10).to_bytes(8, "big") + bytes([1]) * 32
        + (11).to_bytes(8, "big") + bytes([2]) * 32
    )


def test_archive_required_promotion_uses_the_canonical_persisted_output_gate(
    monkeypatch,
) -> None:
    promoted = [_row(10, 1), _row(11, 2)]
    monkeypatch.setattr(
        plan_runtime,
        "resolve_descriptor_retention",
        lambda *_args: _resolution("archive_required"),
    )

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=promoted,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=_evidence(promoted, archive_requirement="archive_required"),
        archive_proof={"verified": True},
    )

    gate = result["promotion_gate"]
    assert result["status"] == "ready_for_owner_authorization"
    assert gate["contract"] == "sli.tier-retention-promotion-gate.v1"
    assert gate["archive_requirement"] == "archive_required"
    assert gate["continuity_declaration_scope_identity"]
    assert gate["output_identity"]
    assert "evidence_kind" not in gate
    assert not hasattr(plan_runtime, "build_archive_copy_promotion_gate")


def test_promotion_rejects_swapped_declaration_progress(monkeypatch) -> None:
    promoted = [_row(10, 1), _row(11, 2)]
    evidence = _evidence(promoted)
    evidence["descriptor_lifecycle"]["declaration_progress"] = {
        **evidence["descriptor_lifecycle"]["declaration_progress"],
        "declaration_ids": [23],
    }
    monkeypatch.setattr(plan_runtime, "resolve_descriptor_retention", _resolver)

    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=promoted,
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence=evidence,
    )

    assert result["status"] == "blocked"
    assert "declaration_progress_evidence_mismatch" in result["blockers"]


def test_malformed_promotion_evidence_is_blocked_not_clean_no_candidates() -> None:
    result = plan_runtime.build_promoted_delete_manifest(
        source_rows=[],
        cutoff_utc=datetime(2026, 7, 27, tzinfo=timezone.utc),
        promotion_evidence={"descriptor_lifecycle": "malformed"},
    )

    assert result["status"] == "blocked"
    assert result["blockers"]
