from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts.maintenance.db_storage_opt1_finalizer import validate

ROOT = Path(__file__).resolve().parents[2]


def _contract() -> dict:
    return json.loads((ROOT / "config" / "db_storage_opt1_finalizer.json").read_text(encoding="utf-8"))


def test_finalizer_blocks_acceptance_without_live_evidence() -> None:
    result = validate(ROOT)
    assert result["status"] == "finalization_blocked_waiting_live_evidence"
    assert result["failures"] == []
    assert result["db_storage_opt1_accepted"] is False
    assert result["source_only_path_complete"] is True
    assert result["live_reclaim_evidence_present"] is False
    assert result["next_stage_authorized"] is False


def test_finalizer_requires_all_live_evidence_categories() -> None:
    live = {item["id"]: item for item in _contract()["required_live_evidence_before_final_acceptance"]}
    assert set(live) == {
        "controlled_production_backfill",
        "functional_shadow",
        "read_write_cutover",
        "external_fk_cutover",
        "dr_reclaim",
    }
    assert live["dr_reclaim"]["required_status"] == "reclaim_completed_with_verified_dr"
    assert "fresh external restore proof" in live["dr_reclaim"]["must_prove"]


def test_finalizer_requires_measured_size_restore_and_query_results() -> None:
    measurements = set(_contract()["final_acceptance_measurements"])
    for required in [
        "production_database_bytes_before_reclaim",
        "production_database_bytes_after_reclaim",
        "v2_archive_bytes",
        "dump_bytes_after_reclaim",
        "restore_duration_ms_after_reclaim",
        "rto_seconds_after_reclaim",
        "query_p95_fast_search",
        "query_p95_deep_search_bounded",
    ]:
        assert required in measurements


def test_finalizer_strictly_forbids_source_only_acceptance() -> None:
    contract = _contract()
    acceptance = contract["acceptance"]
    assert acceptance["finalizer_accepts_without_live_evidence"] is False
    assert acceptance["backup_restore_required"] is True
    assert acceptance["minimum_measured_ratio"] >= 2.5
    assert acceptance["required_dropped_relations"] == ["event_entity_links", "events", "observed_entities"]
    forbidden = "\n".join(contract["strictly_forbidden"]).casefold()
    for token in [
        "source-only gates",
        "before live reclaim",
        "post-reclaim database size",
        "backups or archives were deleted",
        "sql rollback is claimed",
    ]:
        assert token in forbidden


def test_validator_runs_as_direct_script(tmp_path: Path) -> None:
    out = tmp_path / "finalizer.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "maintenance" / "db_storage_opt1_finalizer.py"),
            "--json-out",
            str(out),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["status"] == "finalization_blocked_waiting_live_evidence"
