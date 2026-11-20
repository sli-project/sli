#!/usr/bin/env python3
"""Source-only finalizer gate for DB-STORAGE-OPT-1."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
CONTRACT_PATH = PROJECT_ROOT / "config" / "db_storage_opt1_finalizer.json"


def _check(name: str, ok: bool, actual: Any, expected: Any) -> dict[str, Any]:
    return {"name": name, "status": "ok" if ok else "failed", "actual": actual, "expected": expected}


def validate(root: Path = PROJECT_ROOT) -> dict[str, Any]:
    contract = json.loads((root / CONTRACT_PATH.relative_to(PROJECT_ROOT)).read_text(encoding="utf-8"))
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, actual: Any = None, expected: Any = None) -> None:
        checks.append(_check(name, bool(ok), actual, expected))

    add("stage_id", contract.get("stage") == "DB-STORAGE-OPT-1-FINALIZER", contract.get("stage"), "DB-STORAGE-OPT-1-FINALIZER")
    add("source_ready_finalization_blocked", contract.get("status") == "source_ready_finalization_blocked", contract.get("status"), "source_ready_finalization_blocked")

    expected_gates = [
        "STORAGE-V2-CONTROLLED-PRODUCTION-PREP-1",
        "STORAGE-V2-CONTROLLED-PRODUCTION-BACKFILL-1",
        "STORAGE-V2-FUNCTIONAL-SHADOW-1",
        "STORAGE-V2-READ-WRITE-CUTOVER-1",
        "STORAGE-V2-EXTERNAL-FK-CUTOVER-1",
        "STORAGE-V2-DR-RECLAIM-1",
    ]
    add("accepted_source_gate_inventory", contract.get("accepted_source_gates") == expected_gates, contract.get("accepted_source_gates"), expected_gates)

    live = contract.get("required_live_evidence_before_final_acceptance") or []
    live_ids = {str(item.get("id")) for item in live}
    expected_live = {"controlled_production_backfill", "functional_shadow", "read_write_cutover", "external_fk_cutover", "dr_reclaim"}
    add("required_live_evidence_exact", live_ids == expected_live, sorted(live_ids), sorted(expected_live))
    add("live_evidence_has_required_status_and_proofs", all(item.get("required_status") and item.get("must_prove") for item in live), live, "status + proofs")

    measurements = set(str(item) for item in contract.get("final_acceptance_measurements") or [])
    required_measurements = {
        "production_database_bytes_before_reclaim",
        "production_database_bytes_after_reclaim",
        "v2_archive_bytes",
        "dump_bytes_after_reclaim",
        "restore_duration_ms_after_reclaim",
        "rto_seconds_after_reclaim",
        "query_p95_fast_search",
        "query_p95_deep_search_bounded",
    }
    add("final_measurements_cover_size_dr_query", required_measurements.issubset(measurements), sorted(measurements), sorted(required_measurements))

    acceptance = contract.get("acceptance") or {}
    add("acceptance_target_status", acceptance.get("required_status") == "db_storage_opt1_accepted", acceptance.get("required_status"), "db_storage_opt1_accepted")
    add("source_only_finalizer_is_blocked", acceptance.get("source_only_finalizer_status") == "finalization_blocked_waiting_live_evidence", acceptance.get("source_only_finalizer_status"), "finalization_blocked_waiting_live_evidence")
    add("acceptance_requires_live_ratio_and_zero_loss", float(acceptance.get("minimum_measured_ratio") or 0) >= 2.5 and acceptance.get("data_loss") == 0 and acceptance.get("unexplained_functional_mismatches") == 0, acceptance, "ratio>=2.5 and zero loss/mismatch")
    add("acceptance_requires_exact_dropped_relations", acceptance.get("required_dropped_relations") == ["event_entity_links", "events", "observed_entities"], acceptance.get("required_dropped_relations"), ["event_entity_links", "events", "observed_entities"])
    add("acceptance_refuses_source_only", acceptance.get("finalizer_accepts_without_live_evidence") is False and acceptance.get("backup_restore_required") is True, acceptance, "no source-only acceptance")

    forbidden = " ".join(str(item).casefold() for item in contract.get("strictly_forbidden") or [])
    for token in (
        "source-only gates",
        "before live reclaim",
        "post-reclaim database size",
        "backups or archives were deleted",
        "sql rollback is claimed",
    ):
        add(f"forbidden_contains_{token.replace(' ', '_').replace('-', '_')}", token in forbidden, contract.get("strictly_forbidden"), f"contains {token}")

    next_stage = contract.get("next_stage_after_live_acceptance") or {}
    add("next_stage_not_authorized_by_source_only", next_stage.get("id") == "SECURITY-PACKAGING-BOUNDARY-1" and next_stage.get("authorized_by_this_source_only_finalizer") is False, next_stage, "next stage named but not authorized")

    failures = [item["name"] for item in checks if item["status"] != "ok"]
    return {
        "stage": "DB-STORAGE-OPT-1-FINALIZER",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "finalization_blocked_waiting_live_evidence" if not failures else "failed",
        "db_storage_opt1_accepted": False,
        "source_only_path_complete": not failures,
        "live_reclaim_evidence_present": False,
        "next_stage_authorized": False,
        "expensive_operations": {
            "postgres_connections": 0,
            "restore_runs": 0,
            "production_migrations": 0,
            "production_backfill_runs": 0,
            "server_starts": 0,
        },
        "checks": checks,
        "failures": failures,
        "next_required_action": "run live controlled Storage V2 sequence only with explicit operator approval" if not failures else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    result = validate(PROJECT_ROOT)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if result["status"] == "finalization_blocked_waiting_live_evidence" else 2


if __name__ == "__main__":
    raise SystemExit(main())
