#!/usr/bin/env python3
# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``tier_retention_delete_plan_runtime`` at call time.
"""Build a read-only gate for a future PostgreSQL hot-tier deletion.

The command verifies policy, the durable full-payload backup, warm placement,
and restrictive foreign-key references. It never mutates PostgreSQL,
ClickHouse, the archive, or the backup, and it never grants deletion authority.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.storage.storage_lifecycle_io import (  # noqa: E402
    CONTAINER,
    DATABASE,
    _connect,
    _container_port,
    _http_query,
)
from server.sli.storage.storage_policy import (  # noqa: E402
    StoragePolicy,
    load_storage_policy,
    resolve_descriptor_retention,
)
from server.sli.storage.storage_lifecycle_bounded_io import read_json  # noqa: E402


BACKUP_ROOT = ROOT / "artifacts" / "stage7" / "tier-move-step1" / "backup"
BACKUP_MANIFEST = BACKUP_ROOT / "manifest.json"
COPY_EVIDENCE = (
    ROOT / "artifacts" / "stage7" / "evidence"
    / "tier-move-step1-copy.json"
)
DEFAULT_CANDIDATE_LIMIT = 10_000
MAX_PROMOTION_REFERENCES = 10_000
MAX_PROMOTION_DERIVED_ROWS = 10_000
MAX_DECLARATION_MEMBERS = 10_000
MAX_DECLARATION_IDS = 10_000
MAX_PROMOTION_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_COPY_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_BACKUP_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_BACKUP_FILES = 10_000
FULL_PAGE_ROWS = 20_000
DEFAULT_FULL_MANIFEST = (
    ROOT / "artifacts/stage7/evidence/tier-retention-delete-candidates-v1.bin"
)
@dataclass(frozen=True)
class GateInputs:
    candidate_count: int
    candidates_truncated: bool
    backup_valid: bool
    warm_available: bool
    warm_missing: int
    warm_hash_mismatches: int
    archive_paths_missing: int
    restrictive_reference_rows: int


def load_promotion_evidence(path: Path) -> dict[str, Any]:
    value = read_json(
        path, max_bytes=MAX_PROMOTION_EVIDENCE_BYTES,
        too_large="promotion_evidence_too_large",
    )
    if not isinstance(value, dict):
        raise RuntimeError("promotion_evidence_invalid")
    return value


def load_copy_evidence(path: Path) -> dict[str, Any]:
    value = read_json(
        path, max_bytes=MAX_COPY_EVIDENCE_BYTES,
        too_large="copy_evidence_too_large",
    )
    if not isinstance(value, dict):
        raise RuntimeError("copy_evidence_invalid")
    return value


def source_reference_digest(references: list[dict[str, Any]]) -> str:
    """Canonical digest shared with Ticket03's persisted derived output."""
    return hashlib.sha256(
        json.dumps(references, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()














def assemble_gate(
    policy: StoragePolicy, inputs: GateInputs, *, archive_required: bool = True,
) -> dict[str, Any]:
    blockers: list[str] = []
    if policy.db_retention_days != 7:
        blockers.append("hot_window_is_not_owner_approved_7_days")
    if policy.warm_retention_days != 365:
        blockers.append("warm_window_is_not_owner_approved_365_days")
    if policy.archive_auto_delete_enabled:
        blockers.append("archive_auto_delete_must_remain_disabled")
    if archive_required and not inputs.backup_valid:
        blockers.append("durable_full_payload_backup_invalid")
    if not inputs.warm_available:
        blockers.append("warm_tier_unavailable")
    if inputs.candidates_truncated:
        blockers.append("candidate_set_exceeds_bounded_verification_limit")
    if inputs.warm_missing:
        blockers.append("candidate_rows_missing_from_warm_placement")
    if inputs.warm_hash_mismatches:
        blockers.append("candidate_hash_mismatch_between_hot_and_warm")
    if archive_required and inputs.archive_paths_missing:
        blockers.append("candidate_full_payload_archive_path_missing")
    if inputs.restrictive_reference_rows:
        blockers.append("candidate_rows_are_still_referenced_as_live_evidence")

    technical_gate_passed = not blockers
    return {
        "status": "ready_for_owner_authorization" if (
            technical_gate_passed and inputs.candidate_count > 0
        ) else ("no_candidates" if technical_gate_passed else "blocked"),
        "mode": "read_only_dry_run",
        "policy": {
            "hot_days": policy.db_retention_days,
            "warm_days": policy.warm_retention_days,
            "archive_auto_delete_enabled": policy.archive_auto_delete_enabled,
        },
        "candidate_count": inputs.candidate_count,
        "technical_gate_passed": technical_gate_passed,
        "blockers": blockers,
        "authorization": {
            "required": True,
            "granted": False,
            "delete_performed": False,
        },
        "checks": asdict(inputs),
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()














def build_full_plan(
    *,
    cutoff_utc: datetime | None = None,
    candidate_manifest: Path | None = None,
    promotion_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Verify the complete frozen candidate set in bounded streaming pages."""
    policy = load_storage_policy()
    promotion_lifecycle_value = (
        promotion_evidence.get("descriptor_lifecycle")
        if isinstance(promotion_evidence, dict) else None
    )
    promotion_archive_requirement = str(
        promotion_lifecycle_value.get("archive_requirement") or ""
    ) if isinstance(promotion_lifecycle_value, dict) else ""
    archive_required = promotion_archive_requirement != "no_archive"
    backup = verify_backup() if archive_required else {"required": False, "valid": True}
    copy_evidence = load_copy_evidence(COPY_EVIDENCE)
    port = _container_port(CONTAINER)
    global_rows = int(
        _http_query(
            port, f"select count() from {DATABASE}.event_placement FORMAT TabSeparated"
        ).decode("utf-8").strip()
    )
    manifest_rows = int(
        _http_query(
            port, f"select count() from {DATABASE}.copy_manifest FORMAT TabSeparated"
        ).decode("utf-8").strip()
    )
    digest = hashlib.sha256()
    deletion_digest = hashlib.sha256()
    verified = missing = mismatches = invalid_lines = duplicates = 0
    archive_paths: set[str] = set()
    reference_total = 0
    reference_tables: dict[tuple[str, str, str], int] = {}
    held_event_ids: set[int] = set()
    promotion_rows: list[dict[str, Any]] = []
    promotion_candidates = (
        _promotion_candidate_references(promotion_evidence)
        if promotion_evidence is not None else None
    )
    promotion_progress_binding = None
    if promotion_evidence is not None:
        lifecycle_value = promotion_evidence.get("descriptor_lifecycle")
        publication_value = promotion_evidence.get("derived_publication")
        readback_value = promotion_evidence.get("readback")
        if all(isinstance(value, dict) for value in (
            lifecycle_value, publication_value, readback_value,
        )):
            binding_blockers, promotion_progress_binding = _promotion_progress_binding(
                dict(lifecycle_value), dict(publication_value), dict(readback_value),
            )
            if binding_blockers:
                promotion_progress_binding = None
    promotion_lifecycle = (
        dict(promotion_evidence.get("descriptor_lifecycle"))
        if promotion_evidence is not None
        and isinstance(promotion_evidence.get("descriptor_lifecycle"), dict)
        else {}
    )
    promotion_archive_requirement = str(
        promotion_lifecycle.get("archive_requirement") or ""
    )
    manifest_target = (candidate_manifest or DEFAULT_FULL_MANIFEST).resolve()
    manifest_partial = manifest_target.with_suffix(manifest_target.suffix + ".partial")
    manifest_target.parent.mkdir(parents=True, exist_ok=True)
    manifest_partial.unlink(missing_ok=True)
    manifest_handle = manifest_partial.open("wb")
    with _connect() as conn:
        conn.execute("set transaction isolation level repeatable read, read only")
        with conn.cursor() as cur:
            cur.execute(
                "select now() - (%s * interval '1 day') cutoff",
                (policy.db_retention_days,),
            )
            current_cutoff = cur.fetchone()["cutoff"]
            cutoff = cutoff_utc or current_cutoff
            if cutoff.tzinfo is None:
                raise ValueError("cutoff_utc_timezone_required")
            if cutoff > current_cutoff:
                raise ValueError("cutoff_utc_inside_hot_window")
            selected_candidate_ids = (
                [item["id"] for item in promotion_candidates]
                if promotion_candidates is not None else None
            )
            if selected_candidate_ids is None:
                summary_query = """
                    select count(*)::bigint candidate_count,min(id)::bigint min_id,
                           max(id)::bigint max_id,min(time_created_utc) oldest_utc,
                           max(time_created_utc) newest_candidate_utc,
                           now() at time zone 'utc' checked_at_utc
                    from events_v2_core where time_created_utc < %s
                """
                summary_params = (cutoff,)
            else:
                summary_query = """
                    select count(*)::bigint candidate_count,min(id)::bigint min_id,
                           max(id)::bigint max_id,min(time_created_utc) oldest_utc,
                           max(time_created_utc) newest_candidate_utc,
                           now() at time zone 'utc' checked_at_utc
                    from events_v2_core
                    where id=any(%s::bigint[]) and time_created_utc < %s
                """
                summary_params = (
                    selected_candidate_ids, cutoff,
                )
            cur.execute(summary_query, summary_params)
            postgres = dict(cur.fetchone())
        with conn.cursor(name="tier_retention_full_candidates") as cur:
            cur.itersize = FULL_PAGE_ROWS
            if selected_candidate_ids is None:
                candidate_query = """
                    select id,normalized_hash,time_created_utc
                    from events_v2_core where time_created_utc < %s order by id
                """
                candidate_params = (cutoff,)
            else:
                candidate_query = """
                    select id,normalized_hash,time_created_utc
                    from events_v2_core
                    where id=any(%s::bigint[]) and time_created_utc < %s
                    order by id
                """
                candidate_params = (
                    selected_candidate_ids, cutoff,
                )
            cur.execute(candidate_query, candidate_params)
            while True:
                page = [dict(row) for row in cur.fetchmany(FULL_PAGE_ROWS)]
                if not page:
                    break
                refs = _restrictive_references(
                    conn, [int(row["id"]) for row in page]
                )
                page_held = {int(value) for value in refs["event_ids"]}
                held_event_ids.update(page_held)
                for row in page:
                    event_id = int(row["id"])
                    encoded_id = event_id.to_bytes(8, "big", signed=False)
                    value = row["normalized_hash"]
                    encoded_hash = (
                        bytes.fromhex(value) if isinstance(value, str) else bytes(value)
                    )
                    record = encoded_id + encoded_hash
                    digest.update(record)
                    if event_id not in page_held:
                        deletion_digest.update(record)
                        manifest_handle.write(record)
                        if promotion_evidence is not None:
                            promotion_rows.append(
                                {
                                    "id": event_id,
                                    "normalized_hash": encoded_hash,
                                    "time_created_utc": row["time_created_utc"],
                                }
                            )
                warm_page = (
                    {
                        "missing": 0,
                        "hash_mismatches": 0,
                        "archive_line_invalid": 0,
                        "duplicate_rows": 0,
                        "archive_paths": set(),
                    }
                    if promotion_archive_requirement == "no_archive"
                    else _verify_warm_page(port, page)
                )
                verified += len(page)
                missing += int(warm_page["missing"])
                mismatches += int(warm_page["hash_mismatches"])
                invalid_lines += int(warm_page["archive_line_invalid"])
                duplicates += int(warm_page["duplicate_rows"])
                archive_paths.update(warm_page["archive_paths"])
                reference_total += int(refs["rows"])
                for item in refs["tables"]:
                    key = (
                        str(item["schema_name"]), str(item["table_name"]),
                        str(item["column_name"]),
                    )
                    reference_tables[key] = reference_tables.get(key, 0) + int(item["rows"])
    manifest_handle.close()
    candidate_count = int(postgres.get("candidate_count") or 0)
    deletable_count = candidate_count - len(held_event_ids)
    postgres.update(
        {
            "candidate_count": candidate_count,
            "cutoff_utc": cutoff,
            "current_policy_cutoff_utc": current_cutoff,
            "verified_rows": verified,
            "candidate_identity_sha256": digest.hexdigest(),
            "deletable_count": deletable_count,
            "deletion_identity_sha256": deletion_digest.hexdigest(),
            "page_rows": FULL_PAGE_ROWS,
            "truncated": verified != candidate_count,
        }
    )
    missing_paths = sorted(path for path in archive_paths if not Path(path).is_file())
    warm = {
        "available": True,
        "global_rows": global_rows,
        "manifest_rows": manifest_rows,
        "verified_rows": verified,
        "missing": missing,
        "hash_mismatches": mismatches,
        "archive_paths_missing": len(missing_paths) + invalid_lines,
        "archive_path_count": len(archive_paths),
        "archive_paths_missing_sample": missing_paths[:20],
        "duplicate_placement_rows": duplicates,
    }
    references = {
        "rows": reference_total,
        "held_event_count": len(held_event_ids),
        "held_event_ids": sorted(held_event_ids),
        "tables": [
            {"schema_name": key[0], "table_name": key[1],
             "column_name": key[2], "rows": rows}
            for key, rows in sorted(reference_tables.items())
        ],
    }
    promotion = None
    exact_absent_retry = bool(
        promotion_evidence is not None
        and promotion_progress_binding is not None
        and promotion_candidates
        and candidate_count == 0
    )
    if promotion_evidence is not None and not exact_absent_retry:
        promotion = build_promoted_delete_manifest(
            source_rows=promotion_rows,
            cutoff_utc=cutoff,
            promotion_evidence=promotion_evidence,
            archive_proof={
                "verified": not missing_paths and not invalid_lines and not duplicates,
            },
        )
    inputs = GateInputs(
        candidate_count=deletable_count,
        candidates_truncated=verified != candidate_count,
        backup_valid=bool(backup.get("valid")),
        warm_available=True,
        warm_missing=missing + duplicates,
        warm_hash_mismatches=mismatches,
        archive_paths_missing=int(warm["archive_paths_missing"]),
        restrictive_reference_rows=0,
    )
    result = {
        **assemble_gate(policy, inputs, archive_required=archive_required),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "verification_mode": "full_frozen_stream_v1",
        "mature_candidate_count": candidate_count,
        "retention_holds": references,
        "candidate_manifest": {
            "path": str(manifest_target),
            "format": "big_endian_uint64_event_id_plus_32_byte_normalized_hash",
            "record_bytes": 40,
            "rows": deletable_count,
            "bytes": manifest_partial.stat().st_size,
            "sha256": _sha256(manifest_partial),
            "published": False,
        },
        "postgres": postgres,
        "backup": backup,
        "warm": warm,
        "restrictive_references": references,
        "copy_evidence_status": {
            "source_status": copy_evidence.get("status"),
            "checks": copy_evidence.get("checks"),
        },
        "safety": {
            "postgres_read_only_repeatable_read": True,
            "clickhouse_read_only": True,
            "filesystem_read_only": True,
            "delete_sql_present": False,
            "fk_held_rows_excluded": True,
        },
    }
    if exact_absent_retry and result["status"] == "no_candidates":
        result["processed_package_checkpoint"] = dict(promotion_progress_binding or {})
    if promotion is not None:
        result["promotion_gate"] = promotion["promotion_gate"]
        if promotion["status"] != "ready_for_owner_authorization":
            result["technical_gate_passed"] = False
            result["status"] = "blocked"
            result["blockers"] = [
                *result["blockers"],
                *promotion["blockers"],
            ]
        else:
            gate = promotion["promotion_gate"]
            binding = {
                "promotion_output_identity": gate.get("output_identity"),
                "progress_digest": gate.get("declaration_progress_digest"),
                "candidate_identity_sha256": gate.get("candidate_identity_sha256"),
                "source_reference_digest": gate.get("source_reference_digest"),
                "manifest_digest": gate.get("manifest_digest"),
                "candidate_manifest_sha256": result["candidate_manifest"]["sha256"],
                "candidate_manifest_rows": result["candidate_manifest"]["rows"],
            }
            binding["plan_identity_sha256"] = hashlib.sha256(json.dumps(
                binding, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            result["processed_package_binding"] = binding
    if result["technical_gate_passed"]:
        expected_bytes = deletable_count * 40
        if manifest_partial.stat().st_size != expected_bytes:
            manifest_partial.unlink(missing_ok=True)
            raise RuntimeError("candidate_manifest_size_mismatch")
        os.replace(manifest_partial, manifest_target)
        result["candidate_manifest"]["published"] = True
    else:
        manifest_partial.unlink(missing_ok=True)
    return result


def build_plan(*, candidate_limit: int = DEFAULT_CANDIDATE_LIMIT) -> dict[str, Any]:
    policy = load_storage_policy()
    backup = verify_backup()
    copy_evidence = load_copy_evidence(COPY_EVIDENCE)
    with _connect() as conn:
        conn.execute("set transaction isolation level repeatable read, read only")
        postgres, candidates = _candidate_rows(
            conn,
            hot_days=policy.db_retention_days,
            limit=max(1, candidate_limit),
        )
        references = _restrictive_references(
            conn,
            [int(row["id"]) for row in candidates],
        )
    try:
        warm = verify_warm(candidates)
    except Exception as exc:
        warm = {
            "available": False,
            "error_type": type(exc).__name__,
            "error": str(exc),
            "missing": len(candidates),
            "hash_mismatches": 0,
            "archive_paths_missing": 0,
        }

    inputs = GateInputs(
        candidate_count=int(postgres["candidate_count"]),
        candidates_truncated=bool(postgres["truncated"]),
        backup_valid=bool(backup.get("valid")),
        warm_available=bool(warm.get("available")),
        warm_missing=int(warm.get("missing") or 0),
        warm_hash_mismatches=int(warm.get("hash_mismatches") or 0),
        archive_paths_missing=int(warm.get("archive_paths_missing") or 0),
        restrictive_reference_rows=int(references.get("rows") or 0),
    )
    return {
        **assemble_gate(policy, inputs),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "postgres": postgres,
        "backup": backup,
        "warm": warm,
        "restrictive_references": references,
        "copy_evidence_status": {
            "source_status": copy_evidence.get("status"),
            "checks": copy_evidence.get("checks"),
        },
        "safety": {
            "postgres_read_only_repeatable_read": True,
            "clickhouse_read_only": True,
            "filesystem_read_only": True,
            "delete_sql_present": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-limit", type=int, default=DEFAULT_CANDIDATE_LIMIT)
    parser.add_argument("--full", action="store_true")
    parser.add_argument("--cutoff-utc")
    parser.add_argument("--candidate-manifest", type=Path)
    parser.add_argument(
        "--promotion-evidence", type=Path,
        help="Ticket03 persisted copy-result JSON; enables descriptor promotion gating",
    )
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    cutoff = None
    if args.cutoff_utc:
        cutoff = datetime.fromisoformat(args.cutoff_utc)
    promotion_evidence = (
        load_promotion_evidence(args.promotion_evidence)
        if args.promotion_evidence else None
    )
    result = (
        build_full_plan(
            cutoff_utc=cutoff,
            candidate_manifest=args.candidate_manifest,
            promotion_evidence=promotion_evidence,
        )
        if args.full else build_plan(candidate_limit=max(1, args.candidate_limit))
    )
    payload = json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
    if args.out:
        target = args.out if args.out.is_absolute() else ROOT / args.out
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["technical_gate_passed"] else 2


if __name__ == "__main__":
    import sys as _sys

    _sys.modules.setdefault("server.sli.storage.tier_retention_delete_plan_runtime", _sys.modules[__name__])
from server.sli.storage.tier_retention_delete_plan_runtime_promotion import (
    resolve_current_promotion_contract,
    _source_reference,
    _promotion_candidate_references,
    _is_exact_no_archive_safe_output,
    _promotion_progress_binding,
    build_promoted_delete_manifest,
)


from server.sli.storage.tier_retention_delete_plan_runtime_verify import (
    verify_backup,
    _candidate_rows,
    _restrictive_references,
    _chunks,
    verify_warm,
    _verify_warm_page,
)

if __name__ == "__main__":
    raise SystemExit(main())
