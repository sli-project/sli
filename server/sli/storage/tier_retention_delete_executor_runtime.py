#!/usr/bin/env python3
"""Execute one owner-authorized frozen PostgreSQL hot-retention manifest.

The executor never calculates a moving retention set. It accepts only the
published binary manifest produced by ``tier_retention_delete_plan.py --full``
and rechecks identity, policy, cutoff, hashes and restrictive references
before every bounded commit.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.storage.tier_retention_delete_plan_runtime import (  # noqa: E402
    _restrictive_references,
    resolve_current_promotion_contract,
)
from server.sli.core.app_config import load_config  # noqa: E402
from server.sli.storage.storage_policy import load_storage_policy  # noqa: E402
from server.sli.storage.storage_policy import resolve_descriptor_retention  # noqa: E402
from server.sli.storage.storage_lifecycle_bounded_io import read_bytes  # noqa: E402


DEFAULT_PLAN = ROOT / "artifacts/stage7/evidence/tier-retention-delete-plan-full.json"
DEFAULT_OUTPUT = ROOT / "artifacts/stage7/evidence/tier-retention-delete-execution.json"
CONFIRMATION = "APPLY-STAGE7-HOT-RETENTION-DELETE"
APPROVED_OWNER = "EXAMPLE\\operator"
RECORD = struct.Struct(">Q32s")
MAX_BATCH = 10_000
MAX_CANDIDATE_MANIFEST_BYTES = MAX_BATCH * RECORD.size
MAX_PLAN_JSON_BYTES = 2 * 1024 * 1024
MAX_PROMOTION_REFERENCES = 10_000
MAX_DECLARATION_MEMBERS = 10_000
MAX_DECLARATION_IDS = 10_000


def _read_file_bounded(path: Path, *, max_bytes: int, too_large: str) -> bytes:
    """Use the shared stable descriptor reader at this trust boundary."""
    return read_bytes(path, max_bytes=max_bytes, too_large=too_large)


@dataclass(frozen=True)
class _ValidatedManifestBatch:
    """The exact immutable manifest bytes authorized for one delete transaction."""

    raw: bytes
    records: tuple[tuple[int, bytes], ...]
    ids: tuple[int, ...]
    hashes: tuple[bytes, ...]


class _ValidatedPackage(dict[str, Any]):
    """Preflight result carrying execution-only immutable inputs.

    The batch is deliberately an attribute rather than result data: caller
    output remains JSON-safe while ``execute`` cannot re-read the manifest.
    """

    def __init__(
        self,
        result: dict[str, Any],
        *,
        plan: dict[str, Any],
        manifest_batch: _ValidatedManifestBatch,
    ) -> None:
        super().__init__(result)
        self.plan = plan
        self.manifest_batch = manifest_batch


def _is_hex64(value: object) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(character in "0123456789abcdef" for character in text)


def _windows_account() -> str:
    try:
        completed = subprocess.run(
            ["whoami"], capture_output=True, text=True, check=True, timeout=10
        )
        value = completed.stdout.strip()
        if value:
            return value
    except (OSError, subprocess.SubprocessError):
        pass
    domain = os.getenv("USERDOMAIN", "").strip()
    user = getpass.getuser().strip()
    return f"{domain}\\{user}" if domain else user


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    os.replace(partial, path)


def _validated_manifest_batch(raw: bytes) -> _ValidatedManifestBatch:
    if len(raw) % RECORD.size:
        raise RuntimeError("candidate_manifest_partial_record")
    previous = 0
    records: list[tuple[int, bytes]] = []
    for offset in range(0, len(raw), RECORD.size):
        event_id, normalized_hash = RECORD.unpack(raw[offset:offset + RECORD.size])
        if event_id <= previous:
            raise RuntimeError("candidate_manifest_ids_not_strictly_increasing")
        previous = event_id
        records.append((event_id, normalized_hash))
    frozen_records = tuple(records)
    return _ValidatedManifestBatch(
        raw=raw,
        records=frozen_records,
        ids=tuple(event_id for event_id, _normalized_hash in frozen_records),
        hashes=tuple(normalized_hash for _event_id, normalized_hash in frozen_records),
    )


def _promotion_gate_blockers(
    plan: dict[str, Any], manifest_batch: _ValidatedManifestBatch,
) -> list[str]:
    """Validate the descriptor-promotion extension of a frozen package.

    Every destructive package must bind every binary manifest record to the
    same current descriptor policy and persisted-output proof. Missing proof
    is never interpreted as a legacy downgrade.
    """
    gate = plan.get("promotion_gate")
    if gate is None:
        return ["promotion_gate_required"]
    if not isinstance(gate, dict):
        return ["promotion_gate_invalid"]
    blockers: list[str] = []
    if gate.get("contract") != "sli.tier-retention-promotion-gate.v1":
        blockers.append("promotion_gate_contract_mismatch")
    if gate.get("evidence_kind") is not None:
        return [*blockers, "promotion_gate_evidence_kind_invalid"]
    references_value = gate.get("source_references") or []
    if not isinstance(references_value, list) or len(references_value) > MAX_PROMOTION_REFERENCES:
        return [*blockers, "promotion_gate_source_reference_count_out_of_bounds"]
    references = list(references_value)
    try:
        expected = [
            (int(row["id"]), bytes.fromhex(str(row["sha256"])))
            for row in references
        ]
    except (KeyError, TypeError, ValueError):
        expected = []
        blockers.append("promotion_gate_source_references_invalid")
    if tuple(expected) != manifest_batch.records:
        blockers.append("promotion_gate_exact_manifest_mismatch")
    if not _is_hex64(gate.get("output_identity")):
        blockers.append("promotion_gate_output_identity_invalid")
    if not _is_hex64(gate.get("derived_output_digest")):
        blockers.append("promotion_gate_output_digest_invalid")
    if not _is_hex64(gate.get("source_reference_digest")):
        blockers.append("promotion_gate_source_reference_digest_invalid")
    continuity_scope = str(gate.get("continuity_declaration_scope_identity") or "")
    continuity_sha256 = str(gate.get("continuity_declaration_sha256") or "").lower()
    if not continuity_scope or not _is_hex64(continuity_sha256):
        blockers.append("promotion_gate_durable_continuity_identity_invalid")
    progress_value = gate.get("declaration_progress")
    if not isinstance(progress_value, dict):
        blockers.append("promotion_gate_declaration_progress_invalid")
    else:
        progress = dict(progress_value)
        payload = {
            key: progress.get(key)
            for key in (
                "contract", "declaration_ids", "scope_identity",
                "declaration_sha256", "candidate_identity_sha256",
            )
        }
        digest = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        declaration_ids = progress.get("declaration_ids")
        members = gate.get("continuity_declaration_members") or []
        if not isinstance(members, list) or len(members) > MAX_DECLARATION_MEMBERS:
            blockers.append("promotion_gate_declaration_member_count_out_of_bounds")
        manifest_payload = {
            "contract": "sli.warm-derived-publication.v1",
            "policy_fingerprint": gate.get("policy_fingerprint"),
            "archive_requirement": gate.get("archive_requirement"),
            "read_representation": gate.get("read_representation"),
            "source_ids": [event_id for event_id, _digest in expected],
            "candidate_identity_sha256": gate.get("candidate_identity_sha256"),
            "source_reference_digest": gate.get("source_reference_digest"),
            "derived_output_digest": gate.get("derived_output_digest"),
            "declaration_progress_digest": digest,
            "readback_required": True,
        }
        manifest_digest = hashlib.sha256(json.dumps(
            manifest_payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        if (
            progress.get("contract") != "sli.storage-lifecycle-declaration-progress.v1"
            or not isinstance(declaration_ids, list) or not declaration_ids
            or len(declaration_ids) > MAX_DECLARATION_IDS
            or declaration_ids != sorted(set(declaration_ids))
            or progress.get("scope_identity") != continuity_scope
            or progress.get("declaration_sha256") != continuity_sha256
            or progress.get("candidate_identity_sha256") != gate.get("candidate_identity_sha256")
            or progress.get("digest") != digest
            or gate.get("declaration_progress_digest") != digest
            or gate.get("manifest_digest") != manifest_digest
        ):
            blockers.append("promotion_gate_declaration_progress_invalid")
    blockers.extend(_promotion_gate_policy_recheck_blockers(gate))
    return blockers


def _resolve_promotion_gate_policy_recheck(
    gate: dict[str, Any],
) -> tuple[list[str], dict[str, Any] | None, str | None]:
    """Resolve the current descriptor-promotion contract once and compare it
    against the frozen gate.

    Returns ``(blockers, current, expected_availability)`` so a caller that
    needs both the blocker list and the resolved current contract (e.g. the
    post-delete pre-commit verification) does not resolve the live policy a
    second time.
    """
    source = str(gate.get("source") or "")
    stream = str(gate.get("stream") or "")
    event_keys = [str(value) for value in gate.get("event_keys") or []]
    try:
        current = resolve_current_promotion_contract(
            source=source,
            stream=stream,
            event_keys=event_keys,
            resolver=resolve_descriptor_retention,
        )
    except (KeyError, TypeError, ValueError):
        return ["promotion_gate_descriptor_policy_recheck_failed"], None, None
    blockers: list[str] = []
    expected_availability = (
        "derived_only_available"
        if current["archive_requirement"] == "no_archive"
        and current["read_representation"] == "derived_only"
        else "source_archived"
        if current["archive_requirement"] == "archive_required"
        and current["read_representation"] == "archived_atomic"
        else None
    )
    for field in (
        "descriptor_policies", "policy_fingerprint", "archive_requirement",
        "read_representation", "post_promotion_disposition",
        "executable_lifecycle",
    ):
        if gate.get(field) != current[field]:
            blockers.append("promotion_gate_policy_fingerprint_mismatch")
            break
    if gate.get("read_availability") != expected_availability:
        blockers.append("promotion_gate_read_availability_mismatch")
    return blockers, current, expected_availability


def _promotion_gate_policy_recheck_blockers(gate: dict[str, Any]) -> list[str]:
    """Compare a promotion gate's frozen descriptor policy against the
    current live descriptor policy.

    Shared by the outer preflight (``_promotion_gate_blockers``) and the
    transaction-local recheck immediately before DELETE — one comparison,
    two call sites.
    """
    blockers, _current, _expected_availability = _resolve_promotion_gate_policy_recheck(gate)
    return blockers


def _recheck_promotion_gate_policy_before_delete(gate: dict[str, Any]) -> None:
    """Re-verify the frozen policy fingerprint transaction-locally,
    immediately before DELETE, after FOR UPDATE + durable continuity
    already succeeded. Any drift blocks the delete."""
    blockers = _promotion_gate_policy_recheck_blockers(gate)
    if blockers:
        raise RuntimeError(",".join(blockers))


def _recheck_package_cutoff_against_transaction_hot_horizon(
    cur: Any, *, cutoff: datetime,
) -> None:
    """Reject a frozen cutoff that has entered PostgreSQL's live hot window.

    ``now()`` is deliberately read through the same cursor and transaction
    that will issue DELETE.  This keeps the executor from trusting either the
    planner's earlier clock sample or the host wall clock at the destructive
    boundary.
    """
    if cutoff.tzinfo is None or cutoff.utcoffset() is None:
        raise RuntimeError("package_cutoff_timezone_missing")
    policy = load_storage_policy()
    if policy.db_retention_days != 7 or policy.warm_retention_days != 365:
        raise RuntimeError("owner_storage_policy_changed")
    if policy.archive_auto_delete_enabled:
        raise RuntimeError("archive_auto_delete_enabled")
    try:
        cur.execute(
            "select now() - (%s * interval '1 day') as policy_cutoff_utc",
            (policy.db_retention_days,),
        )
        row = cur.fetchone()
        policy_cutoff = dict(row or {}).get("policy_cutoff_utc")
    except Exception as exc:
        raise RuntimeError("transaction_hot_horizon_query_failed") from exc
    if not isinstance(policy_cutoff, datetime):
        raise RuntimeError("transaction_hot_horizon_unavailable")
    if policy_cutoff.tzinfo is None or policy_cutoff.utcoffset() is None:
        raise RuntimeError("transaction_hot_horizon_timezone_missing")
    if cutoff.astimezone(timezone.utc) > policy_cutoff.astimezone(timezone.utc):
        raise RuntimeError("package_cutoff_inside_transaction_hot_window")


def _recheck_persisted_promotion_output(gate: dict[str, Any]) -> None:
    """Reopen the Ticket03 durable output immediately before/after deletion."""
    from server.sli.storage.storage_lifecycle_io import CONTAINER, _container_port
    from server.sli.storage.warm_tier_incremental_copy_runtime import (
        _derived_output_actual,
        _derived_output_identity,
    )

    output_identity = str(gate.get("output_identity") or "")
    if not _is_hex64(output_identity):
        raise RuntimeError("promotion_gate_output_identity_invalid")
    rows = _derived_output_actual(_container_port(CONTAINER), output_identity)
    if len(rows) != 1:
        raise RuntimeError("promotion_output_missing_or_duplicate")
    actual = dict(rows[0])
    for field in (
        "output_identity", "batch_identity", "candidate_identity_sha256",
        "policy_fingerprint", "derived_output_digest",
        "source_reference_digest", "manifest_digest",
        "continuity_declaration_scope_identity",
        "continuity_declaration_sha256", "source_count",
        "observation_count", "payload_json", "published_at_utc",
    ):
        actual_value = actual.get(field)
        gate_value = gate.get(field)
        if field == "published_at_utc":
            try:
                actual_timestamp = datetime.fromisoformat(
                    str(actual_value).replace("Z", "+00:00")
                )
                gate_timestamp = datetime.fromisoformat(
                    str(gate_value).replace("Z", "+00:00")
                )
                if actual_timestamp.tzinfo is None:
                    actual_timestamp = actual_timestamp.replace(tzinfo=timezone.utc)
                if gate_timestamp.tzinfo is None:
                    gate_timestamp = gate_timestamp.replace(tzinfo=timezone.utc)
                actual_value = actual_timestamp.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                )
                gate_value = gate_timestamp.astimezone(timezone.utc).isoformat(
                    timespec="microseconds"
                )
            except ValueError as exc:
                raise RuntimeError("promotion_output_published_at_utc_invalid") from exc
        if str(actual_value or "") != str(gate_value or ""):
            raise RuntimeError(f"promotion_output_{field}_mismatch")
    try:
        recomputed_identity = _derived_output_identity(actual)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("promotion_output_identity_recompute_failed") from exc
    if recomputed_identity != str(actual["output_identity"]):
        raise RuntimeError("promotion_output_identity_recomputed_mismatch")


def _preflight_durable_promotion_continuity(
    gate: dict[str, Any], *, manifest_batch: _ValidatedManifestBatch, cur: Any | None = None,
) -> str:
    """Verify full durable provenance once before any bounded delete commit.

    A retry after a completed disposition has no hot rows left to re-read and
    is safe as an idempotent no-op.  A mixed present/absent manifest is an
    interrupted disposition: it is intentionally blocked rather than treating
    a partial source set as a fresh complete declaration.
    """
    from server.sli.sources.source_capture_continuity import (
        CaptureContinuityError,
        recheck_durable_promotion_continuity,
    )

    expected = {
        (event_id, normalized_hash.hex())
        for event_id, normalized_hash in manifest_batch.records
    }
    if not expected:
        raise RuntimeError("promotion_continuity_references_invalid")
    if cur is None:
        with _connect_write() as conn:
            with conn.cursor() as owned_cur:
                return _preflight_durable_promotion_continuity(
                    gate, manifest_batch=manifest_batch, cur=owned_cur,
                )
    cur.execute(
        """select id,encode(normalized_hash,'hex') as normalized_hash
             from events_v2_core where id=any(%s::bigint[]) order by id
             for update""",
        (list(manifest_batch.ids),),
    )
    actual = {
        (int(row["id"]), str(row["normalized_hash"]).lower())
        for row in cur.fetchall()
    }
    if not actual:
        return "already_absent_exact_retry"
    if actual != expected:
        raise RuntimeError("promotion_continuity_partial_or_changed_source")
    try:
        recheck_durable_promotion_continuity(cur, promotion_gate=gate)
    except CaptureContinuityError as exc:
        raise RuntimeError(
            "promotion_durable_continuity_recheck_failed:" + str(exc)
        ) from exc
    return "verified_before_disposition"


def _recheck_archive_required_promotion(
    manifest_batch: _ValidatedManifestBatch,
) -> None:
    """Revalidate the existing archive placement proof for one frozen batch."""
    from server.sli.storage.tier_retention_delete_plan_runtime import verify_warm

    warm = verify_warm([
        {"id": event_id, "normalized_hash": normalized_hash}
        for event_id, normalized_hash in manifest_batch.records
    ])
    if any(int(warm.get(field) or 0) for field in (
        "missing", "hash_mismatches", "archive_paths_missing",
    )):
        raise RuntimeError("promotion_archive_proof_recheck_failed")


def _post_delete_promotion_verification(
    cur: Any, gate: dict[str, Any], manifest_batch: _ValidatedManifestBatch,
) -> dict[str, Any]:
    cur.execute(
        "select count(*)::bigint as remaining from events_v2_core where id = any(%s)",
        (list(manifest_batch.ids),),
    )
    remaining = int(dict(cur.fetchone()).get("remaining") or 0)
    if remaining:
        raise RuntimeError("promotion_post_delete_hot_source_still_present")
    _recheck_persisted_promotion_output(gate)
    if gate.get("archive_requirement") == "archive_required":
        _recheck_archive_required_promotion(manifest_batch)
    blockers, _current, availability = _resolve_promotion_gate_policy_recheck(gate)
    if blockers:
        raise RuntimeError(
            "promotion_post_delete_policy_recheck_failed:" + ",".join(blockers)
        )
    if availability is None:
        raise RuntimeError("promotion_post_delete_read_state_invalid")
    return {
        "hot_source_ids_absent": True,
        "persisted_output_verified": True,
        "read_availability": availability,
        "atomic_evidence_available": gate.get("archive_requirement") == "archive_required",
    }


def validate_package(plan_path: Path = DEFAULT_PLAN) -> dict[str, Any]:
    plan_path = plan_path.resolve()
    plan = json.loads(_read_file_bounded(
        plan_path, max_bytes=MAX_PLAN_JSON_BYTES, too_large="retention_plan_too_large",
    ).decode("utf-8"))
    manifest_meta = dict(plan.get("candidate_manifest") or {})
    manifest = Path(str(manifest_meta.get("path") or "")).resolve()
    expected_rows = int(manifest_meta.get("rows") or 0)
    expected_bytes = int(manifest_meta.get("bytes") or 0)
    expected_sha = str(manifest_meta.get("sha256") or "").lower()
    cutoff = datetime.fromisoformat(str((plan.get("postgres") or {}).get("cutoff_utc")))
    policy = load_storage_policy()
    blockers: list[str] = []
    if plan.get("status") != "ready_for_owner_authorization":
        blockers.append("plan_not_ready_for_owner_authorization")
    if not bool(plan.get("technical_gate_passed")) or plan.get("blockers"):
        blockers.append("technical_gate_not_clean")
    if not bool(manifest_meta.get("published")):
        blockers.append("candidate_manifest_not_published")
    if manifest_meta.get("format") != "big_endian_uint64_event_id_plus_32_byte_normalized_hash":
        blockers.append("candidate_manifest_format_mismatch")
    if int(manifest_meta.get("record_bytes") or 0) != RECORD.size:
        blockers.append("candidate_manifest_record_size_mismatch")
    manifest_available = manifest.is_file()
    if not manifest_available:
        blockers.append("candidate_manifest_missing")
        actual_bytes = 0
        actual_sha = None
        manifest_batch = _ValidatedManifestBatch(b"", (), (), ())
    else:
        try:
            manifest_bytes = _read_file_bounded(
                manifest,
                max_bytes=MAX_CANDIDATE_MANIFEST_BYTES,
                too_large="candidate_manifest_too_large",
            )
        except RuntimeError as exc:
            blocker = str(exc)
            blockers.append(
                blocker if blocker == "candidate_manifest_too_large"
                else "candidate_manifest_read_failed"
            )
            actual_bytes = 0
            actual_sha = None
            manifest_batch = _ValidatedManifestBatch(b"", (), (), ())
        else:
            actual_bytes = len(manifest_bytes)
            actual_sha = hashlib.sha256(manifest_bytes).hexdigest()
            try:
                manifest_batch = _validated_manifest_batch(manifest_bytes)
            except RuntimeError as exc:
                blockers.append(str(exc))
                manifest_batch = _ValidatedManifestBatch(b"", (), (), ())
        if actual_bytes != expected_bytes or actual_bytes != expected_rows * RECORD.size:
            blockers.append("candidate_manifest_size_mismatch")
        if actual_sha != expected_sha:
            blockers.append("candidate_manifest_sha256_mismatch")
        if len(manifest_batch.records) != expected_rows:
            blockers.append("candidate_manifest_count_mismatch")
    if expected_rows != int(plan.get("candidate_count") or -1):
        blockers.append("candidate_count_mismatch")
    if expected_rows > MAX_BATCH:
        blockers.append("promotion_manifest_exceeds_atomic_batch")
    if expected_sha != str((plan.get("postgres") or {}).get("deletion_identity_sha256") or "").lower():
        blockers.append("deletion_identity_mismatch")
    if cutoff.tzinfo is None:
        blockers.append("cutoff_timezone_missing")
    if policy.db_retention_days != 7 or policy.warm_retention_days != 365:
        blockers.append("owner_storage_policy_changed")
    if policy.archive_auto_delete_enabled:
        blockers.append("archive_auto_delete_enabled")
    if manifest_available:
        blockers.extend(_promotion_gate_blockers(plan, manifest_batch))
    account = _windows_account()
    if account.casefold() != APPROVED_OWNER.casefold():
        blockers.append("windows_account_is_not_approved_owner")
    return _ValidatedPackage({
        "status": "ready" if not blockers else "blocked",
        "mode": "frozen_manifest_preflight",
        "plan_path": str(plan_path),
        "manifest_path": str(manifest),
        "manifest_rows": expected_rows,
        "manifest_bytes": actual_bytes,
        "manifest_sha256": actual_sha,
        "cutoff_utc": cutoff,
        "windows_account": account,
        "approved_owner": APPROVED_OWNER,
        "blockers": blockers,
        "required_confirmation": CONFIRMATION,
        "postgres_changed": False,
        "physical_reclaim_performed": False,
    }, plan=plan, manifest_batch=manifest_batch)


def _connect_write():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    cfg = load_config()
    if not cfg.postgres_dsn:
        raise RuntimeError("postgres_dsn_not_configured")
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("protected_postgres_admin_credentials_required")
    parts = conninfo_to_dict(cfg.postgres_dsn)
    parts.update(
        user=user,
        password=password,
        connect_timeout=max(1, int(cfg.postgres_connect_timeout_seconds)),
        application_name="sli_stage7_hot_retention_delete",
        options="-c statement_timeout=180000 -c lock_timeout=3000",
    )
    return psycopg.connect(**parts, row_factory=dict_row)


def execute(
    *, plan_path: Path, output: Path, confirmation: str, batch_size: int
) -> dict[str, Any]:
    package = validate_package(plan_path)
    if confirmation != CONFIRMATION:
        raise PermissionError("exact owner confirmation is required")
    if package["status"] != "ready":
        raise RuntimeError("retention_package_preflight_blocked")
    if not isinstance(package, _ValidatedPackage):
        raise RuntimeError("retention_package_validation_identity_unavailable")
    plan = package.plan
    cutoff = datetime.fromisoformat(str((plan.get("postgres") or {}).get("cutoff_utc")))
    manifest_batch = package.manifest_batch
    batch_size = min(MAX_BATCH, max(1, int(batch_size)))
    result: dict[str, Any] = {
        **package,
        "status": "working",
        "mode": "owner_authorized_bounded_delete",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "confirmation_accepted": True,
        "batch_size": batch_size,
        "processed_manifest_rows": 0,
        "deleted_rows": 0,
        "already_absent_rows": 0,
        "batches_committed": 0,
        "post_delete_verifications": [],
    }
    _atomic_json(output, result)
    gate = plan.get("promotion_gate")
    blockers = _promotion_gate_blockers(plan, manifest_batch)
    if blockers:
        raise RuntimeError("promotion_gate_recheck_blocked:" + ",".join(blockers))
    if not isinstance(gate, dict):
        raise RuntimeError("promotion_gate_required")
    gate = dict(gate)
    executed_binding = {
        "promotion_output_identity": gate.get("output_identity"),
        "progress_digest": gate.get("declaration_progress_digest"),
        "candidate_identity_sha256": gate.get("candidate_identity_sha256"),
        "source_reference_digest": gate.get("source_reference_digest"),
        "manifest_digest": gate.get("manifest_digest"),
        "candidate_manifest_sha256": package.get("manifest_sha256"),
        "candidate_manifest_rows": package.get("manifest_rows"),
    }
    executed_binding["plan_identity_sha256"] = hashlib.sha256(json.dumps(
        executed_binding, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    declared_binding = plan.get("processed_package_binding")
    if declared_binding is not None and declared_binding != executed_binding:
        raise RuntimeError("retention_processed_package_binding_mismatch")
    result["executed_package_binding"] = executed_binding
    _recheck_persisted_promotion_output(gate)
    if len(manifest_batch.records) > batch_size:
        raise RuntimeError("promotion_manifest_exceeds_atomic_batch")
    if gate.get("archive_requirement") == "archive_required":
        _recheck_archive_required_promotion(manifest_batch)
    with _connect_write() as conn:
        refs = _restrictive_references(conn, list(manifest_batch.ids))
        if int(refs.get("rows") or 0):
            raise RuntimeError("new_restrictive_reference_blocks_manifest_batch")
        with conn.cursor() as cur:
            continuity_state = _preflight_durable_promotion_continuity(
                gate, manifest_batch=manifest_batch, cur=cur,
            )
            result["durable_continuity_preflight"] = continuity_state
            if continuity_state == "already_absent_exact_retry":
                check = {"absent": len(manifest_batch.records)}
                deleted = 0
                post_delete = None
            else:
                _recheck_persisted_promotion_output(gate)
                _recheck_promotion_gate_policy_before_delete(gate)
                if gate.get("archive_requirement") == "archive_required":
                    _recheck_archive_required_promotion(manifest_batch)
                _recheck_package_cutoff_against_transaction_hot_horizon(
                    cur, cutoff=cutoff,
                )
                cur.execute(
                    """
                    with manifest_row as (
                        select * from unnest(%s::bigint[],%s::bytea[])
                            as value(event_id,normalized_hash)
                    )
                    select
                        count(*) filter (where event.id is null)::bigint as absent,
                        count(*) filter (where event.id is not null and
                            event.normalized_hash<>manifest_row.normalized_hash)::bigint
                            as hash_mismatch,
                        count(*) filter (where event.id is not null and
                            event.time_created_utc >= %s)::bigint as inside_cutoff
                    from manifest_row
                    left join events_v2_core event on event.id=manifest_row.event_id
                    """,
                    (list(manifest_batch.ids), list(manifest_batch.hashes), cutoff),
                )
                check = dict(cur.fetchone())
                if int(check["absent"] or 0):
                    raise RuntimeError("manifest_row_disappeared_after_continuity_lock")
                if int(check["hash_mismatch"] or 0):
                    raise RuntimeError("manifest_hash_changed_in_postgres")
                if int(check["inside_cutoff"] or 0):
                    raise RuntimeError("manifest_row_moved_inside_frozen_cutoff")
                cur.execute(
                    """
                    with manifest_row as (
                        select * from unnest(%s::bigint[],%s::bytea[])
                            as value(event_id,normalized_hash)
                    )
                    delete from events_v2_core event using manifest_row
                    where event.id=manifest_row.event_id
                      and event.normalized_hash=manifest_row.normalized_hash
                      and event.time_created_utc < %s
                    returning event.id
                    """,
                    (list(manifest_batch.ids), list(manifest_batch.hashes), cutoff),
                )
                deleted = len(cur.fetchall())
                if deleted != len(manifest_batch.records):
                    raise RuntimeError("promotion_atomic_delete_count_mismatch")
                post_delete = _post_delete_promotion_verification(
                    cur, gate, manifest_batch,
                )
        conn.commit()
    result["processed_manifest_rows"] = len(manifest_batch.records)
    result["deleted_rows"] = deleted
    result["already_absent_rows"] = int(check["absent"] or 0)
    result["batches_committed"] = 1 if deleted else 0
    if post_delete is not None:
        result["post_delete_verifications"].append(post_delete)
    if manifest_batch.ids:
        result["last_committed_event_id"] = manifest_batch.ids[-1]
    _atomic_json(output, result)
    result.update(
        status="complete",
        completed_at_utc=datetime.now(timezone.utc).isoformat(),
        postgres_changed=bool(result["deleted_rows"]),
        physical_reclaim_performed=False,
        postcondition=(
            "all manifest rows deleted or already absent; physical pages are "
            "left to ordinary autovacuum and reuse"
        ),
    )
    _atomic_json(output, result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--batch-size", type=int, default=10_000)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    result = (
        execute(
            plan_path=args.plan,
            output=output,
            confirmation=str(args.confirmation or ""),
            batch_size=args.batch_size,
        )
        if args.execute
        else validate_package(args.plan)
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("status") in {"ready", "complete"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
