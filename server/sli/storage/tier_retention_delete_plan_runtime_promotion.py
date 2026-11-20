"""Split out of ``server.sli.storage.tier_retention_delete_plan_runtime`` (plan 7.2b).

Module-level names of ``tier_retention_delete_plan_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.tier_retention_delete_plan_runtime as _src


def resolve_current_promotion_contract(
    *,
    source: str,
    stream: str,
    event_keys: list[str],
    resolver=None,
) -> dict[str, _src.Any]:
    """Re-resolve the one descriptor contract that may promote exact IDs."""
    if not source or not stream or not event_keys or len(set(event_keys)) != len(event_keys):
        raise ValueError("descriptor_identity_or_event_keys_invalid")
    resolver = resolver or _src.resolve_descriptor_retention
    resolutions = [
        (event_key, resolver(source, stream, event_key))
        for event_key in event_keys
    ]
    first = resolutions[0][1]
    promotion = dict(first.promotion)
    if (
        first.rollup != "authentication_session"
        or promotion.get("executable_lifecycle")
        != "existing_warm_then_retention_executor"
    ):
        raise ValueError("descriptor_lifecycle_not_supported_by_existing_warm_path")
    descriptor_policies = []
    for event_key, resolution in resolutions:
        if (
            resolution.rollup != first.rollup
            or dict(resolution.promotion) != promotion
            or resolution.rollup_role not in {"boot_scope", "open", "close"}
        ):
            raise ValueError("descriptor_lifecycle_contract_mismatch")
        descriptor_policies.append({
            "event_key": event_key,
            "rollup_role": resolution.rollup_role,
            "policy_fingerprint": resolution.policy_fingerprint,
        })
    policy_fingerprint = _src.hashlib.sha256(_src.json.dumps(
        {
            "source": source,
            "stream": stream,
            "descriptor_policies": descriptor_policies,
            "promotion": promotion,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return {
        "descriptor_policies": descriptor_policies,
        "policy_fingerprint": policy_fingerprint,
        "archive_requirement": promotion["archive_requirement"],
        "read_representation": promotion["read_representation"],
        "post_promotion_disposition": promotion["post_promotion_disposition"],
        "executable_lifecycle": promotion["executable_lifecycle"],
    }


def _source_reference(value: dict[str, _src.Any]) -> dict[str, _src.Any]:
    digest = value.get("sha256", value.get("normalized_hash"))
    if isinstance(digest, bytes):
        digest = digest.hex()
    if not isinstance(digest, str) or len(digest) != 64:
        raise ValueError("source_normalized_hash_invalid")
    int(digest, 16)
    event_id = int(value["id"])
    if event_id <= 0:
        raise ValueError("source_event_id_invalid")
    return {"id": event_id, "sha256": digest.lower()}


def _promotion_candidate_references(
    promotion_evidence: dict[str, _src.Any],
) -> list[dict[str, _src.Any]]:
    """Return the only source rows an immutable promotion may dispose.

    A full retention scan is intentionally not a permission to add unrelated
    mature rows to a descriptor package.  The persisted output owns this
    exact ID/hash set and the later promotion gate rechecks it again.
    """
    publication = promotion_evidence.get("derived_publication")
    lifecycle = promotion_evidence.get("descriptor_lifecycle")
    if not isinstance(publication, dict) or not isinstance(lifecycle, dict):
        return []
    references_value = publication.get("source_references")
    if not isinstance(references_value, list):
        return []
    if len(references_value) > _src.MAX_PROMOTION_REFERENCES:
        return []
    try:
        references = [_src._source_reference(dict(value)) for value in references_value]
    except (TypeError, ValueError):
        return []
    candidate_ids = [int(value) for value in lifecycle.get("candidate_ids") or ()]
    if (
        not references
        or references != sorted(references, key=lambda item: item["id"])
        or len({item["id"] for item in references}) != len(references)
        or candidate_ids != [item["id"] for item in references]
    ):
        return []
    return references


def _is_exact_no_archive_safe_output(derived_rows: _src.Any) -> bool:
    if not isinstance(derived_rows, list) or not derived_rows:
        return False
    for row in derived_rows:
        if not isinstance(row, dict):
            return False
        state = str(row.get("state") or "")
        quality_reason = str(row.get("quality_reason") or "")
        if state != "closed" or quality_reason != "complete":
            return False
    return True


def _promotion_progress_binding(
    lifecycle: dict[str, _src.Any], publication: dict[str, _src.Any], readback: dict[str, _src.Any],
) -> tuple[list[str], dict[str, str] | None]:
    blockers: list[str] = []
    progress_value = lifecycle.get("declaration_progress")
    manifest = publication.get("manifest")
    if not isinstance(progress_value, dict) or not isinstance(manifest, dict):
        return ["declaration_progress_evidence_mismatch"], None
    progress = dict(progress_value)
    payload = {
        key: progress.get(key)
        for key in (
            "contract", "declaration_ids", "scope_identity",
            "declaration_sha256", "candidate_identity_sha256",
        )
    }
    digest = _src.hashlib.sha256(_src.json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    ids = progress.get("declaration_ids")
    if isinstance(ids, list) and len(ids) > _src.MAX_DECLARATION_IDS:
        return ["declaration_progress_id_count_out_of_bounds"], None
    output_identity = str(readback.get("output_identity") or "").lower()
    manifest_payload = {
        key: value for key, value in manifest.items() if key != "manifest_digest"
    }
    manifest_digest = _src.hashlib.sha256(_src.json.dumps(
        manifest_payload, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    if (
        progress.get("contract") != "sli.storage-lifecycle-declaration-progress.v1"
        or not isinstance(ids, list) or not ids or ids != sorted(set(ids))
        or progress.get("scope_identity") != lifecycle.get("continuity_declaration_scope_identity")
        or progress.get("declaration_sha256") != lifecycle.get("continuity_declaration_sha256")
        or progress.get("candidate_identity_sha256") != lifecycle.get("candidate_identity_sha256")
        or progress.get("digest") != digest
        or manifest.get("declaration_progress_digest") != digest
        or manifest.get("manifest_digest") != manifest_digest
        or len(output_identity) != 64
        or any(character not in "0123456789abcdef" for character in output_identity)
    ):
        blockers.append("declaration_progress_evidence_mismatch")
    return blockers, ({
        "declaration_progress": dict(progress),
        "progress_digest": digest,
        "promotion_output_identity": output_identity,
    } if not blockers else None)


def build_promoted_delete_manifest(
    *,
    source_rows: list[dict[str, _src.Any]],
    cutoff_utc: _src.datetime,
    promotion_evidence: dict[str, _src.Any],
    archive_proof: dict[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    """Freeze a descriptor promotion proof into the existing delete package.

    The caller remains responsible for writing the existing binary manifest.
    This function only returns a fail-closed, versioned evidence section that
    binds that manifest's exact IDs/hashes to the Ticket03 persisted output.
    """
    blockers: list[str] = []
    if len(source_rows) > _src.MAX_PROMOTION_REFERENCES:
        blockers.append("promotion_source_reference_count_out_of_bounds")
    if cutoff_utc.tzinfo is None:
        blockers.append("cutoff_timezone_missing")
    try:
        candidates = [_src._source_reference(row) for row in source_rows]
    except (KeyError, TypeError, ValueError) as exc:
        candidates = []
        blockers.append(str(exc))
    if not candidates:
        blockers.append("promotion_source_rows_missing")
    if candidates != sorted(candidates, key=lambda item: item["id"]):
        blockers.append("source_ids_not_strictly_increasing")
    if len({item["id"] for item in candidates}) != len(candidates):
        blockers.append("source_ids_not_exact_unique")
    for row in source_rows:
        observed = row.get("time_created_utc")
        if not isinstance(observed, _src.datetime) or observed.tzinfo is None:
            blockers.append("source_time_invalid")
        elif cutoff_utc.tzinfo is not None and observed >= cutoff_utc:
            blockers.append("source_inside_hot_cutoff")

    lifecycle_value = promotion_evidence.get("descriptor_lifecycle")
    publication_value = promotion_evidence.get("derived_publication")
    readback_value = promotion_evidence.get("readback")
    if not all(isinstance(value, dict) for value in (
        lifecycle_value, publication_value, readback_value,
    )):
        blockers.append("promotion_evidence_structure_invalid")
    lifecycle = dict(lifecycle_value) if isinstance(lifecycle_value, dict) else {}
    publication = dict(publication_value) if isinstance(publication_value, dict) else {}
    readback = dict(readback_value) if isinstance(readback_value, dict) else {}
    manifest = dict(publication.get("manifest") or {})
    publication_references = publication.get("source_references")
    if not isinstance(publication_references, list) or len(publication_references) > _src.MAX_PROMOTION_REFERENCES:
        blockers.append("promotion_source_reference_count_out_of_bounds")
    derived_rows = publication.get("derived")
    if not isinstance(derived_rows, list) or len(derived_rows) > _src.MAX_PROMOTION_DERIVED_ROWS:
        blockers.append("promotion_derived_row_count_out_of_bounds")
    members = lifecycle.get("continuity_declaration_members") or []
    if not isinstance(members, list) or len(members) > _src.MAX_DECLARATION_MEMBERS:
        blockers.append("continuity_declaration_member_count_out_of_bounds")
    progress_blockers, progress_binding = _src._promotion_progress_binding(
        lifecycle, publication, readback,
    )
    blockers.extend(progress_blockers)
    try:
        from server.sli.storage.warm_tier_incremental_copy_runtime import (
            _expected_derived_output_row,
        )

        expected_output = _expected_derived_output_row(publication)
    except (KeyError, TypeError, ValueError):
        expected_output = {}
        blockers.append("persisted_output_contract_invalid")
    continuity_scope_identity = str(
        lifecycle.get("continuity_declaration_scope_identity") or ""
    )
    continuity_declaration_sha256 = str(
        lifecycle.get("continuity_declaration_sha256") or ""
    ).lower()
    if (
        not continuity_scope_identity
        or len(continuity_declaration_sha256) != 64
        or any(value not in "0123456789abcdef" for value in continuity_declaration_sha256)
    ):
        blockers.append("durable_continuity_declaration_missing")
    references = list(publication.get("source_references") or [])
    try:
        references = [_src._source_reference(row) for row in references]
    except (KeyError, TypeError, ValueError):
        references = []
        blockers.append("persisted_source_references_invalid")
    expected_reference_digest = _src.source_reference_digest(references)
    if references != candidates:
        blockers.append("persisted_source_references_do_not_match_exact_manifest")
    if str(manifest.get("source_reference_digest") or "") != expected_reference_digest:
        blockers.append("persisted_source_reference_digest_mismatch")
    if str(manifest.get("derived_output_digest") or "") != str(publication.get("derived_output_digest") or ""):
        blockers.append("persisted_derived_output_digest_mismatch")
    if not (
        readback.get("status") == "verified_persisted_readback"
        and bool(readback.get("verified"))
        and bool(readback.get("promotion_eligible"))
        and str(readback.get("derived_output_digest") or "")
        == str(publication.get("derived_output_digest") or "")
        and str(readback.get("output_identity") or "")
        == str(expected_output.get("output_identity") or "")
        and bool(str(readback.get("published_at_utc") or ""))
    ):
        blockers.append("persisted_derived_readback_not_verified")

    source = str(lifecycle.get("source") or "")
    stream = str(lifecycle.get("stream") or "")
    event_keys = [str(value) for value in lifecycle.get("event_keys") or []]
    try:
        current_contract = _src.resolve_current_promotion_contract(
            source=source,
            stream=stream,
            event_keys=event_keys,
        )
    except (KeyError, TypeError, ValueError):
        current_contract = None
        blockers.append("descriptor_policy_recheck_failed")
    if current_contract is None:
        policy_fingerprint = ""
        archive_requirement = ""
        representation = ""
    else:
        policy_fingerprint = str(current_contract["policy_fingerprint"])
        archive_requirement = str(current_contract["archive_requirement"])
        representation = str(current_contract["read_representation"])
        for field in (
            "descriptor_policies", "policy_fingerprint", "archive_requirement",
            "read_representation", "post_promotion_disposition",
            "executable_lifecycle",
        ):
            if lifecycle.get(field) != current_contract[field]:
                blockers.append("descriptor_policy_contract_mismatch")
                break
        if str(manifest.get("policy_fingerprint") or "") != policy_fingerprint:
            blockers.append("persisted_output_policy_fingerprint_mismatch")
    if archive_requirement == "no_archive":
        if representation != "derived_only":
            blockers.append("no_archive_representation_invalid")
        if not _src._is_exact_no_archive_safe_output(publication.get("derived")):
            blockers.append("incomplete_or_gap_derived_output_not_deletable")
    elif archive_requirement == "archive_required":
        if representation != "archived_atomic":
            blockers.append("archive_representation_invalid")
        if not archive_proof or not bool(archive_proof.get("verified")):
            blockers.append("archive_proof_not_verified")
    else:
        blockers.append("descriptor_archive_requirement_invalid")

    return {
        "status": "ready_for_owner_authorization" if not blockers else "blocked",
        "candidate_ids": [item["id"] for item in candidates] if not blockers else [],
        "candidate_references": candidates if not blockers else [],
        "blockers": blockers,
        "promotion_gate": {
            "contract": "sli.tier-retention-promotion-gate.v1",
            "policy_fingerprint": policy_fingerprint,
            "source": source,
            "stream": stream,
            "event_keys": event_keys,
            "descriptor_policies": (
                current_contract.get("descriptor_policies")
                if current_contract is not None else []
            ),
            "archive_requirement": archive_requirement,
            "read_representation": representation,
            "post_promotion_disposition": (
                current_contract.get("post_promotion_disposition")
                if current_contract is not None else None
            ),
            "executable_lifecycle": (
                current_contract.get("executable_lifecycle")
                if current_contract is not None else None
            ),
            "output_identity": readback.get("output_identity"),
            "batch_identity": expected_output.get("batch_identity"),
            "candidate_identity_sha256": expected_output.get(
                "candidate_identity_sha256"
            ),
            "derived_output_digest": publication.get("derived_output_digest"),
            "source_reference_digest": expected_reference_digest,
            "manifest_digest": expected_output.get("manifest_digest"),
            "source_count": expected_output.get("source_count"),
            "observation_count": expected_output.get("observation_count"),
            "payload_json": expected_output.get("payload_json"),
            "published_at_utc": readback.get("published_at_utc"),
            "source_references": references,
            "continuity_declaration_scope_identity": continuity_scope_identity or None,
            "continuity_declaration_sha256": continuity_declaration_sha256 or None,
            "continuity_declaration_members": list(
                lifecycle.get("continuity_declaration_members") or ()
            ),
            "supplemental_context_ids": [
                int(value) for value in lifecycle.get("supplemental_context_ids") or ()
            ],
            "declaration_progress": lifecycle.get("declaration_progress"),
            "declaration_progress_digest": (
                progress_binding.get("progress_digest") if progress_binding else None
            ),
            "read_availability": (
                "derived_only_available" if archive_requirement == "no_archive"
                else "source_archived"
            ),
        },
    }
