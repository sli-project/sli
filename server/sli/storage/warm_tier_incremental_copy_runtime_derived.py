"""Split out of ``server.sli.storage.warm_tier_incremental_copy_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_copy_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_copy_runtime as _src


def _canonical_derived_observation(
    observation: _src.AuthenticationSessionObservation,
) -> dict[str, _src.Any]:
    return {
        "session_uid": observation.session_uid,
        "state": observation.state,
        "quality_reason": observation.quality_reason,
        "coverage_state": observation.coverage_state,
        "promotion_eligible": observation.promotion_eligible,
        "boot_source_event_id": observation.boot_source_event_id,
        "boot_normalized_hash": observation.boot_normalized_hash,
        "logon_source_event_id": observation.logon_source_event_id,
        "logon_normalized_hash": observation.logon_normalized_hash,
        "logoff_source_event_id": observation.logoff_source_event_id,
        "logoff_normalized_hash": observation.logoff_normalized_hash,
        "source_event_ids": list(observation.source_event_ids),
        "source_hashes": list(observation.source_hashes),
        "logon_time_utc": _src._format_utc(observation.logon_time_utc),
        "logoff_time_utc": _src._format_utc(observation.logoff_time_utc),
        "duration_seconds": observation.duration_seconds,
        "principal": observation.principal,
        "host": observation.host,
        "logon_type": observation.logon_type,
        "privilege_marker": observation.privilege_marker,
        "privilege_source_event_id": observation.privilege_source_event_id,
        "privilege_normalized_hash": observation.privilege_normalized_hash,
        "privilege_attachment_state": observation.privilege_attachment_state,
        "privilege_evidence_source_event_ids": list(
            observation.privilege_evidence_source_event_ids
        ),
        "privilege_evidence_normalized_hashes": list(
            observation.privilege_evidence_normalized_hashes
        ),
        "supplemental_logout_source_event_ids": list(
            observation.supplemental_logout_source_event_ids
        ),
        "supplemental_logout_normalized_hashes": list(
            observation.supplemental_logout_normalized_hashes
        ),
        "explicit_credentials_source_event_ids": list(
            observation.explicit_credentials_source_event_ids
        ),
        "explicit_credentials_normalized_hashes": list(
            observation.explicit_credentials_normalized_hashes
        ),
    }


def _expected_derived_output_row(publication: dict[str, _src.Any]) -> dict[str, _src.Any]:
    """Return the one immutable ClickHouse row for a derived publication."""
    lifecycle = dict(publication["descriptor_lifecycle"])
    manifest = dict(publication["manifest"])
    source_references = list(publication["source_references"])
    derived = list(publication["derived"])
    if len(source_references) > _src.MAX_SOURCE_REFERENCES:
        raise ValueError("derived_source_reference_count_out_of_bounds")
    if len(derived) > _src.MAX_DERIVED_ROWS:
        raise ValueError("derived_observation_count_out_of_bounds")
    payload_json = _src.json.dumps(
        {
            "contract": "sli.warm.authentication-session-output.v1",
            "continuity_declaration": {
                "scope_identity": lifecycle.get(
                    "continuity_declaration_scope_identity"
                ),
                "declaration_sha256": lifecycle.get(
                    "continuity_declaration_sha256"
                ),
            },
            "source_references": source_references,
            "derived": derived,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    batch_identity = str(
        publication.get("batch_identity")
        or lifecycle["candidate_identity_sha256"]
    )
    continuity_scope_identity = str(
        lifecycle.get("continuity_declaration_scope_identity") or ""
    )
    continuity_declaration_sha256 = str(
        lifecycle.get("continuity_declaration_sha256") or ""
    ).lower()
    if not continuity_scope_identity or not _src.HEX64.fullmatch(
        continuity_declaration_sha256
    ):
        raise ValueError("derived_output_continuity_identity_invalid")
    row = {
        "batch_identity": batch_identity,
        "candidate_identity_sha256": str(lifecycle["candidate_identity_sha256"]),
        "policy_fingerprint": str(lifecycle["policy_fingerprint"]),
        "derived_output_digest": str(publication["derived_output_digest"]),
        "source_reference_digest": str(manifest["source_reference_digest"]),
        "manifest_digest": str(manifest["manifest_digest"]),
        "continuity_declaration_scope_identity": continuity_scope_identity,
        "continuity_declaration_sha256": continuity_declaration_sha256,
        "source_count": len(source_references),
        "observation_count": len(derived),
        "payload_json": payload_json,
    }
    return {
        "output_identity": _src._derived_output_identity(row),
        **row,
    }


def classify_derived_output_readback(
    publication: dict[str, _src.Any], actual_rows: list[dict[str, _src.Any]],
) -> dict[str, _src.Any]:
    """Fail closed unless one persisted immutable output exactly matches."""
    if len(actual_rows) != 1:
        raise RuntimeError("partial_or_duplicate_derived_output")
    expected = _src._expected_derived_output_row(publication)
    actual = dict(actual_rows[0])
    for field, error in (
        ("output_identity", "derived_output_identity_mismatch"),
        ("batch_identity", "derived_batch_identity_mismatch"),
        ("candidate_identity_sha256", "derived_candidate_identity_mismatch"),
        ("policy_fingerprint", "derived_policy_fingerprint_mismatch"),
        ("derived_output_digest", "derived_output_digest_mismatch"),
        ("source_reference_digest", "derived_source_reference_mismatch"),
        ("manifest_digest", "derived_manifest_digest_mismatch"),
        (
            "continuity_declaration_scope_identity",
            "derived_continuity_scope_identity_mismatch",
        ),
        (
            "continuity_declaration_sha256",
            "derived_continuity_sha256_mismatch",
        ),
        ("source_count", "derived_source_count_mismatch"),
        ("observation_count", "derived_observation_count_mismatch"),
        ("payload_json", "derived_payload_mismatch"),
    ):
        if str(actual.get(field)) != str(expected[field]):
            raise RuntimeError(error)
    try:
        published_at_utc = _src._format_utc(_src._parse_utc(actual.get("published_at_utc")))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("derived_published_at_utc_invalid") from exc
    derived = publication.get("derived") or []
    promotion_eligible = bool(derived) and all(
        isinstance(item, dict)
        and item.get("coverage_state") == "accepted"
        and item.get("promotion_eligible") is True
        for item in derived
    )
    return {
        "status": "verified_persisted_readback",
        "verified": True,
        "promotion_eligible": promotion_eligible,
        "output_identity": expected["output_identity"],
        "derived_output_digest": expected["derived_output_digest"],
        "published_at_utc": published_at_utc,
    }


def _build_derived_publication(
    *,
    source: str,
    stream: str,
    event_keys: tuple[str, ...],
    evidence: tuple[_src.AuthenticationEvidence, ...],
    continuity_declarations: tuple[_src.ContinuityDeclaration, ...],
    continuity_declaration_scope_identity: str | None = None,
    continuity_declaration_sha256: str | None = None,
    candidate_ids: tuple[int, ...] | None = None,
    continuity_declaration_members: tuple[dict[str, _src.Any], ...] = (),
    supplemental_context_ids: tuple[int, ...] = (),
    declaration_progress: dict[str, _src.Any] | None = None,
) -> dict[str, _src.Any]:
    """Build the canonical descriptor promotion output for one frozen batch."""
    lifecycle = _src._freeze_descriptor_lifecycle(
        source=source,
        stream=stream,
        event_keys=event_keys,
        candidate_ids=(
            candidate_ids
            if candidate_ids is not None
            else tuple(sorted(item.source_event_id for item in evidence))
        ),
        continuity_declaration_scope_identity=continuity_declaration_scope_identity,
        continuity_declaration_sha256=continuity_declaration_sha256,
        continuity_declaration_members=continuity_declaration_members,
        supplemental_context_ids=supplemental_context_ids,
        declaration_progress=declaration_progress,
    )
    observations = _src.assemble_authentication_sessions(evidence, continuity_declarations)
    derived = [_src._canonical_derived_observation(item) for item in observations]
    disposition_ids = set(lifecycle["candidate_ids"])
    references = sorted(
        {
            (event_id, digest)
            for item in observations
            for event_id, digest in _src._observation_evidence_references(item)
            if event_id in disposition_ids
        }
    )
    if not derived or not references:
        raise ValueError("derived_publication_requires_observed_source_coverage")
    source_references = [
        {"id": event_id, "sha256": digest}
        for event_id, digest in references
    ]
    derived_output_digest = _src._derived_output_digest(derived)
    manifest = {
        "contract": "sli.warm-derived-publication.v1",
        "policy_fingerprint": lifecycle["policy_fingerprint"],
        "archive_requirement": lifecycle["archive_requirement"],
        "read_representation": lifecycle["read_representation"],
        "source_ids": [item["id"] for item in source_references],
        "candidate_identity_sha256": lifecycle["candidate_identity_sha256"],
        "source_reference_digest": _src._source_reference_digest(source_references),
        "derived_output_digest": derived_output_digest,
        "declaration_progress_digest": (
            lifecycle["declaration_progress"]["digest"]
            if lifecycle.get("declaration_progress") is not None else None
        ),
        "readback_required": True,
    }
    manifest["manifest_digest"] = _src.hashlib.sha256(
        _src.json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "descriptor_lifecycle": lifecycle,
        "source_references": source_references,
        "derived": derived,
        "derived_output_digest": derived_output_digest,
        "manifest": manifest,
        "archive": None,
        "read_availability": (
            "derived_only_available"
            if lifecycle["archive_requirement"] == "no_archive"
            else "source_archived"
        ),
    }


def _derived_publication_from_frozen_plan(
    conn: _src.Any, frozen: dict[str, _src.Any], source_rows: list[dict[str, _src.Any]],
) -> dict[str, _src.Any] | None:
    lifecycle = frozen.get("descriptor_lifecycle")
    if not lifecycle:
        return None
    with conn.cursor() as cur:
        context = _src.load_verified_lifecycle_context(
            cur, candidate_rows=source_rows, lifecycle=dict(lifecycle),
        )
    evidence = tuple(
        _src.AuthenticationEvidence(
            source_event_id=int(row["source_event_id"]),
            source_record_id=int(row["source_record_id"]),
            event_key=int(row["event_key"]),
            descriptor_source=str(row["descriptor_source"]),
            descriptor_stream=str(row["descriptor_stream"]),
            server_id=int(row["server_id"]),
            channel_id=int(row["channel_id"]),
            provider_name=str(row["provider_name"]),
            logon_id=row.get("logon_id"),
            observed_at_utc=_src._parse_utc(row["observed_at_utc"]),
            normalized_hash=str(row["normalized_hash"]),
            principal=row.get("principal"),
            host=row.get("host"),
            logon_type=row.get("logon_type"),
            privilege_marker=row.get("privilege_marker"),
        )
        for row in context.get("evidence") or []
    )
    declarations = tuple(
        _src.ContinuityDeclaration(
            scope_identity=str(row["scope_identity"]),
            descriptor_source=str(row["descriptor_source"]),
            descriptor_stream=str(row["descriptor_stream"]),
            server_id=int(row["server_id"]),
            channel_id=int(row["channel_id"]),
            provider_name=str(row["provider_name"]),
            channel_generation_identity=str(row["channel_generation_identity"]),
            source_event_ids=tuple(int(value) for value in row["source_event_ids"]),
            source_hashes=tuple(str(value) for value in row["source_hashes"]),
            first_event_record_id=int(row["first_event_record_id"]),
            last_event_record_id=int(row["last_event_record_id"]),
            completeness=str(row["completeness"]),
        )
        for row in context.get("continuity_declarations") or []
    )
    source_by_id = {
        int(row["id"]): (
            str(row["normalized_hash"]).lower()
            if isinstance(row["normalized_hash"], str)
            else bytes(row["normalized_hash"]).hex()
        )
        for row in source_rows
    }
    evidence_by_id = {item.source_event_id: item.normalized_hash for item in evidence}
    candidate_ids = {int(value) for value in lifecycle.get("candidate_ids") or ()}
    supplemental_ids = {
        int(value) for value in lifecycle.get("supplemental_context_ids") or ()
    }
    if (
        {event_id: evidence_by_id.get(event_id) for event_id in candidate_ids}
        != source_by_id
        or set(evidence_by_id) != candidate_ids | supplemental_ids
    ):
        raise RuntimeError("descriptor_source_evidence_does_not_match_frozen_batch")
    publication = _src._build_derived_publication(
        source=lifecycle["source"],
        stream=lifecycle["stream"],
        event_keys=tuple(lifecycle["event_keys"]),
        evidence=evidence,
        continuity_declarations=declarations,
        continuity_declaration_scope_identity=(
            str(lifecycle["continuity_declaration_scope_identity"])
            if lifecycle.get("continuity_declaration_scope_identity") is not None
            else None
        ),
        continuity_declaration_sha256=(
            str(lifecycle["continuity_declaration_sha256"])
            if lifecycle.get("continuity_declaration_sha256") is not None
            else None
        ),
        candidate_ids=tuple(int(value) for value in lifecycle["candidate_ids"]),
        continuity_declaration_members=tuple(
            dict(value)
            for value in lifecycle.get("continuity_declaration_members") or ()
        ),
        supplemental_context_ids=tuple(
            int(value) for value in lifecycle.get("supplemental_context_ids") or ()
        ),
        declaration_progress=(
            dict(lifecycle["declaration_progress"])
            if lifecycle.get("declaration_progress") is not None else None
        ),
    )
    if publication["descriptor_lifecycle"] != lifecycle:
        raise RuntimeError("descriptor_policy_changed_after_plan")
    publication["batch_identity"] = frozen["identity_sha256"]
    return publication


def _stage_derived_output(
    port: int, stage: str, publication: dict[str, _src.Any],
) -> None:
    expected = _src._expected_derived_output_row(publication)
    _src._http_query(port, _src.CREATE_DERIVED_OUTPUT_INPUT.format(db=stage))
    staged_row = {
        **expected,
        "published_at_utc": _src.datetime.now(_src.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        ),
    }
    inserted, interrupted = _src._http_insert_json_rows(
        port, f"{stage}.authentication_session_derived_output_input", [staged_row],
    )
    if interrupted or inserted != 1:
        raise RuntimeError("derived_output_staging_incomplete")
    staged = _src._clickhouse_json(
        port,
        "SELECT output_identity,batch_identity,candidate_identity_sha256,"
        "policy_fingerprint,derived_output_digest,source_reference_digest,"
        "manifest_digest,continuity_declaration_scope_identity,"
        "continuity_declaration_sha256,source_count,observation_count,payload_json,"
        "toString(published_at_utc) published_at_utc "
        f"FROM {stage}.authentication_session_derived_output_input",
    )
    _src.classify_derived_output_readback(publication, staged)
    _src._http_query(
        port,
        f"INSERT INTO {_src.DATABASE}.authentication_session_derived_outputs SELECT "
        "toFixedString(output_identity,64),toFixedString(batch_identity,64),"
        "toFixedString(candidate_identity_sha256,64),"
        "toFixedString(policy_fingerprint,64),"
        "toFixedString(derived_output_digest,64),"
        "toFixedString(source_reference_digest,64),"
        "toFixedString(manifest_digest,64),"
        "continuity_declaration_scope_identity,"
        "toFixedString(continuity_declaration_sha256,64),"
        "source_count,observation_count,"
        "payload_json,published_at_utc "
        f"FROM {stage}.authentication_session_derived_output_input "
        "ORDER BY output_identity",
    )
