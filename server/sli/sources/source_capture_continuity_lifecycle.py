"""Split out of ``server.sli.sources.source_capture_continuity`` (plan 7.2b).

Module-level names of ``source_capture_continuity`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.sources.source_capture_continuity as _src


def _load_verified_lifecycle_range_context(
    cur: _src.Any,
    *,
    candidate_rows: list[_src.Mapping[str, _src.Any]],
    lifecycle: _src.Mapping[str, _src.Any],
) -> dict[str, list[dict[str, _src.Any]]]:
    members_value = lifecycle.get("continuity_declaration_members") or ()
    if not isinstance(members_value, (list, tuple)) or len(members_value) > _src.MAX_CONTINUITY_DECLARATION_MEMBERS:
        raise _src.CaptureContinuityError("capture_declaration_member_count_out_of_bounds")
    members = [dict(value) for value in members_value]
    payload = _src.json.dumps(members, sort_keys=True, separators=(",", ":"))
    range_sha256 = _src.sha256(payload.encode("utf-8")).hexdigest()
    if (
        not members
        or _src._digest(
            lifecycle.get("continuity_declaration_sha256"),
            "continuity_declaration_sha256",
        ) != range_sha256
        or _src._required_text(
            lifecycle.get("continuity_declaration_scope_identity"),
            "continuity_declaration_scope_identity",
        ) != f"{_src.RANGE_CONTRACT_ID}:{range_sha256}"
    ):
        raise _src.CaptureContinuityError("capture_range_identity_mismatch")
    declarations: list[dict[str, _src.Any]] = []
    rebuilt_declarations: list[_src.CaptureDeclaration] = []
    for member in members:
        cur.execute(
            """select d.*,raw.sha256 as current_raw_log_sha256
                 from source_capture_continuity_declarations d
                 join raw_log_files raw on raw.id=d.raw_log_file_id
                 where d.scope_identity=%s and d.declaration_sha256=%s
                   and d.raw_log_file_id=%s""",
            (
                _src._required_text(member.get("scope_identity"), "scope_identity"),
                _src._digest(member.get("declaration_sha256"), "declaration_sha256"),
                _src._positive_int(member.get("raw_log_file_id"), "raw_log_file_id"),
            ),
        )
        rows = [dict(row) for row in cur.fetchall()]
        if len(rows) != 1:
            raise _src.CaptureContinuityError("capture_declaration_missing_or_ambiguous")
        declaration = rows[0]
        covered_value = declaration.get("covered_source_events") or ()
        if len(covered_value) > _src.MAX_CONTINUITY_SOURCE_REFERENCES:
            raise _src.CaptureContinuityError("capture_source_reference_count_out_of_bounds")
        covered = list(covered_value)
        rebuilt = _src.build_capture_declaration({
            "collection_run_id": declaration["collection_run_id"],
            "raw_log_file_id": declaration["raw_log_file_id"],
            "raw_log_sha256": declaration["raw_log_sha256"],
            "server_id": declaration["server_id"],
            "log_source_id": declaration["log_source_id"],
            "descriptor_source": declaration["descriptor_source"],
            "descriptor_stream": declaration["descriptor_stream"],
            "provider_name": declaration["provider_name"],
            "channel_value": declaration["channel_value"],
            "channel_generation_identity": declaration["channel_generation_identity"],
            "selector_event_ids": declaration["selector_event_ids"],
            "query_exhausted": declaration["query_exhausted"],
            "capture_status": "completed",
            "cursor_strategy": "record_id",
            "capture_after_record_id": declaration["capture_after_record_id"],
            "capture_latest_record_id": declaration["capture_latest_record_id"],
            "truncated": False,
            "source_events": [
                {
                    "id": row.get("id"), "record_id": row.get("record_id"),
                    "event_key": row.get("event_key"),
                    "normalized_hash": row.get("sha256"),
                }
                for row in covered
            ],
        })
        if (
            rebuilt.scope_identity != declaration["scope_identity"]
            or rebuilt.declaration_sha256 != declaration["declaration_sha256"]
            or str(declaration.get("current_raw_log_sha256") or "").lower()
            != rebuilt.raw_log_sha256
        ):
            raise _src.CaptureContinuityError("capture_declaration_stale_or_tampered")
        expected_member = {
            "scope_identity": rebuilt.scope_identity,
            "declaration_sha256": rebuilt.declaration_sha256,
            "raw_log_file_id": rebuilt.raw_log_file_id,
            "first_event_record_id": rebuilt.first_event_record_id,
            "last_event_record_id": rebuilt.last_event_record_id,
            "selector_event_ids": list(rebuilt.selector_event_ids),
            "channel_generation_identity": rebuilt.channel_generation_identity,
        }
        if member != expected_member:
            raise _src.CaptureContinuityError("capture_range_member_mismatch")
        declarations.append(declaration)
        rebuilt_declarations.append(rebuilt)
    source_ids = [
        event_id
        for declaration in rebuilt_declarations
        for event_id in declaration.source_event_ids
    ]
    if len(source_ids) != len(set(source_ids)):
        raise _src.CaptureContinuityError("capture_range_source_ids_ambiguous")
    cur.execute(
        """select e.id,e.event_record_id,e.event_id,e.server_id,e.log_source_id,e.channel_id,
                    e.raw_log_file_id,e.logon_id,e.time_created_utc,encode(e.normalized_hash,'hex') as normalized_hash,
                    e.target_user_name as principal,e.workstation_name as host,f.logon_type,
                    channel.value as channel_value,provider.value as provider_name,
                    raw.sha256 as raw_log_sha256
             from events_v2_core e join storage_v2_channel channel on channel.id=e.channel_id
             left join storage_v2_provider provider on provider.id=e.provider_id
             join raw_log_files raw on raw.id=e.raw_log_file_id
             left join event_facts_v2 f on f.event_id=e.id
             where e.id=any(%s::bigint[]) order by e.event_record_id,e.id""",
        (source_ids,),
    )
    evidence = [dict(row) for row in cur.fetchall()]
    selection = _src.prepare_descriptor_range(
        declarations, evidence, batch_limit=len(evidence),
    )
    candidate_ids = {int(row["id"]) for row in candidate_rows}
    if candidate_ids != set(selection["event_ids"]):
        raise _src.CaptureContinuityError("capture_candidate_not_exact_descriptor_batch")
    supplemental_ids = {
        int(value) for value in lifecycle.get("supplemental_context_ids") or ()
    }
    if supplemental_ids != set(selection["supplemental_event_ids"]):
        raise _src.CaptureContinuityError("capture_supplemental_context_changed")
    evidence_by_id = {int(row["id"]): row for row in evidence}
    for candidate in candidate_rows:
        source = evidence_by_id.get(int(candidate["id"]))
        if source is None or _src._digest(
            candidate.get("normalized_hash"), "capture_source_hash",
        ) != _src._digest(source.get("normalized_hash"), "capture_source_hash"):
            raise _src.CaptureContinuityError("capture_candidate_not_covered")
    selected_ids = candidate_ids | supplemental_ids
    selected_evidence = [
        {
            "source_event_id": int(row["id"]),
            "source_record_id": int(row["event_record_id"]),
            "event_key": int(row["event_id"]),
            "descriptor_source": str(lifecycle["source"]),
            "descriptor_stream": str(lifecycle["stream"]),
            "server_id": int(row["server_id"]),
            "channel_id": int(row["channel_id"]),
            "provider_name": str(row["provider_name"]),
            "logon_id": row.get("logon_id"),
            "observed_at_utc": row["time_created_utc"],
            "normalized_hash": _src._digest(row["normalized_hash"], "capture_source_hash"),
            "principal": row.get("principal"), "host": row.get("host"),
            "logon_type": row.get("logon_type"),
            "privilege_marker": (
                str(_src.PRIVILEGE_EVENT_KEY)
                if int(row["event_id"]) == _src.PRIVILEGE_EVENT_KEY else None
            ),
        }
        for row in evidence
        if int(row["id"]) in selected_ids
    ]
    channel_ids = {int(row["channel_id"]) for row in evidence}
    if len(channel_ids) != 1:
        raise _src.CaptureContinuityError("capture_candidate_scope_ambiguous")
    channel_id = next(iter(channel_ids))
    return {
        "evidence": selected_evidence,
        "continuity_declarations": [
            {
                "scope_identity": declaration.scope_identity,
                "descriptor_source": declaration.descriptor_source,
                "descriptor_stream": declaration.descriptor_stream,
                "server_id": declaration.server_id,
                "channel_id": channel_id,
                "provider_name": declaration.provider_name,
                "channel_generation_identity": declaration.channel_generation_identity,
                "source_event_ids": list(declaration.source_event_ids),
                "source_hashes": list(declaration.source_hashes),
                "first_event_record_id": declaration.first_event_record_id,
                "last_event_record_id": declaration.last_event_record_id,
                "completeness": "complete",
                "declaration_sha256": declaration.declaration_sha256,
            }
            for declaration in rebuilt_declarations
        ],
    }


def load_verified_lifecycle_context(
    cur: _src.Any, *, candidate_rows: list[_src.Mapping[str, _src.Any]], lifecycle: _src.Mapping[str, _src.Any],
) -> dict[str, list[dict[str, _src.Any]]]:
    """Load one persisted declaration and re-verify it against Storage V2.

    This is the sole bridge used by the warm lifecycle.  It deliberately takes
    a frozen batch reference, never evidence/declarations supplied by a caller.
    """
    if not candidate_rows:
        raise _src.CaptureContinuityError("capture_candidate_rows_required")
    if len(candidate_rows) > _src.MAX_CONTINUITY_SOURCE_REFERENCES:
        raise _src.CaptureContinuityError("capture_source_reference_count_out_of_bounds")
    if lifecycle.get("continuity_declaration_members"):
        return _src._load_verified_lifecycle_range_context(
            cur, candidate_rows=candidate_rows, lifecycle=lifecycle,
        )
    expected_scope_identity = _src._required_text(
        lifecycle.get("continuity_declaration_scope_identity"),
        "continuity_declaration_scope_identity",
    )
    expected_declaration_sha256 = _src._digest(
        lifecycle.get("continuity_declaration_sha256"),
        "continuity_declaration_sha256",
    )
    raw_ids = {int(row.get("raw_log_file_id") or 0) for row in candidate_rows}
    servers = {int(row.get("server_id") or 0) for row in candidate_rows}
    sources = {int(row.get("log_source_id") or 0) for row in candidate_rows}
    channels = {str(row.get("channel_value") or "") for row in candidate_rows}
    providers = {str(row.get("provider_name") or "") for row in candidate_rows}
    if any(len(values) != 1 for values in (raw_ids, servers, sources, channels, providers)):
        raise _src.CaptureContinuityError("capture_candidate_scope_ambiguous")
    raw_id = next(iter(raw_ids))
    cur.execute(
        """select d.*,raw.sha256 as current_raw_log_sha256
             from source_capture_continuity_declarations d
             join raw_log_files raw on raw.id=d.raw_log_file_id
             where d.scope_identity=%s and d.declaration_sha256=%s
               and d.raw_log_file_id=%s and d.server_id=%s and d.log_source_id=%s
               and d.descriptor_source=%s and d.descriptor_stream=%s
               and d.channel_value=%s and d.provider_name=%s""",
        (expected_scope_identity, expected_declaration_sha256,
         raw_id, next(iter(servers)), next(iter(sources)), str(lifecycle["source"]),
         str(lifecycle["stream"]), next(iter(channels)), next(iter(providers))),
    )
    declarations = [dict(row) for row in cur.fetchall()]
    if len(declarations) != 1:
        raise _src.CaptureContinuityError("capture_declaration_missing_or_ambiguous")
    declaration = declarations[0]
    covered_value = declaration.get("covered_source_events") or []
    if len(covered_value) > _src.MAX_CONTINUITY_SOURCE_REFERENCES:
        raise _src.CaptureContinuityError("capture_source_reference_count_out_of_bounds")
    covered = list(covered_value)
    scope = {
        "collection_run_id": declaration["collection_run_id"], "raw_log_file_id": declaration["raw_log_file_id"],
        "raw_log_sha256": declaration["raw_log_sha256"], "server_id": declaration["server_id"],
        "log_source_id": declaration["log_source_id"], "descriptor_source": declaration["descriptor_source"],
        "descriptor_stream": declaration["descriptor_stream"], "provider_name": declaration["provider_name"],
        "channel_value": declaration["channel_value"],
        "channel_generation_identity": declaration["channel_generation_identity"],
        "selector_event_ids": declaration["selector_event_ids"],
        "query_exhausted": declaration["query_exhausted"],
        "capture_status": "completed", "cursor_strategy": "record_id",
        "capture_after_record_id": declaration["capture_after_record_id"], "capture_latest_record_id": declaration["capture_latest_record_id"],
        "truncated": False,
        "source_events": [{"id": row.get("id"), "record_id": row.get("record_id"), "event_key": row.get("event_key"), "normalized_hash": row.get("sha256")} for row in covered],
    }
    rebuilt = _src.build_capture_declaration(scope)
    if (rebuilt.declaration_sha256 != declaration["declaration_sha256"]
            or rebuilt.scope_identity != declaration["scope_identity"]
            or str(declaration.get("current_raw_log_sha256") or "").lower() != rebuilt.raw_log_sha256):
        raise _src.CaptureContinuityError("capture_declaration_stale_or_tampered")
    ids = list(rebuilt.source_event_ids)
    cur.execute(
        """select e.id,e.event_record_id,e.event_id,e.server_id,e.log_source_id,e.channel_id,
                    e.raw_log_file_id,e.logon_id,e.time_created_utc,encode(e.normalized_hash,'hex') as normalized_hash,
                    e.target_user_name as principal,e.workstation_name as host,f.logon_type,
                    channel.value as channel_value,provider.value as provider_name,
                    raw.sha256 as raw_log_sha256
             from events_v2_core e join storage_v2_channel channel on channel.id=e.channel_id
             left join storage_v2_provider provider on provider.id=e.provider_id
             join raw_log_files raw on raw.id=e.raw_log_file_id
             left join event_facts_v2 f on f.event_id=e.id
             where e.id=any(%s::bigint[]) order by e.event_record_id,e.id""",
        (ids,),
    )
    evidence = [dict(row) for row in cur.fetchall()]
    selection = _src.prepare_descriptor_selection(
        declaration, evidence, batch_limit=len(evidence),
    )
    candidate_ids = {int(row["id"]) for row in candidate_rows}
    if candidate_ids != set(selection["event_ids"]):
        raise _src.CaptureContinuityError("capture_candidate_not_exact_descriptor_batch")
    candidate_hashes = {
        (int(row["id"]), _src._digest(
            row["normalized_hash"].hex() if isinstance(row.get("normalized_hash"), bytes)
            else row.get("normalized_hash"), "capture_source_hash",
        ))
        for row in candidate_rows
    }
    actual_hashes = {(int(row["id"]), _src._digest(row["normalized_hash"], "capture_source_hash")) for row in evidence}
    if not candidate_hashes.issubset(actual_hashes):
        raise _src.CaptureContinuityError("capture_candidate_not_covered")
    channels_by_id = {int(row["id"]): int(row["channel_id"]) for row in evidence}
    selected_evidence = []
    for row in evidence:
        if int(row["id"]) not in candidate_ids:
            continue
        selected_evidence.append({
            "source_event_id": int(row["id"]),
            "source_record_id": int(row["event_record_id"]),
            "event_key": int(row["event_id"]),
            "descriptor_source": str(lifecycle["source"]),
            "descriptor_stream": str(lifecycle["stream"]),
            "server_id": int(row["server_id"]),
            "channel_id": int(row["channel_id"]),
            "provider_name": str(row["provider_name"]),
            "logon_id": row.get("logon_id"),
            "observed_at_utc": row["time_created_utc"],
            "normalized_hash": _src._digest(row["normalized_hash"], "capture_source_hash"),
            "principal": row.get("principal"),
            "host": row.get("host"),
            "logon_type": row.get("logon_type"),
            "privilege_marker": (
                str(_src.PRIVILEGE_EVENT_KEY)
                if int(row["event_id"]) == _src.PRIVILEGE_EVENT_KEY else None
            ),
        })
    channel_ids = {channels_by_id[event_id] for event_id in candidate_ids}
    if len(channel_ids) != 1:
        raise _src.CaptureContinuityError("capture_candidate_scope_ambiguous")
    return {
        "evidence": selected_evidence,
        "continuity_declarations": [{
            "scope_identity": rebuilt.scope_identity,
            "descriptor_source": rebuilt.descriptor_source,
            "descriptor_stream": rebuilt.descriptor_stream,
            "server_id": rebuilt.server_id,
            "channel_id": next(iter(channel_ids)),
            "provider_name": rebuilt.provider_name,
            "channel_generation_identity": rebuilt.channel_generation_identity,
            "source_event_ids": list(rebuilt.source_event_ids),
            "source_hashes": list(rebuilt.source_hashes),
            "first_event_record_id": rebuilt.first_event_record_id,
            "last_event_record_id": rebuilt.last_event_record_id,
            "completeness": "complete",
            "declaration_sha256": rebuilt.declaration_sha256,
        }],
    }


def recheck_durable_promotion_continuity(
    cur: _src.Any, *, promotion_gate: _src.Mapping[str, _src.Any],
) -> None:
    """Re-open immutable provenance in the same transaction as disposition.

    Derived-output readback proves assembly-time state only.  The retention
    executor must prove the durable declaration and exact V2 material again
    before it deletes any source row.  The gate names identities and hashes;
    it never carries a caller-trusted declaration payload.
    """
    references = list(promotion_gate.get("source_references") or ())
    try:
        expected = {
            (
                _src._positive_int(item.get("id"), "promotion_source_event_id"),
                _src._digest(item.get("sha256"), "promotion_source_hash"),
            )
            for item in references
            if isinstance(item, _src.Mapping)
        }
    except (AttributeError, TypeError, _src.CaptureContinuityError) as exc:
        raise _src.CaptureContinuityError("promotion_source_references_invalid") from exc
    if not expected or len(expected) != len(references):
        raise _src.CaptureContinuityError("promotion_source_references_invalid")
    event_ids = sorted(event_id for event_id, _digest_value in expected)
    cur.execute(
        """select e.id,encode(e.normalized_hash,'hex') as normalized_hash,
                  e.raw_log_file_id,e.server_id,e.log_source_id,
                  channel.value as channel_value,provider.value as provider_name
             from events_v2_core e
             join storage_v2_channel channel on channel.id=e.channel_id
             left join storage_v2_provider provider on provider.id=e.provider_id
             where e.id=any(%s::bigint[]) order by e.id""",
        (event_ids,),
    )
    candidate_rows = [dict(row) for row in cur.fetchall()]
    actual = {
        (
            _src._positive_int(row.get("id"), "promotion_source_event_id"),
            _src._digest(row.get("normalized_hash"), "promotion_source_hash"),
        )
        for row in candidate_rows
    }
    if actual != expected:
        raise _src.CaptureContinuityError("promotion_source_material_changed")
    lifecycle = {
        "source": promotion_gate.get("source"),
        "stream": promotion_gate.get("stream"),
        "continuity_declaration_scope_identity": promotion_gate.get(
            "continuity_declaration_scope_identity"
        ),
        "continuity_declaration_sha256": promotion_gate.get(
            "continuity_declaration_sha256"
        ),
    }
    if promotion_gate.get("continuity_declaration_members"):
        lifecycle["continuity_declaration_members"] = list(
            promotion_gate["continuity_declaration_members"]
        )
        lifecycle["supplemental_context_ids"] = list(
            promotion_gate.get("supplemental_context_ids") or ()
        )
    context = _src.load_verified_lifecycle_context(
        cur, candidate_rows=candidate_rows, lifecycle=lifecycle,
    )
    if lifecycle.get("continuity_declaration_members"):
        observed_keys = sorted(
            {
                str(int(row["event_key"]))
                for row in context["evidence"]
                if int(row["source_event_id"]) in set(event_ids)
            },
            key=int,
        )
    else:
        observed_keys = sorted(
            {str(int(row["event_key"])) for row in context["evidence"]}, key=int,
        )
    try:
        expected_keys = sorted(
            {str(int(value)) for value in promotion_gate.get("event_keys") or ()},
            key=int,
        )
    except (TypeError, ValueError) as exc:
        raise _src.CaptureContinuityError("promotion_descriptor_event_keys_invalid") from exc
    if observed_keys != expected_keys:
        raise _src.CaptureContinuityError("promotion_descriptor_event_keys_changed")
