"""Split out of ``server.sli.sources.source_capture_continuity`` (plan 7.2b).

Module-level names of ``source_capture_continuity`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.sources.source_capture_continuity as _src


def prepare_descriptor_range(
    declarations: list[_src.Mapping[str, _src.Any]],
    source_rows: list[_src.Mapping[str, _src.Any]],
    *,
    batch_limit: int,
) -> dict[str, _src.Any]:
    """Compose exact adjacent complete captures into one boot-scoped selection."""
    if len(declarations) > _src.MAX_CONTINUITY_DECLARATION_MEMBERS:
        raise _src.CaptureContinuityError("capture_declaration_member_count_out_of_bounds")
    if len(source_rows) > _src.MAX_CONTINUITY_SOURCE_REFERENCES:
        raise _src.CaptureContinuityError("capture_source_reference_count_out_of_bounds")
    if batch_limit < 1:
        raise _src.CaptureContinuityError("capture_batch_limit_invalid")
    if not declarations:
        raise _src.CaptureContinuityError("capture_declarations_missing")
    ordered = sorted(
        declarations,
        key=lambda item: (
            _src._positive_int(item.get("first_event_record_id"), "first_event_record_id"),
            _src._positive_int(item.get("raw_log_file_id"), "raw_log_file_id"),
        ),
    )
    rows_by_raw: dict[int, list[_src.Mapping[str, _src.Any]]] = {}
    for row in source_rows:
        rows_by_raw.setdefault(
            _src._positive_int(row.get("raw_log_file_id"), "raw_log_file_id"), [],
        ).append(row)
    scope_fields = (
        "server_id", "log_source_id", "descriptor_source", "descriptor_stream",
        "provider_name", "channel_value", "channel_generation_identity",
    )
    expected_scope = tuple(str(ordered[0].get(field)) for field in scope_fields)
    expected_selector = _src._selector_event_ids(ordered[0].get("selector_event_ids"))
    members: list[dict[str, _src.Any]] = []
    authentication_rows: list[_src.Mapping[str, _src.Any]] = []
    previous_latest: int | None = None
    for declaration in ordered:
        if str(declaration.get("completeness") or "") != "complete":
            raise _src.CaptureContinuityError("capture_segment_not_complete")
        if tuple(str(declaration.get(field)) for field in scope_fields) != expected_scope:
            raise _src.CaptureContinuityError("capture_segment_scope_changed")
        if _src._selector_event_ids(declaration.get("selector_event_ids")) != expected_selector:
            raise _src.CaptureContinuityError("capture_segment_scope_changed")
        rebuilt = _src._rebuild_durable_declaration(declaration)
        after = _src._nonnegative_int(
            declaration.get("capture_after_record_id"), "capture_after_record_id",
        )
        latest = _src._positive_int(
            declaration.get("capture_latest_record_id"), "capture_latest_record_id",
        )
        if previous_latest is not None and after != previous_latest:
            raise _src.CaptureContinuityError("capture_segment_gap")
        raw_id = _src._positive_int(declaration.get("raw_log_file_id"), "raw_log_file_id")
        segment_rows = rows_by_raw.pop(raw_id, [])
        covered = list(declaration.get("covered_source_events") or ())
        expected = {
            (
                _src._positive_int(item.get("id"), "capture_source_event_id"),
                _src._positive_int(item.get("record_id"), "capture_source_record_id"),
                _src._positive_int(item.get("event_key"), "capture_source_event_key"),
                _src._digest(item.get("sha256"), "capture_source_hash"),
            )
            for item in covered
            if isinstance(item, _src.Mapping)
        }
        if len(expected) != len(covered):
            raise _src.CaptureContinuityError("capture_declaration_covered_events_invalid")
        actual = {_src._normalized_source_row(row) for row in segment_rows}
        if len(actual) != len(segment_rows) or actual != expected:
            raise _src.CaptureContinuityError("capture_source_material_mismatch")
        raw_sha = _src._digest(declaration.get("raw_log_sha256"), "raw_log_sha256")
        for row in segment_rows:
            if (
                _src._positive_int(row.get("server_id"), "server_id")
                != _src._positive_int(declaration.get("server_id"), "server_id")
                or _src._positive_int(row.get("log_source_id"), "log_source_id")
                != _src._positive_int(declaration.get("log_source_id"), "log_source_id")
                or _src._required_text(row.get("channel_value"), "channel_value")
                != _src._required_text(declaration.get("channel_value"), "channel_value")
                or _src._required_text(row.get("provider_name"), "provider_name")
                != _src._required_text(declaration.get("provider_name"), "provider_name")
                or _src._digest(row.get("raw_log_sha256"), "raw_log_sha256") != raw_sha
            ):
                raise _src.CaptureContinuityError("capture_source_scope_mismatch")
        authentication_rows.extend(
            row for row in segment_rows
            if int(row["event_id"]) in _src.AUTHENTICATION_EVENT_KEYS
        )
        members.append({
            "scope_identity": _src._required_text(
                declaration.get("scope_identity"), "scope_identity",
            ),
            "declaration_sha256": _src._digest(
                declaration.get("declaration_sha256"), "declaration_sha256",
            ),
            "raw_log_file_id": raw_id,
            "first_event_record_id": _src._positive_int(
                declaration.get("first_event_record_id"), "first_event_record_id",
            ),
            "last_event_record_id": _src._positive_int(
                declaration.get("last_event_record_id"), "last_event_record_id",
            ),
            "selector_event_ids": list(rebuilt.selector_event_ids),
            "channel_generation_identity": rebuilt.channel_generation_identity,
        })
        previous_latest = latest
    if rows_by_raw:
        raise _src.CaptureContinuityError("capture_source_material_outside_range")
    authentication_rows.sort(
        key=lambda row: (int(row["event_record_id"]), int(row["id"])),
    )
    boots = [
        row for row in authentication_rows
        if int(row["event_id"]) == _src.BOOT_EVENT_KEY
    ]
    if len(boots) != 1:
        raise _src.CaptureContinuityError("capture_boot_scope_ambiguous")
    lifecycle_rows = [
        row for row in authentication_rows
        if int(row["event_id"]) in _src.AUTHENTICATION_LIFECYCLE_KEYS
    ]
    supplemental_rows = [
        row for row in authentication_rows
        if int(row["event_id"]) in _src.AUTHENTICATION_SUPPLEMENTAL_KEYS
    ]
    if len(lifecycle_rows) + len(supplemental_rows) > batch_limit:
        raise _src.CaptureContinuityError("capture_descriptor_batch_exceeds_limit")
    member_payload = _src.json.dumps(members, sort_keys=True, separators=(",", ":"))
    range_sha256 = _src.sha256(member_payload.encode("utf-8")).hexdigest()
    return {
        "event_ids": [int(row["id"]) for row in lifecycle_rows],
        "event_keys": sorted(
            {str(int(row["event_id"])) for row in lifecycle_rows}, key=int,
        ),
        "supplemental_event_ids": [int(row["id"]) for row in supplemental_rows],
        "declaration_members": members,
        "declaration_scope_identity": f"{_src.RANGE_CONTRACT_ID}:{range_sha256}",
        "declaration_sha256": range_sha256,
    }


def prepare_descriptor_selection(
    declaration: _src.Mapping[str, _src.Any], source_rows: list[_src.Mapping[str, _src.Any]], *, batch_limit: int,
) -> dict[str, _src.Any]:
    """Freeze a descriptor batch only from its durable full raw-file scope.

    The selector receives the durable row plus the exact Storage V2 rows that
    the row claims.  It rejects a subset before it names any lifecycle events;
    the returned IDs are therefore selection output, never caller evidence.
    """
    if batch_limit < 1:
        raise _src.CaptureContinuityError("capture_batch_limit_invalid")
    _src._rebuild_durable_declaration(declaration)
    covered = declaration.get("covered_source_events")
    if not isinstance(covered, list) or not covered:
        raise _src.CaptureContinuityError("capture_declaration_covered_events_missing")
    expected = {
        (
            _src._positive_int(item.get("id"), "capture_source_event_id"),
            _src._positive_int(item.get("record_id"), "capture_source_record_id"),
            _src._positive_int(item.get("event_key"), "capture_source_event_key"),
            _src._digest(item.get("sha256"), "capture_source_hash"),
        )
        for item in covered
        if isinstance(item, _src.Mapping)
    }
    if len(expected) != len(covered):
        raise _src.CaptureContinuityError("capture_declaration_covered_events_invalid")
    actual = {_src._normalized_source_row(row) for row in source_rows}
    if len(actual) != len(source_rows) or actual != expected:
        raise _src.CaptureContinuityError("capture_source_material_mismatch")
    for field in ("raw_log_file_id", "server_id", "log_source_id"):
        expected_value = _src._positive_int(declaration.get(field), field)
        if any(_src._positive_int(row.get(field), field) != expected_value for row in source_rows):
            raise _src.CaptureContinuityError("capture_source_scope_mismatch")
    for field in ("channel_value", "provider_name"):
        expected_value = _src._required_text(declaration.get(field), field)
        if any(_src._required_text(row.get(field), field) != expected_value for row in source_rows):
            raise _src.CaptureContinuityError("capture_source_scope_mismatch")
    raw_digest = _src._digest(declaration.get("raw_log_sha256"), "raw_log_sha256")
    if any(
        _src._digest(row.get("raw_log_sha256"), "raw_log_sha256") != raw_digest
        for row in source_rows
    ):
        raise _src.CaptureContinuityError("capture_raw_source_changed")
    if (
        _src._required_text(declaration.get("descriptor_source"), "descriptor_source")
        != "sli.windows.ad-dc"
        or _src._required_text(declaration.get("descriptor_stream"), "descriptor_stream")
        != "Security"
    ):
        raise _src.CaptureContinuityError("capture_descriptor_scope_unsupported")

    lifecycle_rows = sorted(
        (row for row in source_rows if int(row["event_id"]) in _src.AUTHENTICATION_EVENT_KEYS),
        key=lambda row: (int(row["event_record_id"]), int(row["id"])),
    )
    if not lifecycle_rows:
        raise _src.CaptureContinuityError("capture_descriptor_events_missing")
    if not any(
        int(row["event_id"]) == _src.BOOT_EVENT_KEY for row in lifecycle_rows
    ):
        raise _src.CaptureContinuityError("capture_boot_boundary_missing")
    if len(lifecycle_rows) > batch_limit:
        raise _src.CaptureContinuityError("capture_descriptor_batch_exceeds_limit")
    return {
        "event_ids": [int(row["id"]) for row in lifecycle_rows],
        "event_keys": sorted({str(int(row["event_id"])) for row in lifecycle_rows}, key=int),
        "declaration_scope_identity": _src._required_text(
            declaration.get("scope_identity"), "scope_identity",
        ),
        "declaration_sha256": _src._digest(
            declaration.get("declaration_sha256"), "declaration_sha256",
        ),
    }


def _rebuild_durable_declaration(declaration: _src.Mapping[str, _src.Any]) -> _src.CaptureDeclaration:
    covered = declaration.get("covered_source_events")
    if not isinstance(covered, list):
        raise _src.CaptureContinuityError("capture_declaration_covered_events_invalid")
    if str(declaration.get("completeness") or "") != "complete":
        raise _src.CaptureContinuityError("capture_segment_not_complete")
    rebuilt = _src.build_capture_declaration({
        "collection_run_id": declaration.get("collection_run_id"),
        "raw_log_file_id": declaration.get("raw_log_file_id"),
        "raw_log_sha256": declaration.get("raw_log_sha256"),
        "server_id": declaration.get("server_id"),
        "log_source_id": declaration.get("log_source_id"),
        "descriptor_source": declaration.get("descriptor_source"),
        "descriptor_stream": declaration.get("descriptor_stream"),
        "provider_name": declaration.get("provider_name"),
        "channel_value": declaration.get("channel_value"),
        "channel_generation_identity": declaration.get("channel_generation_identity"),
        "selector_event_ids": declaration.get("selector_event_ids"),
        "query_exhausted": declaration.get("query_exhausted"),
        "capture_status": "completed",
        "cursor_strategy": "record_id",
        "capture_after_record_id": declaration.get("capture_after_record_id"),
        "capture_latest_record_id": declaration.get("capture_latest_record_id"),
        "truncated": False,
        "source_events": [
            {
                "id": row.get("id"), "record_id": row.get("record_id"),
                "event_key": row.get("event_key"), "normalized_hash": row.get("sha256"),
            }
            for row in covered if isinstance(row, _src.Mapping)
        ],
    })
    if (
        len(rebuilt.source_event_ids) != len(covered)
        or rebuilt.scope_identity != str(declaration.get("scope_identity") or "")
        or rebuilt.declaration_sha256 != str(declaration.get("declaration_sha256") or "")
        or rebuilt.first_event_record_id
        != _src._positive_int(declaration.get("first_event_record_id"), "first_event_record_id")
        or rebuilt.last_event_record_id
        != _src._positive_int(declaration.get("last_event_record_id"), "last_event_record_id")
    ):
        raise _src.CaptureContinuityError("capture_declaration_stale_or_tampered")
    current_raw = declaration.get("current_raw_log_sha256")
    if (
        current_raw is not None
        and _src._digest(current_raw, "current_raw_log_sha256") != rebuilt.raw_log_sha256
    ):
        raise _src.CaptureContinuityError("capture_raw_source_changed")
    return rebuilt


def _normalized_source_row(row: _src.Mapping[str, _src.Any]) -> tuple[int, int, int, str]:
    return (
        _src._positive_int(row.get("id"), "capture_source_event_id"),
        _src._positive_int(row.get("event_record_id"), "capture_source_record_id"),
        _src._positive_int(row.get("event_id"), "capture_source_event_key"),
        _src._digest(row.get("normalized_hash"), "capture_source_hash"),
    )
