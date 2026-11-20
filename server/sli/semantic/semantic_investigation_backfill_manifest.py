"""Split out of ``server.sli.semantic.semantic_investigation_backfill`` (plan 7.2b).

Module-level names of ``semantic_investigation_backfill`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.semantic.semantic_investigation_backfill as _src


def _history_cohort_entry(event_id: int, provided: _src.Mapping[str, object] | None) -> dict[str, object]:
    supplied = dict(provided or {})
    count = int(supplied.get("count", 0))
    high = int(supplied.get("high_watermark", 0))
    min_id = supplied.get("min_id")
    max_id = supplied.get("max_id")
    digest = str(supplied.get("cohort_digest") or _src.security_history_cohort_digest(()))
    if count < 0 or high < 0 or len(digest) != 64:
        raise ValueError("security history cohort is invalid")
    if count == 0:
        if min_id is not None or max_id is not None or high != 0:
            raise ValueError("empty security history cohort is invalid")
        digest = _src.security_history_cohort_digest(())
    elif min_id is None or max_id is None or int(min_id) > int(max_id) or int(max_id) != high:
        raise ValueError("security history cohort bounds are invalid")
    return {
        "predicate": _src.security_history_predicate(event_id),
        "high_watermark": high,
        "count": count,
        "cohort_digest": digest,
        "min_id": None if min_id is None else int(min_id),
        "max_id": None if max_id is None else int(max_id),
        "cursor": 0,
        "normalized_count": 0,
        "outbox_count": 0,
        "action_count": 0,
        "state": "no_retained_events" if count == 0 else "planned",
        "terminal_reason": "no_retained_events" if count == 0 else None,
        "samples": {"incomplete_ids": [], "errors": []},
    }


def new_security_history_manifest(
    *, database_identity: _src.Mapping[str, str], plan_digest: str,
    cohorts: _src.Mapping[int, _src.Mapping[str, object]],
    batch_limit: int = _src.SECURITY_HISTORY_BATCH_MAX,
) -> dict[str, object]:
    """Build an immutable, compact local checkpoint; never retain raw ID lists."""
    identity = {name: str(database_identity.get(name) or "") for name in ("host", "database", "role")}
    if not all(identity.values()) or len(str(plan_digest)) != 64:
        raise ValueError("security history manifest identity is invalid")
    selected_limit = int(batch_limit)
    if not 1 <= selected_limit <= _src.MAX_PRODUCER_BATCH:
        raise ValueError("security history batch limit is invalid")
    event_entries = {
        str(event_id): _src._history_cohort_entry(event_id, cohorts.get(event_id))
        for event_id in _src.SECURITY_HISTORY_EVENT_IDS
    }
    return {
        "manifest_type": _src.SECURITY_HISTORY_MANIFEST_TYPE,
        "created_at_utc": _src.datetime.now(_src.timezone.utc).isoformat(),
        "updated_at_utc": _src.datetime.now(_src.timezone.utc).isoformat(),
        "database_identity": identity,
        "runtime_mode": "investigation-v1",
        "source": "events_v2_core",
        "semantic_contract_version": _src.SEMANTIC_CONTRACT_VERSION,
        "normalizer": {"id": _src.NORMALIZER_ID, "version": _src.NORMALIZER_VERSION},
        "assembler": {"id": _src.ASSEMBLER_ID, "version": _src.ASSEMBLER_VERSION},
        "vocabulary": list(_src.SECURITY_HISTORY_EVENT_IDS),
        "selection_fingerprint": _src.security_history_selection_fingerprint(batch_limit=selected_limit),
        "batch_limit": selected_limit,
        "moves_collection_cursors": False,
        "contacts_sources": False,
        "plan_digest": str(plan_digest),
        "events": event_entries,
    }


def new_security_history_manifest_v2(
    *, database_identity: _src.Mapping[str, str], plan_digest: str,
    cohorts: _src.Mapping[int, _src.Mapping[str, object]],
    semantic_context_cohort: _src.Mapping[str, object],
    supersedes: _src.Mapping[str, object] | None,
) -> dict[str, object]:
    """Create a v2 replacement without reclassifying routine logons as signals.

    Raw coverage remains frozen for every agreed Event ID.  Only 4624 has a
    narrower semantic cohort: the existing exact password-reset context.
    """
    raw = _src.new_security_history_manifest(
        database_identity=database_identity,
        plan_digest=plan_digest,
        cohorts=cohorts,
        batch_limit=_src.MAX_PRODUCER_BATCH,
    )
    predecessor: dict[str, str] | None = None
    if supersedes is not None:
        predecessor = {
            "manifest_type": str(supersedes.get("manifest_type") or ""),
            "plan_digest": str(supersedes.get("plan_digest") or "").casefold(),
            "reason": str(supersedes.get("reason") or ""),
        }
        if (
            predecessor["manifest_type"] != _src.SECURITY_HISTORY_MANIFEST_TYPE_V1
            or len(predecessor["plan_digest"]) != 64
            or any(char not in "0123456789abcdef" for char in predecessor["plan_digest"])
            or predecessor["reason"] != _src.SECURITY_HISTORY_SUPERSEDE_REASON
        ):
            raise ValueError("security history v2 supersedes contract is invalid")
    context_count = int(semantic_context_cohort.get("count", 0))
    context_digest = str(semantic_context_cohort.get("cohort_digest") or "")
    reset_high_watermark = int(semantic_context_cohort.get("reset_high_watermark", 0))
    if context_count < 0 or len(context_digest) != 64 or reset_high_watermark < 0:
        raise ValueError("security history v2 context cohort is invalid")
    if reset_high_watermark != int(raw["events"]["4724"]["high_watermark"]):
        raise ValueError("security history v2 reset context boundary is invalid")
    events: dict[str, dict[str, object]] = {}
    for event_id in _src.SECURITY_HISTORY_EVENT_IDS:
        entry = dict(raw["events"][str(event_id)])
        raw_count = int(entry["count"])
        entry["raw_retained_count"] = raw_count
        entry["raw_cohort_digest"] = str(entry["cohort_digest"])
        if event_id == 4624:
            entry["semantic_scope"] = "password_reset_context_only"
            entry["semantic_expected_count"] = context_count
            entry["semantic_context_digest"] = context_digest
            entry["semantic_context_reset_high_watermark"] = reset_high_watermark
            entry["count"] = context_count
            entry["normalized_count"] = 0
            entry["outbox_count"] = 0
            entry["action_count"] = 0
            entry["state"] = "no_retained_events" if context_count == 0 else "planned"
            entry["terminal_reason"] = (
                "no_retained_events" if context_count == 0 else None
            )
        else:
            entry["semantic_scope"] = "all_retained"
            entry["semantic_expected_count"] = raw_count
            entry["semantic_context_digest"] = None
        events[str(event_id)] = entry
    raw.update({
        "manifest_type": _src.SECURITY_HISTORY_MANIFEST_TYPE_V2,
        "selection_fingerprint": _src.security_history_v2_selection_fingerprint(
            batch_limit=_src.MAX_PRODUCER_BATCH,
        ),
        "supersedes": predecessor,
        "semantic_context_strategy": "successful_password_reset_same_domain_sid_within_1h",
        "events": events,
    })
    return raw


def security_history_cohorts(
    cur: _src.Any, *, high_watermarks: _src.Mapping[int, int] | None = None,
) -> dict[int, dict[str, object]]:
    """Read compact exact retained identities without serializing source rows."""
    result: dict[int, dict[str, object]] = {}
    frozen = {int(key): int(value) for key, value in (high_watermarks or {}).items()}
    for event_id in _src.SECURITY_HISTORY_EVENT_IDS:
        predicate = _src.security_history_predicate(event_id)
        limit_clause = "and core.id<=%s" if event_id in frozen else ""
        parameters: tuple[object, ...] = (predicate["provider"], event_id, *(
            (frozen[event_id],) if event_id in frozen else ()
        ))
        cur.execute(
            f"""
            select core.id,encode(core.normalized_hash,'hex') as normalized_hash
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            join storage_v2_provider provider on provider.id=core.provider_id
            where channel.value='Security' and provider.value=%s and core.event_id=%s
              {limit_clause}
            order by core.id
            """,
            parameters,
        )
        count = 0
        minimum: int | None = None
        maximum: int | None = None
        previous = -1
        digest = _src.sha256()
        while page := cur.fetchmany(_src.SECURITY_HISTORY_COHORT_FETCH_SIZE):
            for raw_row in page:
                row = dict(raw_row)
                source_event_id = int(row["id"])
                normalized_hash = _src._history_hash_text(row["normalized_hash"])
                if source_event_id <= previous:
                    raise RuntimeError("security history cohort order is invalid")
                previous = source_event_id
                digest.update(str(source_event_id).encode("ascii"))
                digest.update(b":")
                digest.update(normalized_hash.encode("ascii"))
                digest.update(b"\n")
                count += 1
                minimum = source_event_id if minimum is None else minimum
                maximum = source_event_id
        result[event_id] = {
            "high_watermark": maximum or 0,
            "count": count,
            "cohort_digest": digest.hexdigest(),
            "min_id": minimum,
            "max_id": maximum,
        }
    return result


def validate_security_history_manifest(
    manifest: _src.Mapping[str, object], *, database_identity: _src.Mapping[str, str],
    cohorts: _src.Mapping[int, _src.Mapping[str, object]] | None = None,
    plan_digest: str | None = None,
) -> None:
    """Reject changed immutable pass identity before resume or readback mutation."""
    manifest_type = str(manifest.get("manifest_type") or "")
    try:
        batch_limit = int(manifest.get("batch_limit") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("security history manifest batch limit is invalid") from exc
    if not 1 <= batch_limit <= _src.MAX_PRODUCER_BATCH:
        raise RuntimeError("security history manifest batch limit is invalid")
    if manifest_type not in {
        _src.SECURITY_HISTORY_MANIFEST_TYPE_V1,
        _src.SECURITY_HISTORY_MANIFEST_TYPE_V2,
    }:
        raise RuntimeError("security history manifest type is invalid")
    selection_fingerprint = (
        _src.security_history_v2_selection_fingerprint(batch_limit=batch_limit)
        if manifest_type == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2
        else _src.security_history_selection_fingerprint(batch_limit=batch_limit)
    )
    expected = {
        "manifest_type": manifest_type,
        "database_identity": {name: str(database_identity.get(name) or "") for name in ("host", "database", "role")},
        "runtime_mode": "investigation-v1",
        "source": "events_v2_core",
        "semantic_contract_version": _src.SEMANTIC_CONTRACT_VERSION,
        "normalizer": {"id": _src.NORMALIZER_ID, "version": _src.NORMALIZER_VERSION},
        "assembler": {"id": _src.ASSEMBLER_ID, "version": _src.ASSEMBLER_VERSION},
        "vocabulary": list(_src.SECURITY_HISTORY_EVENT_IDS),
        "selection_fingerprint": selection_fingerprint,
        "batch_limit": batch_limit,
        "moves_collection_cursors": False,
        "contacts_sources": False,
    }
    if plan_digest is not None:
        expected["plan_digest"] = str(plan_digest)
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise RuntimeError("security history manifest immutable contract changed")
    if manifest_type == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2:
        predecessor = manifest.get("supersedes")
        if predecessor is not None:
            if not isinstance(predecessor, _src.Mapping) or (
                str(predecessor.get("manifest_type") or "")
                != _src.SECURITY_HISTORY_MANIFEST_TYPE_V1
            ) or str(predecessor.get("reason") or "") != _src.SECURITY_HISTORY_SUPERSEDE_REASON:
                raise RuntimeError("security history v2 supersedes contract is invalid")
            predecessor_digest = str(predecessor.get("plan_digest") or "").casefold()
            if len(predecessor_digest) != 64 or any(
                char not in "0123456789abcdef" for char in predecessor_digest
            ):
                raise RuntimeError("security history v2 supersedes contract is invalid")
        if manifest.get("semantic_context_strategy") != (
            "successful_password_reset_same_domain_sid_within_1h"
        ):
            raise RuntimeError("security history v2 context strategy is invalid")
    stored_plan_digest = manifest.get("plan_digest")
    if not isinstance(stored_plan_digest, str) or len(stored_plan_digest) != 64:
        raise RuntimeError("security history manifest plan digest is invalid")
    events = manifest.get("events")
    if not isinstance(events, _src.Mapping) or set(events) != {str(value) for value in _src.SECURITY_HISTORY_EVENT_IDS}:
        raise RuntimeError("security history manifest vocabulary is invalid")
    for event_id in _src.SECURITY_HISTORY_EVENT_IDS:
        entry = events.get(str(event_id))
        if not isinstance(entry, _src.Mapping):
            raise RuntimeError("security history manifest cohort is invalid")
        if cohorts is not None:
            observed = cohorts.get(event_id)
            if observed is None:
                observed = _src._history_cohort_entry(event_id, None)
            for field in ("high_watermark", "count", "cohort_digest", "min_id", "max_id"):
                actual = (
                    entry.get("raw_retained_count")
                    if manifest_type == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2 and field == "count"
                    else entry.get("raw_cohort_digest")
                    if manifest_type == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2 and field == "cohort_digest"
                    else entry.get(field)
                )
                if actual != observed.get(field):
                    raise RuntimeError("security history manifest frozen cohort changed")
        if entry.get("predicate") != _src.security_history_predicate(event_id):
            raise RuntimeError("security history manifest predicate is invalid")
        if int(entry.get("cursor") or 0) < 0 or int(entry.get("cursor") or 0) > int(entry["high_watermark"]):
            raise RuntimeError("security history manifest cursor is invalid")
        state = entry.get("state")
        if state not in _src.SECURITY_HISTORY_STATES:
            raise RuntimeError("security history manifest state is invalid")
        reason = entry.get("terminal_reason")
        if state in _src.SECURITY_HISTORY_PROGRESS_STATES and reason is not None:
            raise RuntimeError("security history progress state has terminal reason")
        if state in _src.SECURITY_HISTORY_EXCEPTION_STATES and not str(reason or "").strip():
            raise RuntimeError("security history exceptional state requires terminal reason")
        if state in _src.SECURITY_HISTORY_EXACT_STATE_REASONS and reason != _src.SECURITY_HISTORY_EXACT_STATE_REASONS[state]:
            raise RuntimeError("security history state reason is invalid")
        if int(entry["count"]) == 0 and state != "no_retained_events":
            raise RuntimeError("security history empty cohort state is invalid")
        if int(entry["count"]) != 0 and state == "no_retained_events":
            raise RuntimeError("security history nonempty cohort state is invalid")
        if manifest_type == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2:
            raw_count = int(entry.get("raw_retained_count") or 0)
            semantic_count = int(entry.get("semantic_expected_count") or 0)
            scope = entry.get("semantic_scope")
            if raw_count < 0 or semantic_count < 0 or semantic_count > raw_count:
                raise RuntimeError("security history v2 semantic coverage is invalid")
            if event_id == 4624:
                digest = str(entry.get("semantic_context_digest") or "")
                reset_high_watermark = int(entry.get("semantic_context_reset_high_watermark") or 0)
                if (
                    scope != "password_reset_context_only" or len(digest) != 64
                    or reset_high_watermark < 0 or int(entry["count"]) != semantic_count
                    or reset_high_watermark != int(events["4724"]["high_watermark"])
                ):
                    raise RuntimeError("security history v2 logon context coverage is invalid")
            elif (
                scope != "all_retained" or semantic_count != raw_count
                or int(entry["count"]) != raw_count or entry.get("semantic_context_digest") is not None
            ):
                raise RuntimeError("security history v2 event semantic coverage is invalid")


def security_history_cohort_mismatches(
    manifest: _src.Mapping[str, object], cohorts: _src.Mapping[int, _src.Mapping[str, object]],
) -> tuple[int, ...]:
    """Return frozen Event IDs whose final exact source identity drifted."""
    events = manifest.get("events")
    if not isinstance(events, _src.Mapping):
        raise RuntimeError("security history manifest events are invalid")
    mismatches: list[int] = []
    for event_id in _src.SECURITY_HISTORY_EVENT_IDS:
        entry = events.get(str(event_id))
        if not isinstance(entry, _src.Mapping):
            raise RuntimeError("security history manifest cohort is invalid")
        observed = cohorts.get(event_id)
        if observed is None:
            observed = _src._history_cohort_entry(event_id, None)
        if any(
            (
                entry.get("raw_retained_count")
                if manifest.get("manifest_type") == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2 and field == "count"
                else entry.get("raw_cohort_digest")
                if manifest.get("manifest_type") == _src.SECURITY_HISTORY_MANIFEST_TYPE_V2 and field == "cohort_digest"
                else entry.get(field)
            ) != observed.get(field)
            for field in ("high_watermark", "count", "cohort_digest", "min_id", "max_id")
        ):
            mismatches.append(event_id)
    return tuple(mismatches)
