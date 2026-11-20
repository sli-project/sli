"""Split out of ``server.sli.storage.warm_tier_incremental_plan_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_plan_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_plan_runtime as _src


def _freeze_descriptor_lifecycle(
    *,
    source: str,
    stream: str,
    event_keys: tuple[str, ...],
    candidate_ids: tuple[int, ...] = (),
    continuity_declaration_scope_identity: str | None = None,
    continuity_declaration_sha256: str | None = None,
    continuity_declaration_members: tuple[dict[str, _src.Any], ...] = (),
    supplemental_context_ids: tuple[int, ...] = (),
    declaration_progress: dict[str, _src.Any] | None = None,
    policy: _src.StoragePolicy | None = None,
) -> dict[str, _src.Any]:
    """Freeze the pack-owned lifecycle contract for one exact warm batch.

    This is deliberately descriptor-keyed.  A Windows Event ID is not a
    storage route: callers must supply the source and stream that own it.
    """
    if not source or not stream:
        raise ValueError("descriptor_source_and_stream_required")
    if not event_keys or len(set(event_keys)) != len(event_keys):
        raise ValueError("descriptor_event_keys_must_be_unique")
    if candidate_ids and (
        len(set(candidate_ids)) != len(candidate_ids)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in candidate_ids
        )
    ):
        raise ValueError("descriptor_candidate_ids_must_be_unique_positive_integers")
    if (
        len(set(supplemental_context_ids)) != len(supplemental_context_ids)
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value <= 0
            for value in supplemental_context_ids
        )
        or set(candidate_ids).intersection(supplemental_context_ids)
    ):
        raise ValueError("descriptor_supplemental_ids_invalid")
    resolutions = [
        (event_key, _src.resolve_descriptor_retention(
            source, stream, event_key, policy=policy,
        ))
        for event_key in event_keys
    ]
    first = resolutions[0][1]
    if (
        first.rollup != "authentication_session"
        or first.promotion.get("executable_lifecycle")
        != "existing_warm_then_retention_executor"
    ):
        raise ValueError("descriptor_lifecycle_not_supported_by_existing_warm_path")
    promotion = dict(first.promotion)
    for _, resolution in resolutions:
        if (
            resolution.rollup != first.rollup
            or dict(resolution.promotion) != promotion
            or resolution.rollup_role not in {"boot_scope", "open", "close"}
        ):
            raise ValueError("descriptor_lifecycle_contract_mismatch")
    descriptor_policies = [
        {
            "event_key": event_key,
            "rollup_role": resolution.rollup_role,
            "policy_fingerprint": resolution.policy_fingerprint,
        }
        for event_key, resolution in resolutions
    ]
    fingerprint_payload = {
        "source": source,
        "stream": stream,
        "descriptor_policies": descriptor_policies,
        "promotion": promotion,
    }
    policy_fingerprint = _src.hashlib.sha256(
        _src.json.dumps(fingerprint_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if (continuity_declaration_scope_identity is None) != (continuity_declaration_sha256 is None):
        raise ValueError("continuity_declaration_identity_incomplete")
    if continuity_declaration_sha256 is not None:
        if not continuity_declaration_scope_identity or not _src.re.fullmatch(r"[0-9a-f]{64}", continuity_declaration_sha256):
            raise ValueError("continuity_declaration_identity_invalid")
    if len(continuity_declaration_members) > _src.MAX_DECLARATION_MEMBERS:
        raise ValueError("continuity_declaration_member_count_out_of_bounds")
    members = [dict(item) for item in continuity_declaration_members]
    if members:
        member_sha256 = _src.hashlib.sha256(
            _src.json.dumps(members, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if (
            member_sha256 != continuity_declaration_sha256
            or continuity_declaration_scope_identity
            != f"{_src.RANGE_CONTRACT_ID}:{member_sha256}"
        ):
            raise ValueError("continuity_declaration_range_identity_invalid")
    candidate_digest = _src.hashlib.sha256(
        _src.json.dumps(list(candidate_ids), separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    frozen_progress = None
    if declaration_progress is not None:
        frozen_progress = dict(declaration_progress)
        progress_payload = {
            key: frozen_progress.get(key)
            for key in (
                "contract", "declaration_ids", "scope_identity",
                "declaration_sha256", "candidate_identity_sha256",
            )
        }
        progress_digest = _src.hashlib.sha256(
            _src.json.dumps(progress_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        ids = frozen_progress.get("declaration_ids")
        if (
            frozen_progress.get("contract") != "sli.storage-lifecycle-declaration-progress.v1"
            or not isinstance(ids, list) or not ids or ids != sorted(set(ids))
            or any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in ids)
            or frozen_progress.get("scope_identity") != continuity_declaration_scope_identity
            or frozen_progress.get("declaration_sha256") != continuity_declaration_sha256
            or frozen_progress.get("candidate_identity_sha256") != candidate_digest
            or frozen_progress.get("digest") != progress_digest
        ):
            raise ValueError("declaration_progress_invalid")
    return {
        "source": source,
        "stream": stream,
        "event_keys": list(event_keys),
        "candidate_ids": list(candidate_ids),
        "candidate_identity_sha256": candidate_digest,
        "rollup": first.rollup,
        "archive_requirement": promotion["archive_requirement"],
        "read_representation": promotion["read_representation"],
        "post_promotion_disposition": promotion["post_promotion_disposition"],
        "executable_lifecycle": promotion["executable_lifecycle"],
        "descriptor_policies": descriptor_policies,
        "policy_fingerprint": policy_fingerprint,
        "continuity_declaration_scope_identity": continuity_declaration_scope_identity,
        "continuity_declaration_sha256": continuity_declaration_sha256,
        "continuity_declaration_members": members,
        "supplemental_context_ids": list(supplemental_context_ids),
        "declaration_progress": frozen_progress,
    }


def apply_durable_descriptor_selection(
    result: dict[str, _src.Any], rows: list[dict[str, _src.Any]], selection: dict[str, _src.Any],
) -> None:
    """Freeze one database-selected descriptor scope into the normal plan.

    ``selection`` comes from the durable declaration readback, not an external
    caller.  The function deliberately receives neither evidence nor hashes
    from a caller and rejects any scope that would exceed the normal bound.
    """
    selected_ids = [int(value) for value in selection.get("event_ids") or ()]
    by_id = {int(row["id"]): row for row in rows}
    if not selected_ids or set(selected_ids) != set(by_id) or len(by_id) != len(rows):
        raise ValueError("durable_descriptor_selection_ids_not_exact")
    ordered = [by_id[event_id] for event_id in sorted(selected_ids)]
    batch = dict(result.get("planned_batch") or {})
    limit = int(batch.get("limit") or 0)
    if limit < len(ordered):
        raise ValueError("durable_descriptor_selection_exceeds_plan_limit")
    lifecycle = _src._freeze_descriptor_lifecycle(
        source="sli.windows.ad-dc",
        stream="Security",
        event_keys=tuple(str(value) for value in selection.get("event_keys") or ()),
        candidate_ids=tuple(int(row["id"]) for row in ordered),
        continuity_declaration_scope_identity=str(selection.get("declaration_scope_identity") or ""),
        continuity_declaration_sha256=str(selection.get("declaration_sha256") or ""),
        continuity_declaration_members=tuple(
            dict(value) for value in selection.get("declaration_members") or ()
        ),
        supplemental_context_ids=tuple(
            int(value) for value in selection.get("supplemental_event_ids") or ()
        ),
        declaration_progress=(
            _src._build_declaration_progress(selection, tuple(int(row["id"]) for row in ordered))
            if selection.get("declaration_ids") else None
        ),
    )
    if (
        (lifecycle["archive_requirement"], lifecycle["read_representation"])
        not in {("no_archive", "derived_only"), ("archive_required", "archived_atomic")}
    ):
        raise ValueError("durable_descriptor_selection_contract_invalid")
    result["planned_batch"] = {
        **batch,
        "rows": len(ordered),
        "event_ids": [int(row["id"]) for row in ordered],
        "first_event_id": int(ordered[0]["id"]),
        "last_event_id": int(ordered[-1]["id"]),
        "first_event_utc": min(row["time_created_utc"] for row in ordered),
        "last_event_utc": max(row["time_created_utc"] for row in ordered),
        "identity_sha256": _src._batch_identity(ordered),
        "archive_coverage": dict(batch.get("archive_coverage") or {
            "missing": 0, "missing_ids": [],
        }),
    }
    result["descriptor_lifecycle"] = lifecycle
    frontier_id = int(selection.get("declaration_frontier_id") or 0)
    if frontier_id > 0:
        result.setdefault("selection", {})["durable_declaration_frontier_id"] = frontier_id


def _next_durable_descriptor_batch(
    conn: _src.Any,
    *,
    batch_limit: int,
    hot_cutoff_utc: _src.datetime,
    warm_cutoff_utc: _src.datetime,
    port: int,
    declaration_after_id: int = 0,
    processed_declaration_ids: set[int] | None = None,
) -> tuple[list[dict[str, _src.Any]], dict[str, _src.Any]] | None:
    """Find one exact eligible source-capture scope from durable storage.

    A malformed, stale, partial, foreign, or already warm scope is skipped
    rather than converted into a best-effort descriptor batch.  The normal
    archive planner remains responsible for such source material.
    """
    with conn.cursor() as cur:
        declarations_by_id: list[dict[str, _src.Any]] = []
        processed_ids = sorted(int(value) for value in (processed_declaration_ids or set()))
        exclusion_clause = (
            "and not (d.id = any(%s::bigint[]))" if processed_ids else ""
        )
        scan_after_id = max(0, int(declaration_after_id))
        page_size = max(1, min(max(100, batch_limit), _src.MAX_BATCH_LIMIT))
        while len(declarations_by_id) < _src.MAX_DURABLE_DECLARATION_SCAN:
            def fetch_page() -> list[dict[str, _src.Any]]:
                cur.execute(
                    f"""
                    select d.*,raw.sha256 as current_raw_log_sha256
                    from source_capture_continuity_declarations d
                    join raw_log_files raw on raw.id=d.raw_log_file_id
                    where d.completeness='complete' and d.id > %s
                      {exclusion_clause}
                    order by d.id
                    limit %s
                    """,
                    (
                        (scan_after_id, processed_ids, min(
                            page_size,
                            _src.MAX_DURABLE_DECLARATION_SCAN - len(declarations_by_id),
                        ))
                        if processed_ids else
                        (scan_after_id, min(
                            page_size,
                            _src.MAX_DURABLE_DECLARATION_SCAN - len(declarations_by_id),
                        ))
                    ),
                )
                return [dict(row) for row in cur.fetchmany(page_size)]

            try:
                transaction = getattr(conn, "transaction", None)
                if callable(transaction):
                    with transaction():
                        page = fetch_page()
                else:
                    # Lightweight source-only test adapters do not model
                    # PostgreSQL failed-transaction state. Real psycopg
                    # connections always take the savepoint branch above.
                    page = fetch_page()
            except Exception as exc:
                # A source-only rollout is allowed to run before migration 088;
                # absence of the durable table can only disable derived-only
                # selection, never authorize a fallback promotion or deletion.
                if "source_capture_continuity_declarations" in str(exc):
                    return None
                raise
            if not page:
                break
            declarations_by_id.extend(page)
            scan_after_id = max(int(row.get("id") or 0) for row in page)
            if len(page) < page_size:
                break
        if len(declarations_by_id) >= _src.MAX_DURABLE_DECLARATION_SCAN:
            cur.execute(
                f"""
                select d.*,raw.sha256 as current_raw_log_sha256
                from source_capture_continuity_declarations d
                join raw_log_files raw on raw.id=d.raw_log_file_id
                where d.completeness='complete' and d.id > %s
                  {exclusion_clause}
                order by d.id
                limit 1
                """,
                (
                    (scan_after_id, processed_ids)
                    if processed_ids else (scan_after_id,)
                ),
            )
            if cur.fetchmany(1):
                raise RuntimeError("durable_descriptor_declaration_scan_limit_reached")
        scope_fields = (
            "server_id", "log_source_id", "descriptor_source", "descriptor_stream",
            "provider_name", "channel_value", "channel_generation_identity",
        )
        declarations = sorted(
            declarations_by_id,
            key=lambda item: (
                *(str(item.get(field)) for field in scope_fields),
                int(item.get("capture_after_record_id")),
                int(item.get("id") or 0),
            ),
        )
        for index, declaration in enumerate(declarations):
            if str(declaration.get("current_raw_log_sha256") or "").lower() != str(declaration.get("raw_log_sha256") or "").lower():
                continue
            try:
                scope_rows = _src._declaration_source_rows(cur, declaration)
                if not any(
                    int(row["event_id"]) == _src.BOOT_EVENT_KEY for row in scope_rows
                ):
                    continue
                chain = [declaration]
                chain_rows = list(scope_rows)
                previous = declaration
                expected_scope = tuple(
                    str(declaration.get(field)) for field in scope_fields
                )
                for following in declarations[index + 1:]:
                    if (
                        tuple(str(following.get(field)) for field in scope_fields)
                        != expected_scope
                        or int(following["capture_after_record_id"])
                        != int(previous["capture_latest_record_id"])
                    ):
                        break
                    following_rows = _src._declaration_source_rows(cur, following)
                    if any(
                        int(row["event_id"]) == _src.BOOT_EVENT_KEY
                        for row in following_rows
                    ):
                        break
                    chain.append(following)
                    chain_rows.extend(following_rows)
                    previous = following
                selected = _src.prepare_descriptor_range(
                    chain, chain_rows, batch_limit=batch_limit,
                )
                selected["declaration_frontier_id"] = int(declaration["id"])
                selected["declaration_ids"] = sorted(int(item["id"]) for item in chain)
                if any(
                    _src.resolve_descriptor_retention(
                        str(declaration["descriptor_source"]),
                        str(declaration["descriptor_stream"]),
                        str(event_key),
                    ).promotion.get("executable_lifecycle")
                    == "semantic_then_direct_retention_executor"
                    for event_key in selected.get("event_keys") or ()
                ):
                    continue
            except (_src.CaptureContinuityError, KeyError, TypeError, ValueError):
                continue
            rows_by_id = {int(row["id"]): row for row in chain_rows}
            selected_rows = [rows_by_id[event_id] for event_id in selected["event_ids"]]
            if any(
                row["time_created_utc"] < warm_cutoff_utc
                or row["time_created_utc"] >= hot_cutoff_utc
                for row in chain_rows
            ):
                continue
            warm_present = _src._warm_present_ids(selected["event_ids"], port)
            durable_published = _src._durable_derived_publication_is_verified(
                conn, selected_rows, selected, port,
            )
            if warm_present or durable_published:
                return selected_rows, selected
            return selected_rows, selected
    return None


def _durable_derived_publication_is_verified(
    conn: _src.Any,
    selected_rows: list[dict[str, _src.Any]],
    selection: dict[str, _src.Any],
    port: int,
) -> bool:
    """Check the existing derived-only publication by its exact frozen identity."""
    # The copy runtime owns canonical publication construction and strict
    # ClickHouse readback.  A local import avoids a module-load cycle because
    # that runtime already imports the lifecycle freezer above.
    from server.sli.storage.warm_tier_incremental_copy_runtime import (
        _derived_publication_from_frozen_plan,
        is_derived_publication_durably_verified,
    )

    frozen: dict[str, _src.Any] = {"planned_batch": {"limit": len(selected_rows)}}
    try:
        _src.apply_durable_descriptor_selection(frozen, selected_rows, selection)
        publication = _derived_publication_from_frozen_plan(
            conn,
            {
                "descriptor_lifecycle": frozen["descriptor_lifecycle"],
                "identity_sha256": frozen["planned_batch"]["identity_sha256"],
            },
            selected_rows,
        )
    except (KeyError, TypeError, ValueError, RuntimeError):
        return False
    return bool(
        publication is not None
        and is_derived_publication_durably_verified(port, publication)
    )


def _batch_identity(rows: list[dict[str, _src.Any]]) -> str | None:
    if not rows:
        return None
    digest = _src.hashlib.sha256()
    for row in rows:
        digest.update(int(row["id"]).to_bytes(8, "big", signed=False))
        normalized_hash = row.get("normalized_hash_hex", row.get("normalized_hash"))
        if normalized_hash is None:
            raise ValueError("batch_normalized_hash_missing")
        digest.update(bytes.fromhex(str(normalized_hash)))
    return digest.hexdigest()


def _declaration_source_rows(cur: _src.Any, declaration: dict[str, _src.Any]) -> list[dict[str, _src.Any]]:
    """Load the complete immutable raw scope named by one declaration."""
    covered_value = declaration.get("covered_source_events")
    if not isinstance(covered_value, list):
        raise _src.CaptureContinuityError("capture_declaration_covered_events_invalid")
    covered = list(covered_value)
    ids = [int(item.get("id") or 0) for item in covered if isinstance(item, dict)]
    if len(ids) != len(covered) or len(set(ids)) != len(ids) or any(value <= 0 for value in ids):
        raise _src.CaptureContinuityError("capture_declaration_covered_events_invalid")
    if not ids:
        return []
    cur.execute(
        """
        select event.id,event.event_record_id,event.event_id,
               encode(event.normalized_hash,'hex') as normalized_hash,
               event.server_id,event.log_source_id,event.raw_log_file_id,
               event.time_created_utc,channel.value as channel_value,
               provider.value as provider_name,raw.sha256 as raw_log_sha256
        from events_v2_core event
        join storage_v2_channel channel on channel.id=event.channel_id
        join storage_v2_provider provider on provider.id=event.provider_id
        join raw_log_files raw on raw.id=event.raw_log_file_id
        where event.id=any(%s::bigint[])
        order by event.event_record_id,event.id
        """,
        (ids,),
    )
    return [dict(row) for row in cur.fetchall()]


def _build_declaration_progress(
    selection: dict[str, _src.Any], candidate_ids: tuple[int, ...],
) -> dict[str, _src.Any]:
    declaration_ids = selection.get("declaration_ids") or ()
    if len(declaration_ids) > _src.MAX_DECLARATION_IDS:
        raise ValueError("declaration_progress_id_count_out_of_bounds")
    progress: dict[str, _src.Any] = {
        "contract": "sli.storage-lifecycle-declaration-progress.v1",
        "declaration_ids": sorted(int(value) for value in declaration_ids),
        "scope_identity": str(selection.get("declaration_scope_identity") or ""),
        "declaration_sha256": str(selection.get("declaration_sha256") or "").lower(),
        "candidate_identity_sha256": _src.hashlib.sha256(
            _src.json.dumps(list(candidate_ids), separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    }
    progress["digest"] = _src.hashlib.sha256(_src.json.dumps(
        progress, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return progress
