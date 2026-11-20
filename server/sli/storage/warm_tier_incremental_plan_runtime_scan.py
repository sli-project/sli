"""Split out of ``server.sli.storage.warm_tier_incremental_plan_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_plan_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_plan_runtime as _src


def _warm_state(port: int) -> dict[str, _src.Any]:
    try:
        baseline = _src._json_row(
            port,
            f"SELECT count() AS rows,max(event_id) AS max_event_id "
            f"FROM {_src.DATABASE}.event_placement",
        )
        table = _src._json_row(
            port,
            "SELECT count() AS rows FROM system.tables "
            f"WHERE database='{_src.DATABASE}' AND name='incremental_copy_manifest'",
        )
        earliest_legacy: str | None = None
        latest_v2_upper: str | None = None
        has_v2_columns = False
        if int(table.get("rows") or 0):
            columns = _src._json_row(
                port,
                "SELECT countIf(name='selection_mode') AS mode_columns,"
                "countIf(name='selection_upper_utc') AS upper_columns "
                "FROM system.columns "
                f"WHERE database='{_src.DATABASE}' "
                "AND table='incremental_copy_manifest'",
            )
            has_v2_columns = (
                int(columns.get("mode_columns") or 0) == 1
                and int(columns.get("upper_columns") or 0) == 1
            )
            manifests = _src._json_row(
                port,
                "SELECT min(plan_generated_at_utc) AS earliest_legacy"
                + (
                    ",maxIf(selection_upper_utc,selection_mode="
                    f"'{_src.SELECTION_MODE}') AS latest_v2_upper"
                    if has_v2_columns else ""
                )
                + f" FROM {_src.DATABASE}.incremental_copy_manifest",
            )
            earliest_legacy = manifests.get("earliest_legacy") or None
            latest_v2_upper = manifests.get("latest_v2_upper") or None
            if str(latest_v2_upper).startswith("1970-01-01"):
                latest_v2_upper = None
        return {
            "available": True,
            "rows": int(baseline.get("rows") or 0),
            "max_event_id": int(baseline.get("max_event_id") or 0),
            "earliest_legacy_manifest_utc": earliest_legacy,
            "latest_v2_selection_upper_utc": latest_v2_upper,
            "manifest_v2_columns_present": has_v2_columns,
            "error": None,
        }
    except Exception as exc:
        return {
            "available": False,
            "rows": 0,
            "max_event_id": 0,
            "earliest_legacy_manifest_utc": None,
            "latest_v2_selection_upper_utc": None,
            "manifest_v2_columns_present": False,
            "error": str(exc)[:500],
        }


def _warm_present_ids(event_ids: list[int], port: int) -> set[int]:
    """Ask ClickHouse which of ``event_ids`` already have a warm placement.

    The id list is sent once as the ClickHouse HTTP query body (native HTTP
    interface, the same transport already used by
    ``warm_tier_incremental_copy.py``), never as OS command-line arguments.
    There is therefore no Windows command-line length to divide the batch
    around, and no per-chunk ``docker exec`` subprocess to launch.
    """
    if not event_ids:
        return set()
    requested = [int(value) for value in event_ids]
    ids_csv = ",".join(str(value) for value in requested)
    output = _src._http_query(
        port,
        f"SELECT event_id FROM {_src.DATABASE}.event_placement "
        f"WHERE event_id IN ({ids_csv}) "
        "ORDER BY event_id FORMAT TabSeparatedRaw",
    )
    returned = [
        int(line) for line in output.decode("ascii").splitlines() if line.strip()
    ]
    if len(returned) != len(set(returned)):
        raise RuntimeError("duplicate_warm_event_placement")
    unexpected = set(returned).difference(requested)
    if unexpected:
        raise RuntimeError("clickhouse_returned_unrequested_event_id")
    return set(returned)


def _source_summary(
    conn: _src.Any,
    *,
    warm_max_event_id: int,
    selection_lower_utc: _src.datetime,
    hot_cutoff_utc: _src.datetime,
    warm_cutoff_utc: _src.datetime,
) -> dict[str, _src.Any]:
    sources, event_ids, channels, providers = _src._direct_no_archive_exclusion()
    with conn.cursor() as cur:
        cur.execute(
            """
            /* direct_no_archive_exclusion */
            with direct_descriptor(source,event_id,channel,provider_name) as (
              select * from unnest(%s::text[],%s::int[],%s::text[],%s::text[])
            )
            select count(*)::bigint as source_rows,
                   coalesce(max(event.id), 0)::bigint as source_max_event_id,
                   min(event.time_created_utc) as source_oldest_utc,
                   max(event.time_created_utc) as source_newest_utc,
                   count(*) filter (where event.id > %s)::bigint as appended_rows,
                   count(*) filter (
                       where event.time_created_utc >= %s
                         and event.time_created_utc < %s
                         and (event.time_created_utc >= %s or event.id > %s)
                   )::bigint as eligible_rows,
                   count(*) filter (
                       where event.time_created_utc < %s and event.id > %s
                   )::bigint as archive_only_rows,
                   now() as checked_at_utc
            from events_v2_core event
            join storage_v2_channel channel on channel.id=event.channel_id
            join storage_v2_provider provider on provider.id=event.provider_id
            where not exists (
              select 1 from direct_descriptor direct
              where direct.event_id=event.event_id
                and direct.channel=channel.value
                and direct.provider_name=provider.value
                and exists (
                  select 1
                  from source_capture_continuity_declarations source_declaration
                  where source_declaration.log_source_id=event.log_source_id
                    and source_declaration.descriptor_source=direct.source
                    and source_declaration.descriptor_stream=direct.channel
                    and source_declaration.provider_name=direct.provider_name
                    and source_declaration.channel_value=direct.channel
                )
            )
            """,
            (
                sources,
                event_ids,
                channels,
                providers,
                warm_max_event_id,
                warm_cutoff_utc,
                hot_cutoff_utc,
                selection_lower_utc,
                warm_max_event_id,
                warm_cutoff_utc,
                warm_max_event_id,
            ),
        )
        return dict(cur.fetchone())


def _candidate_page(
    conn: _src.Any,
    *,
    warm_max_event_id: int,
    selection_lower_utc: _src.datetime,
    hot_cutoff_utc: _src.datetime,
    warm_cutoff_utc: _src.datetime,
    after: tuple[_src.datetime, int] | None,
    limit: int,
) -> list[dict[str, _src.Any]]:
    sources, event_ids, channels, providers = _src._direct_no_archive_exclusion()
    cursor_clause = ""
    params: list[_src.Any] = [
        sources,
        event_ids,
        channels,
        providers,
        warm_cutoff_utc,
        hot_cutoff_utc,
        selection_lower_utc,
        warm_max_event_id,
    ]
    if after is not None:
        cursor_clause = "and (event.time_created_utc,event.id) > (%s,%s)"
        params.extend(after)
    params.append(limit)
    with conn.cursor() as cur:
        cur.execute(
            f"""
            /* direct_no_archive_exclusion */
            with direct_descriptor(source,event_id,channel,provider_name) as (
              select * from unnest(%s::text[],%s::int[],%s::text[],%s::text[])
            )
            select event.id,encode(event.normalized_hash, 'hex') as normalized_hash_hex,
                   event.time_created_utc
            from events_v2_core event
            join storage_v2_channel channel on channel.id=event.channel_id
            join storage_v2_provider provider on provider.id=event.provider_id
            where event.time_created_utc >= %s
              and event.time_created_utc < %s
              and (event.time_created_utc >= %s or event.id > %s)
              and not exists (
                select 1 from direct_descriptor direct
                where direct.event_id=event.event_id
                  and direct.channel=channel.value
                  and direct.provider_name=provider.value
                and exists (
                  select 1
                  from source_capture_continuity_declarations source_declaration
                  where source_declaration.log_source_id=event.log_source_id
                    and source_declaration.descriptor_source=direct.source
                    and source_declaration.descriptor_stream=direct.channel
                    and source_declaration.provider_name=direct.provider_name
                    and source_declaration.channel_value=direct.channel
                )
              )
              {cursor_clause}
            order by event.time_created_utc,event.id
            limit %s
            """,
            tuple(params),
        )
        return [dict(row) for row in cur.fetchall()]


def _scan_missing(
    conn: _src.Any,
    *,
    warm_max_event_id: int,
    selection_lower_utc: _src.datetime,
    hot_cutoff_utc: _src.datetime,
    warm_cutoff_utc: _src.datetime,
    batch_limit: int,
    scan_limit: int,
    port: int = 0,
    present_id_resolver: _src.Callable[[list[int], int], set[int]] | None = None,
) -> tuple[list[dict[str, _src.Any]], dict[str, _src.Any]]:
    resolver = present_id_resolver or _src._warm_present_ids
    planned: list[dict[str, _src.Any]] = []
    scanned = 0
    already_present = 0
    complete = False
    after: tuple[_src.datetime, int] | None = None
    while scanned < scan_limit and len(planned) < batch_limit:
        page_limit = min(_src.SCAN_PAGE_ROWS, scan_limit - scanned)
        page = _src._candidate_page(
            conn,
            warm_max_event_id=warm_max_event_id,
            selection_lower_utc=selection_lower_utc,
            hot_cutoff_utc=hot_cutoff_utc,
            warm_cutoff_utc=warm_cutoff_utc,
            after=after,
            limit=page_limit,
        )
        if not page:
            complete = True
            break
        present = resolver([int(row["id"]) for row in page], port)
        already_present += len(present)
        planned.extend(
            _src.select_missing_rows(
                page,
                present,
                limit=batch_limit - len(planned),
            )
        )
        scanned += len(page)
        last = page[-1]
        after = (last["time_created_utc"], int(last["id"]))
        if len(page) < page_limit:
            complete = True
            break
    if len(planned) >= batch_limit:
        complete = False
    checkpoint_upper = hot_cutoff_utc
    if not complete and planned:
        checkpoint_upper = min(
            hot_cutoff_utc,
            planned[-1]["time_created_utc"] + _src.timedelta(microseconds=1),
        )
    planned.sort(key=lambda row: int(row["id"]))
    return planned, {
        "scanned_rows": scanned,
        "already_present_rows": already_present,
        "candidate_scan_complete": complete,
        "scan_limit_reached": scanned >= scan_limit and not complete,
        "checkpoint_upper_utc": checkpoint_upper,
    }


def _archive_coverage(conn: _src.Any, event_ids: list[int]) -> dict[str, _src.Any]:
    if not event_ids:
        return {"missing": 0, "missing_ids": []}
    with conn.cursor() as cur:
        cur.execute(
            """
            select candidate.event_id
            from unnest(%s::bigint[]) as candidate(event_id)
            where not exists (
                select 1
                from storage_v2_archive_blocks archive_block
                where archive_block.archive_kind='event'
                  and archive_block.state='published'
                  and candidate.event_id between
                      archive_block.first_event_id and archive_block.last_event_id
            )
            order by candidate.event_id
            """,
            (event_ids,),
        )
        missing = [int(row["event_id"]) for row in cur.fetchall()]
    return {"missing": len(missing), "missing_ids": missing[:100]}


def _selection_lower(warm: dict[str, _src.Any], hot_days: int) -> tuple[_src.datetime | None, str]:
    if warm.get("latest_v2_selection_upper_utc"):
        return (
            _src._parse_utc(warm["latest_v2_selection_upper_utc"]) - _src.CURSOR_OVERLAP,
            "latest_published_v2_selection_upper_with_overlap",
        )
    if warm.get("earliest_legacy_manifest_utc"):
        return (
            _src._parse_utc(warm["earliest_legacy_manifest_utc"])
            - _src.timedelta(days=hot_days),
            "legacy_manifest_recovery_window",
        )
    return None, "missing"


def _json_row(port: int, query: str) -> dict[str, _src.Any]:
    """One bounded, read-only metadata query over the ClickHouse HTTP
    interface -- no ``docker exec`` subprocess launch per call, so this can
    be called several times per plan build (baseline/table-exists/columns/
    manifest-range) without the launch count growing with how many times
    ``build_plan`` itself is called from a multi-batch drain loop."""
    payload = _src.json.loads(
        _src._http_query(
            port, query + " FORMAT JSON",
            timeout=45, params=_src._READONLY_QUERY_SETTINGS,
        ).decode("utf-8")
    )
    return dict((payload.get("data") or [{}])[0])
