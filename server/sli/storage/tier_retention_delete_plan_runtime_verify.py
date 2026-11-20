"""Split out of ``server.sli.storage.tier_retention_delete_plan_runtime`` (plan 7.2b).

Module-level names of ``tier_retention_delete_plan_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.tier_retention_delete_plan_runtime as _src


def verify_backup() -> dict[str, _src.Any]:
    if not _src.BACKUP_MANIFEST.is_file():
        return {"valid": False, "reason": "manifest_missing", "files": 0}
    manifest = _src.read_json(
        _src.BACKUP_MANIFEST, max_bytes=_src.MAX_BACKUP_MANIFEST_BYTES,
        too_large="backup_manifest_too_large",
    )
    mismatches: list[str] = []
    files = manifest.get("files") or []
    if not isinstance(files, list) or len(files) > _src.MAX_BACKUP_FILES:
        raise RuntimeError("backup_manifest_file_count_out_of_bounds")
    for item in files:
        path = _src.BACKUP_ROOT / "events" / str(item.get("name") or "")
        if (
            not path.is_file()
            or path.stat().st_size != int(item.get("bytes") or -1)
            or _src._sha256(path) != str(item.get("sha256") or "").lower()
        ):
            mismatches.append(path.name)
    return {
        "valid": bool(files) and not mismatches,
        "files": len(files),
        "rows": int((manifest.get("backup") or {}).get("rows") or 0),
        "identity_sha256": (manifest.get("backup") or {}).get("identity_sha256"),
        "mismatches": mismatches,
    }


def _candidate_rows(
    conn: _src.Any,
    *,
    hot_days: int,
    limit: int,
) -> tuple[dict[str, _src.Any], list[dict[str, _src.Any]]]:
    with conn.cursor() as cur:
        cur.execute(
            """
            select count(*)::bigint as candidate_count,
                   min(id)::bigint as min_id,max(id)::bigint as max_id,
                   min(time_created_utc) as oldest_utc,
                   max(time_created_utc) as newest_candidate_utc,
                   now() at time zone 'utc' as checked_at_utc
            from events_v2_core
            where time_created_utc < now() - (%s * interval '1 day')
            """,
            (max(1, hot_days),),
        )
        summary = dict(cur.fetchone())
        cur.execute(
            """
            select id,normalized_hash,time_created_utc
            from events_v2_core
            where time_created_utc < now() - (%s * interval '1 day')
            order by id
            limit %s
            """,
            (max(1, hot_days), limit + 1),
        )
        rows = [dict(row) for row in cur.fetchall()]
    summary["candidate_count"] = int(summary.get("candidate_count") or 0)
    summary["truncated"] = len(rows) > limit
    return summary, rows[:limit]


def _restrictive_references(
    conn: _src.Any,
    candidate_ids: list[int],
) -> dict[str, _src.Any]:
    if not candidate_ids:
        return {"rows": 0, "event_ids": [], "tables": []}
    from psycopg import sql

    with conn.cursor() as cur:
        cur.execute(
            """
            select child_ns.nspname as schema_name,child.relname as table_name,
                   child_att.attname as column_name
            from pg_constraint constraint_row
            join pg_class child on child.oid=constraint_row.conrelid
            join pg_namespace child_ns on child_ns.oid=child.relnamespace
            join unnest(constraint_row.conkey) with ordinality child_key(attnum,ord)
              on true
            join unnest(constraint_row.confkey) with ordinality parent_key(attnum,ord)
              on parent_key.ord=child_key.ord
            join pg_attribute child_att
              on child_att.attrelid=child.oid and child_att.attnum=child_key.attnum
            where constraint_row.contype='f'
              and constraint_row.confrelid='events_v2_core'::regclass
              and constraint_row.confdeltype in ('a','r')
              and array_length(constraint_row.conkey,1)=1
            order by child_ns.nspname,child.relname,child_att.attname
            """
        )
        references = [dict(row) for row in cur.fetchall()]
        total = 0
        tables: list[dict[str, _src.Any]] = []
        for reference in references:
            query = sql.SQL(
                "select count(*)::bigint as count,"
                "array_agg(distinct {}) event_ids from {}.{} where {} = any(%s)"
            ).format(
                sql.Identifier(str(reference["column_name"])),
                sql.Identifier(str(reference["schema_name"])),
                sql.Identifier(str(reference["table_name"])),
                sql.Identifier(str(reference["column_name"])),
            )
            cur.execute(query, (candidate_ids,))
            result = cur.fetchone()
            count = int(result["count"] or 0)
            if count:
                total += count
                tables.append(
                    {
                        **reference,
                        "rows": count,
                        "event_ids": sorted(int(value) for value in result["event_ids"]),
                    }
                )
    return {
        "rows": total,
        "event_ids": sorted(
            {event_id for item in tables for event_id in item["event_ids"]}
        ),
        "tables": tables,
    }


def _chunks(values: list[dict[str, _src.Any]], size: int) -> _src.Iterable[list[dict[str, _src.Any]]]:
    for offset in range(0, len(values), size):
        yield values[offset:offset + size]


def verify_warm(candidate_rows: list[dict[str, _src.Any]]) -> dict[str, _src.Any]:
    port = _src._container_port(_src.CONTAINER)
    global_rows = int(
        _src._http_query(
            port,
            f"select count() from {_src.DATABASE}.event_placement FORMAT TabSeparated",
        ).decode("utf-8").strip()
    )
    manifest_rows = int(
        _src._http_query(
            port,
            f"select count() from {_src.DATABASE}.copy_manifest FORMAT TabSeparated",
        ).decode("utf-8").strip()
    )
    if not candidate_rows:
        return {
            "available": True,
            "global_rows": global_rows,
            "manifest_rows": manifest_rows,
            "missing": 0,
            "hash_mismatches": 0,
            "archive_paths_missing": 0,
        }

    found: dict[int, dict[str, _src.Any]] = {}
    for batch in _src._chunks(candidate_rows, 1000):
        ids = ",".join(str(int(row["id"])) for row in batch)
        payload = _src._http_query(
            port,
            (
                "select event_id,lower(hex(normalized_hash)) as normalized_hash,"
                "archived_payload_path,archived_payload_line "
                f"from {_src.DATABASE}.event_placement where event_id in ({ids}) "
                "FORMAT JSONEachRow"
            ),
        ).decode("utf-8")
        for line in payload.splitlines():
            row = _src.json.loads(line)
            found[int(row["event_id"])] = row

    missing = 0
    mismatches = 0
    archive_missing = 0
    for source in candidate_rows:
        event_id = int(source["id"])
        warm = found.get(event_id)
        if warm is None:
            missing += 1
            continue
        source_hash = source["normalized_hash"]
        expected_hash = (
            str(source_hash).lower()
            if isinstance(source_hash, str)
            else bytes(source_hash).hex()
        )
        if str(warm["normalized_hash"]).lower() != expected_hash:
            mismatches += 1
        archive_path = _src.Path(str(warm.get("archived_payload_path") or ""))
        if (
            not archive_path.is_file()
            or int(warm.get("archived_payload_line") or 0) <= 0
        ):
            archive_missing += 1
    return {
        "available": True,
        "global_rows": global_rows,
        "manifest_rows": manifest_rows,
        "missing": missing,
        "hash_mismatches": mismatches,
        "archive_paths_missing": archive_missing,
    }


def _verify_warm_page(
    port: int,
    candidate_rows: list[dict[str, _src.Any]],
) -> dict[str, _src.Any]:
    if not candidate_rows:
        return {
            "missing": 0,
            "hash_mismatches": 0,
            "archive_line_invalid": 0,
            "duplicate_rows": 0,
            "archive_paths": set(),
        }
    ids = ",".join(str(int(row["id"])) for row in candidate_rows)
    payload = _src._http_query(
        port,
        "select event_id,lower(hex(normalized_hash)) normalized_hash,"
        "archived_payload_path,archived_payload_line "
        f"from {_src.DATABASE}.event_placement where event_id in ({ids}) "
        "FORMAT JSONEachRow",
    ).decode("utf-8")
    found: dict[int, dict[str, _src.Any]] = {}
    duplicates = 0
    for line in payload.splitlines():
        row = _src.json.loads(line)
        event_id = int(row["event_id"])
        if event_id in found:
            duplicates += 1
        found[event_id] = row
    missing = mismatches = invalid_lines = 0
    paths: set[str] = set()
    for source in candidate_rows:
        event_id = int(source["id"])
        warm = found.get(event_id)
        if warm is None:
            missing += 1
            continue
        source_hash = source["normalized_hash"]
        expected = (
            str(source_hash).lower()
            if isinstance(source_hash, str)
            else bytes(source_hash).hex()
        )
        if str(warm["normalized_hash"]).lower() != expected:
            mismatches += 1
        path = str(warm.get("archived_payload_path") or "")
        if int(warm.get("archived_payload_line") or 0) <= 0 or not path:
            invalid_lines += 1
        else:
            paths.add(path)
    return {
        "missing": missing,
        "hash_mismatches": mismatches,
        "archive_line_invalid": invalid_lines,
        "duplicate_rows": duplicates,
        "archive_paths": paths,
    }
