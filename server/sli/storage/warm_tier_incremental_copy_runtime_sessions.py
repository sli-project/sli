"""Split out of ``server.sli.storage.warm_tier_incremental_copy_runtime`` (plan 7.2b).

Module-level names of ``warm_tier_incremental_copy_runtime`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.storage.warm_tier_incremental_copy_runtime as _src


def _pending_sessions(port: int, batch_identity: str) -> list[_src.SessionRevision]:
    if _src._session_schema_present(port):
        rows: list[dict[str, _src.Any]] = []
        seen_session_uids: set[str] = set()
        for lower_bound_hex, upper_bound_hex in _src._pending_session_uid_ranges():
            range_predicate = _src._pending_session_uid_range_predicate(
                lower_bound_hex, upper_bound_hex,
            )
            conflicts = _src._http_query(
                port,
                "SELECT count() FROM (SELECT session_uid,revision,count() rows "
                f"FROM {_src.DATABASE}.session_lifecycle_revisions "
                f"WHERE batch_identity!='{batch_identity}' AND {range_predicate} "
                "GROUP BY session_uid,revision HAVING rows>1)",
            ).decode("utf-8").strip()
            if int(conflicts or 0):
                raise RuntimeError("preexisting_warm_session_revision_conflict")
            remaining_limit = _src.MAX_PENDING_SESSIONS - len(rows)
            query = f"""
            WITH combined AS
            (
                SELECT session_uid,toUInt32(0) revision,state,
                       toUInt16(server_id) server_id,toUInt16(domain_id) domain_id,
                       toUInt16(channel_id) channel_id,logon_id,logon_source_id,
                       logoff_source_id,toNullable(logon_time_utc) logon_time_utc,
                       logoff_time_utc,
                       CAST(NULL,'Nullable(FixedString(64))') previous_revision_sha256,
                       toFixedString(repeat('0',64),64) revision_sha256
                FROM {_src.DATABASE}.sessions
                WHERE {range_predicate}
                UNION ALL
                SELECT session_uid,revision,state,server_id,domain_id,channel_id,
                       logon_id,logon_source_id,logoff_source_id,logon_time_utc,
                       logoff_time_utc,previous_revision_sha256,revision_sha256
                FROM {_src.DATABASE}.session_lifecycle_revisions
                WHERE batch_identity!='{batch_identity}' AND {range_predicate}
            ), ranked AS
            (
                SELECT *,max(revision) OVER (PARTITION BY session_uid) max_revision,
                       count() OVER (PARTITION BY session_uid,revision) revision_rows
                FROM combined
            )
            SELECT lower(hex(session_uid)) session_uid,revision,state,server_id,
                   domain_id,channel_id,logon_id,logon_source_id,logoff_source_id,
                   logon_time_utc,logoff_time_utc,
                   ifNull(toString(previous_revision_sha256),'') previous_revision_sha256,
                   toString(revision_sha256) revision_sha256
            FROM ranked
            WHERE revision=max_revision AND revision_rows=1 AND state!='closed'
            ORDER BY session_uid LIMIT {remaining_limit + 1}
            FORMAT JSONEachRow
            """
            for row in _src._clickhouse_json(port, query.rsplit("FORMAT JSONEachRow", 1)[0]):
                session_uid = str(row["session_uid"])
                if session_uid in seen_session_uids:
                    raise RuntimeError("duplicate_pending_warm_session_uid")
                seen_session_uids.add(session_uid)
                rows.append(row)
            if len(rows) > _src.MAX_PENDING_SESSIONS:
                raise RuntimeError("pending_warm_sessions_out_of_bounds")
        rows.sort(key=lambda row: str(row["session_uid"]))
    else:
        query = f"""
        SELECT lower(hex(session_uid)) session_uid,toUInt32(0) revision,state,
               toUInt16(server_id) server_id,toUInt16(domain_id) domain_id,
               toUInt16(channel_id) channel_id,logon_id,logon_source_id,
               logoff_source_id,logon_time_utc,logoff_time_utc,
               '' previous_revision_sha256,repeat('0',64) revision_sha256
        FROM {_src.DATABASE}.sessions WHERE state!='closed'
        ORDER BY session_uid LIMIT {_src.MAX_PENDING_SESSIONS + 1}
        FORMAT JSONEachRow
        """
        rows = _src._clickhouse_json(port, query.rsplit("FORMAT JSONEachRow", 1)[0])
        if len(rows) > _src.MAX_PENDING_SESSIONS:
            raise RuntimeError("pending_warm_sessions_out_of_bounds")
    result: list[_src.SessionRevision] = []
    for row in rows:
        revision = int(row["revision"])
        logon_time = (
            _src._parse_utc(row["logon_time_utc"])
            if row.get("logon_time_utc") is not None
            else None
        )
        logoff_time = (
            _src._parse_utc(row["logoff_time_utc"])
            if row.get("logoff_time_utc") is not None
            else None
        )
        if revision == 0:
            if row["state"] == "orphan_logoff":
                logon_time = None
            result.append(
                _src.legacy_base_revision(
                    session_uid=row["session_uid"],
                    state=row["state"],
                    server_id=int(row["server_id"]),
                    domain_id=int(row.get("domain_id") or 0),
                    channel_id=int(row["channel_id"]),
                    logon_id=row["logon_id"],
                    logon_source_event_id=row.get("logon_source_id"),
                    logoff_source_event_id=row.get("logoff_source_id"),
                    logon_time_utc=logon_time,
                    logoff_time_utc=logoff_time,
                )
            )
        else:
            result.append(
                _src.SessionRevision(
                    session_uid=str(row["session_uid"]),
                    revision=revision,
                    state=str(row["state"]),
                    server_id=int(row["server_id"]),
                    channel_id=int(row["channel_id"]),
                    logon_id=str(row["logon_id"]),
                    logon_source_event_id=(
                        int(row["logon_source_id"])
                        if row.get("logon_source_id") is not None else None
                    ),
                    logoff_source_event_id=(
                        int(row["logoff_source_id"])
                        if row.get("logoff_source_id") is not None else None
                    ),
                    logon_time_utc=logon_time,
                    logoff_time_utc=logoff_time,
                    previous_revision_sha256=(
                        str(row["previous_revision_sha256"])
                        if row.get("previous_revision_sha256") else None
                    ),
                    revision_sha256=str(row["revision_sha256"]),
                    domain_id=int(row.get("domain_id") or 0),
                )
            )
    return result


def _session_plan(
    pending: list[_src.SessionRevision],
    boundaries: list[_src.SessionBoundary],
    batch_identity: str,
) -> tuple[list[dict[str, _src.Any]], list[dict[str, _src.Any]]]:
    _src.load_session_contract()
    active = list(pending)
    revisions: list[dict[str, _src.Any]] = []
    placements: list[dict[str, _src.Any]] = []
    published_at = _src.datetime.now(_src.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
    for boundary in sorted(boundaries, key=lambda item: item.source_event_id):
        prior = _src._compatible_prior(active, boundary)
        revision = _src.plan_revision(prior, boundary)
        if prior is not None:
            active.remove(prior)
        if revision.state != "closed":
            active.append(revision)
        duration = None
        if revision.logon_time_utc and revision.logoff_time_utc:
            duration = int(
                (revision.logoff_time_utc - revision.logon_time_utc).total_seconds()
            )
        revisions.append(
            {
                "session_uid_hex": revision.session_uid,
                "revision": revision.revision,
                "state": revision.state,
                "server_id": revision.server_id,
                "domain_id": revision.domain_id,
                "channel_id": revision.channel_id,
                "logon_time_utc": _src._format_utc(revision.logon_time_utc),
                "logoff_time_utc": _src._format_utc(revision.logoff_time_utc),
                "duration_s": duration,
                "logon_id": revision.logon_id,
                "logon_source_id": revision.logon_source_event_id,
                "logoff_source_id": revision.logoff_source_event_id,
                "previous_revision_sha256": revision.previous_revision_sha256,
                "revision_sha256": revision.revision_sha256,
                "batch_identity": batch_identity,
                "published_at_utc": published_at,
            }
        )
        placement = {
            "open": "open_session",
            "closed": "closed_session",
            "orphan_logoff": "orphan_logoff",
        }[revision.state]
        for event_id in (
            revision.logon_source_event_id,
            revision.logoff_source_event_id,
        ):
            if event_id is not None:
                placements.append(
                    {
                        "event_id": event_id,
                        "revision": revision.revision,
                        "session_uid_hex": revision.session_uid,
                        "placement": placement,
                        "lifecycle_revision_sha256": revision.revision_sha256,
                        "batch_identity": batch_identity,
                        "published_at_utc": published_at,
                    }
                )
    return revisions, placements


def _canonical_session_revision(row: dict[str, _src.Any]) -> dict[str, _src.Any]:
    return {
        "session_uid_hex": str(row["session_uid_hex"]).lower(),
        "revision": int(row["revision"]),
        "state": str(row["state"]),
        "server_id": int(row["server_id"]),
        "domain_id": int(row.get("domain_id") or 0),
        "channel_id": int(row["channel_id"]),
        "logon_time_utc": (
            _src._format_utc(_src._parse_utc(row["logon_time_utc"]))
            if row.get("logon_time_utc") is not None else None
        ),
        "logoff_time_utc": (
            _src._format_utc(_src._parse_utc(row["logoff_time_utc"]))
            if row.get("logoff_time_utc") is not None else None
        ),
        "duration_s": (
            int(row["duration_s"]) if row.get("duration_s") is not None else None
        ),
        "logon_id": str(row["logon_id"]),
        "logon_source_id": (
            int(row["logon_source_id"])
            if row.get("logon_source_id") is not None else None
        ),
        "logoff_source_id": (
            int(row["logoff_source_id"])
            if row.get("logoff_source_id") is not None else None
        ),
        "previous_revision_sha256": (
            str(row["previous_revision_sha256"])
            if row.get("previous_revision_sha256") else None
        ),
        "revision_sha256": str(row["revision_sha256"]),
        "batch_identity": str(row["batch_identity"]),
    }


def classify_session_existing(
    expected_revisions: list[dict[str, _src.Any]],
    expected_placements: list[dict[str, _src.Any]],
    actual_revisions: list[dict[str, _src.Any]],
    actual_placements: list[dict[str, _src.Any]],
) -> str:
    if not actual_revisions and not actual_placements:
        return "new"
    expected_revision_rows = sorted(
        (_src._canonical_session_revision(row) for row in expected_revisions),
        key=lambda row: (
            row["session_uid_hex"], row["revision"], row["revision_sha256"]
        ),
    )
    actual_revision_rows = sorted(
        (_src._canonical_session_revision(row) for row in actual_revisions),
        key=lambda row: (
            row["session_uid_hex"], row["revision"], row["revision_sha256"]
        ),
    )
    expected_placement_rows = sorted(
        (_src._canonical_session_placement(row) for row in expected_placements),
        key=lambda row: (
            row["event_id"], row["revision"], row["lifecycle_revision_sha256"]
        ),
    )
    actual_placement_rows = sorted(
        (_src._canonical_session_placement(row) for row in actual_placements),
        key=lambda row: (
            row["event_id"], row["revision"], row["lifecycle_revision_sha256"]
        ),
    )
    if (
        expected_revision_rows != actual_revision_rows
        or expected_placement_rows != actual_placement_rows
    ):
        raise RuntimeError("partial_or_mismatched_warm_session_batch")
    return "present"


def _stage_session_rows(
    port: int,
    stage: str,
    revisions: list[dict[str, _src.Any]],
    placements: list[dict[str, _src.Any]],
) -> None:
    if not revisions:
        if placements:
            raise RuntimeError("session_placements_without_revisions")
        return
    _src._http_query(port, _src.CREATE_SESSION_REVISION_INPUT.format(db=stage))
    _src._http_query(port, _src.CREATE_SESSION_PLACEMENT_INPUT.format(db=stage))
    inserted, interrupted = _src._http_insert_json_rows(
        port, f"{stage}.session_revision_input", revisions,
    )
    if interrupted or inserted != len(revisions):
        raise RuntimeError("session_revision_staging_incomplete")
    inserted, interrupted = _src._http_insert_json_rows(
        port, f"{stage}.session_placement_input", placements,
    )
    if interrupted or inserted != len(placements):
        raise RuntimeError("session_placement_staging_incomplete")
    _src._http_query(
        port,
        f"INSERT INTO {_src.DATABASE}.session_lifecycle_revisions SELECT "
        "unhex(session_uid_hex),revision,state,server_id,domain_id,channel_id,"
        "logon_time_utc,logoff_time_utc,duration_s,logon_id,logon_source_id,"
        "logoff_source_id,if(previous_revision_sha256 IS NULL,NULL,"
        "toFixedString(previous_revision_sha256,64)),"
        "toFixedString(revision_sha256,64),toFixedString(batch_identity,64),"
        f"published_at_utc FROM {stage}.session_revision_input "
        "ORDER BY session_uid_hex,revision",
    )
    _src._http_query(
        port,
        f"INSERT INTO {_src.DATABASE}.event_session_placement_revisions SELECT "
        "event_id,revision,unhex(session_uid_hex),placement,"
        "toFixedString(lifecycle_revision_sha256,64),"
        "toFixedString(batch_identity,64),published_at_utc "
        f"FROM {stage}.session_placement_input ORDER BY event_id,revision",
    )
