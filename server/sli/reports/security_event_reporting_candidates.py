"""Split out of ``server.sli.reports.security_event_reporting`` (plan 7.2b).

Module-level names of ``security_event_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reports.security_event_reporting as _src


def get_security_event_candidate_ids(
    access: _src.Mapping[str, _src.Any], *, source_domain_id: int,
    time_from: str | None, time_to: str | None, timezone_name: str = "UTC",
    limit: int = _src.DEFAULT_ROWS, entity_id: int | None = None,
) -> dict[str, _src.Any]:
    """Return only exact bounded IDs for a later per-event authorization step."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("security_events_domain_invalid")
    if not time_from or not time_to:
        raise _src.TimeRangeError("security_events_requires_time_bounds")
    start_raw, end_raw = _src.normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _src._utc(start_raw), _src._utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise _src.TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > _src.timedelta(days=_src.MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= _src.MAX_ROWS:
        raise ValueError("security_events_limit_invalid")
    filters = _src.normalize_security_event_filters(entity_id=entity_id)
    if "entity_id" not in filters:
        raise ValueError("security_events_filter_invalid")
    if not _src._read_access_allowed(access, domain_id, action="view"):
        return {"state": "not_authorized", "items": [], "has_more": False}
    event_db_ids, has_more = _src._read_security_event_candidate_ids(
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        limit=clean_limit,
        filters=filters,
    )
    return {
        "state": "available",
        "items": [{"event_db_id": event_db_id} for event_db_id in event_db_ids],
        "has_more": has_more,
    }


def _read_security_event_candidate_ids(
    *, domain_id: int, period_start: _src.datetime, period_end: _src.datetime,
    limit: int, filters: _src.Mapping[str, _src.Any],
) -> tuple[list[int], bool]:
    """Apply the report's exact predicate but disclose only IDs to its caller."""

    (
        event_ids, provider_predicate, provider_params,
        target_identity_sql, _target_name_sql, filter_sql, filter_params,
    ) = _src.security_event_read_contract(filters)
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select event.id as event_db_id
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join storage_v2_keywords keywords on keywords.id=event.keywords_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                where event.domain_id=%s and server.role='domain_controller'
                  and event.event_id=any(%s) and channel.value=%s and """
            + provider_predicate
            + " and event.time_created_utc>=%s and event.time_created_utc<%s"
            + filter_sql
            + " order by event.time_created_utc desc,event.id desc limit %s",
            [
                domain_id, event_ids, _src.SECURITY_CHANNEL, *provider_params,
                period_start, period_end, *filter_params, limit + 1,
            ],
        )
        rows = [dict(row) for row in cur.fetchall()]
    return [int(row["event_db_id"]) for row in rows[:limit]], len(rows) > limit
