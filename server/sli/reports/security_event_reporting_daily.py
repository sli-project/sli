"""Split out of ``server.sli.reports.security_event_reporting`` (plan 7.2b).

Module-level names of ``security_event_reporting`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.reports.security_event_reporting as _src


def get_security_events_daily(
    access: _src.Mapping[str, _src.Any], *, source_domain_id: int | None,
    time_from: str | None, time_to: str | None, timezone_name: str = "UTC",
    category: str | None = None, event_id: int | None = None, outcome: str | None = None,
    actor: str | None = None, target_account: str | None = None, group: str | None = None,
    source_host: str | None = None, q: str | None = None, entity_id: int | None = None,
) -> dict[str, _src.Any]:
    """Counts of the same authorized, filtered events per local day and family.

    Same bounds, filters and access decision as ``get_security_events_report``;
    an aggregate over the whole filter window, never a display page.
    """
    domain_id = int(source_domain_id) if source_domain_id is not None else None
    if domain_id is not None and domain_id <= 0:
        raise ValueError("security_events_domain_invalid")
    if not time_from or not time_to:
        raise _src.TimeRangeError("security_events_requires_time_bounds")
    start_raw, end_raw = _src.normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    period_start, period_end = _src._utc(start_raw), _src._utc(end_raw)
    if period_start is None or period_end is None or period_start >= period_end:
        raise _src.TimeRangeError("empty_or_reversed_time_range")
    if period_end - period_start > _src.timedelta(days=_src.MAX_PERIOD_DAYS):
        raise ValueError("security_events_period_too_wide")
    try:
        zone = _src.ZoneInfo(timezone_name).key
    except (_src.ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError("security_events_timezone_invalid") from exc
    filters = _src.normalize_security_event_filters(
        category=category, event_id=event_id, outcome=outcome, actor=actor,
        target_account=target_account, group=group, source_host=source_host, q=q,
        entity_id=entity_id, event_db_id=None,
    )
    domain_ids = _src._authorized_security_event_domains(access, action="view") if domain_id is None else None
    if (domain_id is None and not domain_ids) or (domain_id is not None and not _src._read_access_allowed(access, domain_id, action="view")):
        return {"state": "not_authorized", "days": []}
    counts = _src._read_security_events_daily(
        domain_id=domain_ids if domain_id is None else domain_id, period_start=period_start, period_end=period_end, filters=filters, zone=zone,
    )
    by_day: dict[str, dict[str, int]] = {}
    for row in counts:
        family = _src.security_event_family(row.get("event_id")) or "other"
        day = by_day.setdefault(str(row["day"]), {})
        day[family] = day.get(family, 0) + int(row.get("event_count") or 0)
    return {
        "state": "available",
        "timezone": zone,
        "days": [{"date": day, "total": sum(families.values()), "families": families} for day, families in sorted(by_day.items())],
    }


def _read_security_events_daily(
    *, domain_id: int | list[int], period_start: _src.datetime, period_end: _src.datetime, filters: _src.Mapping[str, _src.Any], zone: str,
) -> list[dict[str, _src.Any]]:
    (
        event_ids, provider_predicate, provider_params,
        _target_identity_sql, _target_name_sql, filter_sql, filter_params,
    ) = _src.security_event_read_contract(filters)
    domain_sql = "event.domain_id=any(%s)" if isinstance(domain_id, list) else "event.domain_id=%s"
    with _src._connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """select (event.time_created_utc at time zone %s)::date as day, event.event_id,
                      count(*) as event_count
                 from events_v2_core event
                 join servers server on server.id=event.server_id
                 join storage_v2_channel channel on channel.id=event.channel_id
                 join storage_v2_provider provider on provider.id=event.provider_id
                 left join storage_v2_keywords keywords on keywords.id=event.keywords_id
                 left join event_facts_v2 facts on facts.event_id=event.id
                where """ + domain_sql + """ and server.role='domain_controller'
                  and event.event_id=any(%s) and channel.value=%s and """
            + provider_predicate
            + " and event.time_created_utc>=%s and event.time_created_utc<%s"
            + filter_sql
            + " group by 1, 2 order by 1, 2",
            [zone, domain_id, event_ids, _src.SECURITY_CHANNEL, *provider_params, period_start, period_end, *filter_params],
        )
        return [dict(row) for row in cur.fetchall()]
