from __future__ import annotations

import os
import hashlib
import json
from functools import lru_cache
from datetime import datetime, timezone
from typing import Any

from server.sli.core.database import is_postgres_runtime_db
from server.sli.semantic.event_card_semantics import compile_catalog_risk_sql
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization

_RECENT_EVENT_SAMPLE_DEFAULT = 50_000
_RECENT_ENTITY_SAMPLE_DEFAULT = 20_000
_DASHBOARD_CATALOG_SCHEMA_VERSION = 1
_DASHBOARD_RISK_COMPILER_VERSION = 2


def _dashboard_catalog_fingerprint(entries: list[dict[str, Any]]) -> str:
    """Hash only catalogue fields consumed by the dashboard SQL compiler."""
    rules = []
    for entry in entries:
        card = dict(entry.get("card") or {})
        rules.append({
            "event_id": int(entry.get("event_id") or 0),
            "provider_name": str(entry.get("provider_name") or "").strip().lower(),
            "channel": str(entry.get("channel") or "").strip().lower(),
            "base_risk": str(entry.get("base_risk") or entry.get("severity") or "info").strip().lower(),
            "risk_rules": [
                {"severity": str(rule.get("severity") or "").strip().lower(), "all": list(rule.get("all") or [])}
                for rule in (dict(value) for value in card.get("risk_rules") or [])
            ],
        })
    rules.sort(key=lambda item: (
        item["event_id"], item["provider_name"], item["channel"],
        json.dumps(item["risk_rules"], ensure_ascii=True, sort_keys=True, separators=(",", ":")),
    ))
    payload = {
        "catalog_schema_version": _DASHBOARD_CATALOG_SCHEMA_VERSION,
        "compiler_version": _DASHBOARD_RISK_COMPILER_VERSION,
        "rules": rules,
    }
    canonical = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@lru_cache(maxsize=8)
def _compile_dashboard_risk_sql(catalog_fingerprint: str, catalog_ids: tuple[int, ...]):
    """Cache deterministic SQL by a bounded content-sensitive identity."""
    del catalog_fingerprint
    return compile_catalog_risk_sql(list(catalog_ids), event_alias="e", server_alias="s", placeholder="%s")


def _dashboard_risk_projection():
    entries = [dict(entry) for entry in all_event_catalog_entries()]
    catalog_ids = tuple(sorted({int(entry.get("event_id") or 0) for entry in entries}))
    return _compile_dashboard_risk_sql(_dashboard_catalog_fingerprint(entries), catalog_ids)


def _v2_read_selected(
    authorization: CutoverAuthorization | None = None,
) -> bool:
    """Storage V2 is the only route (plan 6.5); reject bad authority or non-PostgreSQL."""
    resolve_storage_route(authorization=authorization, consumer=StorageRouteConsumer.DASHBOARD)
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_route_requires_postgres")
    return True


def get_overview_activity(
    *,
    time_from: str,
    time_to: str,
    server: str | None = None,
    bucket_count: int = 12,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return exact, bounded time buckets for the Overview chart.

    The query groups inside PostgreSQL and returns only distinct semantic keys
    per bucket.  It never approximates the chart from the newest N rows.
    """
    bucket_count = max(2, min(int(bucket_count), 24))
    start = datetime.fromisoformat(time_from.replace("Z", "+00:00")).astimezone(timezone.utc)
    end = datetime.fromisoformat(time_to.replace("Z", "+00:00")).astimezone(timezone.utc)
    if end <= start or (end - start).total_seconds() > 8 * 24 * 60 * 60:
        raise ValueError("overview_period_must_be_positive_and_not_exceed_8_days")
    if not is_postgres_runtime_db():
        return {"items": [], "available": False, "exact": False, "reason": "postgres_required"}
    _v2_read_selected(authorization)

    from server.sli.core.postgres_runtime_pipeline import connect

    # Storage V2 is the only route (plan 6.5).
    source_sql = """(
        select core.*, channel.value as channel, provider.value as provider_name,
               jsonb_build_object(
                 'TaskName', facts.task_name, 'Action', facts.task_action,
                 'Author', facts.task_author, 'RunAs', facts.run_as,
                 'ProcessName', facts.process_name, 'Message', facts.message_sample
               )::text as event_data_json
        from events_v2_core core
        join storage_v2_channel channel on channel.id=core.channel_id
        left join storage_v2_provider provider on provider.id=core.provider_id
        left join event_facts_v2 facts on facts.event_id=core.id
    ) e join servers s on s.id=e.server_id"""
    activity_time_sql = "e.time_created_utc"
    time_predicate_sql = "e.time_created_utc >= %s::timestamptz and e.time_created_utc < %s::timestamptz"
    time_bounds: list[Any] = [start, end]
    server_predicate = " and lower(s.hostname)=lower(%s)" if server else ""
    seconds = (end - start).total_seconds() / bucket_count
    risk_projection = _dashboard_risk_projection()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"set local statement_timeout = {_statement_timeout_ms()}")
            cur.execute(
                f"""
                select bucket, final_security_severity, count(*)::bigint as count
                from (
                    select least(%s - 1, greatest(0, floor(extract(epoch from ({activity_time_sql} - %s::timestamptz)) / %s)::int)) as bucket,
                           {risk_projection.case_sql} as final_security_severity
                    from {source_sql}
                    where {time_predicate_sql}{server_predicate}
                ) semantic_events
                group by bucket, final_security_severity
                order by bucket, final_security_severity
                """,
                tuple([bucket_count, start, seconds, *risk_projection.case_params, *time_bounds] + ([server] if server else [])),
            )
            rows = _rows(cur)

    buckets = [
        {
            "index": index,
            "bucket_start_utc": (start + (end - start) * index / bucket_count).isoformat().replace("+00:00", "Z"),
            "bucket_end_utc": (start + (end - start) * (index + 1) / bucket_count).isoformat().replace("+00:00", "Z"),
            "critical": 0,
            "important": 0,
            "informational": 0,
        }
        for index in range(bucket_count)
    ]
    for row in rows:
        risk = str(row.get("final_security_severity") or "unknown")
        target = (
            "critical" if risk in {"critical", "high"}
            else "important" if risk == "medium"
            else "informational"
        )
        buckets[int(row["bucket"])][target] += int(row.get("count") or 0)
    return {
        "items": buckets,
        "available": True,
        "exact": risk_projection.exact,
        "reason": None if risk_projection.exact else "catalog_context_projection_incomplete",
    }


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(value, maximum))


def _statement_timeout_ms() -> int:
    return _env_int("ADLOG_DASHBOARD_PG_STATEMENT_TIMEOUT_MS", 5000, minimum=500, maximum=30000)


def _recent_event_sample() -> int:
    return _env_int("ADLOG_DASHBOARD_RECENT_EVENT_SAMPLE", _RECENT_EVENT_SAMPLE_DEFAULT, minimum=1000, maximum=250000)


def _recent_entity_sample() -> int:
    return _env_int("ADLOG_DASHBOARD_RECENT_ENTITY_SAMPLE", _RECENT_ENTITY_SAMPLE_DEFAULT, minimum=1000, maximum=100000)


def _rows(cur) -> list[dict[str, Any]]:
    return [dict(row) for row in cur.fetchall()]


def _estimated_v2_link_rows(cur) -> int:
    """Links live in blocks (event_entity_links_v2 is a view without statistics):
    block row estimate times the mean block size from a 1% page sample."""
    cur.execute(
        """
        select (coalesce(greatest(coalesce(st.n_live_tup, 0), coalesce(pc.reltuples, 0)), 0)
                * coalesce((select avg(cardinality(event_ids))
                            from event_entity_link_blocks_v2 tablesample system (1)), 0))::bigint as estimated_rows
        from pg_class pc
        join pg_namespace pn on pn.oid = pc.relnamespace
        left join pg_stat_user_tables st on st.relid = pc.oid
        where pn.nspname = current_schema() and pc.relname = 'event_entity_link_blocks_v2'
        limit 1
        """
    )
    row = cur.fetchone()
    return int((row or {}).get("estimated_rows") or 0)


#: Widening steps for the recent-link threshold (window = sample × 4**step).
_RECENT_LINK_STEPS = 4


def _recent_v2_link_roles(cur, sample_limit: int) -> list[dict[str, Any]]:
    """Role distribution of the ``sample_limit`` links with the highest event ids.

    Scanning the view ordered by event_id unnests every block. Instead take the
    id of the N-th most recent event as a threshold and read only blocks whose
    range reaches it (BRIN on first/last_event_id); widen the window until the
    sample is full or every event is covered, so the result stays the exact top N.
    """
    window = max(1, int(sample_limit))
    rows: list[dict[str, Any]] = []
    for _ in range(_RECENT_LINK_STEPS + 1):
        cur.execute("select id from events_v2_core order by id desc offset %s limit 1", (window - 1,))
        anchor_id = (cur.fetchone() or {}).get("id")
        threshold = int(anchor_id) if anchor_id is not None else 0
        cur.execute(
            """
            with recent as (
                select role.value as link_role
                from event_entity_link_blocks_v2 block
                cross join lateral unnest(block.event_ids, block.role_ids) as expanded(event_id, role_id)
                join storage_v2_role role on role.id=expanded.role_id
                where block.last_event_id >= %s and expanded.event_id >= %s
                order by expanded.event_id desc
                limit %s
            )
            select link_role, count(*)::bigint as count
            from recent
            group by link_role
            order by count desc, link_role
            """,
            (threshold, threshold, sample_limit),
        )
        rows = _rows(cur)
        if anchor_id is None or sum(int(row.get("count") or 0) for row in rows) >= sample_limit:
            return rows
        window *= 4
    return rows


def _estimated_table_rows(cur, table_name: str) -> int:
    cur.execute(
        """
        select greatest(coalesce(st.n_live_tup, 0), coalesce(pc.reltuples, 0))::bigint as estimated_rows
        from pg_class pc
        join pg_namespace pn on pn.oid = pc.relnamespace
        left join pg_stat_user_tables st on st.relid = pc.oid
        where pn.nspname = current_schema() and pc.relname = %s
        limit 1
        """,
        (table_name,),
    )
    row = cur.fetchone()
    return max(0, int((row or {}).get("estimated_rows") or 0))


def get_dashboard_event_summary(
    *,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return a bounded event summary for the main dashboard.

    Deep reports keep using ``get_event_summary`` with exact counts.  PostgreSQL
    dashboard requests must not run full-table COUNT/GROUP BY operations over the
    multi-million-row events table every five seconds, so this function combines
    PostgreSQL row estimates, the small raw-file catalog and a bounded recent
    sample for top Event IDs.
    """
    _v2_read_selected(authorization)

    from server.sli.core.postgres_runtime_pipeline import connect

    sample_limit = _recent_event_sample()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"set local statement_timeout = {_statement_timeout_ms()}")
            total_events = _estimated_table_rows(cur, "events_v2_core")

            cur.execute(
                """
                select ls.name as channel, coalesce(sum(r.event_count), 0)::bigint as count
                from log_sources ls
                left join raw_log_files r on r.log_source_id = ls.id
                group by ls.id, ls.name
                having coalesce(sum(r.event_count), 0) > 0
                order by count desc, ls.name
                """
            )
            by_channel = _rows(cur)

            cur.execute(
                """
                select
                    s.hostname,
                    s.fqdn,
                    s.role,
                    s.is_active,
                    s.os_name,
                    s.os_version,
                    d.fqdn as domain_fqdn,
                    si.name as site_name,
                    coalesce(sum(r.event_count), 0)::bigint as count
                from servers s
                join domains d on d.id = s.domain_id
                left join sites si on si.id = s.site_id
                left join raw_log_files r on r.server_id = s.id
                group by s.id, s.hostname, s.fqdn, s.role, s.is_active, s.os_name, s.os_version, d.fqdn, si.name
                order by s.hostname
                """
            )
            by_server = _rows(cur)

            cur.execute(
                """
                select s.hostname, ls.name as channel, coalesce(sum(r.event_count), 0)::bigint as count
                from raw_log_files r
                join servers s on s.id = r.server_id
                join log_sources ls on ls.id = r.log_source_id
                group by s.hostname, ls.name
                order by s.hostname, ls.name
                """
            )
            by_server_channel = _rows(cur)

            recent_sql = (
                "select e.event_id, channel.value as channel from events_v2_core e "
                "join storage_v2_channel channel on channel.id=e.channel_id"
            )
            recent_order = "e.id"
            cur.execute(
                f"""
                with recent as (
                    {recent_sql}
                    order by {recent_order} desc
                    limit %s
                )
                select event_id, channel, count(*)::bigint as count
                from recent
                group by event_id, channel
                order by count desc, event_id
                limit 20
                """,
                (sample_limit,),
            )
            top_event_ids = _rows(cur)

    catalog_total = sum(int(row.get("count") or 0) for row in by_channel)
    if total_events <= 0:
        total_events = catalog_total
    important_ids = {
        int(entry.get("event_id") or 0)
        for entry in all_event_catalog_entries()
        if str(entry.get("purpose_tier") or "").lower() in {"critical", "important"}
        or str(entry.get("base_risk") or entry.get("severity") or "").lower() in {"critical", "high", "medium", "important"}
    }
    important_recent = sum(
        int(row.get("count") or 0)
        for row in top_event_ids
        if int(row.get("event_id") or 0) in important_ids
    )
    return {
        "total_events": total_events,
        "by_channel": by_channel,
        "top_event_ids": top_event_ids,
        "by_server": by_server,
        "by_server_channel": by_server_channel,
        "security_24h_summary": {
            "important_total": important_recent,
            "mode": "recent_bounded_sample",
            "sample_size": sample_limit,
        },
        "dashboard_mode": "postgres_v2_bounded_catalog",
        "estimated": True,
        "catalog_event_rows": catalog_total,
        "recent_sample_size": sample_limit,
        "limitations": [
            "total_events uses PostgreSQL planner/statistics estimate for a nonblocking dashboard",
            "top_event_ids is calculated from a bounded recent event sample",
            "deep event reports keep exact query semantics",
        ],
    }


def get_dashboard_entity_summary(
    *,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Return bounded entity totals for the dashboard without scanning 27M links."""
    _v2_read_selected(authorization)

    from server.sli.core.postgres_runtime_pipeline import connect

    sample_limit = _recent_entity_sample()
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(f"set local statement_timeout = {_statement_timeout_ms()}")
            # entities_v2_active is a view (entities minus merged-away sources): no statistics of its own.
            total_entities = (
                max(0, _estimated_table_rows(cur, "entities_v2") - _estimated_table_rows(cur, "entity_identity_merges_v2"))
            )
            total_links = _estimated_v2_link_rows(cur)
            entity_recent_sql = (
                "select entity_type.value as entity_type from entities_v2_active entity "
                "join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id "
                "order by entity.id desc"
            )

            cur.execute(
                f"""
                with recent as (
                    {entity_recent_sql}
                    limit %s
                )
                select entity_type, count(*)::bigint as count
                from recent
                group by entity_type
                order by count desc, entity_type
                """,
                (sample_limit,),
            )
            by_type = _rows(cur)

            by_role = _recent_v2_link_roles(cur, sample_limit)

    return {
        "total_entities": total_entities,
        "total_event_entity_links": total_links,
        "by_type": by_type,
        "by_role": by_role,
        "dashboard_mode": "postgres_v2_statistics_and_sample",
        "estimated": True,
        "recent_sample_size": sample_limit,
        "limitations": [
            "entity/link totals use PostgreSQL statistics estimates",
            "type/role distribution uses a bounded recent sample",
            "deep entity reports keep exact query semantics",
        ],
    }
