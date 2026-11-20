from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from server.sli.core.database import is_postgres_runtime_db, query_rows
from server.sli.ops.logging_config import log_event
from server.sli.storage.permanent_fact_history import (
    _json_ch_time,
    _payload_sha,
    configured_read_port,
    primary_read_enabled,
    read_published_events_many,
)
from server.sli.storage.permanent_fact_history import (
    _rows as _history_rows,
)
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.reporting.reporting_common import (
    clean_int_list,
    format_html_escape,
    format_html_pill,
)
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_policy import load_storage_policy
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError, ArchiveReader
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore
from server.sli.core.time_contract import normalize_utc_range
from server.sli.core.time_format import format_event_time
from server.sli.reporting.ui_labels import (
    channel_label,
    entity_role_label,
    entity_type_label,
    event_id_label,
)

DEFAULT_ENTITY_LIMIT = 200
MAX_ENTITY_LIMIT = 1000
VALID_SORT_ORDERS = {"desc", "asc"}


def normalize_entity_filters(
    *,
    entity_id: int | str | None = None,
    q: str | None = None,
    role: str | None = None,
    event_id: int | str | None = None,
    event_ids: list[int | str] | None = None,
    channel: str | None = None,
    servers: list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    order: str | None = None,
    timezone_name: str | None = "UTC",
) -> dict[str, Any]:
    clean_event_ids = _clean_int_list(event_ids or [])
    if event_id not in (None, ""):
        clean_event_ids.extend(_clean_int_list([event_id]))
    clean_event_ids = _unique_ints(clean_event_ids)

    clean_servers = []
    for server in servers or []:
        value = str(server or "").strip()
        if value and value not in clean_servers:
            clean_servers.append(value)

    clean_limit = DEFAULT_ENTITY_LIMIT if limit is None else int(limit)
    clean_limit = max(1, min(clean_limit, MAX_ENTITY_LIMIT))
    clean_order = str(order or "desc").lower().strip()
    if clean_order not in VALID_SORT_ORDERS:
        clean_order = "desc"

    clean_from, clean_to = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    return {
        "entity_id": _int_or_none(entity_id),
        "q": str(q or "").strip() or None,
        "role": str(role or "").strip() or None,
        "event_id": clean_event_ids[0] if len(clean_event_ids) == 1 else None,
        "event_ids": clean_event_ids,
        "channel": str(channel or "").strip() or None,
        "servers": clean_servers,
        "limit": clean_limit,
        "offset": max(0, int(offset or 0)),
        "time_from": clean_from,
        "time_to": clean_to,
        "timezone": str(timezone_name or "UTC"),
        "order": clean_order,
    }


def make_entity_detail_url(
    *,
    entity_id: int | str | None = None,
    q: str | None = None,
    role: str | None = None,
    event_id: int | str | None = None,
    event_ids: list[int | str] | None = None,
    channel: str | None = None,
    servers: list[str] | None = None,
    limit: int = 300,
    time_from: str | None = None,
    time_to: str | None = None,
    order: str = "desc",
) -> str:
    filters = normalize_entity_filters(
        entity_id=entity_id,
        q=q,
        role=role,
        event_id=event_id,
        event_ids=event_ids,
        channel=channel,
        servers=servers,
        limit=limit,
        time_from=time_from,
        time_to=time_to,
        order=order,
    )
    params: dict[str, Any] = {"limit": filters["limit"], "order": filters["order"]}
    if filters["entity_id"] is not None:
        params["entity_id"] = filters["entity_id"]
    if filters["q"]:
        params["q"] = filters["q"]
    if filters["role"]:
        params["role"] = filters["role"]
    if filters["event_ids"]:
        params["event_id"] = ",".join(str(value) for value in filters["event_ids"])
    if filters["channel"]:
        params["channel"] = filters["channel"]
    if filters["servers"]:
        params["server"] = ",".join(filters["servers"])
    if filters["time_from"]:
        params["time_from"] = filters["time_from"]
    if filters["time_to"]:
        params["time_to"] = filters["time_to"]
    return "/reports/entity-details.html?" + urlencode(params)


def get_entity_detail_report_data(**raw_filters: Any) -> dict[str, Any]:
    authorization = raw_filters.pop("authorization", None)
    # Storage V2 is the only route (plan 6.5).
    resolve_storage_route(
        authorization=authorization,
        consumer=StorageRouteConsumer.EVENT_ENTITIES,
    )
    if not is_postgres_runtime_db():
        raise RuntimeError("storage_v2_entity_details_requires_postgres")
    filters = normalize_entity_filters(**raw_filters)
    entity = _resolve_entity(filters)
    if entity is None:
        log_event("reports", "entity_detail_not_found", "Entity detail requested, but entity was not found.", q=filters.get("q"), entity_id=filters.get("entity_id"))
        return {"filters": filters, "entity": None, "total": 0, "items": []}
    if primary_read_enabled():
        return _get_history_entity_detail_data(entity, filters)

    where_sql, params = _where_clause(filters, int(entity["id"]))
    event_source = _entity_event_source()
    total = query_rows(
        f"""
        select count(*) as count
        from {event_source}
        {where_sql}
        """,
        tuple(params),
    )[0]["count"]
    order_sql = "asc" if filters["order"] == "asc" else "desc"
    rows = query_rows(
        f"""
        select
            eel.entity_id,
            eel.link_role,
            eel.confidence,
            eel.extracted_from,
            eel.attributes_json as link_attributes_json,
            eel.evidence_json,
            e.id as event_db_id,
            s.hostname as server,
            e.channel,
            e.provider_name,
            e.event_id,
            e.event_record_id,
            e.time_created_utc,
            e.time_created_local,
            e.subject_user_name,
            e.subject_domain_name,
            e.target_user_name,
            e.target_domain_name,
            e.ip_address,
            e.workstation_name,
            e.logon_id,
            e.message_text,
            e.event_data_json
        from {event_source}
        {where_sql}
        order by e.time_created_utc {order_sql}, e.event_record_id {order_sql}, e.id {order_sql}
        limit ? offset ?
        """,
        tuple(params + [filters["limit"], filters["offset"]]),
    )
    if rows:
        details_by_event = _read_v2_link_details(
            [int(row["event_db_id"]) for row in rows],
            getattr(authorization, "archive_root", None),
        )
        rows = [_merge_v2_link_detail(row, details_by_event) for row in rows]
    items = [_normalize_entity_event_row(row) for row in rows]
    log_event(
        "reports",
        "entity_detail_report_requested",
        "Entity detail report requested.",
        entity_id=entity["id"],
        role=filters.get("role"),
        total=total,
        returned=len(items),
    )
    return {"filters": filters, "entity": _normalize_entity(entity), "total": total, "items": items}


def render_entity_detail_report(data: dict[str, Any]) -> str:
    filters = data.get("filters") or {}
    entity = data.get("entity")
    items = data.get("items") or []
    total = int(data.get("total") or 0)
    title = _entity_title(entity, filters)
    rows_html = _detail_rows(items)
    if not rows_html:
        rows_html = '<tr><td colspan="11" class="muted">Связанные события не найдены.</td></tr>'
    shown = f"показано {len(items)} из {total}"
    reverse_order = "asc" if filters.get("order") == "desc" else "desc"
    reverse_url = make_entity_detail_url(
        entity_id=entity.get("id") if entity else filters.get("entity_id"),
        q=filters.get("q"),
        role=filters.get("role"),
        event_ids=filters.get("event_ids") or [],
        channel=filters.get("channel"),
        servers=filters.get("servers") or [],
        limit=filters.get("limit") or DEFAULT_ENTITY_LIMIT,
        time_from=filters.get("time_from"),
        time_to=filters.get("time_to"),
        order=reverse_order,
    )
    entity_info = _entity_info_html(entity)
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
{_style()}
</head>
<body>
{report_controls()}
<main class="wrap">
  <header class="hero">
    <div>
      <div class="eyebrow">Сущность и связанные события</div><span class="sr-only">Entity drill-down</span>
      <h1>{_e(title)}</h1>
      <p class="subtitle">Отчет показывает, как учетная запись, компьютер, IP или другая сущность участвовала в событиях: кто действовал, что было целью и откуда пришло действие.</p>
      <div class="pillrow">
        {_pill("Роль", entity_role_label(filters.get("role")) if filters.get("role") else "любая")}
        {_pill("Event ID", _event_ids_label(filters))}
        {_pill("Журнал", channel_label(filters.get("channel"), with_original=True) if filters.get("channel") else "любой")}
        {_pill("Серверы", ", ".join(filters.get("servers") or []) or "все")}
        {_pill("С", format_event_time(filters.get("time_from")) if filters.get("time_from") else "не задано")}
        {_pill("По", format_event_time(filters.get("time_to")) if filters.get("time_to") else "не задано")}
        {_pill("Строк", shown)}
      </div>
    </div>
  </header>

  <section>{entity_info}</section>

  <section>
    <div class="section-title">
      <div>
        <h2>Связанные события</h2>
        <p class="muted">Роль показывает участие сущности в событии: инициатор, цель, источник, затронутый объект, записавший сервер или контекст.</p>
      </div>
      <div class="toolbar">
        <a class="button" href="{_e(reverse_url)}">Сменить порядок</a>
        <button type="button" onclick="window.close()">Закрыть</button>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>UTC</th>
          <th>Роль</th>
          <th>Уверенность</th>
          <th>Сервер</th>
          <th>Журнал</th>
          <th>Тип события</th>
          <th>Record ID</th>
          <th>Инициатор</th>
          <th>Цель</th>
          <th>Источник</th>
          <th>Детали</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </section>
</main>
</body>
</html>
"""


def _get_history_entity_detail_data(
    entity: dict[str, Any], filters: dict[str, Any]) -> dict[str, Any]:
    """Merge published ClickHouse history with the seven-day PostgreSQL window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=load_storage_policy().db_retention_days)
    cold_total, _ = _read_history_entity_links(
        int(entity["id"]), filters, cutoff=cutoff, offset=0, limit=0,
    )
    hot_filters = dict(filters)
    lower = hot_filters.get("time_from")
    if lower is None or datetime.fromisoformat(str(lower).replace("Z", "+00:00")) < cutoff:
        hot_filters["time_from"] = cutoff.isoformat()
    where_sql, params = _where_clause(hot_filters, int(entity["id"]))
    event_source = _entity_event_source()
    hot_total = int(query_rows(
        f"select count(*) as count from {event_source} {where_sql}",
        tuple(params),
    )[0]["count"])
    page_offset = int(filters["offset"])
    page_limit = int(filters["limit"])
    if filters["order"] == "asc":
        cold_offset = min(page_offset, cold_total)
        cold_limit = min(page_limit, cold_total - cold_offset)
        hot_offset = max(0, page_offset - cold_total)
        hot_limit = page_limit - cold_limit
    else:
        hot_offset = min(page_offset, hot_total)
        hot_limit = min(page_limit, hot_total - hot_offset)
        cold_offset = max(0, page_offset - hot_total)
        cold_limit = page_limit - hot_limit
    cold_rows = _read_history_entity_links(
        int(entity["id"]), filters, cutoff=cutoff, offset=cold_offset,
        limit=cold_limit, known_total=cold_total,
    )[1] if cold_limit else []
    order_sql = "asc" if filters["order"] == "asc" else "desc"
    hot_rows = query_rows(
        f"""
        select eel.entity_id,eel.link_role,eel.confidence,eel.extracted_from,
               eel.attributes_json as link_attributes_json,eel.evidence_json,
               e.id as event_db_id,s.hostname as server,e.channel,e.provider_name,
               e.event_id,e.event_record_id,e.time_created_utc,e.time_created_local,
               e.subject_user_name,e.subject_domain_name,e.target_user_name,
               e.target_domain_name,e.ip_address,e.workstation_name,e.logon_id,
               e.message_text,e.event_data_json
        from {event_source} {where_sql}
        order by e.time_created_utc {order_sql},coalesce(e.event_record_id,-1) {order_sql},e.id {order_sql},eel.link_role {order_sql}
        limit ? offset ?
        """,
        tuple(params + [hot_limit, hot_offset]),
    ) if hot_limit else []
    if hot_rows:
        details = _read_v2_link_details(
            [int(row["event_db_id"]) for row in hot_rows],
            None,
        )
        hot_rows = [_merge_v2_link_detail(row, details) for row in hot_rows]
    visible = [*cold_rows, *hot_rows] if filters["order"] == "asc" else [*hot_rows, *cold_rows]
    items = [_normalize_entity_event_row(row) for row in visible]
    total = cold_total + hot_total
    log_event(
        "reports", "entity_detail_report_requested",
        "Entity detail requested from published history and hot data.",
        entity_id=entity["id"], role=filters.get("role"), total=total,
        returned=len(items),
    )
    return {"filters": filters, "entity": _normalize_entity(entity), "total": total, "items": items}


def _read_history_entity_links(
    entity_id: int, filters: dict[str, Any], *, cutoff: datetime,
    offset: int, limit: int, known_total: int | None = None,
) -> tuple[int, list[dict[str, Any]]]:
    port = configured_read_port()
    if port is None:
        raise RuntimeError("history ClickHouse port missing")
    params: dict[str, str] = {}

    def bind(value: Any) -> str:
        name = f"v{len(params)}"
        params[name] = str(value)
        return "{" + name + ":String}"

    parts = [
        f"l.entity_id={int(entity_id)}",
        "l.batch_sha256 IN (SELECT batch_sha256 FROM sli_history.published_batches)",
        f"l.time_created_utc<parseDateTime64BestEffort({bind(cutoff.isoformat())},6,'UTC')",
    ]
    if filters.get("role"):
        parts.append(f"l.link_role={bind(filters['role'])}")
    for key, op in (("time_from", ">="), ("time_to", "<")):
        if filters.get(key):
            parts.append(f"l.time_created_utc{op}parseDateTime64BestEffort({bind(filters[key])},6,'UTC')")
    event_parts = [
        "e.batch_sha256 IN (SELECT batch_sha256 FROM sli_history.published_batches)",
    ]
    if filters.get("event_ids"):
        event_parts.append(
            f"e.event_key IN ({','.join(str(int(value)) for value in filters['event_ids'])})"
        )
    if filters.get("channel"):
        event_parts.append(
            f"JSONExtractString(e.core_json,'channel')={bind(filters['channel'])}"
        )
    if filters.get("servers"):
        names = list(filters["servers"])
        servers = query_rows(
            f"select id from servers where hostname in ({','.join('?' for _ in names)})",
            tuple(names),
        )
        if not servers:
            return 0, []
        event_parts.append(f"e.server_id IN ({','.join(str(int(row['id'])) for row in servers)})")
    if len(event_parts) > 1:
        parts.append(
            "l.event_db_id IN (SELECT e.event_db_id FROM sli_history.events e WHERE "
            + " AND ".join(event_parts) + ")"
        )
    where = " AND ".join(parts)
    if known_total is None:
        count_rows = _history_rows(
            port, f"SELECT count() AS n FROM sli_history.links l WHERE {where}",
            query_params=params,
        )
        total = int(count_rows[0]["n"]) if count_rows else 0
    else:
        total = int(known_total)
    if not total or not limit:
        return total, []
    direction = "ASC" if filters["order"] == "asc" else "DESC"
    links = _history_rows(
        port,
        "SELECT l.event_db_id,l.entity_id,l.link_role,l.details_json,"
        "l.row_sha256,l.batch_sha256,l.time_created_utc "
        "FROM sli_history.links l INNER JOIN sli_history.events e "
        "ON e.event_db_id=l.event_db_id AND e.batch_sha256=l.batch_sha256 "
        f"WHERE {where} "
        f"ORDER BY l.time_created_utc {direction},"
        f"coalesce(JSONExtract(e.core_json,'event_record_id','Nullable(Int64)'),-1) {direction},"
        f"l.event_db_id {direction},l.link_role {direction} "
        f"LIMIT {int(limit)} OFFSET {int(offset)}",
        query_params=params,
    )
    event_ids = sorted({int(row["event_db_id"]) for row in links})
    events: dict[int, dict[str, Any]] = {}
    for start in range(0, len(event_ids), 1_000):
        events.update(read_published_events_many(port, event_ids[start:start + 1_000]))
    server_ids = sorted({int(event["server_id"]) for event in events.values()})
    servers = query_rows(
        f"select id,hostname from servers where id in ({','.join('?' for _ in server_ids)})",
        tuple(server_ids),
    ) if server_ids else []
    server_names = {int(row["id"]): row["hostname"] for row in servers}
    if set(server_names) != set(server_ids):
        raise ArchiveIntegrityError("historical entity server identity missing")
    result: list[dict[str, Any]] = []
    for link in links:
        event_id = int(link["event_db_id"])
        event = events[event_id]
        detail = json.loads(link["details_json"])
        if (
            _payload_sha(detail) != link["row_sha256"]
            or int(detail["event_id"]) != event_id
            or int(detail["entity_id"]) != int(entity_id)
            or str(detail["link_role"]) != str(link["link_role"])
            or link["batch_sha256"] != event["_history_batch_sha256"]
            or link["time_created_utc"] != _json_ch_time(event["time_created_utc"])
        ):
            raise ArchiveIntegrityError("historical entity link mismatch")
        facts = event.get("retained_facts") or {}
        result.append({
            "event_db_id": event_id, "link_role": link["link_role"],
            "confidence": detail.get("confidence"),
            "extracted_from": detail.get("extracted_from"),
            "link_attributes_json": detail.get("attributes_json"),
            "evidence_json": detail.get("evidence_json"),
            "server": server_names[int(event["server_id"])],
            "channel": event.get("channel"), "provider_name": event.get("provider_name"),
            "event_id": event["event_id"], "event_record_id": event.get("event_record_id"),
            "time_created_utc": event["time_created_utc"],
            "time_created_local": event["time_created_utc"],
            "subject_user_name": event.get("subject_user_name"),
            "subject_domain_name": event.get("subject_domain_name"),
            "target_user_name": event.get("target_user_name"),
            "target_domain_name": event.get("target_domain_name"),
            "ip_address": event.get("ip_address"),
            "workstation_name": event.get("workstation_name"),
            "logon_id": event.get("logon_id"),
            "message_text": None,
            "event_data_json": json.dumps(facts, ensure_ascii=False),
            "source_payload_state": "expired",
        })
    return total, result


def _entity_event_source() -> str:
    """Storage V2 links and core under the aliases ``eel`` / ``e`` (plan 6.5)."""
    return """
        (
            select link.event_id,link.entity_id,role.value as link_role,
                   null::double precision as confidence,null::text as extracted_from,
                   null::text as attributes_json,null::text as evidence_json
            from event_entity_links_v2 link
            join storage_v2_role role on role.id=link.role_id
        ) eel
        join (
            select core.id,core.server_id,channel.value as channel,
                   provider.value as provider_name,core.event_id,
                   core.event_record_id,core.time_created_utc,
                   null::text as time_created_local,
                   core.subject_user_name,
                   subject_domain.value as subject_domain_name,
                   core.target_user_name,
                   target_domain.value as target_domain_name,
                   core.ip_address,core.workstation_name,core.logon_id,
                   null::text as message_text,null::text as event_data_json
            from events_v2_core core
            join storage_v2_channel channel on channel.id=core.channel_id
            left join storage_v2_provider provider on provider.id=core.provider_id
            left join storage_v2_domain_name subject_domain on subject_domain.id=core.subject_domain_id
            left join storage_v2_domain_name target_domain on target_domain.id=core.target_domain_id
        ) e on e.id=eel.event_id
        join servers s on s.id=e.server_id
    """


def _read_v2_link_details(
    event_ids: list[int], archive_root: str | Path | None,
) -> dict[int, list[dict[str, Any]]]:
    from server.sli.core.postgres_runtime_pipeline import connect

    reader = ArchiveReader(
        PostgresArchiveManifestStore(connect),
        archive_root=Path(archive_root) if archive_root is not None else None,
    )
    return {
        event_id: [dict(row) for row in rows]
        for event_id, rows in reader.read_link_details_many(
            event_ids, max_blocks=64,
        ).items()
    }


def _merge_v2_link_detail(
    row: dict[str, Any],
    details_by_event: dict[int, list[dict[str, Any]]],
) -> dict[str, Any]:
    event_id = int(row["event_db_id"])
    entity_id = int(row["entity_id"])
    role = str(row["link_role"])
    matches = [
        detail for detail in details_by_event.get(event_id, [])
        if int(detail.get("entity_id") or 0) == entity_id
        and str(detail.get("link_role") or "") == role
    ]
    if len(matches) != 1:
        raise ArchiveIntegrityError(
            "V2 link archive must contain exactly one detail row for "
            f"event={event_id}, entity={entity_id}, role={role}"
        )
    detail = matches[0]
    return {
        **row,
        "confidence": detail.get("confidence"),
        "extracted_from": detail.get("extracted_from"),
        "link_attributes_json": detail.get("attributes_json"),
        "evidence_json": detail.get("evidence_json"),
    }


def _entity_source() -> str:
    return """
        entities_v2 entity
        join storage_v2_entity_type entity_type on entity_type.id=entity.entity_type_id
        left join entity_details_v2 details on details.entity_id=entity.id
        left join domains domain on domain.id=entity.domain_id
    """


def _entity_projection() -> str:
    return """
        entity.id,entity_type.value as entity_type,entity.natural_key,
        entity.display_name,domain.fqdn as domain_name,entity.server_id,
        entity.first_seen_utc,entity.last_seen_utc,details.attributes_json
    """


def _resolve_entity(
    filters: dict[str, Any],
) -> dict[str, Any] | None:
    source = _entity_source()
    projection = _entity_projection()
    if filters.get("entity_id") is not None:
        rows = query_rows(
            f"select {projection} from {source} where entity.id = ?",
            (filters["entity_id"],),
        )
        return rows[0] if rows else None
    q = filters.get("q")
    if not q:
        return None
    rows = query_rows(
        f"""
        select {projection}
        from {source}
        where lower(entity.natural_key) = lower(?) or lower(coalesce(entity.display_name,'')) = lower(?)
           or lower(coalesce(entity.display_name,'')) like ? or lower(entity.natural_key) like ?
        order by case when lower(entity.natural_key) = lower(?) or lower(coalesce(entity.display_name,'')) = lower(?) then 0 else 1 end, entity.last_seen_utc desc, entity.id desc
        limit 1
        """,
        (q, q, f"{q.casefold()}%", f"{q.casefold()}%", q, q),
    )
    return rows[0] if rows else None


def _where_clause(filters: dict[str, Any], entity_id: int) -> tuple[str, list[Any]]:
    parts = ["eel.entity_id = ?"]
    params: list[Any] = [entity_id]
    if filters.get("role"):
        parts.append("eel.link_role = ?")
        params.append(filters["role"])
    event_ids = filters.get("event_ids") or []
    if event_ids:
        parts.append(f"e.event_id in ({','.join(['?'] * len(event_ids))})")
        params.extend(event_ids)
    if filters.get("channel"):
        parts.append("e.channel = ?")
        params.append(filters["channel"])
    servers = filters.get("servers") or []
    if servers:
        parts.append(f"s.hostname in ({','.join(['?'] * len(servers))})")
        params.extend(servers)
    if filters.get("time_from"):
        parts.append("e.time_created_utc >= ?")
        params.append(filters["time_from"])
    if filters.get("time_to"):
        parts.append("e.time_created_utc < ?")
        params.append(filters["time_to"])
    return "where " + " and ".join(parts), params


def _normalize_entity(row: dict[str, Any]) -> dict[str, Any]:
    attributes = _parse_json_object(row.get("attributes_json"))
    return {**row, "attributes": attributes}


def _normalize_entity_event_row(row: dict[str, Any]) -> dict[str, Any]:
    event_data = _parse_json_object(row.get("event_data_json"))
    message = str(row.get("message_text") or "").strip()
    return {
        **row,
        "time_created_utc_display": format_event_time(row.get("time_created_utc")),
        "subject": _principal(row.get("subject_domain_name"), row.get("subject_user_name")),
        "target": _principal(row.get("target_domain_name"), row.get("target_user_name")),
        "source": _source_hint(row),
        "event_data": event_data,
        "event_data_summary": _event_data_summary(event_data),
        "message_text": message,
        "link_attributes": _parse_json_object(row.get("link_attributes_json")),
        "evidence": _parse_json_object(row.get("evidence_json")),
    }


def _detail_rows(items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        event_data_pretty = json.dumps(item.get("event_data") or {}, ensure_ascii=False, indent=2)
        link_pretty = json.dumps(item.get("link_attributes") or {}, ensure_ascii=False, indent=2)
        event_url = "/reports/event-details.html?" + urlencode(
            {"event_db_id": item.get("event_db_id"), "limit": 1}
        )
        rows.append(
            f"""<tr>
<td class="mono" title="{_e(item.get('time_created_utc'))}">{_e(item.get('time_created_utc_display'))}</td>
<td>{_e(entity_role_label(item.get('link_role')))}</td>
<td class="mono">{_e(item.get('confidence'))}</td>
<td>{_e(item.get('server'))}</td>
<td>{_e(channel_label(item.get('channel'), with_original=True))}</td>
<td class="mono"><a href="{_e(event_url)}">{_e(event_id_label(item.get('event_id')))}</a></td>
<td class="mono">{_e(item.get('event_record_id'))}</td>
<td>{_e(item.get('subject'))}</td>
<td>{_e(item.get('target'))}</td>
<td>{_e(item.get('source'))}</td>
<td>
  <div class="summary">{_e(item.get('event_data_summary'))}</div>
  <details><summary>Атрибуты связи</summary><pre>{_e(link_pretty)}</pre></details>
  <details><summary>Поля события</summary><pre>{_e(event_data_pretty)}</pre></details>
  <details><summary>{'Исходное сообщение недоступно' if item.get('source_payload_state') == 'expired' else 'Сообщение Windows'}</summary><pre>{_e(item.get('message_text'))}</pre></details>
</td>
</tr>"""
        )
    return "".join(rows)


def _entity_info_html(entity: dict[str, Any] | None) -> str:
    if not entity:
        return "<h2>Сущность не найдена</h2><p class=\"muted\">Передайте entity_id или q.</p>"
    attrs = json.dumps(entity.get("attributes") or {}, ensure_ascii=False, indent=2)
    return f"""<h2>Сущность</h2>
<div class="entity-grid">
  <div>{_label('ID', entity.get('id'))}</div>
  <div>{_label('Тип', entity_type_label(entity.get('entity_type')))}</div>
  <div>{_label('Отображаемое имя', entity.get('display_name'))}</div>
  <div>{_label('Ключ', entity.get('natural_key'))}</div>
  <div>{_label('Впервые замечена', format_event_time(entity.get('first_seen_utc')))}</div>
  <div>{_label('Последний раз', format_event_time(entity.get('last_seen_utc')))}</div>
</div>
<details><summary>Атрибуты сущности</summary><pre>{_e(attrs)}</pre></details>"""


def _label(name: str, value: Any) -> str:
    return f"<span class=\"muted\">{_e(name)}</span><strong>{_e(value)}</strong>"


def _entity_title(entity: dict[str, Any] | None, filters: dict[str, Any]) -> str:
    if entity:
        return f"Сущность: {entity.get('display_name') or entity.get('natural_key')}"
    if filters.get("q"):
        return f"Сущность: {filters['q']}"
    return "Сущность"


def _parse_json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _principal(domain: Any, name: Any) -> str:
    name_s = str(name or "").strip()
    domain_s = str(domain or "").strip()
    if name_s and domain_s:
        return f"{domain_s}\\{name_s}"
    return name_s or "—"


def _source_hint(row: dict[str, Any]) -> str:
    values = [row.get("ip_address"), row.get("workstation_name")]
    cleaned = [str(value).strip() for value in values if str(value or "").strip()]
    return " / ".join(cleaned) if cleaned else "—"


def _event_data_summary(event_data: dict[str, Any]) -> str:
    priority = ["SubjectUserName", "TargetUserName", "IpAddress", "WorkstationName", "LogonType", "ProcessName", "TaskName", "ServiceName", "MemberName"]
    parts = []
    for key in priority:
        value = event_data.get(key)
        if value not in (None, "", "-"):
            parts.append(f"{key}={value}")
    if not parts:
        for key, value in list(event_data.items())[:8]:
            if value not in (None, ""):
                parts.append(f"{key}={value}")
    return "; ".join(parts) if parts else "—"


_clean_int_list = clean_int_list


def _unique_ints(values: list[int]) -> list[int]:
    output = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


def _int_or_none(value: int | str | None) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _event_ids_label(filters: dict[str, Any]) -> str:
    values = filters.get("event_ids") or []
    return ", ".join(str(value) for value in values) if values else "любой"


_pill = format_html_pill
_e = format_html_escape



def _style() -> str:
    return report_style()
