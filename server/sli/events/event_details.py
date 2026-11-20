from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from server.sli.core.database import is_postgres_runtime_db, query_rows, query_rows_bounded
from server.sli.semantic.event_card_semantics import build_event_card
from server.sli.ops.logging_config import log_event
from server.sli.storage.permanent_fact_history import (
    configured_read_port,
    primary_read_enabled,
    read_published_event,
    read_published_events_many,
)
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.reporting.reporting_common import (
    clean_int_list,
    format_html_escape,
    format_html_pill,
)
from server.sli.storage.runtime_storage import StorageRouteConsumer, resolve_storage_route
from server.sli.storage.storage_policy import load_storage_policy
from server.sli.storage.storage_v2_archive import ArchiveIntegrityError, ArchiveObjectUnavailableError, ArchiveReader
from server.sli.storage.storage_v2_models import parse_utc_timestamp
from server.sli.storage.storage_v2_repository import PostgresArchiveManifestStore
from server.sli.storage.storage_v2_runtime import (
    PostgresStorageV2ReadStore,
    StorageV2RuntimeReader,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)
from server.sli.core.time_format import format_event_time
from server.sli.reporting.ui_labels import channel_label, event_id_label
from server.source_packs.registry import resolve_source_normalizer

DEFAULT_DETAIL_LIMIT = 200
MAX_DETAIL_LIMIT = 1000
VALID_SORT_ORDERS = {"desc", "asc"}
MAX_BATCH_EVENT_IDS = 100
MAX_BATCH_ARCHIVE_BLOCKS = 16


def normalize_detail_filters(
    *,
    event_db_id: int | str | None = None,
    event_id: int | str | None = None,
    event_ids: list[int | str] | None = None,
    channel: str | None = None,
    servers: list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    order: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    logon_id: str | None = None,
) -> dict[str, Any]:
    clean_event_db_id = None
    if event_db_id not in (None, ""):
        try:
            parsed_event_db_id = int(str(event_db_id).strip())
            clean_event_db_id = parsed_event_db_id if parsed_event_db_id > 0 else None
        except (TypeError, ValueError):
            clean_event_db_id = None

    clean_event_ids = _clean_int_list(event_ids or [])
    if event_id not in (None, ""):
        clean_event_ids.extend(_clean_int_list([event_id]))
    clean_event_ids = _unique_ints(clean_event_ids)

    clean_servers = []
    for server in servers or []:
        value = str(server or "").strip()
        if value and value not in clean_servers:
            clean_servers.append(value)

    clean_channel = str(channel or "").strip() or None
    clean_limit = DEFAULT_DETAIL_LIMIT if limit is None else int(limit)
    clean_limit = max(1, min(clean_limit, MAX_DETAIL_LIMIT))
    clean_offset = max(0, int(offset or 0))
    clean_order = str(order or "desc").lower().strip()
    if clean_order not in VALID_SORT_ORDERS:
        clean_order = "desc"

    return {
        "event_db_id": clean_event_db_id,
        "event_id": clean_event_ids[0] if len(clean_event_ids) == 1 else None,
        "event_ids": clean_event_ids,
        "channel": clean_channel,
        "servers": clean_servers,
        "limit": clean_limit,
        "offset": clean_offset,
        "time_from": _clean_time_filter(time_from),
        "time_to": _clean_time_filter(time_to),
        "order": clean_order,
        "user": str(user or "").strip() or None,
        "ip": str(ip or "").strip() or None,
        "logon_id": str(logon_id or "").strip() or None,
    }


def make_event_detail_url(
    *,
    event_db_id: int | str | None = None,
    event_ids: list[int | str] | None = None,
    event_id: int | str | None = None,
    channel: str | None = None,
    servers: list[str] | None = None,
    limit: int = 300,
    time_from: str | None = None,
    time_to: str | None = None,
    order: str = "desc",
    user: str | None = None,
    ip: str | None = None,
    logon_id: str | None = None,
) -> str:
    filters = normalize_detail_filters(
        event_db_id=event_db_id,
        event_id=event_id,
        event_ids=event_ids,
        channel=channel,
        servers=servers,
        limit=limit,
        time_from=time_from,
        time_to=time_to,
        order=order,
        user=user,
        ip=ip,
        logon_id=logon_id,
    )
    params: dict[str, Any] = {"limit": filters["limit"], "order": filters["order"]}
    if filters.get("event_db_id"):
        params["event_db_id"] = filters["event_db_id"]
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
    if filters.get("user"):
        params["user"] = filters["user"]
    if filters.get("ip"):
        params["ip"] = filters["ip"]
    if filters.get("logon_id"):
        params["logon_id"] = filters["logon_id"]
    return "/reports/event-details.html?" + urlencode(params)


def get_event_detail_report_data(
    *,
    authorization: CutoverAuthorization | None = None,
    consumer: str = StorageRouteConsumer.EVENT_DETAILS,
    **raw_filters: Any,
) -> dict[str, Any]:
    filters = normalize_detail_filters(**raw_filters)
    # Storage V2 is the only route (plan 6.5) and serves one exact event.
    _v2_detail_route_selected(authorization, consumer)
    if not filters.get("event_db_id"):
        raise ValueError("storage_v2_detail_requires_exact_event_id")
    v2_row = _get_v2_event_detail_by_id(
        filters, authorization=authorization
    )
    from server.sli.semantic.account_watch_projection import attach_event_priorities

    item = _normalize_event_detail_row(attach_event_priorities([v2_row])[0])
    log_event(
        "reports",
        "event_detail_report_requested",
        "Event detail report served from verified Storage V2 history.",
        event_db_id=filters["event_db_id"],
        storage_backend=(
            "clickhouse_facts" if item.get("source_payload_state") == "expired"
            else "v2_verified_archive"
        ),
    )
    return {"filters": filters, "total": 1, "items": [item]}


def get_event_details_by_ids(
    event_db_ids: list[int],
    *,
    authorization: CutoverAuthorization | None = None,
    consumer: str = StorageRouteConsumer.EVENT_DETAILS,
) -> dict[int, dict[str, Any]]:
    """Hydrate exact IDs through the Storage V2 reader.

    Payload ownership remains in the event-details boundary, which is already
    tracked by the Storage V2 migration inventory. Callers retain their own
    relation order by looking exact IDs up in the returned mapping.
    """
    unique_ids = list(dict.fromkeys(int(value) for value in event_db_ids if int(value) > 0))
    if not unique_ids:
        return {}
    if len(unique_ids) > MAX_BATCH_EVENT_IDS:
        raise ValueError(f"event detail batch is limited to {MAX_BATCH_EVENT_IDS} exact IDs")
    _v2_detail_route_selected(authorization, consumer)
    return _get_v2_event_details_by_ids(unique_ids)


def get_v2_event_details_by_ids(
    event_db_ids: list[int]) -> dict[int, dict[str, Any]]:
    """Hydrate only exact V2 core IDs through the verified V2 archive owner.

    Unlike :func:`get_event_details_by_ids`, this boundary never resolves the
    controller-selected V1/V2 route. Its V2 core query and archive identity
    verification bind the returned payload to the requested V2 numeric IDs; an
    unavailable V2 boundary fails instead of reading a colliding V1 ID.
    """
    unique_ids = list(dict.fromkeys(int(value) for value in event_db_ids if int(value) > 0))
    if not unique_ids:
        return {}
    if len(unique_ids) > MAX_BATCH_EVENT_IDS:
        raise ValueError(f"event detail batch is limited to {MAX_BATCH_EVENT_IDS} exact IDs")
    if not is_postgres_runtime_db():
        raise ValueError("storage_v2_detail_requires_postgres")
    return _get_v2_event_details_by_ids(unique_ids)


def _get_v2_event_details_by_ids(
    event_db_ids: list[int]) -> dict[int, dict[str, Any]]:
    """Hydrate hot raw payload or published historical facts by exact ID."""
    placeholders = ",".join("?" for _ in event_db_ids)
    summaries = query_rows_bounded(
        f"""
        select
            e.*, s.hostname as server,
            provider.value as provider_name,
            channel.value as channel,
            computer.value as computer,
            keywords.value as keywords,
            subject_domain.value as subject_domain_name,
            target_domain.value as target_domain_name,
            facts.process_name, facts.process_id, facts.target_server_name,
            facts.service_name, facts.task_name, facts.task_action,
            facts.task_author, facts.run_as, facts.logon_type,
            facts.result_code, facts.object_name, facts.share_name,
            facts.message_sample
        from events_v2_core e
        join servers s on s.id = e.server_id
        left join storage_v2_provider provider on provider.id = e.provider_id
        join storage_v2_channel channel on channel.id = e.channel_id
        left join storage_v2_computer computer on computer.id = e.computer_id
        left join storage_v2_keywords keywords on keywords.id = e.keywords_id
        left join storage_v2_domain_name subject_domain on subject_domain.id = e.subject_domain_id
        left join storage_v2_domain_name target_domain on target_domain.id = e.target_domain_id
        left join event_facts_v2 facts on facts.event_id = e.id
        where e.id in ({placeholders})
        """,
        tuple(event_db_ids),
        statement_timeout_ms=3000,
    )
    history_primary = primary_read_enabled()
    if not summaries and not history_primary:
        return {}

    from server.sli.core.postgres_runtime_pipeline import connect

    summary_by_id = {int(row["id"]): row for row in summaries}
    payload_by_id: dict[int, dict[str, Any]] = {}
    degradable_ids: set[int] = set()
    history_ids = {
        event_id for event_id in event_db_ids
        if history_primary and (
            event_id not in summary_by_id or _history_is_cold(summary_by_id[event_id])
        )
    }
    if history_ids:
        port = configured_read_port()
        if port is None:
            raise RuntimeError("history ClickHouse port missing")
        try:
            history = read_published_events_many(port, list(history_ids))
        except OSError as exc:
            # History store unreachable: events with a PostgreSQL core are shown
            # from it; an event without a core cannot be shown at all.
            if any(event_id not in summary_by_id for event_id in history_ids):
                raise
            log_event(
                "storage_v2", "event_detail_history_unavailable",
                "History store unreachable; batch served from the verified core without source records.",
                count=len(history_ids), error_type=type(exc).__name__,
            )
            history = {}
            degradable_ids |= history_ids
        server_ids: set[int] = set()
        for event_id, payload in history.items():
            summary = summary_by_id.get(event_id)
            if summary is not None:
                StorageV2RuntimeReader._verify_core_identity(summary, payload)
            elif not _history_is_cold(payload):
                raise ArchiveIntegrityError("hot event absent from PostgreSQL")
            server_ids.add(int(payload["server_id"]))
        server_rows = query_rows_bounded(
            f"select id,hostname from servers where id in ({','.join('?' for _ in server_ids)})",
            tuple(sorted(server_ids)), statement_timeout_ms=3000,
        ) if server_ids else []
        names = {int(row["id"]): row["hostname"] for row in server_rows}
        if set(names) != server_ids:
            raise ArchiveIntegrityError("historical event refers to an unknown server")
        for event_id, payload in history.items():
            payload["server"] = names[int(payload["server_id"])]
            payload.pop("_history_batch_sha256", None)
            payload_by_id[event_id] = payload
    hot_ids = set(summary_by_id) - history_ids
    if hot_ids:
        manifest = PostgresArchiveManifestStore(connect)
        blocks = manifest.find_published_many(
            "event", sorted(hot_ids), MAX_BATCH_ARCHIVE_BLOCKS + 1,
        )
        if len(blocks) > MAX_BATCH_ARCHIVE_BLOCKS:
            raise ArchiveIntegrityError("event archive hydration exceeds bounded block limit")
        archive = ArchiveReader(manifest)
        for block in blocks:
            try:
                block_rows = list(archive.read_block_rows(block))
            except (OSError, ArchiveObjectUnavailableError) as exc:
                # Block absent/unreachable or its path refused: leave its events
                # to the core fallback below. Hash/identity mismatches still raise.
                log_event(
                    "storage_v2", "event_detail_archive_unavailable",
                    "Archive block unavailable; batch served from the verified core without source records.",
                    error_type=type(exc).__name__,
                )
                degradable_ids |= hot_ids
                continue
            for archive_row in block_rows:
                candidate = int(archive_row.get("id") or 0)
                if candidate not in hot_ids:
                    continue
                if candidate in payload_by_id:
                    raise ArchiveIntegrityError(f"event archive contains duplicate event {candidate}")
                summary = summary_by_id[candidate]
                StorageV2RuntimeReader._verify_core_identity(summary, archive_row)
                payload = dict(archive_row)
                payload["server"] = summary["server"]
                payload_by_id[candidate] = payload

    for event_id in sorted((degradable_ids & set(summary_by_id)) - payload_by_id.keys()):
        payload_by_id[event_id] = {**dict(summary_by_id[event_id]), "source_payload_state": "archive_unavailable"}
    absent = sorted((set(event_db_ids) if history_primary else set(summary_by_id)) - payload_by_id.keys())
    if absent:
        raise ArchiveIntegrityError(
            "published event payload is missing for V2 event IDs: "
            + ",".join(str(value) for value in absent)
        )
    from server.sli.semantic.account_watch_projection import attach_event_priorities

    payload_by_id = {int(row["id"]): row for row in attach_event_priorities(list(payload_by_id.values()))}
    return {
        event_id: _normalize_event_detail_row(payload)
        for event_id, payload in payload_by_id.items()
    }


def _history_is_cold(summary: dict[str, Any]) -> bool:
    cutoff = datetime.now(timezone.utc) - timedelta(days=load_storage_policy().db_retention_days)
    return parse_utc_timestamp(summary["time_created_utc"]) < cutoff


def _history_payload(event_db_id: int, summary: dict[str, Any] | None) -> dict[str, Any]:
    port = configured_read_port()
    if port is None:
        raise RuntimeError("history ClickHouse port missing")
    payload = read_published_event(port, event_db_id)
    if summary is not None:
        StorageV2RuntimeReader._verify_core_identity(summary, payload)
    elif not _history_is_cold(payload):
        raise ArchiveIntegrityError("hot event absent from PostgreSQL")
    server_row = query_rows(
        "select hostname as server from servers where id = ?",
        (payload["server_id"],),
    )
    if not server_row:
        raise ArchiveIntegrityError("historical event refers to an unknown server")
    payload["server"] = server_row[0]["server"]
    return payload


def _get_v2_event_detail_by_id(
    filters: dict[str, Any],
    *,
    authorization: CutoverAuthorization | None = None,
) -> dict[str, Any]:
    """Hydrate one explicitly addressed event through the verified V2 archive.

    A sealed V2 route permits only its bounded exact-ID detail path.  The
    route emitted by V2 search therefore never opens a compact V2 row through
    an unverified V1 fallback, including when archive hydration fails.
    """
    event_db_id = filters.get("event_db_id")
    if not event_db_id or not _v2_detail_route_selected(authorization):
        raise ValueError("storage_v2_detail_requires_exact_event_id")
    try:
        from server.sli.core.postgres_runtime_pipeline import connect

        if primary_read_enabled():
            summary = PostgresStorageV2ReadStore(connect).get_event_summary(int(event_db_id))
            if summary is None or _history_is_cold(dict(summary)):
                try:
                    return _history_payload(int(event_db_id), dict(summary) if summary else None)
                except OSError as exc:
                    # History store unreachable (connection refused/timeout):
                    # with a verified PostgreSQL core, show it and say that
                    # the source record is unavailable instead of a 500.
                    if summary is None:
                        raise
                    log_event(
                        "storage_v2",
                        "event_detail_history_unavailable",
                        "History store unreachable; event detail served from the verified core without the source record.",
                        event_db_id=event_db_id,
                        error_type=type(exc).__name__,
                    )
                    payload = {**dict(summary), "source_payload_state": "archive_unavailable"}
                    server_row = query_rows(
                        "select hostname as server from servers where id = ?",
                        (payload["server_id"],),
                    )
                    if not server_row:
                        raise ArchiveIntegrityError("V2 event refers to an unknown server") from exc
                    payload["server"] = server_row[0]["server"]
                    return payload

        reader = StorageV2RuntimeReader(
            PostgresStorageV2ReadStore(connect),
            ArchiveReader(
                PostgresArchiveManifestStore(connect),
            ),
        )
        try:
            payload = dict(reader.event_details(int(event_db_id)))
        except (FileNotFoundError, ArchiveObjectUnavailableError):
            # The archive block is absent or its path is refused (not altered): show the verified
            # PostgreSQL core and facts, and say that the source record is
            # unavailable. An integrity mismatch still fails closed below.
            payload = {**dict(reader.event_summary(int(event_db_id))), "source_payload_state": "archive_unavailable"}
            log_event(
                "storage_v2",
                "event_detail_archive_unavailable",
                "Archive block missing; event detail served from the verified V2 core without the source record.",
                event_db_id=event_db_id,
            )
        server_row = query_rows(
            "select hostname as server from servers where id = ?",
            (payload["server_id"],),
        )
        if not server_row:
            raise ArchiveIntegrityError("V2 event refers to an unknown server")
        payload["server"] = server_row[0]["server"]
        return payload
    except (ArchiveIntegrityError, KeyError, OSError, ValueError) as exc:
        log_event(
            "storage_v2",
            "event_detail_v2_failed",
            "Verified V2 detail hydration failed; V1 fallback is forbidden.",
            event_db_id=event_db_id,
            error_type=type(exc).__name__,
        )
        raise


def _v2_detail_route_selected(
    authorization: CutoverAuthorization | None = None,
    consumer: str = StorageRouteConsumer.EVENT_DETAILS,
) -> bool:
    """Storage V2 is the only route (plan 6.5); reject bad authority or non-PostgreSQL."""
    resolve_storage_route(authorization=authorization, consumer=consumer)
    if not is_postgres_runtime_db():
        raise ValueError("storage_v2_route_requires_postgres")
    return True


def render_event_detail_report(data: dict[str, Any]) -> str:
    filters = data.get("filters") or {}
    items = data.get("items") or []
    total = int(data.get("total") or 0)
    title = _detail_title(filters)
    if len(items) == 1:
        return _render_single_event_story(items[0], filters=filters, total=total, title=title)
    rows_html = _detail_rows(items)
    if not rows_html:
        rows_html = '<tr><td colspan="10" class="muted">События по выбранному фильтру не найдены.</td></tr>'
    returned = len(items)
    shown = f"показано {returned} из {total}"
    reverse_order = "asc" if filters.get("order") == "desc" else "desc"
    reverse_url = _replace_query_order(filters, reverse_order)
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
      <div class="eyebrow">Проверка события</div><span class="sr-only">Event drill-down UTC from</span>
      <h1>{_e(title)}</h1>
      <p class="subtitle">Список событий для проверки. Откройте конкретную запись, чтобы увидеть понятную карточку: кто выполнил действие, на что оно повлияло и что проверить дальше.</p>
      <div class="pillrow">
        {_pill("Event ID", _event_ids_label(filters))}
        {_pill("Журнал", channel_label(filters.get("channel"), with_original=True) if filters.get("channel") else "любой")}
        {_pill("Серверы", ", ".join(filters.get("servers") or []) or "все")}
        {_pill("UTC с", format_event_time(filters.get("time_from")) if filters.get("time_from") else "не задано")}
        {_pill("UTC по", format_event_time(filters.get("time_to")) if filters.get("time_to") else "не задано")}
        {_pill("Порядок", "старые → новые" if filters.get("order") == "asc" else "новые → старые")}
        {_pill("Строк", shown)}
        {_pill("Учетная запись", filters.get("user") or "любая")}
        {_pill("IP", filters.get("ip") or "любой")}
        {_pill("LogonId", filters.get("logon_id") or "любой")}
      </div>
    </div>
  </header>

  <section>
    <div class="section-title">
      <div>
        <h2>Найденные события</h2>
        <p class="muted">Технические поля доступны в каждой строке, но не меняют данные в AD или на серверах.</p>
      </div>
      <div class="toolbar">
        <a class="button" href="{_e(reverse_url)}">Сменить порядок</a>
        <a class="button" href="/">На главную</a>
      </div>
    </div>
    <table>
      <thead>
        <tr>
          <th>UTC</th>
          <th>Локальное время</th>
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


def _normalize_event_detail_row(row: dict[str, Any]) -> dict[str, Any]:
    event_data = _parse_json_object(row.get("event_data_json"))
    message = str(row.get("message_text") or "").strip()
    details = _event_data_summary(event_data)
    return {
        **row,
        "subject": _principal(row.get("subject_domain_name"), row.get("subject_user_name"), row.get("subject_user_sid")),
        "target": _principal(row.get("target_domain_name"), row.get("target_user_name"), row.get("target_user_sid")),
        "source": _source_hint(row),
        "event_data": event_data,
        "event_data_summary": details,
        "time_created_utc_display": format_event_time(row.get("time_created_utc")),
        "time_created_local_display": format_event_time(row.get("time_created_local"), suffix="") if row.get("time_created_local") else "—",
        "message_preview": _shorten(message, 240),
        "message_text": message,
        "investigation_links": _investigation_links({**row, "event_data": event_data}),
    }


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


def _principal(domain: Any, name: Any, sid: Any) -> str:
    name_s = str(name or "").strip()
    domain_s = str(domain or "").strip()
    sid_s = str(sid or "").strip()
    if name_s and domain_s:
        return f"{domain_s}\\{name_s}"
    if name_s:
        return name_s
    if sid_s:
        return sid_s
    return "—"


def _source_hint(row: dict[str, Any]) -> str:
    values = [row.get("ip_address"), row.get("workstation_name"), row.get("computer")]
    cleaned = [str(value).strip() for value in values if str(value or "").strip()]
    return " / ".join(cleaned) if cleaned else "—"


def _event_data_summary(event_data: dict[str, Any]) -> str:
    priority = [
        "SubjectUserName",
        "SubjectDomainName",
        "TargetUserName",
        "TargetDomainName",
        "IpAddress",
        "WorkstationName",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "ProcessName",
        "TaskName",
        "ServiceName",
        "MemberName",
        "GroupName",
        "TargetServerName",
        "Status",
        "SubStatus",
    ]
    parts = []
    for key in priority:
        value = event_data.get(key)
        if value not in (None, "", "-"):
            parts.append(f"{key}={value}")
    if not parts:
        for key, value in list(event_data.items())[:12]:
            if value not in (None, ""):
                parts.append(f"{key}={value}")
    return "; ".join(parts) if parts else "—"


def _detail_rows(items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        expired = item.get("source_payload_state") == "expired"
        event_data_pretty = json.dumps(
            (item.get("retained_facts") or {}) if expired else (item.get("event_data") or {}),
            ensure_ascii=False, indent=2,
        )
        fields_label = "Сохранённые факты" if expired else "Поля события"
        message_label = "Исходное сообщение недоступно" if expired else "Сообщение Windows"
        message_body = "Исходный текст удалён по сроку хранения (7 суток)." if expired else item.get("message_text")
        rows.append(
            f"""<tr>
<td class="mono" title="{_e(item.get('time_created_utc'))}">{_e(item.get('time_created_utc_display'))}</td>
<td class="mono" title="{_e(item.get('time_created_local'))}">{_e(item.get('time_created_local_display'))}</td>
<td>{_e(item.get('server'))}</td>
<td>{_e(channel_label(item.get('channel'), with_original=True))}</td>
<td class="mono">{_e(event_id_label(item.get('event_id')))}</td>
<td class="mono">{_e(item.get('event_record_id'))}</td>
<td>{_e(item.get('subject'))}</td>
<td>{_e(item.get('target'))}</td>
<td>{_e(item.get('source'))}</td>
<td>
  <div class="summary">{_e(item.get('event_data_summary'))}</div>
  {_investigation_links_html(item.get("investigation_links") or [])}
  <details><summary>{_e(fields_label)}</summary><pre>{_e(event_data_pretty)}</pre></details>
  <details><summary>{_e(message_label)}</summary><pre>{_e(message_body)}</pre></details>
</td>
</tr>"""
        )
    return "".join(rows)


def _investigation_links(row: dict[str, Any], *, related_event_ids: list[int] | None = None) -> list[dict[str, str]]:
    server = str(row.get("server") or "").strip()
    channel = str(row.get("channel") or "").strip()
    event_time = str(row.get("time_created_utc") or "").strip()
    subject = str(row.get("subject_user_name") or "").strip()
    target = str(row.get("target_user_name") or "").strip()
    user = target if target and target != "-" else subject
    ip = str(row.get("ip_address") or "").strip()
    logon_id = str(row.get("logon_id") or "").strip()
    links: list[dict[str, str]] = []
    if user:
        links.append({"label": "Цепочка учетной записи", "url": "/reports/account-timeline.html?" + urlencode({"q": user, "limit": 500, "order": "asc"})})
        links.append({"label": "Тот же пользователь", "url": make_event_detail_url(user=user, channel="Security", servers=[server] if server else [], limit=300)})
        links.append({"label": "Сущность: учетная запись", "url": "/reports/entity-details.html?" + urlencode({"q": user, "limit": 300})})
    if ip and ip not in {"-", "::1", "127.0.0.1"}:
        links.append({"label": "Тот же IP", "url": make_event_detail_url(ip=ip, servers=[server] if server else [], limit=300)})
        links.append({"label": "Сущность: IP", "url": "/reports/entity-details.html?" + urlencode({"q": ip, "role": "source", "limit": 300})})
    if logon_id and logon_id not in {"-", "0x0"}:
        links.append({"label": "Тот же LogonId", "url": make_event_detail_url(logon_id=logon_id, servers=[server] if server else [], limit=300, order="desc")})
        links.append({"label": "Сущность: сеанс", "url": "/reports/entity-details.html?" + urlencode({"q": logon_id, "role": "context", "limit": 300})})
    window = _time_window(event_time, minutes=15)
    if window:
        links.append({"label": "Соседние события ±15 минут", "url": make_event_detail_url(servers=[server] if server else [], limit=300, time_from=window[0], time_to=window[1], order="desc")})
    normalizer = resolve_source_normalizer(
        channel,
        row.get("provider_name"),
        str(row.get("event_id") or ""),
    )
    scheduled_task_ids = (
        normalizer.event_ids_for_analysis_family("scheduled_task")
        if normalizer
        else ()
    )
    try:
        current_event_id = int(row.get("event_id") or 0)
    except (TypeError, ValueError):
        current_event_id = 0
    if (
        server
        and related_event_ids
        and current_event_id in scheduled_task_ids
    ):
        links.append(
            {
                "label": "Задания планировщика на этом DC",
                "url": make_event_detail_url(
                    event_ids=related_event_ids,
                    servers=[server],
                    limit=300,
                    order="desc",
                ),
            }
        )
    task_name = str((row.get("event_data") or {}).get("TaskName") or "").strip()
    if task_name:
        window = _time_window(event_time, minutes=60)
        params: dict[str, Any] = {"q": task_name, "channel": channel, "limit": 200, "order": "asc"}
        if server:
            params["server"] = server
        if window:
            params["time_from"], params["time_to"] = window
        links.append({"label": "Изменения этого задания за период", "url": "/reports/search-deep.html?" + urlencode(params)})
    if related_event_ids:
        links.append({"label": "Связанные типы событий", "url": make_event_detail_url(event_ids=related_event_ids, servers=[server] if server else [], limit=300, order="desc")})
    return links


def _time_window(value: str, *, minutes: int) -> tuple[str, str] | None:
    if not value:
        return None
    try:
        parsed = datetime_from_iso(value)
    except ValueError:
        return None
    return ((parsed - timedelta(minutes=minutes)).isoformat(), (parsed + timedelta(minutes=minutes)).isoformat())


def datetime_from_iso(value: str):
    from datetime import datetime, timezone
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _investigation_links_html(links: list[dict[str, str]]) -> str:
    if not links:
        return ""
    body = "".join(f'<a class="button small" href="{_e(item.get("url"))}">{_e(item.get("label"))}</a>' for item in links)
    return f'<div class="investigation-links">{body}</div>'


def _render_single_event_story(item: dict[str, Any], *, filters: dict[str, Any], total: int, title: str) -> str:
    """Render one event as an analyst-friendly fact card, not a one-row table."""
    event_id = int(item.get("event_id") or 0)
    card = build_event_card(item)
    evidence_id = f"{item.get('server') or 'unknown'}-{item.get('channel') or 'event'}-{item.get('event_record_id') or item.get('id') or '—'}"
    expired = item.get("source_payload_state") == "expired"
    event_data_pretty = json.dumps(
        (item.get("retained_facts") or {}) if expired else (item.get("event_data") or {}),
        ensure_ascii=False, indent=2,
    )
    fields_label = "Сохранённые факты" if expired else "Поля события"
    message_label = "Исходное сообщение недоступно" if expired else "Сообщение Windows"
    message_body = "Исходный текст удалён по сроку хранения (7 суток)." if expired else item.get("message_text")
    checks_html = "".join(f"<li>{_e(check)}</li>" for check in card["checks"])
    facts_html = "".join(f"<div><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>" for label, value in card["facts"])
    links = _investigation_links(item, related_event_ids=card.get("related_event_ids") or [])
    links_html = _investigation_links_html(links)
    catalog_note = "" if card["known"] else '<div class="badcallout"><strong>Событие пока не расшифровано каталогом.</strong> Технические данные ниже показаны без предположений.</div>'
    technical_reason = (f'<p class="muted">{_e(card["technical_reason"])}</p>' if card.get("technical_reason") else "")
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(event_id_label(event_id))}</title>{_style()}</head><body>{report_controls()}
<main class="wrap event-story-wrap">
  <div class="event-breadcrumb"><a href="/">Главное</a> <span>→</span> <a href="/reports/search.html">События</a> <span>→</span> запись { _e(item.get('event_record_id') or item.get('id')) }</div>
  <header class="event-story-head">
    <div><div class="eyebrow">Детали события</div><h1>{_e(card['title'])}</h1>
    <p class="subtitle">{_e(item.get('channel') or 'Журнал')} · {_e(item.get('server') or 'сервер не указан')} · {_e(item.get('time_created_local_display') or item.get('time_created_utc_display'))}</p></div>
    <div><span class="risk-badge {card['risk_class']}">{_e(card['risk'])}</span><div class="muted small-text">Уверенность оценки: {_e(card.get('assessment_confidence'))}</div></div>
  </header>
  <div class="event-story-grid">
    <section class="event-facts"><div class="eyebrow">Кто, что и для кого сделал</div>
      <dl class="event-fact-list">{facts_html}</dl>
      <div class="event-summary"><strong>{_e(card['summary'])}</strong></div>
    </section>
    <section class="event-checks"><div class="eyebrow">Что проверить</div><ol>{checks_html}</ol><div class="event-evidence"><span>Идентификатор записи</span><strong>{_e(evidence_id)}</strong><span>Event ID: {_e(event_id)}</span></div></section>
  </div>
  {catalog_note}
  <section><div class="section-title"><div><h2>Следующие действия</h2><p class="muted">Переходы открываются в этом же окне и уточняют контекст без изменения источников.</p></div></div>{links_html}</section>
  <section><div class="section-title"><div><h2>Технические данные</h2><p class="muted">Нужны для проверки первичного события, если краткой карточки недостаточно.</p></div></div>
  {technical_reason}<details><summary>{_e(fields_label)}</summary><pre>{_e(event_data_pretty)}</pre></details><details><summary>{_e(message_label)}</summary><pre>{_e(message_body)}</pre></details></section>
</main></body></html>"""


def _detail_title(filters: dict[str, Any]) -> str:
    parts = ["Детали событий"]
    if filters.get("event_ids"):
        parts.append("Event ID " + ", ".join(str(value) for value in filters["event_ids"]))
    if filters.get("channel"):
        parts.append(str(filters["channel"]))
    if filters.get("servers"):
        parts.append(", ".join(filters["servers"]))
    return " · ".join(parts)


def _event_ids_label(filters: dict[str, Any]) -> str:
    values = filters.get("event_ids") or []
    return ", ".join(str(value) for value in values) if values else "любой"


def _replace_query_order(filters: dict[str, Any], order: str) -> str:
    return make_event_detail_url(
        event_ids=filters.get("event_ids") or [],
        channel=filters.get("channel"),
        servers=filters.get("servers") or [],
        limit=filters.get("limit") or DEFAULT_DETAIL_LIMIT,
        time_from=filters.get("time_from"),
        time_to=filters.get("time_to"),
        order=order,
        user=filters.get("user"),
        ip=filters.get("ip"),
        logon_id=filters.get("logon_id"),
    )


_clean_int_list = clean_int_list


def _unique_ints(values: list[int]) -> list[int]:
    output = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


def _clean_time_filter(value: str | None) -> str | None:
    cleaned = str(value or "").strip()
    return cleaned or None


def _shorten(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


_pill = format_html_pill
_e = format_html_escape



def _style() -> str:
    return report_style(extra_css="""
.event-story-wrap{max-width:1120px}.event-breadcrumb{display:flex;gap:8px;align-items:center;margin:2px 0 14px;color:var(--muted);font-size:13px}.event-story-head{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.event-story-head h1{font-size:38px;letter-spacing:-.03em}.event-story-grid{display:grid;grid-template-columns:1.45fr .75fr;gap:16px;margin-top:18px}.event-facts,.event-checks{border:1px solid var(--line);border-radius:18px;background:var(--panel);padding:22px;box-shadow:var(--shadow-soft)}.event-fact-list{margin:13px 0 18px}.event-fact-list div{display:grid;grid-template-columns:170px 1fr;gap:14px;padding:8px 0;border-bottom:1px solid var(--line)}.event-fact-list div:last-child{border-bottom:0}.event-fact-list dt{color:var(--muted)}.event-fact-list dd{margin:0;font-weight:800;word-break:break-word}.event-summary{border-left:5px solid var(--blue);border-radius:8px;background:color-mix(in srgb,var(--blue) 9%,var(--panel));padding:13px 15px}.event-checks ol{margin:14px 0 26px;padding-left:22px}.event-checks li{margin:0 0 14px;padding-left:4px}.event-evidence{display:grid;gap:5px;border-radius:13px;background:#111827;color:#dce7f4;padding:15px;font-size:12px}.event-evidence span{color:#b6c5d9}.event-evidence strong{font-size:14px;word-break:break-word}@media(max-width:720px){.event-story-head{display:grid}.event-story-head h1{font-size:30px}.event-story-grid{grid-template-columns:1fr}.event-fact-list div{grid-template-columns:1fr;gap:3px}.event-breadcrumb{overflow:auto;white-space:nowrap}}
""")
