"""«Журнал событий» (events.explorer) on the v2 framework.

The published v4 report keeps its dataset, field policy, bounds and export
policy; this declaration presents its rows uniformly. Exact-evidence rights
gate catalogue titles; no risk score or missing participant is invented.
"""

from __future__ import annotations

from typing import Any

from server.sli.access.access_control_v4 import capability_decision_for_resource_groups, report_action_decision
from server.sli.core.database import QueryTimeoutError, query_rows_bounded
from server.sli.core.messages import message
from server.sli.events.event_catalog import lookup_event_catalog
from server.sli.reporting.ui_labels import event_id_label

from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    result,
    source_state,
)
from server.sli.reporting.reporting_v4 import (
    REPORT_LIMIT_MAX,
    execute_report,
    export_report_csv_document,
)

REPORT_KEY = "events.journal"
ACCESS_KEY = "events.explorer"
VIEWS = (
    ("all", "Все события"), ("attention", "Требуют внимания"), ("authentication", "Входы и аутентификация"),
    ("accounts", "Учётные записи"), ("tasks", "Задания и службы"),
)


def _filters(context: QueryContext, *, cursor: bool) -> dict[str, Any]:
    params = context.params
    period = params["period"]
    filters: dict[str, Any] = {"time_from": period["from_utc"], "time_to": period["to_utc"]}
    if params.get("view") and params["view"] != "all":
        filters["view"] = params["view"]
    for key, target in (("q", "q"), ("server", "server")):
        if params.get(key):
            filters[target] = params[key]
    if cursor and context.cursor:
        filters["cursor"] = context.cursor
    return filters


def _source_titles(items: list[dict[str, Any]], access: dict[str, Any]) -> dict[tuple, dict[str, Any]]:
    """Derive titles only for this authorized page, without exposing source fields.

    ID is a global primary key. All three visible dependencies must occur in
    the same engine-projected row, never unioned across grant branches. The
    second read cannot change selection, paging, or recover a hidden field.
    """
    identities = {(row["id"], row["event_id"], row["channel"]) for row in items
                  if type(row.get("id")) is int and row["id"] > 0
                  and type(row.get("event_id")) is int and isinstance(row.get("channel"), str)
                  and row["channel"].strip()}
    if not identities:
        return {}
    ids = sorted({identity[0] for identity in identities})[:REPORT_LIMIT_MAX]
    try:
        sources = query_rows_bounded(
            """select event.id,event.event_id,event.server_id,event.domain_id,
                      channel.value as channel,provider.value as provider_name
               from events_v2_core event
               join storage_v2_channel channel on channel.id=event.channel_id
               left join storage_v2_provider provider on provider.id=event.provider_id
               where event.id=any(?) limit ?""", (ids, len(ids)), statement_timeout_ms=3000,
        )
    except QueryTimeoutError:
        return {}
    titles = {}
    for source in sources:
        identity = (source.get("id"), source.get("event_id"), source.get("channel"))
        if identity not in identities or any(type(source.get(key)) is not int or source[key] <= 0 for key in ("server_id", "domain_id")):
            continue
        resources = [[{"kind": "server", "id": source["server_id"]},
                      {"kind": "domain", "id": source["domain_id"]},
                      {"kind": "channel", "value": source["channel"]}]]
        if not report_action_decision(access, ACCESS_KEY, "view", resource_groups=resources,
                                      required_field_categories=("security", "technical", "raw_evidence"))["allowed"]:
            continue
        if not all(capability_decision_for_resource_groups(access, capability, resource_groups=resources)["allowed"]
                   for capability in ("field.security", "field.technical", "field.raw_evidence", "evidence.exact")):
            continue
        provider = str(source.get("provider_name") or "").strip()
        if not provider:
            continue
        entry = lookup_event_catalog(source["event_id"], source["channel"], provider)
        if not entry or str(entry.get("channel") or "").strip().casefold() != source["channel"].strip().casefold() or str(entry.get("provider_name") or "").strip().casefold() != provider.casefold():
            continue
        # Translations come from the existing source normalizer/catalogue, not
        # a second ID dictionary. Do not publish even the provider in a code.
        labels = {lang: event_id_label(source["event_id"], channel=source["channel"],
                                      provider_name=provider, prefix=False, lang=lang)
                  for lang in ("ru", "en")}
        titles[identity] = message("events.catalog_title", labels)
    return titles


def _row(item: dict[str, Any], titles: dict[tuple, dict[str, Any]] | None = None) -> dict[str, Any]:
    row = dict(item)
    title = (titles or {}).get((item.get("id"), item.get("event_id"), item.get("channel"))) or message("events.unknown_type")
    row["title_text"] = title["text"]
    row["presentation_messages"] = {"title_text": title}
    target = str(item.get("target_user_name") or "").strip()
    actor = str(item.get("subject_user_name") or "").strip()
    target = "" if target in {"-", "—"} else target
    actor = "" if actor in {"-", "—"} else actor
    row["participant"] = target or actor or message("events.participant_unknown")["text"]
    if not target and not actor:
        row["presentation_messages"]["participant"] = message("events.participant_unknown")
    row["on_behalf"] = actor if actor and actor != (target or actor) else None
    return row


def _query(context: QueryContext) -> dict[str, Any]:
    raw = execute_report(ACCESS_KEY, None, limit=min(context.limit, REPORT_LIMIT_MAX), query_filters=_filters(context, cursor=True), access=context.access)
    items = raw.get("items") or []
    titles = _source_titles(items, context.access)
    rows = [_row(item, titles) for item in items]
    state = source_state(raw.get("state"))
    if state == "ok" and not rows:
        state = "empty"
    period = context.params["period"]
    return result(
        REPORT, state=state, items=rows, has_more=bool(raw.get("has_more")), next_cursor=raw.get("next_cursor"),
        window={"from_utc": period["from_utc"], "to_utc_exclusive": period["to_utc"]},
        coverage=raw.get("coverage") or {},
        limitations=[{"code": "no_risk_in_slice", "text": "Оценка риска не входит в этот срез. Название показывается только при точном совпадении источника и разрешённом доступе к доказательству; неизвестный участник не восстанавливается."}],
    )


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    document = export_report_csv_document(ACCESS_KEY, None, query_filters=_filters(context, cursor=False), access=context.access)
    return str(document["csv"]), {"rows": int(document["row_count"]), "truncated": bool(document["truncated"])}


REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Security investigator",
        question="Какие сохранённые события соответствуют выбранному срезу расследования?",
        action="Open exact evidence and pivot to event or entity history.",
        scope="Server-granted event resources and domains, selected filters and bounded period.",
        exclusions="A retained event list is not a proof of complete collection or absence of activity.",
        sources=(
            "Canonical: retained source-native events in the granted resource scope.",
            "Supplemental: retained event details and entity history for authorized evidence pivots.",
        ),
        freshness_expectation="Последнее подтверждение источников событий в выбранном окне; время ответа не заменяет его.",
        rights="events.explorer view grant; engine-enforced event resource scope and field policy; export separately granted.",
        field_classes=(
            "security",
            "technical",
            "raw_evidence",
        ),
        coverage="Expected granted event sources and channels over the selected window.",
        completeness="Source-confirmed retained channel intervals divided by expected source-channel-window duration; rows and successful queries are not the numerator. Unknown when source continuity is not proven.",
        denominator="Ожидаемые источники и каналы событий × выбранный период; число строк не измеряет полноту.",
        retention="Raw events follow the configured bounded retention; derived history may survive without full event text.",
        provenance="Exact event ID, native source, domain, channel and source timestamp; expired evidence remains explicitly unavailable.",
        primary_archetype="timeline",
        product_archetype="investigation-evidence",
        deterministic_policy="Published events.explorer filters, field policy and keyset paging; exact-source catalogue title requires exact-evidence rights; no risk is inferred.",
        result_limits="Published dataset window, page and export bounds apply; source continuity and raw-text retention are independent.",
        fallback="Preserve the published reader state and coverage; missing raw evidence cannot be reconstructed from derived history.",
        acceptance_lanes={
            "product_user": "Event slice answers the investigation question and links only authorized evidence.",
            "authorization": "events.explorer grants, fields and resource scope bound rows and export independently.",
            "deterministic_interpretation": "Filters and keyset order preserve the published dataset; no risk is invented.",
            "api_view_model": "State, rows, cursor and truncation preserve execute_report and export contracts.",
            "ui_honest_states": "Empty, denied, partial, stale and unavailable source states remain distinguishable.",
            "evidence_audit": "Native event identity and expired raw-text boundaries survive authorized evidence pivots.",
        },
    ),
    key=REPORT_KEY,
    section="investigation",
    title="Журнал событий",
    description="Сохранённые события назначенного среза с точными ID: из строки открывается исходное доказательство и история от этого события.",
    archetype="investigation-evidence",
    access=AccessRule(ACCESS_KEY, scope="delegated"),
    params=(
        Param.period(default="24h"),
        Param.choice("view", "Категория", VIEWS, default="all"),
        Param.text("q", "Поиск"),
        Param.text("server", "Источник"),
    ),
    columns=(
        Column("time", "Время", "datetime", path="time_created_utc"),
        Column("event", "Событие", path="title_text", link="/app/events/{id}"),
        Column("participant", "Участник"),
        Column("on_behalf", "От имени"),
        Column("channel", "Журнал"),
        Column("id", "ID в БД", "code", optional=True),
    ),
    query=_query,
    export_csv=_export,
    row_key="id",
    presets=(
        ("Сбои входа (подбор)", {"q": "4625", "view": "authentication"}),
        # 4672 (специальные привилегии) не входит в представление «Входы и аутентификация»:
        # с ним сценарий всегда возвращал пустой список.
        ("Входы администраторов", {"q": "4672", "view": "all"}),
        ("Изменение групп и прав", {"q": "4728", "view": "accounts"}),
        ("Создание учётных записей", {"q": "4720", "view": "accounts"}),
        ("Очистка журнала аудита", {"q": "1102", "view": "attention"}),
    ),
    row_links=(("Карточка события", "/app/events/{id}"),),
    default_limit=50,
    max_limit=REPORT_LIMIT_MAX,
)
