"""«Групповые политики» (ad.gpo.v2) on the v2 report framework (plan 5.3).

Inventory views load the latest collected snapshots for authorised domains.
The changes view reads compact confirmed history for the requested period.
Only the collection of the open tab is built (``QueryContext.tab``).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from server.sli.plugins.gpo.effective_access import analyze_access, linked_scopes, load_directory_graph
from server.sli.reporting.reporting_common import parse_utc, format_iso

from server.sli.reporting.v2.definition import (
    AccessRule,
    Column,
    Detail,
    Param,
    QueryContext,
    ReportDefinition,
    ReportIntent,
    View,
    csv_from_columns,
    result,
    source_state,
    sort_rows,
)
from server.sli.plugins.gpo.reports.gpo_v2_reporting import (
    build_gpo_v2_payload,
    filter_snapshot_view,
    load_authorized_snapshot_pair,
    quality_rows,
)
from server.sli.reports.ad_snapshot_change_reporting import change_view, query_history

REPORT_KEY = "ad.gpo.v2"
GPO_VIEWS = (("attention", "Подтверждённые отклонения"), ("unverified", "Непроверенные сведения"), ("assignment", "Вопросы назначения"), ("all", "Все политики"), ("linked", "Со связями"), ("unlinked", "Без связей"))
SIDES = (("computer", "Компьютер"), ("user", "Пользователь"))
SOURCE_STATUS = (("observed", "Наблюдалось"), ("partial", "Частично"), ("failed", "Ошибка"), ("access_denied", "Нет доступа"), ("parse_error", "Ошибка разбора"), ("not_evaluated", "Не оценивалось"))
COLLECTION_LIMIT = 2000


def _gpo_row(gpo: dict[str, Any]) -> dict[str, Any]:
    reasons = list(gpo.get("reasons") or [])
    confirmed = [reason for reason in reasons if reason["category"] == "deviation"]
    return {
        "id": gpo.get("id"),
        "guid": gpo.get("guid"),
        "display_name": gpo.get("display_name"),
        "gpo_status": gpo.get("gpo_status"),
        "link_count": len(gpo.get("link_ids") or []),
        "setting_count": len(gpo.get("setting_ids") or []),
        "permission_count": len(gpo.get("permission_ids") or []),
        "reason_count": len(confirmed),
        "reason_titles": ", ".join(str(reason.get("title")) for reason in confirmed) or None,
        "unverified_titles": ", ".join(reason["title"] for reason in reasons if reason["category"] == "unverified") or None,
        "assignment_titles": ", ".join(reason["title"] for reason in reasons if reason["category"] == "assignment") or None,
        "priority": reasons[0]["priority"] if reasons else "none",
        "next_step": reasons[0]["next"] if reasons else None,
        "modification_time": gpo.get("modification_time"),
        "creation_time": gpo.get("creation_time"),
        "owner": (gpo.get("owner") or {}).get("name"),
        "wmi_filter_id": gpo.get("wmi_filter_id"),
        "reasons": reasons,
    }


def _collection(snapshot: dict[str, Any], payload: dict[str, Any], tab: str | None, query: str) -> dict[str, list[dict[str, Any]]]:
    sources = {"scopes": "scopes", "settings": "settings", "permissions": "permissions", "wmi": "wmi"}
    if tab in sources:
        rows = filter_snapshot_view(snapshot, sources[tab], query=query, limit=10_000)["items"]
        if tab == "scopes":
            rows = [{**row, "link_count": len(row.get("direct_link_ids") or [])} for row in rows]
        if tab == "wmi":
            rows = [{**row, "used_by": len(row.get("used_by_gpo_ids") or [])} for row in rows]
        if tab == "permissions":
            rows = [{**row, "trustee": row.get("trustee_name") or row.get("trustee_sid")} for row in rows]
        return {tab: rows[:COLLECTION_LIMIT]}
    if tab in {"quality", "changes"}:
        rows = quality_rows(snapshot) if tab == "quality" else list((payload.get("comparison") or {}).get("items") or [])
        needle = query.strip().casefold()
        return {tab: [row for row in rows if not needle or needle in json.dumps(row, ensure_ascii=False, default=str).casefold()]}
    return {}


def _query(context: QueryContext) -> dict[str, Any]:
    if context.tab == "changes":
        return query_history(REPORT, context, ("gpo_v2",))
    pair = load_authorized_snapshot_pair(domain_ids=context.domain_ids)
    if pair.get("state") == "not_collected":
        return result(REPORT, state="not_collected", limitations=[{"code": "not_collected", "text": "Снимок групповых политик для разрешённых доменов ещё не собран."}])
    if not pair.get("current"):
        state = source_state(pair.get("state"))
        return result(REPORT, state=state if state in {"denied", "processing", "error"} else "error",
                      coverage={"reason": "gpo_snapshot_unavailable"})
    if context.tab in {"filtering", "delegation", "linked_scopes"}:
        return _effective_query(context, pair["current"])
    payload = build_gpo_v2_payload(pair)
    snapshot = payload["current"]
    query = str(context.params.get("q") or "")
    view = str(context.params.get("view") or "attention")
    listed = filter_snapshot_view(snapshot, view, query=query)
    counts = {key: filter_snapshot_view(snapshot, key)["total"] for key, _ in GPO_VIEWS}
    items = sort_rows(REPORT, [_gpo_row(gpo) for gpo in listed["items"]], context.sort, context.direction)
    boundaries = payload.get("boundaries") or {}
    limitations = []
    if boundaries.get("not_rsop"):
        limitations.append({"code": "not_rsop", "text": "Это состав политик домена, а не результирующая политика (RSoP) конкретного компьютера или пользователя."})
    if not boundaries.get("deletion_claim_allowed"):
        limitations.append({"code": "no_deletion_claims", "text": "Отсутствие объекта в снимке не доказывает его удаление."})
    if listed.get("state") == "not_evaluated":
        limitations.append({"code": "links_not_observed", "text": "Связи политик в этом снимке не наблюдались, поэтому «без связей» не оценивается."})
    if pair.get("state") == "partial":
        limitations.append({"code": "single_snapshot", "text": "Есть только один снимок: изменения между снимками пока не вычисляются."})
    collections = _collection(snapshot, payload, context.tab, query)
    for tab, rows in collections.items():
        if len(rows) >= COLLECTION_LIMIT:
            limitations.append({"code": f"{tab}_truncated", "text": f"Показаны первые {COLLECTION_LIMIT} строк; уточните поиск."})
    snapshot_state = str(snapshot.get("collection_status") or "")
    state = "empty" if not items and listed.get("state") != "not_evaluated" else "ok"
    if snapshot_state and snapshot_state not in {"complete", "completed"}:
        state = "partial"
    if listed.get("state") == "not_evaluated":
        state = "partial"
    if context.tab == "changes" and pair.get("state") == "partial":
        state = "partial"
    return result(
        REPORT, state=state, items=items, filtered_count=listed.get("total"),
        metrics=[
            {"key": key, "label": label, "value": counts[key], "tone": "warning" if key == "attention" and counts[key] else "accent" if key == "all" else "neutral", "filter": {"view": key}}
            for key, label in GPO_VIEWS
        ],
        coverage={"state": snapshot_state or "unknown", "observed_at_utc": snapshot.get("observed_at"), "snapshots": pair.get("state"),
                  "missing_sources": [key for key, value in (snapshot.get("source_states") or {}).items()
                                      if isinstance(value, dict) and value.get("status") not in {"observed", "no_record", "not_applicable"}]},
        collections=collections, limitations=limitations,
    )


def _effective_query(context: QueryContext, snapshot: dict) -> dict:
    query = str(context.params.get("q") or "").strip()
    needle = query.casefold()
    matched_gpos = [item for item in snapshot.get("gpos") or [] if needle and needle in
                    f"{item.get('display_name')} {item.get('id')} {item.get('guid')}".casefold()]
    if matched_gpos:
        ids = {item["id"] for item in matched_gpos}
        snapshot = {**snapshot, "gpos": matched_gpos, "links": [item for item in snapshot.get("links") or [] if item.get("gpo_id") in ids]}
    if context.tab == "linked_scopes":
        data = linked_scopes(snapshot, query=query)
    else:
        graph = load_directory_graph(snapshot, domain_ids=context.domain_ids)
        data = analyze_access(snapshot, graph, mode=context.tab, query=query)
    rows = [row for row in data["items"] if not needle or needle in json.dumps(row, ensure_ascii=False).casefold()]
    state = data["state"]
    if state == "ok" and not rows:
        state = "empty"
    if snapshot.get("collection_status") not in {"complete", "completed"}:
        state = "partial"
    observations = [parse_utc(snapshot.get("observed_at")), parse_utc((data["coverage"].get("graph") or {}).get("observed_at_utc"))]
    oldest = min((stamp for stamp in observations if stamp is not None), default=None)
    stale_since = oldest + timedelta(hours=36) if oldest else None
    if state in {"ok", "empty"} and stale_since and stale_since < datetime.now(timezone.utc):
        state = "stale"
    limitations = [{"code": "effective_boundary", "text": "Показаны права GPC по DACL и членству в снимке AD, а не RSoP. SYSVOL ACL, SIDHistory, токен входа, внешние группы, владелец и WMI на клиенте не проверяются; разрешение по ACL не доказывает применение или возможность изменения всей GPO."},
                   {"code": "effective_snapshots", "text": "Граф членства выбран в том же разрешённом домене не позднее снимка GPO. Даты источников могут различаться; отсутствие пути не доказывает отсутствие прав."},
                   {"code": "effective_links", "text": "Связи OU/домена показывают наследование, блокировку и принудительность. Связи сайта показаны напрямую: принадлежность компьютера сайту, конфликты настроек и WMI на клиенте не вычисляются."}]
    if data["coverage"].get("truncated"):
        limitations.append({"code": f"{context.tab}_truncated", "text": "Достигнут предел строк или шагов обхода; часть путей может отсутствовать."})
    return result(REPORT, state=state, items=[], collections={context.tab: rows},
                  limitations=limitations, coverage={**data["coverage"], "observed_at_utc": snapshot.get("observed_at"),
                                                     "stale_since_utc": format_iso(stale_since) if stale_since and state == "stale" else None,
                                                     "freshness_threshold_seconds": 36 * 3600,
                                                     "passport": "docs/GPO_REPORT_PASSPORT.md"})


def _export(context: QueryContext) -> tuple[str, dict[str, Any]]:
    data = _query(context)
    view = next((view for view in REPORT.views if view.key == context.tab), REPORT.views[0])
    rows = data["items"] if view.source == "items" else data["collections"].get(view.source, [])
    if data.get("state") == "error":
        raise ValueError("gpo_history_not_exportable")
    truncated = "history_truncated" in data.get("coverage", {}).get("reasons", []) or any(item["code"] == f"{view.key}_truncated" for item in data["limitations"])
    return csv_from_columns(view.columns or REPORT.columns, rows), {"rows": len(rows), "truncated": truncated}


_TABLE = View("table", "gpos", "Политики")
_OUTCOMES = {"allowed": "Разрешено DACL", "denied": "Не разрешено DACL", "unknown": "Не определено", "not_collected": "Не собиралось"}
_RIGHTS = {"apply": "Apply Group Policy", "edit": "Изменение настроек", "modify_permissions": "Изменение разрешений", "modify_owner": "Изменение владельца"}
_RISK = {"broad_edit": "Риск: широкая группа с правом изменения", "non_admin_group_edit": "Риск: группа вне административных SID",
         "direct_principal_edit": "Проверить: прямое делегирование субъекту", "unknown_trustee_edit": "Проверить: неизвестный доверитель", "admin_edit": "Административный доверитель", "none": "Нет правила риска"}
_ACCESS_COLUMNS = (
    Column("gpo", "Политика", path="gpo_name"), Column("principal", "Эффективный субъект"),
    Column("type", "Тип субъекта", "state", path="principal_type", labels={"ad_user": "Пользователь", "ad_computer": "Компьютер"}),
    Column("right", "Право", "state", labels=_RIGHTS), Column("outcome", "Результат DACL", "state", labels=_OUTCOMES),
    Column("path", "Путь членства → GPO ACE"), Column("trustee", "SID доверителя", "code", path="trustee_sid"),
    Column("inherited", "ACE унаследован", "boolean"), Column("graph_time", "Снимок членства", "datetime", path="graph_observed_at"),
    Column("wmi", "WMI-фильтр", "code", path="wmi_filter_id"),
)
REPORT = ReportDefinition(
    intent=ReportIntent(
        version=1,
        user_role="Group Policy reviewer",
        question="Какие групповые политики требуют ручной проверки в выбранном домене?",
        action="Inspect links, settings and permissions before a manual policy review decision.",
        scope="Latest GPO snapshot in server-authorized domains; optional previous snapshot for changes.",
        exclusions="Snapshot settings do not prove client application, compromise or organization compliance.",
        sources=(
            "Canonical: GPO governance snapshot, links, permissions and settings in granted domains.",
            "Supplemental: previous retained GPO snapshot for deterministic comparison.",
        ),
        freshness_expectation="Время последнего подтверждённого снимка GPO; отсутствие предыдущего снимка явно указано.",
        rights="ad.gpo.v2 view grant with identity_basic, technical, security and privilege in server domain scope; export separately granted.",
        field_classes=(
            "identity_basic",
            "technical",
            "security",
            "privilege",
        ),
        coverage="GPO object, link, setting and permission sections observed in the authorized domains.",
        completeness="Source-confirmed GPO objects/section pairs divided by expected objects/section pairs in the snapshot scope; missing links, settings or permissions remain unknown. No ratio without the expected population.",
        denominator="Ожидаемые GPO и разделы связей, настроек и прав в разрешённых доменах; частичный снимок не доказывает полный состав.",
        retention="Derived GPO facts follow the storage policy; changes require a retained comparison snapshot.",
        provenance="GPO entity, snapshot observation times and source-backed links, settings and permissions.",
        primary_archetype="list",
        product_archetype="investigation-evidence",
        risk={"status": "measured", "definition": "Existing broad_edit, non_admin_group_edit, direct_principal_edit and unknown_trustee_edit review rules; no organization risk score."},
        deterministic_policy="Compare retained GPO snapshots and bounded membership/DACL paths; effective rights and review-risk rules do not prove client application.",
        result_limits="Snapshot/history pages and graph traversal are bounded; freshness threshold is 36 hours; WMI and SYSVOL limits remain explicit.",
        fallback="Missing prior snapshot disables comparison; incomplete ACL or membership paths remain unknown; stale snapshot stays stale.",
        acceptance_lanes={
            "product_user": "Links, settings, permissions and changes support a manual GPO review.",
            "authorization": "ad.gpo.v2 grant and identity, technical, security and privilege scope constrain all views and export.",
            "deterministic_interpretation": "Snapshot comparison and DACL precedence preserve unknown paths and existing review-risk rules.",
            "api_view_model": "Collections and export preserve declared row caps, graph truncation and source times.",
            "ui_honest_states": "No previous snapshot, partial ACL, stale and unavailable history remain explicit.",
            "evidence_audit": "GPO identity, source ACE and membership paths link to the retained snapshot.",
        },
    ),
    key=REPORT_KEY,
    section="reports/policies",
    title="Групповые политики",
    description="Групповые политики домена по последнему снимку: что требует ручной проверки, связи, настройки, права и WMI-фильтры.",
    archetype="inventory-status",
    intent_ref="docs/GPO_REPORT_PASSPORT.md",
    access=AccessRule(REPORT_KEY, frozenset({"identity_basic", "technical", "security", "privilege"})),
    params=(
        Param.period(max_days=3650),
        Param.choice("view", "Политики", GPO_VIEWS, default="attention"),
        Param.text("q", "Поиск"),
    ),
    columns=(
        Column("name", "Политика", path="display_name", sortable=True),
        Column("status", "Состояние GPO", "state", path="gpo_status", labels={
            "AllSettingsEnabled": "Включена полностью", "AllSettingsDisabled": "Отключена полностью",
            "UserSettingsDisabled": "Пользовательская часть отключена", "ComputerSettingsDisabled": "Компьютерная часть отключена",
        }),
        Column("reasons", "Требует внимания", path="reason_titles"),
        Column("unverified", "Непроверенные сведения", path="unverified_titles"),
        Column("assignment", "Вопросы назначения", path="assignment_titles"),
        Column("priority", "Приоритет проверки", "state", labels={"high": "Высокий", "medium": "Проверить сведения", "low": "Уточнить назначение", "none": "Нет оснований проверки"}),
        Column("next_step", "Следующий шаг"),
        Column("links", "Связей", "number", path="link_count", sortable=True),
        Column("settings", "Настроек", "number", path="setting_count", sortable=True),
        Column("modified", "Изменена", "datetime", path="modification_time", sortable=True),
        Column("owner", "Владелец", path="owner", optional=True),
        Column("permissions", "Прав", "number", path="permission_count", optional=True),
        Column("created", "Создана", "datetime", path="creation_time", optional=True),
        Column("guid", "GUID", "code", path="guid", optional=True),
    ),
    views=(
        _TABLE,
        View("table", "filtering", "Эффективная фильтрация", source="filtering", columns=(*_ACCESS_COLUMNS, Column("read_aces", "ACE чтения", "list", path="read_ace_ids", optional=True)),
             note="Read и Apply Group Policy через вложенные security-группы; неизвестные данные не означают отсутствие прав."),
        View("table", "delegation", "Эффективное делегирование", source="delegation", columns=(*_ACCESS_COLUMNS, Column("risk", "Проверка делегирования", "state", labels=_RISK)),
             note="Изменение настроек, DACL и владельца через вложенные группы. Правило риска использует SID, а не название группы."),
        View("table", "linked_scopes", "Связи и наследование", source="linked_scopes", columns=(
            Column("gpo", "Политика", path="gpo_name"), Column("scope", "Область", path="scope_name"),
            Column("type", "Тип", "state", path="scope_type", labels={"domain": "Домен", "ou": "OU", "site": "Сайт"}),
            Column("enabled", "Связь включена", "boolean"), Column("enforced", "Принудительная", "boolean"),
            Column("inherited", "Унаследованная связь", "boolean"), Column("blocked", "Наследование заблокировано", "boolean", path="inheritance_blocked"),
            Column("outcome", "Состояние связи", "state", labels={"linked": "Связь действует", "blocked": "Заблокирована", "disabled": "Отключена", "unknown": "Не определено"}),
            Column("path", "Путь наследования"), Column("order", "Порядок", "number"),
            Column("wmi", "WMI-фильтр", path="wmi_name"), Column("wmi_id", "ID WMI", "code", path="wmi_filter_id"),
            Column("wmi_queries", "Запросы WMI", "list"),
            Column("wmi_state", "Состояние WMI", "state", labels={**dict(SOURCE_STATUS), "not_collected": "Не собиралось", "not_applicable": "Не задан", "no_record": "Не найден"}),
        )),
        change_view("Изменения GPO"),
        View("table", "scopes", "Области применения", source="scopes", columns=(
            Column("name", "Контейнер", path="name"), Column("type", "Тип", "state", path="scope_type", labels={"domain": "Домен", "ou": "OU", "site": "Сайт"}),
            Column("links", "Связей", "number", path="link_count"), Column("blocked", "Наследование заблокировано", "boolean", path="gpo_inheritance_blocked"),
            Column("path", "Путь", path="canonical_path"),
        )),
        View("table", "settings", "Настройки", source="settings", columns=(
            Column("gpo", "Политика", path="gpo_name"), Column("side", "Часть", "state", path="side", labels=dict(SIDES)),
            Column("category", "Категория", path="category"), Column("name", "Настройка", path="setting_name"),
            Column("value", "Значение", path="value_display"), Column("path", "Путь", path="path"),
        )),
        View("table", "permissions", "Права", source="permissions", columns=(
            Column("gpo", "Политика", path="gpo_name"), Column("trustee", "Кому", path="trustee"),
            Column("permission", "Право", path="permission"), Column("inherited", "Унаследовано", "boolean"),
        )),
        View("table", "wmi", "WMI-фильтры", source="wmi", columns=(
            Column("name", "Фильтр", path="name"), Column("used", "Используют политик", "number", path="used_by"),
            Column("author", "Автор", path="author"), Column("modified", "Изменён", "datetime", path="modification_time"),
        )),
        View("table", "quality", "Качество сбора", source="quality", note="Что источник действительно наблюдал; частичный сбор не означает отсутствие объектов.", columns=(
            Column("entity", "Объект", path="entity_name"), Column("source", "Источник", path="source", labels={"sysvol_gpt": "SYSVOL / GPT.INI"}),
            Column("status", "Состояние", "state", path="status", labels=dict(SOURCE_STATUS)), Column("detail", "Подробности", path="detail"),
        )),
    ),
    query=_query,
    export_csv=_export,
    row_key="id",
    row_links=(("Настройки политики", "/app/report/ad.gpo.v2?tab=settings&q={display_name}"),),
    detail=Detail(
        title="Основания проверки политики",
        key="id",
        inline="reasons",
        columns=(
            Column("category", "Основание", "state", labels={"deviation": "Подтверждённое отклонение", "unverified": "Непроверенные сведения", "assignment": "Вопрос назначения"}),
            Column("priority", "Приоритет проверки", "state", labels={"high": "Высокий", "medium": "Проверить сведения", "low": "Уточнить назначение"}),
            Column("title", "Причина", path="title"),
            Column("fact", "Наблюдалось", path="fact"),
            Column("condition", "Условие", path="condition"),
            Column("qualification", "Квалификация", path="qualification"),
            Column("limitation", "Ограничение", path="limitation"),
            Column("next", "Безопасный следующий шаг", path="next"),
        ),
    ),
    presets=(("Требуют внимания", {"view": "attention"}), ("Без связей", {"view": "unlinked"})),
    default_limit=500,
    max_limit=10_000,
    home_order=50,
)
