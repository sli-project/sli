from __future__ import annotations

import html
from collections import OrderedDict
from typing import Any
from urllib.parse import urlencode

from server.sli.events.event_search import get_event_search_data, make_search_url
from server.sli.semantic.findings import get_findings_data
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.core.time_format import format_event_time, get_display_timezone, parse_event_time
from server.sli.reporting.ui_labels import event_id_label
from server.source_packs.registry import resolve_source_normalizer

_INVESTIGATION_NORMALIZER = resolve_source_normalizer("Security")
if _INVESTIGATION_NORMALIZER is None:
    raise RuntimeError("Investigation requires the registered Security source normalizer")
P6_STORY_EVENT_IDS = list(_INVESTIGATION_NORMALIZER.investigation_event_ids("important"))
NOISE_EVENT_IDS = set(_INVESTIGATION_NORMALIZER.investigation_event_ids("noise"))
CATEGORY_LABELS: OrderedDict[str, str] = OrderedDict([
    ("failed_logons", "Ошибки входа"),
    ("logons", "Входы и учетные данные"),
    ("passwords", "Пароли"),
    ("lockouts", "Блокировки"),
    ("groups", "Группы"),
    ("privileges", "Привилегии"),
    ("accounts", "Учетные записи"),
    ("kerberos_ntlm", "Kerberos / NTLM"),
    ("system", "Службы и системные события"),
    ("other", "Прочее"),
])


def get_investigation_workspace_data(
    *,
    q: str | None = None,
    limit: int = 300,
    scope: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    timezone_name: str | None = "UTC",
    authorization: object | None = None,
) -> dict[str, Any]:
    query = (q or "").strip()
    clean_scope = _scope(scope)
    limit = max(1, min(int(limit or 300), 2000))
    if not query:
        return {
            "q": "",
            "limit": limit,
            "scope": clean_scope,
            "empty_query": True,
            "search": {"items": [], "total": None, "returned_count": 0, "has_more": False},
            "timeline": {"chain": [], "grouped": {}, "summary": {}},
            "findings": {"items": [], "summary": []},
            "summary": _empty_summary(),
            "pivots": [],
            "next_checks": _starter_checks(),
            "data_quality": _data_quality(
                backend="postgres",
                query="", scope=clean_scope, total_events=None, returned_events=0, findings_count=0,
                limit=limit, time_from=time_from, time_to=time_to, has_more=False,
            ),
        }
    event_ids = _event_ids_for_scope(clean_scope)
    # User-facing timelines follow the product-wide list convention: newest
    # evidence first.  Chronological analytics can still request ascending
    # order through the lower-level event-search API explicitly.
    search_kwargs = {
        "q": query, "event_ids": event_ids,
        "limit": limit, "order": "desc", "time_from": time_from,
        "time_to": time_to, "timezone_name": timezone_name,
        "include_internal_evidence": True,
    }
    findings_kwargs = {
        "q": query, "limit": 50,
        "refresh": False,
    }
    if authorization is not None:
        search_kwargs["authorization"] = authorization
        findings_kwargs["authorization"] = authorization
    search = get_event_search_data(**search_kwargs)
    findings = get_findings_data(**findings_kwargs)
    items = search.get("items") or []
    chain = [_story_item(item) for item in items]
    grouped = _group_timeline(chain)
    # `chain` is newest-first, while the summary fields retain their semantic
    # meaning (first = oldest, last = newest).
    first = chain[-1].get("time") if chain else None
    last = chain[0].get("time") if chain else None
    category_summary = _category_summary(chain)
    pivots = _extract_pivots(items, q=query, limit=limit, scope=clean_scope)
    next_checks = _next_checks(category_summary, pivots, findings.get("items") or [])
    return {
        "q": query,
        "limit": limit,
        "scope": clean_scope,
        "empty_query": False,
        "no_results": not bool(items or findings.get("items")),
        "search": search,
        "timeline": {"chain": chain, "grouped": grouped, "summary": category_summary},
        "findings": findings,
        "summary": {
            "total_events": int(search.get("returned_count") or len(items)),
            "total_is_exact": bool(search.get("total_is_exact")),
            "has_more": bool(search.get("has_more")),
            "chain_events": len(chain),
            "findings": len(findings.get("items") or []),
            "first_event_utc": first,
            "last_event_utc": last,
            "pivots": [item["value"] for item in pivots],
            "category_summary": category_summary,
            "attention_level": _attention_level(category_summary),
            "story": _story_sentence(query, category_summary, len(findings.get("items") or [])),
            "why_it_matters": _why_it_matters(category_summary, bool(findings.get("items"))),
        },
        "pivots": pivots,
        "next_checks": next_checks,
        "data_quality": _data_quality(
            backend=str(findings.get("backend") or "postgres"),
            query=query, scope=clean_scope,
            total_events=(int(search.get("total")) if search.get("total") is not None else None),
            returned_events=len(items), findings_count=len(findings.get("items") or []),
            limit=limit, time_from=time_from, time_to=time_to, has_more=bool(search.get("has_more")),
        ),
    }


def render_investigation_workspace_report(data: dict[str, Any]) -> str:
    q = data.get("q") or ""
    summary = data.get("summary") or {}
    findings = (data.get("findings") or {}).get("items") or []
    scope = data.get("scope") or "important"
    data_quality = data.get("data_quality") or {}
    time_from = data_quality.get("time_from")
    time_to = data_quality.get("time_to")
    filters = {"q": q, "limit": data.get("limit") or 300, "scope": scope, "time_from": time_from, "time_to": time_to}
    if data.get("empty_query"):
        timeline_html = '<div class="empty"><b>Введите учетную запись, IP, компьютер или LogonId.</b><br>После поиска появятся история действий, связанные события и рекомендации. Примеры: administrator, DC1, 192.0.2.13, 0x123456.</div>'
        findings_html = '<tr><td colspan="5">Введите объект расследования, чтобы увидеть связанные находки.</td></tr>'
        pivots_html = '<span class="muted">Связанные проверки появятся после поиска.</span>'
        story_html = _starter_screen_html()
    elif data.get("no_results"):
        timeline_html = '<div class="empty">По запросу ничего не найдено. Проверьте написание учетной записи/IP/хоста/LogonId или расширьте период/режим.</div>'
        findings_html = '<tr><td colspan="5">Связанных находок по этому запросу нет.</td></tr>'
        pivots_html = '<span class="muted">Связанные проверки не найдены.</span>'
        story_html = '<div class="callout"><b>Что произошло:</b> нет данных по выбранному запросу и режиму. <br><b>Что сделать:</b> попробуйте “Все события”, другой период или общий поиск.</div>'
    else:
        timeline_html = _grouped_timeline_html((data.get("timeline") or {}).get("grouped") or {})
        findings_html = "".join(_finding_row(item) for item in findings[:20]) or '<tr><td colspan="5">Связанных находок нет.</td></tr>'
        pivots_html = "".join(_pivot_link(item) for item in data.get("pivots") or []) or '<span class="muted">Связанные проверки не найдены.</span>'
        checks = "".join(f"<li>{html.escape(item)}</li>" for item in data.get("next_checks") or [])
        story_html = f'<div class="grid two"><div class="callout"><h3>Что произошло</h3><p>{html.escape(str(summary.get("story") or "—"))}</p><h3>Почему это важно</h3><p>{html.escape(str(summary.get("why_it_matters") or "—"))}</p></div><div class="callout"><h3>Что проверить дальше</h3><ul>{checks}</ul></div></div>'
    period = f"{html.escape(format_event_time(summary.get('first_event_utc')))}<br>{html.escape(format_event_time(summary.get('last_event_utc')))}" if summary.get('first_event_utc') or summary.get('last_event_utc') else "—<br>—"
    scope_tabs = _scope_tabs(filters)
    search_params = {"q": q, "limit": data.get("limit") or 300, "order": "desc", "time_from": time_from, "time_to": time_to}
    api_params = {"q": q, "limit": data.get("limit") or 300, "scope": scope, "time_from": time_from, "time_to": time_to}
    search_url = "/reports/search.html?" + urlencode({key: value for key, value in search_params.items() if value not in (None, "")}) if q else "/reports/search.html"
    api_url = "/api/investigation/workspace?" + urlencode({key: value for key, value in api_params.items() if value not in (None, "")}) if q else "/api/investigation/workspace"
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Рабочее место расследования</title>{report_style(extra_css='.scope-tabs a{border:1px solid var(--line);border-radius:999px;background:var(--panel);padding:8px 11px;font-weight:800;color:var(--text)}.scope-tabs a.active{background:color-mix(in srgb,var(--blue) 12%,var(--panel));border-color:var(--blue)}.category-title{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-top:18px}.pivot-kind{font-size:11px;text-transform:uppercase;color:var(--muted);display:block}.story-actions{justify-content:flex-end}')} </head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Расследование</div><h1>Рабочее место расследования</h1><p class=\"subtitle\">Собирает историю действий по объекту: что произошло, что подтверждает вывод и что проверить дальше.</p><div class=\"pillrow\"><span class=\"pill\">Уровень внимания: {html.escape(str(summary.get('attention_level') or '—'))}</span><span class=\"pill\">Режим: {html.escape(_scope_label(scope))}</span></div></header>
<section><h2>Поиск</h2><form class=\"search-form\" method=\"get\" action=\"/reports/investigation.html\"><input name=\"q\" value=\"{html.escape(q)}\" placeholder=\"учетная запись, IP, компьютер, LogonId\"><label>С <input type=\"datetime-local\" name=\"time_from\" value=\"{html.escape(_datetime_local_value(time_from))}\" step=\"60\" title=\"Время на этом компьютере\"></label><label>По <input type=\"datetime-local\" name=\"time_to\" value=\"{html.escape(_datetime_local_value(time_to))}\" step=\"60\" title=\"Время на этом компьютере\"></label><input name=\"limit\" value=\"{html.escape(str(data.get('limit') or 300))}\"><input type=\"hidden\" name=\"scope\" value=\"{html.escape(scope)}\"><button>Построить историю</button><a class=\"button\" href=\"{html.escape(search_url)}\">Все события</a></form><div class=\"toolbar scope-tabs\">{scope_tabs}</div><div class=\"toolbar story-actions\"><a class=\"button\" href=\"{html.escape(api_url)}\">Экспорт JSON</a></div></section>
<section><h2>Кратко</h2><div class=\"grid kpi\"><div class=\"card\"><div class=\"muted\">Событий</div><h3>{summary.get('total_events', 0)}</h3></div><div class=\"card\"><div class=\"muted\">В истории</div><h3>{summary.get('chain_events', 0)}</h3></div><div class=\"card\"><div class=\"muted\">Находок</div><h3>{summary.get('findings', 0)}</h3></div><div class=\"card\"><div class=\"muted\">Период</div><p>{period}</p></div></div></section>
<section><h2>Смысловая сводка</h2>{story_html}</section>
<section><h2>Связанные проверки</h2><div class=\"toolbar\">{pivots_html}</div></section>
<section><h2>Цепочка событий</h2><p class=\"muted\">Хронология событий по выбранному объекту.</p><div class=\"timeline\">{timeline_html}</div></section>
<section><h2>Связанные findings</h2><p class=\"muted\">Связанные находки по выбранному объекту.</p><table><thead><tr><th>Важность</th><th>Название</th><th>Цель</th><th>Почему важно</th><th>Действие</th></tr></thead><tbody>{findings_html}</tbody></table></section>
{_data_quality_html(data.get("data_quality") or {})}
</main></body></html>"""


def _data_quality(
    *, backend: str, query: str, scope: str, total_events: int | None, returned_events: int,
    findings_count: int, limit: int, time_from: str | None, time_to: str | None,
    has_more: bool = False,
) -> dict[str, Any]:
    limitations: list[str] = []
    if scope != "all":
        limitations.append("Показаны важные для расследования события; включите «Все события», если нужен полный контекст.")
    truncated = bool(has_more or (total_events is not None and total_events > returned_events))
    if has_more:
        limitations.append(f"Показано {returned_events} событий. Чтобы увидеть остальные, откройте следующую страницу результатов.")
    elif total_events is not None and total_events > returned_events:
        limitations.append(f"Показано {returned_events} из {total_events} событий из-за лимита {limit}.")
    if not time_from and not time_to:
        limitations.append("Явный временной диапазон не задан; применяется безопасное ограниченное окно быстрого поиска.")
    if returned_events == 0 and not findings_count and query:
        limitations.append("Отсутствие результатов не доказывает отсутствие активности: проверьте свежесть каналов, период и полноту импорта.")
    return {
        "backend": backend,
        "evidence_policy": "evidence-first",
        "query": query,
        "scope": scope,
        "total_events": total_events,
        "total_is_exact": total_events is not None,
        "returned_events": returned_events,
        "findings_count": findings_count,
        "truncated": truncated,
        "has_more": bool(has_more),
        "time_from": time_from,
        "time_to": time_to,
        "limitations": limitations,
    }


def _data_quality_html(data: dict[str, Any]) -> str:
    limitations = data.get("limitations") or []
    items = "".join(f"<li>{html.escape(str(item))}</li>" for item in limitations) or "<li>Ограничения не обнаружены.</li>"
    return (
        '<section><h2>Качество и границы данных</h2>'
        f'<div class="pillrow"><span class="pill">Источник данных: {html.escape(str(data.get("backend") or "—"))}</span>'
        f'<span class="pill">Принцип: только подтверждённые данные</span>'
        f'<span class="pill">Показано событий: {int(data.get("returned_events") or 0)}</span>'
        f'<span class="pill">Есть продолжение: {"да" if data.get("has_more") else "нет"}</span></div>'
        f'<ul>{items}</ul></section>'
    )


def _story_item(item: dict[str, Any]) -> dict[str, Any]:
    category = _category_for_event(item.get("event_id"))
    return {
        # The evidence identifier is deliberately carried through the
        # investigation projection.  Event ID describes a Windows event type;
        # the React timeline must navigate to this exact stored record.
        "event_db_id": int(item.get("id") or item.get("event_db_id") or 0),
        "time": item.get("time_created_utc"),
        "time_display": item.get("time_created_utc_display") or format_event_time(item.get("time_created_utc")),
        "server": item.get("server"),
        "channel": item.get("channel"),
        "event_id": item.get("event_id"),
        "label": item.get("label") or event_id_label(item.get("event_id")),
        "category": category,
        "category_label": CATEGORY_LABELS.get(category, "Прочее"),
        "severity": item.get("severity"),
        "subject": item.get("subject"),
        "target": item.get("target"),
        "source": item.get("source"),
        "logon_id": item.get("logon_id"),
        "summary": item.get("summary"),
        "detail_url": _event_detail_url(item),
    }


def _grouped_timeline_html(grouped: dict[str, list[dict[str, Any]]]) -> str:
    if not grouped:
        return '<div class="empty">История не построена.</div>'
    parts: list[str] = []
    for category, label in CATEGORY_LABELS.items():
        items = grouped.get(category) or []
        if not items:
            continue
        body = "".join(_chain_item(item) for item in items[:120])
        parts.append(f'<div class="category-title"><h3>{html.escape(label)}</h3><span class="pill">{len(items)}</span></div>{body}')
    return "".join(parts)


def _chain_item(item: dict[str, Any]) -> str:
    title = item.get("label") or event_id_label(item.get("event_id"))
    return f"""<div class=\"timeline-item\"><div class=\"timeline-marker\"></div><article class=\"timeline-card\"><div class=\"timeline-head\"><h3>{html.escape(str(title))}</h3><span class=\"pill\" title=\"{html.escape(str(item.get('time') or ''))}\">{html.escape(str(item.get('time_display') or format_event_time(item.get('time'))))}</span></div><div class=\"timeline-meta\"><span>DC: {html.escape(str(item.get('server') or '—'))}</span><span>{html.escape(str(item.get('channel') or '—'))}</span><span>Инициатор: {html.escape(str(item.get('subject') or '—'))}</span><span>Цель: {html.escape(str(item.get('target') or '—'))}</span><span>Источник: {html.escape(str(item.get('source') or '—'))}</span><span>LogonId: {html.escape(str(item.get('logon_id') or '—'))}</span></div><p>{html.escape(str(item.get('summary') or item.get('label') or ''))[:500]}</p><a class=\"button\" href=\"{html.escape(str(item.get('detail_url') or '#'))}\">Открыть событие</a></article></div>"""


def _finding_row(item: dict[str, Any]) -> str:
    return f"<tr><td>{html.escape(str(item.get('severity_label') or item.get('severity')))}</td><td>{html.escape(str(item.get('title') or '—'))}</td><td>{html.escape(str(item.get('target') or '—'))}</td><td>{html.escape(str(item.get('why_it_matters') or item.get('summary') or '—'))}</td><td>{html.escape(str(item.get('recommended_action') or '—'))}</td></tr>"


def _category_for_event(raw_event_id: Any) -> str:
    return _INVESTIGATION_NORMALIZER.investigation_category(raw_event_id)


def _category_summary(items: list[dict[str, Any]]) -> dict[str, int]:
    counters = {key: 0 for key in CATEGORY_LABELS}
    for item in items:
        key = str(item.get("category") or "other")
        counters[key if key in counters else "other"] += 1
    counters["total"] = len(items)
    return counters


def _group_timeline(items: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {key: [] for key in CATEGORY_LABELS}
    for item in items:
        grouped.setdefault(str(item.get("category") or "other"), []).append(item)
    return {key: value for key, value in grouped.items() if value}


def _attention_level(summary: dict[str, int]) -> str:
    if summary.get("groups", 0) or summary.get("privileges", 0):
        return "высокий"
    if summary.get("lockouts", 0) or summary.get("passwords", 0) or summary.get("failed_logons", 0) >= 5:
        return "внимание"
    if summary.get("total", 0):
        return "норма"
    return "—"


def _extract_pivots(items: list[dict[str, Any]], *, q: str, limit: int, scope: str) -> list[dict[str, str]]:
    pivots: list[dict[str, str]] = []

    def add(kind: str, value: Any, label: str | None = None) -> None:
        clean = str(value or "").strip()
        if not clean or clean == "—" or clean.lower() == q.lower():
            return
        if any(item["kind"] == kind and item["value"] == clean for item in pivots):
            return
        url = "/reports/investigation.html?" + urlencode({"q": clean, "limit": limit, "scope": scope})
        pivots.append({"kind": kind, "value": clean, "label": label or clean, "url": url})

    for item in items[:250]:
        add("та же учетка", item.get("target_user_name") or item.get("target"))
        add("тот же инициатор", item.get("subject_user_name") or item.get("subject"))
        add("тот же IP", item.get("ip_address"))
        add("тот же host", item.get("workstation_name") or item.get("server"))
        add("тот же LogonId", item.get("logon_id"))
        if len(pivots) >= 12:
            break
    return pivots


def _next_checks(summary: dict[str, int], pivots: list[dict[str, str]], findings: list[dict[str, Any]]) -> list[str]:
    checks: list[str] = []
    if summary.get("failed_logons") and summary.get("logons"):
        checks.append("Сопоставить ошибки входа с последующими успешными входами по той же учетной записи, IP и LogonId.")
    if summary.get("passwords"):
        checks.append("Проверить, кто инициировал смену/сброс пароля и был ли после этого успешный вход.")
    if summary.get("lockouts"):
        checks.append("Определить источник блокировки и повторяемость по IP/host.")
    if summary.get("groups"):
        checks.append("Проверить изменение групп: кто добавил/удалил, какая группа, является ли она привилегированной.")
    if summary.get("privileges"):
        checks.append(
            _INVESTIGATION_NORMALIZER.investigation_check("privileges")
            or "Проверить привилегированную сессию, её источник и учетную запись."
        )
    if findings:
        checks.append("Открыть связанные находки и сверить каждую гипотезу с первичными событиями.")
    if pivots:
        checks.append("Продолжить расследование по связанным объектам: та же учётная запись, IP, компьютер или LogonId.")
    if not checks:
        checks.extend(_starter_checks())
    return checks[:7]


def _story_sentence(q: str, summary: dict[str, int], findings_count: int) -> str:
    if not summary.get("total"):
        return f"По запросу {q} не найдено событий в выбранном режиме."
    parts = []
    for key, label in CATEGORY_LABELS.items():
        count = summary.get(key, 0)
        if count:
            parts.append(f"{label.lower()}: {count}")
    suffix = f"; связанных находок: {findings_count}" if findings_count else ""
    return f"По объекту {q} построена история из {summary.get('total', 0)} событий: " + ", ".join(parts[:8]) + suffix + "."


def _why_it_matters(summary: dict[str, int], has_findings: bool) -> str:
    if summary.get("groups") or summary.get("privileges"):
        return "Есть действия, которые могут менять права или отражать привилегированный вход. Их нужно сверить с первичными событиями, а не только с Event ID."
    if summary.get("passwords") and summary.get("logons"):
        return "Парольные события рядом с входами помогают выявить сценарий сброса/смены пароля и последующего доступа."
    if summary.get("failed_logons") and summary.get("logons"):
        return "Ошибки входа вместе с успешными входами могут указывать на подбор, ошибку пользователя или легитимный вход после неудачных попыток."
    if has_findings:
        return "Есть связанные находки — они требуют сверки с первичными событиями."
    return "Сводка помогает быстро отделить важные события от второстепенного шума и выбрать следующий шаг."


def _pivot_link(item: dict[str, str]) -> str:
    return f'<a class="button" href="{html.escape(item.get("url") or "#")}"><span><span class="pivot-kind">{html.escape(item.get("kind") or "pivot")}</span>{html.escape(item.get("label") or item.get("value") or "—")}</span></a>'


def _scope(scope: str | None) -> str:
    clean = str(scope or "important").strip().lower()
    return clean if clean in {"important", "hide_noise", "all"} else "important"


def _scope_label(scope: str) -> str:
    return {"important": "важная история", "hide_noise": "скрыть шум", "all": "все события"}.get(scope, "важная история")


def _event_ids_for_scope(scope: str) -> list[int] | None:
    if scope == "all":
        return None
    return list(_INVESTIGATION_NORMALIZER.investigation_event_ids(scope))


def _scope_tabs(filters: dict[str, Any]) -> str:
    q = str(filters.get("q") or "")
    limit = int(filters.get("limit") or 300)
    active = _scope(filters.get("scope"))
    tabs = [("important", "Только важные"), ("hide_noise", "Скрыть шум"), ("all", "Все события")]
    links = []
    for key, label in tabs:
        params = {"q": q, "limit": limit, "scope": key, "time_from": filters.get("time_from"), "time_to": filters.get("time_to")}
        href = "/reports/investigation.html?" + urlencode({name: value for name, value in params.items() if value not in (None, "")})
        cls = "active" if active == key else ""
        links.append(f'<a class="{cls}" href="{html.escape(href)}">{html.escape(label)}</a>')
    return "".join(links)


def _datetime_local_value(value: Any) -> str:
    """Render a stored ISO instant into the value syntax of datetime-local."""
    parsed = parse_event_time(value)
    if parsed is None:
        return ""
    tz, _label = get_display_timezone()
    return parsed.astimezone(tz).strftime("%Y-%m-%dT%H:%M")


def _event_detail_url(item: dict[str, Any]) -> str:
    params = {"event_id": item.get("event_id"), "channel": item.get("channel"), "server": item.get("server"), "limit": 50}
    if item.get("time_created_utc"):
        params["time_from"] = item.get("time_created_utc")
        params["time_to"] = item.get("time_created_utc")
    return "/reports/event-details.html?" + urlencode({key: value for key, value in params.items() if value not in (None, "")})


def _empty_summary() -> dict[str, Any]:
    return {
        "total_events": 0,
        "chain_events": 0,
        "findings": 0,
        "first_event_utc": None,
        "last_event_utc": None,
        "pivots": [],
        "category_summary": {},
        "attention_level": "—",
        "story": "Введите объект расследования.",
        "why_it_matters": "Расследование строится только после явного запроса, чтобы не показывать случайные глобальные находки.",
    }


def _starter_checks() -> list[str]:
    return [
        "Начните с учетной записи, IP, host или LogonId.",
        "Для быстрого анализа используйте «Только важные», для полного контекста — «Все события».",
        "Открывайте конкретное событие, чтобы сверить первичные данные.",
    ]


def _starter_screen_html() -> str:
    checks = "".join(f"<li>{html.escape(item)}</li>" for item in _starter_checks())
    return f'<div class="callout"><h3>Стартовый экран</h3><p>Введите объект расследования. Глобальные находки здесь намеренно не показываются, чтобы не вводить в заблуждение.</p><ul>{checks}</ul></div>'
