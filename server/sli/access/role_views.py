from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from server.sli.ai.ai_reports import list_ai_runs
from server.sli.sources.collector_health import get_collector_health
from server.sli.core.database import get_entity_summary, get_event_summary, get_sources
from server.sli.semantic.findings import get_findings_data
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.ops.system_health import get_system_health
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    StorageRouteConsumer,
    resolve_storage_route,
)
from server.sli.storage.storage_v2_transition_controller import CutoverAuthorization
from server.sli.core.time_format import format_event_time
from server.sli.reporting.ui_navigation import default_event_detail_action, primary_actions_for_role

ROLE_VIEW_ORDER = ["security", "it", "technical"]

ROLE_VIEW_META = {
    "security": {
        "title": "Вид ИБ",
        "short_title": "ИБ",
        "subtitle": "Риски, findings, цепочки учетных записей, AI-отчеты и evidence для проверки действий в AD.",
        "audience": "Специалист ИБ",
    },
    "it": {
        "title": "Вид ИТ",
        "short_title": "ИТ",
        "subtitle": "Качество сбора, состояние DC/каналов, эксплуатация, backup, retention и обновления.",
        "audience": "Специалист ИТ",
    },
    "technical": {
        "title": "Технический вид",
        "short_title": "Технический",
        "subtitle": "Сырые события, Event ID, LogonId, сущности, JSON-поля и переходы к детальным таблицам.",
        "audience": "Аналитик / инженер",
    },
}


def get_role_views_meta() -> dict[str, Any]:
    """Return lightweight role-view metadata for release checks.

    This must stay fast and must not query the event database. Full role view
    rendering remains in get_role_views_data().
    """
    return {
        "views": [
            {
                "id": role_id,
                "title": ROLE_VIEW_META[role_id]["title"],
                "short_title": ROLE_VIEW_META[role_id]["short_title"],
                "audience": ROLE_VIEW_META[role_id]["audience"],
            }
            for role_id in ROLE_VIEW_ORDER
        ],
        "principle": "Ролевые представления не удаляют данные: они только меняют порядок и акценты.",
    }


def get_role_views_data(
    *,
    refresh_findings: bool = False,
    preloaded: dict[str, Any] | None = None,
    authorization: CutoverAuthorization | None = None,
    consumer: str = StorageRouteConsumer.ROLE_VIEWS,
) -> dict[str, Any]:
    """Return role-oriented navigation without hiding shared data.

    ``preloaded`` lets the dashboard reuse already computed summaries instead of
    re-running collector, storage and findings queries during the same page load.
    Full report routes may still call this function without preloaded data.
    Findings refresh is opt-in because a read-only dashboard request must not
    mutate findings or repeat an expensive refresh every five seconds.
    """
    # Storage V2 is the only route (plan 6.5): role views render a preloaded
    # dashboard snapshot and never start their own summary reads.
    resolve_storage_route(authorization=authorization, consumer=consumer)
    if not preloaded:
        raise StorageRouteAuthorizationError(
            "storage_v2_role_views_requires_preloaded_snapshot"
        )
    loaded = preloaded or {}
    events = loaded["events"] if "events" in loaded else get_event_summary()
    entities = loaded["entities"] if "entities" in loaded else get_entity_summary()
    collector = loaded["collector"] if "collector" in loaded else get_collector_health()
    system = loaded["system"] if "system" in loaded else get_system_health()
    effective_refresh_findings = bool(refresh_findings)
    findings = loaded["findings"] if "findings" in loaded else get_findings_data(
        limit=50, refresh=effective_refresh_findings, authorization=authorization
    )
    ai_runs = loaded["ai_runs"] if "ai_runs" in loaded else list_ai_runs(limit=5)
    sources = loaded["sources"] if "sources" in loaded else get_sources()

    security_channel = _channel_count(events, "Security")
    total_events = int(events.get("total_events") or 0)
    security_items = [item for item in collector.get("items") or [] if item.get("channel") == "Security"]
    worst_lag = _max_number([item.get("lag_minutes") for item in security_items])
    security_high = int((collector.get("summary") or {}).get("security_high") or 0)
    active_findings = [item for item in findings.get("items") or [] if item.get("status") not in {"closed", "false_positive"}]

    common = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "principle": "Ролевые представления не удаляют данные: они только меняют порядок и акценты.",
        "summary": {
            "sources": len(sources or []),
            "total_events": total_events,
            "security_events": security_channel,
            "entities": int(entities.get("total_entities") or 0),
            "active_findings": len(active_findings),
            "ai_runs": len(ai_runs.get("items") or []),
            "security_high": security_high,
            "worst_security_lag_minutes": worst_lag,
            "system_status": system.get("status"),
        },
    }
    return {
        **common,
        "views": [
            _security_view(common, active_findings, security_items, ai_runs),
            _it_view(common, collector, system),
            _technical_view(common, events, entities),
        ],
    }


def render_role_overview_report(data: dict[str, Any], *, selected: str | None = None) -> str:
    selected = _clean_view(selected)
    views = data.get("views") or []
    if selected:
        views = [view for view in views if view.get("id") == selected] or views
    cards = "".join(_render_view_card(view) for view in views) or '<div class="card"><h3>Данные обновляются</h3><p class="muted">Страница доступна. Обновите её через несколько секунд.</p></div>'
    tabs = "".join(
        f'<a class="button" href="/reports/role-overview.html?view={html.escape(view_id)}">{html.escape(meta["title"])}</a>'
        for view_id, meta in ROLE_VIEW_META.items()
    )
    summary = data.get("summary") or {}
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Ролевые представления</title>{report_style(extra_css=_role_css())}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Ролевые представления</div><h1>ИБ / ИТ / Технический слой</h1><p class=\"subtitle\">Один набор данных используется разными ролями. Мы ничего не удаляем: меняется только порядок, фокус и быстрые действия.</p><div class=\"pillrow\"><span class=\"pill\">Сформирован: {html.escape(format_event_time(data.get('generated_at_utc')))}</span><span class=\"pill\">Событий: {summary.get('total_events', 0)}</span><span class=\"pill\">Findings: {summary.get('active_findings', 0)}</span><span class=\"pill\">Security lag max: {_fmt_minutes(summary.get('worst_security_lag_minutes'))}</span></div></header>
<section><h2>Переключить вид</h2><div class=\"toolbar\">{tabs}<a class=\"button\" href=\"/\">Главная панель</a></div><p class=\"muted\">{html.escape(str(data.get('principle') or ''))}</p></section>
<section><h2>Рабочие слои</h2><div class=\"grid three role-view-grid\">{cards}</div></section>
</main></body></html>"""


def _security_view(common: dict[str, Any], active_findings: list[dict[str, Any]], security_items: list[dict[str, Any]], ai_runs: dict[str, Any]) -> dict[str, Any]:
    summary = common["summary"]
    return {
        "id": "security",
        **ROLE_VIEW_META["security"],
        "status": "high" if summary.get("security_high") else ("warn" if active_findings else "ok"),
        "metrics": [
            {"name": "Активные findings", "value": len(active_findings), "hint": "объекты проверки с evidence"},
            {"name": "Security events", "value": summary.get("security_events"), "hint": "главный AD-канал"},
            {"name": "Security lag", "value": _fmt_minutes(summary.get("worst_security_lag_minutes")), "hint": "важно для доверия к выводам"},
            {"name": "AI-отчеты", "value": len(ai_runs.get("items") or []), "hint": "гипотезы после redaction"},
        ],
        "actions": _dedupe_actions([
            {"label": "ИБ-мониторинг 24ч", "url": "/reports/security-events-monitor.html?period=24h"},
            {"label": "Открыть findings", "url": "/reports/findings.html"},
            {"label": "Рабочее место расследования", "url": "/reports/investigation.html"},
            {"label": "AI-отчеты", "url": "/reports/ai-reports.html"},
            {"label": "Карта навигации", "url": "/reports/ui-navigation.html"},
            {"label": "Подготовить AI prompt", "url": "/reports/ai-prompt-preview.html?redaction_level=strict&limit=80"},
        ] + primary_actions_for_role("security", limit=3)),
        "kept_for_other_roles": "Состояние сбора и технические события не скрываются: они нужны для проверки качества данных.",
    }


def _it_view(common: dict[str, Any], collector: dict[str, Any], system: dict[str, Any]) -> dict[str, Any]:
    summary = common["summary"]
    collector_summary = collector.get("summary") or {}
    retention = (system.get("retention") or {})
    return {
        "id": "it",
        **ROLE_VIEW_META["it"],
        "status": "high" if summary.get("security_high") else ("warn" if system.get("status") == "warn" else "ok"),
        "metrics": [
            {"name": "Источники", "value": summary.get("sources"), "hint": "серверы в наблюдении"},
            {"name": "Security high", "value": collector_summary.get("security_high", 0), "hint": "качество сбора"},
            {"name": "Retention", "value": retention.get("candidates", 0), "hint": "кандидаты на очистку"},
            {"name": "System status", "value": system.get("status"), "hint": "runtime-файлы и БД"},
        ],
        "actions": _dedupe_actions([
            {"label": "Состояние сбора", "url": "/reports/collector-health.html"},
            {"label": "Автосбор", "url": "/reports/autocollection.html"},
            {"label": "Storage Health", "url": "/reports/storage-health.html"},
            {"label": "Диагностика", "url": "/reports/diagnostics.html"},
            {"label": "Состояние системы", "url": "/reports/system-health.html"},
            {"label": "Карта навигации", "url": "/reports/ui-navigation.html"},
        ] + primary_actions_for_role("it", limit=3)),
        "kept_for_other_roles": "Findings и AI-отчеты не скрываются: они помогают ИТ понимать, какие инфраструктурные проблемы влияют на риск.",
    }


def _technical_view(common: dict[str, Any], events: dict[str, Any], entities: dict[str, Any]) -> dict[str, Any]:
    summary = common["summary"]
    return {
        "id": "technical",
        **ROLE_VIEW_META["technical"],
        "status": "ok",
        "metrics": [
            {"name": "Всего событий", "value": summary.get("total_events"), "hint": "строки в активном backend"},
            {"name": "Каналы", "value": len(events.get("by_channel") or []), "hint": "Windows Event Log"},
            {"name": "Сущности", "value": summary.get("entities"), "hint": "объекты наблюдения"},
            {"name": "Связи", "value": entities.get("total_event_entity_links"), "hint": "event → entity"},
        ],
        "actions": _dedupe_actions([
            {"label": "Поиск по всем событиям", "url": "/reports/search.html?limit=300&order=desc"},
            default_event_detail_action(),
            {"label": "Entity details", "url": "/reports/entity-details.html?limit=100"},
            {"label": "Диагностика", "url": "/reports/diagnostics.html"},
            {"label": "Карта навигации", "url": "/reports/ui-navigation.html"},
            {"label": "AI redaction preview", "url": "/reports/ai-redaction-preview.html?redaction_level=strict&limit=80"},
        ] + primary_actions_for_role("technical", limit=3)),
        "kept_for_other_roles": "Сырые события остаются вторым слоем: они нужны для доказательности, но не должны перегружать главный ИБ/ИТ-экран.",
    }


def _render_view_card(view: dict[str, Any]) -> str:
    metrics = "".join(
        f'<div class="mini-stat"><span>{html.escape(str(metric["name"]))}</span><strong>{html.escape(str(metric.get("value", "—")))}</strong><small>{html.escape(str(metric.get("hint") or ""))}</small></div>'
        for metric in view.get("metrics") or []
    )
    actions = "".join(
        f'<a class="button" href="{html.escape(str(action["url"]))}">{html.escape(str(action["label"]))}</a>'
        for action in view.get("actions") or []
    )
    status = html.escape(str(view.get("status") or "ok"))
    return f"""<article class=\"card role-view-card\">
<div class=\"pillrow\"><span class=\"badge {status}\">{html.escape(str(view.get('short_title')))}</span><span class=\"pill\">{html.escape(str(view.get('audience')))}</span></div>
<h3>{html.escape(str(view.get('title')))}</h3><p class=\"muted\">{html.escape(str(view.get('subtitle')))}</p>
<div class=\"entity-grid\">{metrics}</div>
<div class=\"toolbar mt\">{actions}</div>
<p class=\"muted\"><b>Важно:</b> {html.escape(str(view.get('kept_for_other_roles') or ''))}</p>
</article>"""


def _dedupe_actions(actions: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for action in actions:
        url = str(action.get("url") or "")
        label = str(action.get("label") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        result.append({"label": label, "url": url})
    return result


def _channel_count(events: dict[str, Any], channel: str) -> int:
    for row in events.get("by_channel") or []:
        if row.get("channel") == channel:
            return int(row.get("count") or 0)
    return 0


def _max_number(values: list[Any]) -> int | None:
    clean = []
    for value in values:
        try:
            if value is not None:
                clean.append(int(value))
        except (TypeError, ValueError):
            continue
    return max(clean) if clean else None


def _fmt_minutes(value: Any) -> str:
    try:
        return f"{int(value)} мин" if value is not None else "—"
    except (TypeError, ValueError):
        return "—"


def _clean_view(value: str | None) -> str | None:
    clean = (value or "").strip().lower()
    return clean if clean in ROLE_VIEW_ORDER else None


def _role_css() -> str:
    return """
.role-view-grid { align-items: stretch; }
.role-view-card { display: flex; flex-direction: column; gap: 12px; }
.role-view-card .entity-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.role-view-card small { display:block; margin-top:4px; color:var(--muted); font-size:11px; }
.badge.high { background:#fee2e2; color:#991b1b; }
.badge.warn { background:#fffbeb; color:#92400e; }
.badge.ok { background:#ecfdf5; color:#166534; }
@media(max-width:1050px){.role-view-card .entity-grid{grid-template-columns:1fr;}}
"""
