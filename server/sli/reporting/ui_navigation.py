from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.ops.version import get_release_metadata
from server.source_packs.registry import resolve_source_normalizer

ROLE_ORDER = ["security", "it", "technical"]
ROLE_TITLES = {
    "security": "ИБ",
    "it": "ИТ",
    "technical": "Технический",
}


def source_event_id_for_navigation(family: str) -> int:
    normalizer = resolve_source_normalizer("Security")
    event_ids = (
        normalizer.event_ids_for_analysis_family(family)
        if normalizer
        else ()
    )
    if not event_ids:
        raise RuntimeError(f"navigation source event family is unavailable: {family}")
    return int(event_ids[0])


def default_event_detail_action(*, limit: int = 100) -> dict[str, str]:
    event_id = source_event_id_for_navigation("successful_logon")
    return {
        "label": f"Event details {event_id}",
        "url": (
            "/reports/event-details.html?"
            f"event_id={event_id}&channel=Security&limit={int(limit)}"
        ),
    }


_DEFAULT_EVENT_DETAIL_ACTION = default_event_detail_action()


NAV_ITEMS: list[dict[str, Any]] = [
    {
        "id": "home",
        "title": "Главная панель",
        "url": "/",
        "group": "overview",
        "roles": ROLE_ORDER,
        "priority": 10,
        "description": "Общий рабочий экран с быстрым поиском, состоянием наблюдения, источниками и отчетами.",
    },
    {
        "id": "role-overview",
        "title": "Ролевая карта",
        "url": "/reports/role-overview.html",
        "group": "overview",
        "roles": ROLE_ORDER,
        "priority": 20,
        "description": "Поясняет, что видят ИБ, ИТ и технический слой, без удаления общих данных.",
    },
    {
        "id": "ui-navigation",
        "title": "Карта навигации",
        "url": "/reports/ui-navigation.html",
        "group": "overview",
        "roles": ROLE_ORDER,
        "priority": 25,
        "description": "Контрольная карта кнопок, отчетов и ролевой доступности интерфейса.",
    },
    {
        "id": "security-monitor",
        "title": "ИБ-мониторинг 24ч",
        "url": "/reports/security-events-monitor.html?period=24h",
        "group": "security",
        "roles": ["security", "technical"],
        "priority": 30,
        "description": "Ключевые события Security за выбранный период: входы, группы, пароли, блокировки.",
    },
    {
        "id": "findings",
        "title": "Findings",
        "url": "/reports/findings.html",
        "group": "security",
        "roles": ["security"],
        "priority": 40,
        "description": "Сформированные выводы и гипотезы с evidence для ручной проверки.",
    },
    {
        "id": "investigation",
        "title": "Расследование",
        "url": "/reports/investigation.html",
        "group": "security",
        "roles": ["security", "technical"],
        "priority": 50,
        "description": "Рабочее место расследования: pivots, цепочки, переходы к событиям.",
    },
    {
        "id": "ai-reports",
        "title": "AI-отчеты",
        "url": "/reports/ai-reports.html",
        "group": "security",
        "roles": ["security"],
        "priority": 60,
        "description": "AI-гипотезы после безопасной подготовки и redaction-preview.",
    },
    {
        "id": "collector-health",
        "title": "Состояние сбора",
        "url": "/reports/collector-health.html",
        "group": "operations",
        "roles": ["it", "technical"],
        "priority": 70,
        "description": "Lag, timeout, repeated backlog и качество сбора по DC/каналам.",
    },
    {
        "id": "autocollection",
        "title": "Автосбор",
        "url": "/reports/autocollection.html",
        "group": "operations",
        "roles": ["it", "technical"],
        "priority": 80,
        "description": "Текущий scheduled job, skipped-overlap, fairness и прогресс активного сбора.",
    },
    {
        "id": "storage-health",
        "title": "Storage Health",
        "url": "/reports/storage-health.html",
        "group": "operations",
        "roles": ["it"],
        "priority": 90,
        "description": "Состояние raw/processed/logs/reports, retention и dry-run cleanup.",
    },
    {
        "id": "db-status",
        "title": "DB Backend",
        "url": "/reports/db-status.html",
        "group": "operations",
        "roles": ["it", "technical"],
        "priority": 95,
        "description": "PostgreSQL-only runtime: DSN, schema, connection and operational readiness.",
    },
    {
        "id": "diagnostics",
        "title": "Диагностика",
        "url": "/reports/diagnostics.html",
        "group": "operations",
        "roles": ["it", "technical"],
        "priority": 100,
        "description": "Self-test, release gate, watchdog, diagnostic bundle и быстрые проверки.",
    },
    {
        "id": "system-health",
        "title": "Система",
        "url": "/reports/system-health.html",
        "group": "operations",
        "roles": ["it", "technical"],
        "priority": 110,
        "description": "Общее runtime-состояние сервиса и локальной среды проекта.",
    },
    {
        "id": "search",
        "title": "Поиск событий",
        "url": "/reports/search.html?limit=300&order=desc",
        "group": "technical",
        "roles": ["security", "technical"],
        "priority": 120,
        "description": "Низкоуровневый поиск по PostgreSQL: user, IP, computer, LogonId, Event ID.",
    },
    {
        "id": "event-details",
        "title": "Event details",
        "url": _DEFAULT_EVENT_DETAIL_ACTION["url"],
        "group": "technical",
        "roles": ["technical"],
        "priority": 130,
        "description": "Детализация конкретного Event ID с таблицей доказательств.",
    },
    {
        "id": "entity-details",
        "title": "Entity details",
        "url": "/reports/entity-details.html?limit=100",
        "group": "technical",
        "roles": ["technical"],
        "priority": 140,
        "description": "Связи event → entity и технический слой нормализации.",
    },
]

GROUP_TITLES = {
    "overview": "Обзор и роли",
    "security": "ИБ и расследование",
    "operations": "ИТ / эксплуатация",
    "technical": "Технический drill-down",
}


def get_ui_navigation_data() -> dict[str, Any]:
    """Return lightweight UI navigation model without touching AD/DC or event DB."""
    items = sorted((_normalize_item(item) for item in NAV_ITEMS), key=lambda item: (item["priority"], item["title"]))
    by_role = {
        role: [item for item in items if role in item["roles"]]
        for role in ROLE_ORDER
    }
    groups = [
        {
            "id": group_id,
            "title": title,
            "items": [item for item in items if item["group"] == group_id],
        }
        for group_id, title in GROUP_TITLES.items()
    ]
    return {
        "package_type": "UI_NAVIGATION",
        "status": "ok",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "release_metadata": get_release_metadata(),
        "roles": [{"id": role, "title": ROLE_TITLES[role], "items": by_role[role]} for role in ROLE_ORDER],
        "groups": groups,
        "items": items,
        "principle": "Ролевой вид меняет акценты интерфейса, но не скрывает доказательства и технические отчеты окончательно.",
    }


def primary_actions_for_role(role: str, *, limit: int = 5) -> list[dict[str, str]]:
    clean = role if role in ROLE_ORDER else "security"
    items = [item for item in get_ui_navigation_data()["items"] if clean in item["roles"]]
    return [
        {"label": item["title"], "url": item["url"]}
        for item in items[: max(0, int(limit))]
    ]


def render_ui_navigation_report(data: dict[str, Any] | None = None) -> str:
    data = data or get_ui_navigation_data()
    role_cards = "".join(_render_role_card(role) for role in data.get("roles") or [])
    group_sections = "".join(_render_group_section(group) for group in data.get("groups") or [])
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Карта навигации</title>{report_style(extra_css=_css())}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Stage 4 · UI consistency</div><h1>Карта навигации ИБ / ИТ / Технический</h1><p class=\"subtitle\">{_e(data.get('principle'))}</p><div class=\"pillrow\"><span class=\"pill\">Версия: {_e((data.get('release_metadata') or {}).get('project_version'))}</span><span class=\"pill\">Элементов: {len(data.get('items') or [])}</span></div></header>
<section><h2>Быстрые ролевые входы</h2><div class=\"grid three\">{role_cards}</div></section>
{group_sections}
<section><h2>Проверка на “мертвые” кнопки</h2><p class=\"muted\">Эта страница строится из того же каталога, который проверяет <code>ui_nav_check.py</code>. Для Stage 4 цель — чтобы основные кнопки вели на существующие dynamic report routes, главную страницу или явные search/detail routes.</p></section>
</main></body></html>"""


def _normalize_item(item: dict[str, Any]) -> dict[str, Any]:
    roles = [role for role in item.get("roles", []) if role in ROLE_ORDER]
    return {
        "id": str(item.get("id") or ""),
        "title": str(item.get("title") or ""),
        "url": str(item.get("url") or "#"),
        "group": str(item.get("group") or "overview"),
        "roles": roles or ROLE_ORDER,
        "role_titles": [ROLE_TITLES[role] for role in (roles or ROLE_ORDER)],
        "priority": int(item.get("priority") or 1000),
        "description": str(item.get("description") or ""),
    }


def _render_role_card(role: dict[str, Any]) -> str:
    items = role.get("items") or []
    links = "".join(f'<a class="button" href="{_e(item["url"])}">{_e(item["title"])}</a>' for item in items[:6])
    return f"""<article class=\"card nav-role-card\"><div class=\"pillrow\"><span class=\"badge ok\">{_e(role.get('title'))}</span><span class=\"pill\">{len(items)} точек входа</span></div><h3>{_e(role.get('title'))}</h3><p class=\"muted\">Главные действия для этой роли без потери доступа к общим данным.</p><div class=\"toolbar\">{links}</div></article>"""


def _render_group_section(group: dict[str, Any]) -> str:
    rows = "".join(_render_nav_row(item) for item in group.get("items") or [])
    return f"""<section><h2>{_e(group.get('title'))}</h2><table><thead><tr><th>Пункт</th><th>Роли</th><th>Назначение</th><th>Переход</th></tr></thead><tbody>{rows}</tbody></table></section>"""


def _render_nav_row(item: dict[str, Any]) -> str:
    roles = " ".join(f'<span class="role">{_e(title)}</span>' for title in item.get("role_titles") or [])
    return f"""<tr><td><strong>{_e(item.get('title'))}</strong><br><span class=\"mono muted\">{_e(item.get('id'))}</span></td><td>{roles}</td><td>{_e(item.get('description'))}</td><td><a class=\"button\" href=\"{_e(item.get('url'))}\" target=\"_blank\">Открыть</a></td></tr>"""


def _e(value: Any) -> str:
    return html.escape(str(value or ""))


def _css() -> str:
    return """
.nav-role-card .toolbar { margin-top: 12px; }
.nav-role-card .button { margin-bottom: 6px; }
td .role { display:inline-flex; margin:0 4px 4px 0; }
"""
