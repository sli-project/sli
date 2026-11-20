from __future__ import annotations

import html
from pathlib import Path

from server.sli.events.event_details import make_event_detail_url
from server.sli.reporting.report_ui import report_style
from server.sli.reports.analysis_rules import (
    _display_risk,
    _missing_fields_for_event,
    _why_event_matters,
)


def _event_table_rows(criticality: list[dict], servers: list[str]) -> list[dict]:
    rows = []
    for row in criticality:
        rows.append(
            {
                "risk": _display_risk(row["severity"]),
                "event_id": row["event_id"],
                "channel": row["channel"],
                "provider_name": row.get("provider_name", ""),
                "count": row["count"],
                "description": row["title"],
                "why": row.get("why") or _why_event_matters(row["event_id"]),
                "action": row["fix"],
                "missing": row.get("missing") or _missing_fields_for_event(row["event_id"]),
                "detail_url": _event_detail_url(row, servers),
            }
        )
    return rows


def _event_detail_url(row: dict, servers: list[str]) -> str:
    return make_event_detail_url(
        event_id=row["event_id"],
        channel=row.get("channel"),
        servers=servers,
        limit=300,
        order="desc",
    )


def _server_links(paths: list[Path]) -> list[dict[str, str]]:
    links = []
    for path in paths:
        server = path.name.removeprefix("server-").removesuffix("-security-profile.html")
        links.append({"name": server, "file": path.name, "url": f"/reports/{path.name}"})
    return links


def _table(headers: list[str], rows: list[tuple]) -> str:
    head = "".join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(item))}</td>" for item in row) + "</tr>" for row in rows)
    if not body:
        body = f'<tr><td colspan="{len(headers)}">Нет данных</td></tr>'
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _recommendations_table(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        risk = row["risk"]
        table_rows.append(
            f"""<tr class="risk-{html.escape(risk)}">
<td>{html.escape(risk)}</td>
<td>{html.escape(row["title"])}</td>
<td>{html.escape(row["reason"])}</td>
<td>{html.escape(row["action"])}</td>
</tr>"""
        )
    return "<table><thead><tr><th>Риск</th><th>Наблюдение</th><th>Причина</th><th>Рекомендация</th></tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"


def _criticality_table(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        severity = row["severity"]
        table_rows.append(
            f"""<tr class="risk-{html.escape(severity)}">
<td>{html.escape(str(row["event_id"]))}</td>
<td>{html.escape(str(row["channel"]))}</td>
<td>{html.escape(str(row["count"]))}</td>
<td>{html.escape(severity)}</td>
<td>{html.escape(row["title"])}</td>
<td>{html.escape(row["fix"])}</td>
</tr>"""
        )
    if not table_rows:
        table_rows.append('<tr><td colspan="6">Нет данных</td></tr>')
    return "<table><thead><tr><th>Event ID</th><th>Канал</th><th>Количество</th><th>Критичность</th><th>Описание</th><th>Вариант исправления</th></tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"


def _gap_table(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        cls = "risk-low" if row["status"] == "Собирается" else "risk-medium"
        table_rows.append(
            f"""<tr class="{cls}">
<td>{html.escape(str(row["channel"]))}</td>
<td>{html.escape(str(row["event_id"]))}</td>
<td>{html.escape(row["name"])}</td>
<td>{html.escape(row["status"])}</td>
<td>{html.escape(row["source"])}</td>
<td>{html.escape(row["recommendation"])}</td>
</tr>"""
        )
    return "<table><thead><tr><th>Канал</th><th>Event ID</th><th>Контроль</th><th>Статус</th><th>Почему нужен</th><th>Рекомендация</th></tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"


def _correlation_table(rows: list[dict]) -> str:
    table_rows = []
    for row in rows:
        risk = row["risk"]
        table_rows.append(
            f"""<tr class="risk-{html.escape(risk)}">
<td>{html.escape(risk)}</td>
<td>{html.escape(row["scenario"])}</td>
<td>{html.escape(row["facts"])}</td>
<td>{html.escape(row["meaning"])}</td>
<td>{html.escape(row["recommendation"])}</td>
</tr>"""
        )
    return "<table><thead><tr><th>Риск</th><th>Сценарий</th><th>Факты</th><th>Пояснение</th><th>Что проверить</th></tr></thead><tbody>" + "".join(table_rows) + "</tbody></table>"


def _links_table(first_header: str, paths: list[Path]) -> str:
    rows = []
    for path in paths:
        name = path.name
        server = name.removeprefix("server-").removesuffix("-security-profile.html")
        rows.append(f'<tr><td>{html.escape(server)}</td><td><a href="/reports/{html.escape(name)}">{html.escape(name)}</a></td></tr>')
    return f"<table><thead><tr><th>{html.escape(first_header)}</th><th>Отчет</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"


def _style() -> str:
    return report_style()


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value)
