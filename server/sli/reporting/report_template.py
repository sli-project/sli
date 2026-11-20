from __future__ import annotations

import html
import json
from typing import Any

from server.sli.reporting.report_ui import report_controls, report_style
from server.source_packs.registry import resolve_source_normalizer


def _reference_event_ids() -> tuple[int, ...]:
    normalizer = resolve_source_normalizer("Security")
    if normalizer is None:
        return ()
    families = (
        "successful_logon",
        "explicit_credentials",
        "security_log_cleared",
    )
    return tuple(
        event_id
        for family in families
        for event_id in normalizer.event_ids_for_analysis_family(family)[:1]
    )


def render_target_report(context: dict[str, Any]) -> str:
    event_rows_json = _json_for_html_script(context.get("event_rows", []))
    raw_score = context.get("risk_score")
    score_available = (
        isinstance(raw_score, (int, float)) and not isinstance(raw_score, bool)
    )
    score = int(raw_score) if score_available else 0
    score_width = max(0, min(score, 100))
    score_text = f"{score}<span>/100</span>" if score_available else "—"
    server_links = context.get("server_links") or []
    server_links_section = _server_links_section(server_links) if server_links else ""
    reference_event_ids = _reference_event_ids()
    search_event_id = reference_event_ids[0] if reference_event_ids else "Event ID"
    reference_links = "".join(
        "<li><a href="
        f'"https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{event_id}">'
        f"Microsoft: Event {event_id}</a></li>"
        for event_id in reference_event_ids
    )

    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(context["title"])}</title>
{_style(score_width)}
</head>
<body>
{report_controls()}
<header class="wrap report-hero">
  <div class="hero-grid">
    <div>
      <h1>{_e(context["title"])}</h1>
      <div class="subtitle">{_e(context["subtitle"])}</div>
      <div class="pillrow">
        {_pill("Объект", context["scope_name"])}
        {_pill("Окно UTC", context["period_text"])}
        {_pill("Событий", str(context["total_events"]))}
        {_pill("Главный шум", context["main_noise"], context.get("main_noise_class", ""))}
        {_pill("Покрытие", context["coverage_status"], context.get("coverage_class", ""))}
        {_pill("Режим", context["analysis_mode"])}
      </div>
    </div>
    <div class="score">
      <div class="label">Оценка угрозы</div>
      <div class="num">{score_text}</div>
      <div class="bar" aria-label="threat score"><i></i></div>
      <small>{_e(context["risk_note"])}</small>
    </div>
  </div>
</header>

<nav>
  <div class="wrap navrow">
    <a href="#summary">Сводка</a>
    <a href="#actions">Что делать</a>
    <a href="#risks">Риски</a>
    <a href="#coverage">Покрытие</a>
    <a href="#correlation">Корреляции</a>
    <a href="#events">События</a>
    <a href="#sources">Источники</a>
  </div>
</nav>

<main class="wrap">
  <section id="summary">
    <h2>1. Краткая сводка для администратора / ИБ</h2>
    <div class="grid kpi">
      {_kpi_cards(context["kpis"])}
    </div>
    <div class="grid two mt">
      <div class="callout"><h3>Главный вывод</h3><p>{_e(context["main_conclusion"])}</p></div>
      <div class="badcallout"><h3>Главное ограничение</h3><p>{_e(context["main_limitation"])}</p></div>
    </div>
    <h3 class="mt">Распределение событий</h3>
    {_timeline(context["channel_rows"])}
  </section>

  <section id="actions">
    <h2>2. Что делать первым</h2>
    <div class="grid three actions">
      {_action_cards(context["actions"])}
    </div>
  </section>

  <section id="risks">
    <h2>3. Карта рисков и объяснение критичности</h2>
    <div class="grid two">
      {_finding_cards(context["findings"])}
    </div>
  </section>

  <section id="coverage">
    <h2>4. Покрытие логирования DC</h2>
    <div class="matrix">
      <div class="head">Контроль</div><div class="head">Статус в выборке</div><div class="head">Как интерпретировать</div>
      {_coverage_rows(context["coverage_rows"])}
    </div>
  </section>

  <section id="correlation">
    <h2>5. Корреляция событий и пояснения</h2>
    <p class="muted">Этот раздел сопоставляет события по Event ID, учетным записям, источникам и каналам. Это аналитическая подсказка для ручной проверки специалистом ИБ.</p>
    {_correlation_table(context["correlation_rows"])}
  </section>

  <section id="events">
    <h2>6. Детальная таблица событий с фильтрами</h2>
    <p class="muted">Таблица является вторым уровнем: сначала читаем выводы, затем проверяем доказательства по Event ID и каналам.</p>
    <div class="filters">
      <input id="q" placeholder="Поиск: DNS, {search_event_id}, Security..." oninput="renderRows()">
      <select id="risk" onchange="renderRows()">
        <option value="">Все риски</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
      </select>
      <select id="channel" onchange="renderRows()">
        <option value="">Все каналы</option>
        {_channel_options(context["event_rows"])}
      </select>
      <button onclick="resetFilters()">Сбросить</button>
    </div>
    <table id="eventTable">
      <thead><tr><th>Risk</th><th>Event ID</th><th>Канал</th><th>Provider</th><th>Кол-во</th><th>Описание</th><th>Почему важно</th><th>Детали</th><th>Действие</th><th>Недостающие поля</th></tr></thead>
      <tbody></tbody>
    </table>
  </section>

  {server_links_section}

  <section id="sources">
    <h2>7. Исходные данные, допущения и ограничения</h2>
    <div class="grid two">
      <div class="card"><h3>Наблюдаемые факты</h3>{_list(context["source_facts"])}</div>
      <div class="card"><h3>Допущения</h3>{_list(context["assumptions"])}</div>
    </div>
    <details>
      <summary>Справочные ссылки и следующий этап</summary>
      <div>
        <ul>
          {reference_links}
          <li>Следующий шаг проекта: усилить корреляции по LogonId, IP/Workstation, TargetUser, ProcessName и Kerberos-полям.</li>
        </ul>
      </div>
    </details>
    <p class="footer">Отчет самодостаточный: CSS и JS встроены, внешние библиотеки не требуются. Автоматические рекомендации не выполняют действий в AD.</p>
  </section>
</main>

<script>
const rows = {event_rows_json};
function escapeHtml(value) {{
  return String(value ?? '').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
}}
function badge(risk) {{
  const cls = String(risk || 'Info').toLowerCase();
  return `<span class="risk-badge risk-${{escapeHtml(cls)}}">${{escapeHtml(risk)}}</span>`;
}}
function renderRows() {{
  const q = document.getElementById('q').value.toLowerCase();
  const risk = document.getElementById('risk').value;
  const channel = document.getElementById('channel').value;
  const body = document.querySelector('#eventTable tbody');
  const filtered = rows.filter((row) =>
    (!risk || row.risk === risk) &&
    (!channel || row.channel === channel) &&
    (!q || Object.values(row).join(' ').toLowerCase().includes(q))
  );
  body.innerHTML = filtered.map((row) => `<tr>
    <td>${{badge(row.risk)}}</td>
    <td class="mono"><a href="${{escapeHtml(row.detail_url)}}" title="Открыть событие">${{escapeHtml(row.event_id)}}</a></td>
    <td>${{escapeHtml(row.channel)}}</td>
    <td class="mono">${{escapeHtml(row.provider_name)}}</td>
    <td>${{escapeHtml(row.count)}}</td>
    <td>${{escapeHtml(row.description)}}</td>
    <td>${{escapeHtml(row.why)}}</td>
    <td><a class="detail-link" href="${{escapeHtml(row.detail_url)}}">Открыть события</a></td>
    <td>${{escapeHtml(row.action)}}</td>
    <td>${{escapeHtml(row.missing)}}</td>
  </tr>`).join('') || '<tr><td colspan="10" class="muted">Ничего не найдено</td></tr>';
}}
function resetFilters() {{
  document.getElementById('q').value = '';
  document.getElementById('risk').value = '';
  document.getElementById('channel').value = '';
  renderRows();
}}
renderRows();
</script>
</body>
</html>
"""


def _e(value: Any) -> str:
    return html.escape(str(value))


def _json_for_html_script(value: Any) -> str:
    """Serialize JSON without allowing data to terminate an HTML script element."""
    return (
        json.dumps(value, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _pill(name: str, value: Any, cls: str = "") -> str:
    class_attr = f"pill {cls}".strip()
    return f'<span class="{_e(class_attr)}"><strong>{_e(name)}:</strong> {_e(value)}</span>'


def _kpi_cards(items: list[dict[str, Any]]) -> str:
    parts = []
    for item in items:
        parts.append(
            f"""<div class="card kpi-card {_e(item.get("risk", ""))}">
<div class="value">{_e(item["value"])}</div>
<div class="name">{_e(item["name"])}</div>
<div class="hint">{_e(item["hint"])}</div>
</div>"""
        )
    return "".join(parts)


def _action_cards(items: list[dict[str, Any]]) -> str:
    parts = []
    for item in items:
        points = "".join(f"<li>{_e(point)}</li>" for point in item.get("points", []))
        parts.append(
            f"""<div class="card action {_e(item.get("risk", "info"))}">
<h3>{_e(item["title"])}</h3>
<p class="muted">{_e(item["body"])}</p>
<ul>{points}</ul>
</div>"""
        )
    return "".join(parts)


def _finding_cards(items: list[dict[str, Any]]) -> str:
    parts = []
    for item in items:
        evidence = _evidence_refs(item.get("evidence_refs") or [])
        parts.append(
            f"""<div class="card {_e(item.get("severity", "info"))}">
<div class="finding-title"><h3>{_e(item["title"])}</h3>{_risk_badge(item.get("severity", "info"))}</div>
<p><strong>Факт:</strong> {_e(item["facts"])}</p>
<p><strong>Почему важно:</strong> {_e(item["why_it_matters"])}</p>
<p><strong>Действие:</strong> {_e(item["recommended_action"])}</p>
{evidence}
<p class="confidence">Уверенность: {_e(item.get("confidence", "средняя"))}. Недостающие данные: {_e(item.get("missing_data", "не указано"))}</p>
</div>"""
        )
    return "".join(parts)


def _evidence_refs(refs: list[dict[str, Any]]) -> str:
    if not refs:
        return '<p class="muted evidence-empty">Evidence-ссылки появятся после привязки finding к конкретным Event ID.</p>'
    parts = []
    for ref in refs:
        meta = []
        if ref.get("time_from") or ref.get("time_to"):
            meta.append(f"UTC: {_e(ref.get('time_from') or '...')} → {_e(ref.get('time_to') or '...')}")
        if ref.get("servers"):
            meta.append("servers: " + _e(", ".join(str(item) for item in ref.get("servers") or [])))
        parts.append(
            f"""<div class="evidence-ref">
<div class="evidence-meta"><strong>{_e(ref.get("label", "Evidence"))}</strong>{' · ' + ' · '.join(meta) if meta else ''}</div>
<div class="evidence-fields">
  <span>actor: {_e(ref.get("actor", "см. EventData"))}</span>
  <span>target: {_e(ref.get("target", "см. EventData"))}</span>
  <span>source: {_e(ref.get("source", "см. EventData"))}</span>
</div>
<div class="evidence-actions">
  <a class="detail-link" href="{_e(ref.get("detail_url", "#"))}">Открыть события-доказательства</a>
  <a class="detail-link secondary" href="{_e(ref.get("neighbors_url", ref.get("detail_url", "#")))}">Соседние события ±15 минут</a>
</div>
</div>"""
        )
    return '<div class="evidence-box"><div class="evidence-title">Evidence</div>' + "".join(parts) + "</div>"


def _coverage_rows(rows: list[dict[str, Any]]) -> str:
    parts = []
    for row in rows:
        status = row["status"]
        cls = "status-ok" if status == "Собирается" else "status-miss"
        event_id = row.get("event_id")
        control = row["name"] if event_id == "-" else f'{row["name"]} ({event_id})'
        parts.append(
            f"""<div>{_e(control)}</div>
<div class="{cls}">{_e(status)}</div>
<div>{_e(row["source"])} {_e(row["recommendation"])}</div>"""
        )
    return "".join(parts)


def _correlation_table(rows: list[dict[str, Any]]) -> str:
    body = []
    for row in rows:
        body.append(
            f"""<tr>
<td>{_risk_badge(row["risk"])}</td>
<td>{_e(row["scenario"])}</td>
<td>{_e(row["facts"])}</td>
<td>{_e(row["meaning"])}</td>
<td>{_e(row["recommendation"])}</td>
<td>{_e(row.get("confidence", "средняя"))}</td>
</tr>"""
        )
    return "<table><thead><tr><th>Риск</th><th>Сценарий</th><th>Факты</th><th>Пояснение</th><th>Что проверить</th><th>Уверенность</th></tr></thead><tbody>" + "".join(body) + "</tbody></table>"


def _timeline(channel_rows: list[dict[str, Any]]) -> str:
    total = sum(int(row.get("count") or 0) for row in channel_rows)
    if total <= 0:
        return '<div class="callout">Нет событий для распределения по каналам.</div>'
    segments = []
    legend = []
    for row in channel_rows:
        count = int(row.get("count") or 0)
        width = max(2, round(count * 100 / total, 2))
        cls = _channel_class(row["channel"])
        segments.append(f'<div class="seg {cls}" style="width:{width}%"></div>')
        legend.append(f'<span><i class="dot {cls}"></i>{_e(row["channel"])} - {_e(count)}</span>')
    return f'<div class="timeline">{"".join(segments)}</div><div class="legend">{"".join(legend)}</div>'


def _channel_class(channel: str) -> str:
    lowered = channel.lower()
    if "security" in lowered:
        return "security"
    if "dns" in lowered:
        return "dns"
    if "system" in lowered:
        return "system"
    return "other"


def _risk_badge(risk: str) -> str:
    value = _display_risk(risk)
    return f'<span class="risk-badge risk-{_e(value.lower())}">{_e(value)}</span>'


def _display_risk(risk: str) -> str:
    mapping = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
    return mapping.get(str(risk).lower(), str(risk))


def _channel_options(rows: list[dict[str, Any]]) -> str:
    channels = sorted({str(row.get("channel") or "") for row in rows if row.get("channel")})
    return "".join(f"<option>{_e(channel)}</option>" for channel in channels)


def _list(items: list[str]) -> str:
    if not items:
        return '<p class="muted">Нет данных.</p>'
    return "<ul>" + "".join(f"<li>{_e(item)}</li>" for item in items) + "</ul>"


def _server_links_section(links: list[dict[str, str]]) -> str:
    rows = "".join(
        f'<tr><td>{_e(item["name"])}</td><td><a href="{_e(item["url"])}">{_e(item["file"])}</a></td></tr>'
        for item in links
    )
    return f"""<section id="servers">
<h2>7. Отчеты по контроллерам домена</h2>
<table><thead><tr><th>Сервер</th><th>Отчет</th></tr></thead><tbody>{rows}</tbody></table>
</section>"""



def _style(score_width: int) -> str:
    return report_style(score_width=score_width)
