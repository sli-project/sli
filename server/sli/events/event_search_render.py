from __future__ import annotations

from typing import Any

from server.sli.events.event_details import make_event_detail_url
from server.sli.events.event_search_filters import (
    DEFAULT_SEARCH_LIMIT,
    _datetime_local_input_value,
    make_account_timeline_url,
    make_deep_search_url,
    make_search_url,
)
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.reporting.reporting_common import (
    format_html_escape,
    format_html_pill,
)
from server.sli.reporting.ui_labels import channel_label, event_id_label


def render_event_search_report(data: dict[str, Any]) -> str:
    filters = data.get("filters") or {}
    items = data.get("items") or []
    mode = str(data.get("mode") or "fast")
    deep = mode == "deep"
    q = filters.get("q") or ""
    account = filters.get("account") or q
    rows_html = _search_rows(items) or '<tr><td colspan="9" class="muted">События не найдены в ограниченном периоде. Проверьте точное значение или задайте другой период.</td></tr>'
    timeline_url = make_account_timeline_url(account, limit=500, time_from=filters.get("time_from"), time_to=filters.get("time_to")) if account else "/reports/account-timeline.html"
    deep_url = make_deep_search_url(q=q, account=filters.get("account"), limit=min(int(filters.get("limit") or 200), 200), time_from=filters.get("time_from"), time_to=filters.get("time_to"), order=filters.get("order"))
    fast_url = make_search_url(q=q, account=filters.get("account"), limit=filters.get("limit"), time_from=filters.get("time_from"), time_to=filters.get("time_to"), order=filters.get("order"))
    next_url = _next_page_url(data, route="deep" if deep else "fast")
    warning = data.get("warning")
    warning_html = f'<div class="badcallout"><strong>Запрос остановлен безопасно:</strong> {_e(warning)}</div>' if warning else ""
    pagination_html = f'<div class="toolbar"><a class="button primary" href="{_e(next_url)}">Показать ещё</a></div>' if next_url else ""
    title = "Поиск по тексту событий" if deep else "Быстрый поиск по журналам и событиям"
    subtitle = (
        "Ищет текст внутри событий только за выбранный период. Для ускорения показываются найденные события без подсчёта их общего количества."
        if deep
        else "Ищет учётную запись (полное имя или начало логина), IP, LogonId и Event ID. Запрос ищется по всему доступному архиву; пустой запрос ограничен последними 24 часами. Message и EventData не сканируются."
    )
    switch_link = f'<a class="button" href="{_e(fast_url)}">Вернуться к быстрому поиску</a>' if deep else f'<a class="button" href="{_e(deep_url)}">Поиск по тексту события</a>'
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
  <header class="hero calm">
    <div class="eyebrow">{'Поиск по содержимому события' if deep else 'Быстрый поиск'}</div>
    <h1>{_e(title)}</h1>
    <p class="subtitle">{_e(subtitle)}</p>
    {_search_form(filters, action='/reports/search-deep.html' if deep else '/reports/search.html', deep=deep)}
    <div class="pillrow">
      {_pill('Показано', len(items))}
      {_pill('Есть ещё', 'да' if data.get('has_more') else 'нет')}
      {_pill('Период с', filters.get('time_from') or '—')}
      {_pill('Порядок', 'старые → новые' if filters.get('order') == 'asc' else 'новые → старые')}
    </div>
    <div class="toolbar top-toolbar">
      <a class="button primary" href="{_e(timeline_url)}">Показать цепочку по учётной записи</a>
      {switch_link}
      <a class="button" href="/">На главную</a>
    </div>
    {warning_html}
  </header>

  <section>
    <div class="callout"><strong>Результаты поиска:</strong> показаны первые найденные события. Если нужны более ранние, нажмите «Показать ещё».</div>
    <div class="section-title">
      <div>
        <h2>Найденные события</h2>
        <p class="muted">События отсортированы по времени: сначала {"старые" if filters.get("order") == "asc" else "новые"}.</p>
      </div>
    </div>
    <table>
      <thead><tr><th>Время</th><th>Сервер</th><th>Журнал</th><th>Тип события</th><th>Что это значит</th><th>Инициатор</th><th>Цель</th><th>Источник</th><th>Действия</th></tr></thead>
      <tbody>{rows_html}</tbody>
    </table>
    {pagination_html}
  </section>
</main>
</body>
</html>"""


def render_account_timeline_report(data: dict[str, Any]) -> str:
    account = data.get("account") or ""
    items = data.get("chain") or []
    summary = data.get("summary") or {}
    filters = data.get("filters") or {}
    timeline_html = _timeline_html(items) or '<div class="empty">Для этой учётной записи не найдено ключевых событий в ограниченном периоде.</div>'
    raw_url = make_search_url(q=account, account=account, limit=500, order="desc", time_from=filters.get("time_from"), time_to=filters.get("time_to")) if account else "/reports/search.html"
    details_url = make_event_detail_url(user=account, limit=500, order="desc") if account else "/reports/event-details.html"
    next_url = _next_page_url(data, route="timeline")
    pagination_html = f'<div class="toolbar"><a class="button primary" href="{_e(next_url)}">Показать ещё</a></div>' if next_url else ""
    warning = data.get("warning")
    warning_html = f'<div class="badcallout"><strong>Запрос остановлен безопасно:</strong> {_e(warning)}</div>' if warning else ""
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Цепочка событий: {_e(account or 'учётная запись')}</title>
{_style()}
</head>
<body>
{report_controls()}
<main class="wrap">
  <header class="hero calm">
    <div class="eyebrow">История учётной записи</div>
    <h1>Цепочка событий по учётной записи</h1>
    <p class="subtitle">История действий, где учётная запись выступала инициатором или целью. Поиск выполняется по основным полям события.</p>
    {_search_form({**filters, 'q': account}, action='/reports/account-timeline.html')}
    <div class="summary-strip">
      {_metric('Учётная запись', account or '—')}
      {_metric('Показано', summary.get('total', 0))}
      {_metric('Входы', summary.get('logons', 0))}
      {_metric('Пароль / блокировки', summary.get('password_or_lockout', 0))}
      {_metric('Группы / права', summary.get('privileged_or_group', 0))}
    </div>
    <div class="toolbar top-toolbar">
      <a class="button primary" href="{_e(raw_url)}">Быстрый поиск</a>
      <a class="button" href="{_e(details_url)}">Все найденные события</a>
      <a class="button" href="/">На главную</a>
    </div>
    {warning_html}
  </header>

  <section>
    <div class="section-title">
      <div>
        <h2>Хронология событий</h2>
        <p class="muted">Если нужно больше событий, нажмите «Показать ещё».</p>
      </div>
    </div>
    <div class="timeline">{timeline_html}</div>
    {pagination_html}
  </section>
</main>
</body>
</html>"""


def _next_page_url(data: dict[str, Any], *, route: str) -> str | None:
    cursor = data.get("next_cursor")
    if not cursor:
        return None
    filters = dict(data.get("filters") or {})
    kwargs = {
        "q": filters.get("q"),
        "account": filters.get("account"),
        "event_ids": filters.get("event_ids"),
        "channel": filters.get("channel"),
        "servers": filters.get("servers"),
        "limit": filters.get("limit"),
        "time_from": filters.get("time_from"),
        "time_to": filters.get("time_to"),
        "order": filters.get("order"),
        "risk": filters.get("risk"),
        "tier": filters.get("tier"),
        "cursor": cursor,
    }
    if route == "deep":
        return make_deep_search_url(**kwargs)
    if route == "timeline":
        kwargs.pop("account", None)
        return make_account_timeline_url(str(data.get("account") or ""), **kwargs)
    return make_search_url(**kwargs)


def _search_rows(items: list[dict[str, Any]]) -> str:
    rows = []
    for row in items:
        detail_url = make_event_detail_url(event_id=row.get("event_id"), channel=row.get("channel"), servers=[row.get("server")] if row.get("server") else [], limit=100, order="desc")
        account = _best_account(row)
        timeline_url = make_account_timeline_url(account, limit=500) if account and account != "—" else ""
        rows.append(f"""<tr>
<td class="mono" title="{_e(row.get('time_created_utc'))}">{_e(row.get('time_created_utc_display'))}</td>
<td>{_e(row.get('server'))}</td>
<td>{_e(channel_label(row.get('channel'), with_original=True))}</td>
<td class="mono">{_e(event_id_label(row.get('event_id')))}</td>
<td><span class="badge {_e(row.get('severity'))}">{_e(row.get('label'))}</span><div class="muted small-text">{_e(row.get('summary'))}</div></td>
<td>{_e(row.get('subject'))}</td>
<td>{_e(row.get('target'))}</td>
<td>{_e(row.get('source'))}</td>
<td><div class="actions"><a class="button small" href="{_e(detail_url)}">Открыть событие</a>{f'<a class="button small" href="{_e(timeline_url)}">Цепочка учётной записи</a>' if timeline_url else ''}</div></td>
</tr>""")
    return "".join(rows)


def _timeline_html(items: list[dict[str, Any]]) -> str:
    rows = []
    for item in items:
        rows.append(f"""<article class="timeline-item { _e(item.get('severity')) }">
  <div class="timeline-marker"></div>
  <div class="timeline-card">
    <div class="timeline-head">
      <div><strong>{_e(item.get('label'))}</strong><div class="muted mono" title="{_e(item.get('time'))}">{_e(item.get('time_display'))}</div></div>
      <span class="badge {_e(item.get('severity'))}">{_e(event_id_label(item.get('event_id')))}</span>
    </div>
    <p>{_e(item.get('summary'))}</p>
    <div class="timeline-meta">
      <span>Сервер: <b>{_e(item.get('server'))}</b></span>
      <span>Журнал: <b>{_e(channel_label(item.get('channel'), with_original=True))}</b></span>
      <span>Инициатор: <b>{_e(item.get('subject'))}</b></span>
      <span>Цель: <b>{_e(item.get('target'))}</b></span>
      <span>Источник: <b>{_e(item.get('source'))}</b></span>
    </div>
    <a class="button small" href="{_e(item.get('detail_url'))}">Открыть событие</a>
  </div>
</article>""")
    return "".join(rows)


def _best_account(row: dict[str, Any]) -> str:
    target = str(row.get("target") or "").strip()
    subject = str(row.get("subject") or "").strip()
    return target if target and target != "—" else subject


def _facets_html(facets: dict[str, Any]) -> str:
    by_channel = facets.get("by_channel") or []
    by_event = facets.get("by_event_id") or []
    if not by_channel and not by_event:
        return ""
    channel_html = "".join(f'<span class="facet">{_e(channel_label(row.get("channel"), with_original=True))}: <b>{_e(row.get("count"))}</b></span>' for row in by_channel)
    event_html = "".join(f'<span class="facet">{_e(event_id_label(row.get("event_id")))}: <b>{_e(row.get("count"))}</b></span>' for row in by_event)
    return f"""<section class="facets">
      <h2>Срез результатов</h2>
      <div class="facet-row">{channel_html}</div>
      <div class="facet-row">{event_html}</div>
    </section>"""


def _search_form(filters: dict[str, Any], *, action: str, deep: bool = False) -> str:
    q = filters.get("q") or filters.get("account") or ""
    placeholder = "Текст события" if deep else "Логин, IP, LogonId или Event ID"
    time_from = _datetime_local_input_value(filters.get("time_from"))
    time_to = _datetime_local_input_value(filters.get("time_to"))
    order = filters.get("order") or "desc"
    limit = filters.get("limit") or DEFAULT_SEARCH_LIMIT
    button = "Глубокий поиск" if deep else "Найти"
    return f"""<form class="search-form" method="get" action="{_e(action)}">
      <input name="q" value="{_e(q)}" placeholder="{_e(placeholder)}" autofocus>
      <label>С <input type="datetime-local" name="time_from" value="{_e(time_from)}" step="60" title="Локальное время сервера"></label>
      <label>По <input type="datetime-local" name="time_to" value="{_e(time_to)}" step="60" title="Локальное время сервера"></label>
      <input type="hidden" name="order" value="{_e(order)}">
      <input type="hidden" name="limit" value="{_e(limit)}">
      <button type="submit">{button}</button>
    </form>"""


def _metric(name: str, value: Any) -> str:
    return f'<div class="metric"><span>{_e(name)}</span><strong>{_e(value)}</strong></div>'


_pill = format_html_pill


def _shorten(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


_e = format_html_escape


def _style() -> str:
    return report_style()
