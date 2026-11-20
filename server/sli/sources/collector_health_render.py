"""Split out of ``server.sli.sources.collector_health`` (plan 7.2b).

Module-level names of ``collector_health`` are looked up through
``_src`` at call time, so tests that patch them there keep working.
"""

from __future__ import annotations

import server.sli.sources.collector_health as _src


def render_collector_health_report(data: dict[str, _src.Any]) -> str:
    items = data.get("items") or []
    rows = "".join(_src._row_html(item) for item in items) or '<tr><td colspan="17" class="muted">Нет данных о состоянии каналов.</td></tr>'
    perf_rows = _src._performance_rows(items)
    summary = data.get("summary") or {}
    post = data.get("post_collection") or {}
    post_summary = post.get("summary") or {}
    findings_refresh = post.get("findings_refresh") or {}
    operations_slo = data.get("operations_slo") or _src._operations_slo(items, summary, post)
    runtime_history = data.get("runtime_history") or {}
    storage_v2_outbox = data.get("storage_v2_outbox") or {}
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Состояние сбора</title>
{_src._style()}
<style>
.slo-card{{margin:18px 0;padding:22px 24px;border:1px solid var(--line);border-radius:16px;background:var(--panel)}}
.slo-card.slo-breached{{border-left:5px solid #c23737}} .slo-card.slo-attention{{border-left:5px solid #c98716}}
.slo-card.slo-met{{border-left:5px solid #178a5c}} .slo-card.slo-unknown{{border-left:5px solid #7f8b9d}}
.slo-state{{display:inline-block;padding:7px 11px;border-radius:999px;font-weight:700;background:#eef3fb;color:#253b5e}}
.slo-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:14px}}
.slo-grid div{{padding:13px;border:1px solid var(--line);border-radius:11px;background:#fbfcff}}
.slo-grid strong{{display:block;font-size:19px;color:var(--ink)}} .slo-grid span{{display:block;margin-top:5px;color:var(--muted);font-size:13px;line-height:1.35}}
.worker-card{{margin:18px 0;padding:22px 24px;border:1px solid var(--line);border-radius:16px;background:var(--panel);border-left:5px solid #4d72bf}}
.worker-card.worker-failed{{border-left-color:#c23737}} .worker-card.worker-completed{{border-left-color:#178a5c}}
</style>
</head>
<body>
{_src.report_controls()}
<main class="wrap">
  <header class="hero">
    <div>
       <div class="eyebrow">Состояние сбора</div><span class="sr-only">Техническое состояние сбора</span>
      <h1>Состояние сбора по каналам</h1>
      <p class="subtitle">Отчет по качеству данных: свежесть журналов, отставание, режим восстановления, таймауты и скорость чтения.</p>
      <div class="pillrow">
        {_src._pill('Сформирован', _src.format_event_time(data.get('generated_at_utc')))}
        {_src._pill('Каналов', summary.get('channels_total', 0))}
        {_src._pill('Security высокий/внимание', f"{summary.get('security_high', 0)} / {summary.get('security_warn', 0)}")}
        {_src._pill('Таймауты 24ч', summary.get('timeouts_24h', 0))}
        {_src._pill('Частичные 24ч', summary.get('partial_timeouts_24h', 0))}
        {_src._pill('Анализ: в очереди / выполняется', f"{post_summary.get('queued',0)} / {post_summary.get('running',0)}")}
        {_src._pill('Отчеты: готовы / с ошибкой', f"{post_summary.get('completed',0)} / {post_summary.get('failed',0)}")}
        {_src._pill('Актуально / почти актуально / догоняет', f"{summary.get('target_current',0)} / {summary.get('target_near_current',0)} / {summary.get('target_catching_up',0)}")}
        {_src._pill('Отклонённые обновления позиции', summary.get('cursor_rejected', 0))}
        {_src._pill('Зависшие задачи анализа', summary.get('stale_post_collection', 0))}
        {_src._pill('Обновление находок', findings_refresh.get('last_status') or findings_refresh.get('status') or '—')}
        {_src._pill('Разрыв по Event ID', findings_refresh.get('event_id_gap_estimate', '—'))}
      </div>
    </div>
  </header>
  {_src._operations_slo_html(operations_slo)}
  {_src._runtime_history_html(runtime_history)}
  {_src._storage_v2_outbox_html(storage_v2_outbox)}
  <section>
    <div class="section-title">
      <div>
        <h2>Где теряем время</h2>
        <p class="muted">Последний измеренный цикл по каналам: чтение с контроллера домена, ожидание БД, импорт, общая длительность, скорость и отставание. Это помогает понять, где возникает задержка: сеть, журнал Windows, запись на диск, БД или обработка отчётов.</p>
      </div>
    </div>
    <table>
      <thead><tr><th>Сервер</th><th>Журнал</th><th>Способ сбора</th><th>Событий/с</th><th>Чтение с DC</th><th>Очередь БД</th><th>Импорт БД</th><th>Повторные попытки</th><th>Итого по DC</th><th>Изменение номера записи</th><th>Изменение отставания</th><th>Вывод</th></tr></thead>
      <tbody>{perf_rows}</tbody>
    </table>
  </section>
  <section>
    <div class="section-title">
      <div>
        <h2>Каналы</h2>
        <p class="muted">Отставание Security больше 30 минут требует внимания, больше 2 часов — высокий риск. Если включен режим восстановления, канал догоняет накопленные события. Большое число пропущенных записей при малом числе новых может означать повторную обработку уже прочитанных событий.</p>
      </div>
      <div class="toolbar"><a class="button" href="/">На главную</a></div>
    </div>
    <table>
      <thead><tr><th>Сервер</th><th>Журнал</th><th>Последний цикл</th><th>Свежесть данных</th><th>Важность</th><th>Способ сбора</th><th>Последний запуск</th><th>Последнее событие</th><th>Последняя обработанная запись</th><th>Отставание</th><th>Что происходит</th><th>Добавлено / пропущено</th><th>Скорость / время</th><th>Позиция чтения / режим</th><th>Адаптивный лимит</th><th>Восстановление</th><th>Действия</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
</main>
</body>
</html>
"""


def _operations_slo_html(slo: dict[str, _src.Any]) -> str:
    status = str(slo.get("status") or "unknown")
    label = _src._e(slo.get("label") or "Недостаточно данных")
    current = int(slo.get("freshness_current") or 0)
    warning = int(slo.get("freshness_warning") or 0)
    breached = int(slo.get("freshness_breached") or 0)
    unknown = int(slo.get("freshness_unknown") or 0)
    channels = int(slo.get("security_channels") or 0)
    warning_minutes = int(slo.get("warning_minutes") or _src.COLLECTION_CURRENT_MINUTES)
    breach_minutes = int(slo.get("breach_minutes") or _src.COLLECTION_LAGGING_MINUTES)
    if status == "breached":
        explanation = (
            "Хотя бы один канал Security не прошёл проверку или его последняя успешная "
            "проверка просрочена. Проверьте доступ к источнику и состояние процесса сбора."
        )
    elif status == "attention":
        explanation = "Проверка каналов Security задерживается, не подтверждена или есть техническое предупреждение."
    elif status == "met":
        explanation = "Все наблюдаемые каналы Security укладываются в базовый порог свежести; таймаутов и зависших задач нет."
    else:
        explanation = "Недостаточно данных, чтобы оценить свежесть Security-каналов."
    return f"""
  <section class=\"slo-card slo-{_src._e(status)}\">
    <div class=\"section-title\">
      <div>
        <div class=\"eyebrow\">OPERATIONS-SLO-1 · базовый контроль</div>
        <h2>Работа сбора и свежесть данных</h2>
        <p class=\"muted\">{_src._e(explanation)}</p>
      </div>
      <span class=\"slo-state\">{label}</span>
    </div>
    <div class=\"slo-grid\">
      <div><strong>{current} из {channels}</strong><span>Security: актуальная проверка (до {warning_minutes} мин.)</span></div>
      <div><strong>{warning}</strong><span>Security: задержка {warning_minutes}–{breach_minutes} мин.</span></div>
      <div><strong>{breached}</strong><span>Security: ошибка или проверка старше {breach_minutes} мин.</span></div>
      <div><strong>{int(slo.get('timeouts_24h') or 0)} / {int(slo.get('partial_timeouts_24h') or 0)}</strong><span>таймауты / частичные чтения за 24 ч.</span></div>
      <div><strong>{int(slo.get('stale_post_collection') or 0)}</strong><span>зависшие задачи анализа</span></div>
    </div>
    {"<p class=\"muted\">Не удалось оценить свежесть каналов: " + str(unknown) + "</p>" if unknown else ""}
  </section>"""


def _runtime_history_html(history: dict[str, _src.Any]) -> str:
    items = history.get("items") or []
    if not items:
        return ""
    latest = items[0]
    status = str(latest.get("status") or "unknown")
    phase = str(latest.get("phase") or "—")
    worker = str(latest.get("worker_id") or "—")
    started = _src.format_event_time(latest.get("started_at") or latest.get("created_at"))
    duration = latest.get("duration_ms")
    duration_text = f"{round(int(duration) / 1000)} сек." if duration is not None else "выполняется"
    limits = latest.get("max_events_per_channel") or "—"
    servers = ", ".join(latest.get("servers_json") or []) or "подготавливаются"
    errors = latest.get("errors_json") or []
    error_note = f" Ошибка: {_src._e(errors[0])}" if errors else ""
    return f"""
  <section class=\"worker-card worker-{_src._e(status)}\">
    <div class=\"section-title\"><div><div class=\"eyebrow\">RUNTIME-ORCHESTRATOR-1</div><h2>Независимый worker сбора</h2>
    <p class=\"muted\">Последний самостоятельный запуск: <strong>{_src._e(status)}</strong>, этап: {_src._e(phase)}.{error_note}</p></div>
    <span class=\"slo-state\">{_src._e(status)}</span></div>
    <div class=\"slo-grid\"><div><strong>{_src._e(started)}</strong><span>время старта</span></div><div><strong>{_src._e(duration_text)}</strong><span>длительность</span></div>
    <div><strong>{_src._e(str(limits))}</strong><span>лимит на канал</span></div><div><strong>{_src._e(servers)}</strong><span>контроллеры домена</span></div></div>
    <p class=\"muted\">Владелец: {_src._e(worker)}. История хранится в PostgreSQL, поэтому не исчезает при перезапуске веб-сервера.</p>
  </section>"""


def _row_html(item: dict[str, _src.Any]) -> str:
    detail_url = _src._event_url(item)
    warnings = "; ".join(_src.translate_warning(value) for value in (item.get("warnings") or [])) or "—"
    severity = str(item.get("severity") or "unknown")
    return f"""<tr class="row-{_src._e(severity)}">
<td>{_src._e(item.get('server'))}</td>
<td>{_src._e(_src.channel_label(item.get('channel'), with_original=True))}</td>
<td>{_src._e(item.get('cycle_status_label') or _src.status_label(item.get('last_status')))}</td>
<td>{_src._e(item.get('freshness_label') or item.get('display_status') or _src.status_label(item.get('last_status')))}</td>
<td><span class="badge {_src._e(severity)}">{_src._e(_src.severity_label(severity))}</span></td>
<td>{_src._e(_src._backend_label(item))}</td>
<td class="mono" title="{_src._e(item.get('last_successful_collection_utc'))}">{_src._e(_src.format_event_time(item.get('last_successful_collection_utc')))}</td>
<td class="mono" title="{_src._e(item.get('last_event_time_utc'))}">{_src._e(_src.format_event_time(item.get('last_event_time_utc')))}</td>
<td class="mono">{_src._e(item.get('last_event_record_id'))}</td>
<td>{_src._e(_src._minutes(item.get('lag_minutes')))}</td>
<td>{_src._e(item.get('state_explanation'))}<br><span class="muted">{_src._e(warnings)}</span></td>
<td>{_src._e(item.get('inserted_skipped_ratio'))}</td>
<td>{_src._e(_src._speed_label(item))}</td>
<td>{_src._e(_src._cursor_label(item))}</td>
<td>{_src._e(item.get('adaptive_limit'))}<br><span class="muted">{_src._e(_src._adaptive_action_label(item.get('adaptive_action')))}</span></td>
<td>{_src._e(_src.status_label('on' if item.get('recovery_mode') else 'off'))}</td>
<td><a class="button" href="{_src._e(detail_url)}">Открыть события</a></td>
</tr>"""


def _performance_rows(items: list[dict[str, _src.Any]]) -> str:
    focused = [item for item in items if item.get("channel") == "Security"] or items
    rows = []
    for item in focused:
        rows.append(
            "<tr>"
            f"<td>{_src._e(item.get('server'))}</td>"
            f"<td>{_src._e(_src.channel_label(item.get('channel'), with_original=True))}</td>"
            f"<td>{_src._e(_src._backend_label(item))}</td>"
            f"<td>{_src._e(item.get('events_per_second') or '—')}</td>"
            f"<td>{_src._e(_src._sec(item.get('query_duration_ms')))}</td>"
            f"<td>{_src._e(_src._sec(item.get('import_queue_wait_ms')))}</td>"
            f"<td>{_src._e(_src._sec(item.get('import_duration_ms')))}</td>"
            f"<td>{_src._e(item.get('import_retry_count') if item.get('import_retry_count') is not None else '—')}</td>"
            f"<td>{_src._e(_src._sec(item.get('total_duration_ms')))}</td>"
            f"<td>{_src._e(item.get('last_record_id_delta') or '—')}</td>"
            f"<td>{_src._e(_src._lag_delta(item.get('lag_delta_minutes')))}</td>"
            f"<td>{_src._e(_src._performance_explanation(item))}</td>"
            "</tr>"
        )
    return "".join(rows) or '<tr><td colspan="12" class="muted">Метрики появятся после следующего цикла collector.</td></tr>'


def _performance_explanation(item: dict[str, _src.Any]) -> str:
    query = int(item.get("query_duration_ms") or 0)
    queue_ms = int(item.get("import_queue_wait_ms") or 0)
    import_ms = int(item.get("import_duration_ms") or 0)
    total = int(item.get("total_duration_ms") or 0)
    lag_delta = item.get("lag_delta_minutes")
    if total <= 0:
        return "нет замера"
    if lag_delta is not None:
        try:
            if int(lag_delta) > 0:
                return "backlog растет: нужен continuous recovery или больший лимит"
        except (TypeError, ValueError):
            pass
    biggest = max((query, "чтение с DC"), (queue_ms, "ожидание БД"), (import_ms, "импорт БД"), (max(0, total - query - queue_ms - import_ms), "прочие фазы"))[1]
    return f"главная видимая фаза: {biggest}"


def _summary(items: list[dict[str, _src.Any]]) -> dict[str, _src.Any]:
    security = [item for item in items if item.get("channel") == "Security"]
    return {
        "channels_total": len(items),
        "servers_total": len({item.get("server") for item in items if item.get("server")}),
        "timeouts_24h": sum(int(item.get("timeouts_24h") or 0) for item in items),
        "partial_timeouts_24h": sum(int(item.get("partial_timeouts_24h") or 0) for item in items),
        "high": sum(1 for item in items if item.get("severity") == "high"),
        "warn": sum(1 for item in items if item.get("severity") == "warn"),
        "security_high": sum(1 for item in security if item.get("severity") == "high"),
        "security_warn": sum(1 for item in security if item.get("severity") == "warn"),
        "target_current": sum(1 for item in items if item.get("target_state") == "current"),
        "target_near_current": sum(1 for item in items if item.get("target_state") == "near_current"),
        "target_catching_up": sum(1 for item in items if item.get("target_state") == "catching_up"),
        "cursor_rejected": sum(1 for item in items if item.get("cursor_commit_decision") == "rejected"),
    }


def _adaptive_action_label(value: _src.Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "—"
    parts = [part.strip() for part in raw.split(";")]
    action_part = parts[0] if parts else raw
    action, _, reason = action_part.partition(":")
    actions = {
        "keep": "лимит сохранен",
        "increase_limit": "лимит увеличен",
        "decrease_limit": "лимит уменьшен",
    }
    reasons = {
        "stable": "стабильная работа",
        "completed_streak": "серия успешных сборов",
        "partial_timeout": "частичный таймаут",
        "timeout": "таймаут",
        "failed": "ошибка сбора",
        "skipped_gt_inserted_x2": "много повторно прочитанных событий",
    }
    label = actions.get(action, action or "действие")
    if reason:
        label += f": {reasons.get(reason, reason)}"
    if len(parts) > 1 and "->" in parts[1]:
        label += f"; {parts[1].replace('->', ' → ')}"
    if len(parts) > 2 and parts[2].startswith("recovery="):
        mode = parts[2].split("=", 1)[1].strip()
        label += "; восстановление " + ("включено" if mode == "on" else "выключено")
    return label


def _cursor_label(item: dict[str, _src.Any]) -> str:
    strategy = str(item.get("cursor_strategy") or "time_window")
    mode = str(item.get("requested_collection_mode") or item.get("collection_mode") or "auto")
    strategy_labels = {
        "record_id": "EventRecordID",
        "time_window": "окно времени",
        "time_window_fallback": "fallback к времени",
    }
    mode_labels = {
        "current": "текущий",
        "backfill": "backfill",
        "recovery": "восстановление",
        "auto": "auto",
    }
    label = f"{strategy_labels.get(strategy, strategy)} · {mode_labels.get(mode, mode)}"
    if item.get("cursor_fallback_reason"):
        label += f" · {item.get('cursor_fallback_reason')}"
    if item.get("cursor_commit_decision"):
        label += f" · commit={item.get('cursor_commit_decision')}"
    if item.get("cursor_commit_reason"):
        label += f" ({item.get('cursor_commit_reason')})"
    return label


def _speed_label(item: dict[str, _src.Any]) -> str:
    eps = item.get("events_per_second")
    total = item.get("total_duration_ms")
    bits = []
    query = item.get("query_duration_ms")
    import_ms = item.get("import_duration_ms")
    queue_ms = item.get("import_queue_wait_ms")
    retry_count = item.get("import_retry_count")
    if eps is not None:
        bits.append(f"{eps} событий/с")
    if query:
        bits.append(f"сбор {round(int(query)/1000, 1)} с")
    if queue_ms:
        bits.append(f"очередь БД {round(int(queue_ms)/1000, 1)} с")
    if import_ms:
        bits.append(f"импорт {round(int(import_ms)/1000, 1)} с")
    if retry_count:
        bits.append(f"retry {retry_count}")
    if total:
        bits.append(f"итого {round(int(total)/1000, 1)} с")
    return " · ".join(bits) or "появится после следующего запуска collector"


def _event_observation_label(
    channel: str | None,
    status: str | None,
    event_lag_minutes: int | None,
    collection_lag_minutes: int | None,
    recovery_mode: bool,
) -> str:
    """Describe event observation without treating a quiet channel as a failed poll."""
    collection_state = _src._collection_state(status, collection_lag_minutes)
    if collection_state == "error":
        return "состояние событий не подтверждено"
    if collection_state == "stale":
        return "нужна новая проверка канала"
    if channel == "Security" and recovery_mode and (event_lag_minutes or 0) > _src.STALE_WARNING_MINUTES:
        return "события догоняются"
    if channel == "Security" and (event_lag_minutes is None or event_lag_minutes > _src.STALE_WARNING_MINUTES):
        return "события отстают"
    if event_lag_minutes is None or event_lag_minutes > _src.STALE_WARNING_MINUTES:
        return "новых событий не обнаружено"
    return "события актуальны"
