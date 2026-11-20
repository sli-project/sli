from __future__ import annotations

import html
from typing import Any

from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.storage.storage_policy import get_storage_health
from server.sli.core.time_format import format_event_time


def _cell(value: object) -> str:
    return html.escape(str(value if value not in (None, "") else "—"))


def _growth_quality(value: object) -> str:
    labels = {
        "measured": "измерено по истории",
        "measured_partial": "предварительная оценка по короткой истории",
        "estimated_until_24h_history": "предварительная оценка",
        "pending": "нужно накопить данные",
        "baseline_changed": "нужно накопить данные после оптимизации",
    }
    return labels.get(str(value), "оценка уточняется")


def render_storage_health_report(data: dict[str, Any] | None = None) -> str:
    """Render a decision-first storage report; diagnostics remain available below."""
    data = data or get_storage_health()
    overview = data.get("project_overview") or {}
    pressure = data.get("disk_pressure") or {}
    disk = pressure.get("disk") or {}
    lifecycle = data.get("storage_lifecycle") or {}
    forecast = overview.get("forecast") or {}
    thresholds = forecast.get("thresholds") or {}
    warning = thresholds.get("warn") or {}
    cleanup = data.get("cleanup_preview") or {}
    pg_ops = data.get("postgres_operations") or {}
    pg_db = pg_ops.get("database") or {}
    sizes = data.get("sizes") or {}
    warnings = data.get("warnings") or []
    guidance = data.get("operator_guidance") or []
    table_rows = "".join(
        f"<tr><td>{_cell(item.get('table_name'))}</td><td>{_cell(item.get('total_human'))}</td><td>{_cell(item.get('live_rows'))}</td><td>{_cell(item.get('dead_row_ratio'))}</td></tr>"
        for item in (pg_ops.get("tables") or [])
    ) or '<tr><td colspan="4">Данные пока недоступны.</td></tr>'
    size_rows = "".join(
        f"<tr><td>{_cell(name)}</td><td>{_cell(item.get('human'))}</td><td>{_cell(item.get('files_seen'))}</td></tr>"
        for name, item in sizes.items()
    )
    warning_html = "".join(f"<li>{_cell(item)}</li>" for item in warnings) or "<li>Критичных ограничений нет.</li>"
    guidance_html = "".join(f"<li>{_cell(item)}</li>" for item in guidance) or "<li>Действий не требуется.</li>"
    forecast_days = warning.get("estimated_days")
    forecast_text = f"примерно через {forecast_days:.0f} дн." if isinstance(forecast_days, (int, float)) else "нужно накопить наблюдения"
    growth_value = overview.get("growth_human_per_day") or "нужно накопить данные"
    if growth_value not in {"нужно накопить данные", "измерение начинается"}:
        growth_value = f"около {growth_value} в сутки"
    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Хранилище — Security Log Intelligence</title>{report_style()}</head>
<body>{report_controls()}<main class="wrap">
<header class="hero"><div class="eyebrow">ХРАНИЛИЩЕ ПРОЕКТА</div><h1>Место, рост и запас</h1><p class="subtitle">Главная цифра учитывает файлы проекта и PostgreSQL отдельно — без смешивания с историческими снимками до оптимизации.</p><div class="grid kpi"><article class="kpi-card"><span>Объём системы</span><br><strong>{_cell(overview.get('total_human'))}</strong><br><small>файлы приложения и база данных</small></article><article class="kpi-card"><span>Файлы приложения</span><br><strong>{_cell(overview.get('project_files_human'))}</strong><br><small>код, журналы, отчёты и резервные копии</small></article><article class="kpi-card"><span>База данных</span><br><strong>{_cell(overview.get('database_human') or pg_db.get('database_human'))}</strong><br><small>{_cell(pg_db.get('database_name'))}</small></article><article class="kpi-card"><span>Прогноз роста</span><br><strong>{_cell(growth_value)}</strong><br><small>{_cell(_growth_quality(overview.get('growth_quality')))}</small></article><article class="kpi-card"><span>Свободно на диске</span><br><strong>{_cell(disk.get('free_human'))}</strong><br><small>{_cell(disk.get('free_percent'))}% свободно</small></article><article class="kpi-card"><span>До зоны внимания</span><br><strong>{forecast_text}</strong><br><small>до резерва в 15% свободного места</small></article></div></header>
<section><div class="section-title"><div><h2>Что это означает</h2><p class="muted">Прогноз основан на текущем темпе и автоматически отмечен как предварительный, если история ещё короткая.</p></div><span class="pill {'ok' if pressure.get('status') == 'ok' else 'warn'}">Состояние диска: {_cell(pressure.get('status'))}</span></div><div class="grid two"><div><h3>Рекомендации</h3><ul>{guidance_html}</ul></div><div><h3>На что обратить внимание</h3><ul>{warning_html}</ul></div></div></section>
<section><h2>Из чего складывается объём</h2><table><thead><tr><th>Часть</th><th>Размер</th><th>Назначение</th></tr></thead><tbody><tr><td>PostgreSQL</td><td>{_cell(overview.get('database_human') or pg_db.get('database_human'))}</td><td>События и связи</td></tr><tr><td>Резервные копии</td><td>{_cell((sizes.get('backups') or {}).get('human'))}</td><td>Восстановление</td></tr><tr><td>Сырые журналы</td><td>{_cell((sizes.get('raw') or {}).get('human'))}</td><td>Кратковременная обработка</td></tr><tr><td>Отчёты и артефакты</td><td>{_cell((sizes.get('reports') or {}).get('human'))} / {_cell((sizes.get('artifacts') or {}).get('human'))}</td><td>Результаты работы</td></tr></tbody></table><p class="muted">Последнее полное измерение файлов: {_cell((overview.get('scan') or {}).get('duration_ms'))} мс.</p></section>
<details><summary>Технические детали для администратора</summary><section><h2>PostgreSQL operations</h2><p>База: <strong>{_cell(pg_db.get('database_name'))}</strong>. VACUUM/ANALYZE здесь только наблюдаются, автоматически не запускаются.</p><table><thead><tr><th>Таблица</th><th>Размер</th><th>Строк</th><th>Доля устаревших</th></tr></thead><tbody>{table_rows}</tbody></table></section><section><h2>Подробные размеры</h2><table><thead><tr><th>Категория</th><th>Размер</th><th>Файлов</th></tr></thead><tbody>{size_rows}</tbody></table><p class="muted">Снимок: {_cell(format_event_time(data.get('generated_at_utc')))}. Cleanup-кандидаты: {_cell(cleanup.get('total_human'))}.</p></section></details>
</main></body></html>"""
