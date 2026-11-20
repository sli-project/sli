from __future__ import annotations

import html
from typing import Any

from server.jobs.collector import get_autocollection_status


def render_autocollection_report(data: dict[str, Any] | None = None) -> str:
    data = data or get_autocollection_status()
    active = data.get("active_job") or {}
    skipped = data.get("skipped_overlap_summary") or {}
    channels = data.get("channels") or []
    stages = ((data.get("performance") or {}).get("stages") or [])[:12]

    def esc(value: object) -> str:
        return html.escape("" if value is None else str(value))

    channel_rows = "".join(
        f"<tr><td>{esc(item.get('server'))}</td><td>{esc(item.get('channel'))}</td><td>{esc(item.get('severity'))}</td><td>{esc(item.get('lag_minutes'))}</td><td>{esc(item.get('stale_reason'))}</td></tr>"
        for item in channels
    ) or '<tr><td colspan="5" class="muted">Нет данных</td></tr>'
    stage_rows = "".join(
        f"<tr><td>{esc(item.get('stage'))}</td><td>{esc(item.get('server'))}</td><td>{esc(item.get('channel'))}</td><td>{esc(item.get('duration_ms'))}</td><td>{esc(item.get('last_seen'))}</td></tr>"
        for item in stages
    ) or '<tr><td colspan="5" class="muted">Нет данных</td></tr>'
    status_class = "ok" if data.get("status") == "idle" else "warn"

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Состояние автосбора</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;margin:28px;color:#1f2933}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}}.card{{border:1px solid #d9e2ec;border-radius:8px;padding:12px;background:#f8fafc}}.value{{font-size:20px;font-weight:600}}table{{width:100%;border-collapse:collapse;margin:12px 0 24px}}th,td{{border:1px solid #d9e2ec;padding:8px;vertical-align:top}}th{{background:#eef2f7}}.muted{{color:#697586}}.ok{{color:#146c2e}}.warn{{color:#9a5b00}}</style></head>
<body>
<h1>Состояние автосбора</h1>
<div class="grid">
  <div class="card"><div class="muted">Статус</div><div class="value {status_class}">{esc(data.get('status'))}</div></div>
  <div class="card"><div class="muted">Активный job</div><div class="value">{esc(active.get('id') or 'нет')}</div></div>
  <div class="card"><div class="muted">Фаза</div><div class="value">{esc(active.get('phase'))}</div></div>
  <div class="card"><div class="muted">Текущий канал</div><div class="value">{esc(active.get('current_channel'))}</div></div>
</div>
<h2>Активный сбор</h2>
<table><tbody>
<tr><th>trace_id</th><td>{esc(active.get('trace_id'))}</td></tr>
<tr><th>server</th><td>{esc(active.get('current_server'))}</td></tr>
<tr><th>cycle</th><td>{esc(active.get('cycle'))}</td></tr>
<tr><th>events_collected</th><td>{esc(active.get('events_collected'))}</td></tr>
<tr><th>last_progress_at</th><td>{esc(active.get('last_progress_at'))}</td></tr>
<tr><th>message</th><td>{esc(active.get('message'))}</td></tr>
</tbody></table>
<h2>Пропущенные плановые запуски</h2>
<p>{esc(skipped.get('message') or 'Нет пропущенных запусков из-за overlap.')}</p>
<table><tbody><tr><th>count</th><td>{esc(skipped.get('count'))}</td></tr><tr><th>period</th><td>{esc(skipped.get('first_at'))} — {esc(skipped.get('last_at'))}</td></tr></tbody></table>
<h2>Каналы и fairness</h2>
<p class="muted">Non-Security журналы во время Security recovery включаются в read-only сбор, если они устарели. Система не включает журналы на DC и не меняет политики.</p>
<table><thead><tr><th>Сервер</th><th>Канал</th><th>Severity</th><th>Lag, min</th><th>Пояснение</th></tr></thead><tbody>{channel_rows}</tbody></table>
<h2>Где теряем время</h2>
<table><thead><tr><th>Stage</th><th>Server</th><th>Channel</th><th>Duration ms</th><th>Last seen</th></tr></thead><tbody>{stage_rows}</tbody></table>
</body></html>"""
