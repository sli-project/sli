from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.core.database import is_postgres_runtime_db, query_rows
from server.sli.core.paths import REPORTS_DIR
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.core.time_format import format_event_time
from server.sli.reporting.ui_labels import status_label
from server.sli.ai.draft_contract import as_draft_result, draft_notice, draft_provenance


_POSTGRES_ONLY_MESSAGE = "AI run storage is PostgreSQL-only: the SQLite runtime backend has been removed"


def record_ai_run(
    package: dict[str, Any],
    result: dict[str, Any],
    artifacts: dict[str, str]) -> int:
    """Persist safe metadata for one AI analysis run.

    This table intentionally stores file paths and validation metadata, not the
    API key and not local redaction mapping values. The actual result JSON lives
    in data/reports so it can be reviewed or removed by normal retention/backup
    procedures.
    """
    if not is_postgres_runtime_db():
        raise RuntimeError(_POSTGRES_ONLY_MESSAGE)
    result = as_draft_result(result)
    query_summary = _safe_query_summary(package)
    validation_errors = result.get("validation_errors") or []
    completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") if result.get("ai_call_performed") else None
    values = (
        package.get("provider") or "openai_api",
        package.get("model") or "unknown",
        package.get("prompt_version") or "unknown",
        package.get("redaction_level") or "strict",
        result.get("status") or "prepared",
        json.dumps(query_summary, ensure_ascii=False),
        artifacts.get("prompt"),
        artifacts.get("request"),
        artifacts.get("result"),
        artifacts.get("html"),
        bool(result.get("ai_call_performed")),
        json.dumps(validation_errors, ensure_ascii=False),
        completed_at,
    )
    from server.sli.core.postgres_runtime_pipeline import connect

    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into ai_api_runs(provider, model, prompt_version, redaction_level, status, query_summary_json,
                    prompt_file_path, request_file_path, result_file_path, report_file_path, ai_call_performed,
                    validation_errors_json, completed_at)
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id
                """,
                values,
            )
            row = cur.fetchone()
            if not row or row.get("id") is None:
                raise RuntimeError("PostgreSQL did not return ai_api_runs.id")
            return int(row["id"])


def list_ai_runs(*, limit: int = 50) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 200))
    sql = """
        select id, provider, model, prompt_version, redaction_level, status, query_summary_json,
               prompt_file_path, request_file_path, result_file_path, report_file_path, ai_call_performed,
               validation_errors_json, created_at, completed_at
        from ai_api_runs
        order by id desc
        limit ?
    """
    if not is_postgres_runtime_db():
        raise RuntimeError(_POSTGRES_ONLY_MESSAGE)
    rows = query_rows(sql, (limit,))
    rows = [_json_safe(dict(row)) for row in rows]
    for row in rows:
        row["provenance"] = draft_provenance()
        row["query_summary"] = _load_json(row.pop("query_summary_json", None), {})
        row["validation_errors"] = _load_json(row.pop("validation_errors_json", None), [])
        row["created_at_display"] = format_event_time(row.get("created_at"))
        row["completed_at_display"] = format_event_time(row.get("completed_at")) if row.get("completed_at") else "—"
        row["report_url"] = _report_url(row.get("report_file_path"))
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "items": rows,
        "filters": {"limit": limit},
    }


def get_ai_run(*, run_id: int | None = None) -> dict[str, Any] | None:
    if run_id is None:
        sql, params = "select * from ai_api_runs order by id desc limit 1", ()
    else:
        sql, params = "select * from ai_api_runs where id=?", (run_id,)
    if not is_postgres_runtime_db():
        raise RuntimeError(_POSTGRES_ONLY_MESSAGE)
    rows = query_rows(sql, params)
    item = dict(rows[0]) if rows else None
    if item is None:
        return None
    item = _json_safe(item)
    item["provenance"] = draft_provenance()
    item["query_summary"] = _load_json(item.pop("query_summary_json", None), {})
    item["validation_errors"] = _load_json(item.pop("validation_errors_json", None), [])
    item["created_at_display"] = format_event_time(item.get("created_at"))
    item["completed_at_display"] = format_event_time(item.get("completed_at")) if item.get("completed_at") else "—"
    item["report_url"] = _report_url(item.get("report_file_path"))
    item["result"] = _load_result_file(item.get("result_file_path"))
    return item


def render_ai_runs_index(data: dict[str, Any]) -> str:
    rows = "".join(_run_row(item) for item in data.get("items") or []) or '<tr><td colspan="9">AI-запуски пока не выполнялись.</td></tr>'
    generated = format_event_time(data.get("generated_at_utc"))
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI-отчеты</title>{report_style()}</head>
<body>{report_controls()}<main class="wrap"><header class="hero"><div class="eyebrow">AI layer</div><h1>История AI-отчетов</h1><p class="subtitle">Локальный журнал подготовленных и выполненных AI-анализов. API-ключи и таблицы соответствий redaction здесь не сохраняются.</p><div class="pillrow"><span class="pill"><strong>Сформировано:</strong> {_e(generated)}</span><span class="pill"><strong>Записей:</strong> {_e(len(data.get('items') or []))}</span></div></header>
<section><h2>Запуски</h2><table><thead><tr><th>ID</th><th>Статус</th><th>API</th><th>Модель</th><th>Маскирование</th><th>Создан</th><th>Завершен</th><th>Проверка</th><th>Отчет</th></tr></thead><tbody>{rows}</tbody></table></section>
<section><h2>Как запустить новый отчет</h2><pre>set OPENAI_API_KEY=sk-...\nset ADLOG_AI_EXECUTE_ENABLED=true\npython scripts/ai/run_openai_analysis.py --q administrator --limit 80 --redaction-level strict --execute</pre><p class="muted">Перед реальным вызовом сначала откройте redaction preview и убедитесь, что реальные учетные записи, IP, хосты и домены замаскированы.</p></section></main></body></html>"""


def render_ai_run_detail(run: dict[str, Any] | None) -> str:
    if run is None:
        return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI-отчет</title>{report_style()}</head><body>{report_controls()}<main class="wrap"><section><div class="empty">AI-отчет не найден.</div></section></main></body></html>"""
    result = as_draft_result(run.get("result") or {})
    analysis = result.get("analysis") or {}
    validation = run.get("validation_errors") or []
    facts = _items_with_evidence(analysis.get("facts") or [], "statement", "event_indexes")
    hypotheses = _hypotheses(analysis.get("hypotheses") or [])
    evidence = _evidence_rows(analysis.get("evidence") or [])
    alternatives = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("alternative_explanations") or []) or '<li class="muted">Нет данных</li>'
    actions = _actions(analysis.get("recommended_actions") or [])
    limitations = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("limitations") or []) or '<li class="muted">Нет данных</li>'
    checks = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("manual_checks") or []) or '<li class="muted">Нет данных</li>'
    validation_html = "" if not validation else f"<div class='badcallout'><strong>Предупреждения проверки JSON:</strong> {_e(', '.join(map(str, validation)))}</div>"
    raw = json.dumps(result, ensure_ascii=False, indent=2)
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI-отчет #{_e(run.get('id'))}</title>{report_style()}</head>
<body>{report_controls()}<main class="wrap"><header class="hero"><div class="eyebrow">AI report · OpenAI API</div><h1>AI-отчет #{_e(run.get('id'))}</h1><p class="subtitle">AI-отчет помогает аналитику сгруппировать факты и гипотезы. Он не является доказательством инцидента без ручной проверки evidence.</p><div class="pillrow"><span class="pill"><strong>Статус:</strong> {_e(_status_ru(run.get('status')))}</span><span class="pill"><strong>API-вызов:</strong> {_e('выполнен' if run.get('ai_call_performed') else 'не выполнялся')}</span><span class="pill"><strong>Модель:</strong> {_e(run.get('model'))}</span><span class="pill"><strong>Маскирование:</strong> {_e(run.get('redaction_level'))}</span><span class="pill"><strong>Создан:</strong> {_e(run.get('created_at_display'))}</span></div></header>
<section>{draft_notice()}<h2>Резюме</h2><p class="summary">{_e(analysis.get('summary') or 'AI-вызов еще не выполнялся или результат не содержит резюме.')}</p>{validation_html}</section>
<section><div class="grid two"><div class="card"><h3>Факты</h3><ul>{facts}</ul></div><div class="card"><h3>Гипотезы</h3>{hypotheses}</div></div></section>
<section><div class="grid two"><div class="card"><h3>Альтернативные объяснения</h3><ul>{alternatives}</ul></div><div class="card"><h3>Что проверить вручную</h3><ul>{checks}</ul></div></div></section>
<section><h2>Evidence</h2><table><thead><tr><th>№ события</th><th>Event ID</th><th>Значение</th><th>Почему важно</th></tr></thead><tbody>{evidence}</tbody></table></section>
<section><h2>Рекомендации</h2><div class="grid">{actions}</div></section>
<section><h2>Ограничения анализа</h2><ul>{limitations}</ul></section>
<section><h2>Технический JSON</h2><details><summary>Показать результат</summary><pre>{_e(raw)}</pre></details></section></main></body></html>"""


def update_report_file_with_run_id(report_file: str | None, run_id: int) -> None:
    if not report_file:
        return
    path = Path(report_file)
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    text = text.replace("AI-анализ обезличенной цепочки событий", f"AI-анализ обезличенной цепочки событий · запуск #{run_id}")
    path.write_text(text, encoding="utf-8")


def _safe_query_summary(package: dict[str, Any]) -> dict[str, Any]:
    preview = package.get("preview") or {}
    source = preview.get("source") or {}
    filters = preview.get("filters") or {}
    return {
        "provenance": draft_provenance(),
        "filters": filters,
        "source": source,
        "safety": package.get("safety") or {},
        "payload_events": len((package.get("payload") or {}).get("events") or []),
    }


def _load_result_file(path_value: str | None) -> dict[str, Any]:
    if not path_value:
        return {}
    path = Path(path_value)
    try:
        if path.is_file():
            return as_draft_result(json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    return {}


def _report_url(path_value: str | None) -> str | None:
    if not path_value:
        return None
    path = Path(path_value)
    try:
        relative = path.resolve().relative_to(REPORTS_DIR.resolve())
        return f"/reports/{relative.as_posix()}"
    except Exception:
        return None


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _load_json(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def _run_row(item: dict[str, Any]) -> str:
    detail_url = f"/reports/ai-analysis.html?run_id={item.get('id')}"
    validation = item.get("validation_errors") or []
    validation_text = "ок" if not validation else f"предупреждения: {len(validation)}"
    return f"""<tr><td class="mono">{_e(item.get('id'))}</td><td>{draft_notice()} {_e(_status_ru(item.get('status')))}</td><td>{_e('да' if item.get('ai_call_performed') else 'нет')}</td><td>{_e(item.get('model'))}</td><td>{_e(item.get('redaction_level'))}</td><td>{_e(item.get('created_at_display'))}</td><td>{_e(item.get('completed_at_display'))}</td><td>{_e(validation_text)}</td><td><a class="button" href="{_e(detail_url)}">Открыть</a></td></tr>"""


def _items_with_evidence(items: list[Any], text_key: str, indexes_key: str) -> str:
    output = []
    for item in items:
        if isinstance(item, dict):
            indexes = item.get(indexes_key) or []
            suffix = f" <span class='muted'>events: {_e(indexes)}</span>" if indexes else ""
            output.append(f"<li>{_e(item.get(text_key))}{suffix}</li>")
        else:
            output.append(f"<li>{_e(item)}</li>")
    return "".join(output) or '<li class="muted">Нет данных</li>'


def _hypotheses(items: list[Any]) -> str:
    cards = []
    for item in items:
        if not isinstance(item, dict):
            cards.append(f"<div class='callout'>{_e(item)}</div>")
            continue
        cards.append(
            f"<div class='callout'><strong>{_e(item.get('hypothesis'))}</strong><p>{_e(item.get('why_it_matters'))}</p>"
            f"<span class='pill'>events: {_e(item.get('event_indexes') or [])}</span></div>"
        )
    return "".join(cards) or '<div class="empty">Нет данных</div>'


def _evidence_rows(items: list[Any]) -> str:
    rows = []
    for item in items:
        if not isinstance(item, dict):
            continue
        rows.append(
            f"<tr><td class='mono'>{_e(item.get('event_index'))}</td><td class='mono'>{_e(item.get('event_id'))}</td><td>{_e(item.get('meaning'))}</td><td>{_e(item.get('reason'))}</td></tr>"
        )
    return "".join(rows) or '<tr><td colspan="4">Нет evidence</td></tr>'


def _actions(items: list[Any]) -> str:
    cards = []
    for item in items:
        if not isinstance(item, dict):
            cards.append(f"<div class='card'>{_e(item)}</div>")
            continue
        cards.append(
            f"<article class='card'><div class='pillrow'><span class='badge {_e(str(item.get('priority') or 'info'))}'>{_e(item.get('priority'))}</span><span class='pill'>ответственный: {_e(item.get('owner'))}</span></div><h3>{_e(item.get('action'))}</h3><p>{_e(item.get('reason'))}</p></article>"
        )
    return "".join(cards) or '<div class="empty">Нет рекомендаций</div>'


def _status_ru(status: Any) -> str:
    value = str(status or "")
    return {
        "prepared": "подготовлен",
        "completed": "завершен",
        "completed_with_validation_warnings": "завершен с предупреждениями",
        "failed": "ошибка",
    }.get(value, status_label(value) if value else "—")


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))
