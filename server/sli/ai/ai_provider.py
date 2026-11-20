from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from server.sli.ai.ai_prompt_builder import openai_responses_request_body
from server.sli.ai.ai_schema import DEFAULT_OPENAI_MODEL, validate_ai_analysis_shape
from server.sli.ai.draft_contract import as_draft_result, draft_notice
from server.sli.core.paths import REPORTS_DIR
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.access.redaction_leak_check import check_redaction_leaks
from server.sli.core.time_format import format_event_time

OPENAI_RESPONSES_URL = "https://api.openai.com/v1/responses"


@dataclass(frozen=True)
class AiProviderConfig:
    provider: str = "openai_api"
    model: str = DEFAULT_OPENAI_MODEL
    base_url: str = OPENAI_RESPONSES_URL
    timeout_seconds: int = 60
    execute_enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["api_key_present"] = bool(os.getenv("OPENAI_API_KEY"))
        return value


def load_ai_provider_config() -> AiProviderConfig:
    return AiProviderConfig(
        provider=os.getenv("ADLOG_AI_PROVIDER", "openai_api").strip() or "openai_api",
        model=os.getenv("ADLOG_AI_MODEL", DEFAULT_OPENAI_MODEL).strip() or DEFAULT_OPENAI_MODEL,
        base_url=os.getenv("ADLOG_OPENAI_RESPONSES_URL", OPENAI_RESPONSES_URL).strip() or OPENAI_RESPONSES_URL,
        timeout_seconds=_env_int("ADLOG_AI_TIMEOUT_SECONDS", 60),
        execute_enabled=_env_bool("ADLOG_AI_EXECUTE_ENABLED", False),
    )


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value in (None, ""):
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def call_openai_responses(
    request_body: dict[str, Any],
    *,
    api_key: str | None = None,
    base_url: str = OPENAI_RESPONSES_URL,
    timeout_seconds: int = 60,
    urlopen: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    key = api_key or os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set")
    opener = urlopen or urllib.request.urlopen
    request = urllib.request.Request(
        base_url,
        data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=timeout_seconds) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OpenAI API HTTP {exc.code}: {body[:1000]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OpenAI API network error: {exc}") from exc


def extract_structured_json(response: dict[str, Any]) -> dict[str, Any]:
    candidates: list[str] = []
    if isinstance(response.get("output_text"), str):
        candidates.append(response["output_text"])
    for output in response.get("output") or []:
        if not isinstance(output, dict):
            continue
        for content in output.get("content") or []:
            if not isinstance(content, dict):
                continue
            text = content.get("text") or content.get("content")
            if isinstance(text, str):
                candidates.append(text)
    for text in candidates:
        raw = text.strip()
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    raise ValueError("OpenAI response did not contain parseable structured JSON")


def build_ai_api_job(package: dict[str, Any], *, config: AiProviderConfig | None = None) -> dict[str, Any]:
    provider_config = config or load_ai_provider_config()
    request_body = openai_responses_request_body({**package, "model": provider_config.model})
    return {
        "created_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "provider": provider_config.provider,
        "model": provider_config.model,
        "execute_enabled": provider_config.execute_enabled,
        "api_key_present": bool(os.getenv("OPENAI_API_KEY")),
        "request_body": request_body,
        "safety": package.get("safety") or {},
        "prompt_version": package.get("prompt_version"),
    }


def run_openai_analysis(
    package: dict[str, Any],
    *,
    execute: bool = False,
    config: AiProviderConfig | None = None,
    api_key: str | None = None,
) -> dict[str, Any]:
    provider_config = config or load_ai_provider_config()
    job = build_ai_api_job(package, config=provider_config)
    leak_check = check_redaction_leaks(package.get("payload") or package.get("prompt_text") or "", redaction_level=str(package.get("redaction_level") or "strict"))
    job["leak_check"] = leak_check
    if leak_check.get("blocked"):
        if execute:
            raise RuntimeError("AI request blocked: redaction leak check found possible sensitive data")
        return as_draft_result({"status": "prepared_blocked_by_leak_check", "ai_call_performed": False, "job": job})
    if not execute:
        return as_draft_result({"status": "prepared", "ai_call_performed": False, "job": job})
    if not provider_config.execute_enabled:
        raise RuntimeError("ADLOG_AI_EXECUTE_ENABLED is not enabled; refusing to call OpenAI API")
    response = call_openai_responses(
        job["request_body"],
        api_key=api_key,
        base_url=provider_config.base_url,
        timeout_seconds=provider_config.timeout_seconds,
    )
    structured = extract_structured_json(response)
    validation_errors = validate_ai_analysis_shape(
        structured,
        events=list((package.get("payload") or {}).get("events") or []),
    )
    return as_draft_result({
        "status": "completed" if not validation_errors else "completed_with_validation_warnings",
        "ai_call_performed": True,
        "job": {k: v for k, v in job.items() if k != "request_body"},
        "analysis": structured,
        "validation_errors": validation_errors,
        "raw_response": response,
    })


def write_ai_artifacts(
    package: dict[str, Any],
    result: dict[str, Any],
    *,
    out_dir: Path = REPORTS_DIR,
    prefix: str = "ai-openai-analysis",
) -> dict[str, str]:
    result = as_draft_result(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    prompt_path = out_dir / f"{prefix}-prompt.txt"
    request_path = out_dir / f"{prefix}-request.json"
    result_path = out_dir / f"{prefix}-result.json"
    report_path = out_dir / f"{prefix}.html"
    prompt_path.write_text(package.get("prompt_text") or "", encoding="utf-8")
    request_path.write_text(json.dumps(openai_responses_request_body(package), ensure_ascii=False, indent=2), encoding="utf-8")
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(render_ai_provider_report(package, result), encoding="utf-8")
    return {"prompt": str(prompt_path), "request": str(request_path), "result": str(result_path), "html": str(report_path)}


def render_ai_provider_report(package: dict[str, Any], result: dict[str, Any]) -> str:
    result = as_draft_result(result)
    analysis = result.get("analysis") or {}
    generated = format_event_time(result.get("job", {}).get("created_at_utc") or package.get("generated_at_utc"))
    status = result.get("status") or "prepared"
    call_state = "выполнен" if result.get("ai_call_performed") else "не выполнялся"
    facts = _list_items(analysis.get("facts") or [], "statement", "event_indexes")
    hypotheses = _hypothesis_items(analysis.get("hypotheses") or [])
    alternatives = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("alternative_explanations") or []) or '<li class="muted">Нет данных</li>'
    evidence = _evidence_rows(analysis.get("evidence") or [])
    actions = _action_cards(analysis.get("recommended_actions") or [])
    limitations = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("limitations") or []) or '<li class="muted">Нет данных</li>'
    checks = "".join(f"<li>{_e(item)}</li>" for item in analysis.get("manual_checks") or []) or '<li class="muted">Нет данных</li>'
    validation = result.get("validation_errors") or []
    validation_html = "" if not validation else f"<div class='badcallout'><strong>Предупреждения проверки JSON:</strong> {_e(', '.join(map(str, validation)))}</div>"
    raw = json.dumps(result, ensure_ascii=False, indent=2)
    return f"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>AI-анализ OpenAI</title>{report_style()}</head>
<body>{report_controls()}<main class="wrap"><header class="hero"><div class="eyebrow">AI analysis · OpenAI API</div><h1>AI-анализ обезличенной цепочки событий</h1><p class="subtitle">AI-вывод является гипотезой помощника аналитика. Действия в AD не выполняются.</p><div class="pillrow"><span class="pill"><strong>Статус:</strong> {_e(status)}</span><span class="pill"><strong>API-вызов:</strong> {_e(call_state)}</span><span class="pill"><strong>Сформирован:</strong> {_e(generated)}</span><span class="pill"><strong>Модель:</strong> {_e(package.get('model'))}</span><span class="pill"><strong>Маскирование:</strong> {_e(package.get('redaction_level'))}</span></div></header>
<section>{draft_notice()}<h2>Резюме</h2><p>{_e(analysis.get('summary') or 'AI-вызов еще не выполнялся. Подготовлены prompt и request body.')}</p>{validation_html}</section>
<section><div class="grid two"><div class="card"><h3>Факты</h3><ul>{facts}</ul></div><div class="card"><h3>Гипотезы</h3>{hypotheses}</div></div></section>
<section><div class="grid two"><div class="card"><h3>Альтернативные объяснения</h3><ul>{alternatives}</ul></div><div class="card"><h3>Что проверить вручную</h3><ul>{checks}</ul></div></div></section>
<section><h2>Evidence</h2><table><thead><tr><th>№ события</th><th>Event ID</th><th>Значение</th><th>Почему важно</th></tr></thead><tbody>{evidence}</tbody></table></section>
<section><h2>Рекомендации</h2><div class="grid">{actions}</div></section>
<section><h2>Ограничения анализа</h2><ul>{limitations}</ul></section>
<section><h2>Технический JSON</h2><details><summary>Показать результат</summary><pre>{_e(raw)}</pre></details></section></main></body></html>"""


def _list_items(items: list[Any], text_key: str, indexes_key: str) -> str:
    rows = []
    for item in items:
        if isinstance(item, dict):
            suffix = f" <span class='muted'>events: {_e(item.get(indexes_key) or [])}</span>"
            rows.append(f"<li>{_e(item.get(text_key))}{suffix}</li>")
        else:
            rows.append(f"<li>{_e(item)}</li>")
    return "".join(rows) or '<li class="muted">Нет данных</li>'


def _hypothesis_items(items: list[Any]) -> str:
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


def _action_cards(items: list[Any]) -> str:
    cards = []
    for item in items:
        if not isinstance(item, dict):
            cards.append(f"<div class='card'>{_e(item)}</div>")
            continue
        cards.append(
            f"<article class='card'><div class='pillrow'><span class='badge {_e(str(item.get('priority') or 'info'))}'>{_e(item.get('priority'))}</span><span class='pill'>ответственный: {_e(item.get('owner'))}</span></div><h3>{_e(item.get('action'))}</h3><p>{_e(item.get('reason'))}</p></article>"
        )
    return "".join(cards) or '<div class="empty">Нет рекомендаций</div>'


def _e(value: Any) -> str:
    import html

    return html.escape(str(value if value is not None else ""))
