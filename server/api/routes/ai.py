"""AI domain: redaction preview, prompt preview, run history.

Owns ``_ai_preview_filters``/``_ai_prompt_filters`` — used only here.

Response helpers stay on ``RequestHandler`` in ``server.api.http_server``
and are reached through the ``handler`` instance passed to every function
here. This module never imports ``server.api.http_server``.
"""
from __future__ import annotations

from server.sli.ai.ai_prompt_builder import build_ai_prompt_from_filters, render_ai_prompt_preview_report
from server.sli.ai.ai_reports import get_ai_run, list_ai_runs, render_ai_run_detail, render_ai_runs_index
from server.sli.access.data_redaction import build_ai_redaction_preview, render_ai_redaction_preview_report
from server.sli.storage.runtime_storage import validate_storage_route_authorization

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/ai/prompt-preview"),
    ("GET", "/api/ai/redaction-preview"),
    ("GET", "/api/ai/runs"),
    ("GET", "/reports/ai-analysis.html"),
    ("GET", "/reports/ai-prompt-preview.html"),
    ("GET", "/reports/ai-redaction-preview.html"),
    ("GET", "/reports/ai-reports.html"),
)


def _with_storage_route_authorization(handler, values: dict) -> dict:
    authorization = validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )
    return {**values, "authorization": authorization} if authorization is not None else values


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/ai/redaction-preview":
        _handle_ai_redaction_preview_api(handler, query)
        return True
    if path == "/api/ai/prompt-preview":
        _handle_ai_prompt_preview_api(handler, query)
        return True
    if path == "/api/ai/runs":
        _handle_ai_runs_api(handler, query)
        return True
    if path == "/reports/ai-redaction-preview.html":
        _handle_ai_redaction_preview_report(handler, query)
        return True
    if path == "/reports/ai-prompt-preview.html":
        _handle_ai_prompt_preview_report(handler, query)
        return True
    if path == "/reports/ai-reports.html":
        _handle_ai_runs_report(handler, query)
        return True
    if path == "/reports/ai-analysis.html":
        _handle_ai_run_detail_report(handler, query)
        return True
    return False


def _ai_preview_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    raw_servers = first("server") or first("servers") or ""
    servers = [item.strip() for item in raw_servers.split(",") if item.strip()]
    return {
        "q": first("q"),
        "account": first("account") or first("user"),
        "event_id": first("event_id"),
        "channel": first("channel"),
        "provider": first("provider") or first("source"),
        "subject": first("subject") or first("initiator"),
        "target": first("target") or first("object"),
        "servers": servers,
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "limit": int(first("limit") or 50),
        "redaction_level": first("redaction_level") or first("level") or "strict",
    }


def _ai_prompt_filters(query: dict[str, list[str]]) -> dict:
    filters = _ai_preview_filters(query)

    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    filters["model"] = first("model") or "gpt-5.5"
    filters["provider"] = first("provider") or "openai_api"
    filters["allow_unsafe_redaction"] = (first("allow_unsafe_redaction") or "0").lower() in {"1", "true", "yes", "on"}
    return filters


def _handle_ai_redaction_preview_api(handler, query: dict[str, list[str]]) -> None:
    data = build_ai_redaction_preview(
        **_with_storage_route_authorization(handler, _ai_preview_filters(query))
    )
    handler._send_json(data)


def _handle_ai_redaction_preview_report(handler, query: dict[str, list[str]]) -> None:
    data = build_ai_redaction_preview(
        **_with_storage_route_authorization(handler, _ai_preview_filters(query))
    )
    handler._send_html(render_ai_redaction_preview_report(data))


def _handle_ai_prompt_preview_api(handler, query: dict[str, list[str]]) -> None:
    data = build_ai_prompt_from_filters(
        **_with_storage_route_authorization(handler, _ai_prompt_filters(query))
    )
    handler._send_json(data)


def _handle_ai_prompt_preview_report(handler, query: dict[str, list[str]]) -> None:
    data = build_ai_prompt_from_filters(
        **_with_storage_route_authorization(handler, _ai_prompt_filters(query))
    )
    handler._send_html(render_ai_prompt_preview_report(data))


def _handle_ai_runs_api(handler, query: dict[str, list[str]]) -> None:
    data = list_ai_runs(limit=int((query.get("limit") or [50])[0] or 50))
    handler._send_json(data)


def _handle_ai_runs_report(handler, query: dict[str, list[str]]) -> None:
    data = list_ai_runs(limit=int((query.get("limit") or [50])[0] or 50))
    handler._send_html(render_ai_runs_index(data))


def _handle_ai_run_detail_report(handler, query: dict[str, list[str]]) -> None:
    raw = (query.get("run_id") or query.get("id") or [""])[0]
    run_id = None
    try:
        run_id = int(raw) if raw else None
    except ValueError:
        run_id = None
    handler._send_html(render_ai_run_detail(get_ai_run(run_id=run_id)))
