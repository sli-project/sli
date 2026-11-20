from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlencode

from server.sli.events.event_search import get_event_search_data
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.core.time_format import format_event_time, iso_utc_seconds, parse_event_time
from server.sli.reporting.ui_labels import channel_label, event_id_label

MAX_PREVIEW_LIMIT = 200
DEFAULT_PREVIEW_LIMIT = 50
VALID_REDACTION_LEVELS = {"strict", "balanced", "off"}

_FIELD_LABELS_RU = {
    "server": "сервер",
    "channel": "журнал",
    "event_id": "Event ID",
    "event_meaning": "значение события",
    "time_utc": "время UTC",
    "time_display": "время для чтения",
    "relative_offset": "смещение от первого события",
    "subject": "инициатор",
    "target": "цель",
    "source": "источник",
    "workstation": "рабочая станция",
    "logon_id": "LogonId",
    "event_data_summary": "краткие поля события",
    "message_summary": "краткое сообщение",
}

SENSITIVE_EVENT_DATA_KEYS = {
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "TargetUserSid", "TargetUserName",
    "TargetDomainName", "MemberName", "GroupName", "IpAddress", "WorkstationName", "CallerComputerName",
    "Computer", "TargetServerName", "ServiceName", "ProcessName", "ObjectName", "ShareName", "LogonId",
}

_USERNAME_RE = re.compile(r"(?<![\w$.-])([A-Za-zА-Яа-яЁё0-9._-]{2,}\\[A-Za-zА-Яа-яЁё0-9._$-]{2,}|[A-Za-zА-Яа-яЁё0-9._$-]{3,}@[A-Za-z0-9._-]+)")
_SID_RE = re.compile(r"S-1-5(?:-[0-9]+){2,}")
_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"']+")
_HOST_RE = re.compile(r"\b[A-Za-z0-9_-]{2,}\.(?:local|lan|corp|domain|ru|com|net|org)\b", re.IGNORECASE)
_SHORT_HOST_RE = re.compile(r"\b(?:DC|SRV|SERVER|WS|PC|NB|RDS|EXCH|SQL|FS|PKI)[A-Za-z0-9_-]*\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class RedactionContext:
    level: str = "strict"
    counters: dict[str, int] = field(default_factory=dict)
    mapping: dict[str, str] = field(default_factory=dict)

    def token(self, kind: str, value: Any) -> str:
        raw = str(value or "").strip()
        if not raw or raw in {"—", "-"}:
            return "—"
        if self.level == "off":
            return raw
        key = f"{kind}:{raw.lower()}"
        if key not in self.mapping:
            self.counters[kind] = self.counters.get(kind, 0) + 1
            self.mapping[key] = f"{kind}_{self.counters[kind]:03d}"
        return self.mapping[key]

    def public_mapping_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for key in self.mapping:
            kind = key.split(":", 1)[0]
            summary[kind] = summary.get(kind, 0) + 1
        return summary


def normalize_redaction_level(level: str | None) -> str:
    value = str(level or "strict").strip().lower()
    return value if value in VALID_REDACTION_LEVELS else "strict"


def classify_value(value: Any, *, field_name: str = "") -> str:
    raw = str(value or "").strip()
    field = field_name.lower()
    if not raw or raw in {"—", "-"}:
        return "empty"
    if "sid" in field or _SID_RE.fullmatch(raw):
        return "sid"
    if "ip" in field or _is_ip(raw):
        return "ip"
    if "domain" in field:
        return "domain"
    if "server" in field or "computer" in field or "workstation" in field or field in {"host", "hostname"}:
        return "host"
    if "logon" in field and "id" in field:
        return "logon"
    if "path" in field or _PATH_RE.search(raw):
        return "path"
    if "user" in field or "account" in field or "subject" in field or "target" in field or "member" in field:
        return "account"
    if _USERNAME_RE.search(raw):
        return "account"
    if _HOST_RE.search(raw) or _SHORT_HOST_RE.fullmatch(raw):
        return "host"
    return "text"


def redact_value(value: Any, *, field_name: str = "", ctx: RedactionContext) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "—"
    if ctx.level == "off":
        return raw
    kind = classify_value(raw, field_name=field_name)
    if kind == "empty":
        return "—"
    if kind in {"account", "domain", "host", "ip", "sid", "path", "logon"}:
        return ctx.token(kind, raw)
    if ctx.level == "strict" and field_name in {"message_text", "event_data_json"}:
        return _redact_text(raw, ctx)
    return raw


def _redact_text(text: str, ctx: RedactionContext) -> str:
    if ctx.level == "off":
        return text

    def repl_ip(match: re.Match[str]) -> str:
        value = match.group(0)
        return ctx.token("ip", value) if _is_ip(value) else value

    output = _SID_RE.sub(lambda m: ctx.token("sid", m.group(0)), text)
    output = _PATH_RE.sub(lambda m: ctx.token("path", m.group(0)), output)
    output = _USERNAME_RE.sub(lambda m: ctx.token("account", m.group(0)), output)
    output = _HOST_RE.sub(lambda m: ctx.token("host", m.group(0)), output)
    output = _SHORT_HOST_RE.sub(lambda m: ctx.token("host", m.group(0)), output)
    output = _IPV4_RE.sub(repl_ip, output)
    return output


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _principal(domain: Any, name: Any, *, ctx: RedactionContext) -> str:
    d = str(domain or "").strip()
    n = str(name or "").strip()
    if d and n:
        return redact_value(f"{d}\\{n}", field_name="account", ctx=ctx)
    if n:
        return redact_value(n, field_name="account", ctx=ctx)
    if d:
        return redact_value(d, field_name="domain", ctx=ctx)
    return "—"


def redact_event(item: dict[str, Any], *, ctx: RedactionContext, first_time: datetime | None = None) -> dict[str, Any]:
    event_time = parse_event_time(item.get("time_created_utc"))
    relative = None
    if first_time and event_time:
        minutes = int((event_time - first_time).total_seconds() // 60)
        relative = f"+{minutes} мин" if minutes >= 0 else f"{minutes} мин"
    event_data = _load_event_data(item.get("event_data") or item.get("event_data_json"))
    return {
        "time_display": format_event_time(item.get("time_created_utc")),
        "time_utc": iso_utc_seconds(item.get("time_created_utc")),
        "relative_offset": relative or "+0 мин",
        "server": redact_value(item.get("server"), field_name="server", ctx=ctx),
        "channel": channel_label(item.get("channel"), with_original=True),
        "event_id": item.get("event_id"),
        "event_meaning": event_id_label(item.get("event_id")),
        "subject": _principal(item.get("subject_domain_name"), item.get("subject_user_name"), ctx=ctx),
        "target": _principal(item.get("target_domain_name"), item.get("target_user_name"), ctx=ctx),
        "source": redact_value(item.get("ip_address") or item.get("source"), field_name="ip_address", ctx=ctx),
        "workstation": redact_value(item.get("workstation_name"), field_name="workstation_name", ctx=ctx),
        "logon_id": redact_value(item.get("logon_id"), field_name="logon_id", ctx=ctx),
        "event_data_summary": _redact_event_data_summary(event_data, ctx),
        "message_summary": _redact_message(item.get("message_text"), ctx),
    }


def _load_event_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    raw = str(value or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def _redact_event_data_summary(event_data: dict[str, Any], ctx: RedactionContext) -> dict[str, str]:
    output: dict[str, str] = {}
    for key, value in list(event_data.items())[:30]:
        if value in (None, "", "-"):
            continue
        if ctx.level == "strict" and key not in SENSITIVE_EVENT_DATA_KEYS and len(output) >= 12:
            continue
        output[key] = redact_value(value, field_name=key, ctx=ctx) if key in SENSITIVE_EVENT_DATA_KEYS else _redact_text(str(value), ctx)
    return output


def _redact_message(value: Any, ctx: RedactionContext) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    text = raw[:700]
    if ctx.level == "strict":
        text = _redact_text(text, ctx)
    elif ctx.level == "balanced":
        text = _redact_text(text, ctx)
    return text


def build_ai_redaction_preview(
    *,
    q: str | None = None,
    account: str | None = None,
    event_id: int | str | None = None,
    channel: str | None = None,
    servers: list[str] | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    limit: int = DEFAULT_PREVIEW_LIMIT,
    redaction_level: str = "strict",
    authorization: object | None = None,
) -> dict[str, Any]:
    level = normalize_redaction_level(redaction_level)
    safe_limit = max(1, min(int(limit or DEFAULT_PREVIEW_LIMIT), MAX_PREVIEW_LIMIT))
    search_kwargs = dict(
        q=q,
        account=account,
        event_id=event_id,
        channel=channel,
        servers=servers or [],
        time_from=time_from,
        time_to=time_to,
        limit=safe_limit,
        order="asc",
        include_internal_evidence=True,
    )
    if authorization is not None:
        search_kwargs["authorization"] = authorization
    search = get_event_search_data(**search_kwargs)
    ctx = RedactionContext(level=level)
    items = search.get("items") or []
    first_time = parse_event_time(items[0].get("time_created_utc")) if items else None
    sanitized = [redact_event(item, ctx=ctx, first_time=first_time) for item in items]
    payload = {
        "purpose": "security_event_context_analysis",
        "language": "ru",
        "redaction_level": level,
        "events": sanitized,
        "instructions": [
            "Отделяй факты от гипотез.",
            "Не утверждай компрометацию без доказательств.",
            "Указывай, какие события являются evidence.",
            "Показывай альтернативные объяснения и ограничения анализа.",
        ],
    }
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "filters": {
            "q": q,
            "account": account,
            "event_id": event_id,
            "channel": channel,
            "servers": servers or [],
            "time_from": time_from,
            "time_to": time_to,
            "limit": safe_limit,
            "redaction_level": level,
        },
        "source": {
            "preview_events": len(sanitized),
            "has_more": bool(search.get("has_more")),
            "truncated": bool(search.get("truncated")),
            "total_is_exact": False,
            "query_status": search.get("query_status"),
            "bounded_window": {
                "time_from": (search.get("filters") or {}).get("time_from"),
                "time_to": (search.get("filters") or {}).get("time_to"),
                "default_window_applied": (search.get("filters") or {}).get("default_window_applied"),
            },
            "slice_contract": "one_bounded_fast_event_slice",
        },
        "safety": {
            "mode": "preview_only",
            "ai_call_performed": False,
            "raw_logs_sent": False,
            "mapping_stored_in_preview": False,
            "mapping_summary": ctx.public_mapping_summary(),
            "not_sent_by_default": [
                "record_xml",
                "raw_log_file_path",
                "полные Windows-сообщения без ограничения",
                "реальные учетные записи/домены/IP/хосты при strict/balanced",
            ],
        },
        "payload": payload,
        "labels": _FIELD_LABELS_RU,
    }


def render_ai_redaction_preview_report(data: dict[str, Any]) -> str:
    filters = data.get("filters") or {}
    source = data.get("source") or {}
    safety = data.get("safety") or {}
    payload_json = json.dumps(data.get("payload") or {}, ensure_ascii=False, indent=2)
    mapping_rows = "".join(
        f"<tr><td>{html.escape(str(kind))}</td><td>{html.escape(str(count))}</td></tr>"
        for kind, count in (safety.get("mapping_summary") or {}).items()
    ) or '<tr><td colspan="2">Нет замаскированных значений</td></tr>'
    not_sent = "".join(f"<li>{html.escape(str(item))}</li>" for item in safety.get("not_sent_by_default") or [])
    query = filters.get("q") or filters.get("account") or ""
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>AI preview: безопасная подготовка данных</title>{report_style()}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Проверка данных для AI</div><h1>Предпросмотр данных для AI-анализа</h1><p class=\"subtitle\">Этот экран показывает, какие данные будут подготовлены для внешнего или локального AI. На этом этапе запрос к AI не выполняется: можно проверить маскирование данных.</p><div class=\"pillrow\"><span class=\"pill\">Режим: {html.escape(str(filters.get('redaction_level')))}</span><span class=\"pill\">Показано событий: {html.escape(str(source.get('preview_events')))}</span><span class=\"pill\">Есть продолжение: {html.escape('да' if source.get('has_more') else 'нет')}</span><span class=\"pill\">Показаны не все события: {html.escape('да' if source.get('truncated') else 'нет')}</span></div></header>
<section><h2>Параметры</h2><form class=\"search-form\" method=\"get\" action=\"/reports/ai-redaction-preview.html\"><input name=\"q\" value=\"{html.escape(str(query))}\" placeholder=\"учетная запись, IP, хост, LogonId\"><input name=\"limit\" value=\"{html.escape(str(filters.get('limit') or 50))}\"><select name=\"redaction_level\"><option value=\"strict\" {'selected' if filters.get('redaction_level') == 'strict' else ''}>strict — максимум маскирования</option><option value=\"balanced\" {'selected' if filters.get('redaction_level') == 'balanced' else ''}>balanced — умеренно</option><option value=\"off\" {'selected' if filters.get('redaction_level') == 'off' else ''}>off — без маскирования</option></select><button>Обновить preview</button></form></section>
<section><h2>Что защищено</h2><div class=\"grid two\"><div class=\"card\"><h3>Замаскировано</h3><table><thead><tr><th>Тип</th><th>Количество</th></tr></thead><tbody>{mapping_rows}</tbody></table></div><div class=\"card\"><h3>Не отправляется по умолчанию</h3><ul>{not_sent}</ul></div></div></section>
<section><h2>Подготовленные данные в формате JSON</h2><p class=\"muted\">Эти данные можно использовать для AI-анализа позже. Сейчас они только отображаются и никуда не отправляются.</p><pre>{html.escape(payload_json)}</pre></section>
</main></body></html>"""


def make_ai_preview_url(**filters: Any) -> str:
    params = {k: v for k, v in filters.items() if v not in (None, "", [])}
    return "/reports/ai-redaction-preview.html?" + urlencode(params, doseq=True)
