#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Export rendered Security Log Intelligence reports to a standalone folder.

The script is diagnostic only: it performs HTTP GET requests against the
already running local web application and saves HTML/JSON responses for review.
It does not connect to AD, does not change servers, and does not modify SQLite
or raw logs.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import html
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


DEFAULT_BASE_URL = "http://127.0.0.1:8080"


@dataclass(frozen=True)
class Target:
    name: str
    path: str
    kind: str = "html"
    description: str = ""


@dataclass
class CaptureResult:
    name: str
    kind: str
    source_url: str
    output_file: str
    status_code: int | None
    ok: bool
    content_type: str = ""
    bytes: int = 0
    elapsed_ms: int = 0
    error: str = ""
    warnings: list[str] = field(default_factory=list)


def _utc_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d_%H%M%S")


def _safe_name(value: str, max_len: int = 110) -> str:
    value = value.strip().lower()
    value = re.sub(r"^/+", "", value)
    value = value.replace("/", "__")
    value = re.sub(r"[^a-zа-яё0-9_.=-]+", "_", value, flags=re.IGNORECASE)
    value = re.sub(r"_+", "_", value).strip("._-")
    return (value or "root")[:max_len]


def _join_url(base_url: str, path: str) -> str:
    base = base_url.rstrip("/") + "/"
    return urllib.parse.urljoin(base, path.lstrip("/"))


def _query_path(path: str, **params: object) -> str:
    clean_params = {
        key: value
        for key, value in params.items()
        if value is not None and str(value) != ""
    }
    if not clean_params:
        return path
    sep = "&" if "?" in path else "?"
    return path + sep + urllib.parse.urlencode(clean_params, doseq=True)


def _decode_body(body: bytes, content_type: str) -> str:
    charset = "utf-8"
    match = re.search(r"charset=([^;\s]+)", content_type or "", re.IGNORECASE)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        return body.decode(charset, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _redact_scalar(value: str) -> str:
    """Redact one string without using replacement backslash escapes."""
    value = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip_xxx", value)
    value = re.sub(r"\bS-\d-\d+(?:-\d+){2,}\b", "sid_xxx", value)
    value = re.sub(
        r"\b[A-Za-zА-Яа-я0-9_.-]+\\[A-Za-zА-Яа-я0-9_.\$-]+\b",
        lambda _m: "DOMAIN\\account_xxx",
        value,
    )
    value = re.sub(r"\b(?:[A-Za-z0-9-]+\.){2,}[A-Za-z]{2,}\b", "host.host13.example.invalid", value)
    value = re.sub(
        r"\\\\[A-Za-z0-9_.-]+\\[^\s<>'\"]+",
        lambda _m: r"\\server\share\path",
        value,
    )
    value = re.sub(r"\b[A-Za-z]:\\[^\s<>'\"]+", lambda _m: r"C:\path", value)
    return value


def _redact_json_value(value: Any) -> Any:
    if isinstance(value, str):
        return _redact_scalar(value)
    if isinstance(value, list):
        return [_redact_json_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_json_value(item) for key, item in value.items()}
    return value


def _redact_text(text: str, *, kind: str = "html") -> str:
    """Lightweight optional redaction for a portable review bundle.

    JSON is parsed and dumped again so backslashes stay valid JSON escapes.
    HTML/plain text is redacted with function replacements to avoid re.sub
    replacement escape sequences such as ``\a`` turning into control chars.
    """
    if kind == "api":
        try:
            parsed = json.loads(text)
        except Exception:
            return _redact_scalar(text)
        return json.dumps(_redact_json_value(parsed), ensure_ascii=False, indent=2)
    return _redact_scalar(text)




def _visible_text_for_lint(text: str) -> str:
    """Approximate visible HTML text for page-lint.

    Raw UTC values are allowed in title/tooltips and technical attributes, but
    the normal user-visible text must not show ISO timestamps. The exporter is
    a lightweight smoke tool, so a conservative tag/comment/style stripper is
    sufficient here and avoids flagging hidden technical context.
    """
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    text = re.sub(r"<script\b.*?</script>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    return html.unescape(text)

def _warnings_for_text(text: str, status_code: int | None, byte_len: int, *, kind: str = "html") -> list[str]:
    """Return page-lint warnings for captured HTML/API text.

    The checks are intentionally conservative: they do not decide incident
    severity, they only flag report quality problems that should be reviewed
    before a patch is released.
    """
    warnings: list[str] = []

    if status_code is None:
        warnings.append("нет HTTP-статуса")
    elif status_code >= 500:
        warnings.append(f"ошибка сервера HTTP {status_code}")
    elif status_code >= 400:
        warnings.append(f"ошибка HTTP {status_code}")

    visible_text = _visible_text_for_lint(text) if kind != "api" else text

    checks = {
        "Traceback": "обнаружен Traceback",
        "Internal Server Error": "обнаружен Internal Server Error",
        "Failed to fetch": "обнаружен Failed to fetch",
        "API: ошибка": "обнаружена API: ошибка",
        "undefined": "обнаружено undefined",
        "NaN": "обнаружено NaN",
    }
    for needle, label in checks.items():
        haystack = visible_text if kind != "api" else text
        if needle in haystack:
            warnings.append(label)

    if kind == "api" and text:
        try:
            json.loads(text)
        except Exception:
            warnings.append("API JSON невалиден")

    if kind != "api" and re.search(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", visible_text):
        warnings.append("найден сырой ISO timestamp")

    technical_statuses = "repeated|active|new|closed|false_positive|confirmed|investigating|suppressed|resolved"
    if re.search(rf"\b({technical_statuses})\b", visible_text if kind != "api" else text):
        warnings.append("найден технический статус finding/status")

    if kind != "api":
        if re.search(r"<pre[^>]*>\s*[\[{]", text, re.IGNORECASE):
            warnings.append("найден raw JSON/pre-блок в пользовательском UI")
        if re.search(r"<code[^>]*>\s*(undefined|NaN|null)\s*</code>", text, re.IGNORECASE):
            warnings.append("найден технический placeholder в code-блоке")

    for match in re.finditer(r"Связанные сущности:\s*(.{1500,}?)(?:</p>|</div>|</section>)", text, re.DOTALL):
        sample = re.sub(r"\s+", " ", match.group(1))
        warnings.append(f"слишком длинный блок связанных сущностей ({min(len(sample), 999999)} символов)")
        break

    text_only = re.sub(r"<[^>]+>", " ", text) if kind != "api" else text
    if re.search(r"([^\s,;]{8,}[,;]\s*){80,}", text_only):
        warnings.append("найден слишком длинный повторяющийся текстовый блок")

    if byte_len > 2_000_000:
        warnings.append("ответ больше 2 МБ — возможно, раздувание отчета")

    return warnings


def _save_response(
    target: Target,
    base_url: str,
    output_dir: Path,
    timeout: int,
    redact: bool = False,
) -> CaptureResult:
    url = _join_url(base_url, target.path)
    ext = ".json" if target.kind == "api" else ".html"
    # Never derive shareable filenames from queries: slugging loses the
    # structure the bounded identity redactor needs to recognize them.
    saved_name = f"capture_{uuid.uuid4().hex}" if redact else target.name
    output_file = output_dir / f"{_safe_name(saved_name)}{ext}"
    source_url = "[URL withheld]" if redact else url

    started = time.perf_counter()
    status_code: int | None = None
    content_type = ""
    body = b""
    error = ""

    try:
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "SecurityLogIntelligenceSnapshot/1.0",
                "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            },
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = int(resp.status)
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read()
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        body = exc.read() or b""
        error = f"HTTPError: {exc}"
    except Exception as exc:  # noqa: BLE001 - diagnostic script
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    text = _decode_body(body, content_type) if body else ""

    if redact and text:
        text = _redact_text(text, kind=target.kind)
        body = text.encode("utf-8")
        content_type = content_type or "text/plain; charset=utf-8"

    if target.kind == "api" and text:
        try:
            parsed = json.loads(text)
            text = json.dumps(parsed, ensure_ascii=False, indent=2)
            body = text.encode("utf-8")
        except Exception:
            pass

    if redact:
        # Exception text and response headers are arbitrary server-controlled
        # strings; withholding them avoids leaking encoded URLs/identities.
        error = "Capture failed (details withheld)" if error else ""
        content_type = "application/json" if target.kind == "api" else "text/html"

    if text:
        output_file.write_text(text, encoding="utf-8")
    else:
        output_file.write_text(f"Snapshot failed for {source_url}\n{error}\n", encoding="utf-8")

    warnings = _warnings_for_text(text, status_code, len(body), kind=target.kind)
    return CaptureResult(
        name=saved_name,
        kind=target.kind,
        source_url=source_url,
        output_file=str(output_file.name),
        status_code=status_code,
        ok=(status_code is not None and 200 <= status_code < 400 and not error),
        content_type=content_type,
        bytes=len(body),
        elapsed_ms=elapsed_ms,
        error=error,
        warnings=warnings,
    )


def build_targets(q_values: Iterable[str], include_api: bool = True) -> list[Target]:
    q_values = [q for q in q_values if q]
    if not q_values:
        q_values = ["administrator", "DC1", "DC2"]

    targets: list[Target] = [
        Target("home", "/", "html", "Главная страница"),
        Target("collector_health", "/reports/collector-health.html", "html", "Состояние сбора"),
        Target("system_health", "/reports/system-health.html", "html", "Состояние системы"),
        Target("findings", "/reports/findings.html", "html", "Findings"),
        Target("security_events_monitor", "/reports/security-events-monitor.html", "html", "ИБ-мониторинг ключевых событий"),
        Target("investigation_empty", "/reports/investigation.html", "html", "Рабочее место расследования без запроса"),
        Target("search_empty", "/reports/search.html", "html", "Глобальный поиск без запроса"),
        Target("role_overview_all", "/reports/role-overview.html", "html", "Ролевой обзор"),
        Target("role_overview_security", "/reports/role-overview.html?view=security", "html", "Ролевой обзор ИБ"),
        Target("role_overview_it", "/reports/role-overview.html?view=it", "html", "Ролевой обзор ИТ"),
        Target("role_overview_technical", "/reports/role-overview.html?view=technical", "html", "Ролевой обзор технический"),
        Target("ai_reports", "/reports/ai-reports.html", "html", "История AI-отчетов"),
        Target("ai_analysis_latest", "/reports/ai-analysis.html", "html", "Последний AI-отчет"),
        Target("event_details_security_recent", "/reports/event-details.html?channel=Security&limit=100", "html", "Последние Security events"),
        Target("event_details_4624", "/reports/event-details.html?event_id=4624&channel=Security&limit=100", "html", "Успешные входы"),
        Target("event_details_4625", "/reports/event-details.html?event_id=4625&channel=Security&limit=100", "html", "Ошибки входа"),
        Target("event_details_4724", "/reports/event-details.html?event_id=4724&channel=Security&limit=100", "html", "Сброс пароля"),
        Target("event_details_4740", "/reports/event-details.html?event_id=4740&channel=Security&limit=100", "html", "Блокировки"),
        Target("event_details_4728", "/reports/event-details.html?event_id=4728&channel=Security&limit=100", "html", "Добавление в группу"),
    ]

    for raw_q in q_values:
        slug = _safe_name(raw_q, 50)
        targets.extend(
            [
                Target(f"investigation_q_{slug}", _query_path("/reports/investigation.html", q=raw_q, limit=300), "html", f"Расследование по {raw_q}"),
                Target(f"search_q_{slug}", _query_path("/reports/search.html", q=raw_q, limit=200), "html", f"Поиск по {raw_q}"),
                Target(f"account_timeline_q_{slug}", _query_path("/reports/account-timeline.html", q=raw_q, limit=300), "html", f"Timeline учетной записи/объекта {raw_q}"),
                Target(f"entity_details_q_{slug}", _query_path("/reports/entity-details.html", q=raw_q), "html", f"Карточка сущности {raw_q}"),
                Target(f"ai_redaction_preview_q_{slug}", _query_path("/reports/ai-redaction-preview.html", q=raw_q, limit=50, redaction_level="strict"), "html", f"AI redaction preview по {raw_q}"),
                Target(f"ai_prompt_preview_q_{slug}", _query_path("/reports/ai-prompt-preview.html", q=raw_q, limit=50, redaction_level="strict"), "html", f"AI prompt preview по {raw_q}"),
            ]
        )

    if include_api:
        api_targets = [
            Target("api_collector_health", "/api/collector/health", "api", "API состояния сбора"),
            Target("api_system_health", "/api/system/health", "api", "API состояния системы"),
            Target("api_findings", "/api/findings", "api", "API findings"),
            Target("api_security_events_monitor", "/api/security/events-monitor?limit=200", "api", "API ИБ-мониторинга"),
            Target("api_role_views", "/api/role-views", "api", "API ролевых представлений"),
            Target("api_ai_runs", "/api/ai/runs", "api", "API AI runs"),
        ]
        for raw_q in q_values:
            slug = _safe_name(raw_q, 50)
            api_targets.extend(
                [
                    Target(f"api_investigation_q_{slug}", _query_path("/api/investigation/workspace", q=raw_q, limit=300), "api", f"API расследования по {raw_q}"),
                    Target(f"api_events_search_q_{slug}", _query_path("/api/events/search", q=raw_q, limit=200), "api", f"API поиска по {raw_q}"),
                    Target(f"api_ai_redaction_preview_q_{slug}", _query_path("/api/ai/redaction-preview", q=raw_q, limit=50, redaction_level="strict"), "api", f"API redaction preview по {raw_q}"),
                    Target(f"api_ai_prompt_preview_q_{slug}", _query_path("/api/ai/prompt-preview", q=raw_q, limit=50, redaction_level="strict"), "api", f"API prompt preview по {raw_q}"),
                ]
            )
        targets.extend(api_targets)

    return targets


def write_index(output_dir: Path, results: list[CaptureResult], base_url: str, redact: bool) -> None:
    generated = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ok_count = sum(1 for r in results if r.ok)
    warn_count = sum(1 for r in results if r.warnings)
    fail_count = sum(1 for r in results if not r.ok)

    rows = []
    for result in results:
        status = "OK" if result.ok else "ERROR"
        warn_html = "<br>".join(html.escape(w) for w in result.warnings) if result.warnings else "—"
        rows.append(
            "<tr>"
            f"<td><span class='badge {status.lower()}'>{status}</span></td>"
            f"<td>{html.escape(result.kind)}</td>"
            f"<td><a href='{html.escape(result.output_file)}'>{html.escape(result.name)}</a></td>"
            f"<td>{html.escape(str(result.status_code or '—'))}</td>"
            f"<td>{result.bytes:,}</td>"
            f"<td>{result.elapsed_ms}</td>"
            f"<td>{warn_html}</td>"
            f"<td><a href='{html.escape(result.source_url)}'>{html.escape(result.source_url)}</a></td>"
            "</tr>"
        )

    index = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Security Log Intelligence — report snapshot</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#eef3f7;color:#1f2937;margin:0;}}
.wrap{{max-width:1400px;margin:0 auto;padding:24px;}}
header,section{{background:white;border:1px solid #d8e0e8;border-radius:18px;padding:18px;margin-bottom:16px;}}
table{{width:100%;border-collapse:collapse;background:white;}}
th,td{{border:1px solid #d8e0e8;padding:8px;vertical-align:top;font-size:12px;}}
th{{background:#f8fafc;text-align:left;color:#667085;}}
.badge{{display:inline-block;border-radius:999px;padding:4px 8px;font-size:11px;font-weight:800;}}
.badge.ok{{background:#ecfdf5;color:#166534;}}
.badge.error{{background:#fee2e2;color:#991b1b;}}
.kpi{{display:flex;gap:10px;flex-wrap:wrap;}}
.kpi div{{border:1px solid #d8e0e8;border-radius:14px;padding:10px 14px;background:#f8fafc;}}
</style>
</head>
<body>
<div class="wrap">
<header>
<h1>Security Log Intelligence — snapshot отчетов</h1>
<p>Сформировано: {html.escape(generated)}</p>
<p>Источник: <code>{html.escape("[URL withheld]" if redact else base_url)}</code></p>
<p>Redaction: <strong>{"включен" if redact else "выключен"}</strong></p>
<p>Lightweight pattern masking only; not arbitrary-data DLP. Review bodies before sharing.</p>
<div class="kpi">
  <div><strong>{len(results)}</strong><br>всего целей</div>
  <div><strong>{ok_count}</strong><br>успешно</div>
  <div><strong>{warn_count}</strong><br>с предупреждениями</div>
  <div><strong>{fail_count}</strong><br>ошибки</div>
</div>
</header>
<section>
<h2>Результаты</h2>
<table>
<thead><tr><th>Статус</th><th>Тип</th><th>Файл</th><th>HTTP</th><th>Байт</th><th>мс</th><th>Предупреждения</th><th>URL</th></tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</section>
</div>
</body>
</html>"""
    (output_dir / "index.html").write_text(index, encoding="utf-8")


def write_manifest(output_dir: Path, results: list[CaptureResult], base_url: str, args: argparse.Namespace) -> None:
    manifest = {
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "base_url": "[URL withheld]" if args.redact else base_url,
        "args": {
            "q": ["[query withheld]" for _ in args.q] if args.redact else args.q,
            "timeout": args.timeout,
            "include_api": not args.no_api,
            "redact": args.redact,
        },
        "results": [asdict(r) for r in results],
    }
    (output_dir / "snapshot_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def make_zip(output_dir: Path, *, redact: bool = False) -> Path:
    zip_path = output_dir.with_suffix(".zip")
    # Exclusive creation is the final race guard after the CLI preflight.
    # Keep it outside failure handling: a collision is never our file.
    archive_file = zip_path.open("xb")
    try:
        with archive_file:
            with zipfile.ZipFile(archive_file, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for file_path in output_dir.rglob("*"):
                    if file_path.is_file():
                        archive_name = Path("snapshot") / file_path.relative_to(output_dir) if redact else file_path.relative_to(output_dir.parent)
                        zf.write(file_path, archive_name)
    except BaseException as exc:
        # Never unlink this public pathname: even an ownership stat can race
        # with another writer replacing it before unlink. Retain partial output.
        exc.add_note(
            f"ZIP export failed; possible partial archive retained at {zip_path}. "
            "Choose a fresh output destination for retry."
        )
        raise
    return zip_path


def _warning_priority(result: CaptureResult, warning: str) -> str:
    if not result.ok or "Traceback" in warning or "Internal Server Error" in warning or "JSON невалиден" in warning:
        return "P0"
    if "сырой ISO" in warning or "raw JSON" in warning or "undefined" in warning or "NaN" in warning:
        return "P1"
    return "P2"


def write_review_backlog(output_dir: Path, results: list[CaptureResult]) -> dict[str, Any]:
    """Write machine-readable and HTML snapshot review backlog.

    This turns page-lint findings into a small hotfix backlog, so report
    quality is checked as one repeatable maintenance step instead of manual
    browsing page by page.
    """
    warnings = []
    for result in results:
        if not result.ok and not result.warnings:
            warnings.append({
                "priority": "P0",
                "target": result.name,
                "kind": result.kind,
                "file": result.output_file,
                "warning": result.error or f"HTTP {result.status_code}",
                "suggested_action": "исправить ошибку генерации отчета/API до выпуска патча",
            })
        for warning in result.warnings:
            warnings.append({
                "priority": _warning_priority(result, warning),
                "target": result.name,
                "kind": result.kind,
                "file": result.output_file,
                "warning": warning,
                "suggested_action": "проверить рендеринг, форматирование данных и fallback пользовательского UI",
            })
    by_priority = Counter(item["priority"] for item in warnings)
    by_warning = Counter(item["warning"] for item in warnings)
    review = {
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "summary": {
            "targets": len(results),
            "failed": sum(1 for item in results if not item.ok),
            "with_warnings": sum(1 for item in results if item.warnings),
            "warnings": len(warnings),
            "by_priority": dict(sorted(by_priority.items())),
            "by_warning": dict(by_warning.most_common()),
        },
        "backlog": warnings,
        "manual_checklist": [
            "Открыть index.html и проверить все ERROR/WARN.",
            "Сравнить ИБ/ИТ/technical отчеты: данные не должны исчезать, только распределяться по ролям.",
            "Проверить, что обычный UI не показывает raw ISO timestamp, undefined/NaN и raw JSON.",
            "Проверить пустые состояния Investigation/Search и понятные fallback-сообщения API.",
            "Сформировать hotfix backlog по P0/P1 перед выпуском патча.",
        ],
    }
    (output_dir / "snapshot_review.json").write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")

    rows = []
    for item in warnings:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['priority'])}</td>"
            f"<td>{html.escape(item['kind'])}</td>"
            f"<td><a href='{html.escape(item['file'])}'>{html.escape(item['target'])}</a></td>"
            f"<td>{html.escape(item['warning'])}</td>"
            f"<td>{html.escape(item['suggested_action'])}</td>"
            "</tr>"
        )
    checklist = "".join(f"<li>{html.escape(item)}</li>" for item in review["manual_checklist"])
    html_report = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><title>Snapshot review backlog</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#eef3f7;color:#1f2937;margin:0}}.wrap{{max-width:1300px;margin:0 auto;padding:24px}}section,header{{background:white;border:1px solid #d8e0e8;border-radius:18px;padding:18px;margin-bottom:16px}}table{{width:100%;border-collapse:collapse}}th,td{{border:1px solid #d8e0e8;padding:8px;vertical-align:top;font-size:13px}}th{{background:#f8fafc;text-align:left;color:#667085}}</style></head>
<body><main class="wrap"><header><h1>Snapshot review backlog</h1><p>Warnings: {len(warnings)}; failed: {review['summary']['failed']}; targets: {len(results)}</p></header>
<section><h2>Backlog</h2><table><thead><tr><th>Priority</th><th>Kind</th><th>Target</th><th>Warning</th><th>Action</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="5">Warnings не найдены.</td></tr>'}</tbody></table></section>
<section><h2>Manual checklist</h2><ul>{checklist}</ul></section></main></body></html>"""
    (output_dir / "snapshot_review.html").write_text(html_report, encoding="utf-8")
    md_lines = ["# Snapshot review checklist", "", f"Targets: {len(results)}", f"Failed: {review['summary']['failed']}", f"Warnings: {len(warnings)}", "", "## Manual checklist"]
    md_lines.extend(f"- {item}" for item in review["manual_checklist"])
    md_lines.append("\n## Backlog")
    if warnings:
        md_lines.extend(f"- [{item['priority']}] {item['target']}: {item['warning']}" for item in warnings)
    else:
        md_lines.append("- Нет предупреждений page-lint.")
    (output_dir / "snapshot_review_checklist.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return review


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export rendered Security Log Intelligence reports to HTML/JSON snapshot folder.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Local app URL, default: {DEFAULT_BASE_URL}")
    parser.add_argument("--output-dir", default="", help="Output directory. Default: data/report_snapshots/<timestamp>")
    parser.add_argument("--q", action="append", default=[], help="Query/pivot value to capture. Can be repeated.")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds per request.")
    parser.add_argument("--no-api", action="store_true", help="Do not capture API JSON endpoints.")
    parser.add_argument("--redact", action="store_true", help="Mask known identity patterns in bodies and withhold query metadata/URLs/names; not arbitrary-data DLP.")
    parser.add_argument("--no-zip", action="store_true", help="Do not create ZIP archive of the snapshot folder.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path("data") / "report_snapshots" / f"snapshot_{_utc_stamp()}"

    # Repeated runs must select a new output name (or --no-zip). Never
    # replace an existing sibling archive, even if the capture directory is new.
    zip_destination = output_dir.with_suffix(".zip")
    if not args.no_zip and os.path.lexists(zip_destination):
        raise FileExistsError(f"ZIP destination already exists: {zip_destination}")
    if args.redact and output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("Redacted snapshots require an empty output directory")
    output_dir.mkdir(parents=True, exist_ok=True)

    targets = build_targets(args.q, include_api=not args.no_api)
    results: list[CaptureResult] = []

    print(f"Base URL: {args.base_url}")
    print(f"Output:   {output_dir}")
    print(f"Targets:  {len(targets)}")

    for index, target in enumerate(targets, start=1):
        print(f"[{index:02d}/{len(targets):02d}] {target.name} ... ", end="", flush=True)
        result = _save_response(target=target, base_url=args.base_url, output_dir=output_dir, timeout=args.timeout, redact=args.redact)
        results.append(result)
        marker = "OK" if result.ok else "ERROR"
        warn = f", warnings={len(result.warnings)}" if result.warnings else ""
        print(f"{marker} http={result.status_code or '-'} bytes={result.bytes}{warn}")

    write_index(output_dir, results, args.base_url, args.redact)
    write_manifest(output_dir, results, args.base_url, args)
    review = write_review_backlog(output_dir, results)

    zip_path: Path | None = None
    if not args.no_zip:
        zip_path = make_zip(output_dir, redact=args.redact)

    failed = [r for r in results if not r.ok]
    warned = [r for r in results if r.warnings]

    print("\nDone.")
    print(f"Snapshot folder: {output_dir}")
    print(f"Index:           {output_dir / 'index.html'}")
    print(f"Manifest:        {output_dir / 'snapshot_manifest.json'}")
    print(f"Review:          {output_dir / 'snapshot_review.html'}")
    print(f"Review warnings: {review['summary']['warnings']}")
    if zip_path:
        print(f"ZIP:             {zip_path}")
    print(f"Failed:          {len(failed)}")
    print(f"Warnings:        {len(warned)}")

    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
