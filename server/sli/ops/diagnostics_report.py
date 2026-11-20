from __future__ import annotations

import html
import json
import sys
import time
from collections.abc import Callable
from typing import Any

from scripts.maintenance.bundle_common import (
    run_command,  # subprocess-проверки (строки 1-2 таблицы 5.1) остаются изолированными
)
from server.sli.ops.diagnostics_support import (
    LOG_DIR,
    assess_recent_internal_errors,
    tail_lines,
)
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.core.time_format import format_event_time
from server.sli.ops.version import get_release_metadata


def _parse_json_command(result: dict[str, Any]) -> dict[str, Any] | None:
    text = str(result.get("stdout_tail") or "")
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except Exception:
        return None


def _run_in_process_check(func: Callable[[], dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Вызвать проверку в процессе; исключение превращается в проваленную проверку."""
    started = time.monotonic()
    try:
        payload = func()
    except Exception as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        error = {"status": "failed", "duration_ms": duration_ms, "error_type": type(exc).__name__}
        entry = {"command": "in-process", "exit_code": -1, "timed_out": False, "duration_ms": duration_ms, "error_type": type(exc).__name__}
        return entry, error
    duration_ms = int((time.monotonic() - started) * 1000)
    entry = {"command": "in-process", "exit_code": 0, "timed_out": False, "duration_ms": duration_ms}
    return entry, payload


def get_diagnostics_overview(*, run_checks: bool = False) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    in_process: dict[str, dict[str, Any]] = {}
    if run_checks:
        checks["self_test_offline"] = run_command([sys.executable, "scripts/maintenance/self_test.py", "--offline", "--json"], timeout=45)
        checks["release_check"] = run_command([sys.executable, "scripts/maintenance/release_check.py", "--json"], timeout=45)
        from server.sli.ops.runtime_watchdog import run_watchdog
        from server.sli.ops.ui_nav_check import run_ui_nav_check

        for name, func in (("ui_nav_check", run_ui_nav_check), ("runtime_watchdog", run_watchdog)):
            checks[name], in_process[name] = _run_in_process_check(func)
    latest = {
        "internal_errors_tail": tail_lines(LOG_DIR / "internal-errors.log", 20),
        "self_test_tail": tail_lines(LOG_DIR / "self-test.log", 20),
        "release_check_tail": tail_lines(LOG_DIR / "release-check.log", 20),
        "performance_tail": tail_lines(LOG_DIR / "performance-events.log", 20),
    }
    parsed_checks = {name: in_process[name] if name in in_process else _parse_json_command(value) for name, value in checks.items()}
    warnings: list[str] = []
    for name, parsed in parsed_checks.items():
        if parsed and parsed.get("status") not in {"ok", None}:
            warnings.append(f"{name}: status={parsed.get('status')}")
        elif checks.get(name, {}).get("exit_code") not in (0, None):
            warnings.append(f"{name}: exit_code={checks[name].get('exit_code')}")
    internal_errors = assess_recent_internal_errors(
        latest["internal_errors_tail"],
        activity_text=tail_lines(LOG_DIR / "adlog-monitor.log", 1000),
    )
    if internal_errors["active"]:
        warnings.append(f"internal-errors.log has {internal_errors['active_count']} active errors in the last 30 minutes")
    return {
        "status": "warn" if warnings else "ok",
        "release_metadata": get_release_metadata(),
        "checks": checks,
        "parsed_checks": parsed_checks,
        "logs": latest,
        "internal_errors": internal_errors,
        "warnings": warnings,
    }


def render_diagnostics_report(data: dict[str, Any]) -> str:
    metadata = data.get("release_metadata") or {}
    warnings = data.get("warnings") or []
    warning_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in warnings) or "<li>Активных предупреждений на странице нет.</li>"
    checks = data.get("parsed_checks") or {}
    cards = "".join(
        f"<div class='card'><div class='muted'>{html.escape(name)}</div><h3>{html.escape(str((payload or {}).get('status', 'not run')))}</h3><p>{html.escape(str((payload or {}).get('duration_ms', '—')))} ms</p></div>"
        for name, payload in checks.items()
    ) or "<div class='card'><h3>Быстрые проверки не запускались</h3><p>CLI: <code>python scripts/maintenance/self_test.py --offline --json</code></p></div>"
    logs = data.get("logs") or {}
    internal = html.escape(str(logs.get("internal_errors_tail") or "").strip()[-4000:]) or "нет последних ошибок"
    selftest = html.escape(str(logs.get("self_test_tail") or "").strip()[-4000:]) or "self-test.log пуст или еще не создан"
    return f"""<!doctype html>
<html lang=\"ru\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Диагностика</title>{report_style()}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Stage 1 Diagnostics</div><h1>Диагностика и self-test</h1><p class=\"subtitle\">Техническая страница для проверки release gate, self-test, internal errors и runtime watchdog.</p><div class=\"pillrow\"><span class=\"pill\">Статус: {html.escape(str(data.get('status')))}</span><span class=\"pill\">Версия: {html.escape(str(metadata.get('project_version')))}</span><span class=\"pill\">Сформирован: {html.escape(format_event_time(metadata.get('generated_at_utc')))}</span></div></header>
<section><h2>Быстрые команды</h2><div class=\"toolbar\"><code>python scripts/maintenance/self_test.py --offline --json</code><code>python scripts/maintenance/ui_nav_check.py --json</code><code>python scripts/maintenance/runtime_watchdog.py --json</code><code>python scripts/maintenance/collect_diagnostics.py</code></div></section>
<section><h2>Предупреждения</h2><ul>{warning_html}</ul></section>
<section><h2>Последние проверки</h2><div class=\"grid kpi\">{cards}</div></section>
<section><h2>Последние internal errors</h2><pre>{internal}</pre></section>
<section><h2>Последний self-test log</h2><pre>{selftest}</pre></section>
</main></body></html>"""
