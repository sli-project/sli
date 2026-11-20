from __future__ import annotations

import copy
import html
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.core.app_config import load_config
from server.sli.sources.collector_health import get_collector_health
from server.sli.core.database import is_postgres_runtime_db, query_rows_bounded
from server.sli.reporting.report_ui import report_controls, report_style
from server.sli.storage.runtime_storage import get_runtime_storage_summary
from server.sli.storage.storage_policy import build_storage_cleanup_plan
from server.sli.core.time_format import format_event_time

_SYSTEM_HEALTH_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_SYSTEM_HEALTH_CACHE_LOCK = threading.Lock()
_RUNTIME_STORAGE_CACHE_LOCK = threading.RLock()
_RUNTIME_STORAGE_CACHE: dict[str, Any] = {
    "created_monotonic": 0.0,
    "payload": None,
    "refreshing": False,
    "last_error": None,
}
SYSTEM_HEALTH_TIMEOUT_MS = 6000


def _safe_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def _fmt_bytes(value: int) -> str:
    size = float(value or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if size < 1024 or unit == "ГБ":
            return f"{size:.1f} {unit}" if unit != "Б" else f"{int(size)} Б"
        size /= 1024
    return f"{int(value)} Б"


def _cache_seconds() -> int:
    try:
        return max(0, min(int(os.getenv("ADLOG_SYSTEM_HEALTH_CACHE_SECONDS", "30")), 300))
    except ValueError:
        return 30


def _runtime_storage_cache_seconds() -> int:
    try:
        return max(60, min(int(os.getenv("ADLOG_RUNTIME_STORAGE_CACHE_SECONDS", "300")), 3600))
    except ValueError:
        return 300


def clear_system_health_cache() -> None:
    with _SYSTEM_HEALTH_CACHE_LOCK:
        _SYSTEM_HEALTH_CACHE.clear()
    with _RUNTIME_STORAGE_CACHE_LOCK:
        _RUNTIME_STORAGE_CACHE.update(
            {"created_monotonic": 0.0, "payload": None, "refreshing": False, "last_error": None}
        )


def _store_runtime_storage_snapshot(payload: dict[str, Any]) -> None:
    with _RUNTIME_STORAGE_CACHE_LOCK:
        _RUNTIME_STORAGE_CACHE.update(
            {
                "created_monotonic": time.monotonic(),
                "payload": payload,
                "refreshing": False,
                "last_error": None,
            }
        )
    with _SYSTEM_HEALTH_CACHE_LOCK:
        _SYSTEM_HEALTH_CACHE.clear()


def _runtime_storage_response(
    payload: dict[str, Any], *, age_seconds: float, stale: bool, refreshing: bool, cache_hit: bool
) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    scan = result.get("scan") or {}
    complete = bool(scan.get("complete_project_tree")) and int(scan.get("errors") or 0) == 0
    result["snapshot"] = {
        "status": "ready" if complete else "incomplete",
        "scope": "complete_project_tree",
        "generated_at_utc": result.get("generated_at_utc"),
        "age_ms": max(0, int(age_seconds * 1000)),
        "ttl_seconds": _runtime_storage_cache_seconds(),
        "cache_hit": cache_hit,
        "stale": stale,
        "refreshing": refreshing,
    }
    return result


def _warming_runtime_storage(last_error: str | None = None) -> dict[str, Any]:
    warning = "Полный снимок хранилища формируется; частичные размеры не показываются"
    if last_error:
        warning = f"Полный снимок хранилища пока недоступен: {last_error}"
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "sizes": {},
        "counts": {},
        "disk": {},
        "warnings": [warning],
        "scan": {
            "mode": "single_pass",
            "scope": "project_tree",
            "complete_project_tree": False,
            "status": "warming",
            "files_seen": None,
            "errors": None,
        },
        "snapshot": {
            "status": "warming" if not last_error else "unavailable",
            "scope": "complete_project_tree",
            "generated_at_utc": None,
            "age_ms": None,
            "ttl_seconds": _runtime_storage_cache_seconds(),
            "cache_hit": False,
            "stale": False,
            "refreshing": True,
            "last_error": last_error,
        },
    }


def _runtime_storage_refresh_worker() -> None:
    try:
        _store_runtime_storage_snapshot(get_runtime_storage_summary())
    except Exception as exc:  # defensive: storage warmup must never stop HTTP startup
        with _RUNTIME_STORAGE_CACHE_LOCK:
            _RUNTIME_STORAGE_CACHE["refreshing"] = False
            _RUNTIME_STORAGE_CACHE["last_error"] = f"{type(exc).__name__}: {exc}"


def warm_system_health_storage_async() -> bool:
    """Start one read-only full project scan outside the HTTP request path."""
    with _RUNTIME_STORAGE_CACHE_LOCK:
        if _RUNTIME_STORAGE_CACHE.get("refreshing"):
            return False
        _RUNTIME_STORAGE_CACHE["refreshing"] = True
    thread = threading.Thread(target=_runtime_storage_refresh_worker, name="system-storage-warmup", daemon=True)
    thread.start()
    return True


def _runtime_storage_for_system_health(*, force: bool) -> dict[str, Any]:
    if force:
        payload = get_runtime_storage_summary()
        _store_runtime_storage_snapshot(payload)
        return _runtime_storage_response(payload, age_seconds=0.0, stale=False, refreshing=False, cache_hit=False)

    now = time.monotonic()
    with _RUNTIME_STORAGE_CACHE_LOCK:
        cached = _RUNTIME_STORAGE_CACHE.get("payload")
        age = now - float(_RUNTIME_STORAGE_CACHE.get("created_monotonic") or 0.0)
        refreshing = bool(_RUNTIME_STORAGE_CACHE.get("refreshing"))
        last_error = _RUNTIME_STORAGE_CACHE.get("last_error")
    if cached is not None and age < _runtime_storage_cache_seconds():
        return _runtime_storage_response(cached, age_seconds=age, stale=False, refreshing=refreshing, cache_hit=True)

    started = warm_system_health_storage_async()
    if cached is not None:
        return _runtime_storage_response(
            cached,
            age_seconds=age,
            stale=True,
            refreshing=started or refreshing,
            cache_hit=True,
        )
    return _warming_runtime_storage(last_error=last_error)


def _runtime_size(runtime_storage: dict[str, Any], key: str) -> int:
    try:
        return int(((runtime_storage.get("sizes") or {}).get(key) or {}).get("bytes") or 0)
    except (TypeError, ValueError):
        return 0




def _storage_health_summary(runtime_storage: dict[str, Any]) -> dict[str, Any]:
    """Build the System Health storage card from the same filesystem snapshot.

    The dedicated /api/storage/health endpoint retains deep capacity, cleanup and
    PostgreSQL operations diagnostics. System Health intentionally avoids invoking
    that heavier workflow on every page load.
    """
    warnings = [str(item) for item in (runtime_storage.get("warnings") or [])]
    disk = runtime_storage.get("disk") or {}
    return {
        "status": "warn" if warnings else "ok",
        "warnings": warnings,
        "disk_pressure": {
            "free_percent": disk.get("free_percent"),
            "free_bytes": disk.get("free_bytes"),
            "free_human": disk.get("free_human"),
        },
        "source": "runtime_storage_single_pass",
        "detail_endpoint": "/api/storage/health",
        "deep_diagnostics_deferred": True,
    }


def _db_inventory() -> dict[str, Any]:
    rows = query_rows_bounded(
        """
        select c.relname as table_name,
               greatest(c.reltuples, 0)::bigint as estimated_rows,
               pg_database_size(current_database())::bigint as database_size_bytes
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = current_schema()
          and c.relname in ('events_v2_core', 'servers', 'findings')
        """,
        statement_timeout_ms=SYSTEM_HEALTH_TIMEOUT_MS,
    )
    estimates = {str(row.get("table_name")): int(row.get("estimated_rows") or 0) for row in rows}
    size_bytes = int(rows[0].get("database_size_bytes") or 0) if rows else 0
    return {
        "backend": "postgres",
        "path": "PostgreSQL current_database()",
        "size_bytes": size_bytes,
        "size_human": _fmt_bytes(size_bytes),
        "events": estimates.get("events_v2_core", 0),
        "servers": estimates.get("servers", 0),
        "findings": estimates.get("findings", 0),
        "counts_are_estimates": True,
        "count_source": "pg_class.reltuples",
    }


def get_system_health(*, force: bool = False) -> dict[str, Any]:
    postgres = is_postgres_runtime_db()
    if not postgres:
        raise RuntimeError("system health requires PostgreSQL runtime")
    backend = "postgres"
    cache_key = backend
    cache_seconds = _cache_seconds()
    now = time.monotonic()
    if not force and cache_seconds:
        with _SYSTEM_HEALTH_CACHE_LOCK:
            cached = _SYSTEM_HEALTH_CACHE.get(cache_key)
        if cached and now - cached[0] <= cache_seconds:
            payload = dict(cached[1])
            payload["cache"] = {
                "hit": True,
                "ttl_seconds": cache_seconds,
                "age_ms": int((now - cached[0]) * 1000),
            }
            return payload

    started = time.perf_counter()
    timings: dict[str, int] = {}

    def measured(name: str, fn):
        component_started = time.perf_counter()
        value = fn()
        timings[name] = int((time.perf_counter() - component_started) * 1000)
        return value

    cfg = measured("config", load_config)
    db = measured("db_inventory", lambda: _db_inventory())
    collector = measured("collector_health", lambda: get_collector_health())
    retention = measured("retention", lambda: build_storage_cleanup_plan())
    runtime_storage = measured("runtime_storage", lambda: _runtime_storage_for_system_health(force=force))
    storage_health = measured("storage_health_summary", lambda: _storage_health_summary(runtime_storage))

    security_high = int((collector.get("summary") or {}).get("security_high") or 0)
    warnings: list[str] = []
    if security_high:
        warnings.append("Есть высокий риск качества сбора Security")
    if retention["total_candidates"]:
        warnings.append("Есть кандидаты на очистку по retention")
    warnings.extend(runtime_storage.get("warnings") or [])
    warnings.extend(storage_health.get("warnings") or [])
    warnings = list(dict.fromkeys(str(item) for item in warnings))

    config_payload = cfg.to_dict()

    storage_snapshot = runtime_storage.get("snapshot") or {}
    storage_has_values = storage_snapshot.get("status") in {"ready", "incomplete"}
    data_bytes = _runtime_size(runtime_storage, "data") if storage_has_values else None
    reports_bytes = _runtime_size(runtime_storage, "reports") if storage_has_values else None
    logs_bytes = _runtime_size(runtime_storage, "logs") if storage_has_values else None
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "warn" if warnings else "ok",
        "warnings": warnings,
        "config": config_payload,
        "db": db,
        "storage": {
            "data_dir_bytes": data_bytes,
            "reports_dir_bytes": reports_bytes,
            "logs_dir_bytes": logs_bytes,
            "data_dir_human": _fmt_bytes(data_bytes) if data_bytes is not None else "—",
            "reports_dir_human": _fmt_bytes(reports_bytes) if reports_bytes is not None else "—",
            "logs_dir_human": _fmt_bytes(logs_bytes) if logs_bytes is not None else "—",
            "source": "full_project_runtime_storage_snapshot",
        },
        "runtime_storage": runtime_storage,
        "storage_health": storage_health,
        "retention": {
            "candidates": retention["total_candidates"],
            "bytes": retention["total_bytes"],
            "bytes_human": _fmt_bytes(retention["total_bytes"]),
        },
        "collector_summary": collector.get("summary") or {},
        "performance": {
            "total_duration_ms": int((time.perf_counter() - started) * 1000),
            "component_duration_ms": timings,
            "bounded_db_timeout_ms": SYSTEM_HEALTH_TIMEOUT_MS,
        },
        "cache": {"hit": False, "ttl_seconds": cache_seconds, "age_ms": 0},
    }
    if not storage_snapshot.get("refreshing") and storage_snapshot.get("status") in {"ready", "incomplete"}:
        with _SYSTEM_HEALTH_CACHE_LOCK:
            _SYSTEM_HEALTH_CACHE[cache_key] = (time.monotonic(), payload)
    return payload


def render_system_health_report(data: dict[str, Any]) -> str:
    warnings = data.get("warnings") or []
    warnings_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in warnings) or "<li>Критичных предупреждений нет.</li>"
    cfg = data.get("config") or {}
    cfg_rows = "".join(f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>" for k, v in cfg.items())
    db = data.get("db") or {}
    storage = data.get("storage") or {}
    runtime_storage = data.get("runtime_storage") or {}
    runtime_sizes = runtime_storage.get("sizes") or {}
    runtime_counts = runtime_storage.get("counts") or {}
    runtime_scan = runtime_storage.get("scan") or {}
    runtime_snapshot = runtime_storage.get("snapshot") or {}
    project_scope_label = "Проект целиком"
    disk = runtime_storage.get("disk") or {}
    last_cleanup = runtime_storage.get("last_raw_cleanup") or {}
    retention = data.get("retention") or {}
    collector = data.get("collector_summary") or {}
    runtime_rows = "".join(
        f"<tr><th>{html.escape(label)}</th><td>{html.escape(str((runtime_sizes.get(key) or {}).get('human', '—')))}</td><td>{html.escape(str((runtime_sizes.get(key) or {}).get('bytes', '—')))}</td></tr>"
        for key, label in (
            ("project", project_scope_label),
            ("data", "data/"),
            ("raw", "data/raw"),
            ("raw_archive", "data/raw_archive"),
            ("processed", "data/processed"),
            ("reports", "data/reports"),
            ("logs", "data/logs"),
            ("backups", "backups/"),
            ("maintenance", "data/maintenance"),
        )
    )
    cleanup_exclusions = last_cleanup.get("exclusion_summary") or {}
    cleanup_exclusions_html = "".join(
        f"<li>{html.escape(str(k))}: {html.escape(str(v))}</li>" for k, v in cleanup_exclusions.items()
    ) or "<li>Последний dry-run/apply еще не выполнялся или исключений не было.</li>"
    last_cleanup_html = (
        f"<div class='card'><div class='muted'>Последний raw cleanup</div>"
        f"<h3>{html.escape(str(last_cleanup.get('mode', 'нет данных')))}</h3>"
        f"<p>Режим архивации: {html.escape(str(last_cleanup.get('archive_mode', '—')))}; кандидатов: {html.escape(str(last_cleanup.get('total_candidates', '—')))}; объем: {html.escape(str(last_cleanup.get('total_human', '—')))}.</p>"
        f"<p class='muted'>Записано: {html.escape(format_event_time(last_cleanup.get('recorded_at_utc')) if last_cleanup.get('recorded_at_utc') else '—')}</p></div>"
        if last_cleanup
        else "<div class='card'><div class='muted'>Последний raw cleanup</div><h3>нет данных</h3><p>Запустите dry-run: <code>python scripts/maintenance/raw_storage_cleanup.py</code>. Он покажет кандидатов и причины исключения без переноса raw-файлов.</p></div>"
    )
    return f"""<!doctype html>
<html lang=\"ru\">
<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Состояние системы</title>{report_style()}</head>
<body>{report_controls()}<main class=\"wrap\">
<header class=\"hero\"><div class=\"eyebrow\">Эксплуатация</div><h1>Состояние системы</h1><p class=\"subtitle\">Проверка runtime-файлов, активной базы данных, отчетов, логов, retention и качества сбора.</p><div class=\"pillrow\"><span class=\"pill\">Статус: {html.escape(str(data.get('status')))}</span><span class=\"pill\">Сформирован: {html.escape(format_event_time(data.get('generated_at_utc')))}</span></div></header>
<section><h2>Кратко</h2><div class=\"grid kpi\"><div class=\"card\"><div class=\"muted\">{html.escape(str(db.get('backend') or 'База данных'))}</div><h3>{html.escape(str(db.get('size_human')))}</h3><p>{html.escape(str(db.get('events')))} событий, {html.escape(str(db.get('servers')))} серверов; {'оценка' if db.get('counts_are_estimates') else 'точно'}</p></div><div class=\"card\"><div class=\"muted\">Findings</div><h3>{html.escape(str(db.get('findings')))}</h3><p>объекты проверки</p></div><div class=\"card\"><div class=\"muted\">Retention</div><h3>{html.escape(str(retention.get('candidates')))}</h3><p>{html.escape(str(retention.get('bytes_human')))} кандидатов на очистку</p></div><div class=\"card\"><div class=\"muted\">Security high</div><h3>{html.escape(str(collector.get('security_high', 0)))}</h3><p>каналы с высоким риском качества</p></div></div></section>
<section><h2>Предупреждения</h2><ul>{warnings_html}</ul></section>
<section><h2>Хранилище проекта</h2><div class="grid kpi"><div class="card"><div class="muted">{html.escape(project_scope_label)}</div><h3>{html.escape(str((runtime_sizes.get('project') or {}).get('human', '—')))}</h3><p>{html.escape(str(runtime_counts.get('raw_files', 0)))} временных raw-файлов</p></div><div class="card"><div class="muted">data/raw</div><h3>{html.escape(str((runtime_sizes.get('raw') or {}).get('human', '—')))}</h3><p>временный буфер разработки</p></div><div class="card"><div class="muted">PostgreSQL</div><h3>{html.escape(str(db.get('size_human', '—')))}</h3><p>единственный runtime backend</p></div><div class="card"><div class="muted">Диск</div><h3>{html.escape(str(disk.get('free_human', '—')))}</h3><p>свободно: {html.escape(str(disk.get('free_percent', '—')))}%</p></div></div><p class="muted">Полный снимок охватывает весь действующий корень проекта. Состояние: {html.escape(str(runtime_snapshot.get('status', 'не сформирован')))}; возраст: {html.escape(str(runtime_snapshot.get('age_ms', '—')))} мс; ошибок чтения: {html.escape(str(runtime_scan.get('errors', '—')))}. Пока снимок формируется, частичные размеры не показываются.</p></section>

<section><h2>Детализация storage</h2><table><thead><tr><th>Категория</th><th>Размер</th><th>Байт</th></tr></thead><tbody>{runtime_rows}</tbody></table><div class="grid two mt">{last_cleanup_html}<div class="card"><div class="muted">Почему raw не попал в кандидаты</div><ul>{cleanup_exclusions_html}</ul><p class="muted">Проверка: <code>python scripts/maintenance/raw_storage_cleanup.py --older-than-days 7</code>. Применение переноса: добавить <code>--apply</code>; zip-архив: <code>--archive-mode zip --apply</code>.</p></div></div></section>

<section><h2>Хранилище legacy summary</h2><table><tbody><tr><th>База</th><td>{html.escape(str(db.get('path')))}</td></tr><tr><th>data/</th><td>{html.escape(str(storage.get('data_dir_human')))}</td></tr><tr><th>Отчеты</th><td>{html.escape(str(storage.get('reports_dir_human')))}</td></tr><tr><th>Логи</th><td>{html.escape(str(storage.get('logs_dir_human')))}</td></tr></tbody></table></section>
<section><h2>Конфигурация</h2><table><thead><tr><th>Параметр</th><th>Значение</th></tr></thead><tbody>{cfg_rows}</tbody></table></section>
</main></body></html>"""
