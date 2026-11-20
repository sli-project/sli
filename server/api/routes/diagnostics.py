"""Diagnostics domain: system/storage/DB health, migration status, overview.

All routes here are read-only and ambient-gated to ``operations.view`` —
nothing in this module makes its own authorization decision. Several of
them were, and remain, one-liners inline in the original dispatcher rather
than named ``_handle_*`` methods; this module keeps that shape instead of
inventing a wrapper method that never existed.

Response helpers stay on ``RequestHandler`` in ``server.api.http_server``
and are reached through the ``handler`` instance passed to every function
here. This module never imports ``server.api.http_server``.
"""
from __future__ import annotations

from server.sli.ops.db_status import get_db_status, render_db_status_report
from server.sli.ops.diagnostics_report import get_diagnostics_overview, render_diagnostics_report
from server.sli.storage.storage_health import render_storage_health_report
from server.sli.storage.storage_policy import get_storage_health
from server.sli.ops.system_health import get_system_health, render_system_health_report

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/db/status"),
    ("GET", "/api/diagnostics/overview"),
    ("GET", "/api/storage/health"),
    ("GET", "/api/storage/lifecycle"),
    ("GET", "/api/system/health"),
    ("GET", "/reports/db-status.html"),
    ("GET", "/reports/diagnostics.html"),
    ("GET", "/reports/storage-health.html"),
    ("GET", "/reports/system-health.html"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/system/health":
        handler._send_json(get_system_health(force=(query.get("force", ["0"])[0].lower() in {"1", "true", "yes"})))
        return True
    if path == "/api/storage/health":
        handler._send_json(get_storage_health(deep=(query.get("deep", ["0"])[0].lower() in {"1", "true", "yes"})))
        return True
    if path == "/api/storage/lifecycle":
        from server.sli.storage.storage_lifecycle import get_storage_lifecycle_status

        handler._send_json(get_storage_lifecycle_status(history_limit=int(query.get("limit", ["48"])[0]), include_estimate=True))
        return True
    if path == "/api/db/status":
        handler._send_json(get_db_status(connect=(query.get("connect", ["1"])[0].lower() in {"1", "true", "yes"})))
        return True
    if path == "/api/diagnostics/overview":
        handler._send_json(get_diagnostics_overview(run_checks=(query.get("run_checks", ["0"])[0].lower() in {"1", "true", "yes"})))
        return True
    if path == "/reports/system-health.html":
        _handle_system_health_report(handler)
        return True
    if path == "/reports/storage-health.html":
        _handle_storage_health_report(handler, query)
        return True
    if path == "/reports/db-status.html":
        handler._send_html(render_db_status_report())
        return True
    if path == "/reports/diagnostics.html":
        _handle_diagnostics_report(handler, query)
        return True
    return False


def _handle_system_health_report(handler) -> None:
    data = get_system_health()
    handler._send_html(render_system_health_report(data))


def _handle_storage_health_report(handler, query: dict[str, list[str]]) -> None:
    data = get_storage_health(deep=(query.get("deep", ["0"])[0].lower() in {"1", "true", "yes"}))
    handler._send_html(render_storage_health_report(data))


def _handle_diagnostics_report(handler, query: dict[str, list[str]]) -> None:
    run_checks = (query.get("run_checks", ["0"])[0].lower() in {"1", "true", "yes"})
    data = get_diagnostics_overview(run_checks=run_checks)
    handler._send_html(render_diagnostics_report(data))
