"""Security events monitor domain: dashboard, report page, CSV export.

The CSV handler writes its own headers directly, duplicating what the
reports v4 CSV handler in routes/reports.py (ticket 03) does. This is not
unified into a shared ``_send_csv`` helper — that consolidation is out of
scope for this refactor (see spec.md §1, tech debt is logged, not fixed).

Response helpers stay on ``RequestHandler`` in ``server.api.http_server``
and are reached through the ``handler`` instance passed to every function
here. This module never imports ``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.events.security_events_monitor import (
    get_security_events_monitor_data,
    render_security_events_monitor_csv,
    render_security_events_monitor_report,
)
from server.sli.storage.runtime_storage import StorageRouteAuthorizationError
from server.sli.storage.storage_v2_transition_controller import is_controller_authorization

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/security/events-monitor"),
    ("GET", "/reports/security-events-monitor.csv"),
    ("GET", "/reports/security-events-monitor.html"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/security/events-monitor":
        _handle_security_events_monitor_api(handler, query)
        return True
    if path == "/reports/security-events-monitor.html":
        _handle_security_events_monitor_report(handler, query)
        return True
    if path == "/reports/security-events-monitor.csv":
        _handle_security_events_monitor_csv(handler, query)
        return True
    return False


def _security_events_monitor_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None
    return {
        "group": first("group"),
        "event_id": first("event_id"),
        "account": first("account") or first("user"),
        "source": first("source") or first("ip") or first("host"),
        "target": first("target"),
        "server": first("server"),
        "risk": first("risk") or first("severity"),
        "only_privileged": (first("only_privileged") or first("privileged") or "0").lower() in {"1", "true", "yes", "on"},
        "only_service": (first("only_service") or first("service") or "0").lower() in {"1", "true", "yes", "on"},
        "period": first("period"),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "limit": int(first("limit") or 300),
    }


def _with_storage_route_authorization(handler, values: dict) -> dict:
    authorization = getattr(handler, "storage_route_authorization", None)
    if authorization is None:
        return values
    if not is_controller_authorization(authorization):
        raise StorageRouteAuthorizationError("storage_transition_authorization_invalid")
    return {**values, "authorization": authorization}


def _handle_security_events_monitor_api(handler, query: dict[str, list[str]]) -> None:
    data = get_security_events_monitor_data(**_with_storage_route_authorization(handler, _security_events_monitor_filters(query)))
    handler._send_json(data)


def _handle_security_events_monitor_report(handler, query: dict[str, list[str]]) -> None:
    data = get_security_events_monitor_data(**_with_storage_route_authorization(handler, _security_events_monitor_filters(query)))
    handler._send_html(render_security_events_monitor_report(data))


def _handle_security_events_monitor_csv(handler, query: dict[str, list[str]]) -> None:
    data = get_security_events_monitor_data(**_with_storage_route_authorization(handler, _security_events_monitor_filters(query)))
    body = render_security_events_monitor_csv(data).encode("utf-8-sig")
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/csv; charset=utf-8")
    handler.send_header("Content-Disposition", "attachment; filename=security-events-monitor.csv")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
