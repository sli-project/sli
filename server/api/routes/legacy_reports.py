"""Legacy generated-report catch-all.

**Must be dispatched last** among every ``routes_X.try_handle_get`` call in
``http_server.py``'s ``_do_GET`` — its ``startswith("/reports/")`` fallback
would otherwise shadow every other domain's own, more specific
``/reports/*.html`` routes. This is the one order-sensitive point between
domains in the whole file (see spec.md §1, investigation-routes.md).

``/api/reports`` (the legacy JSON catalog) is NOT here — it was already
moved to ``routes/reports.py`` in ticket 03 (it shares a module,
``server.sli.reporting.reports``, with ``resolve_report`` below, but is a different
route serving a different purpose).

Carries ``_handle_domain_security_overview_report`` unchanged: it is dead
code (``/reports/domain-security-overview.html`` is actually served by a
hardcoded inline 403 in ``try_handle_get`` below, so this method is never
reached). This is preexisting behavior, not introduced or fixed by this
refactor — see investigation-routes.md, "Прочие находки" (R21 tech debt).

Response helpers stay on ``RequestHandler`` in ``server.api.http_server``
and are reached through the ``handler`` instance passed to every function
here. This module never imports ``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.reporting.reports import resolve_report

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/reports/*"),
    ("GET", "/reports/domain-security-overview.html"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/reports/domain-security-overview.html":
        handler._send_json({"error": "report_artifact_unclassified"}, HTTPStatus.FORBIDDEN)
        return True
    if path.startswith("/reports/"):
        _handle_report(handler, path)
        return True
    return False


def _handle_report(handler, path: str) -> None:
    # Legacy generated artifacts have no stable report/resource/scope map.
    # Catalog visibility alone must never authorize their bytes.
    handler._send_json({"error": "report_artifact_unclassified"}, HTTPStatus.FORBIDDEN)


def _handle_domain_security_overview_report(handler) -> None:
    """Serve a ready overview artifact without turning GET into a job."""
    report = resolve_report("domain-security-overview.html")
    if report is None:
        handler._send_html(
            "<html><body><h1>Обзор безопасности домена</h1>"
            "<p>Готовый обзор пока не сформирован. Откройте текущие события или попросите ИТ/администратора запустить обновление обзора.</p>"
            "</body></html>",
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )
        return
    handler._send_file(report, "text/html; charset=utf-8")
