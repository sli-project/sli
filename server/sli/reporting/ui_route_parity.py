"""Canonical legacy-to-React route parity for the unified workspace.

The legacy HTML surface no longer exists as a reachable product mode: every
legacy path is unconditionally redirected to the typed React workspace so old
bookmarks do not resurrect a second product surface.
"""
from __future__ import annotations

from urllib.parse import urlencode


_DIRECT_ROUTES = {
    "/vpn-report": "/app/vpn-report",
    "/reports/search.html": "/app/events",
    "/reports/search-deep.html": "/app/events",
    "/reports/security-events-monitor.html": "/app/events",
    "/reports/account-timeline.html": "/app/investigations",
    "/reports/investigation.html": "/app/investigations",
    "/reports/findings.html": "/app/scenarios",
    "/reports/collector-health.html": "/app/operations",
    "/reports/autocollection.html": "/app/operations",
    "/reports/system-health.html": "/app/operations",
    "/reports/storage-health.html": "/app/operations",
    "/reports/db-status.html": "/app/operations",
    "/reports/diagnostics.html": "/app/operations",
    "/reports/role-overview.html": "/app/settings",
    "/reports/ui-navigation.html": "/app/settings",
}

_EXPLICIT_FALLBACK_ROUTES = frozenset({
    "/reports/domain-security-overview.html",
    "/reports/ai-redaction-preview.html",
    "/reports/ai-prompt-preview.html",
    "/reports/ai-reports.html",
    "/reports/ai-analysis.html",
})

_PRESERVED_QUERY_KEYS = frozenset({
    "q", "scope", "event_db_id", "entity_id", "event_id", "server", "channel",
    "time_from", "time_to", "risk", "status", "result_class", "risk_class",
})


def react_route_for_legacy(path: str, query: dict[str, list[str]]) -> str | None:
    """Return a parity redirect, or ``None`` for a path with no legacy mapping."""
    if path == "/admin":
        return "/app/admin"
    if path == "/reports/event-details.html":
        raw_id = (query.get("event_db_id") or query.get("id") or [""])[0]
        try:
            event_db_id = int(raw_id)
        except (TypeError, ValueError):
            event_db_id = 0
        return f"/app/events/{event_db_id}" if event_db_id > 0 else "/app/events"
    if path == "/reports/entity-details.html":
        raw_id = (query.get("entity_id") or [""])[0]
        try:
            entity_id = int(raw_id)
        except (TypeError, ValueError):
            entity_id = 0
        return f"/app/entities/{entity_id}" if entity_id > 0 else "/app/entities"
    target = _DIRECT_ROUTES.get(path)
    if target is None:
        return None
    preserved = {
        key: values[0]
        for key, values in query.items()
        if key in _PRESERVED_QUERY_KEYS and values and str(values[0]).strip()
    }
    return f"{target}?{urlencode(preserved)}" if preserved else target


def route_parity_manifest() -> dict:
    """Expose the bounded acceptance contract without reading runtime data."""
    items = [
        {"legacy_path": path, "react_path": target, "state": "redirected", "fallback": None}
        for path, target in sorted(_DIRECT_ROUTES.items())
    ]
    items.extend([
        {"legacy_path": "/admin", "react_path": "/app/admin", "state": "redirected", "fallback": None},
        {"legacy_path": "/reports/event-details.html", "react_path": "/app/events/{event_db_id}", "state": "redirected", "fallback": None},
        {"legacy_path": "/reports/entity-details.html", "react_path": "/app/entities/{entity_id}", "state": "redirected", "fallback": None},
    ])
    return {
        "status": "accepted",
        "ui_platform": "react",
        "legacy_default": "redirect",
        "legacy_fallback": "removed",
        "mapped_routes": items,
        "export_only_routes": sorted(_EXPLICIT_FALLBACK_ROUTES),
        "csv_exports_redirected": False,
    }
