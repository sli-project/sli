"""Workspace/UI domain: bootstrap, route parity, v4 workspace, overview,
dashboard snapshot, role views, and their report-page equivalents.

Shared ambient auth/authz machinery and response helpers stay on
``RequestHandler`` in ``server.api.http_server`` and are reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.access.auth import auth_required
from server.sli.access.domain_scope import resolve_domain_selection
from server.sli.agents.collection_health import get_agent_collection_health
from server.sli.reporting.dashboard_snapshot import build_dashboard_snapshot
from server.sli.reporting.home_summary import home_summary
from server.sli.reporting.reporting_v4 import workspace as get_v4_workspace
from server.sli.access.role_views import get_role_views_data, render_role_overview_report
from server.sli.reporting.ui_api_models import OverviewWorkspaceResponse, UiBootstrapResponse, V4WorkspaceResponse
from server.sli.reporting.ui_navigation import get_ui_navigation_data, render_ui_navigation_report
from server.sli.reporting.ui_route_parity import route_parity_manifest
from server.sli.reporting.ui_workspace import get_overview_workspace_data
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    validate_storage_route_authorization,
)
from server.sli.storage.storage_v2_transition_controller import is_controller_authorization

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/domains"),
    ("GET", "/api/v1/home/summary"),
    ("GET", "/api/dashboard/snapshot"),
    ("GET", "/api/role-views"),
    ("GET", "/api/ui/navigation"),
    ("GET", "/api/v1/overview"),
    ("GET", "/api/v1/ui/bootstrap"),
    ("GET", "/api/v1/ui/route-parity"),
    ("GET", "/api/v1/workspace"),
    ("GET", "/reports/role-overview.html"),
    ("GET", "/reports/ui-navigation.html"),
)


def _storage_route_authorization(handler):
    return validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/domains":
        try:
            if query:
                raise ValueError("domain_parameters_invalid")
            selection = resolve_domain_selection(handler._access_decision(), {})
        except PermissionError:
            handler._send_json({"error": "workspace_view_required"}, HTTPStatus.FORBIDDEN)
            return True
        except ValueError:
            handler._send_json({"error": "domain_parameters_invalid"}, HTTPStatus.BAD_REQUEST)
            return True
        handler._send_json({"items": list(selection.domains)})
        return True
    if path == "/api/v1/home/summary":
        try:
            payload = home_summary(handler._access_decision(), authorization=_storage_route_authorization(handler),
                                   version=(query.get("contract") or ["v1"])[0], query=query)
        except PermissionError as exc:
            error = "domain_scope_denied" if str(exc) == "domain_scope_denied" else "workspace_view_required"
            handler._send_json({"error": error}, HTTPStatus.FORBIDDEN)
            return True
        except ValueError:
            handler._send_json({"error": "home_parameters_invalid"}, HTTPStatus.BAD_REQUEST)
            return True
        handler._send_json(payload)
        return True
    if path == "/api/v1/ui/bootstrap":
        _handle_ui_bootstrap_api(handler)
        return True
    if path == "/api/v1/ui/route-parity":
        handler._send_json(route_parity_manifest())
        return True
    if path == "/api/v1/workspace":
        _handle_v4_workspace_api(handler)
        return True
    if path == "/api/v1/overview":
        _handle_v1_overview_api(handler, query)
        return True
    if path == "/api/dashboard/snapshot":
        force = query.get("force", ["0"])[0].lower() in {"1", "true", "yes"}
        authorization = _storage_route_authorization(handler)
        handler._send_json(
            build_dashboard_snapshot(force=force)
            if authorization is None
            else build_dashboard_snapshot(force=force, authorization=authorization)
        )
        return True
    if path == "/api/ui/navigation":
        handler._send_json(get_ui_navigation_data())
        return True
    if path == "/api/role-views":
        _handle_role_views_api(handler, query)
        return True
    if path == "/reports/role-overview.html":
        _handle_role_overview_report(handler, query)
        return True
    if path == "/reports/ui-navigation.html":
        handler._send_html(render_ui_navigation_report())
        return True
    return False


def _handle_ui_bootstrap_api(handler) -> None:
    principal = getattr(handler, "_principal", None)
    # Authentication is intentionally optional for local bootstrap.  In
    # that mode the mutation boundary grants the local browser operator
    # actions (but admin APIs still require an authenticated admin).  Give
    # React the same effective role instead of making it fail closed while
    # the server would accept the action.
    effective_role = str((principal or {}).get("role") or ("viewer" if auth_required() else "operator"))
    access = handler._access_decision()
    payload = UiBootstrapResponse(
        principal=handler._public_principal(principal) if principal else None,
        effective_role=effective_role,
        navigation=access["navigation"],
        capabilities=access["capabilities"],
        packages=access["packages"],
        allowed_report_count=access["allowed_report_count"],
    )
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v4_workspace_api(handler) -> None:
    try:
        payload = V4WorkspaceResponse(**get_v4_workspace(
            getattr(handler, "_principal", None), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_overview_api(handler, query: dict[str, list[str]] | None = None) -> None:
    """Bounded snapshot adapter; it never starts a collection or a job."""
    query = query or {}
    if query.get("view") == ["agents"]:
        handler._send_json({"api_version": "v1", "agent_collection": get_agent_collection_health()})
        return
    first = lambda name: (query.get(name) or [None])[0]
    values = {"time_from": first("time_from"), "time_to": first("time_to"), "server": first("server")}
    authorization = _storage_route_authorization(handler)
    if authorization is not None:
        values["authorization"] = authorization
    payload = OverviewWorkspaceResponse(**get_overview_workspace_data(**values))
    handler._send_json(payload.model_dump(mode="json"))


def _handle_role_views_api(handler, query: dict[str, list[str]]) -> None:
    # GET is a read contract. Findings refresh belongs to the durable
    # post-collection worker, never to a query-string side effect.
    authorization = _storage_route_authorization(handler)
    values = {"refresh_findings": False}
    if authorization is not None:
        values["authorization"] = authorization
    handler._send_json(get_role_views_data(**values))


def _handle_role_overview_report(handler, query: dict[str, list[str]]) -> None:
    raw_view = (query.get("view") or [""])[0] or None
    # Reuse the bounded/stale-while-revalidate dashboard snapshot.  Calling
    # get_role_views_data() directly performs exact full-history event/entity
    # summaries and timed out on the production PostgreSQL dataset.
    authorization = _storage_route_authorization(handler)
    snapshot = (
        build_dashboard_snapshot()
        if authorization is None
        else build_dashboard_snapshot(authorization=authorization)
    )
    role_data = snapshot.get("role_views") or {
        "generated_at_utc": snapshot.get("generated_at_utc"),
        "principle": "Ролевые представления прогреваются; повторите открытие после обновления snapshot.",
        "summary": {},
        "views": [],
    }
    handler._send_html(render_role_overview_report(role_data, selected=raw_view))
