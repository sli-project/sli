"""Operations domain: plugins, sources, source packs/adapters, DC onboarding.

Source-onboarding preflight is the one route in the file with a double
sequential gate: the ambient dispatcher does a coarse
``_authorize_mutation("operator")`` + ``_require_capability("operations.view")``
check in ``try_handle_post`` below, and then the handler itself does a
second, stricter ``_require_access("admin")`` check before building the
plan. Both gates are preserved, in their original positions — this is not
redundant, it is two different questions ("can this actor mutate at all"
vs. "is this actor specifically an admin").

Shared ambient auth/authz machinery (``_authorize_mutation``,
``_require_capability``, ``_require_access``, ``_access_decision``,
``_read_json_body``, response helpers) stays on ``RequestHandler`` in
``server.api.http_server`` and is reached through the ``handler`` instance
passed to every function here. This module never imports
``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus
from urllib.parse import unquote

from psycopg import Error

from server.sli.reporting.ui_api_models import (
    SourceAdaptersResponse,
    SourcePacksResponse,
)
from server.sli.reporting.ui_operations import (
    get_operations_overview,
    get_platform_readiness,
    get_source_detail,
)
from server.sli.reports.administrative_activity import AdministrativeActivityError
from server.sli.reports.administrative_activity_reader import (
    AdministrativeActivityReaderUnavailable,
    list_administrative_activity,
)
from server.sli.plugins.registry import require_plugin
from server.sli.sources.plugin_management import (
    PluginManagementError,
    build_plugin_management_catalog,
    get_plugin_management,
)
from server.sli.sources.plugin_state import (
    PluginStateConflict,
    can_manage_plugins,
    list_plugin_states,
    set_plugin_enabled,
)
from server.source_packs.adapters import list_source_adapters
from server.source_packs.registry import list_source_packs

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/plugins"),
    ("POST", "/api/v1/plugins/*"),
    ("GET", "/api/v1/operations/administrative-activity"),
    ("GET", "/api/v1/operations/overview"),
    ("GET", "/api/v1/operations/plugins"),
    ("GET", "/api/v1/operations/plugins/*"),
    ("GET", "/api/v1/operations/sources/*"),
    ("GET", "/api/v1/source-adapters"),
    ("GET", "/api/v1/source-packs"),
    ("POST", "/api/v1/source-onboarding/preflight"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/plugins":
        if not handler._require_capability("operations.view"):
            return True
        try:
            payload = {
                "items": list_plugin_states(),
                "can_manage": can_manage_plugins(getattr(handler, "_principal", None), handler._access_decision()),
                "mutation_api_enabled": True,
            }
        except (Error, RuntimeError):
            handler._send_json({"error": "plugin_state_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
            return True
        handler._send_json(payload)
        return True
    if path == "/api/v1/operations/overview":
        handler._send_json(get_platform_readiness() if query.get("view") == ["readiness"] else get_operations_overview())
        return True
    if path == "/api/v1/operations/plugins":
        handler._send_json(build_plugin_management_catalog())
        return True
    if path == "/api/v1/operations/administrative-activity":
        _handle_administrative_activity_api(handler, query)
        return True
    if path.startswith("/api/v1/operations/plugins/"):
        _handle_v1_operation_plugin_api(handler, path)
        return True
    if path.startswith("/api/v1/operations/sources/"):
        _handle_v1_operation_source_api(handler, path)
        return True
    if path == "/api/v1/source-packs":
        _handle_source_packs_api(handler)
        return True
    if path == "/api/v1/source-adapters":
        _handle_source_adapters_api(handler)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path.startswith("/api/v1/plugins/"):
        if not handler._authorize_mutation(required_role="viewer"):
            return True
        if not can_manage_plugins(getattr(handler, "_principal", None), handler._access_decision()):
            handler._send_json({"error": "plugin_management_owner_or_admin_required"}, HTTPStatus.FORBIDDEN)
            return True
        body = handler._read_json_body()
        try:
            item = set_plugin_enabled(
                unquote(path.removeprefix("/api/v1/plugins/")), body,
                principal=handler._principal, access=handler._access_decision(),
            )
        except PermissionError:
            handler._send_json({"error": "plugin_management_owner_or_admin_required"}, HTTPStatus.FORBIDDEN)
            return True
        except LookupError:
            handler._send_json({"error": "plugin_not_found"}, HTTPStatus.NOT_FOUND)
            return True
        except PluginStateConflict as exc:
            handler._send_json({"error": exc.reason}, HTTPStatus.CONFLICT)
            return True
        except ValueError:
            handler._send_json({"error": "plugin_state_request_invalid"}, HTTPStatus.BAD_REQUEST)
            return True
        except (Error, RuntimeError):
            handler._send_json({"error": "plugin_state_unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
            return True
        handler._send_json({"item": item})
        return True
    if path == "/api/v1/source-onboarding/preflight":
        if not handler._authorize_mutation(required_role="operator") or not handler._require_capability("operations.view"):
            return True
        _handle_source_onboarding_preflight(handler)
        return True
    return False


def _handle_source_packs_api(handler) -> None:
    payload = SourcePacksResponse(items=list_source_packs())
    handler._send_json(payload.model_dump(mode="json"))


def _handle_source_adapters_api(handler) -> None:
    payload = SourceAdaptersResponse(items=list_source_adapters())
    handler._send_json(payload.model_dump(mode="json"))


def get_configured_domain_controller_targets():
    return require_plugin("sli.ad", "get_configured_domain_controller_targets")


def plan_dc_onboarding(*args, **kwargs):
    return require_plugin("sli.ad", "plan_dc_onboarding", *args, **kwargs)


def _handle_source_onboarding_preflight(handler) -> None:
    """Build an admin-only plan; never save or contact a proposed source."""
    if not handler._require_access("admin"):
        return
    candidate = handler._read_json_body()
    existing = [item["hostname"] for item in get_configured_domain_controller_targets()]
    plan = plan_dc_onboarding(candidate, existing_hostnames=existing)
    handler._send_json(plan.public_dict())


def _handle_v1_operation_source_api(handler, path: str) -> None:
    hostname = unquote(path.removeprefix("/api/v1/operations/sources/"))
    try:
        payload = get_source_detail(hostname)
    except ValueError as exc:
        error = str(exc)
        status = (
            HTTPStatus.NOT_FOUND
            if error == "source_not_found"
            else HTTPStatus.BAD_REQUEST
        )
        handler._send_json({"error": error}, status=status)
        return
    handler._send_json(payload)


def _handle_v1_operation_plugin_api(handler, path: str) -> None:
    plugin_id = unquote(path.removeprefix("/api/v1/operations/plugins/"))
    try:
        payload = get_plugin_management(plugin_id)
    except PluginManagementError as exc:
        error = str(exc)
        status = (
            HTTPStatus.NOT_FOUND
            if error == "plugin_not_found"
            else HTTPStatus.BAD_REQUEST
        )
        handler._send_json({"error": error}, status=status)
        return
    handler._send_json(payload)


def _handle_administrative_activity_api(handler, query: dict[str, list[str]]) -> None:
    allowed = {"before_activity_id", "category", "limit"}
    if set(query) - allowed or any(len(values) != 1 for values in query.values()):
        handler._send_json(
            {"error": "administrative_activity_query_invalid"},
            status=HTTPStatus.BAD_REQUEST,
        )
        return
    try:
        before = (
            int(query["before_activity_id"][0])
            if "before_activity_id" in query else None
        )
        limit = int(query.get("limit", ["50"])[0])
        category = query.get("category", [None])[0]
        payload = list_administrative_activity(
            handler._access_decision(),
            before_activity_id=before,
            category=category,
            limit=limit,
        )
    except (ValueError, AdministrativeActivityError):
        handler._send_json(
            {"error": "administrative_activity_query_invalid"},
            status=HTTPStatus.BAD_REQUEST,
        )
        return
    except PermissionError:
        handler._send_json(
            {"error": "administrative_activity_access_denied"},
            status=HTTPStatus.FORBIDDEN,
        )
        return
    except AdministrativeActivityReaderUnavailable:
        handler._send_json(
            {"error": "administrative_activity_reader_runtime_disabled"},
            status=HTTPStatus.SERVICE_UNAVAILABLE,
        )
        return
    handler._send_json(payload)
