"""Objects (v4 object facade) domain.

The shared dispatcher in ``server.api.http_server`` skips its usual ambient
``_require_capability`` check for paths this module owns (see
``is_resource_aware``) because this module gates itself instead: both GET
handlers below call ``handler._require_capability("objects.view")`` as their
first statement, before any facade/SQL work. ``object_facade_v4.search_objects``/
``object_detail`` also re-check ``objects.view`` internally (cheap
defense-in-depth) and additionally enforce a *resource-scoped* check once a
specific object has been resolved; a denial at that second, scoped check
raises a distinct signal (``object_not_found``, same channel as a missing
object) rather than ``PermissionError``, so this module maps it to 404 —
deliberately indistinguishable from "no such object" — instead of 403.
Only a denial of the base module check (no ``objects.view`` at all) stays 403.

Shared ambient auth/authz machinery (``_require_capability``,
``_access_decision``, response helpers) stays on ``RequestHandler`` in
``server.api.http_server`` and is reached through the ``handler`` instance
passed to every function here. This module never imports
``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.access.object_facade_v4 import object_detail as get_v4_object_detail, search_objects as search_v4_objects
from server.sli.reporting.ui_api_models import V4ObjectDetailResponse, V4ObjectSearchResponse

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/objects"),
    ("GET", "/api/v1/objects/*"),
)


def is_resource_aware(path: str) -> bool:
    """True for paths this domain gates itself (see module docstring)."""
    return path == "/api/v1/objects" or path.startswith("/api/v1/objects/")


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/objects":
        _handle_v4_objects_api(handler, query)
        return True
    if path.startswith("/api/v1/objects/"):
        _handle_v4_object_detail_api(handler, path, query)
        return True
    return False


def _handle_v4_objects_api(handler, query: dict[str, list[str]]) -> None:
    if not handler._require_capability("objects.view"):
        return
    try:
        payload = V4ObjectSearchResponse(**search_v4_objects(
            getattr(handler, "_principal", None), query=query.get("q", [""])[0],
            object_type=query.get("type", query.get("object_type", [None]))[0],
            limit=int(query.get("limit", ["30"])[0]), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v4_object_detail_api(handler, path: str, query: dict[str, list[str]]) -> None:
    if not handler._require_capability("objects.view"):
        return
    parts = path.removeprefix("/api/v1/objects/").split("/", 1)
    if len(parts) != 2:
        handler._send_json({"error": "invalid_object_path"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        payload = V4ObjectDetailResponse(**get_v4_object_detail(
            getattr(handler, "_principal", None), object_type=parts[0], object_id=parts[1],
            event_limit=int(query.get("event_limit", ["30"])[0]), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except (TypeError, ValueError) as exc:
        status = HTTPStatus.NOT_FOUND if str(exc) == "object_not_found" else HTTPStatus.BAD_REQUEST
        handler._send_json({"error": str(exc)}, status)
        return
    handler._send_json(payload.model_dump(mode="json"))
