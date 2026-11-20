"""Access control v4 domain: RBAC read-model, assignments, access requests.

Shared ambient auth/authz machinery stays on ``RequestHandler`` in
``server.api.http_server`` and is reached through the ``handler`` instance
passed to every function here. This module never imports
``server.api.http_server``.

``/api/v1/reports/<key>/preference`` lives here (not in routes/reports.py)
because it calls ``update_user_report_preference`` from
``server.sli.access.access_control_v4``, not the ``reporting_v4`` backend.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.access.access_control_v4 import (
    create_package_assignment,
    create_report_assignment,
    effective_access,
    list_access_audit,
    list_report_grant_options,
    list_access_subjects,
    update_user_report_preference,
)
from server.sli.access.access_requests_v4 import (
    create_report_access_request,
    decide_report_access_request,
    list_report_access_requests,
)
from server.sli.reporting.ui_api_models import V4AccessResponse

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/access/audit"),
    ("GET", "/api/v1/access/effective"),
    ("GET", "/api/v1/access/grant-options"),
    ("GET", "/api/v1/access/report-requests"),
    ("GET", "/api/v1/access/subjects"),
    ("POST", "/api/v1/access/assignments"),
    ("POST", "/api/v1/access/package-assignments"),
    ("POST", "/api/v1/access/report-requests"),
    ("POST", "/api/v1/access/report-requests/{}/decision"),
    ("POST", "/api/v1/reports/{}/preference"),
)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/access/effective":
        _handle_effective_access(handler, query)
        return True
    if path == "/api/v1/access/subjects":
        _handle_access_subjects(handler, query)
        return True
    if path == "/api/v1/access/grant-options":
        _handle_access_grant_options(handler)
        return True
    if path == "/api/v1/access/audit":
        _handle_access_audit(handler, query)
        return True
    if path == "/api/v1/access/report-requests":
        _handle_report_access_requests(handler, query)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    """Body is read lazily inside each handler, matching the original code's
    order — this contract does not take a pre-parsed body (see routes/auth.py)."""
    if path == "/api/v1/access/assignments":
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("reports.assign"):
            return True
        _handle_access_assignment_create(handler)
        return True
    if path == "/api/v1/access/report-requests":
        if not handler._authorize_mutation(required_role="viewer") or not handler._require_capability("reports.catalog"):
            return True
        _handle_report_access_request_create(handler)
        return True
    if path.startswith("/api/v1/access/report-requests/") and path.endswith("/decision"):
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
            return True
        _handle_report_access_request_decision(handler, path)
        return True
    if path == "/api/v1/access/package-assignments":
        if not handler._authorize_mutation(required_role="admin") or not handler._require_capability("access.manage"):
            return True
        _handle_package_assignment_create(handler)
        return True
    if path.startswith("/api/v1/reports/") and path.endswith("/preference"):
        if not handler._authorize_mutation(required_role="viewer") or not handler._require_capability("reports.catalog"):
            return True
        from urllib.parse import unquote
        report_key = unquote(path.removeprefix("/api/v1/reports/").removesuffix("/preference").strip("/"))
        _handle_report_preference(handler, report_key)
        return True
    return False


def _handle_effective_access(handler, query: dict[str, list[str]]) -> None:
    preview_value = query.get("user_id", [None])[0]
    try:
        preview_user_id = int(preview_value) if preview_value not in (None, "") else None
    except ValueError:
        handler._send_json({"error": "invalid_user_id"}, HTTPStatus.BAD_REQUEST)
        return
    if preview_user_id is not None and not handler._require_capability("access.preview"):
        return
    try:
        decision = effective_access(getattr(handler, "_principal", None), preview_user_id=preview_user_id) if preview_user_id is not None else handler._access_decision()
        payload = V4AccessResponse(**decision)
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        return
    handler._send_json(payload.model_dump(mode="json"))


def _handle_access_subjects(handler, query: dict[str, list[str]]) -> None:
    if not handler._require_capability("access.manage"):
        return
    values = query.get("account_type", ["all"])
    if len(values) != 1 or values[0] not in ("all", "people", "service"):
        handler._send_json({"error": "invalid_account_type"}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(list_access_subjects(account_type=values[0]))


def _handle_access_grant_options(handler) -> None:
    if not handler._require_capability("reports.assign"):
        return
    handler._send_json(list_report_grant_options())


def _handle_access_audit(handler, query: dict[str, list[str]]) -> None:
    if not handler._require_capability("access.manage"):
        return
    try:
        handler._send_json(list_access_audit(limit=int(query.get("limit", ["100"])[0])))
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_report_access_requests(handler, query: dict[str, list[str]]) -> None:
    try:
        handler._send_json(list_report_access_requests(
            actor=getattr(handler, "_principal", None),
            include_all=(query.get("scope", ["mine"])[0] == "all"),
            limit=int(query.get("limit", ["100"])[0]),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_access_assignment_create(handler) -> None:
    try:
        item = create_report_assignment(handler._read_json_body(), actor=getattr(handler, "_principal", None), remote_address=handler.client_address[0])
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item}, HTTPStatus.CREATED)


def _handle_report_access_request_create(handler) -> None:
    try:
        item = create_report_access_request(
            handler._read_json_body(),
            actor=getattr(handler, "_principal", None),
            remote_address=handler.client_address[0],
        )
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except ValueError as exc:
        status = (
            HTTPStatus.CONFLICT
            if str(exc) == "active_request_already_exists"
            else HTTPStatus.BAD_REQUEST
        )
        handler._send_json({"error": str(exc)}, status)
        return
    handler._send_json({"item": item}, HTTPStatus.CREATED)


def _handle_report_access_request_decision(handler, path: str) -> None:
    raw_id = path.removeprefix("/api/v1/access/report-requests/").removesuffix("/decision").strip("/")
    try:
        request_id = int(raw_id)
        item = decide_report_access_request(
            request_id, handler._read_json_body(),
            actor=getattr(handler, "_principal", None),
            remote_address=handler.client_address[0],
        )
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item})


def _handle_package_assignment_create(handler) -> None:
    try:
        item = create_package_assignment(handler._read_json_body(), actor=getattr(handler, "_principal", None), remote_address=handler.client_address[0])
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item}, HTTPStatus.CREATED)


def _handle_report_preference(handler, report_key: str) -> None:
    try:
        item = update_user_report_preference(
            report_key, handler._read_json_body(),
            actor=getattr(handler, "_principal", None),
            remote_address=handler.client_address[0],
        )
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item})
