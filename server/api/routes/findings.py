"""Findings domain: workspace list, report page, lifecycle status update.

Shared ambient auth/authz machinery (``_authorize_mutation``,
``_require_capability``, ``_read_json_body``, response helpers) stays on
``RequestHandler`` in ``server.api.http_server`` and is reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.access.scope import legacy_domain_ids
from server.sli.semantic.finding_risk_acceptance import (
    RiskAcceptanceError,
    change_risk_acceptance,
    get_risk_audit,
    risk_responsibles,
)

from server.sli.semantic.findings import (
    FindingLifecycleError,
    get_security_problems_data,
    update_finding_lifecycle,
)
from server.sli.reporting.v2.definition import QueryContext
from server.sli.reporting.v2.reports.security_problems import projected_rows, queue_access
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    validate_storage_route_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
    is_controller_authorization,
)

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/findings"),
    ("GET", "/api/findings/risk-responsibles"),
    ("GET", "/api/findings/{}/risk-audit"),
    ("GET", "/reports/findings.html"),
    ("POST", "/api/findings/{}/status"),
    ("POST", "/api/findings/{}/risk-acceptance"),
)


def is_resource_aware(path: str) -> bool:
    """The queue alias owns its report and field checks, like v2."""
    return path in {"/api/findings", "/reports/findings.html"}


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path.startswith("/api/findings/") and path.endswith("/risk-audit"):
        if not handler._require_capability("investigations.view"):
            return True
        try:
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                raise ValueError
            before = (query.get("before") or [None])[0]
            handler._send_json(get_risk_audit(int(parts[2]), before=int(before) if before is not None else None))
        except (ValueError, RiskAcceptanceError):
            handler._send_json({"error": "invalid_cursor_or_finding"}, HTTPStatus.BAD_REQUEST)
        return True
    if path == "/api/findings/risk-responsibles":
        if handler._require_capability("investigations.manage"):
            handler._send_json(risk_responsibles())
        return True
    if path == "/api/findings":
        _handle_findings_api(handler, query)
        return True
    if path == "/reports/findings.html":
        _handle_findings_report(handler, query)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path.startswith("/api/findings/") and path.endswith("/risk-acceptance"):
        if not handler._authorize_mutation() or not handler._require_capability("investigations.manage"):
            return True
        _handle_risk_acceptance(handler, path)
        return True
    if path.startswith("/api/findings/") and path.endswith("/status"):
        if not handler._authorize_mutation() or not handler._require_capability("investigations.manage"):
            return True
        _handle_finding_status_update(handler, path)
        return True
    return False


def _handle_risk_acceptance(handler, path: str) -> None:
    try:
        parts = path.strip("/").split("/")
        if len(parts) != 4:
            raise ValueError
        finding_id = int(parts[2])
    except ValueError:
        handler._send_json({"error": "invalid_finding_id"}, HTTPStatus.BAD_REQUEST)
        return
    principal = getattr(handler, "_principal", {})
    actor = str(principal.get("username") or principal.get("label") or principal.get("type") or "")
    try:
        result = change_risk_acceptance(finding_id, handler._read_json_body(), actor=actor)
    except RiskAcceptanceError as exc:
        status = (HTTPStatus.NOT_FOUND if exc.code == "not_found" else
                  HTTPStatus.CONFLICT if exc.code in {"risk_already_accepted", "risk_not_active"} else HTTPStatus.BAD_REQUEST)
        handler._send_json({"error": exc.code}, status)
        return
    handler._send_json(result)


def _findings_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None
    return {
        "source": first("source"),
        "status": first("status"),
        "severity": first("severity"),
        "q": first("q"),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "limit": int(first("limit") or 200),
        "refresh": False,
    }


def _storage_route_authorization(
    handler,
) -> CutoverAuthorization | None:
    """Read the sealed route capability from the server, never request input."""
    return validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )


def _with_storage_route_authorization(handler, values: dict) -> dict:
    authorization = _storage_route_authorization(handler)
    return {**values, "authorization": authorization}


def _handle_findings_api(handler, query: dict[str, list[str]]) -> None:
    if query.get("source") != ["semantic-production"]:
        handler._send_json({"error": "legacy_findings_retired"}, HTTPStatus.GONE)
        return
    try:
        projection = queue_access(handler._access_decision())
        projection.validate_request(query, {})
        scope = projection.restrict_request({"domain": int(query["domain"][0])} if query.get("domain") else {})
        domain_ids = legacy_domain_ids(scope)
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except ValueError:
        handler._send_json({"error": "report_request_invalid"}, HTTPStatus.BAD_REQUEST)
        return
    filters = _findings_filters(query)
    filters.pop("source")
    filters.pop("refresh")
    filters["risk"] = (query.get("risk") or [None])[0]
    filters["domain_ids"] = domain_ids
    if query.get("entity_id"):
        filters["entity_id"] = int(query["entity_id"][0])
    if "show_suppressed" in query:
        filters["show_suppressed"] = query["show_suppressed"] == ["true"]
    values = _with_storage_route_authorization(handler, filters)
    data = get_security_problems_data(**values)
    context = QueryContext(
        access=projection.access, params={}, runtime={"storage_route_authorization": values["authorization"]},
        field_access=projection.fields_allowed, scope=scope, domain_ids=domain_ids,
    )
    handler._send_json({**data, "items": projected_rows(data, context, projection)})


def _handle_findings_report(handler, query: dict[str, list[str]]) -> None:
    handler._send_json({"error": "legacy_findings_retired"}, HTTPStatus.GONE)


def _handle_finding_status_update(handler, path: str) -> None:
    parts = [item for item in path.split("/") if item]
    try:
        finding_id = int(parts[2])
    except (IndexError, ValueError):
        handler._send_json({"error": "invalid_finding_id"}, HTTPStatus.BAD_REQUEST)
        return
    payload = handler._read_json_body()
    principal = getattr(handler, "_principal", {})
    changed_by = str(principal.get("username") or principal.get("label") or "")
    try:
        result = update_finding_lifecycle(
            finding_id,
            new_status=str(payload.get("status") or ""),
            changed_by=changed_by,
            note=payload.get("note"),
            **({"assigned_to": payload["assigned_to"]} if "assigned_to" in payload else {}),
            status_reason=payload.get("status_reason"),
        )
    except FindingLifecycleError as exc:
        status = HTTPStatus.NOT_FOUND if exc.code == "not_found" else HTTPStatus.CONFLICT if exc.code == "invalid_transition" else HTTPStatus.BAD_REQUEST
        handler._send_json({"error": exc.code, "message": str(exc)}, status)
        return
    handler._send_json(result, HTTPStatus.OK)
