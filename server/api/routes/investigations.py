"""Investigations domain: legacy workspace report + v1 case management.

Two different backend modules under one word "investigation" live in this
one file on purpose (see spec.md §4): the legacy workspace
(``server.sli.semantic.investigation``, read-only summary/report) and v1 case
management (``server.sli.semantic.investigation_cases``, full CRUD with
resource-scoped authorization). They share no code but are kept together
because splitting them would separate closely-related domain knowledge for
no structural benefit.

This is the one domain with a nonstandard, resource-scoped auth layer:
``_require_investigation_module``/``_require_investigation_access`` check
report assignment AND per-resource-group capability, not just a role or a
flat capability. The ambient dispatcher in ``server.api.http_server`` skips
its usual GET capability gate for this domain's paths (see
``is_resource_aware``) because authorization here depends on the specific
case/event being read, which the ambient gate cannot see.

For mutations, the dispatcher still does its own coarse role check
(``_authorize_mutation("viewer")``) before calling ``try_handle_post`` —
that part is NOT bypassed. The resource-scoped checks
(``_require_investigation_module``/``_require_investigation_access``) then
run again, inside each handler, and — this is the order every mutation
handler must follow — strictly before any request-body reading:
``_require_investigation_module`` first (it needs no resource data), then
the minimum needed to resolve the resource (nothing, for handlers whose
resource is the case from the URL; just ``event_db_id`` from the body, for
``_handle_v1_investigation_create``/``_handle_v1_investigation_event``,
which cannot resolve their event resource group any other way), then
``_require_investigation_access``, and only then the rest of the body.
A resource-scoped denial reached after the module check has already passed
answers exactly like the resource not existing (404, ``not_found``, via
``_send_investigation_case_error``/``InvestigationCaseError``) — it must
never be distinguishable from a missing case/event by status code or
response shape. The module-level (not resource-scoped) denial is unchanged
and stays 403.

Shared ambient auth/authz machinery (``_authorize_mutation``,
``_access_decision``, ``_read_json_body``, response helpers) stays on
``RequestHandler`` in ``server.api.http_server`` and is reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server``.
"""
from __future__ import annotations

from functools import partial
from http import HTTPStatus
from typing import Any

from server.sli.plugins.registry import call_plugin, plugin_hook
from server.sli.access.access_control_v4 import (
    capability_decision_for_resource_groups,
    report_action_decision,
)
from server.sli.core.time_contract import TimeRangeError
from server.sli.reporting.ui_api_models import (
    InvestigationCaseResponse,
    InvestigationsWorkspaceResponse,
)
from server.sli.reporting.ui_workspace import (
    EntityEvidenceLookupError,
    get_entity_workspace_resource_preflight,
    get_investigations_workspace_data,
    parse_investigation_entity_id,
    parse_investigation_event_id,
)
from server.sli.reports.security_event_reporting import get_security_event_candidate_ids
from server.sli.semantic.investigation import (
    get_investigation_workspace_data,
    render_investigation_workspace_report,
)
from server.sli.semantic.investigation_cases import (
    InvestigationCaseError,
    case_resource_groups,
    case_resource_groups_batch,
    create_case,
    event_resource_group,
    get_case,
    get_case_evidence_page,
    list_cases,
    update_case_status,
)
from server.sli.semantic.investigation_cases import (
    add_event as add_investigation_event,
)
from server.sli.semantic.investigation_cases import (
    add_evidence_ref as add_investigation_evidence_ref,
)
from server.sli.semantic.investigation_cases import (
    add_note as add_investigation_note,
)
from server.sli.semantic.investigation_cases import (
    assign_owner as assign_investigation_owner,
)
from server.sli.semantic.investigation_cases import (
    remove_event as remove_investigation_event,
)
from server.sli.semantic.investigation_finding_links import (
    create_case_from_finding,
    finding_event_ids,
    link_finding_to_case,
)
from server.sli.storage.runtime_storage import (
    StorageRouteAuthorizationError,
    validate_storage_route_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)

get_vpn_session_evidence = partial(call_plugin, "sli.remote-access", "get_vpn_session_evidence")


def plugin_evidence_allowed(*args, **kwargs):
    hook = plugin_hook("sli.remote-access", "evidence_allowed")
    return bool(hook and hook(*args, **kwargs))


# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/investigation/workspace"),
    ("GET", "/api/v1/investigation-cases"),
    ("GET", "/api/v1/investigations"),
    ("GET", "/api/v1/investigations/*"),
    ("GET", "/reports/investigation.html"),
    ("POST", "/api/v1/investigations"),
    ("POST", "/api/v1/investigations/*"),
)


def is_resource_aware(path: str) -> bool:
    """True for paths this domain gates itself (see module docstring)."""
    return (
        path == "/api/v1/investigation-cases"
        or path == "/api/v1/investigations"
        or path.startswith("/api/v1/investigations/")
    )


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/investigations":
        _handle_v1_investigations_api(handler, query)
        return True
    if path == "/api/v1/investigation-cases":
        _handle_v1_investigation_cases_api(handler, query)
        return True
    if path.startswith("/api/v1/investigations/"):
        _handle_v1_investigation_case_api(handler, path, query)
        return True
    if path == "/api/investigation/workspace":
        _handle_investigation_api(handler, query)
        return True
    if path == "/reports/investigation.html":
        _handle_investigation_report(handler, query)
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path == "/api/v1/investigations" or path.startswith("/api/v1/investigations/"):
        # Product role ``viewer`` is the InfoSec analyst.  Investigation
        # work is its primary state-changing capability; operational jobs
        # remain operator-only and administration remains admin-only.
        if not handler._authorize_mutation(required_role="viewer"):
            return True
        if path == "/api/v1/investigations":
            _handle_v1_investigation_create(handler)
        elif path.endswith("/from-finding"):
            _handle_v1_investigation_from_finding(handler)
        elif path.endswith("/findings"):
            _handle_v1_investigation_finding(handler, path)
        elif path.endswith("/evidence-refs"):
            _handle_v1_investigation_evidence_ref(handler, path)
        elif path.endswith("/events/remove"):
            _handle_v1_investigation_event_remove(handler, path)
        elif path.endswith("/events"):
            _handle_v1_investigation_event(handler, path)
        elif path.endswith("/notes"):
            _handle_v1_investigation_note(handler, path)
        elif path.endswith("/status"):
            _handle_v1_investigation_status(handler, path)
        elif path.endswith("/owner"):
            _handle_v1_investigation_owner(handler, path)
        else:
            handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return True
    return False


def _investigation_report_key(handler, action: str) -> str | None:
    access = handler._access_decision()
    for key in ("investigations.workspace", "cases.workspace"):
        report = next((item for item in access.get("reports", []) if item.get("report_key") == key), None)
        if report and report.get("allowed") and action in set(report.get("allowed_actions") or []):
            return key
    return None


def _storage_route_authorization(
    handler,
) -> CutoverAuthorization | None:
    """Read only a valid sealed controller capability from the server."""
    return validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )


def _case_resources(handler, investigation_id):
    authorization = _storage_route_authorization(handler)
    if authorization is None:
        return case_resource_groups(investigation_id)
    return case_resource_groups(investigation_id, authorization=authorization)


def _case_resources_batch(handler, case_ids):
    authorization = _storage_route_authorization(handler)
    if authorization is None:
        return case_resource_groups_batch(case_ids)
    return case_resource_groups_batch(case_ids, authorization=authorization)


def _event_resources(handler, event_db_id):
    authorization = _storage_route_authorization(handler)
    if authorization is None:
        return event_resource_group(event_db_id)
    return event_resource_group(event_db_id, authorization=authorization)


def _require_investigation_module(handler, action: str, capability: str) -> bool:
    access = handler._access_decision()
    available_capabilities = set(access.get("capabilities") or []) | set(access.get("resource_bound_capabilities") or [])
    report_key = _investigation_report_key(handler, action)
    if report_key is None:
        handler._send_json({
            "error": "report_not_assigned",
            "required_report": "investigations.workspace",
            "required_action": action,
        }, HTTPStatus.FORBIDDEN)
        return False
    if capability not in available_capabilities:
        handler._send_json({
            "error": "insufficient_capability",
            "required_capability": capability,
        }, HTTPStatus.FORBIDDEN)
        return False
    return True


def _investigation_access_decision(
    handler,
    action: str,
    capability: str,
    resource_groups: list[list[dict[str, Any]]],
) -> dict[str, Any]:
    access = handler._access_decision()
    capability_result = capability_decision_for_resource_groups(
        access,
        capability,
        resource_groups=resource_groups,
    )
    if not capability_result["allowed"]:
        return capability_result
    report_key = _investigation_report_key(handler, action)
    if report_key is None:
        return {
            "allowed": False,
            "reason": "report_not_assigned",
            "report_key": "investigations.workspace",
            "action": action,
        }
    return report_action_decision(
        access,
        report_key,
        action,
        resource_groups=resource_groups,
    )


def _require_investigation_access(
    handler,
    action: str,
    capability: str,
    resource_groups: list[list[dict[str, Any]]],
) -> bool:
    if not _require_investigation_module(handler, action, capability):
        return False
    decision = _investigation_access_decision(handler, action, capability, resource_groups)
    if decision["allowed"]:
        return True
    # Module check already passed here, so the caller has access to the
    # domain in general — a 403 at this point would confirm the specific
    # case/event exists but is out of scope. Answer the same way as "not
    # found" instead (R10); callers already catch InvestigationCaseError.
    raise InvestigationCaseError("not_found", "Investigation resource was not found")


def _entity_evidence_allowed(handler, event_db_id: int) -> bool:
    """Authorize one preflight ID before the event-details owner reads payload."""
    try:
        resources = _event_resources(handler, event_db_id)
    except InvestigationCaseError:
        return False
    if not resources:
        return False
    groups = [resources]
    access = handler._access_decision()
    for capability in ("objects.view", "investigations.view", "evidence.exact", "field.security"):
        if not capability_decision_for_resource_groups(
            access, capability, resource_groups=groups
        ).get("allowed"):
            return False
    report_key = _investigation_report_key(handler, "view")
    if report_key is None:
        return False
    reports = []
    for report in access.get("reports", []):
        candidate = dict(report)
        if str(candidate.get("report_key") or "") == report_key:
            candidate["grants"] = [
                dict(grant) for grant in candidate.get("grants", [])
                if "security" in set(grant.get("field_categories") or [])
            ]
        reports.append(candidate)
    return report_action_decision(
        {**access, "reports": reports}, report_key, "view", resource_groups=groups
    ).get("allowed") is True


def _entity_security_event_candidates(
    handler, *, entity_id: int, time_from_utc: str,
    time_to_utc_exclusive: str, timezone_name: str, limit: int,
) -> dict[str, Any]:
    """Reuse the security-report owner's exact SID/link ID preflight."""
    preflight = get_entity_workspace_resource_preflight(entity_id=entity_id)
    if preflight is None or preflight.get("domain_id") is None:
        return {"state": "not_collected", "items": [], "has_more": False}
    resources = [
        {"kind": "domain", "id": int(preflight["domain_id"])},
        *(
            [{"kind": "server", "id": int(preflight["server_id"])}]
            if preflight.get("server_id") is not None else []
        ),
    ]
    access = handler._access_decision()
    if not capability_decision_for_resource_groups(
        access, "objects.view", resource_groups=[resources],
    ).get("allowed"):
        return {"state": "not_authorized", "items": [], "has_more": False}
    if not _investigation_access_decision(
        handler, "view", "investigations.view", [resources],
    ).get("allowed"):
        return {"state": "not_authorized", "items": [], "has_more": False}
    return get_security_event_candidate_ids(
        access,
        source_domain_id=int(preflight["domain_id"]),
        time_from=time_from_utc,
        time_to=time_to_utc_exclusive,
        timezone_name=timezone_name,
        limit=limit,
        entity_id=entity_id,
    )


def _investigation_case_id(path: str) -> str | None:
    parts = [part for part in path.split("/") if part]
    return parts[3] if len(parts) > 3 and parts[3] else None


def _case_actor(handler) -> str:
    principal = getattr(handler, "_principal", {})
    return str(principal.get("username") or principal.get("label") or principal.get("type") or "operator")


def _visible_case_result(handler, result: dict[str, Any]) -> dict[str, Any]:
    """Filter typed evidence through its owning report before serialization.

    Investigation scope is necessary to open a case, but it does not grant the
    separate right to read VPN Accounting evidence.  Do not expose a hidden
    reference or its count when that right is absent.
    """

    visible: list[dict[str, Any]] = []
    hidden = False
    decisions: dict[int, bool] = {}
    for raw_ref in result.get("evidence_refs") or []:
        item = dict(raw_ref)
        domain_id = int(item.get("source_domain_id") or 0)
        allowed = decisions.get(domain_id)
        if allowed is None:
            allowed = plugin_evidence_allowed(
                handler._access_decision(),
                source_domain_id=domain_id,
                action="view",
            )
            decisions[domain_id] = allowed
        if allowed:
            visible.append(item)
        else:
            hidden = True
    return {
        **result,
        "evidence_refs": visible,
        "evidence_refs_state": "partially_authorized" if hidden else "available",
    }


def _send_investigation_case_error(handler, exc: InvestigationCaseError) -> None:
    status_by_code = {
        "not_found": HTTPStatus.NOT_FOUND,
        "event_not_found": HTTPStatus.NOT_FOUND,
        "forbidden": HTTPStatus.FORBIDDEN,
        "conflict": HTTPStatus.CONFLICT,
        "finding_already_linked": HTTPStatus.CONFLICT,
        "investigation_case_closed": HTTPStatus.CONFLICT,
        "finding_not_found": HTTPStatus.NOT_FOUND,
        "unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
    }
    status = status_by_code.get(exc.code, HTTPStatus.BAD_REQUEST)
    handler._send_json({"error": exc.code, "message": str(exc), **exc.details}, status)


def _investigation_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None
    return {
        "q": first("q") or first("account") or first("user"),
        "limit": int(first("limit") or 300), "scope": first("scope") or first("mode"),
        "time_from": first("time_from"), "time_to": first("time_to"),
        "timezone_name": first("timezone") or "UTC",
    }


def _handle_investigation_api(handler, query: dict[str, list[str]]) -> None:
    try:
        values = _investigation_filters(query)
        authorization = _storage_route_authorization(handler)
        if authorization is not None:
            values["authorization"] = authorization
        data = get_investigation_workspace_data(**values)
    except StorageRouteAuthorizationError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        return
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(data)


def _handle_investigation_report(handler, query: dict[str, list[str]]) -> None:
    try:
        values = _investigation_filters(query)
        authorization = _storage_route_authorization(handler)
        if authorization is not None:
            values["authorization"] = authorization
        data = get_investigation_workspace_data(**values)
    except StorageRouteAuthorizationError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        return
    handler._send_html(render_investigation_workspace_report(data))


def _handle_v1_investigations_api(handler, query: dict[str, list[str]]) -> None:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    def related_event_allowed(event_id: int) -> bool:
        try:
            resources = _event_resources(handler, event_id)
        except InvestigationCaseError:
            return False
        if not resources:
            return False
        return _investigation_access_decision(
            handler, "view", "investigations.view", [resources]
        ).get("allowed") is True

    try:
        raw_event_db_id = parse_investigation_event_id(first("event_db_id"))
        raw_entity_id = parse_investigation_entity_id(first("entity_id"))
        if raw_event_db_id is None and raw_entity_id is not None:
            # Do not resolve the entity itself here: its only response-safe
            # identity is a later exact event proof, checked one-by-one.
            if not _require_investigation_module(handler, "view", "objects.view"):
                return
            if not _require_investigation_module(handler, "view", "investigations.view"):
                return
        else:
            resource_groups = [_event_resources(handler, raw_event_db_id)] if raw_event_db_id is not None else []
            if not _require_investigation_access(handler, "view", "investigations.view", resource_groups):
                return
        workspace_kwargs: dict[str, Any] = {
            "q": first("q"),
            "cursor": first("cursor"),
            "scope": first("scope"),
            "time_from": first("time_from"),
            "time_to": first("time_to"),
            "timezone_name": first("timezone") or "UTC",
            "event_db_id": first("event_db_id"),
            "entity_id": first("entity_id"),
            "related_event_allowed": related_event_allowed,
            "entity_evidence_allowed": lambda event_id: _entity_evidence_allowed(handler, event_id),
            "entity_security_event_candidates": (
                lambda **kwargs: _entity_security_event_candidates(handler, **kwargs)
            ),
        }
        authorization = _storage_route_authorization(handler)
        if authorization is not None:
            workspace_kwargs["authorization"] = authorization
        data = get_investigations_workspace_data(**workspace_kwargs)
    except StorageRouteAuthorizationError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.CONFLICT)
        return
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        error = str(exc)
        handler._send_json({"error": error if error in {"invalid_event_db_id", "invalid_entity_id", "invalid_cursor"} else "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
        return
    except EntityEvidenceLookupError as exc:
        if exc.code == "unavailable":
            handler._send_json({"error": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)
        return
    payload = InvestigationsWorkspaceResponse(**data)
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_investigation_case_api(handler, path: str, query: dict | None = None) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "view", "investigations.view"):
            return
        if query and (query.get("evidence_page") or [""])[0] == "1":
            first = lambda key: (query.get(key) or [None])[0]
            result = get_case_evidence_page(
                investigation_id,
                case_allowed=lambda groups: _investigation_access_decision(
                    handler, "view", "investigations.view", groups,
                )["allowed"],
                reference_allowed=lambda domain: plugin_evidence_allowed(
                    handler._access_decision(), source_domain_id=domain, action="view",
                ),
                event_after=first("event_after"), reference_after=first("reference_after"),
                anchor_event_id=first("anchor_event_id"),
                authorization=_storage_route_authorization(handler),
            )
            handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"))
            return
        resources = _case_resources(handler, investigation_id)
        if not _require_investigation_access(handler, "view", "investigations.view", resources):
            return
        result = _visible_case_result(handler, get_case(investigation_id))
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"))
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_cases_api(handler, query: dict[str, list[str]]) -> None:
    if not _require_investigation_module(handler, "view", "investigations.view"):
        return
    try:
        raw_limit = (query.get("limit") or ["50"])[0]
        limit = int(raw_limit)
    except ValueError:
        limit = 50
    items = list_cases(limit=limit)
    resources_by_case = _case_resources_batch(handler, [int(item["id"]) for item in items])
    visible = [
        {**item, "case_number": f"INV-{int(item['id']):07d}"} for item in items
        if _investigation_access_decision(
            handler, "view", "investigations.view", resources_by_case.get(int(item["id"]), [])
        )["allowed"]
    ]
    handler._send_json({"items": visible, "limit": max(1, min(limit, 100)), "scope_filtered": len(visible) != len(items)})


def _handle_v1_investigation_create(handler) -> None:
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        payload = handler._read_json_body()
        raw_event_db_id = payload.get("event_db_id")
        event_db_id = int(raw_event_db_id) if raw_event_db_id is not None else None
        resources = [_event_resources(handler, event_db_id)] if event_db_id is not None else []
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        result = create_case(
            title=str(payload.get("title") or ""),
            owner=payload.get("owner"),
            actor=_case_actor(handler),
            event_db_id=event_db_id,
            authorization=_storage_route_authorization(handler),
        )
        result = _visible_case_result(handler, result)
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"), HTTPStatus.CREATED)
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _finding_id_from_body(handler) -> int:
    payload = handler._read_json_body()
    raw = payload.get("finding_id")
    if isinstance(raw, bool) or raw is None:
        raise TypeError("finding_id")
    return int(raw)


def _finding_event_resources(handler, finding_id: int) -> list[list[dict[str, Any]]]:
    """Scope of the events a finding copies into a case: all must be in scope."""
    return [_event_resources(handler, event_id) for event_id in finding_event_ids(finding_id)]


def _handle_v1_investigation_from_finding(handler) -> None:
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        finding_id = _finding_id_from_body(handler)
        resources = _finding_event_resources(handler, finding_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        result = create_case_from_finding(finding_id=finding_id, actor=_case_actor(handler))
        result = _visible_case_result(handler, result)
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"), HTTPStatus.CREATED)
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_finding_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_finding(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        finding_id = _finding_id_from_body(handler)
        resources = _case_resources(handler, investigation_id) + _finding_event_resources(handler, finding_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        result = link_finding_to_case(
            investigation_id=investigation_id, finding_id=finding_id, actor=_case_actor(handler),
        )
        result = _visible_case_result(handler, result)
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"), HTTPStatus.CREATED)
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_finding_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_event(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        payload = handler._read_json_body()
        event_db_id = int(payload.get("event_db_id"))
        resources = _case_resources(handler, investigation_id) + [_event_resources(handler, event_db_id)]
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        result = add_investigation_event(
            investigation_id=investigation_id, event_db_id=event_db_id,
            relation_status=str(payload.get("relation_status") or "confirmed"), actor=_case_actor(handler),
            authorization=_storage_route_authorization(handler),
        )
        handler._send_json({"status": "ok", "event": result}, HTTPStatus.CREATED)
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_evidence_ref(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        payload = handler._read_json_body()
        evidence_kind = str(payload.get("evidence_kind") or "").strip()
        source_domain_id = int(payload.get("source_domain_id"))
        reference_id = str(payload.get("reference_id") or "").strip()
        resources = _case_resources(handler, investigation_id) + [
            [{"kind": "domain", "id": source_domain_id}]
        ]
        if not _require_investigation_access(
            handler, "start_case", "investigations.manage", resources
        ):
            return
        evidence = get_vpn_session_evidence(
            handler._access_decision(),
            source_domain_id=source_domain_id,
            session_row_id=reference_id,
        )
        if evidence.get("state") != "available":
            raise InvestigationCaseError("not_found", "Investigation resource was not found")
        result = add_investigation_evidence_ref(
            investigation_id=investigation_id,
            evidence_kind=evidence_kind,
            source_domain_id=source_domain_id,
            reference_id=reference_id,
            relation_status=str(payload.get("relation_status") or "confirmed"),
            actor=_case_actor(handler),
        )
        handler._send_json({"status": "ok", "evidence_ref": result}, HTTPStatus.CREATED)
    except TypeError:
        handler._send_json({"error": "invalid_evidence_ref"}, HTTPStatus.BAD_REQUEST)
    except ValueError as exc:
        code = str(exc)
        if code == "vpn_session_evidence_session_not_found":
            handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        elif code == "vpn_session_evidence_observation_bound_exceeded":
            handler._send_json({"error": "unavailable"}, HTTPStatus.SERVICE_UNAVAILABLE)
        else:
            handler._send_json({"error": "invalid_evidence_ref"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_event_remove(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        resources = _case_resources(handler, investigation_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        payload = handler._read_json_body()
        result = remove_investigation_event(
            investigation_id=investigation_id,
            event_db_id=int(payload.get("event_db_id")),
            actor=_case_actor(handler),
        )
        handler._send_json({"status": "ok", "event": result})
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_note(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        resources = _case_resources(handler, investigation_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        payload = handler._read_json_body()
        result = add_investigation_note(investigation_id=investigation_id, body=str(payload.get("body") or ""), actor=_case_actor(handler))
        handler._send_json({"status": "ok", "note": result}, HTTPStatus.CREATED)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_status(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        resources = _case_resources(handler, investigation_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        payload = handler._read_json_body()
        result = update_case_status(investigation_id=investigation_id, status=str(payload.get("status") or ""), actor=_case_actor(handler))
        result = _visible_case_result(handler, result)
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"))
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)


def _handle_v1_investigation_owner(handler, path: str) -> None:
    investigation_id = _investigation_case_id(path)
    if investigation_id is None:
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
        return
    try:
        if not _require_investigation_module(handler, "start_case", "investigations.manage"):
            return
        resources = _case_resources(handler, investigation_id)
        if not _require_investigation_access(handler, "start_case", "investigations.manage", resources):
            return
        payload = handler._read_json_body()
        result = assign_investigation_owner(
            investigation_id=investigation_id, owner=payload.get("owner"), actor=_case_actor(handler)
        )
        result = _visible_case_result(handler, result)
        handler._send_json(InvestigationCaseResponse(**result).model_dump(mode="json"))
    except (TypeError, ValueError):
        handler._send_json({"error": "invalid_investigation_id"}, HTTPStatus.BAD_REQUEST)
    except InvestigationCaseError as exc:
        _send_investigation_case_error(handler, exc)
