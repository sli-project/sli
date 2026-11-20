"""Entities domain: workspace list/detail, exact-evidence detail report.

Owns ``_entity_detail_filters`` — not to be confused with events.py's
``_event_detail_filters`` (different filter set, different backend).

Shared ambient auth/authz machinery and response helpers stay on
``RequestHandler`` in ``server.api.http_server`` and are reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server``.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from functools import partial
from http import HTTPStatus

from server.sli.plugins.registry import call_plugin
from server.sli.core.database import get_entity_summary
from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.access.entity_access_projection import project_ad_context
from server.sli.entities.entity_details import get_entity_detail_report_data, render_entity_detail_report
from server.sli.reports.security_event_reporting import get_security_events_report
from server.sli.semantic.semantic_relation_reporting import get_semantic_relations
from server.sli.core.time_contract import TimeRangeError, normalize_utc_range
from server.sli.reporting.ui_api_models import EntitiesWorkspaceResponse, EntityWorkspaceDetailResponse
from server.sli.reporting.ui_workspace import (
    EntityTypeFilterError,
    get_entities_workspace_data,
    get_entity_workspace_detail_data,
    get_entity_workspace_resource_preflight,
)

get_entity_vpn_sessions = partial(call_plugin, "sli.remote-access", "get_entity_vpn_sessions")


# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/entities/details"),
    ("GET", "/api/entities/summary"),
    ("GET", "/api/v1/entities"),
    ("GET", "/api/v1/entities/*"),
    ("GET", "/api/v1/entities/{}/vpn-sessions"),
    ("GET", "/reports/entity-details.html"),
)


def entity_security_interpretation(
    access: dict, *, entity_id: int, domain_id: int | None,
    time_from_utc: str | None, time_to_utc_exclusive: str | None,
    timezone_name: str, limit: int,
) -> dict:
    """Compose an entity slice exclusively through the existing report owners."""
    if domain_id is None or not time_from_utc or not time_to_utc_exclusive:
        return {
            "security_actions_state": "time_bounds_required",
            "security_actions": [],
            "semantic_relations_state": "time_bounds_required",
            "semantic_relations": [],
        }
    actions = get_security_events_report(
        access, source_domain_id=domain_id, time_from=time_from_utc,
        time_to=time_to_utc_exclusive, timezone_name=timezone_name,
        limit=limit, entity_id=entity_id,
    )
    relations = get_semantic_relations(
        access, domain_id=domain_id, time_from=time_from_utc,
        time_to=time_to_utc_exclusive, timezone_name=timezone_name,
        limit=limit, entity_id=entity_id,
    )
    def authorized_items(result: dict) -> tuple[str, list]:
        state = str(result.get("state") or "temporarily_unavailable")
        # Readers own projection and authorization. A composition route must not
        # turn a denied or partial response into an item-bearing detail view.
        return state, list(result.get("items") or []) if state == "available" else []
    actions_state, action_items = authorized_items(actions)
    relations_state, relation_items = authorized_items(relations)
    return {
        "security_actions_state": actions_state,
        "security_actions": action_items,
        "semantic_relations_state": relations_state,
        "semantic_relations": relation_items,
    }


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/entities/summary":
        handler._send_json(get_entity_summary(
            authorization=getattr(handler, "storage_route_authorization", None),
        ))
        return True
    if path == "/api/entities/details":
        _handle_entity_details_api(handler, query)
        return True
    if path == "/api/v1/entities":
        _handle_v1_entities_api(handler, query)
        return True
    if path.startswith("/api/v1/entities/") and path.endswith("/vpn-sessions"):
        _handle_v1_entity_vpn_sessions_api(handler, path, query)
        return True
    if path.startswith("/api/v1/entities/"):
        _handle_v1_entity_by_id_api(handler, path, query)
        return True
    if path == "/reports/entity-details.html":
        _handle_entity_details_report(handler, query)
        return True
    return False


def _entity_detail_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    raw_servers = first("server") or first("servers") or ""
    servers = [item.strip() for item in raw_servers.split(",") if item.strip()]
    return {
        "entity_id": first("entity_id"),
        "q": first("q"),
        "role": first("role"),
        "event_id": first("event_id"),
        "event_ids": query.get("event_id") or [],
        "channel": first("channel"),
        "servers": servers,
        "limit": int(first("limit") or 200),
        "offset": int(first("offset") or 0),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "timezone_name": first("timezone") or "UTC",
        "order": first("order"),
    }


def _handle_entity_details_api(handler, query: dict[str, list[str]]) -> None:
    try:
        data = get_entity_detail_report_data(
            **_entity_detail_filters(query),
            authorization=getattr(handler, "storage_route_authorization", None),
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(data)


def _handle_entity_details_report(handler, query: dict[str, list[str]]) -> None:
    data = get_entity_detail_report_data(
        **_entity_detail_filters(query),
        authorization=getattr(handler, "storage_route_authorization", None),
    )
    handler._send_html(render_entity_detail_report(data))


def _handle_v1_entities_api(handler, query: dict[str, list[str]]) -> None:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    def many(name: str) -> tuple[str, ...]:
        return tuple(
            value.strip()
            for raw in (query.get(name) or [])
            for value in raw.split(",")
            if value.strip()
        )

    try:
        limit = int(first("limit") or 50)
    except ValueError:
        limit = 50
    try:
        data = get_entities_workspace_data(
            q=first("q"),
            entity_types=many("entity_type"),
            exclude_entity_types=many("exclude_entity_type"),
            limit=limit,
        )
    except EntityTypeFilterError as exc:
        handler._send_json(
            {"error": "unknown_entity_type", "unknown_types": exc.unknown_types},
            HTTPStatus.BAD_REQUEST,
        )
        return
    payload = EntitiesWorkspaceResponse(**data)
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_entity_vpn_sessions_api(handler, path: str, query: dict[str, list[str]]) -> None:
    raw_id = path.removeprefix("/api/v1/entities/").removesuffix("/vpn-sessions").strip("/")
    try:
        entity_id = int(raw_id)
    except ValueError:
        handler._send_json({"error": "invalid_entity_id"}, HTTPStatus.BAD_REQUEST)
        return
    if entity_id <= 0:
        handler._send_json({"error": "invalid_entity_id"}, HTTPStatus.BAD_REQUEST)
        return
    allowed_keys = {"time_from", "time_to", "timezone", "limit"}
    if set(query) - allowed_keys or any(len(query.get(name) or []) != 1 for name in query):
        handler._send_json({"error": "invalid_entity_vpn_context"}, HTTPStatus.BAD_REQUEST)
        return
    first = lambda name, default=None: (query.get(name) or [default])[0]
    raw_time_from, raw_time_to = first("time_from"), first("time_to")
    if not raw_time_from or not raw_time_to:
        handler._send_json({"error": "entity_vpn_time_bounds_required"}, HTTPStatus.BAD_REQUEST)
        return
    timezone_name = str(first("timezone", "UTC") or "UTC")
    try:
        time_from_utc, time_to_utc_exclusive = normalize_utc_range(
            raw_time_from, raw_time_to, timezone_name=timezone_name,
        )
        limit = int(first("limit", "50") or 50)
    except (TypeError, ValueError, TimeRangeError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    preflight = get_entity_workspace_resource_preflight(entity_id=entity_id)
    if preflight is None:
        handler._send_json({"error": "entity_not_found", "entity_id": entity_id}, HTTPStatus.NOT_FOUND)
        return
    resources = []
    if preflight.get("server_id") is not None:
        resources.append({"kind": "server", "id": int(preflight["server_id"])})
    if preflight.get("domain_id") is not None:
        resources.append({"kind": "domain", "id": int(preflight["domain_id"])})
    access = handler._access_decision()
    if not resources or not capability_decision_for_resource_groups(
        access, "objects.view", resource_groups=[resources],
    )["allowed"]:
        handler._send_json({"error": "entity_not_found", "entity_id": entity_id}, HTTPStatus.NOT_FOUND)
        return
    try:
        payload = get_entity_vpn_sessions(
            access,
            entity_id=int(preflight["id"]),
            trusted_domain_id=int(preflight["domain_id"]),
            time_from_utc=str(time_from_utc),
            time_to_utc_exclusive=str(time_to_utc_exclusive),
            limit=limit,
        )
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload)


def _handle_v1_entity_by_id_api(handler, path: str, query: dict[str, list[str]]) -> None:
    """Read one exact entity; malformed path/cursor is a client error."""
    raw_id = path.removeprefix("/api/v1/entities/").strip("/")
    try:
        entity_id = int(raw_id)
    except ValueError:
        handler._send_json({"error": "invalid_entity_id"}, HTTPStatus.BAD_REQUEST)
        return
    if entity_id <= 0:
        handler._send_json({"error": "invalid_entity_id"}, HTTPStatus.BAD_REQUEST)
        return

    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    for name in ("time_from", "time_to", "timezone"):
        if len(query.get(name) or []) > 1:
            handler._send_json({"error": f"duplicate_{name}"}, HTTPStatus.BAD_REQUEST)
            return

    try:
        limit = int(first("limit") or 50)
    except ValueError:
        handler._send_json({"error": "invalid_entity_limit"}, HTTPStatus.BAD_REQUEST)
        return
    raw_before_time = first("before_time_utc")
    raw_before_id = first("before_event_db_id")
    if (raw_before_time is None) != (raw_before_id is None):
        handler._send_json({"error": "entity_cursor_requires_time_and_event_id"}, HTTPStatus.BAD_REQUEST)
        return
    before_event_db_id = None
    if raw_before_id is not None:
        try:
            before_event_db_id = int(raw_before_id)
        except ValueError:
            handler._send_json({"error": "invalid_before_event_db_id"}, HTTPStatus.BAD_REQUEST)
            return
        if before_event_db_id <= 0 or not raw_before_time:
            handler._send_json({"error": "invalid_entity_cursor"}, HTTPStatus.BAD_REQUEST)
            return
    raw_time_from = first("time_from")
    raw_time_to = first("time_to")
    timezone_name = first("timezone") or "UTC"
    if bool(raw_time_from) != bool(raw_time_to):
        handler._send_json(
            {"error": "entity_time_context_requires_both_bounds"}, HTTPStatus.BAD_REQUEST,
        )
        return
    try:
        time_from_utc, time_to_utc_exclusive = normalize_utc_range(
            raw_time_from, raw_time_to, timezone_name=timezone_name,
        )
        if time_from_utc and time_to_utc_exclusive:
            start = datetime.fromisoformat(time_from_utc.replace("Z", "+00:00"))
            end = datetime.fromisoformat(time_to_utc_exclusive.replace("Z", "+00:00"))
            if end - start > timedelta(days=31):
                handler._send_json(
                    {"error": "entity_time_context_period_too_wide"}, HTTPStatus.BAD_REQUEST,
                )
                return
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return

    preflight = get_entity_workspace_resource_preflight(entity_id=entity_id)
    if preflight is None:
        handler._send_json({"error": "entity_not_found", "entity_id": entity_id}, HTTPStatus.NOT_FOUND)
        return
    access = handler._access_decision()

    def resource_group(candidate: dict, *, include_channel: bool = False) -> list[dict]:
        resources: list[dict] = []
        if candidate.get("server_id") is not None:
            resources.append({"kind": "server", "id": int(candidate["server_id"])})
        if candidate.get("domain_id") is not None:
            resources.append({"kind": "domain", "id": int(candidate["domain_id"])})
        if include_channel and candidate.get("channel"):
            resources.append({"kind": "channel", "value": str(candidate["channel"])})
        return resources or [{"kind": "unscoped", "value": "global"}]

    def allows(capability: str, resources: list[dict]) -> bool:
        return bool(capability_decision_for_resource_groups(
            access, capability, resource_groups=[resources],
        ).get("allowed"))

    if not allows("objects.view", resource_group(preflight)):
        # Once the exact object is outside the caller's scope, do not reveal
        # whether the ID exists through a different status or response shape.
        handler._send_json({"error": "entity_not_found", "entity_id": entity_id}, HTTPStatus.NOT_FOUND)
        return

    def event_evidence_projection(candidate: dict) -> str | None:
        resources = resource_group(candidate, include_channel=True)
        if not allows("evidence.exact", resources):
            return None
        technical = allows("field.technical", resources)
        security = allows("field.security", resources)
        if technical and security:
            return "full"
        if technical:
            return "technical"
        if security:
            return "security_metadata"
        return "metadata"

    object_resources = resource_group(preflight)
    projected_capabilities = {
        capability for capability in (
            "field.identity_basic", "field.security", "field.privilege",
            "field.hr", "field.contact", "field.technical",
        ) if allows(capability, object_resources)
    }
    include_relations = (
        allows("field.privilege", object_resources)
        and allows("objects.privileges", object_resources)
    )

    data = get_entity_workspace_detail_data(
        entity_id=int(preflight["id"]),
        limit=limit,
        before_time_utc=raw_before_time,
        before_event_db_id=before_event_db_id,
        time_from_utc=time_from_utc,
        time_to_utc_exclusive=time_to_utc_exclusive,
        timezone_name=timezone_name,
        event_evidence_projection=event_evidence_projection,
        ad_context_projection=lambda context: project_ad_context(
            context,
            capabilities=projected_capabilities,
            include_relations=include_relations,
        ),
    )
    if data is None:
        handler._send_json({"error": "entity_not_found", "entity_id": entity_id}, HTTPStatus.NOT_FOUND)
        return
    data = dict(data)
    data.update(entity_security_interpretation(
        access,
        entity_id=int(preflight["id"]),
        domain_id=(int(preflight["domain_id"]) if preflight.get("domain_id") is not None else None),
        time_from_utc=time_from_utc,
        time_to_utc_exclusive=time_to_utc_exclusive,
        timezone_name=timezone_name,
        limit=limit,
    ))
    data["entity"] = dict(data["entity"])
    if "field.technical" not in projected_capabilities:
        data["entity"]["natural_key"] = ""
    if "field.security" not in projected_capabilities:
        data["entity"]["latest_state"] = None
        data["current_states"] = []
    payload = EntityWorkspaceDetailResponse(**data)
    handler._send_json(payload.model_dump(mode="json"))
