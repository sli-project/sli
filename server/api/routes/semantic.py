"""Semantic subsystem domain: scenarios, actions, calibration, review.

This is only HTTP transport over the semantic subsystem, not an
architectural decision about it — moving these routes is not a decision
about semantic subsystem behavior (see spec.md's R08 boundary).

Shared ambient auth/authz machinery (``_authorize_mutation``,
``_require_capability``, ``_read_json_body``, response helpers) stays on
``RequestHandler`` in ``server.api.http_server`` and is reached through the
``handler`` instance passed to every function here. This module never
imports ``server.api.http_server`` — it raises the shared
``RequestInputError`` from ``server.api.errors`` instead (that type is
also used by http_server.py's own request-body parsing, so it lives in a
neutral module neither side needs to import the other for).
"""
from __future__ import annotations

from datetime import datetime, timezone
from http import HTTPStatus

from server.api.errors import RequestInputError
from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.core.time_contract import TimeRangeError
from server.sli.reporting.ui_api_models import (
    SemanticActionsResponse,
    SemanticCalibrationResponse,
    SemanticScenarioReviewResponse,
    SemanticScenariosResponse,
)
from server.sli.semantic.investigation_cases import (
    InvestigationCaseError,
    event_resource_group,
)
from server.sli.semantic.semantic_relation_reporting import get_semantic_relations
from server.sli.semantic.semantic_reviews import create_scenario_review
from server.sli.semantic.semantic_workspace import (
    get_semantic_actions_event_preflight,
    get_semantic_actions_workspace_data,
    get_semantic_calibration_workspace_data,
    get_semantic_scenarios_event_preflight,
    get_semantic_scenarios_workspace_data,
)
from server.sli.storage.runtime_storage import validate_storage_route_authorization
from server.sli.storage.evidence_ref import EvidenceRefError, EvidenceScope
from server.sli.sigma.attack_coverage import get_attack_coverage
from server.sli.sigma.rule_list import get_sigma_rules

_EXACT_EVENT_CAPABILITIES = ("semantic.review", "evidence.exact", "field.security")

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v1/semantic/sigma-rules"),
    ("GET", "/api/v1/semantic/attack-coverage"),
    ("GET", "/api/v1/semantic/actions"),
    ("GET", "/api/v1/semantic/calibration"),
    ("GET", "/api/v1/semantic/relations"),
    ("GET", "/api/v1/semantic/scenarios"),
    ("POST", "/api/v1/semantic/scenarios/{}/review"),
)


def is_resource_aware(path: str, query: dict | None = None) -> bool:
    if path in {"/api/v1/semantic/relations", "/api/v1/semantic/attack-coverage", "/api/v1/semantic/sigma-rules"}:
        return True
    if path not in {"/api/v1/semantic/scenarios", "/api/v1/semantic/actions"}:
        return False
    values = (query or {}).get("event_db_id") or []
    try:
        return len(values) == 1 and int(values[0]) > 0 and str(int(values[0])) == str(values[0]).strip()
    except (TypeError, ValueError):
        return False


def _semantic_module_access(handler) -> bool:
    access = handler._access_decision()
    if access.get("platform_owner"):
        return True
    available = set(access.get("capabilities") or []) | set(access.get("resource_bound_capabilities") or [])
    missing = [capability for capability in _EXACT_EVENT_CAPABILITIES if capability not in available]
    if missing:
        handler._send_json({"error": "insufficient_capability", "required_capability": missing[0]}, HTTPStatus.FORBIDDEN)
        return False
    return True


def _send_exact_unavailable(handler, *, reason: str, preflight: dict) -> None:
    handler._send_json({"api_version": "v1", "generated_at_utc": datetime.now(timezone.utc).isoformat(), "read_only": True, "execution": preflight["execution"], "state": "unavailable", "items": [], "has_more": False, "filters": {}, "limits": {"coverage_state": "unavailable", "reason": reason, "time_from_utc": preflight.get("time_from_utc"), "time_to_utc_exclusive": preflight.get("time_to_utc_exclusive")}})


def _exact_event_preflight(handler, query: dict, preflight_reader):
    if any(len(query[key]) != 1 for key in ("event_db_id", "time_from", "time_to", "timezone") if key in query):
        raise ValueError("invalid_semantic_context")
    raw = (query.get("event_db_id") or [""])[0]
    event_id = int(raw)
    if not _semantic_module_access(handler):
        return None
    authorization = validate_storage_route_authorization(getattr(handler, "storage_route_authorization", None))
    access = handler._access_decision()
    try:
        anchor_group = event_resource_group(event_id, authorization=authorization)
    except InvestigationCaseError:
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return None
    if any(not capability_decision_for_resource_groups(access, capability, resource_groups=[anchor_group])["allowed"] for capability in _EXACT_EVENT_CAPABILITIES):
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return None
    preflight = preflight_reader(event_db_id=event_id, time_from=(query.get("time_from") or [None])[0], time_to=(query.get("time_to") or [None])[0], timezone_name=(query.get("timezone") or ["UTC"])[0])
    if preflight.get("state") != "ready":
        _send_exact_unavailable(handler, reason=str(preflight.get("reason") or "evidence_unavailable"), preflight=preflight)
        return None
    try:
        groups = [anchor_group if event == event_id else event_resource_group(event, authorization=authorization) for event in preflight.get("resource_event_ids") or []]
    except InvestigationCaseError:
        _send_exact_unavailable(handler, reason="evidence_unavailable", preflight=preflight)
        return None
    access = handler._access_decision()
    if any(not capability_decision_for_resource_groups(access, capability, resource_groups=groups)["allowed"] for capability in _EXACT_EVENT_CAPABILITIES):
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return None
    return preflight


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/v1/semantic/sigma-rules":
        try:
            keys = {"installation_id", "plugin_id", "source_instance_id", "source_generation", "collection_scope_id"}
            if query and (set(query) != keys or any(len(values) != 1 for values in query.values())):
                raise ValueError
            scope = EvidenceScope(**{key: value[0] for key, value in query.items()}) if query else None
        except (ValueError, TypeError, EvidenceRefError):
            raise RequestInputError("sigma_rule_filter_invalid") from None
        handler._send_json(get_sigma_rules(handler._access_decision(), scope=scope))
        return True
    if path == "/api/v1/semantic/attack-coverage":
        _handle_v1_attack_coverage_api(handler, query)
        return True
    if path == "/api/v1/semantic/relations":
        _handle_v1_semantic_relations_api(handler, query)
        return True
    if path == "/api/v1/semantic/scenarios":
        _handle_v1_semantic_scenarios_api(handler, query)
        return True
    if path == "/api/v1/semantic/actions":
        _handle_v1_semantic_actions_api(handler, query)
        return True
    if path == "/api/v1/semantic/calibration":
        _handle_v1_semantic_calibration_api(handler, query)
        return True
    return False


def _handle_v1_attack_coverage_api(handler, query: dict[str, list[str]]) -> None:
    required = {"installation_id", "plugin_id", "source_instance_id", "source_generation",
                "since", "until", "catalog_sha256"}
    try:
        if (set(query) - required - {"collection_scope_id"} or required - set(query)
                or any(len(values) != 1 for values in query.values())):
            raise ValueError
        values = {key: value[0] for key, value in query.items()}
        scope = EvidenceScope(**{key: values[key] for key in (
            "installation_id", "plugin_id", "source_instance_id", "source_generation")},
            collection_scope_id=values.get("collection_scope_id", ""))
        payload = get_attack_coverage(handler._access_decision(), scope=scope,
                                      since=values["since"], until=values["until"],
                                      catalog_sha256=values["catalog_sha256"])
    except (ValueError, TypeError, EvidenceRefError):
        raise RequestInputError("sigma_attack_filter_invalid") from None
    handler._send_json(payload)


def _handle_v1_semantic_relations_api(handler, query: dict[str, list[str]]) -> None:
    allowed = {
        "domain_id", "time_from", "time_to", "timezone", "limit", "cursor",
        "category", "event_id", "outcome", "actor", "target", "group", "source", "q",
        "event_db_id", "entity_id", "rule_version", "relation_kind",
    }
    try:
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            raise ValueError("invalid_semantic_relation_filter")
        if any(name not in query or not str(query[name][0]).strip() for name in ("domain_id", "time_from", "time_to", "timezone")):
            raise ValueError("invalid_semantic_relation_filter")
        def value(name: str) -> str | None:
            raw = query.get(name, [None])[0]
            return str(raw).strip() if raw is not None else None
        raw_domain = value("domain_id")
        domain_id = int(raw_domain or "")
        if domain_id <= 0 or str(domain_id) != raw_domain:
            raise ValueError("invalid_semantic_relation_filter")
        for name in ("event_db_id", "entity_id", "rule_version"):
            raw = value(name)
            if raw is not None and (not raw.isdecimal() or int(raw) <= 0 or str(int(raw)) != raw):
                raise ValueError("invalid_semantic_relation_filter")
        payload = get_semantic_relations(
            handler._access_decision(), domain_id=domain_id,
            time_from=value("time_from"), time_to=value("time_to"),
            timezone_name=value("timezone") or "UTC", limit=value("limit") or "100",
            cursor=value("cursor"), event_db_id=value("event_db_id"), entity_id=value("entity_id"),
            rule_version=value("rule_version"), relation_kind=value("relation_kind"),
            category=value("category"), event_id=value("event_id"), outcome=value("outcome"),
            actor=value("actor"), target_account=value("target"), group=value("group"),
            source_host=value("source"), q=value("q"),
        )
    except (TypeError, ValueError, TimeRangeError) as exc:
        raise RequestInputError("invalid_semantic_relation_filter") from exc
    handler._send_json(payload)


def try_handle_post(handler, path: str) -> bool:
    if path.startswith("/api/v1/semantic/scenarios/") and path.endswith("/review"):
        if not handler._authorize_mutation(required_role="viewer"):
            return True
        if not handler._require_capability("semantic.review"):
            return True
        _handle_v1_semantic_scenario_review(handler, path)
        return True
    return False


def _handle_v1_semantic_scenarios_api(handler, query: dict[str, list[str]]) -> None:
    def first(name: str) -> str | None:
        value = query.get(name, [None])[0]
        return str(value).strip() if value is not None else None

    try:
        if "event_db_id" in query and not is_resource_aware("/api/v1/semantic/scenarios", query):
            raise ValueError("invalid_event_db_id")
        limit = int(first("limit") or "30")
        pagination = {"cursor": first("cursor"), "scenario_id": first("scenario_id"), "evidence_cursor": first("evidence_cursor")}
        if is_resource_aware("/api/v1/semantic/scenarios", query):
            preflight = _exact_event_preflight(handler, query, get_semantic_scenarios_event_preflight)
            if preflight is None:
                return
            data = get_semantic_scenarios_workspace_data(status=first("status"), result_class=first("result_class"), risk_class=first("risk_class"), limit=limit, event_item_ids=preflight["item_ids"], metadata_only=True, authorized_evidence_ids=preflight["resource_event_ids"], **pagination)
            data["limits"].update({"coverage_state": "bounded_exact_matches" if preflight["item_ids"] else "no_exact_proof", "time_from_utc": preflight.get("time_from_utc"), "time_to_utc_exclusive": preflight.get("time_to_utc_exclusive")})
            handler._send_json(SemanticScenariosResponse(**data).model_dump(mode="json"))
            return
        data = get_semantic_scenarios_workspace_data(
            status=first("status"),
            result_class=first("result_class"),
            risk_class=first("risk_class"),
            limit=limit,
            **pagination,
        )
        payload = SemanticScenariosResponse(**data)
    except (TypeError, ValueError, TimeRangeError) as exc:
        raise RequestInputError(str(exc) or "invalid_semantic_scenario_filter") from exc
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_semantic_actions_api(handler, query: dict[str, list[str]]) -> None:
    def first(name: str) -> str | None:
        value = query.get(name, [None])[0]
        return str(value).strip() if value is not None else None

    try:
        if "event_db_id" in query and not is_resource_aware("/api/v1/semantic/actions", query):
            raise ValueError("invalid_event_db_id")
        if is_resource_aware("/api/v1/semantic/actions", query):
            preflight = _exact_event_preflight(handler, query, get_semantic_actions_event_preflight)
            if preflight is None:
                return
            data = get_semantic_actions_workspace_data(status=first("status"), action_kind=first("action_kind"), limit=int(first("limit") or "30"), event_item_ids=preflight["item_ids"], metadata_only=True, authorized_evidence_ids=preflight["resource_event_ids"])
            data["limits"].update({"coverage_state": "bounded_exact_matches" if preflight["item_ids"] else "no_exact_proof", "time_from_utc": preflight.get("time_from_utc"), "time_to_utc_exclusive": preflight.get("time_to_utc_exclusive")})
            handler._send_json(SemanticActionsResponse(**data).model_dump(mode="json"))
            return
        data = get_semantic_actions_workspace_data(
            status=first("status"), action_kind=first("action_kind"),
            limit=int(first("limit") or "30"),
        )
        payload = SemanticActionsResponse(**data)
    except (TypeError, ValueError, TimeRangeError) as exc:
        raise RequestInputError(str(exc) or "invalid_semantic_action_filter") from exc
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_semantic_calibration_api(handler, query: dict[str, list[str]]) -> None:
    try:
        hours = int(query.get("window_hours", ["24"])[0])
        payload = SemanticCalibrationResponse(
            **get_semantic_calibration_workspace_data(window_hours=hours)
        )
    except (TypeError, ValueError) as exc:
        raise RequestInputError("invalid_semantic_calibration_window") from exc
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v1_semantic_scenario_review(handler, path: str) -> None:
    parts = [part for part in path.split("/") if part]
    scenario_id = parts[4] if len(parts) == 6 and parts[5] == "review" else ""
    payload = handler._read_json_body()
    principal = getattr(handler, "_principal", {})
    reviewed_by = str(
        principal.get("username") or principal.get("label")
        or principal.get("type") or "local-operator"
    )
    reviewer_role = str(principal.get("role") or "operator")
    try:
        result = create_scenario_review(
            scenario_id=scenario_id,
            verdict=str(payload.get("verdict") or ""),
            review_confidence=str(payload.get("review_confidence") or ""),
            rationale=str(payload.get("rationale") or ""),
            reviewed_by=reviewed_by,
            reviewer_role=reviewer_role,
            review_request_id=payload.get("review_request_id"),
        )
    except LookupError:
        handler._send_json({"error": "semantic_scenario_not_found"}, HTTPStatus.NOT_FOUND)
        return
    except ValueError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    replayed = bool(result.pop("replayed", False))
    response = SemanticScenarioReviewResponse(item=result, replayed=replayed)
    handler._send_json(response.model_dump(mode="json"), HTTPStatus.OK if replayed else HTTPStatus.CREATED)
