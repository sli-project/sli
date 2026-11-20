"""Events domain: search, deep search, timeline, exact-evidence lookup.

Owns ``_event_search_filters``/``_event_detail_filters`` — the query-string
normalization shared by every handler in this module. ``entities.py`` has
its own, separate ``_entity_detail_filters`` (different filter set); the two
are not related despite the similar name.

Shared ambient auth/authz machinery (``_require_capability``,
``_access_decision``, response helpers) stays on ``RequestHandler`` in
``server.api.http_server`` and is reached through the ``handler`` instance
passed to every function here. This module never imports
``server.api.http_server``.
"""
from __future__ import annotations

from http import HTTPStatus

from server.sli.core.database import QueryTimeoutError, get_event_summary
from server.sli.core.time_contract import TimeRangeError
from server.sli.events.event_details import (
    get_event_detail_report_data,
    get_event_details_by_ids,
    render_event_detail_report,
)
from server.sli.events.event_search import (
    event_summary_projection,
    get_account_timeline_data,
    get_event_category_counts,
    get_event_deep_search_data,
    get_event_search_data,
    render_account_timeline_report,
    render_event_search_report,
)
from server.sli.reporting.ui_api_models import EventEntitiesResponse, EventListResponse
from server.sli.reporting.ui_workspace import (
    EVENT_ENTITY_LIMIT,
    get_event_entities_data,
)
from server.sli.storage.runtime_storage import (
    validate_storage_route_authorization,
)
from server.sli.storage.storage_v2_transition_controller import (
    CutoverAuthorization,
)

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("POST", "/api/v1/event-search/query"),
    ("POST", "/api/v1/event-search/page"),
    ("POST", "/api/v1/event-search/members"),
    ("GET", "/api/events/details"),
    ("GET", "/api/events/search"),
    ("GET", "/api/events/search/deep"),
    ("GET", "/api/events/summary"),
    ("GET", "/api/events/timeline"),
    ("GET", "/api/v1/events"),
    ("GET", "/api/v1/events/*"),
    ("GET", "/api/v1/events/batch"),
    ("GET", "/api/v1/events/{}/entities"),
    ("GET", "/api/v1/events/{}/relations"),
    ("GET", "/reports/account-timeline.html"),
    ("GET", "/reports/event-details.html"),
    ("GET", "/reports/search-deep.html"),
    ("GET", "/reports/search.html"),
)


def try_handle_post(handler, path: str) -> bool:
    if path in ("/api/v1/event-search/query", "/api/v1/event-search/page", "/api/v1/event-search/members"):
        _handle_evsearch_read(handler, path.rsplit("/", 1)[-1])
        return True
    return False


def _handle_evsearch_read(handler, operation):
    from server.sli.core.messages import message, select_locale
    from server.sli.reporting.read_timeout import report_read_budget

    try:
        with report_read_budget(timeout_ms=8000):
            _handle_evsearch_read_bounded(handler, operation)
    except QueryTimeoutError:
        code = "evsearch.snapshot_timeout"
        locale = select_locale(accept_language=handler.headers.get("Accept-Language"))
        handler._send_json({"error": code, "message": message(code, locale=locale)}, HTTPStatus.SERVICE_UNAVAILABLE)


def _handle_evsearch_read_bounded(handler, operation):
    # POST is read-only, but uses the existing origin/session guard. Registry
    # dispatch happens BEFORE the server's fallback mutation authorization.
    if not handler._authorize_mutation(required_role="viewer"):
        return
    principal = getattr(handler, "_principal", None)
    if not principal or principal.get("type") != "session":
        handler._send_json({"error": "authentication_required" if not principal else "insufficient_permissions"},
                           HTTPStatus.UNAUTHORIZED if not principal else HTTPStatus.FORBIDDEN)
        return
    if not handler._require_capability("events.view"):
        return
    from server.sli.core.messages import message, select_locale
    from server.sli.events.evsearch_contract import ContractError
    from server.sli.events.evsearch_runtime import RUNTIME
    from server.sli.storage.runtime_storage import StorageRouteAuthorizationError

    body = handler._read_json_body(max_bytes=16 * 1024)
    try:
        result = RUNTIME.execute(operation, body, principal=principal,
                                 authorization=_storage_route_authorization(handler))
    except (PermissionError, ContractError, QueryTimeoutError, StorageRouteAuthorizationError) as exc:
        if isinstance(exc, PermissionError):
            code, status = "evsearch.policy_denied", HTTPStatus.FORBIDDEN
        elif isinstance(exc, QueryTimeoutError):
            code, status = "evsearch.snapshot_timeout", HTTPStatus.SERVICE_UNAVAILABLE
        elif isinstance(exc, StorageRouteAuthorizationError):
            code, status = "evsearch.history_unavailable", HTTPStatus.SERVICE_UNAVAILABLE
        else:
            code = exc.code
            status = (HTTPStatus.GONE if code.endswith("snapshot_expired") else
                      HTTPStatus.CONFLICT if code.endswith("snapshot_invalidated") else
                      HTTPStatus.SERVICE_UNAVAILABLE if any(word in code for word in ("unavailable", "timeout", "integrity")) else
                      HTTPStatus.UNPROCESSABLE_ENTITY)
        locale = select_locale(accept_language=handler.headers.get("Accept-Language"))
        handler._send_json({"error": code, "message": message(code, locale=locale)}, status)
        return
    handler._send_json(result)


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path == "/api/events/summary":
        handler._send_json(get_event_summary(
            authorization=_storage_route_authorization(handler),
        ))
        return True
    if path == "/api/events/details":
        _handle_event_details_api(handler, query)
        return True
    if path == "/api/v1/events/batch":
        _handle_events_batch_api(handler, query)
        return True
    if path.startswith("/api/v1/events/") and path.endswith("/relations"):
        _handle_event_relations_api(handler, path)
        return True
    if path.startswith("/api/v1/events/") and path.endswith("/entities"):
        _handle_event_entities_api(handler, path)
        return True
    if path.startswith("/api/v1/events/"):
        _handle_event_by_id_api(handler, path)
        return True
    if path == "/api/v1/events":
        _handle_v1_events_api(handler, query)
        return True
    if path == "/api/events/search":
        _handle_event_search_api(handler, query)
        return True
    if path == "/api/events/search/deep":
        _handle_event_deep_search_api(handler, query)
        return True
    if path == "/api/events/timeline":
        _handle_account_timeline_api(handler, query)
        return True
    if path == "/reports/event-details.html":
        _handle_event_details_report(handler, query)
        return True
    if path == "/reports/search.html":
        _handle_event_search_report(handler, query)
        return True
    if path == "/reports/search-deep.html":
        _handle_event_deep_search_report(handler, query)
        return True
    if path == "/reports/account-timeline.html":
        _handle_account_timeline_report(handler, query)
        return True
    return False


def _event_search_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    raw_servers = first("server") or first("servers") or ""
    servers = [item.strip() for item in raw_servers.split(",") if item.strip()]
    try:
        limit = int(first("limit") or 200)
    except ValueError:
        limit = 200
    try:
        offset = int(first("offset") or 0)
    except ValueError:
        offset = 0
    view = str(first("view") or "").strip().lower()
    view_categories = {
        "authentication": "authentication",
        "accounts": "account_management",
        "tasks": "service_task",
    }
    return {
        "q": first("q"),
        "account": first("account") or first("user"),
        "event_id": first("event_id"),
        "event_ids": query.get("event_id") or [],
        "channel": first("channel"),
        "provider": first("provider") or first("source"),
        "subject": first("subject") or first("initiator"),
        "target": first("target") or first("object"),
        "servers": servers,
        "limit": limit,
        "offset": offset,
        "cursor": first("cursor"),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "timezone_name": first("timezone") or "UTC",
        "order": first("order"),
        "risk": first("risk") or ("high" if view == "attention" else None),
        "tier": first("tier"),
        "category": first("category") or view_categories.get(view),
    }


def _event_detail_filters(query: dict[str, list[str]]) -> dict:
    def first(name: str) -> str | None:
        values = query.get(name) or []
        return values[0] if values else None

    raw_servers = first("server") or first("servers") or ""
    servers = [item.strip() for item in raw_servers.split(",") if item.strip()]
    return {
        "event_db_id": first("event_db_id") or first("id"),
        "event_id": first("event_id"),
        "event_ids": query.get("event_id") or [],
        "channel": first("channel"),
        "servers": servers,
        "limit": int(first("limit") or 200),
        "offset": int(first("offset") or 0),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "order": first("order"),
        "user": first("user"),
        "ip": first("ip"),
        "logon_id": first("logon_id"),
    }


def _storage_route_authorization(
    handler,
) -> CutoverAuthorization | None:
    """Read the opaque controller capability from the server, never a request."""
    return validate_storage_route_authorization(
        getattr(handler, "storage_route_authorization", None)
    )


def _with_storage_route_authorization(handler, values: dict) -> dict:
    authorization = _storage_route_authorization(handler)
    return {**values, "authorization": authorization} if authorization is not None else values


def _handle_event_search_api(handler, query: dict[str, list[str]]) -> None:
    try:
        data = get_event_search_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(data)


def _handle_event_search_report(handler, query: dict[str, list[str]]) -> None:
    data = get_event_search_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    handler._send_html(render_event_search_report(data))


def _handle_event_deep_search_api(handler, query: dict[str, list[str]]) -> None:
    try:
        data = get_event_deep_search_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(data)


def _handle_event_deep_search_report(handler, query: dict[str, list[str]]) -> None:
    data = get_event_deep_search_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    handler._send_html(render_event_search_report(data))


def _handle_account_timeline_api(handler, query: dict[str, list[str]]) -> None:
    try:
        data = get_account_timeline_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(data)


def _handle_account_timeline_report(handler, query: dict[str, list[str]]) -> None:
    data = get_account_timeline_data(**_with_storage_route_authorization(handler, _event_search_filters(query)))
    handler._send_html(render_account_timeline_report(data))


def _handle_event_details_api(handler, query: dict[str, list[str]]) -> None:
    data = get_event_detail_report_data(**_with_storage_route_authorization(handler, _event_detail_filters(query)))
    handler._send_json(data)


def _handle_event_details_report(handler, query: dict[str, list[str]]) -> None:
    data = get_event_detail_report_data(**_with_storage_route_authorization(handler, _event_detail_filters(query)))
    handler._send_html(render_event_detail_report(data))


def _handle_v1_events_api(handler, query: dict[str, list[str]]) -> None:
    filters = _event_search_filters(query)
    try:
        data = get_event_search_data(**_with_storage_route_authorization(handler, filters))
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    payload = EventListResponse(
        items=[event_summary_projection(item) for item in (data.get("items") or [])],
        next_cursor=data.get("next_cursor"),
        has_more=bool(data.get("has_more")),
        query_status=str(data.get("query_status") or "ok"),
        warning=data.get("warning"),
        category_counts=get_event_category_counts(**_with_storage_route_authorization(handler, filters)),
    )
    handler._send_json(payload.model_dump(mode="json"))


def _handle_event_by_id_api(handler, path: str) -> None:
    """Stable exact-evidence API for the unified UI contract."""
    if not handler._require_capability("evidence.exact"):
        return
    raw_id = path.removeprefix("/api/v1/events/")
    try:
        event_db_id = int(raw_id)
    except ValueError:
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
        return
    data = get_event_detail_report_data(
        **_with_storage_route_authorization(handler, {"event_db_id": event_db_id, "limit": 1})
    )
    items = data.get("items") or []
    if not items:
        handler._send_json({"error": "event_not_found", "event_db_id": event_db_id}, HTTPStatus.NOT_FOUND)
        return
    from server.sli.semantic.event_card_semantics import build_event_card

    item = dict(items[0])
    item["event_db_id"] = int(item.get("id") or event_db_id)
    item["semantics"] = build_event_card(item)
    handler._send_json({"api_version": "v1", "item": item})


def _batch_event_db_ids(query: dict[str, list[str]]) -> list[int]:
    """Parse exact event identifiers, de-duplicate, and enforce the API cap."""
    parsed: list[int] = []
    for raw in query.get("event_db_id") or []:
        for part in str(raw).replace(";", ",").split(","):
            try:
                event_db_id = int(part.strip())
            except ValueError:
                continue
            if event_db_id > 0 and event_db_id not in parsed:
                parsed.append(event_db_id)
            if len(parsed) == 100:
                return parsed
    return parsed


def _handle_events_batch_api(handler, query: dict[str, list[str]]) -> None:
    """Hydrate at most 100 exact evidence records with one bounded query."""
    if not handler._require_capability("evidence.exact"):
        return
    event_db_ids = _batch_event_db_ids(query)
    if not event_db_ids:
        handler._send_json({"error": "event_db_id_required"}, HTTPStatus.BAD_REQUEST)
        return
    from server.sli.semantic.event_card_semantics import build_event_card

    authorization = _storage_route_authorization(handler)
    details_by_id = (
        get_event_details_by_ids(event_db_ids, authorization=authorization)
        if authorization is not None
        else get_event_details_by_ids(event_db_ids)
    )
    items: list[dict] = []
    for event_db_id in event_db_ids:
        stored = details_by_id.get(event_db_id)
        if stored is None:
            continue
        item = dict(stored)
        item["event_db_id"] = int(item.get("id") or event_db_id)
        item["semantics"] = build_event_card(item)
        items.append(item)
    handler._send_json({
        "api_version": "v1",
        "items": items,
        "requested_event_db_ids": event_db_ids,
        "missing_event_db_ids": [event_db_id for event_db_id in event_db_ids if event_db_id not in details_by_id],
        "limit": 100,
    })


def _handle_event_relations_api(handler, path: str) -> None:
    from server.sli.events.event_relations import get_event_relations

    raw_id = path.removeprefix("/api/v1/events/").removesuffix("/relations").rstrip("/")
    try:
        event_db_id = int(raw_id)
    except ValueError:
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
        return
    authorization = _storage_route_authorization(handler)
    relations = (
        get_event_relations(event_db_id, authorization=authorization)
        if authorization is not None
        else get_event_relations(event_db_id)
    )
    handler._send_json(relations)


def _handle_event_entities_api(handler, path: str) -> None:
    raw_id = path.removeprefix("/api/v1/events/").removesuffix("/entities").rstrip("/")
    try:
        event_db_id = int(raw_id)
    except ValueError:
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
        return
    if event_db_id <= 0:
        handler._send_json({"error": "invalid_event_db_id"}, HTTPStatus.BAD_REQUEST)
        return
    authorization = _storage_route_authorization(handler)
    try:
        entities = (
            get_event_entities_data(event_db_id=event_db_id, authorization=authorization)
            if authorization is not None
            else get_event_entities_data(event_db_id=event_db_id)
        )
    except QueryTimeoutError:
        # Even the existence check can time out; absence is not established.
        entities = {
            "event_db_id": event_db_id,
            "event_found": None,
            "evidence_status": "timeout",
            "items": [],
            "limit": EVENT_ENTITY_LIMIT,
            "warning": "Связанные сущности временно недоступны: превышено время запроса. Это не означает, что связей нет.",
        }
    handler._send_json(EventEntitiesResponse(**entities).model_dump(mode="json"))
