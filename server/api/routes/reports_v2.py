"""Single report API for the v2 framework (ADR 0010 §3).

GET /api/v2/reports                      catalog of v2 reports the user may open
GET /api/v2/reports/{key}                declaration + parameter options
GET /api/v2/reports/{key}/data?...       ReportResult
GET /api/v2/reports/{key}/export.csv?... CSV export (if declared)
GET /api/v2/reports/{key}/rows/{id}/detail?... drill-down result (if declared)
"""

from __future__ import annotations

import logging
import re
from dataclasses import replace
from http import HTTPStatus
from urllib.parse import unquote

from server.sli.access.domain_scope import (
    parse_domain_id,
    resolve_report_domain_selection,
)
from server.sli.access.scope import legacy_domain_ids
from server.sli.core.keyset_cursor import decode_cursor, encode_cursor
from server.sli.core.messages import message
from server.sli.core.time_contract import TimeRangeError
from server.sli.plugins.registry import BUNDLED, plugin_installed
from server.sli.reporting.navigation_registry import (
    load_registry,
    navigation_plugin_states,
)
from server.sli.reporting.v2.access import ReportAccess, report_grant
from server.sli.reporting.v2.definition import Detail, QueryContext, parse_params
from server.sli.reporting.v2.registry import catalog, get_report
from server.sli.sources.gpo_v2_source import GpoV2SourceContractError
from server.sli.sources.plugin_state import annotate_plugin_report, report_plugin_state
from server.sli.storage.runtime_storage import validate_storage_route_authorization

PREFIX = "/api/v2/reports"
_ROUTE = re.compile(r"^/api/v2/reports/(?P<key>[a-z0-9][a-z0-9_.-]{1,79})(?:/(?P<action>data|export\.csv)|/rows/(?P<row>(?:[A-Za-z0-9_.:-]|%[a-fA-F0-9]{2}){1,128})/detail)?$")
_ROW_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
_LOG = logging.getLogger(__name__)

# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/v2/reports"),
    ("GET", "/api/v2/reports/*"),
)


def _match_route(path: str) -> tuple[re.Match[str], str | None] | None:
    match = _ROUTE.fullmatch(path)
    if not match:
        return None
    row_id = match.group("row")
    if row_id is not None:
        # Decode only this segment, once; separators and encoded escapes stay invalid.
        try:
            row_id = unquote(row_id, errors="strict")
        except UnicodeDecodeError:
            return None
        if not _ROW_ID.fullmatch(row_id):
            return None
    return match, row_id


def is_resource_aware(path: str) -> bool:
    """Every v2 report route checks the report grant itself."""
    return path == PREFIX or _match_route(path) is not None


def _default_domain_metadata(definition, access, options):
    """Recommend within report grants and, for VPN, delegated source options."""
    from server.sli.core.platform_settings import get_setting
    from server.sli.core.report_domain import (
        ReportDomainNotConfiguredError,
        preferred_domain,
    )

    try:
        preferred = get_setting("reports.domain_fqdn")
    except ReportDomainNotConfiguredError:
        preferred = None
    try:
        selection = resolve_report_domain_selection(access, definition.access, {})
        domains = selection.domains
        if definition.key == "vpn.connections":
            allowed = {str(option["value"]) for option in options.get("domain", [])}
            domains = tuple(row for row in domains if str(row["id"]) in allowed)
        chosen = preferred_domain(domains, preferred)
        return {"default_domain_id": chosen["id"] if chosen else None,
                "default_domain_state": "available" if chosen else "unknown"}
    except PermissionError:
        return {"default_domain_id": None, "default_domain_state": "denied"}
    except Exception:
        # Metadata failure must not silently select another domain.
        return {"default_domain_id": None, "default_domain_state": "unavailable"}


def _with_only_domain(definition, access, query: dict[str, list[str]]) -> dict[str, list[str]]:
    """Fill a missing required domain from the user's available options.

    The options come from the report's own access-filtered option source.
    Prefer an available declared default, otherwise the only visible domain.
    An obsolete default must not silently select a domain outside the options.
    """
    if definition.key == "vpn.connections":
        if query.get("scope") == ["all"]:
            raise ValueError("report_parameter_required:domain")
        if "domain_id" in query:
            selected = parse_domain_id(query)
            if "domain" in query and parse_domain_id({"domain_id": query["domain"]}) != selected:
                raise ValueError("domain_scope_invalid")
            query = {key: value for key, value in query.items() if key != "domain_id"}
            query["domain"] = [str(selected)]
    params = [param for param in definition.params if param.kind == "domain" and param.required and not (query.get(param.key) or [""])[0].strip()]
    if not params:
        return query
    options = (definition.options(access) if definition.options else {}) or {}
    filled = dict(query)
    if definition.key == "vpn.connections":
        chosen = _default_domain_metadata(definition, access, options)["default_domain_id"]
        if chosen is not None:
            filled["domain"] = [str(chosen)]
        return filled
    for param in params:
        values = [str(value) for value, _label in param.options] if param.options else [
            str(option["value"]) for option in options.get(param.options_from or param.key) or []
            if option.get("value") not in (None, "")
        ]
        if str(param.default) in values:
            filled[param.key] = [str(param.default)]
        elif len(values) == 1:
            filled[param.key] = values
        elif param.default not in (None, ""):
            raise ValueError(f"report_parameter_required:{param.key}")
    return filled


def try_handle_get(handler, path: str, query: dict[str, list[str]]) -> bool:
    if path == PREFIX:
        handler._send_json(catalog(handler._access_decision(), plugin_states=navigation_plugin_states()))
        return True
    if not path.startswith("/api/v2/reports/"):
        return False
    route = _match_route(path)
    if route is None:
        return False
    match, row_id = route
    definition = get_report(match.group("key"))
    if definition is None:
        _, owners = load_registry()
        owner = owners.get(match.group("key"))
        if owner and owner["owner_id"] in BUNDLED and not plugin_installed(owner["owner_id"]):
            if report_grant(handler._access_decision(), owner["access_key"]) is None:
                handler._send_json({"error": "report_access_denied"}, HTTPStatus.FORBIDDEN)
            else:
                handler._send_json({"state": "not_installed", "reason": "plugin_not_installed",
                                    "plugin_id": owner["owner_id"], "items": []})
            return True
        handler._send_json({"error": "report_not_found"}, HTTPStatus.NOT_FOUND)
        return True
    access = handler._access_decision()
    if report_grant(access, definition.access.report_key) is None:
        handler._send_json({"error": "report_access_denied"}, HTTPStatus.FORBIDDEN)
        return True
    action = match.group("action")
    if row_id is not None and not (isinstance(definition.detail, Detail) and definition.detail.query is not None):
        handler._send_json({"error": "report_detail_not_available"}, HTTPStatus.NOT_FOUND)
        return True
    if action is None and row_id is None:
        try:
            projection = ReportAccess(definition, access)
        except PermissionError as exc:
            handler._send_json({"error": str(exc), "state": "denied", "reason": str(exc)}, HTTPStatus.FORBIDDEN)
            return True
        payload = projection.declaration()
        plugin = report_plugin_state(definition.key)
        if plugin is not None:
            payload["plugin"] = plugin
        visible_options = {param.get("options_from") or param["key"] for param in payload["params"]}
        payload["filter_options"] = {key: list(values) for key, values in (definition.options(access) if definition.options else {}).items() if key in visible_options}
        if definition.key in {"ad.users.v2", "ad.computers.v6", "ad.infrastructure", "vpn.connections"}:
            payload.update(_default_domain_metadata(definition, access, payload["filter_options"]))
        handler._send_json(payload)
        return True
    export = action == "export.csv"
    if export and definition.export_csv is None:
        handler._send_json({"error": "report_export_not_available"}, HTTPStatus.NOT_FOUND)
        return True
    try:
        projection = ReportAccess(definition, access, definition.access.export_action if export else "view")
        projection.validate_request(query, {key: (query.get(key) or [None])[0] for key in ("tab", "sort")}, detail=row_id is not None)
        selection = None
        if definition.key in {"ad.users.v2", "ad.computers.v6", "ad.infrastructure"}:
            selection = resolve_report_domain_selection(
                access, definition.access, query, definition.access.export_action if export else "view",
            )
            # Keep the legacy alias executable through the existing scope adapter.
            if selection.domain_id is not None:
                query = {**query, "domain": [str(selection.domain_id)]}
        visible_definition = replace(definition, params=tuple(p for p in definition.params if projection.fields_allowed(p.field_categories)))
        params, paging = parse_params(visible_definition, _with_only_domain(visible_definition, access, query))
        projection.validate_request(query, paging, detail=row_id is not None)
        scope = projection.restrict_request(params)
        cursor_binding = {"scope": scope.fingerprint, "report": definition.key, "params": params,
                          "sort": paging["sort"], "direction": paging["direction"], "tab": paging["tab"],
                          "dataset_version": report_grant(access, definition.access.report_key).get("dataset_version")}
        generic = definition.access.scope == "generic"
        if row_id is not None:
            cursor_binding["row"] = row_id
        if generic and paging["cursor"]:
            paging["cursor"] = decode_cursor(paging["cursor"], cursor_binding).get("cursor")
        runtime = {"storage_route_authorization": validate_storage_route_authorization(getattr(handler, "storage_route_authorization", None))}
        if definition.key.startswith("workstations."):
            from server.sli.plugins.workstations.scope import WorkstationScopeAdapter

            runtime["workstation_scope_adapter"] = WorkstationScopeAdapter()
        domain_ids = selection.domain_ids if selection is not None else (
            legacy_domain_ids(scope) if definition.access.scope == "domain" else None
        )
        context = QueryContext(
            access=access, params=params, domain_ids=domain_ids,
            action="export" if export else "view",
            cursor=paging["cursor"], limit=paging["limit"], timezone=paging["timezone"], tab=paging["tab"],
            sort=paging["sort"], direction=paging["direction"],
            runtime=runtime,
            field_access=projection.fields_allowed,
            scope=scope, principal=access.get("subject") or {},
        )
        if selection is not None:
            context.runtime["domain_selection"] = selection
        if row_id is not None:
            detail = definition.detail
            detail_context = QueryContext(
                access=context.access, params=context.params, domain_ids=context.domain_ids, action="view",
                cursor=context.cursor, limit=min(context.limit, detail.default_limit), timezone=context.timezone,
                tab=context.tab, sort=context.sort, direction=context.direction,
                runtime=context.runtime,
                field_access=context.field_access,
                scope=context.scope, principal=context.principal,
            )
            payload = projection.result(detail.query(detail_context, row_id), detail=True)
            if selection is not None:
                payload.update(domain_scope=selection.to_json(), domains=list(selection.domains))
            annotate_plugin_report(definition.key, payload)
            if generic and payload.get("next_cursor"):
                payload["next_cursor"] = encode_cursor(cursor_binding, {"cursor": payload["next_cursor"]})
            handler._send_json(payload)
            return True
        if not export:
            payload = projection.result(definition.query(context))
            if selection is not None:
                payload.update(domain_scope=selection.to_json(), domains=list(selection.domains))
            if generic and payload.get("next_cursor"):
                payload["next_cursor"] = encode_cursor(cursor_binding, {"cursor": payload["next_cursor"]})
            annotate_plugin_report(definition.key, payload)
            handler._send_json(payload)
            return True
        body, meta = definition.export_csv(context)
        body = projection.csv(body)
    except PermissionError as exc:
        payload = {"error": str(exc) or "report_access_denied", "state": "denied", "reason": str(exc) or "report_access_denied"}
        if "projection" in locals():
            payload["access"] = {**projection.summary, "allowed": False, "reason": payload["reason"]}
        handler._send_json(payload, HTTPStatus.FORBIDDEN)
        return True
    except LookupError as exc:
        handler._send_json({"error": str(exc).strip("'") or "report_row_not_found"}, HTTPStatus.NOT_FOUND)
        return True
    except GpoV2SourceContractError:
        _LOG.error("GPO snapshot unavailable: source contract violation")
        handler._send_json({
            "error": "gpo_snapshot_unavailable",
            "state": "error",
            "reason": "source_contract_error",
            "message": message("reports.renderer.error_gpo_snapshot"),
        }, HTTPStatus.SERVICE_UNAVAILABLE)
        return True
    except (TimeRangeError, TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc) or "report_request_invalid"}, HTTPStatus.BAD_REQUEST)
        return True
    data = body.encode("utf-8-sig")
    rows = int(meta.get("rows") or 0)
    truncated = bool(meta.get("truncated"))
    suffix = f"INCOMPLETE-first-{rows}-rows" if truncated else f"complete-{rows}-rows"
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/csv; charset=utf-8")
    handler.send_header("Content-Disposition", f'attachment; filename="sli-{definition.key}-{suffix}.csv"')
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("X-Sli-Export-Truncated", "true" if truncated else "false")
    handler.send_header("X-Sli-Export-Rows", str(rows))
    handler.end_headers()
    handler.wfile.write(data)
    return True
