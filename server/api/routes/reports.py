"""Reports v4 + VPN reporting domain.

Reports v4 (``server.sli.reporting.reporting_v4``) and VPN reporting
(``server.sli.reports.vpn_session_reporting`` / ``vpn_connections_reporting``) are
different backend modules but share the ``/api/v1/reports/*`` URL prefix, so
they live in one route module — precedence between their exact-match and
startswith/endswith variants matters more than backend ownership (see
spec.md §4). The legacy ``/api/reports`` catalog (``server.sli.reporting.reports``) is
a third, older module and is intentionally not unified with the v4 catalog.

``/api/v1/reports/<key>/preference`` is NOT here — it moved to
``routes/access.py`` in ticket 02 (it calls
``update_user_report_preference`` from ``access_control_v4``, not this
domain's ``reporting_v4`` backend).

Shared ambient auth/authz machinery (``_access_decision``,
``_authorize_mutation``, ``_require_capability``, ``_read_json_body``,
response helpers) stays on ``RequestHandler`` in ``server.api.http_server``
and is reached through the ``handler`` instance passed to every function
here. This module never imports ``server.api.http_server``.
"""
from __future__ import annotations

import re
from functools import partial
from http import HTTPStatus

from server.sli.plugins.registry import call_plugin, plugin_installed, require_plugin
from server.sli.access.access_control_v4 import report_access_trace
from server.sli.core.time_contract import TimeRangeError
from server.sli.reporting.reporting_v4 import (
    builder_preview as preview_v4_report,
)
from server.sli.reporting.reporting_v4 import (
    dataset_registry as get_v4_dataset_registry,
)
from server.sli.reporting.reporting_v4 import (
    execute_report as execute_v4_report,
)
from server.sli.reporting.reporting_v4 import (
    export_report_csv_document as export_v4_report_csv_document,
)
from server.sli.reporting.reporting_v4 import (
    promote_report_version as promote_v4_report_version,
)
from server.sli.reporting.reporting_v4 import (
    publish_report as publish_v4_report,
)
from server.sli.reporting.reporting_v4 import (
    report_access_summary as get_v4_report_access_summary,
)
from server.sli.reporting.reporting_v4 import (
    report_catalog as get_v4_report_catalog,
)
from server.sli.reporting.reporting_v4 import (
    report_definition_detail as get_v4_report_definition_detail,
)
from server.sli.reporting.reporting_v4 import (
    report_definitions as get_v4_report_definitions,
)
from server.sli.reporting.reporting_v4 import (
    retire_report as retire_v4_report,
)
from server.sli.reporting.reporting_v4 import (
    set_report_visibility as set_v4_report_visibility,
)
from server.sli.reporting.reports import list_reports
from server.sli.reporting.ui_api_models import (
    V4ReportAccessTraceResponse,
    V4ReportCatalogResponse,
)
from server.sli.reports.security_event_reporting import (
    get_security_event_sources,
    get_security_events_report,
    render_security_events_csv,
)
from server.sli.reports.windows_authentication_reporting import (
    get_windows_authentication_report,
    get_windows_authentication_sources,
)
from server.sli.sources.plugin_state import annotate_plugin_report, report_plugin_state

get_ad_account_change_history = partial(call_plugin, "sli.ad", "get_ad_account_change_history")
get_ad_account_change_sources = partial(call_plugin, "sli.ad", "get_ad_account_change_sources")
get_ad_group_membership_history = partial(call_plugin, "sli.ad", "get_ad_group_membership_history")
get_dc_powershell_activity = partial(call_plugin, "sli.ad", "get_dc_powershell_activity")

get_vpn_authorization_timeline = partial(call_plugin, "sli.remote-access", "get_vpn_authorization_timeline")
get_vpn_failed_authorization_series = partial(call_plugin, "sli.remote-access", "get_vpn_failed_authorization_series")
get_vpn_session_evidence = partial(call_plugin, "sli.remote-access", "get_vpn_session_evidence")
get_vpn_session_report = partial(call_plugin, "sli.remote-access", "get_vpn_session_report")
get_vpn_session_sources = partial(call_plugin, "sli.remote-access", "get_vpn_session_sources")


# Маршруты модуля для реестра (server/api/route_registry.py).
ROUTES: tuple[tuple[str, str], ...] = (
    ("GET", "/api/reports"),
    ("GET", "/api/v1/reports/ad.groups/membership-changes"),
    ("GET", "/api/v1/reports/ad.state/account-change-sources"),
    ("GET", "/api/v1/reports/ad.state/account-changes"),
    ("GET", "/api/v1/reports/ad.state/security-event-sources"),
    ("GET", "/api/v1/reports/ad.state/security-events"),
    ("GET", "/api/v1/reports/ad.state/security-events.csv"),
    ("GET", "/api/v1/reports/catalog"),
    ("GET", "/api/v1/reports/datasets"),
    ("GET", "/api/v1/reports/dc.powershell/activity"),
    ("GET", "/api/v1/reports/definitions"),
    ("GET", "/api/v1/reports/vpn.*"),
    ("GET", "/api/v1/reports/vpn.audit/authorizations"),
    ("GET", "/api/v1/reports/vpn.audit/failed-authorizations/series"),
    ("GET", "/api/v1/reports/vpn.audit/session-sources"),
    ("GET", "/api/v1/reports/vpn.audit/sessions"),
    ("GET", "/api/v1/reports/vpn.audit/sessions/evidence"),
    ("GET", "/api/v1/reports/vpn.audit/windows-authentication"),
    ("GET", "/api/v1/reports/vpn.audit/windows-authentication-sources"),
    ("GET", "/api/v1/reports/{}/access-summary"),
    ("GET", "/api/v1/reports/{}/access-trace"),
    ("GET", "/api/v1/reports/{}/data"),
    ("GET", "/api/v1/reports/{}/export.csv"),
    ("POST", "/api/v1/reports/builder/preview"),
    ("GET", "/api/v1/reports/definitions/*"),
    ("POST", "/api/v1/reports/definitions"),
    ("POST", "/api/v1/reports/definitions/*"),
)


def is_resource_aware(path: str) -> bool:
    """True only where the handler must inspect a domain-scoped grant itself."""
    if _is_access_summary_path(path):
        return True  # the handler enforces reports.assign OR access.manage itself
    return path in {
        "/api/v1/reports/ad.state/account-change-sources",
        "/api/v1/reports/ad.state/account-changes",
        "/api/v1/reports/ad.state/security-event-sources",
        "/api/v1/reports/ad.state/security-events",
        "/api/v1/reports/ad.state/security-events.csv",
        "/api/v1/reports/ad.groups/membership-changes",
        "/api/v1/reports/dc.powershell/activity",
    }


def try_handle_get(handler, path: str, query: dict) -> bool:
    if path.startswith("/api/v1/reports/vpn.") and not plugin_installed("sli.remote-access"):
        handler._send_json({"state": "not_installed", "reason": "plugin_not_installed",
                            "plugin_id": "sli.remote-access", "items": []})
        return True
    if path == "/api/v1/reports/catalog":
        _handle_v4_report_catalog_api(handler)
        return True
    if path == "/api/v1/reports/vpn.audit/session-sources":
        _handle_vpn_session_sources_api(handler)
        return True
    if path == "/api/v1/reports/vpn.audit/windows-authentication-sources":
        _handle_windows_authentication_sources_api(handler)
        return True
    if path == "/api/v1/reports/vpn.audit/windows-authentication":
        _handle_windows_authentication_report_api(handler, query)
        return True
    if path == "/api/v1/reports/vpn.audit/sessions/evidence":
        _handle_vpn_session_evidence_api(handler, query)
        return True
    if path == "/api/v1/reports/vpn.audit/sessions":
        _handle_vpn_session_report_api(handler, query)
        return True
    if path == "/api/v1/reports/vpn.audit/failed-authorizations/series":
        _handle_vpn_failed_authorization_series_api(handler, query)
        return True
    if path == "/api/v1/reports/vpn.audit/authorizations":
        _handle_vpn_authorization_timeline_api(handler, query)
        return True
    if path == "/api/v1/reports/dc.powershell/activity":
        _handle_dc_powershell_activity_api(handler, query)
        return True
    if path == "/api/v1/reports/ad.state/account-change-sources":
        _handle_ad_account_change_sources_api(handler)
        return True
    if path == "/api/v1/reports/ad.state/account-changes":
        _handle_ad_account_change_history_api(handler, query)
        return True
    if path == "/api/v1/reports/ad.state/security-event-sources":
        _handle_security_event_sources_api(handler)
        return True
    if path == "/api/v1/reports/ad.state/security-events":
        _handle_security_events_api(handler, query)
        return True
    if path == "/api/v1/reports/ad.state/security-events.csv":
        _handle_security_events_export_api(handler, query)
        return True
    if path == "/api/v1/reports/ad.groups/membership-changes":
        _handle_ad_group_membership_history_api(handler, query)
        return True
    if path == "/api/v1/reports/datasets":
        _handle_v4_report_datasets_api(handler)
        return True
    if path == "/api/v1/reports/definitions":
        _handle_v4_report_definitions_api(handler, query)
        return True
    if path.startswith("/api/v1/reports/definitions/"):
        _handle_v4_report_definition_detail_api(handler, path)
        return True
    if path.startswith("/api/v1/reports/") and path.endswith("/export.csv"):
        _handle_v4_report_export_api(handler, path, query)
        return True
    if path.startswith("/api/v1/reports/") and path.endswith("/access-summary") and _is_access_summary_path(path):
        _handle_v4_report_access_summary_api(handler, path)
        return True
    if path.startswith("/api/v1/reports/") and path.endswith("/access-trace"):
        _handle_v4_report_access_trace_api(handler, path)
        return True
    if path.startswith("/api/v1/reports/") and path.endswith("/data"):
        _handle_v4_report_data_api(handler, path, query)
        return True
    if path == "/api/reports":
        handler._send_json({"items": list_reports()})
        return True
    return False


def try_handle_post(handler, path: str) -> bool:
    if path == "/api/v1/reports/builder/preview":
        if not handler._authorize_mutation(required_role="viewer") or not handler._require_capability("reports.design"):
            return True
        _handle_v4_report_builder_preview(handler)
        return True
    if path == "/api/v1/reports/definitions":
        if not handler._authorize_mutation() or not handler._require_capability("reports.publish"):
            return True
        _handle_v4_report_publish(handler)
        return True
    if path.startswith("/api/v1/reports/definitions/"):
        return _handle_v4_report_lifecycle(handler, path)
    return False


def _handle_v4_report_catalog_api(handler) -> None:
    try:
        payload = V4ReportCatalogResponse(**get_v4_report_catalog(
            getattr(handler, "_principal", None), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v4_report_datasets_api(handler) -> None:
    try:
        handler._send_json(get_v4_dataset_registry(
            getattr(handler, "_principal", None), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)


def _handle_v4_report_definitions_api(handler, query: dict[str, list[str]]) -> None:
    try:
        handler._send_json(get_v4_report_definitions(
            getattr(handler, "_principal", None),
            limit=int(query.get("limit", ["200"])[0]),
            access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_v4_report_data_api(handler, path: str, query: dict[str, list[str]]) -> None:
    report_key = path.removeprefix("/api/v1/reports/").removesuffix("/data").strip("/")
    try:
        limit = int(query.get("limit", ["50"])[0])
        fields = [item for value in query.get("field", []) for item in value.split(",") if item]
        payload = execute_v4_report(
            report_key, getattr(handler, "_principal", None), limit=limit, fields=fields or None,
            query_filters=_v4_report_query_filters(query),
            access=handler._access_decision(),
        )
        annotate_plugin_report(report_key, payload, legacy=True)
        handler._send_json(payload)
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


_ACCESS_SUMMARY_RE = re.compile(r"/api/v1/reports/[^/]+/access-summary")


def _is_access_summary_path(path: str) -> bool:
    return bool(_ACCESS_SUMMARY_RE.fullmatch(path))


def _handle_v4_report_access_summary_api(handler, path: str) -> None:
    report_key = path.removeprefix("/api/v1/reports/").removesuffix("/access-summary")
    try:
        handler._send_json(get_v4_report_access_summary(
            report_key, getattr(handler, "_principal", None), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except LookupError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_v4_report_access_trace_api(handler, path: str) -> None:
    report_key = path.removeprefix("/api/v1/reports/").removesuffix("/access-trace").strip("/")
    try:
        payload = V4ReportAccessTraceResponse(**report_access_trace(handler._access_decision(), report_key))
    except LookupError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload.model_dump(mode="json"))


def _handle_v4_report_export_api(handler, path: str, query: dict[str, list[str]]) -> None:
    report_key = path.removeprefix("/api/v1/reports/").removesuffix("/export.csv").strip("/")
    try:
        fields = [item for value in query.get("field", []) for item in value.split(",") if item]
        document = export_v4_report_csv_document(
            report_key, getattr(handler, "_principal", None), fields=fields or None,
            query_filters=_v4_report_query_filters(query),
            access=handler._access_decision(),
        )
        body = str(document["csv"]).encode("utf-8-sig")
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    # A downloaded file keeps only its NAME: response headers are gone once the
    # browser saves it.  A bounded export must therefore say so in the
    # filename, otherwise a 200-row slice of a larger result is filed as a
    # complete audit export.
    safe_key = re.sub(r"[^A-Za-z0-9._-]+", "-", report_key).strip("-") or "report"
    truncated = bool(document["truncated"])
    filename = (
        f"sli-report-{safe_key}-INCOMPLETE-first-{int(document['row_count'])}-rows.csv"
        if truncated
        else f"sli-report-{safe_key}-complete-{int(document['row_count'])}-rows.csv"
    )
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/csv; charset=utf-8")
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    # Machine-readable facts for API clients, which do see headers.
    handler.send_header("X-Sli-Export-Truncated", "true" if truncated else "false")
    handler.send_header("X-Sli-Export-Rows", str(int(document["row_count"])))
    handler.send_header("X-Sli-Export-Row-Limit", str(int(document["row_limit"])))
    handler.send_header("X-Sli-Export-Has-More", "true" if document["has_more"] else "false")
    handler.send_header("X-Sli-Export-Total-Count", str(document["total_count"]))
    handler.end_headers()
    handler.wfile.write(body)


def _v4_report_query_filters(query: dict[str, list[str]]) -> dict[str, str]:
    allowed = {
        "limit", "field", "q", "server", "time_from", "time_to", "cursor",
        "sort", "direction", "entity_type", "activity_state", "privileged_overlap",
        "application_state", "link_count", "has_executable_components", "view",
    }
    if any(key not in allowed for key in query):
        raise ValueError("unknown_report_query_filter")
    result: dict[str, str] = {}
    for key in (
        "q", "server", "time_from", "time_to", "cursor", "sort", "direction",
        "entity_type", "activity_state", "privileged_overlap", "view",
        "application_state", "link_count", "has_executable_components",
    ):
        values = query.get(key) or []
        if len(values) > 1:
            raise ValueError("duplicate_report_query_filter")
        if values and str(values[0]).strip():
            result[key] = str(values[0]).strip()
    return result


def _handle_vpn_session_report_api(handler, query: dict[str, list[str]]) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        domain_id = int(first("domain_id", "0") or 0)
        payload = get_vpn_session_report(
            handler._access_decision(),
            source_domain_id=domain_id,
            action=str(first("action", "view") or "view"),
            time_from=first("time_from"),
            time_to=first("time_to"),
            timezone_name=str(first("timezone", "UTC") or "UTC"),
            limit=int(first("limit", "50") or 50),
            offset=int(first("offset", "0") or 0),
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        code = str(exc)
        status = (
            HTTPStatus.NOT_FOUND
            if code == "vpn_session_source_domain_not_registered"
            else HTTPStatus.BAD_REQUEST
        )
        handler._send_json({"error": code}, status)
        return
    payload["plugin"] = report_plugin_state("vpn.audit")
    handler._send_json(payload)


def _handle_vpn_session_sources_api(handler) -> None:
    handler._send_json(get_vpn_session_sources(handler._access_decision()))


def _handle_windows_authentication_sources_api(handler) -> None:
    handler._send_json(get_windows_authentication_sources(handler._access_decision()))


def _handle_windows_authentication_report_api(
    handler,
    query: dict[str, list[str]],
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_windows_authentication_report(
            handler._access_decision(),
            source_domain_id=int(first("domain_id", "0") or 0),
            time_from=first("time_from"),
            time_to=first("time_to"),
            timezone_name=str(first("timezone", "UTC") or "UTC"),
            limit=int(first("limit", "200") or 200),
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload)


def _handle_vpn_session_evidence_api(handler, query: dict[str, list[str]]) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_vpn_session_evidence(
            handler._access_decision(),
            source_domain_id=int(first("domain_id", "0") or 0),
            session_row_id=str(first("session_row_id", "") or ""),
        )
    except (TypeError, ValueError) as exc:
        code = str(exc)
        status = (
            HTTPStatus.NOT_FOUND
            if code == "vpn_session_evidence_session_not_found"
            else HTTPStatus.BAD_REQUEST
        )
        handler._send_json({"error": code}, status)
        return
    handler._send_json(payload)


def _handle_vpn_failed_authorization_series_api(
    handler,
    query: dict[str, list[str]],
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_vpn_failed_authorization_series(
            handler._access_decision(),
            source_domain_id=int(first("domain_id", "0") or 0),
            time_from=first("time_from"),
            time_to=first("time_to"),
            timezone_name=str(first("timezone", "UTC") or "UTC"),
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload)


def _handle_vpn_authorization_timeline_api(
    handler,
    query: dict[str, list[str]],
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_vpn_authorization_timeline(
            handler._access_decision(),
            source_domain_id=int(first("domain_id", "0") or 0),
            time_from=first("time_from"),
            time_to=first("time_to"),
            timezone_name=str(first("timezone", "UTC") or "UTC"),
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload)


def _call_ad_report_handler(name, handler, *args, **kwargs) -> None:
    payload = call_plugin("sli.ad", name, handler, *args, **kwargs)
    if payload is not None:
        handler._send_json(payload)


def _handle_dc_powershell_activity_api(handler, query) -> None:
    _call_ad_report_handler("handle_dc_powershell_activity_api", handler, query, get_dc_powershell_activity=get_dc_powershell_activity)


def _handle_ad_account_change_history_api(handler, query) -> None:
    _call_ad_report_handler("handle_ad_account_change_history_api", handler, query, get_ad_account_change_history=get_ad_account_change_history)


def _handle_ad_account_change_sources_api(handler) -> None:
    _call_ad_report_handler("handle_ad_account_change_sources_api", handler, get_ad_account_change_sources=get_ad_account_change_sources)


def _handle_security_event_sources_api(handler) -> None:
    _call_ad_report_handler("handle_security_event_sources_api", handler, get_security_event_sources=get_security_event_sources)


def _handle_security_events_api(handler, query) -> None:
    _call_ad_report_handler("handle_security_events_api", handler, query, get_security_events_report=get_security_events_report)


def _handle_security_events_export_api(handler, query) -> None:
    _call_ad_report_handler("handle_security_events_export_api", handler, query, get_security_events_report=get_security_events_report, render_security_events_csv=render_security_events_csv)


def _handle_ad_group_membership_history_api(handler, query) -> None:
    _call_ad_report_handler("handle_ad_group_membership_history_api", handler, query, get_ad_group_membership_history=get_ad_group_membership_history)


def _security_event_arguments(query: dict[str, list[str]], *, export: bool = False) -> dict:
    return require_plugin("sli.ad", "security_event_arguments", query, export=export)


def _handle_v4_report_builder_preview(handler) -> None:
    try:
        handler._send_json(preview_v4_report(
            handler._read_json_body(), getattr(handler, "_principal", None),
            access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_v4_report_publish(handler) -> None:
    try:
        item = publish_v4_report(
            handler._read_json_body(), getattr(handler, "_principal", None),
            remote_address=handler.client_address[0], access=handler._access_decision(),
        )
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json({"item": item}, HTTPStatus.CREATED)


def _definition_path_parts(path: str) -> list[str]:
    return path.removeprefix("/api/v1/reports/definitions/").strip("/").split("/")


def _handle_v4_report_definition_detail_api(handler, path: str) -> None:
    parts = _definition_path_parts(path)
    if len(parts) != 1 or not parts[0]:
        handler._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
        return
    try:
        handler._send_json(get_v4_report_definition_detail(
            parts[0], getattr(handler, "_principal", None), access=handler._access_decision(),
        ))
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
    except LookupError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)


def _handle_v4_report_lifecycle(handler, path: str) -> bool:
    """POST /definitions/{key}/retire | visibility | versions/{n}/publish."""
    parts = _definition_path_parts(path)
    key = parts[0] if parts else ""
    action = parts[1:]
    is_promote = len(action) == 3 and action[0] == "versions" and action[2] == "publish"
    if not key or not (action in (["retire"], ["visibility"]) or is_promote):
        return False
    if (
        not handler._authorize_mutation(required_role="admin")
        or not handler._require_capability("reports.publish")
    ):
        return True
    principal = getattr(handler, "_principal", None)
    remote = handler.client_address[0]
    try:
        if action == ["retire"]:
            item = retire_v4_report(
                key, principal, remote_address=remote, access=handler._access_decision(),
            )
        elif action == ["visibility"]:
            item = set_v4_report_visibility(
                key, handler._read_json_body(), principal,
                remote_address=remote, access=handler._access_decision(),
            )
        else:
            item = promote_v4_report_version(
                key, action[1], principal,
                remote_address=remote, access=handler._access_decision(),
            )
    except PermissionError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        return True
    except LookupError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        return True
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return True
    handler._send_json({"item": item})
    return True
