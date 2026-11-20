"""AD legacy report handlers; shared transport and access machinery stay in core."""
from __future__ import annotations

from http import HTTPStatus

from server.sli.core.time_contract import TimeRangeError


def handle_dc_powershell_activity_api(
    handler, query: dict[str, list[str]], *, get_dc_powershell_activity,
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_dc_powershell_activity(
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


def handle_ad_account_change_history_api(
    handler, query: dict[str, list[str]], *, get_ad_account_change_history,
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_ad_account_change_history(
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


def handle_ad_account_change_sources_api(handler, *, get_ad_account_change_sources) -> None:
    handler._send_json(get_ad_account_change_sources(handler._access_decision()))


_SECURITY_EVENT_FILTERS = {
    "domain_id", "time_from", "time_to", "timezone", "limit", "cursor",
    "category", "event_id", "event_db_id", "entity_id", "outcome", "actor", "target", "group", "source", "q",
}


def _security_event_arguments(query: dict[str, list[str]], *, export: bool = False) -> dict:
    allowed = _SECURITY_EVENT_FILTERS - ({"cursor", "limit"} if export else set())
    if any(key not in allowed for key in query):
        raise ValueError("unknown_security_events_filter")
    first = lambda name, default=None: (query.get(name) or [default])[0]
    return {
        "source_domain_id": int(first("domain_id", "0") or 0),
        "time_from": first("time_from"),
        "time_to": first("time_to"),
        "timezone_name": str(first("timezone", "UTC") or "UTC"),
        "limit": 500 if export else int(first("limit", "200") or 200),
        "cursor": None if export else first("cursor"),
        "category": first("category"),
        "event_id": int(first("event_id")) if first("event_id") not in (None, "") else None,
        "event_db_id": first("event_db_id"),
        "entity_id": first("entity_id"),
        "outcome": first("outcome"),
        "actor": first("actor"),
        "target_account": first("target"),
        "group": first("group"),
        "source_host": first("source"),
        "q": first("q"),
    }


def handle_security_event_sources_api(handler, *, get_security_event_sources) -> None:
    handler._send_json(get_security_event_sources(handler._access_decision()))


def handle_security_events_api(handler, query: dict[str, list[str]], *, get_security_events_report) -> None:
    try:
        payload = get_security_events_report(
            handler._access_decision(), **_security_event_arguments(query)
        )
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    handler._send_json(payload)


def handle_security_events_export_api(handler, query: dict[str, list[str]], *, get_security_events_report, render_security_events_csv) -> None:
    try:
        payload = get_security_events_report(
            handler._access_decision(),
            **_security_event_arguments(query, export=True),
            action="export",
        )
        if payload.get("state") == "not_authorized":
            handler._send_json({"error": "security_events_export_not_authorized"}, HTTPStatus.FORBIDDEN)
            return
        body = render_security_events_csv(payload).encode("utf-8-sig")
    except TimeRangeError as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    except (TypeError, ValueError) as exc:
        handler._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return
    row_count = len(payload.get("items") or [])
    truncated = bool(payload.get("has_more"))
    suffix = f"INCOMPLETE-first-{row_count}-rows" if truncated else f"complete-{row_count}-rows"
    handler.send_response(HTTPStatus.OK)
    handler.send_header("Content-Type", "text/csv; charset=utf-8")
    handler.send_header("Content-Disposition", f'attachment; filename="sli-security-events-{suffix}.csv"')
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("X-Sli-Export-Truncated", "true" if truncated else "false")
    handler.send_header("X-Sli-Export-Rows", str(row_count))
    handler.end_headers()
    handler.wfile.write(body)


def handle_ad_group_membership_history_api(
    handler, query: dict[str, list[str]], *, get_ad_group_membership_history,
) -> None:
    first = lambda name, default=None: (query.get(name) or [default])[0]
    try:
        payload = get_ad_group_membership_history(
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

