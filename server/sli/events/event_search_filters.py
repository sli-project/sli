from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from server.sli.core.time_contract import normalize_utc_range
from server.sli.reporting.reporting_common import (
    clean_int_list,
)
from server.sli.semantic.event_semantic_contract import normalize_category

DEFAULT_SEARCH_LIMIT = 200


MAX_SEARCH_LIMIT = 1000


DEFAULT_SEARCH_WINDOW_HOURS = 24


DEFAULT_DEEP_WINDOW_HOURS = 1


VALID_SORT_ORDERS = {"desc", "asc"}


def normalize_search_filters(
    *,
    q: str | None = None,
    account: str | None = None,
    event_id: int | str | None = None,
    event_ids: list[int | str] | None = None,
    channel: str | None = None,
    provider: str | None = None,
    subject: str | None = None,
    target: str | None = None,
    servers: list[str] | None = None,
    limit: int | None = None,
    offset: int | None = None,
    cursor: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    order: str | None = None,
    risk: str | None = None,
    tier: str | None = None,
    category: str | None = None,
    timezone_name: str | None = "UTC",
    default_window_hours: int = DEFAULT_SEARCH_WINDOW_HOURS,
) -> dict[str, Any]:
    clean_event_ids = _clean_int_list(event_ids or [])
    if event_id not in (None, ""):
        clean_event_ids.extend(_clean_int_list([event_id]))
    clean_servers = []
    for server in servers or []:
        value = str(server or "").strip()
        if value and value not in clean_servers:
            clean_servers.append(value)
    clean_limit = DEFAULT_SEARCH_LIMIT if limit is None else int(limit)
    clean_limit = max(1, min(clean_limit, MAX_SEARCH_LIMIT))
    clean_order = str(order or "desc").lower().strip()
    if clean_order not in VALID_SORT_ORDERS:
        clean_order = "desc"
    clean_from, clean_to = normalize_utc_range(time_from, time_to, timezone_name=timezone_name)
    default_window_applied = False
    if not clean_from and not clean_to:
        # Exact fast search is index-backed.  Restricting an operator's account,
        # IP, LogonId or Event ID query to an invisible 24-hour window makes old
        # but retained evidence look as though it does not exist.
        if default_window_hours != DEFAULT_SEARCH_WINDOW_HOURS or not (str(q or "").strip() or str(account or "").strip()):
            clean_from = _default_time_from(default_window_hours)
            default_window_applied = True
    decoded_cursor = decode_search_cursor(cursor)
    clean_category = str(category or "").strip().lower()
    return {
        "q": str(q or "").strip() or None,
        "account": str(account or "").strip() or None,
        "event_ids": _unique_ints(clean_event_ids),
        "channel": str(channel or "").strip() or None,
        "provider": str(provider or "").strip() or None,
        "subject": str(subject or "").strip() or None,
        "target": str(target or "").strip() or None,
        "servers": clean_servers,
        "limit": clean_limit,
        "offset": max(0, int(offset or 0)),
        "offset_ignored": max(0, int(offset or 0)) > 0,
        "cursor": str(cursor or "").strip() or None,
        "cursor_values": decoded_cursor,
        "time_from": clean_from,
        "time_to": clean_to,
        "order": clean_order,
        "risk": str(risk or "").strip().lower() or None,
        "tier": str(tier or "").strip().lower() or None,
        "category": normalize_category(clean_category, known=False) if clean_category else None,
        "timezone": str(timezone_name or "UTC"),
        "default_window_hours": int(default_window_hours),
        "default_window_applied": default_window_applied,
    }


def _default_time_from(hours: int) -> str:
    value = datetime.now(timezone.utc) - timedelta(hours=max(1, int(hours)))
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _datetime_local_input_value(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return parsed.astimezone().strftime("%Y-%m-%dT%H:%M")


def encode_search_cursor(row: dict[str, Any]) -> str | None:
    if not row:
        return None
    payload = {
        "time": _cursor_scalar(row.get("time_created_utc")),
        "record": int(row["event_record_id"]) if row.get("event_record_id") is not None else -1,
        "id": int(row.get("id") or 0),
    }
    if not payload["time"] or payload["id"] <= 0:
        return None
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_search_cursor(value: str | None) -> dict[str, Any] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        time_value = str(payload.get("time") or "").strip()
        row_id = int(payload.get("id") or 0)
        record_id = int(payload["record"]) if payload.get("record") is not None else -1
        if not time_value or row_id <= 0:
            return None
        return {"time": time_value, "record": record_id, "id": row_id}
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _cursor_scalar(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value or "").strip()


def make_search_url(**filters: Any) -> str:
    clean = normalize_search_filters(**filters)
    params: dict[str, Any] = {"limit": clean["limit"], "order": clean["order"]}
    for key in ("q", "account", "channel", "time_from", "time_to", "cursor", "risk", "tier"):
        if clean.get(key):
            params[key] = clean[key]
    if clean["event_ids"]:
        params["event_id"] = ",".join(str(value) for value in clean["event_ids"])
    if clean["servers"]:
        params["server"] = ",".join(clean["servers"])
    return "/reports/search.html?" + urlencode(params)


def make_deep_search_url(**filters: Any) -> str:
    clean = normalize_search_filters(default_window_hours=DEFAULT_DEEP_WINDOW_HOURS, **filters)
    params: dict[str, Any] = {"limit": min(clean["limit"], 200), "order": clean["order"]}
    for key in ("q", "account", "channel", "time_from", "time_to", "cursor", "risk", "tier"):
        if clean.get(key):
            params[key] = clean[key]
    if clean["event_ids"]:
        params["event_id"] = ",".join(str(value) for value in clean["event_ids"])
    if clean["servers"]:
        params["server"] = ",".join(clean["servers"])
    return "/reports/search-deep.html?" + urlencode(params)


def make_account_timeline_url(account: str, **filters: Any) -> str:
    clean = normalize_search_filters(
        account=account,
        q=filters.get("q"),
        limit=filters.get("limit", 500),
        order=filters.get("order", "desc"),
        time_from=filters.get("time_from"),
        time_to=filters.get("time_to"),
        servers=filters.get("servers"),
        channel=filters.get("channel"),
        cursor=filters.get("cursor"),
    )
    params: dict[str, Any] = {"q": account, "limit": clean["limit"], "order": clean["order"]}
    for key in ("time_from", "time_to", "cursor"):
        if clean.get(key):
            params[key] = clean[key]
    if clean["servers"]:
        params["server"] = ",".join(clean["servers"])
    return "/reports/account-timeline.html?" + urlencode(params)


def _unique_ints(values: list[int]) -> list[int]:
    output: list[int] = []
    for value in values:
        if value not in output:
            output.append(value)
    return output


_clean_int_list = clean_int_list
