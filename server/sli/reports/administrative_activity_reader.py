"""Bounded, capability-aware reader for the immutable admin journal."""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Mapping

from server.sli.reports.administrative_activity import (
    AdministrativeActivityError,
    load_administrative_activity_contract,
)


CONTRACT_ID = "sli.administrative-activity-reader.v1"
CAPABILITY = "administrative.activity.view"
DEFAULT_LIMIT = 50
MAXIMUM_LIMIT = 200
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class AdministrativeActivityReaderUnavailable(RuntimeError):
    """The schema may exist, but runtime read has not been activated."""


def list_administrative_activity(
    access: Mapping[str, Any],
    *,
    before_activity_id: int | None = None,
    category: str | None = None,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Return one reverse-keyset page; denial never contacts PostgreSQL."""
    capabilities = {str(item) for item in access.get("capabilities", [])}
    if not bool(access.get("platform_owner")) and CAPABILITY not in capabilities:
        raise PermissionError("administrative_activity_access_denied")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= MAXIMUM_LIMIT:
        raise AdministrativeActivityError("administrative_activity_reader_limit_invalid")
    clean_before = None if before_activity_id is None else int(before_activity_id)
    if clean_before is not None and clean_before < 1:
        raise AdministrativeActivityError("administrative_activity_reader_cursor_invalid")
    clean_category = str(category).strip() if category is not None else None
    categories = set(load_administrative_activity_contract()["categories"])
    if clean_category == "":
        clean_category = None
    if clean_category is not None and clean_category not in categories:
        raise AdministrativeActivityError("administrative_activity_reader_category_invalid")
    contract = load_administrative_activity_contract()
    if contract["runtime_read_enabled"] is not True:
        raise AdministrativeActivityReaderUnavailable(
            "administrative_activity_reader_runtime_disabled"
        )

    rows = _read_rows(
        before_activity_id=clean_before,
        category=clean_category,
        limit=clean_limit + 1,
    )
    has_more = len(rows) > clean_limit
    items = [_public_row(row) for row in rows[:clean_limit]]
    return {
        "contract_id": CONTRACT_ID,
        "status": "ok",
        "items": items,
        "page": {
            "limit": clean_limit,
            "has_more": has_more,
            "next_before_activity_id": (
                items[-1]["activity_id"] if has_more and items else None
            ),
        },
        "filters": {"category": clean_category},
        "bounded": True,
        "contains_sensitive_details": False,
    }


def _read_rows(
    *, before_activity_id: int | None, category: str | None, limit: int
) -> list[dict[str, Any]]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select *
            from read_administrative_activity_v1(%s::bigint,%s::integer,%s::text)
            """,
            (before_activity_id, limit, category),
        )
        return [dict(row) for row in cur.fetchall()]


def _connect():
    from server.sli.core.postgres_runtime_pipeline import connect

    return connect()


def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    activity_id = int(result.get("activity_id") or 0)
    if activity_id < 1:
        raise AdministrativeActivityError("administrative_activity_reader_row_invalid")
    for key in ("content_hash_hex", "previous_record_hash_hex", "record_hash_hex"):
        value = str(result.get(key) or "")
        if HASH_RE.fullmatch(value) is None:
            raise AdministrativeActivityError("administrative_activity_reader_hash_invalid")
        result[key] = value
    for key in ("occurred_at_utc", "recorded_at_utc"):
        value = result.get(key)
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise AdministrativeActivityError("administrative_activity_reader_time_invalid")
        result[key] = value.astimezone(timezone.utc).isoformat()
    details = result.get("details_json")
    if not isinstance(details, Mapping):
        raise AdministrativeActivityError("administrative_activity_reader_details_invalid")
    result["details_json"] = dict(details)
    result["activity_id"] = activity_id
    for key in ("event_uid", "correlation_id", "remote_address"):
        if result.get(key) is not None:
            result[key] = str(result[key])
    return result
