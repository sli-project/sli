from __future__ import annotations

"""Exact, bounded RADIUS Accounting sessions for one preflighted entity.

This owner deliberately accepts the entity's canonical ID and its domain only
from the caller that already performed the trusted entity resource preflight.
It does not resolve names, poll a source, mutate a cursor, or turn Accounting
observations into Windows events.
"""

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.reporting.reporting_common import format_iso, get_runtime_connection
from server.sli.plugins.remote_access.reports.vpn_report_composition import vpn_report_composition_decision


CONTRACT_ID = "sli.entity-vpn-sessions.v1"
MAX_PERIOD_DAYS = 31
DEFAULT_LIMIT = 50
MAX_LIMIT = 100


def get_entity_vpn_sessions(
    access: Mapping[str, Any],
    *,
    entity_id: int,
    trusted_domain_id: int,
    time_from_utc: str,
    time_to_utc_exclusive: str,
    limit: int = DEFAULT_LIMIT,
) -> dict[str, Any]:
    """Read an exact entity's projected Accounting sessions.

    ``trusted_domain_id`` must come from the entity resource preflight, never
    an untrusted card/query parameter.  The function evaluates all VPN access
    branches before opening a database connection.
    """

    clean_entity_id = _positive_int(entity_id, "entity_vpn_entity_invalid")
    domain_id = _positive_int(trusted_domain_id, "entity_vpn_domain_invalid")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= MAX_LIMIT:
        raise ValueError("entity_vpn_limit_invalid")
    period_start = _utc_bound(time_from_utc)
    period_end = _utc_bound(time_to_utc_exclusive)
    if period_start >= period_end:
        raise ValueError("entity_vpn_time_range_invalid")
    if period_end - period_start > timedelta(days=MAX_PERIOD_DAYS):
        raise ValueError("entity_vpn_period_too_wide")

    composition = vpn_report_composition_decision(
        access,
        source_domain_id=domain_id,
        action="view",
    )
    branches = {
        "sessions": asdict(composition.sessions),
        "session_evidence": asdict(composition.session_evidence),
    }
    time_range = {
        "from_utc": _iso(period_start),
        "to_utc_exclusive": _iso(period_end),
    }
    base = {
        "contract_id": CONTRACT_ID,
        "entity_id": clean_entity_id,
        "source_domain_id": domain_id,
        "branches": branches,
        "time_range": time_range,
        "limits": {"items": clean_limit, "max_items": MAX_LIMIT, "bounded": True},
    }
    if not composition.sessions.allowed:
        return {
            **base,
            "state": "not_authorized",
            "items": [],
            "has_more": False,
        }

    rows = _read_entity_session_rows(
        entity_id=clean_entity_id,
        domain_id=domain_id,
        period_start=period_start,
        period_end=period_end,
        limit=clean_limit,
    )
    items = [
        _public_session(
            row,
            entity_id=clean_entity_id,
            domain_id=domain_id,
            evidence_allowed=composition.session_evidence.allowed,
        )
        for row in rows[:clean_limit]
    ]
    return {
        **base,
        "state": "available",
        "items": items,
        "has_more": len(rows) > clean_limit,
    }


def _read_entity_session_rows(
    *,
    entity_id: int,
    domain_id: int,
    period_start: datetime,
    period_end: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    """Read only the existing security-barrier session projection."""

    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction isolation level repeatable read, read only")
        cur.execute(
            """
            select session_row_id,entity_id,domain_id,generation,
                   lifecycle_state,completeness,started_at_utc,
                   last_observed_at_utc,stopped_at_utc,duration_seconds,
                   observation_count,anomalies,updated_at
            from radius_vpn_session_rows_v1
            where entity_id=%s and domain_id=%s
              and last_observed_at_utc>=%s and last_observed_at_utc<%s
            order by last_observed_at_utc desc,session_row_id desc
            limit %s
            """,
            (entity_id, domain_id, period_start, period_end, limit + 1),
        )
        return [dict(row) for row in cur.fetchall()]


def _public_session(
    row: Mapping[str, Any],
    *,
    entity_id: int,
    domain_id: int,
    evidence_allowed: bool,
) -> dict[str, Any]:
    """Publish source facts; a session is never represented as a Windows event."""

    if int(row.get("entity_id") or 0) != entity_id or int(row.get("domain_id") or 0) != domain_id:
        raise ValueError("entity_vpn_row_identity_mismatch")
    session_row_id = str(row.get("session_row_id") or "").strip()
    if not session_row_id:
        raise ValueError("entity_vpn_session_identity_invalid")
    return {
        "session_row_id": session_row_id,
        "entity_id": entity_id,
        "source_domain_id": domain_id,
        "generation": int(row.get("generation") or 0),
        "lifecycle_state": str(row.get("lifecycle_state") or "unknown"),
        "completeness": str(row.get("completeness") or "unknown"),
        "started_at_utc": _nullable_iso(row.get("started_at_utc")),
        "last_observed_at_utc": _nullable_iso(row.get("last_observed_at_utc")),
        "stopped_at_utc": _nullable_iso(row.get("stopped_at_utc")),
        "duration_seconds": _nullable_int(row.get("duration_seconds")),
        "observation_count": int(row.get("observation_count") or 0),
        "anomalies": list(row.get("anomalies") or ()),
        "updated_at": _nullable_iso(row.get("updated_at")),
        "evidence_ref": (
            {
                "kind": "vpn_accounting_session",
                "source_domain_id": domain_id,
                "session_row_id": session_row_id,
            }
            if evidence_allowed else {"state": "not_authorized"}
        ),
    }


def _positive_int(value: int, error: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(error) from exc
    if result <= 0:
        raise ValueError(error)
    return result


def _utc_bound(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("entity_vpn_time_range_invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("entity_vpn_time_range_invalid")
    return parsed.astimezone(timezone.utc)


def _nullable_int(value: Any) -> int | None:
    return int(value) if value is not None else None


def _nullable_iso(value: Any) -> str | None:
    if value is None:
        return None
    return _iso(_utc_bound(str(value)))


_iso = format_iso
_connect = get_runtime_connection
