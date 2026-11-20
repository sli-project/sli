from __future__ import annotations

"""Bounded read service for the RADIUS branch of the existing VPN report."""

from dataclasses import asdict
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Sequence

from server.sli.reporting.reporting_common import get_runtime_connection
from server.sli.core.time_contract import normalize_utc_range
from server.sli.plugins.remote_access.reports.vpn_report_composition import (
    vpn_report_composition_decision,
)
from server.source_packs.radius.session_read_model import (
    RadiusLifecycleInput,
    RadiusSessionRow,
    fold_radius_sessions,
)


CONTRACT_ID = "sli.vpn-session-report.v1"
SESSION_EVIDENCE_CONTRACT_ID = "sli.vpn-session-evidence.v1"
DEFAULT_LIMIT = 50
MAXIMUM_LIMIT = 200
DISCOVERY_BATCH_LIMIT = 256
DISCOVERY_SCAN_LIMIT = 10_000
MAX_SESSION_EVIDENCE_OBSERVATIONS = 10_000
_SESSION_ROW_ID = re.compile(r"^radius-session-row:[0-9a-f]{64}$")


def get_vpn_session_sources(access: Mapping[str, Any]) -> dict[str, Any]:
    """Discover only registered domains the caller may read."""

    registered_count = 0
    authorized: list[dict[str, int]] = []
    after_domain_id = 0
    while len(authorized) <= 100:
        registered = _read_session_source_domain_batch(
            after_domain_id=after_domain_id,
            limit=DISCOVERY_BATCH_LIMIT,
        )
        if not registered:
            break
        registered_count += len(registered)
        if registered_count > DISCOVERY_SCAN_LIMIT:
            raise ValueError("vpn_session_source_discovery_scan_limit")
        for domain_id in registered:
            if vpn_report_composition_decision(
                access,
                source_domain_id=domain_id,
                action="view",
            ).sessions.allowed:
                authorized.append({"source_domain_id": domain_id})
        after_domain_id = registered[-1]
        if len(registered) < DISCOVERY_BATCH_LIMIT:
            break
    items = authorized[:100]
    has_session_access = bool(access.get("platform_owner")) or (
        "vpn.sessions.view" in (access.get("capabilities") or [])
    )
    return {
        "contract_id": CONTRACT_ID,
        "report_key": "vpn.audit",
        "state": (
            "available" if items
            else "not_collected" if registered_count == 0 and has_session_access
            else "not_authorized"
        ),
        "items": items,
        "bounded": True,
        "limit": 100,
        # Never derive pagination metadata from domains hidden by access.
        "has_more": len(authorized) > 100,
    }


def _read_session_source_domain_batch(
    *,
    after_domain_id: int,
    limit: int,
) -> list[int]:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """select domain_id
               from radius_vpn_session_coverage_v1
               where domain_id>%s
               order by domain_id
               limit %s""",
            (after_domain_id, limit),
        )
        return [int(row["domain_id"]) for row in cur.fetchall()]


def get_vpn_session_report(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    action: str = "view",
    time_from: str | None = None,
    time_to: str | None = None,
    timezone_name: str = "UTC",
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
) -> dict[str, Any]:
    """Return one domain-scoped branch without touching raw evidence."""

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_session_domain_invalid")
    clean_limit = int(limit)
    if not 1 <= clean_limit <= MAXIMUM_LIMIT:
        raise ValueError("vpn_session_limit_invalid")
    clean_offset = int(offset)
    if not 0 <= clean_offset <= 10000:
        raise ValueError("vpn_session_offset_invalid")
    start_utc, end_utc = normalize_utc_range(
        time_from,
        time_to,
        timezone_name=timezone_name,
    )
    composition = vpn_report_composition_decision(
        access,
        source_domain_id=domain_id,
        action=action,
    )
    branches = {
        "directory": asdict(composition.directory),
        "sessions": asdict(composition.sessions),
        "session_evidence": asdict(composition.session_evidence),
    }
    if not composition.sessions.allowed:
        return {
            "contract_id": CONTRACT_ID,
            "report_key": composition.report_key,
            "source_domain_id": domain_id,
            "state": "not_authorized",
            "branches": branches,
            "coverage": None,
            "items": [],
            "page": {
                "limit": clean_limit,
                "offset": clean_offset,
                "has_more": False,
            },
        }

    coverage, rows = _read_session_projection(
        domain_id=domain_id,
        start_utc=start_utc,
        end_utc=end_utc,
        limit=clean_limit,
        offset=clean_offset,
    )
    if coverage is None:
        raise ValueError("vpn_session_source_domain_not_registered")
    items = [_public_row(row) for row in rows[:clean_limit]]
    return {
        "contract_id": CONTRACT_ID,
        "report_key": composition.report_key,
        "source_domain_id": domain_id,
        "state": _coverage_state(coverage),
        "branches": branches,
        "coverage": _public_row(coverage),
        "items": items,
        "page": {
            "limit": clean_limit,
            "offset": clean_offset,
            "has_more": len(rows) > clean_limit,
        },
        "time_range": {
            "from_utc": start_utc,
            "to_utc_exclusive": end_utc,
            "timezone": timezone_name,
        },
    }


def get_vpn_session_evidence(
    access: Mapping[str, Any],
    *,
    source_domain_id: int,
    session_row_id: str,
) -> dict[str, Any]:
    """Return immutable manifest references for one exact Accounting session.

    The protected SQL view returns the candidate's delivered observations with
    effective overlay keys.  This service repeats the canonical Python fold
    and only then selects the requested row.  It therefore never associates
    evidence through a time-only rule.
    """

    domain_id = int(source_domain_id)
    if domain_id <= 0:
        raise ValueError("vpn_session_evidence_domain_invalid")
    clean_row_id = str(session_row_id or "").strip()
    if not _SESSION_ROW_ID.fullmatch(clean_row_id):
        raise ValueError("vpn_session_evidence_session_row_id_invalid")
    composition = vpn_report_composition_decision(
        access,
        source_domain_id=domain_id,
        action="view",
    )
    branch = asdict(composition.session_evidence)
    if not composition.session_evidence.allowed:
        return {
            "contract_id": SESSION_EVIDENCE_CONTRACT_ID,
            "report_key": composition.report_key,
            "source_domain_id": domain_id,
            "session_row_id": clean_row_id,
            "state": "not_authorized",
            "branch": branch,
            "lifecycle": None,
            "observations": [],
        }

    rows = _read_session_evidence_observations(
        domain_id=domain_id,
        session_row_id=clean_row_id,
        limit=MAX_SESSION_EVIDENCE_OBSERVATIONS,
    )
    if len(rows) > MAX_SESSION_EVIDENCE_OBSERVATIONS:
        raise ValueError("vpn_session_evidence_observation_bound_exceeded")
    target, observation_ids = _folded_session_evidence_membership(
        rows,
        session_row_id=clean_row_id,
    )
    if target is None:
        raise ValueError("vpn_session_evidence_session_not_found")
    by_id = {str(row["observation_id"]): row for row in rows}
    observations = [
        _public_evidence_observation(by_id[observation_id])
        for observation_id in observation_ids
    ]
    stop_evidence = [
        item["evidence"]
        for item in observations
        if item["lifecycle_event"] == "stop"
    ]
    return {
        "contract_id": SESSION_EVIDENCE_CONTRACT_ID,
        "report_key": composition.report_key,
        "source_domain_id": domain_id,
        "session_row_id": clean_row_id,
        "state": "available",
        "branch": branch,
        "lifecycle": {
            "lifecycle_state": target.lifecycle_state,
            "completeness": target.completeness,
            "started_at_utc": _iso(target.started_at_utc),
            "last_observed_at_utc": _iso(target.last_observed_at_utc),
            "stopped_at_utc": _iso(target.stopped_at_utc),
            "duration_seconds": target.duration_seconds,
            "observation_count": target.observation_count,
            "anomalies": list(target.anomalies),
            "stop_evidence": stop_evidence,
            "incomplete_reason": (
                target.completeness
                if target.completeness != "complete"
                else None
            ),
        },
        "observations": observations,
        "limits": {
            "observation_limit": MAX_SESSION_EVIDENCE_OBSERVATIONS,
            "bounded": True,
        },
    }
def _read_session_projection(
    *,
    domain_id: int,
    start_utc: str | None,
    end_utc: str | None,
    limit: int,
    offset: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    predicates = ["domain_id=%s"]
    params: list[Any] = [domain_id]
    if start_utc is not None:
        predicates.append("last_observed_at_utc>=%s")
        params.append(start_utc)
    if end_utc is not None:
        predicates.append("last_observed_at_utc<%s")
        params.append(end_utc)
    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """
            select domain_id,total_delivery_count,queued_delivery_count,
                   leased_delivery_count,failed_delivery_count,
                   delivered_delivery_count,quarantined_delivery_count,
                   projected_receipt_count,identity_unresolved_count,
                   timestamp_unresolved_count,projected_session_count,
                   history_available_from_utc,history_available_to_utc
            from radius_vpn_session_coverage_v1
            where domain_id=%s
            """,
            (domain_id,),
        )
        coverage_row = cur.fetchone()
        cur.execute(
            f"""
            select session_row_id,entity_id,domain_id,generation,
                   lifecycle_state,completeness,started_at_utc,
                   last_observed_at_utc,stopped_at_utc,duration_seconds,
                   observation_count,anomalies,updated_at
            from radius_vpn_session_rows_v1
            where {' and '.join(predicates)}
            order by last_observed_at_utc desc,session_row_id
            limit %s offset %s
            """,
            (*params, limit + 1, offset),
        )
        rows = [dict(row) for row in cur.fetchall()]
    return (
        dict(coverage_row) if coverage_row is not None else None,
        rows,
    )


def _read_session_evidence_observations(
    *,
    domain_id: int,
    session_row_id: str,
    limit: int,
) -> list[dict[str, Any]]:
    """Read only the protected candidate view, never its source tables."""

    with _connect() as conn, conn.cursor() as cur:
        cur.execute("set transaction read only")
        cur.execute(
            """select observation_id,lifecycle_event,identity_state,
                      timestamp_state,session_identity_key,
                      exact_principal_key,observed_at_utc,evidence_uid,
                      source_instance_id,stream_id,transport_binding,
                      object_reference,canonical_record_sha256,
                      object_sha256,object_size_bytes,verified_at_utc
               from radius_vpn_session_evidence_observations_v1
               where domain_id=%s and session_row_id=%s
               order by observed_at_utc,observation_id
               limit %s""",
            (domain_id, session_row_id, limit + 1),
        )
        return [dict(row) for row in cur.fetchall()]


def _folded_session_evidence_membership(
    rows: Sequence[Mapping[str, Any]],
    *,
    session_row_id: str,
) -> tuple[RadiusSessionRow | None, list[str]]:
    """Bind original observation IDs to canonical fold rows without heuristics.

    ``fold_radius_sessions`` remains the only producer of session identifiers
    and lifecycle results.  The small second pass only retains each ordered
    input's membership in the fold's already-produced ``(key, generation)``
    row; it performs no timestamp proximity correlation.
    """

    inputs = tuple(
        RadiusLifecycleInput(
            observation_id=str(row["observation_id"]),
            lifecycle_event=str(row["lifecycle_event"]),
            identity_state=str(row["identity_state"]),
            timestamp_state=str(row["timestamp_state"]),
            session_identity_key=(
                str(row["session_identity_key"])
                if row.get("session_identity_key") is not None
                else None
            ),
            exact_principal_key=(
                str(row["exact_principal_key"])
                if row.get("exact_principal_key") is not None
                else None
            ),
            observed_at_utc=row.get("observed_at_utc"),
            evidence_sha256=(
                str(row["canonical_record_sha256"])
                if row.get("canonical_record_sha256") is not None
                else None
            ),
        )
        for row in rows
    )
    folded = fold_radius_sessions(inputs)
    rows_by_key_generation = {
        (row.session_identity_key, row.generation): row
        for row in folded.sessions
    }
    memberships: dict[str, list[str]] = {}
    grouped: dict[str, list[RadiusLifecycleInput]] = {}
    for item in inputs:
        if item.identity_state == "exact" and item.timestamp_state == "ready":
            assert item.session_identity_key is not None
            grouped.setdefault(item.session_identity_key, []).append(item)

    for session_key, values in grouped.items():
        ordered = sorted(
            values,
            key=lambda item: (
                _as_utc(item.observed_at_utc),
                item.observation_id,
            ),
        )
        generation = 0
        current_generation: int | None = None
        current_ids: list[str] = []

        def finish_current() -> None:
            if current_generation is None:
                return
            canonical = rows_by_key_generation.get(
                (session_key, current_generation)
            )
            if canonical is not None:
                memberships[canonical.session_row_id] = list(current_ids)

        for item in ordered:
            if item.lifecycle_event == "start":
                finish_current()
                generation += 1
                current_generation = generation
                current_ids = [item.observation_id]
                continue
            if current_generation is None:
                generation += 1
                current_generation = generation
                current_ids = [item.observation_id]
            else:
                current_ids.append(item.observation_id)
            if item.lifecycle_event == "stop":
                finish_current()
                current_generation = None
                current_ids = []
        finish_current()

    target = next(
        (row for row in folded.sessions if row.session_row_id == session_row_id),
        None,
    )
    return target, memberships.get(session_row_id, [])


_connect = get_runtime_connection


def _coverage_state(coverage: Mapping[str, Any]) -> str:
    total = int(coverage.get("total_delivery_count") or 0)
    projected = int(coverage.get("projected_session_count") or 0)
    pending = sum(
        int(coverage.get(key) or 0)
        for key in (
            "queued_delivery_count",
            "leased_delivery_count",
            "failed_delivery_count",
        )
    )
    unresolved = (
        int(coverage.get("identity_unresolved_count") or 0)
        + int(coverage.get("timestamp_unresolved_count") or 0)
        + int(coverage.get("quarantined_delivery_count") or 0)
    )
    if total == 0:
        return "not_collected"
    if pending > 0:
        return "processing"
    if projected == 0 and unresolved > 0:
        return "identity_incomplete"
    if unresolved > 0:
        return "partial"
    return "available"


def _public_row(row: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in row.items():
        if isinstance(value, datetime):
            result[str(key)] = value.astimezone(timezone.utc).isoformat()
        elif isinstance(value, tuple):
            result[str(key)] = list(value)
        else:
            result[str(key)] = value
    return result


def _public_evidence_observation(row: Mapping[str, Any]) -> dict[str, Any]:
    """Keep raw accounting payload and effective identity keys out of the API."""

    return {
        "observation_id": str(row["observation_id"]),
        "lifecycle_event": str(row["lifecycle_event"]),
        "observed_at_utc": _iso(_as_utc(row.get("observed_at_utc"))),
        "evidence": {
            "evidence_uid": str(row["evidence_uid"]),
            "source_instance_id": str(row["source_instance_id"]),
            "stream_id": str(row["stream_id"]),
            "transport_binding": str(row["transport_binding"]),
            "object_reference": str(row["object_reference"]),
            "canonical_record_sha256": str(row["canonical_record_sha256"]),
            "object_sha256": str(row["object_sha256"]),
            "object_size_bytes": int(row["object_size_bytes"]),
            "verified_at_utc": _iso(_as_utc(row.get("verified_at_utc"))),
        },
    }


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("vpn_session_evidence_timestamp_invalid")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
