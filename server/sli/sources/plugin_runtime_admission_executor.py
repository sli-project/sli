"""Exact database calls for disabled Stage 10 component admission leases."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterator
from uuid import UUID, uuid4

from server.sli.sources.plugin_runtime_admission import (
    ACQUISITION,
    CONSUMER,
    PluginRuntimeAdmissionError,
)


LEASE_KIND = {
    ACQUISITION: "source_contact",
    CONSUMER: "delivery_claim",
}
COMPONENT_ROLE = {
    ACQUISITION: "adlog_radius_accounting_worker",
    CONSUMER: "adlog_radius_session_consumer",
}


@dataclass(frozen=True)
class PluginComponentLease:
    lease_uid: UUID
    component_id: str
    admission_mode: str
    expires_at_utc: datetime


def acquire_component_lease(
    conn: Any,
    *,
    lease_uid: UUID,
    component_id: str,
    holder_key: str,
    activate_role: bool = True,
) -> PluginComponentLease:
    if component_id not in LEASE_KIND or not str(holder_key).strip():
        raise PluginRuntimeAdmissionError("component_lease_request_invalid")
    with conn.cursor() as cur:
        if activate_role:
            cur.execute(f"set local role {COMPONENT_ROLE[component_id]}")
        cur.execute(
            """
            select lease_uid,component_id,admission_mode,expires_at_utc
            from acquire_plugin_component_lease_v1(%s,%s,%s,%s,%s)
            """,
            (
                lease_uid,
                "sli.remote-access",
                component_id,
                LEASE_KIND[component_id],
                str(holder_key),
            ),
        )
        row = cur.fetchone()
    if row is None:
        raise PluginRuntimeAdmissionError("component_lease_result_missing")
    result = PluginComponentLease(
        lease_uid=UUID(str(row[0])),
        component_id=str(row[1]),
        admission_mode=str(row[2]),
        expires_at_utc=row[3],
    )
    expected_mode = "open" if component_id == ACQUISITION else {
        "open",
        "drain_only",
    }
    if (
        result.lease_uid != lease_uid
        or result.component_id != component_id
        or (
            result.admission_mode != expected_mode
            if isinstance(expected_mode, str)
            else result.admission_mode not in expected_mode
        )
        or not isinstance(result.expires_at_utc, datetime)
        or result.expires_at_utc.tzinfo is None
    ):
        raise PluginRuntimeAdmissionError("component_lease_result_invalid")
    return result


def release_component_lease(
    conn: Any,
    *,
    lease: PluginComponentLease,
    holder_key: str,
    outcome: str,
    activate_role: bool = True,
) -> bool:
    if outcome not in {"completed", "failed", "cancelled"}:
        raise PluginRuntimeAdmissionError("component_lease_outcome_invalid")
    with conn.cursor() as cur:
        if activate_role:
            cur.execute(f"set local role {COMPONENT_ROLE[lease.component_id]}")
        cur.execute(
            "select release_plugin_component_lease_v1(%s,%s,%s)",
            (lease.lease_uid, str(holder_key), outcome),
        )
        row = cur.fetchone()
    if row is None or not isinstance(row[0], bool):
        raise PluginRuntimeAdmissionError("component_lease_release_invalid")
    return bool(row[0])


@contextmanager
def component_lease_scope(
    conn: Any,
    *,
    component_id: str,
    holder_key: str,
    lease_uid: UUID | None = None,
) -> Iterator[PluginComponentLease]:
    """Commit admission before work and always publish a terminal outcome."""
    lease = acquire_component_lease(
        conn,
        lease_uid=lease_uid or uuid4(),
        component_id=component_id,
        holder_key=holder_key,
    )
    conn.commit()
    try:
        yield lease
    except BaseException:
        conn.rollback()
        release_component_lease(
            conn,
            lease=lease,
            holder_key=holder_key,
            outcome="failed",
        )
        conn.commit()
        raise
    else:
        release_component_lease(
            conn,
            lease=lease,
            holder_key=holder_key,
            outcome="completed",
        )
        conn.commit()
