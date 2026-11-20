from __future__ import annotations

"""Pure session folding for exact RADIUS Accounting observations.

The module neither reads PostgreSQL nor acknowledges outbox deliveries.  It
does not classify an unclosed session as currently active: freshness and risk
windows require a separate owner-approved policy.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from typing import Iterable


CONTRACT_ID = "sli.radius-session-read-model.v1"
_LIFECYCLE_EVENTS = frozenset({"start", "interim_update", "stop"})


class RadiusSessionReadModelError(ValueError):
    """Fail-closed contract error safe for aggregate diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusLifecycleInput:
    observation_id: str
    lifecycle_event: str
    identity_state: str
    timestamp_state: str
    session_identity_key: str | None = field(repr=False)
    exact_principal_key: str | None = field(repr=False)
    observed_at_utc: datetime | str | None
    evidence_sha256: str | None = None


@dataclass(frozen=True)
class RadiusSessionRow:
    session_row_id: str
    session_identity_key: str = field(repr=False)
    exact_principal_key: str = field(repr=False)
    generation: int
    lifecycle_state: str
    completeness: str
    started_at_utc: datetime | None
    last_observed_at_utc: datetime
    stopped_at_utc: datetime | None
    duration_seconds: int | None
    observation_count: int
    anomalies: tuple[str, ...]
    observation_ids: tuple[str, ...] = ()
    evidence_sha256s: tuple[str, ...] = ()


@dataclass(frozen=True)
class RadiusSessionFoldResult:
    contract_id: str
    sessions: tuple[RadiusSessionRow, ...]
    input_observations: int
    exact_ready_observations: int
    unresolved_identity_observations: int
    unresolved_timestamp_observations: int
    complete_sessions: int
    partial_sessions: int
    open_observed_sessions: int


@dataclass
class _MutableSession:
    session_identity_key: str
    exact_principal_key: str
    generation: int
    observation_ids: list[str]
    evidence_sha256s: list[str]
    events: list[tuple[datetime, str]]
    has_start: bool = False
    has_stop: bool = False
    anomalies: set[str] = field(default_factory=set)


def fold_radius_sessions(
    observations: Iterable[RadiusLifecycleInput],
) -> RadiusSessionFoldResult:
    """Fold exact, timestamped lifecycle facts without inventing state."""

    values = tuple(observations)
    seen: set[str] = set()
    grouped: dict[
        str, list[tuple[datetime, RadiusLifecycleInput]]
    ] = {}
    principal_by_session: dict[str, str] = {}
    unresolved_identity = 0
    unresolved_timestamp = 0
    exact_ready = 0

    for item in values:
        observation_id = _token(item.observation_id, "observation_id")
        if observation_id in seen:
            raise RadiusSessionReadModelError(
                "duplicate_observation_id"
            )
        seen.add(observation_id)
        event = str(item.lifecycle_event or "").strip()
        if event not in _LIFECYCLE_EVENTS:
            raise RadiusSessionReadModelError("lifecycle_event_invalid")
        identity_state = str(item.identity_state or "").strip()
        timestamp_state = str(item.timestamp_state or "").strip()
        if identity_state not in {"exact", "unresolved"}:
            raise RadiusSessionReadModelError("identity_state_invalid")
        if timestamp_state not in {"ready", "unresolved"}:
            raise RadiusSessionReadModelError("timestamp_state_invalid")
        session_key = str(item.session_identity_key or "").strip() or None
        principal_key = str(item.exact_principal_key or "").strip() or None
        if identity_state == "unresolved":
            if session_key is not None or principal_key is not None:
                raise RadiusSessionReadModelError(
                    "unresolved_identity_has_exact_keys"
                )
            unresolved_identity += 1
            continue
        if session_key is None or principal_key is None:
            raise RadiusSessionReadModelError(
                "exact_identity_keys_required"
            )
        if not session_key.startswith("radius-session:"):
            raise RadiusSessionReadModelError(
                "session_identity_key_invalid"
            )
        evidence_sha256 = str(item.evidence_sha256 or "").strip().lower()
        if not evidence_sha256:
            raise RadiusSessionReadModelError("evidence_sha256_required")
        if (
            len(evidence_sha256) != 64
            or any(character not in "0123456789abcdef" for character in evidence_sha256)
        ):
            raise RadiusSessionReadModelError("evidence_sha256_invalid")
        if timestamp_state == "unresolved":
            if item.observed_at_utc is not None:
                raise RadiusSessionReadModelError(
                    "unresolved_timestamp_has_value"
                )
            unresolved_timestamp += 1
            continue
        observed_at = _utc(item.observed_at_utc)
        previous_principal = principal_by_session.setdefault(
            session_key, principal_key
        )
        if previous_principal != principal_key:
            raise RadiusSessionReadModelError(
                "session_key_principal_conflict"
            )
        grouped.setdefault(session_key, []).append(
            (observed_at, item)
        )
        exact_ready += 1

    rows: list[RadiusSessionRow] = []
    for session_key in sorted(grouped):
        ordered = sorted(
            grouped[session_key],
            key=lambda pair: (
                pair[0],
                str(pair[1].observation_id),
            ),
        )
        current: _MutableSession | None = None
        generation = 0
        principal_key = principal_by_session[session_key]
        for observed_at, item in ordered:
            event = item.lifecycle_event
            if event == "start":
                if current is not None:
                    current.anomalies.add("start_before_stop")
                    rows.append(_finish(current))
                generation += 1
                current = _new_session(
                    session_key=session_key,
                    principal_key=principal_key,
                    generation=generation,
                    observation_id=item.observation_id,
                    evidence_sha256=str(item.evidence_sha256 or "").strip().lower(),
                    observed_at=observed_at,
                    event="start",
                )
                continue
            if current is None:
                generation += 1
                current = _new_session(
                    session_key=session_key,
                    principal_key=principal_key,
                    generation=generation,
                    observation_id=item.observation_id,
                    evidence_sha256=str(item.evidence_sha256 or "").strip().lower(),
                    observed_at=observed_at,
                    event=event,
                )
            else:
                current.observation_ids.append(item.observation_id)
                evidence_sha256 = str(item.evidence_sha256 or "").strip().lower()
                if evidence_sha256:
                    current.evidence_sha256s.append(evidence_sha256)
                current.events.append((observed_at, event))
            if event == "stop":
                current.has_stop = True
                rows.append(_finish(current))
                current = None
        if current is not None:
            rows.append(_finish(current))

    result_rows = tuple(sorted(
        rows,
        key=lambda row: (
            row.last_observed_at_utc,
            row.session_row_id,
        ),
        reverse=True,
    ))
    return RadiusSessionFoldResult(
        contract_id=CONTRACT_ID,
        sessions=result_rows,
        input_observations=len(values),
        exact_ready_observations=exact_ready,
        unresolved_identity_observations=unresolved_identity,
        unresolved_timestamp_observations=unresolved_timestamp,
        complete_sessions=sum(
            row.completeness == "complete" for row in result_rows
        ),
        partial_sessions=sum(
            row.completeness != "complete" for row in result_rows
        ),
        open_observed_sessions=sum(
            row.lifecycle_state in {"open_observed", "partial_open"}
            for row in result_rows
        ),
    )


def _new_session(
    *,
    session_key: str,
    principal_key: str,
    generation: int,
    observation_id: str,
    evidence_sha256: str,
    observed_at: datetime,
    event: str,
) -> _MutableSession:
    return _MutableSession(
        session_identity_key=session_key,
        exact_principal_key=principal_key,
        generation=generation,
        observation_ids=[observation_id],
        evidence_sha256s=[evidence_sha256] if evidence_sha256 else [],
        events=[(observed_at, event)],
        has_start=event == "start",
    )


def _finish(current: _MutableSession) -> RadiusSessionRow:
    first_at = current.events[0][0]
    last_at = current.events[-1][0]
    started_at = (
        next(
            observed_at
            for observed_at, event in current.events
            if event == "start"
        )
        if current.has_start
        else None
    )
    stopped_at = (
        next(
            observed_at
            for observed_at, event in reversed(current.events)
            if event == "stop"
        )
        if current.has_stop
        else None
    )
    if current.has_start and current.has_stop:
        completeness = "complete"
        lifecycle_state = "closed"
    elif current.has_stop:
        completeness = "missing_start"
        lifecycle_state = "partial_closed"
    elif current.has_start:
        completeness = "missing_stop"
        lifecycle_state = "open_observed"
    else:
        completeness = "middle_only"
        lifecycle_state = "partial_open"
    duration = (
        int((stopped_at - started_at).total_seconds())
        if started_at is not None and stopped_at is not None
        else None
    )
    if duration is not None and duration < 0:
        raise RadiusSessionReadModelError("negative_session_duration")
    material = (
        f"{current.session_identity_key}\0"
        f"{current.generation}\0{current.observation_ids[0]}"
    ).encode("utf-8")
    return RadiusSessionRow(
        session_row_id=(
            f"radius-session-row:{sha256(material).hexdigest()}"
        ),
        session_identity_key=current.session_identity_key,
        exact_principal_key=current.exact_principal_key,
        generation=current.generation,
        lifecycle_state=lifecycle_state,
        completeness=completeness,
        started_at_utc=started_at,
        last_observed_at_utc=last_at if current.events else first_at,
        stopped_at_utc=stopped_at,
        duration_seconds=duration,
        observation_count=len(current.observation_ids),
        anomalies=tuple(sorted(current.anomalies)),
        observation_ids=tuple(current.observation_ids),
        evidence_sha256s=tuple(current.evidence_sha256s),
    )


def _utc(value: datetime | str | None) -> datetime:
    if value is None:
        raise RadiusSessionReadModelError(
            "ready_timestamp_value_required"
        )
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            )
        )
    except ValueError as exc:
        raise RadiusSessionReadModelError(
            "observed_at_utc_invalid"
        ) from exc
    if parsed.tzinfo is None:
        raise RadiusSessionReadModelError(
            "observed_at_utc_timezone_required"
        )
    return parsed.astimezone(timezone.utc)


def _token(value: str, field_name: str) -> str:
    token = str(value or "").strip()
    if not token or len(token) > 256:
        raise RadiusSessionReadModelError(f"{field_name}_invalid")
    return token
