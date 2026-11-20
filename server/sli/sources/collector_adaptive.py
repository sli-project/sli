from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from server.sli.storage.archive_state import DEFAULT_CHANNELS, utc_now
from server.sli.core.database import is_postgres_runtime_db
from server.sli.ops.logging_config import log_event

SECURITY_CHANNEL = "Security"
DNS_CHANNEL = "DNS Server"
RECOVERY_ON_LAG_MINUTES = int(os.environ.get("ADLOG_SECURITY_RECOVERY_LAG_MINUTES", "60"))
RECOVERY_OFF_LAG_MINUTES = int(os.environ.get("ADLOG_SECURITY_RECOVERY_EXIT_LAG_MINUTES", "15"))
COMPLETED_GROW_AFTER = int(os.environ.get("ADLOG_SECURITY_GROW_AFTER_COMPLETED", "1"))
SECURITY_FAST_RECOVERY = os.environ.get("ADLOG_SECURITY_RECOVERY_FAST", "true").strip().lower() not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


SECURITY_DEFAULT_LIMIT = _env_int("ADLOG_SECURITY_RECOVERY_START_LIMIT", _env_int("ADLOG_SECURITY_MAX_EVENTS", 20000 if SECURITY_FAST_RECOVERY else 500))
SECURITY_MIN_LIMIT = _env_int("ADLOG_SECURITY_MIN_EVENTS", 100)
SECURITY_MAX_LIMIT = _env_int("ADLOG_SECURITY_RECOVERY_MAX_LIMIT", _env_int("ADLOG_SECURITY_MAX_LIMIT", 50000 if SECURITY_FAST_RECOVERY else 5000))
SECURITY_TARGET_LIMIT = _env_int("ADLOG_SECURITY_RECOVERY_TARGET_LIMIT", SECURITY_MAX_LIMIT)
SECURITY_GROW_STEP = _env_int("ADLOG_SECURITY_GROW_STEP", 10000 if SECURITY_FAST_RECOVERY else 500)
SECURITY_GROW_FACTOR = max(1.0, float(os.environ.get("ADLOG_SECURITY_RECOVERY_RAMP_FACTOR", "2" if SECURITY_FAST_RECOVERY else "1")))
SECURITY_TIMEOUT_SECONDS = _env_int("ADLOG_SECURITY_TIMEOUT_SECONDS", 900)
DNS_MAX_EVENTS = _env_int("ADLOG_DNS_MAX_EVENTS", 200)
NON_SECURITY_MAX_EVENTS = _env_int("ADLOG_NON_SECURITY_MAX_EVENTS", 500)
NON_SECURITY_TIMEOUT_SECONDS = _env_int("ADLOG_CHANNEL_TIMEOUT_SECONDS", 300)
NON_SECURITY_RECOVERY_MAX_EVENTS = _env_int(
    "ADLOG_NON_SECURITY_RECOVERY_MAX_EVENTS", 50_000
)
NON_SECURITY_RECOVERY_GROW_STEP = _env_int(
    "ADLOG_NON_SECURITY_RECOVERY_GROW_STEP", 1_000
)
CHANNEL_FAIRNESS_ENABLED = os.environ.get("ADLOG_CHANNEL_FAIRNESS_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}
# The operations UI treats a channel check older than one hour as stale.
# Keep the recovery sampler on the same contract so secondary channels do not
# look broken for five hours while Security is catching up.
CHANNEL_FAIRNESS_STALE_MINUTES = _env_int("ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES", 60)
CHANNEL_FAIRNESS_MAX_EVENTS = _env_int("ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS", min(100, NON_SECURITY_MAX_EVENTS))
CHANNEL_FAIRNESS_TIMEOUT_SECONDS = _env_int("ADLOG_CHANNEL_FAIRNESS_TIMEOUT_SECONDS", min(120, NON_SECURITY_TIMEOUT_SECONDS))


@dataclass(frozen=True)
class AdaptivePlan:
    server: str
    channels: list[str]
    channel_limits: dict[str, int]
    channel_timeouts: dict[str, int]
    recovery_mode: bool
    security_limit: int
    reason: str
    fairness_channels: list[str] | None = None
    fairness_reason: str | None = None
    recovery_channels: list[str] | None = None


def get_adaptive_plan_for_server(server: str) -> AdaptivePlan:
    """Build the adaptive collection plan from the active runtime backend.

    Only PostgreSQL is supported; any other backend raises ``RuntimeError``.
    """
    if not is_postgres_runtime_db():
        raise RuntimeError("Adaptive collection plan is PostgreSQL-only: the SQLite runtime backend has been removed")
    from server.sli.core.postgres_runtime_pipeline import get_adaptive_plan_state_pg

    source = get_adaptive_plan_state_pg(
        server,
        channels=list(DEFAULT_CHANNELS),
        security_channel=SECURITY_CHANNEL,
        fairness_enabled=CHANNEL_FAIRNESS_ENABLED,
        fairness_stale_minutes=CHANNEL_FAIRNESS_STALE_MINUTES,
    )
    return _build_adaptive_plan(
        server=server,
        lag=source.get("security_lag_minutes"),
        state=source.get("adaptive_state"),
        fairness_channels=list(source.get("fairness_channels") or []),
        channel_states=dict(source.get("adaptive_states") or {}),
        backend_reason="postgres_runtime",
    )


def _state_value(state: Any, key: str, default: Any = None) -> Any:
    if state is None:
        return default
    try:
        value = state[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def _build_adaptive_plan(
    *,
    server: str,
    lag: int | None,
    state: Any,
    fairness_channels: list[str],
    channel_states: dict[str, Any],
    backend_reason: str,
) -> AdaptivePlan:
    configured_start = _bounded_limit(SECURITY_DEFAULT_LIMIT)
    current_limit = _bounded_limit(_state_value(state, "current_limit", configured_start))
    previous_recovery = bool(_state_value(state, "recovery_mode", False))

    recovery = previous_recovery
    reason = "normal"
    if lag is not None and lag > RECOVERY_ON_LAG_MINUTES:
        recovery = True
        reason = f"security_lag>{RECOVERY_ON_LAG_MINUTES}m"
    elif lag is not None and lag < RECOVERY_OFF_LAG_MINUTES:
        recovery = False
        reason = f"security_lag<{RECOVERY_OFF_LAG_MINUTES}m"
    # The start floor applies on entry, not on each recovery plan: timeout
    # transitions persist recovery_mode=True together with their reduced limit.
    if recovery and not previous_recovery and SECURITY_FAST_RECOVERY and configured_start > current_limit:
        current_limit = configured_start
        reason += ";fast_recovery_start_limit"

    security_recovery = recovery
    recovery_channels = [
        channel
        for channel in DEFAULT_CHANNELS
        if channel != SECURITY_CHANNEL
        and bool(_state_value(channel_states.get(channel), "recovery_mode", False))
    ]
    recovery = bool(security_recovery or recovery_channels)
    fairness_reason: str | None = None
    if security_recovery and fairness_channels:
        fairness_reason = f"stale_non_security_channels>{CHANNEL_FAIRNESS_STALE_MINUTES}m"
        reason += f";fairness_channels={len(fairness_channels)}"
    elif not security_recovery:
        fairness_channels = []
    if recovery_channels:
        reason += f";non_security_recovery={len(recovery_channels)}"

    reason += f";backend={backend_reason}"
    channels = [SECURITY_CHANNEL] if security_recovery else list(DEFAULT_CHANNELS)
    for channel in recovery_channels:
        if channel not in channels:
            channels.append(channel)
    for channel in fairness_channels:
        if channel not in channels:
            channels.append(channel)

    limits = {channel: NON_SECURITY_MAX_EVENTS for channel in channels}
    timeouts = {channel: NON_SECURITY_TIMEOUT_SECONDS for channel in channels}
    limits[SECURITY_CHANNEL] = current_limit
    timeouts[SECURITY_CHANNEL] = SECURITY_TIMEOUT_SECONDS
    if DNS_CHANNEL in limits:
        limits[DNS_CHANNEL] = DNS_MAX_EVENTS
    for channel in recovery_channels:
        limits[channel] = min(
            NON_SECURITY_RECOVERY_MAX_EVENTS,
            max(
                1,
                int(
                    _state_value(
                        channel_states.get(channel), "current_limit", NON_SECURITY_MAX_EVENTS
                    )
                ),
            ),
        )
    for channel in fairness_channels:
        if channel not in recovery_channels:
            limits[channel] = min(int(limits.get(channel) or NON_SECURITY_MAX_EVENTS), CHANNEL_FAIRNESS_MAX_EVENTS)
            timeouts[channel] = min(int(timeouts.get(channel) or NON_SECURITY_TIMEOUT_SECONDS), CHANNEL_FAIRNESS_TIMEOUT_SECONDS)

    return AdaptivePlan(
        server=server,
        channels=channels,
        channel_limits=limits,
        channel_timeouts=timeouts,
        recovery_mode=recovery,
        security_limit=current_limit,
        reason=reason,
        fairness_channels=fairness_channels,
        fairness_reason=fairness_reason,
        recovery_channels=recovery_channels,
    )


ADAPTIVE_STATE_MODES = {"update", "observe"}


def normalize_adaptive_state_mode(value: str | None) -> str:
    clean = str(value or "update").strip().lower()
    if clean not in ADAPTIVE_STATE_MODES:
        raise ValueError(f"Unsupported adaptive state mode: {value!r}")
    return clean


def adaptive_observation_action(mode: str) -> str:
    return f"{normalize_adaptive_state_mode(mode)}_only:state_unchanged"


def log_security_adaptive_observation(
    *,
    server: str,
    status: str,
    inserted: int,
    skipped: int,
    lag_minutes: int | None,
    limit_used: int | None,
    mode: str,
) -> None:
    log_event(
        "collector",
        "adaptive_security_observation",
        "Security collector run recorded without mutating adaptive state.",
        server=server,
        channel=SECURITY_CHANNEL,
        status=status,
        inserted=inserted,
        skipped=skipped,
        lag_minutes=lag_minutes,
        limit_used=limit_used,
        adaptive_state_mode=normalize_adaptive_state_mode(mode),
        adaptive_state_changed=False,
    )


def compute_security_adaptive_transition(
    *,
    state: Any,
    status: str,
    inserted: int,
    skipped: int,
    lag_minutes: int | None,
    previous_limit: int | None,
    partial_kind: str | None = None,
) -> dict[str, Any]:
    """Return the next adaptive state without performing database I/O."""
    prev_limit = _bounded_limit(previous_limit or _state_value(state, "current_limit", SECURITY_DEFAULT_LIMIT))
    consecutive = int(_state_value(state, "consecutive_completed", 0) or 0)
    recovery = bool(_state_value(state, "recovery_mode", False))
    next_limit = prev_limit
    action = "keep"
    reason = "stable"

    if status == "partial_timeout" and partial_kind == "failure":
        consecutive = 0
        action = "keep"
        reason = "functional_partial_failure"
    elif status == "partial_timeout":
        next_limit = max(SECURITY_MIN_LIMIT, max(1, prev_limit // 2))
        consecutive = 0
        recovery = True
        action = "decrease_limit"
        reason = "partial_timeout"
    elif status == "completed":
        consecutive += 1
        if consecutive >= COMPLETED_GROW_AFTER:
            if SECURITY_FAST_RECOVERY and (lag_minutes is None or lag_minutes > RECOVERY_ON_LAG_MINUTES):
                multiplied = int(prev_limit * SECURITY_GROW_FACTOR)
                stepped = prev_limit + SECURITY_GROW_STEP
                next_limit = min(SECURITY_MAX_LIMIT, SECURITY_TARGET_LIMIT, max(multiplied, stepped, prev_limit))
                reason = "completed_fast_recovery"
            else:
                next_limit = min(SECURITY_MAX_LIMIT, prev_limit + SECURITY_GROW_STEP)
                reason = "completed_streak"
            consecutive = 0
            action = "increase_limit" if next_limit != prev_limit else "keep"
        else:
            action = "keep"
            reason = f"completed_streak_{consecutive}"
    elif status == "timeout":
        next_limit = max(SECURITY_MIN_LIMIT, max(1, prev_limit // 2))
        consecutive = 0
        recovery = True
        action = "decrease_limit"
        reason = status
    elif status == "failed":
        # A functional failure (for example, denial on another event channel)
        # is not evidence that the Security batch overloaded the runtime.
        # Keep the established limit and wait for the fault to be resolved.
        consecutive = 0
        action = "keep"
        reason = "functional_failure"

    if lag_minutes is not None and lag_minutes > RECOVERY_ON_LAG_MINUTES:
        recovery = True
    elif status == "completed" and lag_minutes is not None and lag_minutes < RECOVERY_OFF_LAG_MINUTES:
        recovery = False

    action_text = f"{action}:{reason}; {prev_limit}->{next_limit}; recovery={'on' if recovery else 'off'}"
    return {
        "previous_limit": prev_limit,
        "current_limit": next_limit,
        "consecutive_completed": consecutive,
        "recovery_mode": recovery,
        "last_status": status,
        "last_lag_minutes": lag_minutes,
        "last_action": action_text,
        "action": action,
        "reason": reason,
        "updated_at": utc_now(),
        "inserted": inserted,
        "skipped": skipped,
    }


def compute_non_security_adaptive_transition(
    *,
    state: Any,
    status: str,
    previous_limit: int | None,
    truncated: bool,
    partial_kind: str | None = None,
) -> dict[str, Any]:
    """Advance one bounded non-Security channel until its frozen boundary."""
    baseline = max(1, int(NON_SECURITY_MAX_EVENTS))
    previous = max(1, int(previous_limit or _state_value(state, "current_limit", baseline)))
    recovery = bool(_state_value(state, "recovery_mode", False))
    current = previous
    action = "keep"
    reason = "stable"

    if truncated:
        current = min(
            NON_SECURITY_RECOVERY_MAX_EVENTS,
            max(baseline, previous * 2, previous + NON_SECURITY_RECOVERY_GROW_STEP),
        )
        recovery = True
        action = "increase_limit" if current > previous else "keep"
        reason = "bounded_limit_before_source_boundary"
    elif status == "completed":
        current = baseline
        recovery = False
        action = "exit_recovery"
        reason = "source_boundary_reached"
    elif status in {"timeout", "partial_timeout"} and partial_kind != "failure":
        current = max(baseline, previous // 2)
        recovery = True
        action = "decrease_limit" if current < previous else "keep"
        reason = status

    return {
        "previous_limit": previous,
        "current_limit": current,
        "consecutive_completed": 0,
        "recovery_mode": recovery,
        "last_status": status,
        "last_lag_minutes": None,
        "last_action": (
            f"{action}:{reason}; {previous}->{current}; "
            f"recovery={'on' if recovery else 'off'}"
        ),
        "action": action,
        "reason": reason,
        "updated_at": utc_now(),
    }


def log_security_adaptive_transition(*, server: str, transition: dict[str, Any]) -> None:
    log_event(
        "collector",
        "adaptive_security_decision",
        "Adaptive Security collector decision.",
        server=server,
        channel=SECURITY_CHANNEL,
        previous_limit=transition["previous_limit"],
        next_limit=transition["current_limit"],
        reason=transition["reason"],
        previous_status=transition["last_status"],
        inserted=transition["inserted"],
        skipped=transition["skipped"],
        lag_minutes=transition["last_lag_minutes"],
        recovery_mode=transition["recovery_mode"],
        adaptive_action=transition["action"],
    )


def _bounded_limit(value: Any) -> int:
    try:
        limit = int(value)
    except (TypeError, ValueError):
        limit = SECURITY_DEFAULT_LIMIT
    return max(SECURITY_MIN_LIMIT, min(SECURITY_MAX_LIMIT, limit))
