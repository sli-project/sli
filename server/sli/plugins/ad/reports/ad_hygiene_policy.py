"""Owner-approved account hygiene policy, evaluated only from observed AD facts."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from server.sli.core.platform_settings import get_setting

REPLICATION_CAVEAT = "lastLogonTimestamp — приблизительный реплицируемый атрибут; возможна задержка репликации. Это не доказательство отсутствия входов."


def thresholds() -> dict[str, int]:
    return {"password_age": int(get_setting("ad.password_max_age_days")),
            "inactivity": int(get_setting("ad.inactivity_days"))}


def _timestamp(value: Any) -> datetime | None:
    try:
        stamp = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            return None
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def evaluate(value: Any, observed_at: Any, days: int, *, source_state: str | None = None) -> dict[str, Any]:
    """Unknown facts never become a policy pass or failure; the boundary is strict."""
    fact, observed = _timestamp(value), _timestamp(observed_at)
    reason = None
    if source_state and source_state not in {"observed", "complete", "completed"}:
        reason = "source_untrustworthy"
    elif fact is None:
        reason = "fact_missing_or_invalid"
    elif observed is None:
        reason = "observation_time_missing_or_invalid"
    elif fact > observed:
        reason = "fact_after_observation"
    return {"status": "unknown" if reason else "exceeded" if observed - fact > timedelta(days=days) else "within_policy",
            "reason": reason, "threshold_days": days, "value": fact.isoformat() if fact else None,
            "observed_at": observed.isoformat() if observed else None}


def for_user(user: Mapping[str, Any], observed_at: Any, policy: Mapping[str, int]) -> dict[str, dict[str, Any]]:
    states = user.get("sourceStates") or {}
    directory = (states.get("directory") or {}).get("status")
    observed_at = (states.get("directory") or {}).get("observed_at") or observed_at
    password = evaluate(user.get("passwordLastSet"), observed_at, policy["password_age"],
                        source_state=(states.get("password_last_set") or {}).get("status") or directory)
    inactivity = evaluate(user.get("lastLogonTimestamp"), observed_at, policy["inactivity"],
                          source_state=(states.get("last_logon_timestamp") or {}).get("status") or directory)
    inactivity["limitation"] = REPLICATION_CAVEAT
    return {"password_age": password, "inactivity": inactivity}


def inactivity_sql(attributes: str, observed_at: str, *, days: int | None = None) -> str:
    """Server-owned PostgreSQL expression; malformed/future/absent facts yield NULL.

    Alias expressions come only from report code. The numeric policy is validated
    by platform settings before interpolation, never supplied by a report filter.
    """
    threshold = thresholds()["inactivity"] if days is None else int(days)
    if not 1 <= threshold <= 3650:
        raise ValueError("value_must_be_days_1_3650")
    raw = f"({attributes}->>'last_logon_utc')"
    return (f"(case when {raw} ~ 'T.*(Z|[+-][0-9]{{2}}:[0-9]{{2}})$' "
            f"and pg_input_is_valid({raw},'timestamp with time zone') then "
            f"case when {observed_at} is not null and {raw}::timestamptz <= {observed_at} "
            f"then {raw}::timestamptz < {observed_at} - interval '{threshold} days' end end)")
