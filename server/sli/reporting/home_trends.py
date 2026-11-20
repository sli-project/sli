"""Comparable measurements and completed event windows for the Home projection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import isfinite
from zoneinfo import ZoneInfo


def numeric(value):
    return type(value) in {int, float} and isfinite(value) and value >= 0


def _utc(value):
    at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if at.tzinfo is None:
        raise ValueError("home_window_timezone_required")
    return at.astimezone(timezone.utc)


def _iso(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def completed_windows(context, now):
    """Use the last completed local days; custom bounds remain exact and exclusive."""
    zone = ZoneInfo(context["time_zone"])
    period = context["period"]
    days = {"current": 1, "24h": 1, "7d": 7, "30d": 30, "90d": 90}.get(period["preset"])
    if days is not None:
        end = now.astimezone(zone).replace(hour=0, minute=0, second=0, microsecond=0)
        start = end - timedelta(days=days)
        before = start - timedelta(days=days)
    else:
        start, end = _utc(period["from_utc"]), _utc(period["to_utc"])
        if end > now or start >= end:
            raise ValueError("home_window_incomplete")
        before = start - (end - start)
    return ({"from_utc": _iso(start), "to_utc": _iso(end)},
            {"from_utc": _iso(before), "to_utc": _iso(start)})


def compare(current, previous, *, meaning="neutral"):
    missing = {"state": "missing", "message_code": "home.comparison.missing", "absolute_change": None,
               "percent_change": None, "tone": "neutral"}
    if not previous or not numeric(previous.get("value")) or not numeric(current.get("value")):
        return missing
    same = all(current.get(key) == previous.get(key) and current.get(key) is not None
               for key in ("scope", "time_zone", "unit", "definition_version", "coverage"))
    same = same and (current.get("coverage") or {}).get("complete") is True
    try:
        zone = ZoneInfo(current["time_zone"])
        left, right = current["window"], previous["window"]
        endpoints = [_utc(window[key]) for window in (left, right) for key in ("from_utc", "to_utc")]
        start, end, prior_start, prior_end = endpoints
        local = [at.astimezone(zone) for at in endpoints]
        # Exact-duration windows and complete local days are distinct valid
        # definitions; a local day may contain 23 or 25 hours across DST.
        midnights = all(at.hour == at.minute == at.second == at.microsecond == 0 for at in local)
        duration_matches = end - start == prior_end - prior_start or (
            midnights and local[1] - local[0] == local[3] - local[2])
        same = same and end > start and prior_end > prior_start and duration_matches and prior_end == start
    except (KeyError, ValueError, TypeError):
        same = False
    if not same:
        return {**missing, "state": "incomparable", "message_code": "home.comparison.incomparable"}
    change = current["value"] - previous["value"]
    good = change < 0 if meaning == "lower_is_better" else change > 0
    tone = "neutral" if not change or meaning == "neutral" else "success" if good else "danger"
    percent = change / previous["value"] * 100 if previous["value"] else None
    return {"state": "comparable", "message_code": "home.comparison.absolute" if percent is None else "home.comparison.percent",
            "absolute_change": change, "percent_change": percent, "tone": tone}
