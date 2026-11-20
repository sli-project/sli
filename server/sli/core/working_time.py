"""Shared administrator calendar; no implicit working hours when unset."""
from datetime import date, datetime
import json
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_SID = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+")

SETTING_KEY = "security.working_time"


def _utc(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError("working_time_invalid")
    return parsed


def validate(value):
    try:
        if not isinstance(value, dict) or set(value) != {
                "timezone", "weekdays", "start", "end", "excluded_dates", "exceptions"}:
            raise ValueError
        ZoneInfo(value["timezone"])
        days = value["weekdays"]
        if (not isinstance(days, list) or not days or len(days) > 7
                or any(type(day) is not int or not 0 <= day <= 6 for day in days)
                or len(set(days)) != len(days)):
            raise ValueError
        for key in ("start", "end"):
            if not isinstance(value[key], str) or not re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value[key]):
                raise ValueError
        if value["start"] == value["end"]:
            raise ValueError
        if not isinstance(value["excluded_dates"], list) or len(value["excluded_dates"]) > 366:
            raise ValueError
        for day in value["excluded_dates"]:
            if date.fromisoformat(day).isoformat() != day:
                raise ValueError
        if not isinstance(value["exceptions"], list) or len(value["exceptions"]) > 100:
            raise ValueError
        for item in value["exceptions"]:
            if (not isinstance(item, dict) or set(item) != {"subject_sid", "start_utc", "end_utc", "reason"}
                    or not isinstance(item["subject_sid"], str) or not _SID.fullmatch(item["subject_sid"])
                    or not isinstance(item["reason"], str) or not 1 <= len(item["reason"]) <= 256):
                raise ValueError
            start, end = (_utc(item[key]) for key in ("start_utc", "end_utc"))
            if start >= end:
                raise ValueError
        return value
    except (ValueError, TypeError, KeyError, AttributeError, ZoneInfoNotFoundError):
        raise ValueError("working_time_invalid") from None


def setting_value(raw):
    try:
        value = validate(json.loads(raw))
    except (ValueError, TypeError):
        raise ValueError("working_time_invalid") from None
    normalized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(normalized) > 1024:
        raise ValueError("working_time_invalid")
    return normalized


def outside(instant, subject_sid, calendar):
    """Start inclusive/end exclusive, including shifts across local midnight."""
    from datetime import timedelta
    instant = _utc(instant)
    local = instant.astimezone(ZoneInfo(calendar["timezone"]))
    for item in calendar["exceptions"]:
        if item["subject_sid"] == subject_sid and _utc(item["start_utc"]) <= instant < _utc(item["end_utc"]):
            return False, local.isoformat()
    clock = local.strftime("%H:%M")
    start, end = calendar["start"], calendar["end"]
    day = local.date()
    if start < end:
        inside = start <= clock < end
    else:
        inside = clock >= start or clock < end
        if clock < end:
            day -= timedelta(days=1)
    inside = inside and day.weekday() in calendar["weekdays"] and day.isoformat() not in calendar["excluded_dates"]
    return not inside, local.isoformat()
