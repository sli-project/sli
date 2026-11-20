"""One API-boundary UTC range contract shared by backend data routes."""
from __future__ import annotations

import re
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_DATE_ONLY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class TimeRangeError(ValueError):
    pass


def _zone(name: str | None) -> tzinfo:
    try:
        return ZoneInfo(str(name or "UTC").strip() or "UTC")
    except ZoneInfoNotFoundError as exc:
        raise TimeRangeError("invalid_timezone") from exc


def _localize_wall_time(value: datetime, zone: tzinfo) -> datetime:
    """Attach an IANA zone while rejecting ambiguous/nonexistent wall times."""
    candidates: list[datetime] = []
    for fold in (0, 1):
        candidate = value.replace(tzinfo=zone, fold=fold)
        roundtrip = candidate.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None)
        if roundtrip == value:
            candidates.append(candidate)
    if not candidates:
        raise TimeRangeError("nonexistent_local_datetime")
    offsets = {candidate.utcoffset() for candidate in candidates}
    if len(offsets) > 1:
        raise TimeRangeError("ambiguous_local_datetime_requires_offset")
    return candidates[0]


def _instant(value: str | None, *, zone: tzinfo, exclusive_date_end: bool) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        if _DATE_ONLY.fullmatch(raw):
            day = date.fromisoformat(raw) + (timedelta(days=1) if exclusive_date_end else timedelta())
            parsed = datetime.combine(day, time.min, tzinfo=zone)
        else:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = _localize_wall_time(parsed, zone)
    except TimeRangeError:
        raise
    except ValueError as exc:
        raise TimeRangeError("invalid_datetime") from exc
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_utc_range(
    time_from: str | None,
    time_to: str | None,
    *,
    timezone_name: str | None = "UTC",
) -> tuple[str | None, str | None]:
    """Normalize once; a date upper bound means the next local midnight."""
    zone = _zone(timezone_name)
    start = _instant(time_from, zone=zone, exclusive_date_end=False)
    end = _instant(time_to, zone=zone, exclusive_date_end=True)
    if start and end:
        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if start_dt >= end_dt:
            raise TimeRangeError("empty_or_reversed_time_range")
    return start, end
