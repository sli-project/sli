from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

RU_DATE_FORMAT = "%d.%m.%Y %H:%M:%S"
DEFAULT_DISPLAY_TZ = os.environ.get("ADLOG_DISPLAY_TIMEZONE", "UTC")
FIXED_TIMEZONE_FALLBACKS = {
    "Europe/Moscow": timezone(timedelta(hours=3), "Europe/Moscow"),
    "Asia/Novosibirsk": timezone(timedelta(hours=7), "Asia/Novosibirsk"),
}


def get_display_timezone(timezone_name: str | None = None):
    """Return configured report timezone.

    UTC is the safe default for investigations. Operators may set
    ADLOG_DISPLAY_TIMEZONE (for example, Europe/Moscow) to render a local
    operational view while raw UTC remains available in tooltips/API payloads.
    """
    name = (timezone_name or DEFAULT_DISPLAY_TZ or "UTC").strip()
    if name.upper() in {"UTC", "Z"}:
        return timezone.utc, "UTC"
    try:
        return ZoneInfo(name), name
    except ZoneInfoNotFoundError:
        fixed = FIXED_TIMEZONE_FALLBACKS.get(name)
        if fixed is not None:
            return fixed, name
        return timezone.utc, "UTC"


def parse_event_time(value: Any) -> datetime | None:
    """Parse common Windows/ISO timestamps and normalize them to UTC.

    Windows events often arrive as strings like
    2026-07-07T02:34:28.9127653Z. Python supports up to 6 fractional
    digits, so we trim longer fractions while preserving the instant.
    """
    raw = str(value or "").strip()
    if not raw or raw == "—":
        return None
    # Normalize the common Z suffix. Keep offset strings otherwise.
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    if "." in raw:
        head, tail = raw.split(".", 1)
        fraction = tail
        offset = ""
        for marker in ("+", "-"):
            if marker in tail:
                fraction, offset = tail.split(marker, 1)
                offset = marker + offset
                break
        if len(fraction) > 6:
            fraction = fraction[:6]
        raw = f"{head}.{fraction}{offset}"
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        # Some local values are stored as 'YYYY-mm-dd HH:MM:SS'.
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.strptime(str(value), fmt)
                break
            except ValueError:
                parsed = None  # type: ignore[assignment]
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_event_time(
    value: Any,
    *,
    suffix: str | None = "UTC",
    empty: str = "—",
    timezone_name: str | None = None,
    mode: str = "utc",
) -> str:
    parsed = parse_event_time(value)
    if parsed is None:
        return empty if value in (None, "") else str(value)
    if mode == "local":
        tz, tz_label = get_display_timezone(timezone_name)
        parsed = parsed.astimezone(tz)
        suffix = tz_label if suffix is None else suffix
    label = parsed.strftime(RU_DATE_FORMAT)
    return f"{label} {suffix}" if suffix else label


def format_event_time_compact(value: Any, *, empty: str = "—", timezone_name: str | None = None, mode: str = "utc") -> str:
    parsed = parse_event_time(value)
    if parsed is None:
        return empty if value in (None, "") else str(value)
    if mode == "local":
        tz, _ = get_display_timezone(timezone_name)
        parsed = parsed.astimezone(tz)
    return parsed.strftime("%d.%m %H:%M:%S")


def iso_utc_seconds(value: Any) -> str | None:
    parsed = parse_event_time(value)
    if parsed is None:
        return None
    return parsed.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def format_duration_minutes(value: Any, *, empty: str = "—") -> str:
    """Render a minute duration in a compact Russian human-readable form."""
    try:
        minutes = int(value)
    except (TypeError, ValueError):
        return empty
    if minutes < 0:
        minutes = 0
    days, rem = divmod(minutes, 1440)
    hours, mins = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days} д")
    if hours:
        parts.append(f"{hours} ч")
    if mins or not parts:
        parts.append(f"{mins} мин")
    return " ".join(parts[:2] if days else parts)


def format_datetime_label(value: Any, *, prefix: str = "Сформирован", empty: str = "—") -> str:
    rendered = format_event_time(value, empty=empty)
    return f"{prefix}: {rendered}" if rendered != empty else f"{prefix}: {empty}"


def format_event_time_with_context(
    value: Any,
    *,
    empty: str = "—",
    timezone_name: str | None = None,
    mode: str = "utc",
) -> dict[str, str]:
    """Return both display label and raw UTC tooltip for report UI.

    This keeps P4 behaviour explicit: user mode shows readable time with a
    timezone label, while the original UTC value remains available as technical
    context.
    """
    raw = "" if value is None else str(value)
    parsed = parse_event_time(value)
    if parsed is None:
        return {"display": empty if value in (None, "") else raw, "tooltip": raw, "timezone": "unknown"}
    utc_raw = iso_utc_seconds(parsed) or raw
    label = format_event_time(parsed.isoformat(), empty=empty, timezone_name=timezone_name, mode=mode, suffix=None if mode == "local" else "UTC")
    tz_label = get_display_timezone(timezone_name)[1] if mode == "local" else "UTC"
    return {"display": label, "tooltip": utc_raw, "timezone": tz_label}


def format_report_time(value: Any, *, empty: str = "—", timezone_name: str | None = None) -> str:
    """Default report timestamp formatter used by human-facing HTML."""
    return format_event_time(value, empty=empty, timezone_name=timezone_name, mode="local", suffix=None)
