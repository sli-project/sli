"""Shared calendar: minute advance, first fold and latest missed slot only."""
from datetime import datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo
UTC = timezone.utc

def local_instant(naive, zone):
    """First fold only; a missing wall minute advances to the first valid minute."""
    for _ in range(1441):
        instant = naive.replace(tzinfo=zone, fold=0).astimezone(UTC)
        if instant.astimezone(zone).replace(tzinfo=None) == naive:
            return instant
        naive += timedelta(minutes=1)
    raise ValueError("invalid_notification_request")


def latest_slot(schedule, now):
    zone = ZoneInfo(schedule["timezone"])
    local = now.astimezone(zone)
    wall_time = time.fromisoformat(schedule["local_time"])
    for days in range(9):
        day = local.date() - timedelta(days=days)
        if schedule["weekday"] is not None and day.weekday() != schedule["weekday"]:
            continue
        slot = local_instant(datetime.combine(day, wall_time), zone)
        if schedule["created_at"] <= slot <= now:
            return slot
    return None


def period_start(schedule, slot):
    zone = ZoneInfo(schedule["timezone"])
    return local_instant(slot.astimezone(zone).replace(tzinfo=None)
                         - timedelta(days=schedule["period_days"]), zone)
