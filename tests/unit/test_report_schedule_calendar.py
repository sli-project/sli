"""Original calendar semantics using existing zoneinfo files, no DB/service."""
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest.mock import patch
from zoneinfo import ZoneInfo
from server.sli.core import report_schedule_calendar as calendar

UTC = timezone.utc


def moment(value):
    return datetime.fromisoformat(value).replace(tzinfo=UTC)


def schedule(**kwargs):
    return {"created_at": moment("2026-01-01"), "timezone": "America/New_York", "local_time": "02:30",
            "weekday": None, "period_days": 1, **kwargs}


class CalendarTests(unittest.TestCase):
    def setUp(self):
        path = Path(r"D:\SLI_platform_deps\postgresql-18\pgsql\share\timezone\America\New_York")
        try:
            self.zone = ZoneInfo("America/New_York")
        except Exception:
            if not path.is_file():
                self.skipTest("Existing IANA timezone files required")
            with path.open("rb") as stream:
                self.zone = ZoneInfo.from_file(stream, key="America/New_York")
        self.zone_patch = patch.object(calendar, "ZoneInfo", lambda key: self.zone)
        self.zone_patch.start()
        self.addCleanup(self.zone_patch.stop)

    def test_gap_advances_to_first_valid_minute(self):
        self.assertEqual(calendar.latest_slot(schedule(), moment("2026-03-08T07:05:00")), moment("2026-03-08T07:00:00"))

    def test_first_fold_only_and_latest_slot_not_replayed(self):
        row = schedule(local_time="01:30")
        self.assertEqual(calendar.latest_slot(row, moment("2026-11-01T06:40:00")), moment("2026-11-01T05:30:00"))
        self.assertEqual(calendar.latest_slot(row, moment("2026-11-03T08:00:00")), moment("2026-11-03T06:30:00"))

    def test_period_is_local_calendar_day_not_fixed_24_hours(self):
        row = schedule(local_time="08:00")
        slot = calendar.latest_slot(row, moment("2026-03-08T12:00:00"))
        start = calendar.period_start(row, slot)
        self.assertEqual((slot-start).total_seconds(), 23*3600)


if __name__ == "__main__":
    unittest.main()
