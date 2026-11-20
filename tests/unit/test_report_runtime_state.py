"""Exact runtime quality cases used by report and producer."""
from datetime import datetime, timedelta, timezone
import unittest
from server.sli.semantic import runtime_state as state

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


class RuntimeStateTests(unittest.TestCase):
    def test_active_empty_stale_manual_and_unknown(self):
        row = {"status": "idle", "heartbeat_at": NOW, "expected_interval_seconds": 30,
               "details_json": {"runtime_mode": "findings-v1", "manual_runtime": False}}
        self.assertEqual(state.scheduled_quality(row, generated=NOW, total=1), "ok")
        self.assertEqual(state.scheduled_quality(row, generated=NOW, total=0), "empty")
        self.assertEqual(state.scheduled_quality(row, generated=NOW+timedelta(minutes=5), total=1), "stale")
        row["details_json"]["manual_runtime"] = True
        self.assertEqual(state.scheduled_quality(row, generated=NOW, total=1), "partial")
        self.assertEqual(state.scheduled_quality({}, generated=NOW, total=0), "partial")

    def test_coverage_refresh_and_selected_variant_truncation_are_limitations(self):
        row = {"status": "running", "heartbeat_at": NOW, "details_json": {
            "runtime_mode": "findings-v1", "manual_runtime": False}}
        for key in ("refresh_limited", "coverage_incomplete", "has_more"):
            self.assertEqual(state.scheduled_quality(row, generated=NOW, total=0, **{key: True}), "partial")


if __name__ == "__main__":
    unittest.main()
