"""Synthetic orchestration, real calendar and ACL projection; no SQL/transport."""
from datetime import datetime, timezone, timedelta
from threading import Event
from unittest.mock import patch
import unittest
from uuid import uuid4

from server.sli.core import report_schedule_producer as producer, report_schedule_calendar as calendar
from tests.unit.test_report_schedule_projection import definition, actual_report_access, security_candidate, access

NOW = datetime(2026, 10, 25, 9, tzinfo=timezone.utc)


class Backend:
    def __init__(self, stop):
        self.stop = stop
        self.calls = []
        self.standby = False
        self.expire_on_read = False
        self.revoke = False
        self.quality_timeout = False
        self.capacity = False
        self.failed = False
    def lead(self, token, deadline):
        self.calls.append("lead")
        return None if self.standby else str(uuid4())
    def claim(self, token, limit, deadline):
        self.calls.append("claim")
        return [{"job_id": str(uuid4()), "lease": str(uuid4()), "slot": NOW, "period_from": NOW-timedelta(days=1),
            "evaluated_at": NOW, "schedule": {"report_key": "security.problems", "created_at": NOW-timedelta(days=2),
                "timezone": "UTC", "local_time": "09:00", "weekday": None, "period_days": 1}}]
    def facts(self, claim, deadline):
        self.calls.append("facts")
        return {"owner_user_id": 7, "actors": {7: access(), 8: access(export=not self.revoke)},
                "bindings": [{"recipient_user_id": 8}]}
    def candidates(self, claim, deadline):
        self.calls.append("aggregate")
        if self.expire_on_read:
            self.stop.set()
        if self.failed:
            return {"report_key": "security.problems", "quality": "error", "roots": [], "counts": {}}
        return security_candidate()
    def failure(self, claim, quality, deadline):
        self.calls.append("failure")
        self.failed = True
    def publish(self, claim, selection, deadline):
        self.calls.append(("publish", selection))
        if self.capacity:
            raise producer.RpcCapacity("report_producer_capacity")
        if self.quality_timeout and not self.failed:
            raise producer.RpcReadDeadline("report_producer_read_deadline")
        return {"published": True, "jobs": 1}


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.stop = Event()
        self.backend = Backend(self.stop)
        p = patch.object(calendar, "ZoneInfo", lambda key: timezone.utc)
        p.start()
        self.addCleanup(p.stop)
    def cycle(self):
        result = producer.run_cycle(self.backend, self.stop, clock=lambda: 10,
            definition_loader=lambda key: definition(), authority_factory=actual_report_access())
        self.assertIn("status", result)
        return result
    def test_due_calendar_aggregate_acl_then_durable_publication_boundary(self):
        result = self.cycle()
        self.assertEqual(result["published"], 1)
        self.assertEqual(self.backend.calls[:4], ["lead", "claim", "facts", "aggregate"])
        self.assertEqual(self.backend.calls[4][1]["variant"], "cohorts")
        self.assertTrue(self.backend.calls[4][1]["include_count"])
    def test_export_revocation_is_decided_by_real_policy_before_publish(self):
        self.backend.revoke = True
        self.cycle()
        self.assertFalse(self.backend.calls[-1][1]["include_count"])
    def test_leader_contention_does_not_claim(self):
        self.backend.standby = True
        self.assertEqual(self.cycle()["status"], "standby")
        self.assertEqual(self.backend.calls, ["lead"])
    def test_shutdown_after_read_never_publishes(self):
        self.backend.expire_on_read = True
        self.assertEqual(self.cycle()["status"], "stopped")
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "publish" for call in self.backend.calls))
    def test_already_stopped_does_not_touch_backend(self):
        self.stop.set()
        self.assertEqual(self.cycle()["status"], "stopped")
        self.assertEqual(self.backend.calls, [])
    def test_quality_deadline_can_only_publish_countless_error(self):
        self.backend.quality_timeout = True
        self.assertEqual(self.cycle()["published"], 1)
        self.assertIn("failure", self.backend.calls)
        self.assertFalse(self.backend.calls[-1][1]["include_count"])
    def test_capacity_preserves_staged_data_and_does_not_fake_source_error(self):
        self.backend.capacity = True
        self.assertEqual(self.cycle()["status"], "backpressure")
        self.assertNotIn("failure", self.backend.calls)


if __name__ == "__main__":
    unittest.main()
