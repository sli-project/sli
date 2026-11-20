"""File audit contact is not proof of successful Security collection."""
from datetime import datetime, timedelta, timezone
import unittest

from server.sli.agents import collection_health as health

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
AGENT = "00000000-0000-4000-8000-000000000001"


def agent(**changes):
    return {"id": AGENT, "host_id": AGENT, "instance_name": "fixture",
            "status": "active", "last_seen": NOW, "created_at": NOW - timedelta(days=2),
            "policy_revision": 1, "applied_policy_revision": 1, "applied_collection_state": "active",
            "collection_policy": {"state": "active", "interval_seconds": 60},
            "assigned_modules": [{"module_id": "sli.file-audit", "enabled": True, "config": {}}],
            **changes}


def stream(**changes):
    return {"agent_id": AGENT, "module_id": "sli.file-audit", "revision": "1", "channel": "Security",
            "last_packet_at": NOW - timedelta(seconds=30), "last_import_at": NOW,
            "pending_since": None, "read_error": False, **changes}


class FileAuditHealthTests(unittest.TestCase):
    def test_latest_read_outcome_controls_health(self):
        for changes, state in [({}, "current"), ({"read_error": True}, "error"),
                               ({"read_error": None}, "unknown"),
                               ({"pending_since": NOW - timedelta(seconds=30), "last_import_at": None}, "lagging"),
                               ({"pending_since": NOW - timedelta(seconds=901)}, "error")]:
            with self.subTest(changes=changes):
                result = health.collection_health_view([agent()], [stream(**changes)], now=NOW)
                item = result["items"][0]
                self.assertEqual(item["state"], state)
                check = item["modules"][0]["channels"][0]
                self.assertEqual(check["channel"], "Security")
                self.assertEqual(check["state"], state)
                self.assertEqual(check["failure_reason"], "read_error" if changes.get("read_error") else
                                 "import_overdue" if changes.get("pending_since") == NOW - timedelta(seconds=901) else None)

    def test_unapplied_and_new_policy_missing_packet_stay_waiting(self):
        for changes in ({"applied_policy_revision": 0}, {"policy_applied_at": NOW}):
            result = health.collection_health_view([agent(**changes)], [], now=NOW)
            self.assertEqual(result["items"][0]["state"], "waiting")

    def test_diagnostics_failure_and_wrong_revision_do_not_become_current(self):
        result = health.collection_health_view([agent()], [stream()], now=NOW, diagnostics_available=False)
        self.assertEqual(result["items"][0]["state"], "unknown")
        self.assertEqual(result["items"][0]["modules"][0]["channels"][0]["state"], "unknown")
        result = health.collection_health_view([agent()], [stream(revision="0")], now=NOW)
        self.assertEqual(result["items"][0]["modules"][0]["channels"][0]["failure_reason"], "packet_missing")

    def test_paused_collection_and_historical_gaps_are_preserved(self):
        result = health.collection_health_view([agent(collection_policy={"state": "paused"})],
                                              [stream(read_error=True)], now=NOW)
        self.assertEqual(result["items"][0]["state"], "paused")
        result = health.collection_health_view([agent(last_accepted_gap_at=NOW - timedelta(days=8))],
                                              [stream(historical_unimported_packets=2)], now=NOW)
        self.assertEqual(result["state"], "current")
        self.assertEqual(result["completeness"]["state"], "known_gaps")
        self.assertEqual(result["items"][0]["modules"][0]["channels"][0]["historical_unimported_packets"], 2)

