"""Registry contact remains independent of unavailable collection diagnostics."""
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from server.sli.agents import collection_health as health

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


def agent(last_seen):
    return {
        "id": "00000000-0000-4000-8000-000000000001",
        "host_id": "00000000-0000-4000-8000-000000000002",
        "instance_name": "fixture-agent", "status": "active", "last_seen": last_seen,
        "created_at": NOW - timedelta(days=1), "policy_revision": 1,
        "applied_policy_revision": 1, "applied_collection_state": "active",
        "collection_policy": {"state": "active", "interval_seconds": 60},
        "assigned_modules": [{"module_id": "sli.windows.ad-dc", "enabled": True,
                              "config": {"channels": {"Security": True, "System": False,
                                                       "Directory Service": False}}}],
    }


class RegistryConnectivityTests(unittest.TestCase):
    def test_contact_thresholds_do_not_depend_on_stream_availability(self):
        for last_seen, expected in [
            (NOW, "online"), (NOW - timedelta(seconds=300), "online"),
            (NOW - timedelta(seconds=301), "offline"), (None, "never_seen"),
            # Preserve existing clock-skew behavior; do not redefine age here.
            (NOW + timedelta(seconds=30), "online"),
        ]:
            with self.subTest(last_seen=last_seen):
                for available in (True, False):
                    result = health.collection_health_view(
                        [agent(last_seen)], [], now=NOW, diagnostics_available=available)
                    item = result["items"][0]
                    self.assertEqual(item["connection"], expected)
                    self.assertNotEqual(result["state"], "current")
                    if not available:
                        self.assertEqual(item["state"], "unknown")
                        self.assertEqual(item["modules"][0]["channels"][0]["state"], "unknown")

    def test_stream_timeout_retains_fresh_contact_but_not_collection_success(self):
        row = agent(datetime.now(timezone.utc))
        row["last_accepted_gap_at"] = NOW - timedelta(days=8)
        def read(sql, params=(), **kwargs):
            self.assertEqual(kwargs, {"statement_timeout_ms": 3000,
                                      **({"jit": False} if sql == health._STREAMS_SQL else {})})
            if sql == health._AGENTS_SQL:
                return [row]
            self.assertEqual(sql, health._STREAMS_SQL)
            raise TimeoutError("synthetic-private-detail")
        with patch.object(health, "query_rows_bounded", side_effect=read) as query:
            result = health.get_agent_collection_health()
        self.assertEqual(query.call_count, 2)
        self.assertEqual(result["state"], "partial")
        self.assertEqual(result["diagnostics"], {"state": "unavailable", "reason": "timeout"})
        self.assertEqual(result["current_agents"], 0)
        self.assertEqual(result["items"][0]["connection"], "online")
        self.assertEqual(result["items"][0]["state"], "unknown")
        self.assertEqual(result["items"][0]["completeness"]["state"], "known_gaps")
        self.assertNotIn("synthetic-private-detail", str(result))

    def test_registry_failure_has_no_contact_fallback(self):
        with patch.object(health, "query_rows_bounded", side_effect=TimeoutError):
            result = health.get_agent_collection_health()
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["items"], [])

    def test_authorization_denial_has_no_contact_fallback(self):
        with patch.object(health, "query_rows_bounded", side_effect=[[agent(NOW)], PermissionError()]):
            result = health.get_agent_collection_health()
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["items"], [])

    def test_malformed_timestamp_still_fails_closed(self):
        with patch.object(health, "query_rows_bounded", side_effect=[[agent("invalid")], TimeoutError()]):
            result = health.get_agent_collection_health()
        self.assertEqual(result["state"], "unavailable")
        self.assertEqual(result["items"], [])
