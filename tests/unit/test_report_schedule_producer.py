"""Synthetic cursor boundary; the real shared ACL composer is not mocked."""
from contextlib import nullcontext
from types import SimpleNamespace
from uuid import uuid4
import unittest
from unittest.mock import patch
import sys

from server.sli.core import report_schedule_producer as producer
from tests.unit.test_access_composition import facts, grant_caps, NOW, SUBJECT


def envelope():
    policy = facts()
    del policy["requests"], policy["preferences"]
    grant_caps(policy, ["field.security", "field.identity_basic", "reports.export"])
    return {"evaluated_at": NOW.isoformat(), "report_key": "security.problems", "schedule_revision": 4,
        "owner_user_id": 7, "dependencies": {}, "actors": [{"subject": {**SUBJECT, "is_active": True}, "facts": policy}],
        "bindings": [{"id": str(uuid4()), "revision": 2, "recipient_user_id": 7, "channel": "telegram", "channel_revision": 1}]}


def connection(data):
    statements = []
    cursor = SimpleNamespace(execute=lambda sql, params: statements.append((sql, params)),
                             fetchone=lambda: {"facts": data})
    conn = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(cursor))
    return conn, statements


class ProducerAccessTests(unittest.TestCase):
    def test_entry_exits_failed_connection_cycle_for_supervisor_restart(self):
        conn = SimpleNamespace()
        driver = SimpleNamespace(connect=lambda *args, **kwargs: nullcontext(conn))
        rows = SimpleNamespace(dict_row=object())
        # A failed cycle must release the connection instead of repeatedly
        # consuming a dead session. No driver, server or health write occurs.
        with patch.dict(sys.modules, {'psycopg': driver, 'psycopg.rows': rows}), \
             patch.dict('os.environ', {'SLI_REPORT_PRODUCER_PG_DSN': 'synthetic-only'}), \
             patch.object(producer, 'connection_options', return_value={'conninfo': 'synthetic-only', 'password': 'synthetic-only'}), \
             patch.object(sys, 'argv', ['producer']), patch.object(producer.signal, 'signal'), \
             patch.object(producer, 'run_cycle', return_value={'status': 'failed', 'leader': None}) as cycle, \
             patch.object(producer.threading.Event, 'wait', side_effect=AssertionError('failed cycle waited')) as wait:
            self.assertEqual(producer.main(), 1)
            cycle.assert_called_once()
            wait.assert_not_called()

    def test_sql_success_payload_normalizes_validates_and_projects(self):
        from tests.unit.test_report_schedule_projection import actual_report_access, definition, access
        from server.sli.core.report_schedule_projection import project
        raw = {"report_key": "security.problems", "generated_at": NOW.isoformat(),
            "counts": {"individual": {"total": 51, "has_more": True}, "cohorts": {"total": 1, "has_more": False}},
            "quality_inputs": {"refresh_limited": False, "coverage_incomplete": False,
                "heartbeat": {"status": "idle", "heartbeat_at": NOW.isoformat(), "expected_interval_seconds": 30,
                    "details_json": {"runtime_mode": "findings-v1", "manual_runtime": False}}}}
        normalized = producer.normalize_candidate(raw, "security.problems")
        self.assertEqual(set(normalized), {"report_key", "quality", "counts", "roots"})
        snapshot = {"owner_user_id": 7, "actors": {7: access(), 8: access()}, "bindings": [{"recipient_user_id": 8}]}
        result = project(definition(), snapshot, normalized, authority_factory=actual_report_access())
        self.assertEqual((result["item_count"], result["truncated"], result["quality"]), (1, False, "ok"))
        snapshot["actors"][7] = access(identity=False)
        result = project(definition(), snapshot, normalized, authority_factory=actual_report_access())
        self.assertEqual((result["item_count"], result["truncated"], result["quality"]), (51, True, "partial"))
        with self.assertRaises(ValueError):
            producer.normalize_candidate({**raw, "items": [{"actor": "private-fixture"}]}, "security.problems")
        raw["quality_inputs"]["heartbeat"]["source_rows"] = ["private-fixture"]
        with self.assertRaises(ValueError):
            producer.normalize_candidate(raw, "security.problems")

    def test_fixed_accessor_and_real_identity_projection(self):
        conn, statements = connection(envelope())
        result = producer.read_claimed_access(conn, str(uuid4()), str(uuid4()), deadline=12, clock=lambda: 10)
        self.assertIn("actors", result)
        self.assertEqual(result["actors"][7]["reports"][0]["field_categories"], ["identity_basic", "security"])
        self.assertTrue(all("report_schedule_acl_facts" in sql or "set_config" in sql for sql, _ in statements))
        self.assertIn(("2000ms", "500ms"), [params for sql, params in statements if "set_config" in sql])

    def test_denied_identity_does_not_return_authorized_projection(self):
        data = envelope()
        data["actors"][0]["facts"]["direct_capabilities"] = []
        conn, _ = connection(data)
        result = producer.read_claimed_access(conn, str(uuid4()), str(uuid4()), deadline=12, clock=lambda: 10)
        self.assertIn("actors", result)
        self.assertEqual(result["actors"][7]["reports"][0]["field_categories"], [])

    def test_inactive_actor_and_unbound_recipient_fail_closed(self):
        for kind in ("inactive", "recipient"):
            data = envelope()
            if kind == "inactive":
                data["actors"][0]["subject"]["is_active"] = False
            else:
                data["bindings"][0]["recipient_user_id"] = 99
            conn, _ = connection(data)
            with self.assertRaisesRegex(ValueError, "^invalid_schedule_access_facts$"):
                producer.read_claimed_access(conn, str(uuid4()), str(uuid4()), deadline=12, clock=lambda: 10)

    def test_deadline_expiration_never_reads(self):
        conn, statements = connection(envelope())
        with self.assertRaises(TimeoutError):
            producer.read_claimed_access(conn, str(uuid4()), str(uuid4()), deadline=10, clock=lambda: 10)
        self.assertEqual(statements, [])

    def test_read_budget_shrinks_to_remaining_cycle_time(self):
        conn, statements = connection(envelope())
        producer.read_claimed_access(conn, str(uuid4()), str(uuid4()), deadline=10.125, clock=lambda: 10)
        self.assertIn(("125ms", "125ms"), [params for sql, params in statements if "set_config" in sql])


if __name__ == "__main__":
    unittest.main()
