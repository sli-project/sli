"""Regression coverage for read-adapter binds, without a PostgreSQL service."""

import re
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from server.sli.core import database, notification_outbox as outbox, report_schedules
from server.sli.core import postgres_runtime_pipeline, setup_status
from server.sli.plugins.remote_access import setup
from server.sli.reporting import read_timeout


class Cursor:
    def __init__(self, store):
        self.store = store
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, params=()):
        # Escaped %% is a literal percent, never a psycopg parameter.
        binds = sum(token == "%s" for token in re.findall(r"%%|%s", sql))
        if binds != len(params):
            raise ValueError(f"bind arity: {binds} != {len(params)}")
        self.store.calls.append((" ".join(sql.split()), params))
        expected_sql, expected_params, result = self.store.expected.pop(0)
        if " ".join(sql.split()) != expected_sql or params != expected_params:
            raise AssertionError((sql, params, expected_sql, expected_params))
        if isinstance(result, Exception):
            raise result
        self.rows = result

    def fetchall(self):
        return self.rows


class Store:
    def __init__(self, *expected):
        self.expected = list(expected)
        self.calls = []
        self.commits = 0

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.commits += 1


JOURNAL = "select " + ",".join(outbox.JOB_FIELDS) + ",object_kind from notification_outbox"
EVIDENCE = (
    "select lower(source_instance_id) as source_instance_id, max(verified_at_utc) as last_data_utc "
    "from radius_vpn_session_evidence_observations_v1 where lower(source_instance_id) = any(%s) "
    "group by lower(source_instance_id)"
)
EVENTS = (
    "select max(created_at) as last_data_utc from collector_channel_runs "
    "where lower(server) = any(%s) and lower(channel) = any(%s) and inserted > 0"
)
TICK = "select id from report_schedules where enabled order by last_checked_at,id limit %s"


class QueryAdapterConsumersTest(unittest.TestCase):
    def setUp(self):
        # Never read config or connect to storage. Keep query_rows and _pg_sql real.
        self.addCleanup(patch.stopall)
        patch.object(database, "_require_runtime_db", return_value=None).start()
        patch.object(read_timeout, "remaining_read_ms", return_value=None).start()
        self.connection = patch.object(postgres_runtime_pipeline, "connect").start()
        self.connection.side_effect = AssertionError("unexpected database access")
        self.direct = patch.object(outbox, "connect").start()
        self.direct.side_effect = AssertionError("unexpected direct database access")
        self.release = patch.object(report_schedules, "release").start()
        self.release.side_effect = AssertionError("unexpected schedule release")

    def store(self, *expected):
        store = Store(*expected)
        self.connection.side_effect = None
        self.connection.return_value = store
        return store

    def test_journal_empty(self):
        store = self.store((JOURNAL + " order by id desc limit %s", (51,), []))
        self.assertEqual(outbox.journal_rows(), ([], False))
        self.assertEqual(store.expected, [])

    def test_journal_first_page_and_enrichment(self):
        row = dict.fromkeys(outbox.JOB_FIELDS)
        row.update(id="job", object_id="run", object_kind="report_schedule")
        store = self.store(
            (JOURNAL + " order by id desc limit %s", (2,), [row, row]),
            ("select id,period_from,period_to,quality from report_schedule_runs where id=any(%s::uuid[])",
             (["run"],), [{"id": "run", "quality": "complete"}]),
        )
        rows, more = outbox.journal_rows(limit=1)
        self.assertEqual(len(rows), 1)
        self.assertTrue(more)
        self.assertEqual(rows[0]["quality"], "complete")
        self.assertEqual(store.expected, [])

    def test_journal_cursor_and_max_limit(self):
        before = "00000000-0000-0000-0000-000000000001"
        store = self.store((JOURNAL + " where id<%s order by id desc limit %s", (before, 201), []))
        self.assertEqual(outbox.journal_rows(before=before, limit=200), ([], False))
        self.assertEqual(store.expected, [])

    def test_journal_invalid_inputs_do_not_query(self):
        for limit in (0, 201, True, "1"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                outbox.journal_rows(limit=limit)
        with self.assertRaises(ValueError):
            outbox.journal_rows(before="invalid")
        self.connection.assert_not_called()

    def test_tick_empty_selection(self):
        store = self.store((TICK, (7,), []))
        report_schedules.tick(limit=7)
        self.assertEqual(store.expected, [])
        self.release.assert_not_called()
        self.direct.assert_not_called()

    def test_tick_selection_and_direct_cursor_binds(self):
        store = self.store((TICK, (2,), [{"id": "first"}, {"id": "second"}]))
        direct = Store(*[
            ("update report_schedules set last_checked_at=clock_timestamp() where id=%s", (key,), [])
            for key in ("first", "second")
        ])
        self.direct.side_effect = None
        self.direct.return_value = direct
        self.release.side_effect = [PermissionError("denied"), True]
        report_schedules.tick(limit=2)
        self.assertEqual([call.args for call in self.release.call_args_list], [("first",), ("second",)])
        self.assertEqual(direct.commits, 2)
        self.assertEqual(store.expected + direct.expected, [])

    def test_reader_storage_failure_propagates(self):
        for sql, params, invoke in (
            (JOURNAL + " order by id desc limit %s", (51,), outbox.journal_rows),
            (TICK, (50,), report_schedules.tick),
        ):
            with self.subTest(sql=sql):
                self.store((sql, params, OSError("storage unavailable")))
                with self.assertRaisesRegex(OSError, "storage unavailable"):
                    invoke()
        self.release.assert_not_called()

    def test_remote_evidence_without_target(self):
        store = self.store((EVIDENCE, (["vpn"],), [
            {"source_instance_id": "VPN", "last_data_utc": "2026-01-01T00:00:00Z"},
        ]))
        self.assertEqual(setup.source_data({}, [{"source_instance_id": "VPN"}]),
                         {"vpn": "2026-01-01T00:00:00Z"})
        self.assertEqual(store.expected, [])

    def test_remote_combines_evidence_and_channel_arrivals(self):
        store = self.store(
            (EVIDENCE, (["vpn"],), [{"source_instance_id": "VPN", "last_data_utc": "2026-01-01T00:00:00Z"}]),
            (EVENTS, (["host"], ["security", "nps"]), [{"last_data_utc": "2026-01-02T00:00:00Z"}]),
        )
        result = setup.source_data({"channels": ["Security", "NPS"]}, [
            {"source_instance_id": "VPN", "collection_target": "HOST"},
        ])
        self.assertEqual(result, {"vpn": datetime(2026, 1, 2, tzinfo=timezone.utc)})
        self.assertEqual(store.expected, [])

    def test_remote_empty_instances_and_channels(self):
        store = self.store((EVIDENCE, ([],), []))
        self.assertEqual(setup.source_data({}, []), {})
        self.assertEqual(store.expected, [])
        store = self.store((EVIDENCE, (["vpn"],), []), (EVENTS, (["host"], []), [{"last_data_utc": None}]))
        self.assertEqual(setup.source_data({}, [{"source_instance_id": "VPN", "collection_target": "HOST"}]),
                         {"vpn": None})
        self.assertEqual(store.expected, [])

    def test_remote_storage_failure_stays_unavailable(self):
        store = self.store((EVIDENCE, (["vpn"],), OSError("storage unavailable")))
        self.assertEqual(setup.source_data({}, [{"source_instance_id": "VPN"}]), {"vpn": "unavailable"})
        self.assertEqual(store.expected, [])
        store = self.store((EVIDENCE, (["vpn"],), []), (EVENTS, (["host"], []), OSError("storage unavailable")))
        self.assertEqual(setup.source_data({}, [{"source_instance_id": "VPN", "collection_target": "HOST"}]),
                         {"vpn": "unavailable"})
        self.assertEqual(store.expected, [])

    def test_generic_setup_source_arrivals(self):
        sql = (
            "select lower(server) as source_instance_id, max(created_at) as last_data_utc "
            "from collector_channel_runs where lower(server) = any(%s) and lower(channel) = any(%s) "
            "and inserted > 0 group by lower(server)"
        )
        pack = {"pack_id": "synthetic.generic", "source_kind": "event", "channels": ["Security"]}
        store = self.store((sql, (["host"], ["security"]), [
            {"source_instance_id": "HOST", "last_data_utc": "2026-01-01T00:00:00Z"},
        ]))
        self.assertEqual(setup_status._source_data(pack, [{"source_instance_id": "HOST"}]),
                         {"host": "2026-01-01T00:00:00Z"})
        self.assertEqual(store.expected, [])
        self.assertEqual(setup_status._source_data(pack, []), {})
        self.assertEqual(len(store.calls), 1)
        self.store((sql, (["host"], ["security"]), OSError("storage unavailable")))
        with self.assertRaisesRegex(OSError, "storage unavailable"):
            setup_status._source_data(pack, [{"source_instance_id": "HOST"}])

    def test_safe_does_not_hide_successful_empty_read(self):
        self.assertEqual(setup_status._safe(lambda: []), [])


if __name__ == "__main__":
    unittest.main()
