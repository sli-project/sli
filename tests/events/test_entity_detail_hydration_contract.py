"""SQL-faithful hot-row contract tests; no database or archive IO."""
from contextlib import ExitStack
import re
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from server.sli.entities import entity_details as details


class EntityDetailHydrationContractTests(unittest.TestCase):
    def run_page(self, *, history=False, hot=True, cold=False, order="desc", archive=None):
        hot_row = {"entity_id": 7, "event_db_id": 101, "link_role": "actor",
                   "event_id": 4624, "server": "synthetic", "channel": "Security"}
        cold_row = {**hot_row, "event_db_id": 99, "confidence": 0.5}
        detail = {"entity_id": 7, "link_role": "actor", "confidence": 0.75,
                  "attributes_json": '{"field":"synthetic"}'}

        def query(sql, params):
            if "count(*)" in sql:
                return [{"count": int(hot)}]
            # Only return columns actually in the outer SELECT. A WHERE predicate
            # does not project entity_id, even though the fixture knows its value.
            projection = re.split(r"\bfrom\b", sql, maxsplit=1, flags=re.I)[0]
            names = [part.strip().split()[-1].split(".")[-1]
                     for part in re.sub(r"^\s*select\s+", "", projection, flags=re.I).split(",")]
            return [{name: hot_row.get(name) for name in names}] if hot else []

        def cold_read(_entity_id, _filters, *, offset, limit, **kwargs):
            return int(cold), [cold_row][offset:offset + limit] if cold else []

        with ExitStack() as stack:
            for name, value in {
                "resolve_storage_route": lambda **kwargs: None,
                "is_postgres_runtime_db": lambda: True,
                "primary_read_enabled": lambda: history,
                "_resolve_entity": lambda filters: {"id": 7},
                "query_rows": query,
                "log_event": lambda *args, **kwargs: None,
                "load_storage_policy": lambda: SimpleNamespace(db_retention_days=7),
                "_read_history_entity_links": cold_read,
            }.items():
                stack.enter_context(patch.object(details, name, value))
            reader = stack.enter_context(patch.object(
                details, "_read_v2_link_details",
                return_value={101: [detail]} if archive is None else archive,
            ))
            result = details.get_entity_detail_report_data(entity_id=7, limit=10, order=order)
            self.assertEqual(reader.call_count, int(hot))
            return result

    def test_hot_page_hydrates_exact_identity(self):
        result = self.run_page()
        self.assertEqual(result["items"][0]["confidence"], 0.75)
        self.assertEqual(result["items"][0]["link_attributes"], {"field": "synthetic"})

    def test_hot_history_hydrates_exact_identity(self):
        self.assertEqual(self.run_page(history=True)["items"][0]["confidence"], 0.75)

    def test_mixed_history_preserves_both_orders(self):
        for order, expected in [("asc", [99, 101]), ("desc", [101, 99])]:
            with self.subTest(order=order):
                result = self.run_page(history=True, cold=True, order=order)
                self.assertEqual([r["event_db_id"] for r in result["items"]], expected)
                self.assertEqual(result["total"], 2)

    def test_empty_and_cold_only_skip_archive(self):
        self.assertEqual(self.run_page(hot=False)["items"], [])
        self.assertEqual(self.run_page(history=True, hot=False)["items"], [])
        self.assertEqual(self.run_page(history=True, hot=False, cold=True)["items"][0]["event_db_id"], 99)

    def test_archive_identity_and_cardinality_remain_strict(self):
        good = {"entity_id": 7, "link_role": "actor", "confidence": 0.75}
        for archive in [{}, {101: [{**good, "entity_id": 8}]},
                        {101: [{**good, "link_role": "target"}]}, {101: [good, good]},
                        {102: [good]}]:
            for history in [False, True]:
                with self.subTest(archive=archive, history=history):
                    with self.assertRaises(details.ArchiveIntegrityError):
                        self.run_page(history=history, archive=archive)

    def test_foreign_details_do_not_override_exact_match(self):
        exact = {"entity_id": 7, "link_role": "actor", "confidence": 0.25}
        result = self.run_page(archive={101: [
            {**exact, "entity_id": 8, "confidence": 1},
            {**exact, "link_role": "target", "confidence": 1}, exact,
        ]})
        self.assertEqual(result["items"][0]["confidence"], 0.25)
