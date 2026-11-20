"""Deep-query contract and optional PostgreSQL CTE integration, synthetic data only."""
from __future__ import annotations

import ast
import base64
import json
from datetime import datetime, timezone
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_functions(path, names=None, namespace=None):
    # Avoid bootstrapping the application/configuration for this isolated test.
    tree = ast.parse((ROOT / path).read_text())
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
             and (names is None or node.name in names)]
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0), *nodes], type_ignores=[])
    result = namespace or {}
    exec(compile(ast.fix_missing_locations(module), str(path), "exec"), result)
    return result


def query_fixture(query_rows):
    sql = load_functions("server/sli/events/event_search_sql.py", namespace={
        "AUTHENTICATION_EVENT_IDS": {4624}, "ACCOUNT_MANAGEMENT_EVENT_IDS": {4720},
        "PRIVILEGE_MANAGEMENT_EVENT_IDS": {4672}, "POLICY_CHANGE_EVENT_IDS": {4719},
        "SERVICE_TASK_EVENT_IDS": {4698},
    })
    src = SimpleNamespace(**{key: value for key, value in sql.items() if key.startswith("_")})
    src._database = SimpleNamespace(query_rows_bounded=query_rows)
    src.StorageV2RuntimeReader = Mock()
    src.StorageV2RuntimeReader.return_value.deep_search_candidates.return_value = []
    src.PostgresStorageV2ReadStore = Mock()
    src.ArchiveReader = Mock()
    src.PostgresArchiveManifestStore = Mock()
    query = load_functions("server/sli/events/event_search_readers.py", {"_query_v2_deep_archive_rows"}, {"_src": src})["_query_v2_deep_archive_rows"]
    return query, src


class DeepQueryTest(unittest.TestCase):
    def test_provider_and_every_predicate_are_retained(self):
        database = Mock(return_value=[])
        query, _ = query_fixture(database)
        filters = dict(q="needle", account="alice", channel="Security", provider="ProviderA",
                       servers=["A"], event_ids=[4624], subject="bob", target="eve",
                       time_from="2026-10-20T00:00:00Z", time_to="2026-10-21T00:00:00Z",
                       order="asc", cursor_values=dict(time="2026-10-20T01:00:00Z", record=0, id=100))
        self.assertEqual(query(filters, 2, 1000), [])
        sql, params = database.call_args.args
        for clause in ("left join storage_v2_provider provider on provider.id=e.provider_id",
                       "channel.value = ?", "lower(coalesce(provider.value, '')) = lower(?)",
                       "s.hostname in (?)", "e.event_id in (?)", "e.time_created_utc >= ?",
                       "e.time_created_utc < ?", "e.id > ?", "e.subject_user_name", "e.target_user_name",
                       "order by e.time_created_utc asc,coalesce(e.event_record_id,-1) asc,e.id asc limit ?"):
            self.assertIn(clause, sql)
        self.assertEqual(params[-1], 10001)
        self.assertNotIn("needle", params)
        self.assertNotIn("alice", params)

    def test_candidate_overflow_is_explicit_before_archive_reads(self):
        database = Mock(return_value=[{"id": i} for i in range(10001)])
        query, src = query_fixture(database)
        with self.assertRaisesRegex(ValueError, "candidate limit; narrow"):
            query(dict(q="needle", order="desc"), 2, 1000)
        src.StorageV2RuntimeReader.assert_not_called()

    def test_cursor_roundtrip_preserves_zero_and_null_record_keys(self):
        functions = load_functions("server/sli/events/event_search_filters.py", {
            "encode_search_cursor", "decode_search_cursor", "_cursor_scalar",
        }, dict(base64=base64, json=json, datetime=datetime, timezone=timezone))
        for record, expected in [(0, 0), (None, -1), (7, 7)]:
            with self.subTest(record=record):
                cursor = functions["encode_search_cursor"]({
                    "id": 100, "event_record_id": record,
                    "time_created_utc": "2026-10-20T00:00:50Z",
                })
                raw = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
                self.assertEqual(raw["record"], expected)
                self.assertEqual(functions["decode_search_cursor"](cursor)["record"], expected)

    def test_exact_metadata_handoff_uses_one_query_and_account_contract(self):
        rows = [{"id": 100, "server": "A"}, {"id": 102, "server": "A"}]
        database = Mock(return_value=rows)
        query, src = query_fixture(database)
        runtime = src.StorageV2RuntimeReader.return_value
        runtime.deep_search_candidates.return_value = [{"id": 102, "server_id": 1}]
        with patch.dict("sys.modules", {
            "server.sli.core.postgres_runtime_pipeline": SimpleNamespace(connect=Mock()),
        }):
            result = query(dict(q="needle", account="DOMAIN\\alice", order="desc"), 1, 1000)
        self.assertEqual(result, [{"id": 102, "server_id": 1, "server": "A"}])
        self.assertEqual(database.call_count, 1)
        self.assertEqual(runtime.deep_search_candidates.call_args.kwargs, dict(
            term="needle", candidates=rows, max_blocks=8, max_results=1,
            account_values=["domain\\alice", "alice"],
        ))

    @pytest.mark.postgres_integration
    @unittest.skipUnless(os.environ.get("ADLOG_TEST_PG_DSN"), "requires disposable PostgreSQL CI DSN")
    def test_postgres_executes_real_filter_sql_on_interleaved_synthetic_rows(self):
        import psycopg
        from psycopg.rows import dict_row
        from server.sli.storage.storage_v2_archive import (
            ArchivePublisher, ArchiveReader, InMemoryArchiveManifestStore,
        )
        from server.sli.storage.storage_v2_runtime import StorageV2RuntimeReader

        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        manifest = InMemoryArchiveManifestStore()
        payloads = [
            dict(id=i, server_id=2 if i == 101 else 1, domain_id=1, log_source_id=1,
                 event_id=9999 if i == 101 else 4624, event_record_id=record,
                 time_created_utc=f"2026-10-20T00:00:{second:02d}Z", message_text="needle",
                 subject_user_name="bob" if i == 101 else "alice")
            for i, second, record in [(100, 50, 0), (101, 30, 101), (102, 10, None)]
        ]
        ArchivePublisher(Path(directory.name), manifest).publish_rows(
            archive_set_id=str(uuid4()), archive_kind="event", block_index=0, rows=payloads,
        )
        runtime = StorageV2RuntimeReader(Mock(), ArchiveReader(manifest))

        cte = """with servers(id,hostname) as (values (1,'A'),(2,'B')),
          storage_v2_channel(id,value) as (values (1,'Security'),(2,'Other')),
          storage_v2_provider(id,value) as (values (1,'ProviderA'),(2,'ProviderB')),
          events_v2_core(id,server_id,domain_id,log_source_id,event_id,time_created_utc,
                         event_record_id,channel_id,provider_id,subject_user_name,target_user_name) as (
            values (100,1,1,1,4624,'2026-10-20 00:00:50+00'::timestamptz,0,1,1,'alice',''),
                   (101,2,1,1,9999,'2026-10-20 00:00:30+00'::timestamptz,101,2,2,'bob',''),
                   (102,1,1,1,4624,'2026-10-20 00:00:10+00'::timestamptz,null,1,1,'alice','')) """
        with psycopg.connect(os.environ["ADLOG_TEST_PG_DSN"], row_factory=dict_row,
                             autocommit=False, connect_timeout=5) as connection:
            with connection.cursor() as cur:
                cur.execute("set transaction read only")
                cur.execute("set local statement_timeout = '5s'")
                captured = []

                def database(sql, params, **kwargs):
                    cur.execute(cte + sql.replace("?", "%s"), params)
                    rows = cur.fetchall()
                    captured.append(rows)
                    return rows

                query, src = query_fixture(database)
                src.StorageV2RuntimeReader.return_value = runtime
                pipeline = SimpleNamespace(connect=Mock())
                cases = [
                    ({"servers": ["A"]}, [100, 102]),
                    ({"provider": "providera"}, [100, 102]),
                    ({"channel": "Security"}, [100, 102]),
                    ({"event_ids": [4624]}, [100, 102]),
                    ({"time_from": "2026-10-20T00:00:40Z"}, [100]),
                    ({"time_to": "2026-10-20T00:00:20Z"}, [102]),
                    ({"servers": ["A"], "cursor_values": {"time": "2026-10-20T00:00:50Z", "record": 0, "id": 100}}, [102]),
                    ({"servers": ["A"], "order": "asc"}, [102, 100]),
                    ({"account": "alice", "provider": "ProviderA"}, [100, 102]),
                    ({"servers": ["A"], "order": "asc", "cursor_values": {"time": "2026-10-20T00:00:10Z", "record": -1, "id": 102}}, [100]),
                ]
                with patch.dict("sys.modules", {"server.sli.core.postgres_runtime_pipeline": pipeline}):
                    for extra, expected in cases:
                        with self.subTest(extra=extra):
                            result = query({"q": "needle", "order": "desc", **extra}, 2, 1000)
                            self.assertEqual([r["id"] for r in captured[-1]], expected)
                            self.assertEqual([r["id"] for r in result], expected)

                    # Equal timestamps force PostgreSQL to use both the NULL/0
                    # record key and the final ID tiebreaker. Continue using the
                    # actual returned row's encoded/decoded cursor on each page.
                    tied = [dict(payloads[0], id=i, event_record_id=record)
                            for i, record in [(200, None), (201, 0), (202, None), (203, 0)]]
                    ArchivePublisher(Path(directory.name), manifest).publish_rows(
                        archive_set_id=str(uuid4()), archive_kind="event", block_index=0, rows=tied,
                    )
                    cte = cte[:cte.index("            values (100")] + """
                        values (200,1,1,1,4624,'2026-10-20 00:00:50+00'::timestamptz,null,1,1,'alice',''),
                               (201,1,1,1,4624,'2026-10-20 00:00:50+00'::timestamptz,0,1,1,'alice',''),
                               (202,1,1,1,4624,'2026-10-20 00:00:50+00'::timestamptz,null,1,1,'alice',''),
                               (203,1,1,1,4624,'2026-10-20 00:00:50+00'::timestamptz,0,1,1,'alice','')) """
                    cursors = load_functions("server/sli/events/event_search_filters.py", {
                        "encode_search_cursor", "decode_search_cursor", "_cursor_scalar",
                    }, dict(base64=base64, json=json, datetime=datetime, timezone=timezone))
                    for order, expected in [("asc", [200, 202, 201, 203]),
                                            ("desc", [203, 201, 202, 200])]:
                        filters = {"q": "needle", "order": order, "servers": ["A"]}
                        for index, event_id in enumerate(expected):
                            with self.subTest(order=order, after=filters.get("cursor_values")):
                                result = query(filters, 1, 1000)
                                self.assertEqual([r["id"] for r in captured[-1]], expected[index:])
                                self.assertEqual([r["id"] for r in result], [event_id])
                                cursor = cursors["encode_search_cursor"](result[0])
                                filters["cursor_values"] = cursors["decode_search_cursor"](cursor)
                                self.assertEqual(filters["cursor_values"]["record"],
                                                 0 if event_id in (201, 203) else -1)
                        self.assertEqual(query(filters, 1, 1000), [])
                        self.assertEqual(captured[-1], [])


if __name__ == "__main__":
    unittest.main()
