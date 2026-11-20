"""Synthetic function tests: no benchmark entrypoint, database or Docker execution."""

import ast
from contextlib import contextmanager, nullcontext
import hashlib
import gzip
import json
import math
from pathlib import Path
import socket
import sys
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/maintenance"


def functions(file, *names, **extras):
    tree = ast.parse((SCRIPTS / file).read_text())
    nodes = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name in names
    ]
    env = dict(
        contextmanager=contextmanager,
        Any=object,
        Path=Path,
        hashlib=hashlib,
        json=json,
        math=math,
        time=time,
        subprocess=subprocess,
        tempfile=tempfile,
        uuid=uuid,
        DATABASE="stage7",
        TABLE="events",
        ROOT=ROOT,
        **extras,
    )
    exec(compile(ast.Module(nodes, type_ignores=[]), str(SCRIPTS / file), "exec"), env)
    return SimpleNamespace(**env)


class EvidenceContracts(unittest.TestCase):
    def setUp(self):
        self.guards = [
            patch.object(
                subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")
            ),
            patch.object(
                socket, "socket", side_effect=AssertionError("network forbidden")
            ),
            patch.object(
                socket,
                "create_connection",
                side_effect=AssertionError("network forbidden"),
            ),
        ]
        for guard in self.guards:
            guard.start()
            self.addCleanup(guard.stop)

    def test_current_point_contract_is_validated_before_work(self):
        module = functions(
            "stage7_control_d_prime_benchmark.py", "_detail_latency_limits"
        )
        contract = json.loads(
            (ROOT / "config/stage7_storage_evaluation.json").read_text()
        )
        self.assertTrue(
            hasattr(module, "_detail_latency_limits"),
            "missing current-contract validation",
        )
        self.assertEqual(module._detail_latency_limits(contract), (25.0, 250.0))
        for value in (None, True, 0, -1, float("nan"), float("inf"), "25"):
            broken = json.loads(json.dumps(contract))
            broken["query_classes"]["point"]["warm_p95_ms_max"] = value
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                module._detail_latency_limits(broken)

    def test_detail_uses_its_own_channel(self):
        module = functions(
            "stage7_clickhouse_candidate_a.py", "_workloads", _sql_literal=repr
        )
        seeds = dict(
            event_id=1,
            server_id=1,
            channel="latest-channel",
            entity_id=8,
            detail_event_id=41,
            detail=dict(
                server_id=2, channel="detail-channel", event_id=3, event_record_id=4
            ),
        )
        query = module._workloads(seeds)["event_detail"]
        self.assertIn("channel='detail-channel'", query)
        self.assertNotIn("latest-channel", query)

    def test_detail_seed_resolves_selected_event_channel(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        cursor.fetchone.side_effect = [
            dict(value="latest-channel"),
            dict(channel_id=9),
            dict(value="detail-channel"),
        ]
        connection = SimpleNamespace(cursor=lambda: cursor)
        module = functions(
            "stage7_clickhouse_candidate_a.py",
            "_query_seed_values",
            _query_seeds=lambda _: dict(channel_id=7, detail_event_id=41),
        )
        seeds = module._query_seed_values(connection)
        self.assertEqual(seeds["detail"].get("channel"), "detail-channel")
        self.assertEqual(cursor.execute.call_args_list[-1].args[1], (9,))

    def test_a_rejects_stable_empty_detail(self):
        module = functions(
            "stage7_clickhouse_candidate_a.py",
            "_measure_queries",
            "_validate_detail_result",
            _workloads=lambda _: {"event_detail": "synthetic"},
            _http_query=lambda *_: b"",
            _p95=lambda x: x[0],
        )
        with self.assertRaisesRegex(RuntimeError, "detail"):
            module._measure_queries(
                1,
                {"detail_event_id": 41, "detail": {}},
                independent_runs=1,
                warmups=0,
                measured=1,
            )

    def test_volume_failure_cleans_only_successful_acquisitions(self):
        for file in (
            "stage7_clickhouse_candidate_a.py",
            "stage7_clickhouse_candidate_b.py",
        ):
            calls = []
            primary = RuntimeError("second create failed")

            def docker(args, **_):
                calls.append(args)
                if args[:2] == ["volume", "create"] and "backup" in args[2]:
                    raise primary
                return ""

            cleanup = Mock(return_value=SimpleNamespace(returncode=0, stderr=b""))
            fake_root = Mock()
            fake_root.__truediv__ = Mock(return_value=fake_root)
            fake_root.read_text.return_value = "{}"
            fake_root.resolve.return_value = fake_root
            env = dict(
                _load_contract=lambda: dict(canonical_corpus={}, performance_gates={}),
                _connect=lambda: nullcontext(object()),
                _published_blocks=lambda *_: [],
                _stream_contracts=lambda _: {},
                _query_seed_values=lambda _: {},
                _relation_sizes=lambda _: {},
                _docker=docker,
                _verify_snapshot_corpus=lambda *_: {},
            )
            env["_cleanup_owned_resources"] = functions(
                "stage7_clickhouse_candidate_a.py", "_cleanup_owned_resources"
            )._cleanup_owned_resources
            module = functions(file, "_run_candidate", **env)
            module._run_candidate.__globals__["ROOT"] = fake_root
            with self.subTest(file=file), patch.object(subprocess, "run", cleanup):
                with self.assertRaises(RuntimeError) as caught:
                    module._run_candidate(lambda: nullcontext(object()), {})
                self.assertIs(caught.exception, primary)
                self.assertEqual(cleanup.call_count, 1)
                removed = cleanup.call_args.args[0]
                self.assertEqual(removed[:3], ["docker", "volume", "rm"])
                self.assertEqual(removed[3:], [calls[0][2]])

    def test_timeline_projection_preserves_roles_and_order(self):
        seeds = dict(
            event_id=1,
            server_id=1,
            channel="c",
            entity_id=8,
            detail_event_id=41,
            detail=dict(server_id=2, channel="c", event_id=3, event_record_id=4),
        )
        for file in (
            "stage7_clickhouse_candidate_a.py",
            "stage7_clickhouse_candidate_b.py",
        ):
            module = functions(file, "_workloads", _sql_literal=repr)
            query = module._workloads(seeds)["entity_timeline"].lower()
            with self.subTest(file=file):
                self.assertIn(
                    "array join entity_ids as entity_id,entity_role_ids as role_id",
                    query,
                )
                self.assertIn("source_id as event_id,role_id", query)
                self.assertIn("order by source_id desc,role_id asc limit 100", query)
                self.assertNotIn("distinct", query)

    def test_timeline_integer_normalization_and_multiplicity(self):
        module = functions(
            "stage7_control_benchmark.py", "_normalize_timeline", "_digest_rows"
        )
        self.assertTrue(
            hasattr(module, "_normalize_timeline"),
            "missing portable timeline normalization",
        )
        rows = [
            {"event_id": "9", "role_id": "1"},
            {"event_id": 9, "role_id": 1},
            {"event_id": 8, "role_id": 2},
        ]
        normalized = module._normalize_timeline(rows)
        self.assertEqual(
            normalized,
            [
                {"event_id": 9, "role_id": 1},
                {"event_id": 9, "role_id": 1},
                {"event_id": 8, "role_id": 2},
            ],
        )
        for broken in (
            [{"event_id": 1, "role_id": True}],
            [{"event_id": 1.5, "role_id": 2}],
            [{"event_id": 8, "role_id": 2}, {"event_id": 9, "role_id": 1}],
            rows * 34,
        ):
            with (
                self.subTest(broken=broken),
                self.assertRaises((ValueError, RuntimeError)),
            ):
                module._normalize_timeline(broken)

    def test_timeline_preflight_rejects_unlike_answers_and_pairing(self):
        helper = functions(
            "stage7_control_benchmark.py", "_normalize_timeline", "_digest_rows"
        )
        reference = [{"event_id": 9, "role_id": 1}, {"event_id": 9, "role_id": 2}]
        for payload, bad_arrays in (
            (b'{"event_id":"9","role_id":"1"}\n', b"0"),
            (b"", b"1"),
        ):
            module = functions(
                "stage7_clickhouse_candidate_a.py",
                "_assert_timeline_parity",
                _normalize_timeline=getattr(helper, "_normalize_timeline", lambda x: x),
                _reference_timeline=lambda *_: reference,
                _http_query=Mock(side_effect=[bad_arrays, payload]),
            )
            self.assertTrue(
                hasattr(module, "_assert_timeline_parity"),
                "missing cross-engine preflight",
            )
            with self.assertRaisesRegex(RuntimeError, "timeline"):
                module._assert_timeline_parity(
                    1, {"entity_id": 8}, "query", connect=object(), table="events"
                )

    def test_cleanup_error_preserves_primary_and_attempts_all_owned_targets(self):
        module = functions(
            "stage7_clickhouse_candidate_a.py", "_cleanup_owned_resources"
        )
        with patch.object(
            subprocess,
            "run",
            side_effect=[
                OSError("container fail"),
                SimpleNamespace(returncode=1, stderr=b"volume removal diagnostic"),
            ],
        ) as run:
            failures = module._cleanup_owned_resources(
                "owned-container", ["owned-data"]
            )
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            [failure["target"] for failure in failures], ["container", "volumes"]
        )
        self.assertEqual(failures[1].get("error"), "volume removal diagnostic")

    def test_snapshot_imports_every_connection_and_keeps_exporter_open(self):
        connections = []

        class Connection:
            def __init__(self):
                self.closed = False
                self.statements = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                self.closed = True

            def execute(self, sql, params=None):
                self.statements.append((str(sql), params))
                return SimpleNamespace(
                    fetchone=lambda: {
                        "snapshot": "00000003-0000001B-1",
                        "identity": "synthetic-db",
                    }
                )

        def connect():
            conn = Connection()
            connections.append(conn)
            return conn

        module = functions("stage7_control_benchmark.py", "_exported_snapshot")
        self.assertTrue(
            hasattr(module, "_exported_snapshot"), "missing exported-snapshot binding"
        )
        with module._exported_snapshot(connect) as (bound, receipt):
            self.assertFalse(connections[0].closed)
            for _ in range(2):
                with bound() as conn:
                    self.assertIn("repeatable read", conn.statements[0][0].lower())
                    self.assertIn(
                        "set transaction snapshot", conn.statements[1][0].lower()
                    )
                    self.assertIn("00000003-0000001B-1", conn.statements[1][0])
            self.assertFalse(connections[0].closed)
            self.assertEqual(receipt["binding"], "exported_repeatable_read_read_only")
        self.assertTrue(all(conn.closed for conn in connections))

    def test_snapshot_closes_exporter_on_primary_failure(self):
        conn = Mock()
        conn.__enter__ = Mock(return_value=conn)
        conn.__exit__ = Mock(return_value=False)
        conn.execute.return_value.fetchone.return_value = {
            "snapshot": "00000003-0000001B-1",
            "identity": "db",
        }
        module = functions("stage7_control_benchmark.py", "_exported_snapshot")
        self.assertTrue(
            hasattr(module, "_exported_snapshot"), "missing exported-snapshot binding"
        )
        with self.assertRaisesRegex(RuntimeError, "primary"):
            with module._exported_snapshot(lambda: conn):
                raise RuntimeError("primary")
        conn.__exit__.assert_called_once()

    def test_detail_identity_rejects_wrong_source_even_when_one_row(self):
        module = functions(
            "stage7_clickhouse_candidate_a.py", "_validate_detail_result"
        )
        seeds = {
            "detail_event_id": 41,
            "detail": dict(server_id=2, channel="c", event_id=3, event_record_id=4),
        }
        payload = json.dumps(
            dict(
                source_id="40",
                server_id="2",
                channel="c",
                event_id="3",
                event_record_id="4",
            )
        ).encode()
        with self.assertRaisesRegex(RuntimeError, "identity"):
            module._validate_detail_result(payload, seeds)

    def test_b_validates_locator_identity_before_accepting_detail(self):
        reader = SimpleNamespace(read_event=lambda _: {"id": 41}, close=lambda: None)
        validator = Mock(side_effect=RuntimeError("detail identity mismatch"))
        module = functions(
            "stage7_clickhouse_candidate_b.py",
            "_measure_detail",
            FramedArchiveReader=lambda *_: reader,
            _http_query=lambda *_: b'{"source_id":40}\n',
            _validate_detail_result=validator,
            _digest_rows=lambda _: "hash",
            _sql_literal=repr,
            _p95=lambda _: 0,
        )
        with self.assertRaisesRegex(RuntimeError, "identity"):
            module._measure_detail(
                1,
                dict(
                    detail_event_id=41,
                    detail=dict(
                        server_id=2, channel="c", event_id=3, event_record_id=4
                    ),
                ),
                data_path=Path("synthetic"),
                index_path=Path("synthetic"),
                independent_runs=1,
                warmups=0,
                measured=1,
            )

    def test_fresh_snapshot_identity_rejects_stale_core_or_archive_links(self):
        row = dict(
            id=41,
            server_id=2,
            channel="c",
            event_record_id=3,
            time_created_utc="synthetic",
            normalized_hash="A",
        )

        class Cursor:
            def __init__(self, rows):
                self.rows = rows

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def execute(self, *_):
                pass

            def __iter__(self):
                return iter(self.rows)

            def fetchall(self):
                return self.rows

        blocks = [
            SimpleNamespace(
                archive_kind="event", public_dict=lambda: {"kind": "event"}
            ),
            SimpleNamespace(
                archive_kind="link_detail", public_dict=lambda: {"kind": "link"}
            ),
        ]
        archived_link = {"event_id": 41, "entity_id": 8, "role_id": 1}

        def cursor(name=None):
            if name == "stage7_snapshot_identity":
                return Cursor([row])
            if name == "stage7_snapshot_links":
                return Cursor([dict(archived_link, role_id=1)])
            return Cursor([{"block": block} for block in blocks])

        connection = SimpleNamespace(cursor=cursor)

        class Reader:
            def __init__(self, _):
                pass

            def read_block_rows(self, block):
                return [row] if block.archive_kind == "event" else [archived_link]

        module = functions(
            "stage7_control_benchmark.py",
            "_verify_snapshot_corpus",
            "_digest_rows",
            ArchiveReader=Reader,
            PostgresArchiveManifestStore=SimpleNamespace(
                _from_row=lambda x: x["block"]
            ),
        )
        streams = {
            (2, "c"): dict(source_instance_uid="s", stream_uid="t", log_epoch_uid="e")
        }
        injected = {
            "scripts.maintenance.stage7_clickhouse_candidate_a": SimpleNamespace(
                _stream_contracts=lambda _: streams
            ),
            "scripts.maintenance.stage7_event_identity": SimpleNamespace(
                event_uid=lambda **kw: "uid-" + kw["normalized_sha256"]
            ),
        }
        expected = dict(
            events=1,
            event_uid_sequence_sha256=hashlib.sha256(b"uid-A\n").hexdigest(),
            archive_blocks=2,
            archive_rows=2,
            event_entity_links=1,
        )
        with patch.dict(sys.modules, injected):
            good = module._verify_snapshot_corpus(connection, expected)
            self.assertEqual(good["events"], 1)
            stale = dict(expected, event_uid_sequence_sha256="historical")
            with self.assertRaisesRegex(RuntimeError, "canonical"):
                module._verify_snapshot_corpus(connection, stale)
            archived_link["role_id"] = 2
            with self.assertRaisesRegex(RuntimeError, "link"):
                module._verify_snapshot_corpus(connection, expected)

    def test_snapshot_refuses_reuse_after_scope_and_wrong_database(self):
        class Connection:
            def __init__(self, identity):
                self.identity = identity

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def execute(self, *_):
                return SimpleNamespace(
                    fetchone=lambda: dict(
                        identity=self.identity, snapshot="00000003-0000001B-1"
                    )
                )

        connections = iter([Connection("one-db"), Connection("other-db")])
        module = functions("stage7_control_benchmark.py", "_exported_snapshot")
        with module._exported_snapshot(lambda: next(connections)) as (bound, _):
            with self.assertRaisesRegex(RuntimeError, "database identity"):
                with bound():
                    pass
        with self.assertRaisesRegex(RuntimeError, "no longer active"):
            with bound():
                pass

    def test_all_entrypoints_pass_explicit_live_snapshot_factory(self):
        for file in (
            "stage7_control_benchmark.py",
            "stage7_clickhouse_candidate_a.py",
            "stage7_clickhouse_candidate_b.py",
            "stage7_control_d_prime_benchmark.py",
        ):
            state = {"active": False}
            bound = object()

            @contextmanager
            def exported(_):
                state["active"] = True
                try:
                    yield bound, {"receipt": "synthetic"}
                finally:
                    state["active"] = False

            def measurement(*args):
                self.assertTrue(state["active"])
                self.assertIs(args[-2], bound)
                return {"assembled": True}

            module = functions(
                file,
                "run",
                _exported_snapshot=exported,
                _snapshot_source=lambda: object(),
                _run_snapshot=measurement,
                _run_candidate=measurement,
                _load_contract=lambda: {},
                _detail_latency_limits=lambda _: None,
            )
            with self.subTest(file=file):
                result = module.run([512]) if "prime" in file else module.run()
                self.assertEqual(result, {"assembled": True})
                self.assertFalse(state["active"])

    def test_b_early_temp_and_frame_failures_remove_both_owned_volumes(self):
        for stage in ("temporary", "builder", "source"):
            primary = RuntimeError("synthetic " + stage + " failed")
            fake_root = Mock()
            fake_root.__truediv__ = Mock(return_value=fake_root)
            fake_root.read_text.return_value = "{}"
            fake_root.resolve.return_value = fake_root

            class Builder:
                def __init__(self, **_):
                    if stage == "builder":
                        raise primary

            @contextmanager
            def temporary(**_):
                if stage == "temporary":
                    raise primary
                yield "/tmp/synthetic-not-read"

            def source(*_):
                raise primary

            cleanup = Mock(return_value=SimpleNamespace(returncode=0))
            env = dict(
                _load_contract=lambda: dict(canonical_corpus={}, performance_gates={}),
                _verify_snapshot_corpus=lambda *_: {},
                _published_blocks=lambda *_: [],
                _stream_contracts=lambda _: {},
                _query_seed_values=lambda _: {},
                _relation_sizes=lambda _: {},
                _docker=lambda *_: "",
                RAW_FRAME_ROWS=512,
                FramedArchiveBuilder=Builder,
                _stream_source_into_builders=source,
                _cleanup_owned_resources=functions(
                    "stage7_clickhouse_candidate_a.py", "_cleanup_owned_resources"
                )._cleanup_owned_resources,
            )
            module = functions(
                "stage7_clickhouse_candidate_b.py", "_run_candidate", **env
            )
            module._run_candidate.__globals__["ROOT"] = fake_root
            module._run_candidate.__globals__["tempfile"] = SimpleNamespace(
                TemporaryDirectory=temporary
            )
            with self.subTest(stage=stage), patch.object(subprocess, "run", cleanup):
                with self.assertRaises(RuntimeError) as caught:
                    module._run_candidate(lambda: nullcontext(object()), {})
                self.assertIs(caught.exception, primary)
                targets = cleanup.call_args.args[0]
                self.assertEqual(targets[:3], ["docker", "volume", "rm"])
                self.assertEqual(len(targets[3:]), 2)
                self.assertTrue(
                    all(target.startswith("sli-stage7-b-") for target in targets[3:])
                )

    def test_existing_archive_reader_rechecks_pinned_content_on_each_read(self):
        # Exercise the exact unchanged verifier method using only synthetic bytes.
        path = ROOT / "server/sli/storage/storage_v2_archive.py"
        tree = ast.parse(path.read_bytes())
        method = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_read_verified_block"
        )
        env = dict(
            Path=Path,
            gzip=gzip,
            ArchiveBlock=object,
            ArchiveIntegrityError=RuntimeError,
            ArchiveObjectUnavailableError=RuntimeError,
            _sha256=lambda data: hashlib.sha256(data).hexdigest().upper(),
        )
        exec(compile(ast.Module([method], type_ignores=[]), str(path), "exec"), env)
        raw = b'{"kind":"event","row":{"id":41}}\n'
        compressed = gzip.compress(raw)
        with tempfile.TemporaryDirectory(
            prefix="synthetic-stage7-verifier-"
        ) as directory:
            file = Path(directory) / "synthetic.gz"
            file.write_bytes(compressed)
            block = SimpleNamespace(
                state="published",
                object_location=str(file),
                compressed_bytes=len(compressed),
                raw_bytes=len(raw),
                archive_sha256=hashlib.sha256(compressed).hexdigest().upper(),
                raw_sha256=hashlib.sha256(raw).hexdigest().upper(),
            )
            reader = SimpleNamespace(archive_root=None)
            self.assertEqual(env["_read_verified_block"](reader, block), raw)
            file.write_bytes(bytes([compressed[0] ^ 1]) + compressed[1:])
            with self.assertRaisesRegex(RuntimeError, "compressed SHA-256"):
                env["_read_verified_block"](reader, block)

    def test_timeline_preflight_uses_candidate_b_table(self):
        helper = functions("stage7_control_benchmark.py", "_normalize_timeline")
        query = Mock(side_effect=[b"0\n", b'{"event_id":"9","role_id":"1"}\n'])
        module = functions(
            "stage7_clickhouse_candidate_a.py",
            "_assert_timeline_parity",
            _normalize_timeline=helper._normalize_timeline,
            _reference_timeline=lambda *_: [{"event_id": 9, "role_id": 1}],
            _http_query=query,
        )
        result = module._assert_timeline_parity(
            1, {"entity_id": 8}, "timeline", connect=object(), table="events_b"
        )
        self.assertIn("stage7.events_b", query.call_args_list[0].args[1])
        self.assertEqual(result, [{"event_id": 9, "role_id": 1}])

    def test_physical_sizes_are_explicitly_not_claimed_snapshot_isolated(self):
        cursor = Mock()
        cursor.__enter__ = Mock(return_value=cursor)
        cursor.__exit__ = Mock(return_value=False)
        cursor.fetchall.return_value = [
            {"table_name": "events_v2_core", "total_bytes": 100}
        ]
        cursor.fetchone.return_value = {"archive_bytes": 20}
        module = functions(
            "stage7_control_benchmark.py",
            "_relation_sizes",
            CONTROL_TABLES={"events_v2_core"},
            LEGACY_DATA_TABLES=set(),
        )
        result = module._relation_sizes(SimpleNamespace(cursor=lambda: cursor))
        self.assertEqual(
            result.get("postgresql_physical_size_scope"),
            "live_files_not_mvcc_snapshot_isolated",
        )

    def test_unbound_physical_numbers_cannot_select_a_variant(self):
        module = functions("stage7_control_d_prime_benchmark.py", "_select_variant")
        variant = dict(
            id="synthetic",
            semantic_parity=True,
            storage={"projected_live_bytes": 100},
            event_detail_benchmark={"warm_p95_ms": 1, "cold_p95_ms": 2},
        )
        self.assertIsNone(
            module._select_variant([variant], warm_limit_ms=25, cold_limit_ms=250)
        )
        variant["storage"]["postgresql_physical_size_scope"] = (
            "live_files_not_mvcc_snapshot_isolated"
        )
        self.assertIsNone(
            module._select_variant([variant], warm_limit_ms=25, cold_limit_ms=250)
        )

    def test_private_framing_choice_ignores_unbound_projected_totals(self):
        module = functions("stage7_control_d_prime_benchmark.py", "_select_variant")

        def variant(name, private, projected, warm=1):
            return dict(
                id=name,
                semantic_parity=True,
                storage={
                    "event_archive_and_index_bytes": private,
                    "projected_live_bytes": projected,
                    "postgresql_physical_size_scope": "live_files_not_mvcc_snapshot_isolated",
                },
                event_detail_benchmark={"warm_p95_ms": warm, "cold_p95_ms": 2},
            )

        compact = variant("compact", 100, 999999)
        larger = variant("larger", 200, 1)
        selected = module._select_variant(
            [larger, compact], warm_limit_ms=25, cold_limit_ms=250
        )
        self.assertIs(selected, compact)
        compact["storage"]["projected_live_bytes"] = -999999999
        larger["storage"]["projected_live_bytes"] = 10**30
        self.assertIs(
            module._select_variant(
                [compact, larger], warm_limit_ms=25, cold_limit_ms=250
            ),
            compact,
        )
        for invalid in (None, True, False, 0, -1, 1.5, "1"):
            bad = variant("bad", invalid, -1)
            with self.subTest(invalid=invalid):
                self.assertIsNone(
                    module._select_variant([bad], warm_limit_ms=25, cold_limit_ms=250)
                )
        tie = variant("a-tie", 100, 0)
        self.assertIs(
            module._select_variant([compact, tie], warm_limit_ms=25, cold_limit_ms=250),
            tie,
        )
        self.assertIs(
            module._select_variant([tie, compact], warm_limit_ms=25, cold_limit_ms=250),
            tie,
        )
        fast = variant("z-fast", 100, 0, warm=0.5)
        self.assertIs(
            module._select_variant([tie, fast], warm_limit_ms=25, cold_limit_ms=250),
            fast,
        )
        too_slow = variant("slow", 1, 0, warm=30)
        self.assertIsNone(
            module._select_variant([too_slow], warm_limit_ms=25, cold_limit_ms=250)
        )
        compact["semantic_parity"] = False
        self.assertIsNone(
            module._select_variant([compact], warm_limit_ms=25, cold_limit_ms=250)
        )

    def test_acceptance_size_fields_remain_unknown_while_diagnostics_are_kept(self):
        for file in (
            "stage7_clickhouse_candidate_a.py",
            "stage7_clickhouse_candidate_b.py",
        ):
            tree = ast.parse((SCRIPTS / file).read_bytes())
            storage = next(
                value
                for node in ast.walk(tree)
                if isinstance(node, ast.Dict)
                for key, value in zip(node.keys, node.values)
                if isinstance(key, ast.Constant)
                and key.value == "storage"
                and isinstance(value, ast.Dict)
            )
            fields = {
                key.value: value
                for key, value in zip(storage.keys, storage.values)
                if isinstance(key, ast.Constant)
            }
            with self.subTest(file=file):
                self.assertIsInstance(
                    fields["full_managed_storage_bytes_without_event_registry"],
                    ast.Constant,
                )
                self.assertIsNone(
                    fields["full_managed_storage_bytes_without_event_registry"].value
                )
                self.assertIn(
                    "diagnostic_live_file_full_managed_storage_bytes_without_event_registry",
                    fields,
                )


if __name__ == "__main__":
    unittest.main()
