"""Offline ownership regressions; no opt-in, Docker, database or HTTP required."""
from __future__ import annotations

import ast
import copy
import importlib.util
import json
from pathlib import Path
import types
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


def load_guard():
    path = HERE / "stage6s_disposable.py"
    spec = importlib.util.spec_from_file_location("stage6s_disposable", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WiringTests(unittest.TestCase):
    def test_no_preliminary_drop_or_inherited_endpoint_guard(self):
        tree = ast.parse((HERE / "test_stage6s_multi_capture_disposable_e2e.py").read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(n.func, ast.Attribute) and n.func.attr == "_drop_database" for n in calls))
        self.assertFalse(any(isinstance(n, ast.FunctionDef) and n.name == "_guarded_environment" for n in ast.walk(tree)))


class FakeDocker:
    def __init__(self, guard):
        self.guard = guard
        self.records = {}
        self.calls = []
        self.corrupt = None
        self.fail_create = False

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "create":
            if self.fail_create:
                raise RuntimeError("synthetic create failure")
            cid = format(len(self.records) + 1, "064x")
            image = args[-1]
            kind = "ch" if image == self.guard.CH_IMAGE else "pg"
            port = "8123/tcp" if kind == "ch" else "5432/tcp"
            label = args[args.index("--label") + 1].split("=", 1)[1]
            self.records[cid] = {
                "Id": cid, "Config": {"Image": image, "Labels": {self.guard.LABEL: label}},
                "State": {"Running": False},
                "HostConfig": {"NetworkMode": "bridge"},
                "Mounts": [{"Type": "tmpfs", "Destination": p} for p in self.guard.MOUNTS[kind]],
                "NetworkSettings": {"Ports": {port: [{"HostIp": "127.0.0.1", "HostPort": str(20000 + len(self.records))}]}},
            }
            return cid
        cid = args[-1]
        if args[0] == "inspect":
            record = copy.deepcopy(self.records[cid])
            if self.corrupt:
                self.corrupt(record)
            return json.dumps([record])
        if args[0] == "start":
            self.records[cid]["State"]["Running"] = True
            return cid
        if args[0] == "rm":
            del self.records[cid]
            return cid
        raise AssertionError(args)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict("os.environ", {"SLI_STAGE6S_DISPOSABLE_E2E": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.g = load_guard()
        self.docker = FakeDocker(self.g)

    def test_two_runs_have_distinct_labels_and_ids_and_owned_cleanup(self):
        with self.g.owned_resources(self.docker) as first:
            with self.g.owned_resources(self.docker) as second:
                self.assertNotEqual(first.run_id, second.run_id)
                self.assertNotEqual(first.ch_id, second.ch_id)
                self.assertNotEqual(first.pg_id, second.pg_id)
                self.assertIn("host=127.0.0.1", first.pg_dsn)
                self.assertIn("sslmode=disable", first.pg_dsn)
                self.assertEqual(first.ch_host, "127.0.0.1")
        self.assertFalse(self.docker.records)
        removed = [a[-1] for a in self.docker.calls if a[0] == "rm"]
        self.assertCountEqual(removed, [first.ch_id, first.pg_id, second.ch_id, second.pg_id])

    def test_bad_inspect_never_reaches_consumer(self):
        corruptions = [
            lambda r: r.update(Id="f" * 64),
            lambda r: r["Config"]["Labels"].clear(),
            lambda r: r["Config"].update(Image="foreign:latest"),
            lambda r: r["HostConfig"].update(NetworkMode="host"),
            lambda r: r.update(Mounts=[{"Type": "bind", "Destination": "/data"}]),
            lambda r: r["NetworkSettings"].update(Ports={"8123/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8123"}]}),
            lambda r: r["NetworkSettings"].update(Ports={"8123/tcp": [{"HostIp": "127.0.0.1", "HostPort": "bad"}]}),
            lambda r: r["State"].update(Running="yes"),
            lambda r: r["NetworkSettings"].update(Ports={"8123/tcp": [{"HostIp": "127.0.0.1", "HostPort": "65536"}]}),
            lambda r: r["NetworkSettings"].update(Ports={"8123/tcp": [{"HostIp": "127.0.0.1", "HostPort": "0"}]}),
            lambda r: r["NetworkSettings"].update(Ports={"8123/tcp": []}),
            lambda r: r.clear(),
        ]
        for corrupt in corruptions:
            with self.subTest(corrupt=corrupt):
                docker = FakeDocker(self.g)
                docker.corrupt = corrupt
                consumer = Mock()
                with self.assertRaisesRegex(RuntimeError, "ownership"):
                    with self.g.owned_resources(docker) as resource:
                        consumer(resource)  # The first possible HTTP / DDL boundary.
                consumer.assert_not_called()
                self.assertFalse(any(a[0] == "rm" for a in docker.calls))

    def test_failed_create_does_not_probe_or_cleanup(self):
        self.docker.fail_create = True
        consumer = Mock()
        with self.assertRaises(RuntimeError):
            with self.g.owned_resources(self.docker) as resource:
                consumer(resource)
        consumer.assert_not_called()
        self.assertEqual([a[0] for a in self.docker.calls], ["create"])

    def test_cleanup_refuses_changed_label(self):
        with self.assertRaisesRegex(RuntimeError, "cleanup"):
            with self.g.owned_resources(self.docker) as resource:
                self.docker.records[resource.ch_id]["Config"]["Labels"].clear()
        removed = [a[-1] for a in self.docker.calls if a[0] == "rm"]
        self.assertEqual(removed, [resource.pg_id])

    def test_postgres_mismatch_prevents_all_probes_and_keeps_foreign_id(self):
        def docker(args):
            result = self.docker(args)
            if args[0] == "inspect":
                rows = json.loads(result)
                if rows[0]["Config"]["Image"] == self.g.PG_IMAGE:
                    rows[0]["Config"]["Labels"].clear()
                    return json.dumps(rows)
            return result
        consumer = Mock()
        with self.assertRaisesRegex(RuntimeError, "ownership"):
            with self.g.owned_resources(docker) as resource:
                consumer(resource)
        consumer.assert_not_called()
        self.assertEqual([a[-1] for a in self.docker.calls if a[0] == "rm"], ["0" * 63 + "1"])
        self.assertEqual(list(self.docker.records), ["0" * 63 + "2"])

    def test_second_create_failure_cleans_only_proven_first_resource(self):
        def docker(args):
            if args[0] == "create" and self.docker.records:
                raise RuntimeError("second create failed")
            return self.docker(args)
        with self.assertRaisesRegex(RuntimeError, "create_failed_resources_may_remain"):
            with self.g.owned_resources(docker):
                self.fail("unexpected resource")
        self.assertEqual([a[-1] for a in self.docker.calls if a[0] == "rm"], ["0" * 63 + "1"])

    def test_pinned_boundaries_ignore_hostile_environment_and_repeat_resolution(self):
        with self.g.owned_resources(self.docker) as resource:
            query = Mock(return_value=b"ok")
            io = types.SimpleNamespace(_http_query=query, _container_port=Mock(), CONTAINER="warm")
            alias = types.SimpleNamespace(_http_query=query, _container_port=io._container_port, CONTAINER="warm")
            class Patcher:
                def setattr(self, obj, name, value):
                    setattr(obj, name, value)
            env = {"ADLOG_WARM_CLICKHOUSE_HOST": "production.invalid", "ADLOG_WARM_CLICKHOUSE_PASSWORD_FILE": "/never/read", "SLI_STAGE6S_DISPOSABLE_CH_PORT": "8123", "SLI_STAGE6S_DISPOSABLE_PG_DSN": "host=production.invalid", "DOCKER_HOST": "tcp://production.invalid", "DOCKER_CONTEXT": "production"}
            with patch.dict("os.environ", env), patch.object(Path, "read_text", side_effect=AssertionError("credential read")):
                self.g.pin_clickhouse(Patcher(), resource, io, alias)
                for _ in range(3):
                    self.assertEqual(io._container_port(io.CONTAINER), resource.ch_port)
                    self.assertEqual(alias._container_port(alias.CONTAINER), resource.ch_port)
                    alias._http_query(resource.ch_port, "SELECT 1")
                with self.assertRaises(RuntimeError):
                    io._container_port("foreign")
                with self.assertRaises(RuntimeError):
                    alias._http_query(8123, "DROP DATABASE sli_warm")
            self.assertEqual(query.call_count, 3)
            for call in query.call_args_list:
                self.assertEqual(call.kwargs["host"], "127.0.0.1")
                self.assertEqual(call.kwargs["auth"], resource.ch_auth)


    def test_opt_in_checked_before_docker_and_subprocess(self):
        with patch.dict("os.environ", {"SLI_STAGE6S_DISPOSABLE_E2E": "0"}):
            with patch.object(self.g.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "opt_in"):
                    with self.g.local_docker():
                        self.fail("unexpected adapter")
                with self.assertRaisesRegex(RuntimeError, "opt_in"):
                    with self.g.owned_resources(self.docker):
                        self.fail("unexpected resource")
                run.assert_not_called()
                self.assertEqual(self.docker.calls, [])

    def test_docker_adapter_uses_clean_local_environment_and_never_echoes_errors(self):
        import subprocess

        hostile = {"DOCKER_HOST": "tcp://foreign", "DOCKER_CONTEXT": "foreign", "HOME": "/foreign"}
        with patch.dict("os.environ", hostile), patch.object(self.g.subprocess, "run") as run:
            run.return_value = types.SimpleNamespace(returncode=0, stdout=b"ok")
            with self.g.local_docker() as docker:
                self.assertEqual(docker(["inspect", "a" * 64]), "ok")
                call = run.call_args
                self.assertEqual(call.args[0][0], "/usr/bin/docker")
                self.assertIn("unix:///var/run/docker.sock", call.args[0])
                self.assertEqual(set(call.kwargs["env"]), {"PATH", "HOME"})
                self.assertNotEqual(call.kwargs["env"]["HOME"], "/foreign")
                run.side_effect = subprocess.TimeoutExpired(["secret-sentinel"], 120)
                with self.assertRaises(RuntimeError) as error:
                    docker(["create", "--env", "PASSWORD=secret-sentinel"])
                self.assertNotIn("secret-sentinel", str(error.exception))
                self.assertIsNone(error.exception.__cause__)

    def test_start_failure_removes_only_previously_proven_id(self):
        def docker(args):
            if args[0] == "start":
                raise RuntimeError("start failed")
            return self.docker(args)
        with self.assertRaisesRegex(RuntimeError, "start failed"):
            with self.g.owned_resources(docker):
                self.fail("unexpected ready resource")
        self.assertEqual([a for a in self.docker.calls if a[0] == "rm"], [["rm", "--force", "--volumes", "0" * 63 + "1"]])

    def test_malformed_inspect_and_create_are_not_cleanup_authority(self):
        for output in ("not-json", "[]", "{}", "[null]", "[{},{}]"):
            def docker(args):
                if args[0] == "inspect":
                    return output
                return self.docker(args)
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                with self.g.owned_resources(docker):
                    self.fail("unexpected ready resource")
            self.assertFalse(any(a[0] == "rm" for a in self.docker.calls))
        docker = Mock(return_value="not-an-id")
        with self.assertRaisesRegex(RuntimeError, "identity_unverified"):
            with self.g.owned_resources(docker):
                self.fail("unexpected ready resource")
        self.assertEqual(docker.call_count, 1)

    def test_real_http_helpers_and_executor_late_import_are_pinned(self):
        import sys

        root = HERE.parents[1]
        path = root / "server/sli/storage/storage_lifecycle_io.py"
        spec = importlib.util.spec_from_file_location("offline_storage_io", path)
        io = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(io)
        executor_path = root / "server/sli/storage/tier_retention_delete_executor_runtime.py"
        tree = ast.parse(executor_path.read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_recheck_persisted_promotion_output")
        namespace = {"Any": object, "_is_hex64": lambda value: len(value) == 64}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(executor_path), "exec"), namespace)
        with self.g.owned_resources(self.docker) as resource:
            class Patcher:
                def setattr(self, obj, name, value):
                    setattr(obj, name, value)
            alias = types.SimpleNamespace(_http_query=io._http_query, _container_port=io._container_port, CONTAINER=io.CONTAINER)
            self.g.pin_clickhouse(Patcher(), resource, io, alias)
            def actual(port, identity):
                alias._http_query(port, "SELECT owned_output")
                return []  # Stop after the actual executor's IO boundary.
            alias._derived_output_actual = actual
            alias._derived_output_identity = Mock()
            modules = {"server.sli.storage.storage_lifecycle_io": io, "server.sli.storage.warm_tier_incremental_copy_runtime": alias}
            response = Mock(status=200)
            response.read.return_value = b"ok"
            connection = Mock()
            connection.getresponse.return_value = response
            hostile = {"ADLOG_WARM_CLICKHOUSE_HOST": "foreign", "ADLOG_WARM_CLICKHOUSE_PASSWORD_FILE": "/never/read"}
            with patch.dict(sys.modules, modules), patch.dict("os.environ", hostile), patch.object(Path, "read_text", side_effect=AssertionError("credential read")), patch.object(io.http.client, "HTTPConnection", return_value=connection) as http:
                io._drop_database(resource.ch_port, "sli_warm")
                io._http_insert_json_rows(resource.ch_port, "sli_warm.test", [{"id": 1}])
                for _ in range(2):
                    with self.assertRaisesRegex(RuntimeError, "promotion_output_missing"):
                        namespace[function.name]({"output_identity": "a" * 64})
            self.assertEqual(http.call_count, 4)
            for call in http.call_args_list:
                self.assertEqual(call.args, ("127.0.0.1", resource.ch_port))
            self.assertTrue(all("Authorization" in call.kwargs["headers"] for call in connection.request.call_args_list))


if __name__ == "__main__":
    unittest.main()
