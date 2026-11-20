"""Offline lifecycle tests: never launch PostgreSQL or connect to a database."""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent

def load_helper():
    spec = importlib.util.spec_from_file_location('bootstrap_cluster', HERE / 'bootstrap_cluster.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@unittest.skipUnless(sys.platform == "linux", "Linux-only private-cluster orchestration")
class ClusterTests(unittest.TestCase):

    def setUp(self):
        self.helper = load_helper()
        self.calls = []
        self.running = set()
        self.failure = None
        self.env = patch.dict('os.environ', {'SLI_BOOTSTRAP_DISPOSABLE_CLUSTER': '1', 'PGHOST': 'foreign.invalid', 'PGSERVICE': 'foreign', 'PGDATA': '/foreign/preexisting/data', 'SLI_BOOTSTRAP_TEST_PG_DSN': 'host=foreign.invalid dbname=production', 'SLI_BOOTSTRAP_TEST_PSQL': '/foreign/psql'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.root = patch.object(self.helper.os, 'geteuid', return_value=1000)
        self.root.start()
        self.addCleanup(self.root.stop)
        self.binary = patch.object(Path, 'is_file', return_value=True)
        self.binary.start()
        self.addCleanup(self.binary.stop)
        self.runner = patch.object(self.helper.subprocess, 'run', side_effect=self.run_process)
        self.runner.start()
        self.addCleanup(self.runner.stop)

    def run_process(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if '--version' in command:
            return subprocess.CompletedProcess(command, 0, 'initdb (PostgreSQL) 18.0', '')
        data = command[command.index('-D') + 1]
        if Path(command[0]).name == 'initdb':
            Path(data).mkdir()
            if self.failure == 'init_timeout':
                raise subprocess.TimeoutExpired(command, 45)
            if self.failure == 'init':
                return subprocess.CompletedProcess(command, 1, '', 'synthetic failure')
        if 'start' in command:
            self.running.add(data)
            if self.failure == 'start':
                raise subprocess.TimeoutExpired(command, 90)
        if 'stop' in command:
            if self.failure == 'stop':
                return subprocess.CompletedProcess(command, 1, '', 'synthetic failure')
            self.running.discard(data)
        return subprocess.CompletedProcess(command, 0, '', '')

    def test_failure_and_retry_use_distinct_owned_clusters(self):
        paths = []
        for fails in (True, False):
            try:
                with self.helper.owned_cluster(Path('/official/pg18/bin')) as cluster:
                    paths.append(cluster.data)
                    self.assertTrue(cluster.data.exists())
                    self.assertNotIn('foreign', cluster.host)
                    self.assertEqual(Path(cluster.host).parent, cluster.data.parent)
                    if fails:
                        raise ValueError('synthetic migration failed')
            except ValueError:
                self.assertTrue(fails)
            self.assertFalse(paths[-1].parent.exists())
            self.assertFalse(self.running)
        self.assertNotEqual(*paths)
        starts = [c for c, _ in self.calls if 'start' in c]
        self.assertEqual(len(starts), 2)
        for command in starts:
            config = Path(command[command.index('-D') + 1]).parent
            self.assertIn("listen_addresses=''", command[command.index('-o') + 1])
            self.assertNotEqual(config, Path('/official/pg18/bin'))
        for _, kwargs in self.calls:
            self.assertNotIn('PGHOST', kwargs['env'])
            self.assertNotIn('PGSERVICE', kwargs['env'])

    def test_partial_start_failure_still_stops_owned_cluster(self):
        self.failure = 'start'
        with self.assertRaisesRegex(RuntimeError, 'start'), self.helper.owned_cluster(Path('/official/pg18/bin')):
            self.fail('unexpected cluster')
        data = next((c[c.index('-D') + 1] for c, _ in self.calls if 'start' in c))
        self.assertFalse(self.running)
        self.assertFalse(Path(data).parent.exists())
        self.assertTrue(any(('stop' in c for c, _ in self.calls)))

    def test_failed_stop_preserves_directory_and_reports_blocker(self):
        import shutil
        self.failure = 'stop'
        with self.assertRaisesRegex(RuntimeError, 'cleanup_incomplete'), self.helper.owned_cluster(Path('/official/pg18/bin')) as cluster:
            root = cluster.data.parent
        self.assertTrue(root.exists())
        self.assertIn(str(cluster.data), self.running)
        shutil.rmtree(root)

    def test_partial_init_failure_removes_only_new_private_directory(self):
        self.failure = 'init'
        with self.assertRaisesRegex(RuntimeError, 'init_failed'), self.helper.owned_cluster(Path('/official/pg18/bin')):
            self.fail('unexpected cluster')
        data = next((c[c.index('-D') + 1] for c, _ in self.calls if '-D' in c))
        self.assertFalse(Path(data).parent.exists())
        self.assertFalse(any(('start' in c or 'stop' in c for c, _ in self.calls)))

    def test_init_timeout_preserves_uncertain_partial_directory(self):
        import shutil
        self.failure = "init_timeout"
        with self.assertRaisesRegex(RuntimeError, "cleanup_incomplete"), self.helper.owned_cluster(Path("/official/pg18/bin")):
            self.fail("unexpected cluster")
        data = next(c[c.index("-D") + 1] for c, _ in self.calls if "-D" in c)
        root = Path(data).parent
        self.assertTrue(root.exists())
        self.assertFalse(any("start" in c or "stop" in c for c, _ in self.calls))
        shutil.rmtree(root)  # The initializer was synthetic, with no live child.

    def test_wrong_version_does_not_initialize_or_start(self):
        with patch.object(self.helper.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'initdb (PostgreSQL) 17.6', '')) as run, self.assertRaisesRegex(RuntimeError, 'postgresql18'), self.helper.owned_cluster(Path('/official/pg18/bin')):
            self.fail('unexpected cluster')
        self.assertEqual(run.call_count, 1)
        self.assertIn('--version', run.call_args.args[0])

    def test_missing_or_relative_binaries_fail_before_process(self):
        with patch.object(Path, 'is_file', return_value=False), self.assertRaisesRegex(RuntimeError, 'installed_pg18'), self.helper.owned_cluster(Path('/official/pg18/bin')):
            self.fail('unexpected cluster')
        with self.assertRaisesRegex(RuntimeError, 'absolute'), self.helper.owned_cluster(Path('relative/bin')):
            self.fail('unexpected cluster')
        self.assertFalse(self.calls)

    def test_connection_identity_gate_is_read_only_and_rejects_foreign_cluster(self):
        cluster = SimpleNamespace(data=Path('/tmp/synthetic-owned/data'))
        for row in (('/foreign/data', 180000, None, 'postgres'), (str(cluster.data), 170000, None, 'postgres'), (str(cluster.data), 180000, '127.0.0.1', 'postgres'), (str(cluster.data), 180000, None, 'foreign')):
            connection = Mock()
            connection.execute.return_value.fetchone.return_value = row
            with self.assertRaisesRegex(RuntimeError, 'identity_mismatch'):
                self.helper.assert_owned_connection(connection, cluster)
            self.assertEqual(connection.execute.call_count, 1)
            self.assertTrue(connection.execute.call_args.args[0].startswith('select '))
        connection.execute.return_value.fetchone.return_value = (str(cluster.data), 180000, None, 'postgres')
        self.helper.assert_owned_connection(connection, cluster)

    def test_owned_marker_skips_shared_template_before_any_database_access(self):
        spec = importlib.util.spec_from_file_location('owned_conftest', HERE.parent / 'conftest.py')
        conftest = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(conftest)
        request = SimpleNamespace(node=SimpleNamespace(get_closest_marker=lambda name: object() if name in {'postgres_integration', 'postgres_owned_cluster'} else None))
        with patch.dict('os.environ', {'ADLOG_TEST_PG_DSN': 'host=foreign.invalid dbname=foreign'}), patch.dict('sys.modules', {'psycopg': None}):
            fixture = conftest.isolated_postgres_integration_database.__wrapped__(request)
            next(fixture)
            with self.assertRaises(StopIteration):
                next(fixture)

    def test_actual_integration_wiring_failure_and_retry_clean_owned_clusters(self):
        import pytest
        spec = importlib.util.spec_from_file_location('bootstrap_integration', HERE / 'test_existing_postgres_bootstrap.py')
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        paths = []
        for fail_schema in (True, False):
            monkeypatch = pytest.MonkeyPatch()
            self.addCleanup(monkeypatch.undo)
            monkeypatch.setenv('SLI_BOOTSTRAP_TEST_PG_BIN', '/official/pg18/bin')
            with patch.dict(sys.modules, {'bootstrap_cluster': self.helper}):
                fixture = integration.bootstrap_postgres_cluster.__wrapped__(monkeypatch)
                cluster = next(fixture)
                paths.append(cluster.data)
                connection = Mock()
                connection.__enter__ = Mock(return_value=connection)
                connection.__exit__ = Mock(return_value=False)
                connection.execute.return_value.fetchone.return_value = (str(cluster.data), 180000, None, 'postgres')
                bootstrap = Mock()
                bootstrap.read_cluster_snapshot.return_value = SimpleNamespace(data_directory=cluster.data, server_version_num=180000, database_exists=False, runtime_role_exists=False)
                bootstrap.build_plan.return_value = {}
                bootstrap.base_schema_markers.return_value = []
                bootstrap.forward_migration_inventory.return_value = []
                bootstrap._expected_ledger.return_value = []
                if fail_schema:
                    bootstrap._apply_database_schema.side_effect = ValueError('synthetic migration failure')
                driver = SimpleNamespace(connect=Mock(return_value=connection))
                try:
                    with patch.dict(sys.modules, {'psycopg': driver}), patch.object(integration, '_bootstrap_module', return_value=bootstrap):
                        if fail_schema:
                            with self.assertRaisesRegex(ValueError, 'migration failure'):
                                integration.test_full_postgresql18_forward_chain_in_isolated_cluster(cluster)
                        else:
                            integration.test_full_postgresql18_forward_chain_in_isolated_cluster(cluster)
                    bootstrap.create_target_database.assert_called_once()
                    self.assertEqual(bootstrap.create_target_database.call_args.kwargs['database'], cluster.database)
                    self.assertTrue(cluster.database.startswith('sli_test_bootstrap_'))
                    self.assertEqual(driver.connect.call_args.kwargs['host'], cluster.host)
                finally:
                    fixture.close()
                    monkeypatch.undo()
                self.assertFalse(cluster.data.parent.exists())
                self.assertFalse(self.running)
        self.assertNotEqual(*paths)

    def test_legacy_bootstrap_settings_fail_with_migration_guidance(self):
        import pytest
        spec = importlib.util.spec_from_file_location('bootstrap_legacy_guard', HERE / 'test_existing_postgres_bootstrap.py')
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        for legacy in ('SLI_BOOTSTRAP_TEST_PG_DSN', 'SLI_BOOTSTRAP_TEST_PSQL'):
            monkeypatch = pytest.MonkeyPatch()
            try:
                monkeypatch.delenv('SLI_BOOTSTRAP_TEST_PG_DSN', raising=False)
                monkeypatch.delenv('SLI_BOOTSTRAP_TEST_PSQL', raising=False)
                monkeypatch.delenv('SLI_BOOTSTRAP_DISPOSABLE_CLUSTER', raising=False)
                monkeypatch.setenv(legacy, 'synthetic-private-value-never-log')
                fixture = integration.bootstrap_postgres_cluster.__wrapped__(monkeypatch)
                with self.assertRaises(pytest.fail.Exception) as error:
                    try:
                        next(fixture)
                    except pytest.skip.Exception:
                        self.fail("legacy configuration silently skipped native coverage")
                message = str(error.exception)
                self.assertIn('SLI_BOOTSTRAP_DISPOSABLE_CLUSTER=1', message)
                self.assertIn('SLI_BOOTSTRAP_TEST_PG_BIN', message)
                self.assertNotIn('synthetic-private-value-never-log', message)
            finally:
                monkeypatch.undo()
        self.assertFalse(self.calls)

    def test_no_opt_in_and_no_legacy_settings_remains_a_skip(self):
        import pytest
        spec = importlib.util.spec_from_file_location('bootstrap_unconfigured_guard', HERE / 'test_existing_postgres_bootstrap.py')
        integration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(integration)
        monkeypatch = pytest.MonkeyPatch()
        try:
            for key in ('SLI_BOOTSTRAP_DISPOSABLE_CLUSTER', 'SLI_BOOTSTRAP_TEST_PG_DSN', 'SLI_BOOTSTRAP_TEST_PSQL'):
                monkeypatch.delenv(key, raising=False)
            fixture = integration.bootstrap_postgres_cluster.__wrapped__(monkeypatch)
            with self.assertRaises(pytest.skip.Exception):
                next(fixture)
        finally:
            monkeypatch.undo()
        self.assertFalse(self.calls)

    def test_opt_in_and_root_guards_precede_any_process(self):
        for environment, uid in (('0', 1000), ('1', 0)):
            with patch.dict('os.environ', {'SLI_BOOTSTRAP_DISPOSABLE_CLUSTER': environment}), patch.object(self.helper.os, 'geteuid', return_value=uid), self.assertRaisesRegex(RuntimeError, 'opt_in|nonroot'), self.helper.owned_cluster(Path('/official/pg18/bin')):
                self.fail('unexpected cluster')
        self.assertFalse(self.calls)
if __name__ == '__main__':
    unittest.main()
