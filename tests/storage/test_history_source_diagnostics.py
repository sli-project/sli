"""Synthetic metadata-only checks; no live database or archive reads."""
import importlib
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

diagnostic = importlib.import_module('server.sli.storage.history_source_diagnostics')


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(diagnostic, 'metadata-only diagnostic is not implemented')
        self.cores = [{'id': 41, 'time_created_utc': datetime(2026, 10, 1, tzinfo=timezone.utc)}]
        self.links = [{'event_id': 41, 'entity_id': 3, 'role_id': 2}]

    def summary(self, blocks=(), **kwargs):
        return diagnostic.summarize(self.cores, self.links, blocks, no_archive_ids=set(), **kwargs)

    def test_missing_manifest_counts_dates_and_capped_numeric_ids(self):
        result = self.summary()
        self.assertEqual(result['missing_published_manifest_links'], 1)
        self.assertEqual(result['missing_published_manifest_events'], 1)
        self.assertEqual(result['sample_event_ids'], [41])
        self.assertEqual(result['missing_time_min_utc'], '2026-10-01T00:00:00+00:00')
        self.assertFalse(result['detail_presence_checked'])
        self.assertFalse(result['deletion_authorized'])

    def test_published_coverage_is_unknown_not_detail_presence(self):
        result = self.summary([{'first_event_id': 1, 'last_event_id': 100, 'state': 'published'}])
        self.assertEqual(result['missing_published_manifest_links'], 0)
        self.assertEqual(result['manifest_covered_detail_unchecked_links'], 1)
        self.assertEqual(result['reason'], 'detail_presence_not_checked')

    def test_staging_and_quarantine_are_not_published(self):
        for state in ('staging', 'verified', 'quarantined'):
            with self.subTest(state=state):
                result = self.summary([{'first_event_id': 41, 'last_event_id': 41, 'state': state}])
                self.assertEqual(result['missing_published_manifest_links'], 1)
                self.assertEqual(result['unpublished_manifest_events'], 1)

    def test_no_archive_is_not_reported_missing(self):
        result = diagnostic.summarize(self.cores, self.links, [], no_archive_ids={41})
        self.assertEqual(result['missing_published_manifest_links'], 0)
        self.assertEqual(result['no_archive_links'], 1)

    def test_sample_capped_and_no_payload(self):
        cores = [{'id': i, 'time_created_utc': self.cores[0]['time_created_utc'], 'secret': 'private'} for i in range(10)]
        links = [{'event_id': i, 'entity_id': i, 'role_id': 2, 'payload': 'private'} for i in range(10)]
        result = diagnostic.summarize(cores, links, [], no_archive_ids=set())
        self.assertEqual(result['sample_event_ids'], list(range(5)))
        self.assertNotIn('private', json.dumps(result))

    def test_exhausted_row_budget_does_not_claim_missing_counts(self):
        result = self.summary(truncated=True)
        self.assertEqual(result['reason'], 'diagnostic_row_budget_exceeded')
        self.assertTrue(result['truncated'])
        self.assertIsNone(result['missing_published_manifest_links'])

    def test_database_path_is_read_only_and_does_not_advance_frontier(self):
        class Connection:
            def __init__(self): self.calls = []; self.sql = ''
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return self
            def execute(self, sql, params=()): self.calls.append((sql, params)); self.sql = sql
            def fetchone(self): return {'role': 'adlog_storage_worker'}
            def fetchall(inner):
                if 'from events_v2_core' in inner.sql: return self.cores
                if 'from event_entity_link_blocks_v2' in inner.sql: return self.links
                return []
        conn = Connection()
        calls = []
        result = diagnostic.inspect_batch(connect=lambda: conn, read_frontier=lambda: calls.append(1) or 40,
                                          catalog=lambda *args: {}, batch_events=1000)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result['frontier_before'], 40)
        self.assertEqual(result['frontier_after'], 40)
        self.assertTrue(result['frontier_unchanged'])
        sql = '\n'.join(q.lower() for q, _ in conn.calls)
        self.assertIn('repeatable read read only', sql)
        self.assertIn('statement_timeout', sql)
        self.assertIn('lock_timeout', sql)
        for q, _ in conn.calls:
            self.assertTrue(q.strip().lower().startswith(('select', 'set')))
        self.assertEqual(result['missing_published_manifest_links'], 1)

    def test_actual_row_limits_and_changed_frontier_are_inconclusive(self):
        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return self
            def execute(self, sql, params=()): self.sql = sql; self.params = params
            def fetchone(self): return {'role': 'adlog_storage_worker'}
            def fetchall(inner):
                if 'from events_v2_core' in inner.sql: return self.cores
                if 'from event_entity_link_blocks_v2' in inner.sql:
                    self.assertEqual(inner.params[-1], diagnostic.MAX_LINKS + 1)
                    return self.links * (diagnostic.MAX_LINKS + 1)
                self.assertEqual(inner.params[-1], diagnostic.MAX_MANIFESTS + 1)
                return []
        frontier = iter((40, 42))
        result = diagnostic.inspect_batch(connect=Connection, read_frontier=lambda: next(frontier),
                                          catalog=lambda *args: {})
        self.assertTrue(result['truncated'])
        self.assertFalse(result['frontier_unchanged'])
        self.assertIsNone(result['missing_published_manifest_links'])
        self.assertEqual(result['reason'], 'history_frontier_changed_during_diagnostic')
        self.assertEqual(result['observed_link_rows'], diagnostic.MAX_LINKS)

    def test_timeout_and_private_exception_are_sanitized(self):
        import sys
        import types
        catalog = types.ModuleType('server.sli.events.event_catalog')
        catalog.lookup_event_catalog = lambda *args: {}
        history = types.ModuleType('server.sli.storage.permanent_fact_history')
        history.configured_read_port = lambda: 8123
        class Failure(Exception):
            sqlstate = '57014'
        def fail(*args):
            raise Failure('private DSN password payload')
        history.next_after_id = fail
        modules = {'server.sli.events.event_catalog': catalog,
                   'server.sli.storage.permanent_fact_history': history}
        import server.sli.storage as storage
        # A full-suite import also caches this module on its parent package.
        # Patch both locations; restore both so the fixture cannot leak.
        with (patch.dict(sys.modules, modules),
              patch.object(storage, 'permanent_fact_history', history, create=True),
              patch.dict('os.environ', {'ADLOG_STORAGE_V2_WORKER_DSN': 'configured'}, clear=True),
              patch('builtins.print') as output):
            self.assertEqual(diagnostic.main([]), 2)
        rendered = str(output.call_args)
        self.assertIn('diagnostic_statement_timeout', rendered)
        self.assertNotIn('private', rendered)
        self.assertNotIn('password', rendered)

    def test_wrong_active_role_rejected_before_source_queries(self):
        class Connection:
            def __init__(self): self.sql = []
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return self
            def execute(self, sql, params=()): self.sql.append(sql)
            def fetchone(self): return {'role': 'adlog_user'}
        conn = Connection()
        with self.assertRaisesRegex(RuntimeError, 'diagnostic_worker_role_required'):
            diagnostic.inspect_batch(connect=lambda: conn, read_frontier=lambda: 40,
                                     catalog=lambda *args: {})
        self.assertFalse(any('from events_v2_core' in sql for sql in conn.sql))

    def test_frontier_change_without_truncation_remains_explicit(self):
        class Connection:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def cursor(self): return self
            def execute(self, sql, params=()): self.sql = sql
            def fetchone(self): return {'role': 'adlog_storage_worker'}
            def fetchall(inner):
                if 'from events_v2_core' in inner.sql: return self.cores
                if 'from event_entity_link_blocks_v2' in inner.sql: return self.links
                return []
        frontier = iter((40, 41))
        result = diagnostic.inspect_batch(connect=Connection, read_frontier=lambda: next(frontier),
                                          catalog=lambda *args: {})
        self.assertFalse(result['truncated'])
        self.assertFalse(result['frontier_unchanged'])
        self.assertEqual(result['reason'], 'history_frontier_changed_during_diagnostic')
        self.assertEqual(result['missing_published_manifest_links'], 1)

    def test_worker_connector_missing_parts_never_calls_psycopg(self):
        import sys
        import types
        fake_pg = types.ModuleType('psycopg')
        fake_rows = types.ModuleType('psycopg.rows')
        fake_rows.dict_row = object()
        fake_secrets = types.ModuleType('server.sli.core.secret_files')
        fake_secrets.postgres_secret_parts = lambda name: {}
        fake_pg.connect = lambda **kwargs: self.fail('connection must not be opened')
        with patch.dict(sys.modules, {'psycopg': fake_pg, 'psycopg.rows': fake_rows,
                                     'server.sli.core.secret_files': fake_secrets}):
            with self.assertRaisesRegex(RuntimeError, 'worker_connection_required'):
                diagnostic._connect_worker_readonly()

    def test_cli_errors_do_not_expose_exception_or_try_admin(self):
        with patch.dict('os.environ', {}, clear=True), patch('builtins.print') as output:
            self.assertEqual(diagnostic.main([]), 2)
        rendered = str(output.call_args)
        self.assertIn('worker_connection_required', rendered)
        self.assertNotIn('Traceback', rendered)


if __name__ == '__main__':
    unittest.main()
