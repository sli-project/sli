"""Opt-in real-login smoke contracts on an ALREADY provisioned test cluster.

No cluster, role, login, grants, schema or fixture is created by this suite.
SLI_REPORT_TEST_PRODUCER_DSN and SLI_REPORT_TEST_DELIVERY_DSN must identify
distinct real logins on 127.0.0.1:55432 in the same sli_test_* database, with
migration 285 already applied and producer principal bound.
SLI_REPORT_TEST_SCENARIO names a local JSON file containing schedule_id,
report_key, expected_count, expected_quality for one due synthetic schedule.
The fixture must have exactly one enabled SMTP binding, current view/export
grants, synthetic findings, no other due schedules and an empty outbox.

These tests mutate only that pre-seeded disposable fixture. They neither
provide the full parity/concurrency matrix nor establish deployment readiness.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
from threading import Event
import time
from unittest.mock import patch
import unittest
from uuid import UUID, uuid4


class ProducerLoginPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        keys = ('SLI_REPORT_TEST_PRODUCER_DSN', 'SLI_REPORT_TEST_DELIVERY_DSN', 'SLI_REPORT_TEST_SCENARIO')
        if not all(os.environ.get(key) for key in keys):
            raise unittest.SkipTest('pre-provisioned disposable real-login fixture not configured')
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from psycopg.rows import dict_row
        from tests.postgres_integration_guard import assert_disposable_database
        cls.psycopg, cls.dict_row = psycopg, dict_row
        cls.dsns = {name: os.environ[key] for name, key in zip(('producer', 'delivery'), keys[:2])}
        database = None
        identities = []
        for name, dsn in cls.dsns.items():
            parts = conninfo_to_dict(dsn)
            # Refuse before opening a socket, not after connecting to a target.
            assert parts.get('host') == '127.0.0.1' and str(parts.get('port')) == '55432'
            assert not parts.get('hostaddr') or parts['hostaddr'] == '127.0.0.1'
            assert parts.get('dbname', '').startswith('sli_test_')
            assert database is None or database == parts['dbname']
            database = parts['dbname']
            with cls.connect(name) as conn:
                assert_disposable_database(conn)
                row = conn.execute('select session_user,current_user,r.rolsuper,r.rolbypassrls,r.rolcanlogin '
                    'from pg_catalog.pg_roles r where r.rolname=session_user').fetchone()
                assert row['session_user'] == row['current_user'] and row['rolcanlogin']
                assert not row['rolsuper'] and not row['rolbypassrls']
                identities.append(row['session_user'])
        assert len(set(identities)) == 2
        cls.scenario = json.loads(Path(os.environ[keys[2]]).read_text('utf-8'))
        assert set(cls.scenario) == {'schedule_id', 'report_key', 'expected_count', 'expected_quality'}
        UUID(cls.scenario['schedule_id'])
        assert cls.scenario['report_key'] in {'security.problems', 'file-audit.mass-operations'}

    @classmethod
    def connect(cls, role):
        return cls.psycopg.connect(cls.dsns[role], row_factory=cls.dict_row, connect_timeout=2,
            application_name='sli-report-disposable-test', options='-c statement_timeout=2000 -c lock_timeout=500')

    def denied(self, role, statement, params=()):
        with self.connect(role) as conn:
            with self.assertRaises(self.psycopg.errors.InsufficientPrivilege):
                conn.execute(statement, params)

    def test_direct_sources_configuration_and_raw_functions_are_denied(self):
        for sql in ('select * from public.findings_active limit 1',
                    'select * from public.events_v2_core limit 1',
                    'select * from public.finding_evidence limit 1',
                    'select * from public.auth_users limit 1',
                    'select * from public.report_schedules limit 1',
                    "select public.read_file_ransom_details('[]'::jsonb,'[]'::jsonb)",
                    "insert into public.notification_outbox(id) values(gen_random_uuid())"):
            with self.subTest(sql=sql):
                self.denied('producer', sql)
        self.denied('delivery', 'select * from public.report_schedules limit 1')

    def test_wrong_lease_and_cross_role_accessors_fail_closed(self):
        for function in ('report_schedule_acl_facts', 'report_schedule_candidates'):
            self.denied('producer', f'select public.{function}(%s::uuid,%s::uuid)', (uuid4(), uuid4()))
            self.denied('delivery', f'select public.{function}(%s::uuid,%s::uuid)', (uuid4(), uuid4()))
        self.denied('producer', 'select public.report_schedule_delivery(%s::uuid,%s::uuid)', (uuid4(), uuid4()))
        with self.connect('delivery') as conn:
            self.assertIsNone(conn.execute('select public.report_schedule_delivery(%s::uuid,%s::uuid) as data',
                                          (uuid4(), uuid4())).fetchone()['data'])

    def test_due_real_aggregate_durable_outbox_actual_worker_transport_spy(self):
        from server.sli.core import notification_outbox as outbox, notification_smtp as smtp, notification_telegram as telegram
        from server.sli.core import report_schedule_producer as producer
        from server.sli.core.report_schedule_projection import project
        from server.sli.reporting.v2.registry import get_report
        from server.sli.core.report_schedule_calendar import latest_slot, period_start
        with self.connect('producer') as conn:
            backend = producer.SqlBackend(conn)
            deadline = time.monotonic() + 20
            leader = backend.lead(None, deadline)
            self.assertIsNotNone(leader)
            with self.connect('producer') as contender:
                self.assertIsNone(producer.SqlBackend(contender).lead(None, deadline))
            claims = backend.claim(leader, 2, deadline)
            self.assertEqual(len(claims), 1)
            claim = claims[0]
            self.assertEqual(str(claim['schedule']['id']), self.scenario['schedule_id'])
            schedule = claim['schedule']
            schedule['created_at'] = producer._instant(schedule['created_at'])
            self.assertEqual(latest_slot(schedule, claim['evaluated_at']), claim['slot'])
            self.assertEqual(period_start(schedule, claim['slot']), claim['period_from'])
            snapshot = backend.facts(claim, deadline)
            candidate = backend.candidates(claim, deadline)
            selection = project(get_report(schedule['report_key']), snapshot, candidate)['selection']
            first = backend.publish(claim, selection, deadline)
            self.assertTrue(first['published'])
            self.assertFalse(backend.publish(claim, selection, deadline)['published'])
            # Reload the schedule-derived current ACL facts for dispatch; no
            # caller-built allow flags and no SET ROLE superuser simulation.
            current = backend.facts(claim, deadline)['actors']
        sent = []
        @contextmanager
        def connect_delivery():
            with self.connect('delivery') as conn:
                yield conn
        with patch.object(outbox, 'connect', connect_delivery), \
             patch.object(outbox, 'recipient_access', current.__getitem__), \
             patch.object(telegram, 'send', side_effect=AssertionError('unexpected fixture channel')), \
             patch.object(smtp, 'send', side_effect=lambda job, channel: sent.append(job) or 'accepted'):
            self.assertTrue(outbox.process_one(smtp=True, telegram=True, notification_only=True, include_reports=True))
        self.assertEqual(len(sent), 1)
        run = sent[0]['report_run']
        self.assertEqual(run['report_key'], self.scenario['report_key'])
        self.assertEqual(run['item_count'], self.scenario['expected_count'])
        self.assertEqual(run['quality'], self.scenario['expected_quality'])
        with self.connect('delivery') as conn:
            row = conn.execute('select state,result_code from public.notification_outbox where id=%s',
                               (sent[0]['id'],)).fetchone()
            self.assertEqual((row['state'], row['result_code']), ('accepted', 'accepted'))


if __name__ == '__main__':
    unittest.main()
