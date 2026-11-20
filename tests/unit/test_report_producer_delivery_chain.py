"""Synthetic durable boundary through actual producer/policy/outbox code.

Storage/RPCs and transport are spies. This does not establish PostgreSQL
query parity, transaction semantics, concurrency or grants.
"""
import ast
from contextlib import nullcontext
from copy import deepcopy
from pathlib import Path
import sys
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from server.sli.core import report_schedule_delivery as delivery
from server.sli.core import report_schedule_producer as producer
from tests.unit.test_report_producer_cycle import Backend
from tests.unit.test_report_schedule_delivery import fixture
from tests.unit.test_report_schedule_projection import actual_report_access, definition, access

ROOT = Path(__file__).resolve().parents[2]


def source_function(path, name, namespace):
    source = ROOT / path
    tree = ast.parse(source.read_text('utf-8'))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
    exec(compile(tree, str(source), 'exec'), namespace)
    return namespace[name]


class ChainTests(unittest.TestCase):
    def test_preloaded_transport_attribute_cannot_bypass_spy(self):
        import server.sli.core as core
        poison = SimpleNamespace(send=lambda *_: self.fail('preloaded transport bypassed spy'))
        with patch.object(core, 'notification_smtp', poison, create=True):
            _, states, sends = self.chain()
            self.assertEqual(states, [('accepted', 'accepted')])
            self.assertEqual(len(sends), 1)

    def chain(self, *, revoke=False, channel_revision=5):
        stop = Event()
        backend = Backend(stop)
        job, payload = fixture()
        job.update(object_kind='report_schedule', subscription_revision=3, attempts=1)
        durable = []
        original_publish = backend.publish
        def publish(claim, selection, deadline):
            durable.append(deepcopy(selection))
            payload['selection'] = deepcopy(selection)
            return original_publish(claim, selection, deadline)
        backend.publish = publish
        from datetime import timezone
        with patch.object(producer.calendar, 'ZoneInfo', lambda key: timezone.utc):
            outcome = producer.run_cycle(backend, stop, clock=lambda: 10,
                definition_loader=lambda key: definition(), authority_factory=actual_report_access())
        self.assertEqual(outcome['published'], 1)
        self.assertEqual(len(durable), 1)
        states, sends, sql_calls = [], [], []
        row = None
        def execute(sql, params=()):
            nonlocal row
            sql_calls.append(sql)
            if 'report_schedule_delivery(' in sql:
                row = {'prepared': payload}
            elif sql.lstrip().startswith('select id from notification_outbox'):
                row = {'id': job['id']}
            elif sql.startswith('select enabled,tls_mode,secret_ref,revision'):
                row = {'revision': channel_revision, 'enabled': True}
            elif sql.lstrip().startswith('update notification_outbox'):
                states.append(params[:2])
                row = {'id': job['id']}
            else:
                row = None
        cursor = SimpleNamespace(execute=execute, fetchone=lambda: row)
        conn = SimpleNamespace(cursor=lambda: nullcontext(cursor), commit=lambda: None)
        namespace = dict(dry_run_transport=lambda job: self.fail('unsent report consumed as dry run'),
            claim_job=lambda **kwargs: deepcopy(job), connect=lambda: nullcontext(conn))
        process = source_function('server/sli/core/notification_outbox.py', 'process_one', namespace)
        prepare = source_function('server/sli/core/report_schedules.py', 'prepare_delivery', {})
        smtp = SimpleNamespace(RESULTS={'accepted': 'accepted'}, send=lambda job, ch: sends.append(deepcopy(job)) or 'accepted')
        schedules = SimpleNamespace(prepare_delivery=prepare)
        actors = {7: access(), 8: access(export=not revoke)}
        original_authorize = delivery.authorize
        def authorize(job, payload):
            return original_authorize(job, payload, definition=definition(), actor_access=actors.__getitem__,
                                      authority_factory=actual_report_access())
        import server.sli.core as core
        with patch.dict(sys.modules, {'server.sli.core.report_schedules': schedules,
                                      'server.sli.core.notification_smtp': smtp}), \
             patch.object(core, 'report_schedules', schedules, create=True), \
             patch.object(core, 'notification_smtp', smtp, create=True), \
             patch.object(delivery, 'authorize', authorize):
            self.assertTrue(process(smtp=True, telegram=True, notification_only=True, include_reports=True))
        self.assertTrue(any('report_schedule_delivery(' in sql for sql in sql_calls))
        self.assertFalse(any('from report_schedules' in sql for sql in sql_calls))
        return durable, states, sends

    def test_due_snapshot_publication_then_actual_worker_transport_spy(self):
        frozen, states, sends = self.chain()
        self.assertTrue(frozen[0]['include_count'])
        self.assertEqual(states, [('accepted', 'accepted')])
        self.assertEqual(len(sends), 1)
        self.assertEqual(sends[0]['report_run']['item_count'], 1)
        self.assertNotIn('actors', sends[0]['report_run'])

    def test_revoked_export_between_publication_and_dispatch_never_sends(self):
        _, states, sends = self.chain(revoke=True)
        self.assertEqual(states, [('blocked', 'recipient_denied')])
        self.assertEqual(sends, [])

    def test_changed_channel_revision_never_sends(self):
        _, states, sends = self.chain(channel_revision=6)
        self.assertEqual(states, [('blocked', 'recipient_denied')])
        self.assertEqual(sends, [])


if __name__ == '__main__':
    unittest.main()
