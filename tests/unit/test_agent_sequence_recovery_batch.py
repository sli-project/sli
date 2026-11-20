"""Exact all-stream preview authorization; no runtime database required."""
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from server.sli.agents import sequence_recovery as recovery
from server.sli.agents.ca import AgentError

AGENT = '00000000-0000-4000-8000-000000000001'
ACCESS = {'platform_owner': True}


class BatchRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.cur = Mock()
        self.cur.fetchone.return_value = {'id': AGENT, 'status': 'active', 'key_fingerprint': 'key'}
        self.streams = [{'id': '9', '_proof': 'first'}, {'id': '10', '_proof': 'second'}]
        self.body = {'agent_id': AGENT, 'observation_ids': ['9', '10'],
                     'preview_token': recovery._preview_token(AGENT, self.streams), 'confirm_loss': True}

    def test_exact_all_stream_set_authorizes_under_agent_lock(self):
        with patch.object(recovery, '_eligible', return_value=self.streams), patch.object(recovery, 'authorize') as authorize:
            result = recovery.authorize_all(self.cur, self.body, actor='session:1', access=ACCESS)
        self.assertEqual(result, {'status': 'authorized', 'agent_id': AGENT, 'observation_ids': ['9', '10'], 'preview_token': self.body['preview_token']})
        self.assertIn("set_config('statement_timeout'", self.cur.execute.call_args_list[0].args[0])
        self.assertTrue(self.cur.execute.call_args_list[1].args[0].endswith('for update'))
        self.assertEqual([c.args[1]['observation_id'] for c in authorize.call_args_list], ['9', '10'])
        self.assertFalse(self.cur.connection.commit.called)

    def test_history_query_is_bounded_before_first_read(self):
        self.cur.fetchall.return_value = []
        with patch.object(recovery, "recovery_preview", return_value={}):
            recovery.list_gaps(self.cur, AGENT, access=ACCESS)
        self.assertIn("set_config('statement_timeout'", self.cur.execute.call_args_list[0].args[0])
        self.assertIn("from sli_agent_audit", self.cur.execute.call_args_list[1].args[0])

    def test_added_removed_or_changed_preview_rejects_everything(self):
        for latest in ([{'id': '9'}], [{'id': '9'}, {'id': '10'}, {'id': '11'}], [{'id': '9'}, {'id': '12'}], []):
            with self.subTest(latest=latest), patch.object(recovery, '_eligible', return_value=[{**item, '_proof': 'changed'} for item in latest]), patch.object(recovery, 'authorize') as authorize:
                with self.assertRaises(AgentError):
                    recovery.authorize_all(self.cur, self.body, actor='session:1', access=ACCESS)
                authorize.assert_not_called()

    def test_reused_ids_with_changed_boundary_proof_reject_everything(self):
        changed = [{**item, '_proof': 'different-key-or-packet'} for item in self.streams]
        with patch.object(recovery, '_eligible', return_value=changed), patch.object(recovery, 'authorize') as authorize:
            with self.assertRaises(AgentError):
                recovery.authorize_all(self.cur, self.body, actor='session:1', access=ACCESS)
            authorize.assert_not_called()

    def test_duplicate_malformed_or_wildcard_ids_never_query(self):
        for ids in ([], ['9', '9'], ['*'], ['01'], ['9'] * 101):
            with self.subTest(ids=ids):
                cur = Mock()
                with self.assertRaises(AgentError):
                    recovery.authorize_all(cur, {**self.body, 'observation_ids': ids}, actor='session:1', access=ACCESS)
                cur.execute.assert_not_called()

    def test_nonowner_never_queries(self):
        with self.assertRaises(AgentError):
            recovery.authorize_all(self.cur, self.body, actor='session:1', access={'platform_owner': False})
        self.cur.execute.assert_not_called()

    def test_disabled_agent_cannot_authorize(self):
        self.cur.fetchone.return_value = {'id': AGENT, 'status': 'disabled'}
        with patch.object(recovery, 'authorize') as authorize, self.assertRaises(AgentError):
            recovery.authorize_all(self.cur, self.body, actor='session:1', access=ACCESS)
        authorize.assert_not_called()

    def test_per_boundary_failure_is_not_swallowed_or_committed(self):
        with patch.object(recovery, '_eligible', return_value=self.streams), patch.object(recovery, 'authorize', side_effect=[{}, AgentError('stale')]):
            with self.assertRaises(AgentError):
                recovery.authorize_all(self.cur, self.body, actor='session:1', access=ACCESS)
        self.assertFalse(self.cur.connection.commit.called)

    def test_preview_filters_accepted_key_tip_and_expired(self):
        now = datetime(2026, 10, 23, tzinfo=timezone.utc)
        def row(oid, **changes):
            details = {'module_id': 'stream.' + oid, 'previous_hash': None, 'key_fingerprint': 'key',
                       'expected_sequence': '1', 'received_sequence': '5', 'missing_packets': '4',
                       'previous_observed_at': None, 'packet_observed_at': now.isoformat()}
            return {'id': oid, 'details': details, 'previous': None, 'accepted_id': None,
                    'authorized_at': None, 'now': now, 'occurred_at': now, **changes}
        current = row('1')
        authorized = row('2', authorized_at=now)
        accepted = row('3', accepted_id='33')
        stale_key = row('4'); stale_key['details']['key_fingerprint'] = 'old'
        expired = row('5'); expired['details']['packet_observed_at'] = (now - timedelta(days=8)).isoformat()
        stale_tip = row('6'); stale_tip['details']['previous_hash'] = 'old'
        self.cur.fetchall.return_value = [current, authorized, accepted, stale_key, expired, stale_tip]
        result = recovery._eligible(self.cur, self.cur.fetchone.return_value)
        self.assertEqual([item['id'] for item in result], ['1', '2'])
        self.assertEqual([item['status'] for item in result], ['pending', 'authorized'])
        self.assertTrue(all(item['loss_event_count'] is None for item in result))

    def test_overflow_fails_closed_not_partial_preview(self):
        self.cur.fetchall.return_value = [{}] * 101
        with self.assertRaises(AgentError):
            recovery._eligible(self.cur, self.cur.fetchone.return_value)


if __name__ == '__main__':
    unittest.main()
