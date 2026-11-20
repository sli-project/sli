import json
from types import SimpleNamespace

import pytest

from server.sli.agents import security_recovery as recovery
from server.sli.agents.ca import AgentError

AGENT = '00000000-0000-4000-8000-000000000001'
HOST = '00000000-0000-4000-8000-000000000002'


class Cursor:
    def execute(self, sql, params):
        assert params == (AGENT,)
        assert "sli.windows.ad-dc" in sql

    def fetchone(self):
        return {'envelope': {'cursor_after': {'strategy': 'bookmark', 'token': json.dumps({
            'next': 0, 'channels': {'Security': {'generation': HOST, 'record_id': 100, 'bookmark': 'saved'}}})}}}


def fixture(monkeypatch):
    config = {'channel_generations': {'System': 'unchanged'}, 'initial_read_hours': 'all'}
    agent = {'host_id': HOST, 'policy_revision': 4, 'assigned_modules': [
        {'module_id': 'sli.windows.ad-dc', 'enabled': True, 'config': config}]}
    monkeypatch.setattr(recovery.policies, '_agent', lambda *_: agent)
    calls = []
    def assign(cur, body, *, actor):
        calls.append((body, actor))
        return {'policy_revision': 5}
    monkeypatch.setattr(recovery.policies, 'assign_module', assign)
    args = SimpleNamespace(agent_id=AGENT, expected_revision=4, oldest_record=101,
                           initial_read_hours=0, actor='lab', owner_user_id=34)
    return args, calls


def test_recovery_is_audited_bounded_and_changes_only_security_generation(monkeypatch):
    args, calls = fixture(monkeypatch)
    assert recovery.recover(Cursor(), args)['old_record'] == 100
    body, actor = calls[0]
    assert actor == 'local:lab' and body['expected_revision'] == 4
    assert body['config']['channel_generations']['System'] == 'unchanged'
    assert body['config']['channel_generations']['Security'].startswith('security-recovery-')
    assert body['config']['initial_read_hours'] == 0


@pytest.mark.parametrize('oldest', [100, 99, True])
def test_no_reset_without_proven_overwritten_anchor(monkeypatch, oldest):
    args, calls = fixture(monkeypatch)
    args.oldest_record = oldest
    with pytest.raises(AgentError, match='gap_not_proven'):
        recovery.recover(Cursor(), args)
    assert not calls


def test_owner_authority_is_required_before_database_access(monkeypatch):
    args, calls = fixture(monkeypatch)
    monkeypatch.setattr(recovery, 'owner_principal', lambda _: {'id': 34})
    monkeypatch.setattr(recovery, 'effective_access', lambda _: {'platform_owner': False})
    with pytest.raises(AgentError, match='owner_required'):
        recovery.run(args)
    assert not calls
