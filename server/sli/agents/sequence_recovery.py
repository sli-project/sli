"""Explicit owner acceptance of one authenticated transport discontinuity.

No automatic restore detection, fake receipts, agent reset or privilege grant.
The append-only audit is also the recovery journal; the agent lock serializes
observation, authorization and ingress. A receipt and loss record commit together.
"""
from __future__ import annotations

from datetime import timedelta
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.agents.registry import audit
from sli_agent.envelope import digest, timestamp

OBSERVED = 'sequence_gap_observed'
AUTHORIZED = 'sequence_gap_authorized'
ACCEPTED = 'sequence_gap_accepted'
AUTH_TTL = timedelta(minutes=20)


def _owner(access):
    if not isinstance(access, dict) or access.get('platform_owner') is not True:
        raise AgentError('platform_owner_required', 403)


def _id(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal() or len(value) > 19 or value.startswith('0') or not 0 < int(value) <= 9223372036854775807:
        raise AgentError('agent_sequence_recovery_invalid')
    return value


def _latest(cur, agent, module):
    cur.execute("""select a.id::text,a.details,a.occurred_at from sli_agent_audit a
        where target=%s and action=%s and details->>'module_id'=%s
        order by a.id desc limit 1""", (str(agent), OBSERVED, module))
    return cur.fetchone()


def _event(cur, observation_id, action):
    cur.execute("""select a.id::text,a.details,a.occurred_at from sli_agent_audit a
        where action=%s and details->>'observation_id'=%s order by a.id desc limit 1""",
        (action, observation_id))
    return cur.fetchone()


def _previous(cur, agent, module):
    cur.execute("""select envelope from sli_agent_receipts where agent_id=%s and module_id=%s
        order by sequence desc limit 1""", (str(agent), module))
    row = cur.fetchone()
    return row['envelope'] if row else None


def _same_tip(details, previous, fingerprint):
    return (details['previous_hash'] == (digest(previous) if previous else None)
            and details['key_fingerprint'] == fingerprint)


def observe_boundary(cur, identity, envelope, previous, now):
    """Called only after authentication/signature/module validation and agent lock."""
    agent, module = str(identity['id']), envelope['module_id']
    row = _latest(cur, agent, module)
    fingerprint = identity['key_fingerprint']
    envelope_hash = digest(envelope)
    if row and _same_tip(row['details'], previous, fingerprint):
        # Freeze the first witnessed boundary at a tip; a different signed packet
        # must not silently replace the operator's preview or cause audit flooding.
        if row['details']['envelope_hash'] != envelope_hash:
            return None
    else:
        expected = previous['sequence'] + 1 if previous else 1
        audit(cur, OBSERVED, 'agent:' + agent, agent, module_id=module,
              packet_id=envelope['packet_id'], envelope_hash=envelope_hash,
              previous_hash=digest(previous) if previous else None,
              key_fingerprint=fingerprint, expected_sequence=str(expected),
              received_sequence=str(envelope['sequence']),
              missing_packets=str(envelope['sequence'] - expected),
              previous_observed_at=previous['observed_at_utc'] if previous else None,
              packet_observed_at=envelope['observed_at_utc'],
              loss_event_count=None, loss_time_bounds_known=False,
              reason='authenticated_sequence_gap', first_buffer_proven=False)
        row = _latest(cur, agent, module)
    if _event(cur, row['id'], ACCEPTED):
        return None
    permission = _event(cur, row['id'], AUTHORIZED)
    if not permission or now > permission['occurred_at'] + AUTH_TTL:
        return None
    return row['id']


def record_acceptance(cur, observation_id, envelope, now):
    # Called after the real receipt/inbox INSERT, before the same transaction's
    # commit. Failure must roll back the receipt rather than report success.
    audit(cur, ACCEPTED, 'agent:' + envelope['agent_id'], envelope['agent_id'],
          observation_id=observation_id, module_id=envelope['module_id'],
          packet_id=envelope['packet_id'], accepted_at=now.isoformat(),
          reason='operator_confirmed_sequence_gap')


def authorize(cur, body, *, actor, access):
    _owner(access)
    if not isinstance(body, dict) or set(body) != {'observation_id', 'confirm_loss'} or body['confirm_loss'] is not True:
        raise AgentError('agent_sequence_recovery_invalid')
    observation_id = _id(body['observation_id'])
    cur.execute('select target from sli_agent_audit where id=%s and action=%s', (observation_id, OBSERVED))
    found = cur.fetchone()
    if not found:
        raise AgentError('agent_sequence_recovery_stale', 409)
    agent_id = uuid_text(found['target'])
    # Same ordering as packet authentication, revoke and policy mutation.
    cur.execute('select id,status,key_fingerprint from sli_agents where id=%s for update', (agent_id,))
    agent = cur.fetchone()
    if not agent or agent['status'] != 'active':
        raise AgentError('agent_sequence_recovery_stale', 409)
    cur.execute('select details from sli_agent_audit where id=%s and action=%s', (observation_id, OBSERVED))
    details = cur.fetchone()['details']
    latest = _latest(cur, agent_id, details['module_id'])
    if (not latest or latest['id'] != observation_id
            or not _same_tip(details, _previous(cur, agent_id, details['module_id']), agent['key_fingerprint'])):
        raise AgentError('agent_sequence_recovery_stale', 409)
    if _event(cur, observation_id, ACCEPTED):
        raise AgentError('agent_sequence_recovery_stale', 409)
    permission = _event(cur, observation_id, AUTHORIZED)
    cur.execute('select clock_timestamp() as now')
    now = cur.fetchone()['now']
    # A retry/double click is idempotent while the authorization is live.
    if not permission or now > permission['occurred_at'] + AUTH_TTL:
        audit(cur, AUTHORIZED, actor, agent_id, observation_id=observation_id,
              module_id=details['module_id'], confirm_loss=True)
    return {'status': 'authorized', 'observation_id': observation_id}


def list_gaps(cur, agent_id, *, access):
    _owner(access)
    agent_id = uuid_text(agent_id)
    _bound_recovery_queries(cur)
    cur.execute("""select o.id::text,o.details,o.occurred_at,
        accepted.id as accepted_id, permission.occurred_at as authorized_at,
        clock_timestamp() as now
        from (select id,details,occurred_at from sli_agent_audit
              where target=%s and action=%s order by id desc limit 101) o
        left join lateral (select id from sli_agent_audit
             where action=%s and details->>'observation_id'=o.id::text
             order by id desc limit 1) accepted on true
        left join lateral (select occurred_at from sli_agent_audit
             where action=%s and details->>'observation_id'=o.id::text
             order by id desc limit 1) permission on true
        order by o.id desc""", (agent_id, OBSERVED, ACCEPTED, AUTHORIZED))
    observations = cur.fetchall()
    result = []
    for row in observations[:100]:
        status = ('accepted' if row['accepted_id'] else 'authorized'
                  if row['authorized_at'] and row['now'] <= row['authorized_at'] + AUTH_TTL else 'pending')
        d = row['details']
        result.append({'id': row['id'], 'agent_id': agent_id, 'module_id': d['module_id'],
                       'expected_sequence': d['expected_sequence'], 'received_sequence': d['received_sequence'],
                       'missing_packets': d['missing_packets'], 'observed_at': row['occurred_at'].isoformat(),
                       'previous_observed_at': d['previous_observed_at'], 'packet_observed_at': d['packet_observed_at'],
                       'loss_event_count': None, 'loss_time_bounds_known': False, 'status': status})
    return {'gaps': result, 'truncated': len(observations) > 100,
            'recovery_preview': recovery_preview(cur, agent_id)}


def _public_gap(row, agent_id, status):
    details = row['details']
    return {'id': row['id'], 'agent_id': agent_id, 'module_id': details['module_id'],
            'expected_sequence': details['expected_sequence'], 'received_sequence': details['received_sequence'],
            'missing_packets': details['missing_packets'], 'observed_at': row['occurred_at'].isoformat(),
            'previous_observed_at': details['previous_observed_at'], 'packet_observed_at': details['packet_observed_at'],
            'loss_event_count': None, 'loss_time_bounds_known': False, 'status': status}


def _bound_recovery_queries(cur):
    # Keep a stricter existing timeout; SET LOCAL cannot leak into pooled sessions.
    cur.execute("""select set_config('statement_timeout',
        least(3000,coalesce(nullif(setting::bigint,0),3000))::text,true)
        from pg_settings where name='statement_timeout'""")


def _eligible(cur, agent):
    """Exact current boundary set, never a wildcard grant for future streams."""
    if not agent or agent['status'] != 'active':
        return []
    agent_id = str(agent['id'])
    _bound_recovery_queries(cur)
    cur.execute("""select o.id::text,o.details,o.occurred_at,r.envelope as previous,
        accepted.id as accepted_id,permission.occurred_at as authorized_at,clock_timestamp() as now
        from (select distinct on (details->>'module_id') id,details,occurred_at from sli_agent_audit
              where target=%s and action=%s order by details->>'module_id',id desc) o
        left join lateral (select envelope from sli_agent_receipts
             where agent_id=%s and module_id=o.details->>'module_id'
             order by sequence desc limit 1) r on true
        left join lateral (select id from sli_agent_audit
             where action=%s and details->>'observation_id'=o.id::text
             order by id desc limit 1) accepted on true
        left join lateral (select occurred_at from sli_agent_audit
             where action=%s and details->>'observation_id'=o.id::text
             order by id desc limit 1) permission on true
        order by o.id limit 101""", (agent_id, OBSERVED, agent_id, ACCEPTED, AUTHORIZED))
    rows = cur.fetchall()
    if len(rows) > 100:
        raise AgentError('agent_sequence_recovery_preview_limit', 409)
    result = []
    for row in rows:
        if row['accepted_id'] or not _same_tip(row['details'], row['previous'], agent['key_fingerprint']):
            continue
        # Authorization cannot make an expired buffered packet admissible.
        if row['now'] > timestamp(row['details']['packet_observed_at']) + timedelta(days=7):
            continue
        status = ('authorized' if row['authorized_at'] and row['now'] <= row['authorized_at'] + AUTH_TTL
                  else 'pending')
        result.append({**_public_gap(row, agent_id, status), '_proof': digest(row['details'])})
    return result


def _preview_token(agent_id, streams):
    return digest({'agent_id': agent_id, 'boundaries': [
        {'id': item['id'], 'proof': item['_proof']} for item in streams]})


def recovery_preview(cur, agent_id):
    cur.execute('select id,status,key_fingerprint from sli_agents where id=%s', (agent_id,))
    streams = _eligible(cur, cur.fetchone())
    return {'agent_id': agent_id, 'observation_ids': [item['id'] for item in streams],
            'preview_token': _preview_token(agent_id, streams),
            'streams': [{key: value for key, value in item.items() if key != '_proof'} for item in streams]}


def authorize_all(cur, body, *, actor, access):
    """Authorize the reviewed all-stream set atomically under the lifecycle lock.

    The caller owns the transaction: any exception rolls back every audit row.
    No receipt is manufactured; each later packet still proves its own boundary.
    """
    _owner(access)
    if (not isinstance(body, dict) or set(body) != {'agent_id', 'observation_ids', 'preview_token', 'confirm_loss'}
            or body['confirm_loss'] is not True or not isinstance(body['observation_ids'], list)
            or not 1 <= len(body['observation_ids']) <= 100
            or not isinstance(body['preview_token'], str) or len(body['preview_token']) != 64
            or any(char not in '0123456789abcdef' for char in body['preview_token'])):
        raise AgentError('agent_sequence_recovery_invalid')
    agent_id = uuid_text(body['agent_id'])
    ids = [_id(value) for value in body['observation_ids']]
    if len(set(ids)) != len(ids):
        raise AgentError('agent_sequence_recovery_invalid')
    _bound_recovery_queries(cur)
    cur.execute('select id,status,key_fingerprint from sli_agents where id=%s for update', (agent_id,))
    agent = cur.fetchone()
    if not agent or agent['status'] != 'active':
        raise AgentError('agent_sequence_recovery_stale', 409)
    streams = _eligible(cur, agent)
    expected = [item['id'] for item in streams]
    token = _preview_token(agent_id, streams)
    if set(ids) != set(expected) or body['preview_token'] != token:
        raise AgentError('agent_sequence_recovery_stale', 409)
    # Compare the complete preview before the first write. All subsequent calls
    # use the same connection and already-held agent lock, including TTL renewal.
    for observation_id in expected:
        authorize(cur, {'observation_id': observation_id, 'confirm_loss': True}, actor=actor, access=access)
    return {'status': 'authorized', 'agent_id': agent_id, 'observation_ids': expected, 'preview_token': token}
