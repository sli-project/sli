"""Local owner recovery of a proven overwritten DC Security bookmark.

Use the audited module-assignment operation; never edit a spool or DB cursor.
The retained native lower bound is supplied by the lab administrator.
"""
import argparse
import json
import sys
from uuid import uuid4

from server.sli.access.access_control_v4 import effective_access
from server.sli.agents import policies
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.agents.file_audit_admin import owner_principal
from server.sli.core.postgres_runtime_pipeline import connect
from sli_agent.ad_dc import cursor_state


def recover(cur, args):
    agent_id = uuid_text(args.agent_id)
    agent = policies._agent(cur, agent_id)
    policies._next_revision(agent, args.expected_revision)
    modules = [m for m in agent['assigned_modules'] if isinstance(m, dict)
               and m.get('module_id') == 'sli.windows.ad-dc' and m.get('enabled') is True]
    if len(modules) != 1:
        raise AgentError('security_recovery_module_required', 409)
    cur.execute("select envelope from sli_agent_packet_inbox where envelope->>'agent_id'=%s "
                "and envelope->>'module_id'='sli.windows.ad-dc' "
                "order by (envelope->>'sequence')::bigint desc limit 1", (agent_id,))
    row = cur.fetchone()
    progress = cursor_state(row['envelope']['cursor_after'])['channels'].get('Security') if row else None
    config = modules[0]['config']
    generation = config.get('channel_generations', {}).get('Security', str(agent['host_id']))
    if (not progress or progress['generation'] != generation or progress['record_id'] is None
            or type(args.oldest_record) is not int or args.oldest_record <= progress['record_id']):
        raise AgentError('security_recovery_gap_not_proven', 409)
    if type(args.initial_read_hours) is not int or not 0 <= args.initial_read_hours <= 24:
        raise AgentError('security_recovery_depth_invalid')
    changed = {**config, 'channel_generations': {**config.get('channel_generations', {}),
        'Security': 'security-recovery-' + str(uuid4())}, 'initial_read_hours': args.initial_read_hours}
    result = policies.assign_module(cur, {'agent_id': agent_id, 'module_id': 'sli.windows.ad-dc',
        'enabled': True, 'config': changed, 'expected_revision': args.expected_revision}, actor='local:' + args.actor)
    return {'agent_id': agent_id, 'policy_revision': result['policy_revision'],
            'old_record': progress['record_id'], 'retained_oldest_record': args.oldest_record,
            'initial_read_hours': args.initial_read_hours, 'channel': 'Security'}


def run(args):
    if (not args.actor.strip() or len(args.actor) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in args.actor)):
        raise AgentError('security_recovery_actor_invalid')
    principal = owner_principal(args.owner_user_id)
    if not principal or effective_access(principal).get('platform_owner') is not True:
        raise AgentError('security_recovery_owner_required', 403)
    with connect() as conn, conn.cursor() as cur:
        result = recover(cur, args)
        conn.commit()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-id', required=True)
    parser.add_argument('--owner-user-id', required=True, type=int)
    parser.add_argument('--actor', required=True)
    parser.add_argument('--expected-revision', required=True, type=int)
    parser.add_argument('--oldest-record', required=True, type=int)
    parser.add_argument('--initial-read-hours', type=int, default=24)
    args = parser.parse_args()
    try:
        result = run(args)
    except AgentError as exc:
        sys.stderr.write(str(exc) + '\n')
        return 1
    except Exception:  # noqa: BLE001 - credentials and DB diagnostics stay private
        sys.stderr.write('security_recovery_failed\n')
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
