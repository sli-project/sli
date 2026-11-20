"""Trusted local server owner CLI; uses the same audited recovery as the UI."""
import argparse
import json
import sys
from server.sli.access.access_control_v4 import effective_access
from server.sli.agents.file_audit_admin import owner_principal
from server.sli.agents import sequence_recovery
from server.sli.agents.ca import AgentError
from server.sli.core.postgres_runtime_pipeline import connect


def run(args):
    actor="local-owner:"+str(args.owner_user_id)+":"+args.actor
    if args.owner_user_id <= 0 or not args.actor.strip() or len(actor) > 128 or any(ord(c)<32 or ord(c)==127 for c in args.actor):
        raise AgentError('agent_sequence_recovery_invalid')
    principal=owner_principal(args.owner_user_id)
    if not principal: raise AgentError('platform_owner_required',403)
    access=effective_access(principal)
    sequence_recovery._owner(access)
    if args.action == 'status':
        if not args.agent_id or args.observation_id or args.preview_token or args.confirm_loss:
            raise AgentError('agent_sequence_recovery_invalid')
    elif not args.agent_id or not args.observation_id or not args.preview_token or not args.confirm_loss:
        raise AgentError('agent_sequence_recovery_invalid')
    with connect() as conn,conn.cursor() as cur:
        if args.action=='status':
            return sequence_recovery.list_gaps(cur,args.agent_id,access=access)
        result=sequence_recovery.authorize_all(cur,{'agent_id':args.agent_id,'observation_ids':args.observation_id,'preview_token':args.preview_token,'confirm_loss':True},
            actor=actor,access=access)
        conn.commit()
        return result


def main(argv=None):
    parser=argparse.ArgumentParser(description='Explicit owner authorization of a recorded packet gap; does not prove events are irrecoverable')
    parser.add_argument('--owner-user-id',required=True,type=int)
    parser.add_argument('--actor',required=True)
    parser.add_argument('--action',required=True,choices=('status','authorize'))
    parser.add_argument('--agent-id')
    parser.add_argument('--observation-id',action='append',help='Repeat for every exact ID in the displayed recovery preview')
    parser.add_argument('--preview-token',help='Exact token from the displayed recovery preview')
    parser.add_argument('--confirm-loss',action='store_true',help='Accept the exact recorded packet gap; event count/time bounds are unknown')
    args=parser.parse_args(argv)
    try: result=run(args)
    except AgentError as exc:
        sys.stderr.write(str(exc)+'\n');return 1
    except Exception:
        sys.stderr.write('agent_sequence_recovery_failed\n');return 1
    print(json.dumps(result,ensure_ascii=True,default=str));return 0


if __name__=='__main__':
    raise SystemExit(main())
