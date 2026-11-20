"""Local owner command using the audited workstation policy operations."""
from __future__ import annotations

import argparse
import json
import sys
from uuid import uuid4

from server.sli.access.access_control_v4 import effective_access
from server.sli.agents import policies
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.agents.file_audit_admin import owner_principal
from server.sli.core.postgres_runtime_pipeline import connect
from sli_agent.workstations import WorkstationsModule


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "workstation_admin_arguments_invalid\n")


def recover_security_config(cur, agent, config):
    """Re-read a blocked channel with an explicit, unknown-loss generation gap."""
    cur.execute("""select envelope,packet from sli_agent_packet_inbox
        where envelope->>'agent_id'=%s and envelope->>'module_id'='sli.workstations'
          and packet->'header'->>'channel'='Security'
        order by (envelope->>'sequence')::bigint desc limit 3""", (str(agent['id']),))
    rows = cur.fetchall()
    generation = config.get('channel_generations', {}).get('Security', str(agent['host_id']))
    collector = WorkstationsModule(str(agent['host_id']), config)
    blocked = []
    for row in rows:
        envelope, packet = row['envelope'], row['packet']
        progress = collector._state({'generation': envelope['generation'],
                                    'cursor_after': envelope['cursor_after']})['channels'].get('Security')
        if (envelope.get('policy_revision') != config.get('policy_revision')
                or packet.get('context', {}).get('workstations', {}).get('read_error')
                != 'agent_workstations_read_failed'
                or not progress or progress['generation'] != generation or progress['record_id'] is None):
            raise AgentError('workstation_security_recovery_not_blocked', 409)
        blocked.append(progress)
    if len(blocked) != 3 or any(value != blocked[0] for value in blocked):
        raise AgentError('workstation_security_recovery_not_blocked', 409)
    # Never claim the cause was an overwrite. The existing capture contract
    # reports channel_reset/gap with unknown lost_count on this generation.
    return {**config, 'channel_generations': {**config.get('channel_generations', {}),
                                             'Security': 'security-recovery-' + str(uuid4())}}


def run(args):
    agent_id = uuid_text(args.agent_id)
    if (args.owner_user_id <= 0 or not args.actor.strip() or len("local:" + args.actor) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in args.actor)):
        raise AgentError("workstation_admin_arguments_invalid")
    principal = owner_principal(args.owner_user_id)
    if not principal or effective_access(principal).get("platform_owner") is not True:
        raise AgentError("workstation_admin_owner_required", 403)
    actor = "local:" + args.actor
    with connect() as conn, conn.cursor() as cur:
        agent = policies._agent(cur, agent_id)
        policies._next_revision(agent, args.expected_revision)
        # Preserve an existing owner's family/filter configuration on recovery.
        matches = [m for m in agent["assigned_modules"] if isinstance(m, dict)
                   and m.get("module_id") == "sli.workstations"]
        if len(matches) > 1:
            raise AgentError("invalid_agent_module_assignment")
        config = matches[0].get("config", {}) if matches else {}
        config = dict(config)
        if args.recover_security_read:
            if len(matches) != 1 or matches[0].get('enabled') is not True:
                raise AgentError('workstation_security_recovery_not_blocked', 409)
            config = recover_security_config(cur, agent, config)
        if args.batch_size is not None:
            config["batch_size"] = args.batch_size
        result = policies.assign_module(cur, {"agent_id": agent_id,
            "expected_revision": args.expected_revision, "module_id": "sli.workstations",
            "enabled": True, "config": config}, actor=actor)
        revision = result["policy_revision"]
        control = {"state": "active"}
        for name in ("interval_seconds", "batch_size"):
            if getattr(args, name) is not None:
                control[name] = getattr(args, name)
        if args.enable_audit:
            control["manage_windows_audit"] = True
        result = policies.update_control(cur, {"agent_id": agent_id,
            "expected_revision": revision, "collection_policy": control}, actor=actor)
        # assign_module/update_control already persist the supported audit actions
        # in this transaction. Do not introduce an unregistered action here.
        conn.commit()
        return {"agent_id": agent_id, "policy_revision": result["policy_revision"],
                "state": "active", "manage_windows_audit": result["collection_policy"]["manage_windows_audit"]}


def main(argv=None):
    parser = Parser(description=__doc__)
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--owner-user-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--expected-revision", required=True, type=int)
    parser.add_argument("--enable-audit", action="store_true")
    parser.add_argument("--recover-security-read", action="store_true")
    parser.add_argument("--interval-seconds", type=int)
    parser.add_argument("--batch-size", type=int)
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except AgentError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except Exception:  # noqa: BLE001 - no credentials or source diagnostics
        sys.stderr.write("workstation_admin_failed\n")
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
