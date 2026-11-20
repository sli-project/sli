"""Local administrator: one command prepares, waits for drain, then switches."""
import argparse
import json
import sys
import time

from server.sli.access.access_control_v4 import effective_access
from server.sli.agents import runtime_switch
from server.sli.agents.ca import AgentError
from server.sli.agents.file_audit_admin import owner_principal
from server.sli.core.postgres_runtime_pipeline import connect


def run(args):
    actor = f"local:{args.owner_user_id}:{args.actor}"
    if (args.owner_user_id <= 0 or not args.actor.strip() or len(actor) > 128
            or any(ord(c) < 32 or ord(c) == 127 for c in actor)
            or not 0 <= args.wait_seconds <= 3600 or not args.confirm):
        raise AgentError("agent_replacement_invalid")
    principal = owner_principal(args.owner_user_id)
    if not principal:
        raise AgentError("agent_replacement_denied", 403)
    access = effective_access(principal)
    body = {"old_agent_id": args.old_agent_id, "new_agent_id": args.new_agent_id, "confirm": True}

    def operation(phase):
        # Never retain a transaction/row lock while waiting for an agent.
        with connect() as conn, conn.cursor() as cur:
            result = runtime_switch.replace(cur, {**body, "phase": phase}, actor=actor, access=access)
            conn.commit()
            return result

    result = operation("prepare")
    if result["state"] == "completed":
        return result
    deadline = time.monotonic() + args.wait_seconds
    while True:
        try:
            return operation("complete")
        except AgentError as exc:
            if str(exc) not in {"agent_replacement_not_ready", "agent_replacement_pending_import"}:
                raise
            if time.monotonic() >= deadline:
                return {**result, "reason": str(exc)}
            time.sleep(min(5, max(0, deadline - time.monotonic())))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner-user-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--old-agent-id", required=True)
    parser.add_argument("--new-agent-id", required=True)
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--wait-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except AgentError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except Exception:
        sys.stderr.write("agent_replacement_failed\n")
        return 1
    print(json.dumps(result, ensure_ascii=True, default=str))
    return 0 if result["state"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
