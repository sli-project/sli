"""Trusted local server owner CLI over the existing audited agent operations.

Like issue_token, access to the server runtime is the local authentication
boundary. An active platform owner supplies the product authority; this command
does not create sessions or grants, and never bypasses plugin scope checks.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import uuid4

from server.sli.access.access_control_v4 import _principal_for_user, effective_access
from server.sli.agents import policies, registry
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.plugins.registry import plugin_hook
from sli_agent.file_audit_policy import policy


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "file_audit_admin_arguments_invalid\n")


def owner_principal(user_id):
    try:
        return _principal_for_user(user_id)
    except ValueError:
        raise AgentError("file_audit_admin_owner_required", 403) from None


def run(args):
    agent_id = uuid_text(args.agent_id)
    if (args.owner_user_id <= 0 or not args.actor.strip() or len(args.actor) > 128
            or any(ord(char) < 32 or ord(char) == 127 for char in args.actor)
            or args.action != "apply" and (args.enable_management or args.assign_module)
            or args.action != "status" and (args.policy is None or args.expected_revision is None)
            or args.action == "status" and (args.policy is not None or args.expected_revision is not None)):
        raise AgentError("file_audit_admin_arguments_invalid")
    principal = owner_principal(args.owner_user_id)
    if not principal:
        raise AgentError("file_audit_admin_owner_required", 403)
    access = effective_access(principal)
    if access.get("platform_owner") is not True:
        raise AgentError("file_audit_admin_owner_required", 403)
    hook = plugin_hook("sli.file-audit", "audit_status" if args.action == "status" else "enqueue_audit")
    if hook is None:
        raise AgentError("file_audit_plugin_unavailable", 409)
    config = None
    if args.action != "status":
        if args.policy.stat().st_size > 48 * 1024:
            raise AgentError("file_audit_admin_policy_invalid")
        try:
            config = policy(json.loads(args.policy.read_text("utf-8-sig")))
        except (ValueError, TypeError):
            raise AgentError("file_audit_admin_policy_invalid") from None
    actor = "local:" + args.actor
    with connect() as conn, conn.cursor() as cur:
        if args.action == "status":
            return hook(cur, agent_id, principal=principal, access=access)
        agent = policies._agent(cur, agent_id)
        policies._next_revision(agent, args.expected_revision)
        revision = args.expected_revision
        if args.enable_management:
            result = policies.update_control(cur, {"agent_id": agent_id, "expected_revision": revision,
                "collection_policy": {"manage_windows_audit": True}}, actor=actor)
            revision = result["policy_revision"]
        command = {"contract_id": "sli.file-audit.audit-command.v1", "command_id": str(uuid4()),
                   "action": args.action, "policy_revision": str(revision + 1),
                   "collection_scope_ids": [root["collection_scope_id"] for root in config["roots"]]}
        result = hook(cur, {"agent_id": agent_id, "expected_revision": revision,
                           "config": config, "command": command,
                           **({"activate_collection": True, "enabled": True} if args.assign_module else {})},
                      principal=principal, access=access)
        registry.audit(cur, "local_file_audit_command", actor, agent_id,
                       owner_user_id=args.owner_user_id, command_id=result["command_id"],
                       command_action=args.action, revision=result["policy_revision"])
        conn.commit()
        return result


def main(argv=None):
    parser = Parser(description="Local server owner file-audit administration")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--owner-user-id", required=True, type=int)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--action", required=True, choices=("check", "apply", "restore", "status"))
    parser.add_argument("--expected-revision", type=int)
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--enable-management", action="store_true")
    parser.add_argument("--assign-module", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except AgentError as exc:
        sys.stderr.write(str(exc) + "\n")
        return 1
    except Exception:  # noqa: BLE001 - no credentials, database diagnostics or private paths
        sys.stderr.write("file_audit_admin_failed\n")
        return 1
    print(json.dumps(result, ensure_ascii=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
