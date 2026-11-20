"""Local server administrator CLI; commit token and audit before revealing it."""
from __future__ import annotations

import argparse
import re
import sys

from server.sli.agents import registry
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.core.postgres_runtime_pipeline import connect


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics can echo supplied account/input values.
        self.exit(2, "issue_token_invalid_arguments\n")


def main(argv=None):
    parser = Parser(description="Issue a host-bound one-time token as a local server administrator")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--key-fingerprint", required=True)
    parser.add_argument("--host-name", help="Administrator-approved computer name for replacement enrollment")
    parser.add_argument("--replacement-for", help="Old agent UUID: enroll idle for explicit drain-fenced replacement")
    parser.add_argument("--instance-name", help="Exact instance name also supplied as MSI INSTANCE_NAME")
    parser.add_argument("--ttl", type=int, default=900)
    parser.add_argument("--actor", required=True)
    args = parser.parse_args(argv)
    try:
        host_id = uuid_text(args.host_id)
        if not re.fullmatch(r"[0-9a-f]{64}", args.key_fingerprint):
            raise AgentError("invalid_key_fingerprint")
        if not 60 <= args.ttl <= 900:
            raise AgentError("invalid_enrollment_ttl")
        if args.host_name is not None and registry.reported_hostname(args.host_name) is None:
            raise AgentError("invalid_agent_registration_name")
        if not args.actor.strip() or len(args.actor) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in args.actor):
            raise AgentError("invalid_token_actor")
    except AgentError as exc:
        parser.exit(2, str(exc) + "\n")

    try:
        with connect() as conn, conn.cursor() as cur:
            result = registry.create_token(cur, {
                "host_id": host_id, "key_fingerprint": args.key_fingerprint,
                "ttl_seconds": args.ttl,
                **({"replacement_for": args.replacement_for} if args.replacement_for else {}),
                **({"instance_name": args.instance_name} if args.instance_name else {}),
                **({"registration_host_name": args.host_name} if args.host_name is not None else {}),
            }, actor=args.actor)
            conn.commit()
    except Exception:
        # Never expose database diagnostics, bind values, or exception text.
        sys.stderr.write("issue_token_failed\n")
        return 1
    print(result["token"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
