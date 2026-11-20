"""Retire a pilot by ID after replacement enrollment, in one audited transaction."""
from __future__ import annotations

import argparse
import re
import sys

from server.sli.agents import registry
from server.sli.agents.ca import AgentError, uuid_text
from server.sli.core.postgres_runtime_pipeline import connect


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "revoke_agent_invalid_arguments\n")


def main(argv=None):
    parser = Parser(description="Retire an enrolled pilot as a local server administrator")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--replacement-host-id", required=True)
    parser.add_argument("--replacement-key-fingerprint", required=True)
    parser.add_argument("--actor", required=True)
    args = parser.parse_args(argv)
    try:
        agent_id = uuid_text(args.agent_id)
        host_id = uuid_text(args.replacement_host_id)
        if not re.fullmatch(r"[0-9a-f]{64}", args.replacement_key_fingerprint):
            raise AgentError("invalid_key_fingerprint")
        if not args.actor.strip() or len(args.actor) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in args.actor):
            raise AgentError("invalid_revoke_actor")
    except AgentError as exc:
        parser.exit(2, str(exc) + "\n")

    try:
        with connect() as conn, conn.cursor() as cur:
            # Lock the replacement against concurrent disable, and never retire it.
            cur.execute(
                "select a.id from sli_agents a where a.host_id=%s and a.key_fingerprint=%s "
                "and a.id<>%s and a.status='active' and exists (select 1 from sli_agent_certificates c "
                "where c.agent_id=a.id and c.revoked_at is null and c.not_after>clock_timestamp()) for update of a",
                (host_id, args.replacement_key_fingerprint, agent_id),
            )
            if not cur.fetchone():
                raise AgentError("replacement_agent_not_registered")
            registry.revoke(cur, {"agent_id": agent_id}, actor=args.actor, disable=True)
            conn.commit()
    except Exception:
        sys.stderr.write("revoke_agent_failed\n")
        return 1
    print("revoked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
