"""Read-only EXPLAIN of the production stream query using ADLOG_PG_DSN.

Run from the candidate checkout: python -m scripts.maintenance.explain_agent_collection_health
Redirect stdout to retain the JSON plan. No DSN, registry rows or payloads are printed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()
    dsn = os.environ.get("ADLOG_PG_DSN")
    if not dsn:
        print("ADLOG_PG_DSN is required in the process environment", file=sys.stderr)
        return 2

    import psycopg
    from psycopg.rows import dict_row

    from server.sli.agents.collection_health import (
        _AGENTS_SQL,
        _STREAMS_SQL,
        _requested_streams,
    )
    from server.sli.core.database import _pg_sql

    try:
        with psycopg.connect(dsn, row_factory=dict_row,
                             options="-c default_transaction_read_only=on", connect_timeout=5) as conn:
            conn.execute("set transaction isolation level repeatable read, read only")
            conn.execute("set local search_path=pg_catalog,public")
            conn.execute("set local statement_timeout='3s'")
            conn.execute("set local jit=off")
            if conn.execute("select to_regclass('public.sli_agent_stream_import_health') as name").fetchone()["name"] is None:
                print("Migration 297 is required; no migration was applied", file=sys.stderr)
                return 2
            agents = conn.execute(_pg_sql(_AGENTS_SQL)).fetchall()
            requested = _requested_streams(agents)
            plan = conn.execute("explain (analyze,buffers,format json) " + _pg_sql(_STREAMS_SQL),
                                (json.dumps(requested),)).fetchone()["QUERY PLAN"][0]
            buffers = sum(plan["Plan"].get(key, 0) for key in (
                "Shared Hit Blocks", "Shared Read Blocks", "Local Hit Blocks", "Local Read Blocks"))
            print(json.dumps({"requested_streams": len(requested), "statement_timeout_ms": 3000,
                              "target_ms": 300, "jit": "off", "required_migration": 297,
                              "execution_ms": plan["Execution Time"], "buffers": buffers,
                              "within_target": plan["Execution Time"] <= 300,
                              "plan": plan}, indent=2))
            conn.rollback()
    except psycopg.Error as exc:
        # Exception text can contain connection credentials or server details.
        print(f"EXPLAIN failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
