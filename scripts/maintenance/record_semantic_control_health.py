#!/usr/bin/env python3
"""Preview or record bounded control health from local PostgreSQL state only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_control_health import record_current_security_control_health  # noqa: E402
from server.sli.core.app_config import load_config  # noqa: E402

CONFIRMATION = "SEMANTIC-CONTROL-HEALTH-LOCAL-1"


def _admin_connection():
    import psycopg
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row

    parts = conninfo_to_dict(load_config().postgres_dsn or "")
    user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not user or not password:
        raise RuntimeError("local PostgreSQL admin credentials are required for execute")
    parts.update(user=user, password=password, application_name="adlog_semantic_control_health_recorder")
    return psycopg.connect(**parts, row_factory=dict_row)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--max-sources", type=int, default=20)
    args = parser.parse_args()
    if args.execute and args.confirm != CONFIRMATION:
        print(json.dumps({"status": "failed", "reason": f"--execute requires --confirm {CONFIRMATION}"}, ensure_ascii=False))
        return 2
    try:
        if args.execute:
            with _admin_connection() as conn:
                result = record_current_security_control_health(
                    execute=True, max_sources=args.max_sources, connection=conn,
                )
        else:
            result = record_current_security_control_health(
                execute=False, max_sources=args.max_sources,
            )
    except Exception as exc:
        result = {"status": "failed", "error_type": type(exc).__name__, "error": str(exc)}
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    return 0 if result.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
