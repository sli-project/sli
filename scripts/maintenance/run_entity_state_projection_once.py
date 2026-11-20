"""Process a bounded batch of already-published Storage V2 state jobs."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.entities.entity_state_runtime import (
    connect_entity_state_worker as _connect,
    run_entity_state_projection_cycle as run_once,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run bounded durable entity-state projection.")
    parser.add_argument("--execute", action="store_true", help="Required; no database connection is made without it.")
    parser.add_argument("--limit", type=int, default=1, help="Jobs to process (1..16).")
    args = parser.parse_args()
    if not args.execute:
        result: dict[str, object] = {"status": "blocked", "reason": "--execute is required", "connections": 0}
    else:
        result = run_once(limit=max(1, min(int(args.limit), 16)))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result.get("status") in {"ok", "blocked"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
