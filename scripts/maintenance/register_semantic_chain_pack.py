#!/usr/bin/env python3
"""Install the semantic chain pack as DRAFT rules only.

This command is deliberately not a worker launcher and cannot move a rule out
of DRAFT.  TEST/SHADOW promotion remains a separate owner-controlled action.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_chain_pack import (  # noqa: E402
    DEFAULT_PACK_PATH,
    load_dispatch_rule_pack,
    register_draft_dispatch_rule_pack,
)
from server.sli.semantic.semantic_worker_connection import connect_semantic_worker  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Register semantic chain rules in DRAFT only.")
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK_PATH)
    parser.add_argument("--apply", action="store_true", help="Persist DRAFT rules; omitted means read-only validation.")
    args = parser.parse_args()
    rules = load_dispatch_rule_pack(args.pack)
    payload = {
        "pack": str(args.pack),
        "apply": bool(args.apply),
        "lifecycle": "draft",
        "rules": [f"{item.rule_id}@{item.rule_version}" for item in rules],
        "worker_started": False,
        "findings_created": 0,
    }
    if not args.apply:
        payload["status"] = "validated_read_only"
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    with connect_semantic_worker() as conn:
        with conn.transaction(), conn.cursor() as cur:
            payload["registered"] = list(register_draft_dispatch_rule_pack(cur, args.pack))
    payload["status"] = "registered_draft"
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
