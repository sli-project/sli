#!/usr/bin/env python3
"""Build or execute exactly one sealed empty-tier warm bootstrap batch."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from server.sli.storage.warm_tier_bootstrap_runtime import (
    DEFAULT_PLAN,
    EVIDENCE_ROOT,
    execute_bootstrap,
    plan_and_record,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--batch-limit", type=int, default=10_000)
    parser.add_argument("--scan-limit", type=int, default=500_000)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirmation")
    args = parser.parse_args()
    plan_path = args.plan.resolve()
    if plan_path.parent != EVIDENCE_ROOT.resolve():
        parser.error(f"plan must be directly inside {EVIDENCE_ROOT}")
    try:
        if args.execute:
            result = execute_bootstrap(
                plan_path, confirmation=args.confirmation, execute=True,
            )
        else:
            if args.confirmation is not None:
                parser.error("--confirmation is valid only with --execute")
            result = plan_and_record(
                output_path=plan_path, batch_limit=args.batch_limit,
                scan_limit=args.scan_limit,
            )
    except (RuntimeError, ValueError, OSError) as exc:
        result = {
            "package_type": "WARM_TIER_BOOTSTRAP_RECEIPT",
            "status": "blocked", "error": str(exc)[:1000],
            "safety": {"routing_changed": False, "delete_performed": False, "runtime_started": False},
        }
    print(json.dumps(result, ensure_ascii=False, default=str))
    return 0 if result.get("status") not in {"blocked"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
