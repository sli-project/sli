#!/usr/bin/env python3
"""Read-only runtime watchdog snapshot.

The watchdog does not stop/start services or clean files. It only returns a JSON
snapshot that can be displayed in diagnostics or reviewed by operators.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.maintenance.bundle_common import write_json  # noqa: E402
from server.sli.ops.runtime_watchdog import run_watchdog  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run read-only runtime watchdog snapshot.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = run_watchdog()
    if args.out:
        write_json(args.out, result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
    else:
        print(f"Runtime watchdog: {result['status']} ({result['duration_ms']} ms)")
        for warning in result.get("warnings") or []:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
