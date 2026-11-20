#!/usr/bin/env python3
"""Quick UI/navigation sanity check for release gate.

This is intentionally structural and fast. It validates that known dynamic report
routes and role-view metadata are registered without rendering heavy pages.
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
from server.sli.ops.ui_nav_check import REQUIRED_REPORTS, REQUIRED_ROLES, run_ui_nav_check  # noqa: E402,F401


def main() -> int:
    parser = argparse.ArgumentParser(description="Run quick UI/navigation release check.")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = run_ui_nav_check()
    if args.out:
        write_json(args.out, result)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"UI nav check: {result['status']} ({result['duration_ms']} ms)")
        for warning in result.get("warnings") or []:
            print(f"- {warning}")
    return 0 if result["status"] in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
