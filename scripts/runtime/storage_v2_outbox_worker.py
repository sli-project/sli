"""Retired Storage V2 outbox worker (plan 6.5).

Imports publish straight to Storage V2, and the V1 relations this worker
drained and cleaned up were dropped by migration 097, so it has no work left.
The supervisor no longer starts it. The file stays because the applied AD DC
compatibility registration (config/stage9_ad_dc_compatibility_registration_v1.json)
lists it among the existing execution entrypoints.
"""

from __future__ import annotations

import json
import sys


def main(argv: list[str] | None = None) -> int:
    del argv
    print(json.dumps({"status": "retired", "reason": "storage_v2_outbox_removed_plan_6_5"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
