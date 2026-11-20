from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.sli.ops.runtime_parity import audit_pg_runtime_parity  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit PostgreSQL runtime boundaries and hidden SQLite access.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = audit_pg_runtime_parity(PROJECT_ROOT)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"PG runtime parity audit: {result['status']}")
        for failure in result.get("failures") or []:
            print(f"- {failure}")
    return 0 if result["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
