#!/usr/bin/env python3
"""Вывести подробное состояние PostgreSQL без изменения базы."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.maintenance.bundle_common import json_default  # noqa: E402
from server.sli.ops.postgres_operations import get_postgres_operations_status  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Подробное состояние PostgreSQL; выполняются только SELECT."
    )
    parser.add_argument("--table-limit", type=int, default=15)
    parser.add_argument("--long-query-seconds", type=int, default=60)
    args = parser.parse_args()
    result = get_postgres_operations_status(
        table_limit=max(1, min(args.table_limit, 100)),
        long_query_seconds=max(1, args.long_query_seconds),
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, default=json_default))
    return 0 if result.get("status") in {"ok", "warn"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
