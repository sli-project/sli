"""Write one compact, machine-readable snapshot of the live runtime baseline.

It is read-only: no AD/DC call, collection, migration, backup or restart.  The
single stable output replaces hand-copied counters in handoff documents.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.sources.collector_health import get_collector_health
from server.sli.core.postgres_runtime_pipeline import connect
from server.sli.sources.runtime_collection_history import recent_runtime_collection_runs


def _embedded_scheduler_status() -> str:
    """Read the last server start declaration, not this utility's environment."""
    path = ROOT / "data" / "logs" / "server-runtime.log"
    try:
        tail = path.read_text(encoding="utf-8", errors="replace")[-20_000:]
    except OSError:
        return "unknown"
    lines = [line.strip() for line in tail.splitlines() if line.strip().startswith("Schedule:")]
    if not lines:
        return "unknown"
    return "disabled" if "disabled" in lines[-1].lower() else "enabled"


def build() -> dict[str, Any]:
    health = get_collector_health()
    with connect() as conn, conn.cursor() as cur:
        cur.execute("select coalesce(max(version),0) as version from schema_migrations")
        migration = int((cur.fetchone() or {}).get("version") or 0)
        cur.execute("select pg_database_size(current_database()) as bytes")
        database_bytes = int((cur.fetchone() or {}).get("bytes") or 0)
    return {
        "package_type": "RUNTIME_BASELINE",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "runtime": {
            "database_backend": health.get("backend"),
            "database_migration_version": migration,
            "database_bytes": database_bytes,
            "scheduler_embedded_status": _embedded_scheduler_status(),
        },
        "operations_slo": health.get("operations_slo"),
        "security_channels": [
            {key: item.get(key) for key in ("server", "last_successful_collection_utc", "last_event_time_utc", "lag_minutes", "last_status", "timeouts_24h", "partial_timeouts_24h")}
            for item in health.get("items", []) if item.get("channel") == "Security"
        ],
        "collection_runs": recent_runtime_collection_runs(limit=5),
        "storage_v2_outbox": health.get("storage_v2_outbox"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Write the current read-only runtime baseline.")
    parser.add_argument("--out", type=Path, default=ROOT / "artifacts" / "runtime_baseline.json")
    args = parser.parse_args()
    payload = build()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.out.with_suffix(args.out.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    temporary.replace(args.out)
    print(json.dumps({"status": "ok", "path": str(args.out), "slo": (payload.get("operations_slo") or {}).get("status")}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
