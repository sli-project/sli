#!/usr/bin/env python3
"""Run a bounded read-only analytics probe against the isolated warm tier."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


CONTAINER = "sli-warm-tier-step1"
DATABASE = "sli_warm"
DEFAULT_OUTPUT = (
    ROOT / "artifacts" / "stage7" / "evidence" / "warm-tier-read-probe.json"
)
MAX_WINDOW_DAYS = 365
MAX_QUERY_MEMORY_BYTES = 1_073_741_824
MAX_EXTERNAL_GROUP_BY_BYTES = 268_435_456
MAX_QUERY_THREADS = 4
MAX_RESULT_BYTES = 10_485_760

SESSION_ANALYTICS_QUERY = """
SELECT toDate(logon_time_utc) AS day,state,count() AS sessions,
       round(avg(ifNull(duration_s,0)),2) AS avg_duration_s,
       quantileExact(0.95)(ifNull(duration_s,0)) AS p95_duration_s
FROM sli_warm.sessions
WHERE logon_time_utc >= {from_utc:DateTime64(6,'UTC')}
  AND logon_time_utc < {to_utc:DateTime64(6,'UTC')}
GROUP BY day,state
ORDER BY day,state
FORMAT JSON
""".strip()


def _utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _clickhouse_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def build_command(time_from_utc: datetime, time_to_utc: datetime) -> list[str]:
    return [
        "docker",
        "exec",
        CONTAINER,
        "clickhouse-client",
        "--readonly",
        "1",
        "--max_execution_time",
        "30",
        "--max_memory_usage",
        str(MAX_QUERY_MEMORY_BYTES),
        "--max_bytes_before_external_group_by",
        str(MAX_EXTERNAL_GROUP_BY_BYTES),
        "--max_threads",
        str(MAX_QUERY_THREADS),
        "--max_result_rows",
        "2000",
        "--max_result_bytes",
        str(MAX_RESULT_BYTES),
        "--result_overflow_mode",
        "throw",
        "--query",
        SESSION_ANALYTICS_QUERY,
        "--param_from_utc",
        _clickhouse_timestamp(time_from_utc),
        "--param_to_utc",
        _clickhouse_timestamp(time_to_utc),
    ]


def run_probe(time_from_utc: datetime, time_to_utc: datetime) -> dict[str, Any]:
    if time_from_utc >= time_to_utc:
        raise ValueError("time_from_utc must be before time_to_utc")
    window_days = (time_to_utc - time_from_utc).total_seconds() / 86400
    if window_days > MAX_WINDOW_DAYS:
        raise ValueError(f"probe window must not exceed {MAX_WINDOW_DAYS} days")

    command = build_command(time_from_utc, time_to_utc)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        timeout=45,
        check=False,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"warm-tier read probe failed: {error}")

    payload = json.loads(completed.stdout.decode("utf-8"))
    statistics = payload.get("statistics") or {}
    rows = payload.get("data") or []
    return {
        "package_type": "WARM_TIER_READ_PROBE",
        "status": "ok",
        "mode": "isolated_read_only",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": {
            "container": CONTAINER,
            "database": DATABASE,
            "time_from_utc": time_from_utc.isoformat(),
            "time_to_utc": time_to_utc.isoformat(),
            "window_days": window_days,
        },
        "safety": {
            "clickhouse_readonly": True,
            "production_postgresql_contacted": False,
            "production_routing_changed": False,
            "feature_flags_changed": False,
        },
        "result": {
            "groups": rows,
            "group_count": len(rows),
            "rows_read": int(statistics.get("rows_read") or 0),
            "bytes_read": int(statistics.get("bytes_read") or 0),
            "elapsed_seconds": float(statistics.get("elapsed") or 0),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-utc", required=True, type=_utc)
    parser.add_argument("--to-utc", required=True, type=_utc)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    result = run_probe(args.from_utc, args.to_utc)
    output = args.output.resolve()
    evidence_root = (ROOT / "artifacts" / "stage7" / "evidence").resolve()
    if output.parent != evidence_root:
        parser.error(f"output must be directly inside {evidence_root}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
