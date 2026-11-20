"""Run one bounded, explicitly enabled semantic risk evaluation batch."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from time import perf_counter
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sli.semantic.semantic_processing import SemanticFeatureSettings  # noqa: E402
from server.sli.semantic.semantic_worker_connection import (  # noqa: E402
    connect_semantic_worker,
)
from server.sli.semantic.semantic_risk_runtime_repository import (  # noqa: E402
    claim_risk_evaluation_jobs,
    enqueue_risk_backlog,
    execute_risk_evaluation,
    fail_risk_evaluation_job,
    load_risk_evaluation_work_item,
)


def _connect():
    return connect_semantic_worker()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run one fail-closed semantic risk TEST/SHADOW/ENABLED batch."
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--limit", type=int, default=1)
    args = parser.parse_args()
    settings = SemanticFeatureSettings.from_env()
    if not args.execute or not settings.risk_engine_enabled:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": (
                        "--execute and the complete semantic dependency chain through "
                        "ADLOG_SEMANTIC_RISK_ENGINE_ENABLED are required"
                    ),
                    "connections": 0,
                }
            )
        )
        return 0

    limit = max(1, min(int(args.limit), 16))
    conn = _connect()
    queued = 0
    completed = 0
    failed = 0
    modes: dict[str, int] = {"test": 0, "shadow": 0, "enabled": 0}
    try:
        with conn.cursor() as cur:
            cur.execute(
                "select 1 from schema_migrations "
                "where version=29 and name='semantic_risk_runtime'"
            )
            if not cur.fetchone():
                raise RuntimeError("migration 029 is required")
        conn.commit()
        with conn.transaction(), conn.cursor() as cur:
            queued = len(enqueue_risk_backlog(cur, limit=limit))
        for _ in range(limit):
            with conn.transaction(), conn.cursor() as cur:
                claimed = claim_risk_evaluation_jobs(cur, limit=1)
            if not claimed:
                break
            job = claimed[0]
            started = perf_counter()
            try:
                with conn.transaction(), conn.cursor() as cur:
                    work = load_risk_evaluation_work_item(
                        cur,
                        job_id=str(job["job_id"]),
                        lease_token=str(job["lease_token"]),
                    )
                    result = execute_risk_evaluation(
                        cur,
                        work=work,
                        evaluation_ms=max(0, int((perf_counter() - started) * 1000)),
                    )
                    modes[result.evaluation_mode] += 1
                    completed += 1
            except Exception as exc:
                with conn.transaction(), conn.cursor() as cur:
                    fail_risk_evaluation_job(
                        cur,
                        job_id=str(job["job_id"]),
                        lease_token=str(job["lease_token"]),
                        attempt_count=int(job["attempt_count"]),
                        max_attempts=int(job["max_attempts"]),
                        error_code=type(exc).__name__,
                        error_detail=str(exc),
                    )
                failed += 1
    finally:
        conn.close()
    print(
        json.dumps(
            {
                "status": "ok" if not failed else "partial",
                "queued": queued,
                "completed": completed,
                "failed": failed,
                "modes": modes,
                "findings_created": 0,
            },
            sort_keys=True,
        )
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
