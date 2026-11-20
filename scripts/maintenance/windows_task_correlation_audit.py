#!/usr/bin/env python3
"""Task Scheduler correlation evaluator (live audit retired in plan 6.5)."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


TASK_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"
EXPECTED_EVENT_IDS = (100, 102, 200, 201)


def evaluate_task_correlation(
    event_rows: list[dict[str, Any]],
    pair_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    by_event = {int(row["event_id"]): row for row in event_rows}
    normalization_ready = set(by_event) == set(EXPECTED_EVENT_IDS) and all(
        int(by_event[event_id]["total"]) > 0
        and int(by_event[event_id]["nonempty"]) == int(by_event[event_id]["total"])
        and int(by_event[event_id]["uuid_shaped"]) == int(by_event[event_id]["total"])
        for event_id in EXPECTED_EVENT_IDS
    )
    by_pair = {
        (int(row["opener"]), int(row["closer"])): row
        for row in pair_rows
    }

    def pair_is_one_to_one(opener: int, closer: int) -> bool:
        if not normalization_ready or (opener, closer) not in by_pair:
            return False
        open_row = by_event[opener]
        close_row = by_event[closer]
        shared = int(by_pair[(opener, closer)]["shared_ids"])
        return (
            int(open_row["distinct_ids"]) == int(open_row["total"])
            and int(close_row["distinct_ids"]) == int(close_row["total"])
            and shared == int(close_row["distinct_ids"])
        )

    return {
        "status": "ok" if normalization_ready else "gaps_found",
        "normalization_ready": normalization_ready,
        "safe_pair_candidates": {
            "100_to_102_by_correlation_id": pair_is_one_to_one(100, 102),
            "200_to_201_by_correlation_id": pair_is_one_to_one(200, 201),
        },
        "event_metrics": event_rows,
        "pair_metrics": pair_rows,
        "raw_identifiers_in_report": False,
    }


def main() -> int:
    # The live audit read the V1 `events` table, which migration 097 dropped
    # (plan 6.5). Only the pure evaluator above remains, for its unit tests.
    print(json.dumps({"status": "retired", "reason": "v1_events_dropped_plan_6_5"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
