from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from server.sli.ops.logging_config import append_jsonl_bounded, log_event
from server.sli.core.paths import DATA_DIR

PERFORMANCE_LOG_PATH = DATA_DIR / "logs" / "performance-events.log"
_PERF_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def monotonic_ms() -> int:
    return int(time.monotonic() * 1000)


def _json_default(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    return str(value)


def log_performance_stage(
    stage: str,
    *,
    trace_id: str | None = None,
    job_id: int | None = None,
    server: str | None = None,
    channel: str | None = None,
    backend: str | None = None,
    status: str = "completed",
    started_ms: int | None = None,
    duration_ms: int | None = None,
    events_count: int | None = None,
    bytes_count: int | None = None,
    error: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """Write a P-Core performance JSONL record for one measured pipeline stage.

    This log answers the operator question: where does collection spend time?
    It is intentionally independent from the normal monitor log so it can be
    tailed, parsed and graphed without mixing with business events.
    """
    if duration_ms is None and started_ms is not None:
        duration_ms = max(0, monotonic_ms() - started_ms)
    payload: dict[str, Any] = {
        "ts": utc_now(),
        "trace_id": trace_id,
        "job_id": job_id,
        "server": server,
        "channel": channel,
        "backend": backend,
        "stage": stage,
        "status": status,
        "duration_ms": duration_ms,
        "events_count": events_count,
        "bytes_count": bytes_count,
        "error": error,
    }
    payload.update(fields)
    payload = {key: value for key, value in payload.items() if value not in (None, "")}
    PERFORMANCE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    PERFORMANCE_LOG_PATH.touch(exist_ok=True)
    with _PERF_LOCK:
        append_jsonl_bounded(
            PERFORMANCE_LOG_PATH,
            payload,
            max_bytes=20_000_000,
        )
    log_event(
        "performance",
        "stage_completed" if status == "completed" else "stage_status",
        "Collection pipeline stage measured.",
        stage=stage,
        trace_id=trace_id,
        job_id=job_id,
        server=server,
        channel=channel,
        backend=backend,
        status=status,
        duration_ms=duration_ms,
        events_count=events_count,
        bytes_count=bytes_count,
        error=error,
        **{key: value for key, value in fields.items() if value not in (None, "")},
    )
    return payload


class StageTimer:
    def __init__(self, stage: str, **fields: Any) -> None:
        self.stage = stage
        self.fields = fields
        self.started_ms = monotonic_ms()

    def finish(self, *, status: str = "completed", **fields: Any) -> dict[str, Any]:
        merged = dict(self.fields)
        merged.update(fields)
        return log_performance_stage(self.stage, started_ms=self.started_ms, status=status, **merged)
