from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_SCHEMA_REQUIRED_FIELDS = [
    "ts",
    "level",
    "component",
    "event",
    "message",
    "pid",
    "thread",
]

ERROR_SCHEMA_REQUIRED_FIELDS = [
    *LOG_SCHEMA_REQUIRED_FIELDS,
    "internal_error_id",
    "error_type",
    "error",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_internal_error_id(prefix: str = "INT") -> str:
    return f"{prefix}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"


def make_structured_log_payload(
    *,
    component: str,
    event: str,
    message: str,
    level: str = "INFO",
    **fields: Any,
) -> dict[str, Any]:
    """Build a normalized JSONL log payload used by diagnostics/self-test.

    This function is side-effect free and can be tested independently. It is the
    source contract for Stage 1 structured logging: every long-running or risky
    stage should include component/event/status/duration_ms and, when relevant,
    job_id/trace_id/server/channel/stage counters.
    """
    payload: dict[str, Any] = {
        "ts": utc_now(),
        "level": str(level or "INFO").upper(),
        "component": str(component or "unknown"),
        "event": str(event or "event"),
        "message": str(message or ""),
        "pid": os.getpid(),
        "thread": threading.current_thread().name,
    }
    for key, value in fields.items():
        if value in (None, ""):
            continue
        payload[key] = value
    return payload


def validate_structured_log_payload(payload: dict[str, Any], *, error: bool = False) -> dict[str, Any]:
    required = ERROR_SCHEMA_REQUIRED_FIELDS if error else LOG_SCHEMA_REQUIRED_FIELDS
    missing = [key for key in required if key not in payload]
    warnings: list[str] = []
    if "duration_ms" in payload:
        try:
            if int(payload["duration_ms"]) < 0:
                warnings.append("duration_ms is negative")
        except (TypeError, ValueError):
            warnings.append("duration_ms is not numeric")
    return {
        "status": "failed" if missing else ("warn" if warnings else "ok"),
        "missing": missing,
        "warnings": warnings,
    }


def write_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
