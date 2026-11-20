"""Shared guard that prevents importing fail-closed collection batches."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def blocked_batch_marker(input_dir: Path) -> dict[str, Any] | None:
    marker = Path(input_dir) / "collection-blocked.json"
    if not marker.is_file():
        return None
    try:
        payload = json.loads(marker.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "status": "blocked",
            "failure_code": "collection_block_marker_unreadable",
            "error_type": type(exc).__name__,
            "marker": str(marker),
        }
    return {
        "status": "blocked",
        "failure_code": str(payload.get("failure_code") or "collection_batch_quarantined"),
        "pipeline_disposition": str(payload.get("pipeline_disposition") or "blocked_pre_import"),
        "marker": str(marker),
    }
