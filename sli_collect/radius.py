"""Bounded Accounting collection; the server supplies an opaque saved cursor."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from sli_collect.packets import make_packet
from sli_collect.radius_contract import RadiusFileCursor
from sli_collect.radius_tail import (
    RadiusTailBatch,
    read_bounded_tail,
)


def collect_radius_packet(directory: Path, *, cursor: RadiusFileCursor,
                          source_timezone_id: str, source_utc_offset_minutes: int,
                          observed_at: datetime | None = None,
                          allow_exact_boundary_recovery: bool = True,
                          read_tail: Callable[..., RadiusTailBatch] = read_bounded_tail) -> dict[str, Any]:
    tail = read_tail(directory, cursor=cursor, allow_exact_boundary_recovery=allow_exact_boundary_recovery)
    # This summary is an authenticated producer assertion, not an independent
    # server observation. Never use it to advance through partial source bytes.
    progress = {}
    if tail.empty and (tail.end_offset > tail.start_offset or tail.previous_generation_eof):
        progress["empty_progress_v1"] = {"skipped_bytes": tail.end_offset - tail.start_offset,
                                         "physical_lines": tail.physical_lines}
    return make_packet(
        source=cursor.source_instance_id, channel=cursor.stream_id,
        generation=tail.file_generation,
        cursor={"before": asdict(cursor), "start_offset": tail.start_offset,
                "end_offset": tail.end_offset},
        records=[{"format": "accounting_line", "record_id": None, "payload": line}
                 for line in tail.records],
        continuity={"status": "complete", "previous_generation_eof": tail.previous_generation_eof},
        context={**progress, "source_timezone_id": source_timezone_id,
                 "source_utc_offset_minutes": source_utc_offset_minutes,
                 "candidate_count": tail.candidate_count, "bytes_read": tail.bytes_read,
                 "partial_trailing_bytes": tail.partial_trailing_bytes,
                 "rotation_backlog_generations": tail.rotation_backlog_generations,
                 "cursor_generation_recovered": tail.cursor_generation_recovered},
        observed_at=observed_at,
    )
