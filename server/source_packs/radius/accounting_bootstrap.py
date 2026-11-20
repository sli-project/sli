"""Pure cursor-anchor derivation for the Stage 9 RADIUS Accounting pilot."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath
import re

from server.source_packs.radius.accounting import (
    RadiusAccountingContractError,
    parse_database_compatible_record,
)


_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class RadiusCursorBootstrapError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusCursorAnchor:
    file_generation: str
    byte_offset: int
    last_record_sha256: str
    boundary_lag_bytes: int


def derive_cursor_anchor(
    *,
    source_instance_id: str,
    file_name: str,
    file_creation_time_ns: int,
    tail_bytes: bytes,
    tail_start_offset: int,
    observed_file_size: int,
) -> RadiusCursorAnchor:
    """Anchor the cursor after the last complete, valid record.

    ``tail_bytes`` is an already-read bounded suffix.  The function performs no
    I/O and returns only opaque generation/hash material plus byte offsets.
    """

    source = str(source_instance_id or "").strip()
    if _TOKEN.fullmatch(source) is None:
        raise RadiusCursorBootstrapError("bootstrap_source_instance_invalid")
    name = str(file_name or "")
    if (
        not name
        or PurePath(name).name != name
        or "/" in name
        or "\\" in name
    ):
        raise RadiusCursorBootstrapError("bootstrap_file_basename_invalid")
    creation_ns = int(file_creation_time_ns)
    start = int(tail_start_offset)
    size = int(observed_file_size)
    if creation_ns <= 0:
        raise RadiusCursorBootstrapError("bootstrap_creation_time_invalid")
    if start < 0 or size < start or len(tail_bytes) != size - start:
        raise RadiusCursorBootstrapError("bootstrap_tail_range_invalid")
    if not tail_bytes:
        raise RadiusCursorBootstrapError("bootstrap_complete_record_required")

    newline_positions = [
        index
        for index, value in enumerate(tail_bytes)
        if value == 0x0A
    ]
    if not newline_positions:
        raise RadiusCursorBootstrapError("bootstrap_complete_record_required")
    boundary_index = newline_positions[-1]
    complete_region = tail_bytes[: boundary_index + 1]
    segments = complete_region.splitlines()
    if start > 0:
        if len(segments) < 2:
            raise RadiusCursorBootstrapError("bootstrap_bounded_tail_too_small")
        segments = segments[1:]
    non_empty = [segment for segment in segments if segment.strip()]
    if not non_empty:
        raise RadiusCursorBootstrapError("bootstrap_complete_record_required")
    try:
        line = non_empty[-1].decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise RadiusCursorBootstrapError(
            "bootstrap_record_encoding_invalid"
        ) from exc
    try:
        record = parse_database_compatible_record(line)
    except RadiusAccountingContractError as exc:
        raise RadiusCursorBootstrapError(
            "bootstrap_last_record_invalid"
        ) from exc

    generation_material = (
        f"{source.casefold()}\0{name.casefold()}\0{creation_ns}"
    )
    generation = (
        "gen-"
        + sha256(generation_material.encode("utf-8")).hexdigest()[:32]
    )
    offset = start + boundary_index + 1
    return RadiusCursorAnchor(
        file_generation=generation,
        byte_offset=offset,
        last_record_sha256=record.canonical_record_sha256,
        boundary_lag_bytes=size - offset,
    )
