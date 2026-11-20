from __future__ import annotations

"""Bounded read-only file-tail adapter for RADIUS Accounting.

The adapter reads at most one exact file generation and returns complete text
records only. It never writes the source, database, cursor or evidence store.
File names and paths are intentionally excluded from the result object.
"""

import fnmatch
import os
import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path

from sli_collect.radius_accounting import (
    RadiusAccountingContractError,
    parse_database_compatible_record,
)
from sli_collect.radius_contract import (
    RadiusFileCursor,
)

MAXIMUM_CANDIDATES = 20
MAXIMUM_READ_BYTES = 4 * 1024 * 1024
MAXIMUM_RECORDS = 1000
MAXIMUM_RECORD_BYTES = 65_536
MAXIMUM_RECOVERY_RECORD_BYTES = 65_537
_REPARSE_POINT = 0x400


class RadiusTailReadError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RadiusTailBatch:
    file_generation: str
    start_offset: int
    end_offset: int
    previous_generation_eof: bool
    records: tuple[str, ...] = field(repr=False)
    candidate_count: int
    bytes_read: int
    partial_trailing_bytes: int
    cursor_generation_recovered: bool = False
    rotation_backlog_generations: int = 0
    physical_lines: int = 0

    @property
    def empty(self) -> bool:
        return not self.records


@dataclass(frozen=True)
class _Candidate:
    path: Path = field(repr=False)
    file_generation: str
    file_creation_time_ns: int
    file_device: int
    file_inode: int
    modified_time_ns: int
    size_bytes: int


def derive_file_generation(
    *,
    source_instance_id: str,
    file_name: str,
    file_creation_time_ns: int,
) -> str:
    material = (
        f"{source_instance_id.casefold()}\0"
        f"{file_name.casefold()}\0{int(file_creation_time_ns)}"
    )
    return "gen-" + sha256(material.encode("utf-8")).hexdigest()[:32]


def read_bounded_tail(
    directory: Path,
    *,
    cursor: RadiusFileCursor,
    maximum_candidates: int = MAXIMUM_CANDIDATES,
    maximum_read_bytes: int = MAXIMUM_READ_BYTES,
    maximum_records: int = MAXIMUM_RECORDS,
    allow_exact_boundary_recovery: bool = False,
    maximum_payload_bytes: int | None = None,
) -> RadiusTailBatch:
    candidate_limit = int(maximum_candidates)
    byte_limit = int(maximum_read_bytes)
    record_limit = int(maximum_records)
    if candidate_limit != MAXIMUM_CANDIDATES:
        raise RadiusTailReadError("tail_candidate_limit_changed")
    if not 1 <= byte_limit <= MAXIMUM_READ_BYTES:
        raise RadiusTailReadError("tail_byte_limit_changed")
    if not 1 <= record_limit <= MAXIMUM_RECORDS:
        raise RadiusTailReadError("tail_record_limit_changed")
    if maximum_payload_bytes is not None and (type(maximum_payload_bytes) is not int
                                             or not 1 <= maximum_payload_bytes <= MAXIMUM_READ_BYTES):
        raise RadiusTailReadError("tail_payload_limit_invalid")
    candidates = tuple(
        _inventory(Path(directory), cursor.source_instance_id)
    )
    if not candidates:
        raise RadiusTailReadError("tail_accounting_file_not_observed")
    if len(candidates) > candidate_limit:
        raise RadiusTailReadError("tail_candidate_limit_exceeded")

    current = next(
        (
            item
            for item in candidates
            if item.file_generation == cursor.file_generation
        ),
        None,
    )
    recovery_bytes = 0
    recovered = False
    if current is None:
        if not allow_exact_boundary_recovery:
            raise RadiusTailReadError("tail_cursor_generation_not_found")
        physical, recovery_bytes = _recover_exact_boundary(
            candidates,
            cursor=cursor,
        )
        current = replace(
            physical,
            file_generation=cursor.file_generation,
        )
        recovered = True
    if current.size_bytes < cursor.byte_offset:
        raise RadiusTailReadError("tail_cursor_past_eof")

    selected = current
    start = cursor.byte_offset
    rotated = False
    if current.size_bytes == cursor.byte_offset:
        current_order = _rotation_order(current)
        newer = sorted(
            (
                item
                for item in candidates
                if item.path != current.path
                and _rotation_order(item) > current_order
            ),
            key=_rotation_order,
        )
        if newer:
            # Consume the earliest still-present generation.  Selecting the
            # newest here silently skipped every intermediate file when more
            # than one rotation happened between bounded invocations.
            selected = newer[0]
            start = 0
            rotated = True
    return _read_candidate(
        selected,
        start_offset=start,
        previous_generation_eof=rotated,
        candidate_count=len(candidates),
        byte_limit=byte_limit - recovery_bytes,
        record_limit=record_limit,
        recovery_bytes=recovery_bytes,
        cursor_generation_recovered=recovered,
        rotation_backlog_generations=(
            max(0, len(newer) - 1) if rotated else 0
        ),
        maximum_payload_bytes=maximum_payload_bytes,
    )


def read_bounded_current_generation_probe(
    directory: Path,
    *,
    source_instance_id: str,
) -> RadiusTailBatch:
    """Read one current generation with an in-memory, zero-offset cursor.

    This is a source-readiness probe only: the cursor is derived from the
    current inventory and never persisted, advanced, or returned to a caller.
    The same fixed limits and bounded tail parser apply as to collection.
    """

    candidates = tuple(_inventory(Path(directory), source_instance_id))
    if not candidates:
        raise RadiusTailReadError("tail_accounting_file_not_observed")
    if len(candidates) > MAXIMUM_CANDIDATES:
        raise RadiusTailReadError("tail_candidate_limit_exceeded")
    current = max(candidates, key=_rotation_order)
    cursor = RadiusFileCursor(
        source_instance_id=source_instance_id,
        stream_id="radius-accounting",
        transport_binding="windows-rpc-smb-readonly-tail-v1",
        file_generation=current.file_generation,
        byte_offset=0,
    )
    return read_bounded_tail(Path(directory), cursor=cursor)


def _rotation_order(candidate: _Candidate) -> tuple[int, str, int, str]:
    """Return a deterministic, payload-free order for NPS file generations."""

    return (
        candidate.modified_time_ns,
        candidate.path.name.casefold(),
        candidate.file_creation_time_ns,
        candidate.file_generation,
    )


def _inventory(
    directory: Path,
    source_instance_id: str,
) -> Iterable[_Candidate]:
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not fnmatch.fnmatch(entry.name.casefold(), "in*.log"):
                    continue
                stat = entry.stat(follow_symlinks=False)
                if bool(
                    int(getattr(stat, "st_file_attributes", 0))
                    & _REPARSE_POINT
                ):
                    raise RadiusTailReadError(
                        "tail_reparse_point_forbidden"
                    )
                with open(entry.path, "rb") as stream:
                    opened = os.fstat(stream.fileno())
                yield _Candidate(
                    path=Path(entry.path),
                    file_generation=derive_file_generation(
                        source_instance_id=source_instance_id,
                        file_name=entry.name,
                        file_creation_time_ns=int(opened.st_ctime_ns),
                    ),
                    file_creation_time_ns=int(opened.st_ctime_ns),
                    file_device=int(opened.st_dev),
                    file_inode=int(opened.st_ino),
                    modified_time_ns=int(opened.st_mtime_ns),
                    size_bytes=int(opened.st_size),
                )
    except OSError as exc:
        raise RadiusTailReadError("tail_inventory_failed") from exc


def _read_candidate(
    candidate: _Candidate,
    *,
    start_offset: int,
    previous_generation_eof: bool,
    candidate_count: int,
    byte_limit: int,
    record_limit: int,
    recovery_bytes: int = 0,
    cursor_generation_recovered: bool = False,
    rotation_backlog_generations: int = 0,
    maximum_payload_bytes: int | None = None,
) -> RadiusTailBatch:
    if byte_limit < 1:
        raise RadiusTailReadError("tail_recovery_exhausted_byte_budget")
    requested = min(
        byte_limit,
        max(0, candidate.size_bytes - start_offset),
    )
    try:
        with candidate.path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                int(opened.st_dev) != candidate.file_device
                or int(opened.st_ino) != candidate.file_inode
            ):
                raise RadiusTailReadError("tail_file_replaced_during_open")
            if int(opened.st_size) < candidate.size_bytes:
                raise RadiusTailReadError("tail_file_truncated_during_open")
            if int(opened.st_size) < start_offset:
                raise RadiusTailReadError("tail_cursor_past_eof")
            stream.seek(start_offset)
            payload = stream.read(requested)
    except RadiusTailReadError:
        raise
    except OSError as exc:
        raise RadiusTailReadError("tail_file_read_failed") from exc

    newline_positions = [
        position for position, value in enumerate(payload) if value == 0x0A
    ]
    if not newline_positions:
        if len(payload) > MAXIMUM_RECORD_BYTES:
            raise RadiusTailReadError("tail_record_too_large")
        return RadiusTailBatch(
            file_generation=candidate.file_generation,
            start_offset=start_offset,
            end_offset=start_offset,
            previous_generation_eof=previous_generation_eof,
            records=(),
            candidate_count=candidate_count,
            bytes_read=recovery_bytes + len(payload),
            partial_trailing_bytes=len(payload),
            cursor_generation_recovered=cursor_generation_recovered,
            rotation_backlog_generations=rotation_backlog_generations,
        )
    boundary = newline_positions[min(record_limit, len(newline_positions)) - 1]
    complete = payload[: boundary + 1]
    records: list[str] = []
    consumed = 0
    wire_bytes = 0
    budget_stopped = False
    for physical in complete.splitlines(keepends=True):
        raw = physical.rstrip(b"\r\n")
        if not raw.strip():
            consumed += len(physical)
            continue
        if len(raw) > MAXIMUM_RECORD_BYTES:
            raise RadiusTailReadError("tail_record_too_large")
        try:
            text = raw.decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise RadiusTailReadError(
                "tail_record_encoding_invalid"
            ) from exc
        # Agent envelopes use ASCII JSON. Budget that representation, including
        # the record wrapper, while retaining the exact source byte boundary.
        record_bytes = len(json.dumps(text, ensure_ascii=True).encode("ascii")) + 100
        if maximum_payload_bytes is not None and wire_bytes + record_bytes > maximum_payload_bytes:
            if not records:
                raise RadiusTailReadError("tail_record_payload_limit_exceeded")
            boundary = consumed - 1
            budget_stopped = True
            break
        records.append(text)
        wire_bytes += record_bytes
        consumed += len(physical)
    if len(records) > record_limit:
        raise RadiusTailReadError("tail_record_limit_exceeded")
    trailing_bytes = len(payload) - boundary - 1
    if (
        len(newline_positions) < record_limit
        and trailing_bytes > MAXIMUM_RECORD_BYTES
        and not budget_stopped
    ):
        raise RadiusTailReadError("tail_record_too_large")
    return RadiusTailBatch(
        file_generation=candidate.file_generation,
        start_offset=start_offset,
        end_offset=start_offset + boundary + 1,
        previous_generation_eof=previous_generation_eof,
        records=tuple(records),
        physical_lines=payload[:boundary + 1].count(b"\n"),
        candidate_count=candidate_count,
        bytes_read=recovery_bytes + len(payload),
        partial_trailing_bytes=trailing_bytes,
        cursor_generation_recovered=cursor_generation_recovered,
        rotation_backlog_generations=rotation_backlog_generations,
    )


def _recover_exact_boundary(
    candidates: tuple[_Candidate, ...],
    *,
    cursor: RadiusFileCursor,
) -> tuple[_Candidate, int]:
    expected = str(cursor.last_record_sha256 or "").casefold()
    if len(expected) != 64:
        raise RadiusTailReadError("tail_recovery_last_hash_required")
    matches: list[_Candidate] = []
    bytes_read = 0
    for candidate in candidates:
        if candidate.size_bytes < cursor.byte_offset:
            continue
        length = min(
            cursor.byte_offset,
            MAXIMUM_RECOVERY_RECORD_BYTES,
        )
        start = cursor.byte_offset - length
        try:
            with candidate.path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if (
                    int(opened.st_dev) != candidate.file_device
                    or int(opened.st_ino) != candidate.file_inode
                ):
                    raise RadiusTailReadError(
                        "tail_file_replaced_during_recovery"
                    )
                if int(opened.st_size) < cursor.byte_offset:
                    continue
                stream.seek(start)
                payload = stream.read(length)
        except RadiusTailReadError:
            raise
        except OSError as exc:
            raise RadiusTailReadError(
                "tail_recovery_read_failed"
            ) from exc
        bytes_read += len(payload)
        if not payload.endswith(b"\n"):
            continue
        segments = [item for item in payload.splitlines() if item.strip()]
        if not segments:
            continue
        try:
            line = segments[-1].decode("utf-8-sig", errors="strict")
            digest = parse_database_compatible_record(
                line
            ).canonical_record_sha256
        except (UnicodeDecodeError, RadiusAccountingContractError):
            continue
        if digest == expected:
            matches.append(candidate)
    if not matches:
        raise RadiusTailReadError("tail_recovery_boundary_not_found")
    if len(matches) != 1:
        raise RadiusTailReadError("tail_recovery_boundary_ambiguous")
    if bytes_read >= MAXIMUM_READ_BYTES:
        raise RadiusTailReadError("tail_recovery_exhausted_byte_budget")
    return matches[0], bytes_read
