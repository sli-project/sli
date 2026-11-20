"""Stable, explicitly bounded readers for storage-lifecycle trust boundaries."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def read_bytes(path: Path, *, max_bytes: int, too_large: str) -> bytes:
    try:
        before = path.stat()
    except OSError as exc:
        raise RuntimeError("bounded_file_stat_failed") from exc
    if int(before.st_size) > max_bytes:
        raise RuntimeError(too_large)
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            identity = _file_identity(before)
            if _file_identity(opened) != identity:
                raise RuntimeError("bounded_file_changed_during_open")
            payload = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
            if _file_identity(after) != identity:
                raise RuntimeError("bounded_file_changed_during_read")
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError("bounded_file_read_failed") from exc
    if len(payload) > max_bytes:
        raise RuntimeError(too_large)
    return payload


def read_json(path: Path, *, max_bytes: int, too_large: str) -> Any:
    try:
        return json.loads(read_bytes(path, max_bytes=max_bytes, too_large=too_large))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("bounded_json_invalid") from exc


def iter_json_lines(
    path: Path, *, max_bytes: int, max_line_bytes: int, max_rows: int, too_large: str,
) -> Iterator[Any]:
    try:
        before = path.stat()
    except OSError as exc:
        raise RuntimeError("bounded_file_stat_failed") from exc
    if int(before.st_size) > max_bytes:
        raise RuntimeError(too_large)
    identity = _file_identity(before)
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if _file_identity(opened) != identity:
                raise RuntimeError("bounded_file_changed_during_open")
            rows = 0
            while True:
                line = handle.readline(max_line_bytes + 1)
                if not line:
                    break
                if len(line) > max_line_bytes:
                    raise RuntimeError("bounded_jsonl_line_too_large")
                if not line.strip():
                    continue
                rows += 1
                if rows > max_rows:
                    raise RuntimeError("bounded_jsonl_row_count_out_of_bounds")
                try:
                    yield json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise RuntimeError("bounded_jsonl_invalid") from exc
            after = os.fstat(handle.fileno())
            if _file_identity(after) != identity:
                raise RuntimeError("bounded_file_changed_during_read")
    except RuntimeError:
        raise
    except OSError as exc:
        raise RuntimeError("bounded_file_read_failed") from exc
