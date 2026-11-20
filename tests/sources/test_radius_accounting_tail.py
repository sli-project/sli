from __future__ import annotations

import os
from pathlib import Path

import pytest

from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
    parse_database_compatible_record,
)
from server.source_packs.radius.accounting_runtime_contract import (
    RadiusFileCursor,
)
from server.source_packs.radius.accounting_tail import (
    MAXIMUM_RECORD_BYTES,
    MAXIMUM_READ_BYTES,
    RadiusTailReadError,
    derive_file_generation,
    read_bounded_current_generation_probe,
    read_bounded_tail,
)


SOURCE_ID = "radius.radius01.example.invalid"


def _radius_line(session: str) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    index = {
        name: position
        for position, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
    }
    values = {
        "ComputerName": "NPS01",
        "ServiceName": "IAS",
        "Record-Date": "07/30/2026",
        "Record-Time": "15:00:00",
        "Packet-Type": "4",
        "NAS-Identifier": "VPN-GW-01",
        "Acct-Status-Type": "1",
        "Acct-Session-Id": session,
    }
    for name, value in values.items():
        row[index[name]] = value
    return ",".join(row)


def _generation(path: Path) -> str:
    with path.open("rb") as stream:
        stat = os.fstat(stream.fileno())
    return derive_file_generation(
        source_instance_id=SOURCE_ID,
        file_name=path.name,
        file_creation_time_ns=stat.st_ctime_ns,
    )


def _cursor(path: Path, offset: int) -> RadiusFileCursor:
    return RadiusFileCursor(
        source_instance_id=SOURCE_ID,
        stream_id="radius-accounting",
        transport_binding="windows-rpc-smb-readonly-tail-v1",
        file_generation=_generation(path),
        byte_offset=offset,
    )


def test_tail_reads_only_complete_records_and_preserves_partial(
    tmp_path: Path,
) -> None:
    path = tmp_path / "IN2607.log"
    path.write_bytes(b"first\nsecond\npartial")
    batch = read_bounded_tail(tmp_path, cursor=_cursor(path, 0))
    assert batch.records == ("first", "second")
    assert batch.start_offset == 0
    assert batch.end_offset == len(b"first\nsecond\n")
    assert batch.partial_trailing_bytes == len(b"partial")
    assert batch.previous_generation_eof is False


def test_agent_payload_budget_keeps_exact_physical_offset(tmp_path: Path) -> None:
    path = tmp_path / "IN-fixture.log"
    first = b"\xef\xbb\xbf" + "fixture-\u044f".encode("utf-8") + b"\r\n"
    path.write_bytes(first + b"next\r\npartial")
    batch = read_bounded_tail(tmp_path, cursor=_cursor(path, 0), maximum_payload_bytes=120)
    assert batch.records == ("fixture-\u044f",)
    assert batch.end_offset == len(first)
    next_batch = read_bounded_tail(tmp_path, cursor=_cursor(path, batch.end_offset), maximum_records=1)
    assert next_batch.records == ("next",)


def test_agent_oversize_line_is_not_skipped(tmp_path: Path) -> None:
    path = tmp_path / "IN-fixture.log"
    path.write_bytes(b"fixture\n")
    with pytest.raises(RadiusTailReadError, match="tail_record_payload_limit_exceeded"):
        read_bounded_tail(tmp_path, cursor=_cursor(path, 0), maximum_payload_bytes=100)


def test_tail_continues_from_exact_cursor_offset(tmp_path: Path) -> None:
    path = tmp_path / "IN2607.log"
    prefix = b"already\n"
    path.write_bytes(prefix + b"new\n")
    batch = read_bounded_tail(
        tmp_path,
        cursor=_cursor(path, len(prefix)),
    )
    assert batch.records == ("new",)
    assert batch.start_offset == len(prefix)
    assert batch.end_offset == len(prefix + b"new\n")


def test_tail_rotates_only_after_current_generation_eof(
    tmp_path: Path,
) -> None:
    current = tmp_path / "IN2607.log"
    current.write_bytes(b"old\n")
    cursor = _cursor(current, len(b"old\n"))
    newer = tmp_path / "IN2608.log"
    newer.write_bytes(b"new\n")
    newer_time = current.stat().st_mtime_ns + 10_000_000
    os.utime(newer, ns=(newer_time, newer_time))

    batch = read_bounded_tail(tmp_path, cursor=cursor)
    assert batch.file_generation == _generation(newer)
    assert batch.records == ("new",)
    assert batch.start_offset == 0
    assert batch.previous_generation_eof is True
    assert batch.rotation_backlog_generations == 0


def test_tail_consumes_multiple_rotations_in_oldest_first_order(
    tmp_path: Path,
) -> None:
    current = tmp_path / "IN2607.log"
    current.write_bytes(b"old\n")
    cursor = _cursor(current, len(b"old\n"))
    middle = tmp_path / "IN2608.log"
    middle.write_bytes(b"middle\n")
    newest = tmp_path / "IN2609.log"
    newest.write_bytes(b"newest\n")
    shared_time = current.stat().st_mtime_ns + 10_000_000
    os.utime(middle, ns=(shared_time, shared_time))
    os.utime(newest, ns=(shared_time, shared_time))

    first = read_bounded_tail(tmp_path, cursor=cursor)
    assert first.file_generation == _generation(middle)
    assert first.records == ("middle",)
    assert first.rotation_backlog_generations == 1

    second = read_bounded_tail(
        tmp_path,
        cursor=_cursor(middle, len(b"middle\n")),
    )
    assert second.file_generation == _generation(newest)
    assert second.records == ("newest",)
    assert second.rotation_backlog_generations == 0


def test_tail_fails_closed_on_oversized_unterminated_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "IN2607.log"
    path.write_bytes(b"x" * (MAXIMUM_RECORD_BYTES + 1))
    with pytest.raises(
        RadiusTailReadError,
        match="tail_record_too_large",
    ):
        read_bounded_tail(tmp_path, cursor=_cursor(path, 0))


def test_tail_fails_closed_when_oversized_record_follows_valid_record(
    tmp_path: Path,
) -> None:
    path = tmp_path / "IN2607.log"
    path.write_bytes(b"valid\n" + b"x" * (MAXIMUM_RECORD_BYTES + 1))
    with pytest.raises(
        RadiusTailReadError,
        match="tail_record_too_large",
    ):
        read_bounded_tail(tmp_path, cursor=_cursor(path, 0))


def test_tail_refuses_missing_generation_and_cursor_past_eof(
    tmp_path: Path,
) -> None:
    path = tmp_path / "IN2607.log"
    path.write_bytes(b"one\n")
    missing = RadiusFileCursor(
        source_instance_id=SOURCE_ID,
        stream_id="radius-accounting",
        transport_binding="windows-rpc-smb-readonly-tail-v1",
        file_generation="gen-" + "0" * 32,
        byte_offset=0,
    )
    with pytest.raises(
        RadiusTailReadError,
        match="tail_cursor_generation_not_found",
    ):
        read_bounded_tail(tmp_path, cursor=missing)
    with pytest.raises(RadiusTailReadError, match="tail_cursor_past_eof"):
        read_bounded_tail(tmp_path, cursor=_cursor(path, 999))


def test_tail_limits_are_fixed_and_result_hides_path(tmp_path: Path) -> None:
    path = tmp_path / "IN2607.log"
    path.write_bytes(b"one\n")
    with pytest.raises(
        RadiusTailReadError,
        match="tail_byte_limit_changed",
    ):
        read_bounded_tail(
            tmp_path,
            cursor=_cursor(path, 0),
            maximum_read_bytes=MAXIMUM_READ_BYTES + 1,
        )
    batch = read_bounded_tail(tmp_path, cursor=_cursor(path, 0))
    rendered = repr(batch)
    assert str(path) not in rendered
    assert path.name not in rendered


def test_ephemeral_probe_reads_current_generation_without_persisted_cursor(
    tmp_path: Path,
) -> None:
    older = tmp_path / "IN2607.log"
    older.write_bytes(b"older\n")
    current = tmp_path / "IN2608.log"
    current.write_bytes(b"current\n")
    os.utime(current, ns=(older.stat().st_mtime_ns + 10_000_000,) * 2)

    batch = read_bounded_current_generation_probe(
        tmp_path,
        source_instance_id=SOURCE_ID,
    )

    assert batch.records == ("current",)
    assert batch.start_offset == 0
    assert batch.previous_generation_eof is False


def test_tail_recovers_exact_boundary_after_file_rename(
    tmp_path: Path,
) -> None:
    first = _radius_line("session-1")
    second = _radius_line("session-2")
    original = tmp_path / "IN2607.log"
    original.write_bytes((first + "\n").encode("utf-8"))
    cursor = _cursor(
        original,
        len((first + "\n").encode("utf-8")),
    )
    cursor = RadiusFileCursor(
        **{
            **cursor.__dict__,
            "last_record_sha256": parse_database_compatible_record(
                first
            ).canonical_record_sha256,
        }
    )
    renamed = tmp_path / "IN2608.log"
    original.rename(renamed)
    with renamed.open("ab") as stream:
        stream.write((second + "\n").encode("utf-8"))

    with pytest.raises(
        RadiusTailReadError,
        match="tail_cursor_generation_not_found",
    ):
        read_bounded_tail(tmp_path, cursor=cursor)
    batch = read_bounded_tail(
        tmp_path,
        cursor=cursor,
        allow_exact_boundary_recovery=True,
    )
    assert batch.records == (second,)
    assert batch.file_generation == cursor.file_generation
    assert batch.cursor_generation_recovered is True


def test_tail_refuses_ambiguous_boundary_recovery(tmp_path: Path) -> None:
    first = _radius_line("session-1")
    payload = (first + "\n").encode("utf-8")
    old = tmp_path / "IN2606.log"
    old.write_bytes(payload)
    cursor = _cursor(old, len(payload))
    cursor = RadiusFileCursor(
        **{
            **cursor.__dict__,
            "last_record_sha256": parse_database_compatible_record(
                first
            ).canonical_record_sha256,
        }
    )
    old.unlink()
    (tmp_path / "IN2607.log").write_bytes(payload)
    (tmp_path / "IN2608.log").write_bytes(payload)
    with pytest.raises(
        RadiusTailReadError,
        match="tail_recovery_boundary_ambiguous",
    ):
        read_bounded_tail(
            tmp_path,
            cursor=cursor,
            allow_exact_boundary_recovery=True,
        )
