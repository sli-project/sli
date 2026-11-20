from __future__ import annotations

from datetime import datetime, timezone

import pytest

from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
    parse_database_compatible_record,
)
from server.source_packs.radius.accounting_bootstrap import (
    RadiusCursorBootstrapError,
    derive_cursor_anchor,
)


def _line(*, status: str = "1") -> str:
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
        "Acct-Status-Type": status,
        "Acct-Session-Id": "opaque-session",
        "NAS-Identifier": "VPN-GW-01",
    }
    for name, value in values.items():
        row[index[name]] = value
    return ",".join(row)








def test_anchor_stops_after_last_complete_record_and_hashes_canonical_text() -> None:
    first = _line(status="1")
    second = _line(status="2")
    partial = _line(status="3")[:40]
    data = (first + "\r\n" + second + "\r\n" + partial).encode()
    anchor = derive_cursor_anchor(
        source_instance_id="radius.radius01.example.invalid",
        file_name="IN260730.log",
        file_creation_time_ns=1_722_331_200_000_000_000,
        tail_bytes=data,
        tail_start_offset=0,
        observed_file_size=len(data),
    )
    expected_offset = len((first + "\r\n" + second + "\r\n").encode())
    assert anchor.byte_offset == expected_offset
    assert anchor.boundary_lag_bytes == len(partial.encode())
    assert anchor.last_record_sha256 == (
        parse_database_compatible_record(second).canonical_record_sha256
    )
    assert anchor.file_generation.startswith("gen-")


def test_generation_is_stable_for_same_file_and_changes_for_new_creation() -> None:
    line = (_line() + "\r\n").encode()
    common = {
        "source_instance_id": "radius.radius01.example.invalid",
        "file_name": "IN260730.log",
        "tail_bytes": line,
        "tail_start_offset": 0,
        "observed_file_size": len(line),
    }
    first = derive_cursor_anchor(
        **common,
        file_creation_time_ns=100,
    )
    repeated = derive_cursor_anchor(
        **common,
        file_creation_time_ns=100,
    )
    replacement = derive_cursor_anchor(
        **common,
        file_creation_time_ns=101,
    )
    assert first.file_generation == repeated.file_generation
    assert first.file_generation != replacement.file_generation


def test_truncated_tail_discards_first_partial_segment() -> None:
    first = _line(status="1")
    second = _line(status="2")
    data = ("partial-prefix\n" + first + "\n" + second + "\n").encode()
    anchor = derive_cursor_anchor(
        source_instance_id="radius.radius01.example.invalid",
        file_name="IN260730.log",
        file_creation_time_ns=100,
        tail_bytes=data,
        tail_start_offset=500,
        observed_file_size=500 + len(data),
    )
    assert anchor.byte_offset == 500 + len(data)
    assert anchor.last_record_sha256 == (
        parse_database_compatible_record(second).canonical_record_sha256
    )


def test_no_complete_record_fails_closed() -> None:
    with pytest.raises(
        RadiusCursorBootstrapError,
        match="bootstrap_complete_record_required",
    ):
        derive_cursor_anchor(
            source_instance_id="radius.radius01.example.invalid",
            file_name="IN260730.log",
            file_creation_time_ns=int(
                datetime.now(timezone.utc).timestamp() * 1_000_000_000
            ),
            tail_bytes=b"partial",
            tail_start_offset=0,
            observed_file_size=7,
        )
