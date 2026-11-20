from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from server.source_packs.radius.accounting import (
    DATABASE_COMPATIBLE_COLUMNS,
)
from server.source_packs.radius.accounting_runtime_contract import (
    RadiusFixtureLedger,
    RadiusRuntimeContractError,
    initial_cursor,
    load_contract,
    plan_batch,
    validate_contract,
)


NOW = datetime(2026, 7, 30, 8, 0, tzinfo=timezone.utc)


def _line(
    *,
    packet_type: str,
    status: str = "",
    class_attribute: str = "opaque-class",
    dn: str = "example.test/Users/sample.user",
    session: str = "opaque-session",
) -> str:
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
        "Packet-Type": packet_type,
        "Fully-Qualified-Distinguished-Name": dn,
        "Class": class_attribute,
        "NAS-Identifier": "VPN-GW-01",
        "Acct-Status-Type": status,
        "Acct-Session-Id": session,
    }
    for name, value in values.items():
        row[index[name]] = value
    return ",".join(row)


def _cursor():
    return initial_cursor(
        source_instance_id="radius-radius01-1",
        transport_binding="unc-logfiles-in",
        file_generation="in-20260730",
    )


def _resolver(value: str) -> str | None:
    return (
        "sid:S-1-5-21-100000003-200000003-300000003-1101"
        if value == "example.test/Users/sample.user"
        else None
    )


def test_contract_is_fixture_only_and_bounded() -> None:
    result = validate_contract(load_contract())
    assert result["runtime_enabled"] is False
    assert result["cache_ttl_seconds"] == 604_800
    assert result["cache_maximum_entries"] == 10_000


def test_access_accept_class_resolves_following_accounting_session() -> None:
    cursor = _cursor()
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=[
            _line(packet_type="2"),
            _line(packet_type="4", status="1"),
        ],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    assert plan.counters["session_identity_ready"] == 1
    assert plan.session_observations[0].timestamp_ready is True
    assert plan.next_cursor.byte_offset == 200


def test_accounting_control_events_advance_without_session_observations() -> None:
    cursor = _cursor()
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=[
            _line(packet_type="4", status="7", session=""),
            _line(packet_type="4", status="8", session=""),
        ],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )

    assert plan.counters["records"] == 2
    assert plan.counters["accounting_control"] == 2
    assert plan.counters["accounting_lifecycle"] == 0
    assert plan.session_observations == ()
    assert len(plan.evidence_sha256) == 2
    assert plan.next_cursor.byte_offset == 200


def test_unmatched_class_confirms_session_but_not_identity() -> None:
    cursor = _cursor()
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=100,
        lines=[_line(packet_type="4", status="1")],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    observation = plan.session_observations[0]
    assert observation.session_confirmed_by_accounting is True
    assert observation.session_identity_ready is False
    assert observation.session_identity_key is None


@pytest.mark.parametrize("phase", ["evidence", "outbox", "cache"])
def test_failure_never_advances_cursor_or_partial_state(phase: str) -> None:
    cursor = _cursor()
    ledger = RadiusFixtureLedger(cursor=cursor)
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=[
            _line(packet_type="2"),
            _line(packet_type="4", status="1"),
        ],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    with pytest.raises(RuntimeError, match="injected"):
        ledger.commit(plan, fail_after=phase)
    assert ledger.cursor == cursor
    assert ledger.evidence == set()
    assert ledger.session_outbox == set()
    assert ledger.class_cache == {}


def test_successful_commit_is_idempotent_in_outbox() -> None:
    cursor = _cursor()
    ledger = RadiusFixtureLedger(cursor=cursor)
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=200,
        lines=[
            _line(packet_type="2"),
            _line(packet_type="4", status="1"),
        ],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    ledger.commit(plan)
    assert ledger.cursor.byte_offset == 200
    assert len(ledger.session_outbox) == 1
    assert len(ledger.class_cache) == 1


def test_rotation_requires_previous_eof_and_zero_offset() -> None:
    cursor = _cursor()
    with pytest.raises(
        RadiusRuntimeContractError,
        match="rotation_requires_previous_eof",
    ):
        plan_batch(
            cursor=cursor,
            class_cache={},
            file_generation="in-20260731",
            start_offset=0,
            end_offset=0,
            lines=[],
            identity_resolver=_resolver,
            batch_observed_at_utc=NOW,
            source_timezone_id="N. Central Asia Standard Time",
            source_utc_offset_minutes=420,
        )
    plan = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation="in-20260731",
        start_offset=0,
        end_offset=0,
        lines=[],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
        previous_generation_eof=True,
    )
    assert plan.next_cursor.file_generation == "in-20260731"
    assert plan.rotation_from_eof is True


def test_expired_class_binding_is_not_used() -> None:
    cursor = _cursor()
    first = plan_batch(
        cursor=cursor,
        class_cache={},
        file_generation=cursor.file_generation,
        start_offset=0,
        end_offset=100,
        lines=[_line(packet_type="2")],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW - timedelta(days=8),
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    second = plan_batch(
        cursor=first.next_cursor,
        class_cache=first.proposed_class_cache,
        file_generation=cursor.file_generation,
        start_offset=100,
        end_offset=200,
        lines=[_line(packet_type="4", status="1")],
        identity_resolver=_resolver,
        batch_observed_at_utc=NOW,
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    assert second.counters["expired_class_cache_entries"] == 1
    assert second.counters["session_identity_unresolved"] == 1
