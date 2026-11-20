from __future__ import annotations

import pytest

from server.source_packs.radius.accounting import (
    ADAPTER_CONTRACT_ID,
    DATABASE_COMPATIBLE_COLUMNS,
    RadiusAccountingContractError,
    build_class_identity_binding,
    build_session_observation,
    parse_database_compatible_record,
)


def _line(
    *,
    service_name: str = "IAS",
    packet_type: str = "4",
    status: str = "1",
    session_id: str = "opaque-session-001",
    nas_identifier: str = "VPN-GW-01",
    user_name: str = "EXAMPLE\\sample.user",
    distinguished_name: str = "example.test/Users/sample.user",
    class_attribute: str = "opaque-class-001",
) -> str:
    row = [""] * len(DATABASE_COMPATIBLE_COLUMNS)
    values = {
        "ComputerName": "NPS01",
        "ServiceName": service_name,
        "Record-Date": "07/30/2026",
        "Record-Time": "09:30:00",
        "Packet-Type": packet_type,
        "User-Name": user_name,
        "Fully-Qualified-Distinguished-Name": distinguished_name,
        "NAS-Identifier": nas_identifier,
        "NAS-IP-Address": "192.0.2.1",
        "Acct-Status-Type": status,
        "Acct-Session-Id": session_id,
        "Class": class_attribute,
    }
    positions = {
        name: index for index, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
    }
    for name, value in values.items():
        row[positions[name]] = value
    return ",".join(row)


def test_parser_accepts_only_exact_evidence_34_shape() -> None:
    record = parse_database_compatible_record(_line())
    assert record.adapter_contract_id == ADAPTER_CONTRACT_ID
    assert record.packet_type == 4
    assert record.accounting_status == "start"
    assert record.is_accounting_request is True
    assert record.nas_identity == "VPN-GW-01"
    assert len(record.canonical_record_sha256) == 64
    assert "opaque-session-001" not in repr(record)
    assert "sample.user" not in repr(record)
    assert "opaque-class-001" not in repr(record)


def test_parser_accepts_database_compatible_ras_service_records() -> None:
    record = parse_database_compatible_record(_line(service_name="RAS"))

    assert record.packet_type == 4
    assert record.accounting_status == "start"


@pytest.mark.parametrize(
    ("status", "expected"),
    [("1", "start"), ("2", "stop"), ("3", "interim_update")],
)
def test_accounting_lifecycle_values_are_closed_and_explicit(
    status: str,
    expected: str,
) -> None:
    record = parse_database_compatible_record(_line(status=status))
    observation = build_session_observation(
        record,
        source_instance_id="radius-radius01-1",
    )
    assert observation is not None
    assert observation.lifecycle_event == expected
    assert observation.session_confirmed_by_accounting is True
    assert observation.session_identity_ready is False
    assert observation.session_identity_key is None
    assert observation.timestamp_ready is False
    assert observation.observed_at_utc is None


@pytest.mark.parametrize(
    ("status", "expected"),
    [("7", "accounting_on"), ("8", "accounting_off")],
)
def test_accounting_control_values_are_explicit_non_session_events(
    status: str,
    expected: str,
) -> None:
    record = parse_database_compatible_record(
        _line(status=status, session_id=""),
    )

    assert record.accounting_status == expected
    assert record.is_accounting_control_event is True
    assert build_session_observation(
        record,
        source_instance_id="radius-radius01-1",
    ) is None


def test_access_packets_do_not_create_accounting_lifecycle() -> None:
    for packet_type in ("1", "2", "3"):
        record = parse_database_compatible_record(
            _line(packet_type=packet_type, status=""),
        )
        assert build_session_observation(
            record,
            source_instance_id="radius-radius01-1",
        ) is None


def test_exact_principal_is_required_before_session_identity_exists() -> None:
    record = parse_database_compatible_record(_line())
    unresolved = build_session_observation(
        record,
        source_instance_id="radius-radius01-1",
    )
    resolved = build_session_observation(
        record,
        source_instance_id="radius-radius01-1",
        exact_principal_key="sid:S-1-5-21-100000003-200000003-300000003-1101",
    )
    assert unresolved is not None and resolved is not None
    assert unresolved.session_identity_key is None
    assert resolved.session_identity_key.startswith("radius-session:")
    assert resolved.session_identity_ready is True


def test_access_accept_class_binding_requires_external_identity_resolution() -> None:
    accept = parse_database_compatible_record(
        _line(packet_type="2", status=""),
    )
    unresolved = build_class_identity_binding(
        accept,
        source_instance_id="radius-radius01-1",
    )
    resolved = build_class_identity_binding(
        accept,
        source_instance_id="radius-radius01-1",
        exact_principal_key="sid:S-1-5-21-100000003-200000003-300000003-1101",
    )
    assert unresolved is not None and resolved is not None
    assert unresolved.identity_lookup_ready is True
    assert unresolved.exact_identity_ready is False
    assert resolved.exact_identity_ready is True
    assert "opaque-class-001" not in repr(resolved)
    assert "sample.user" not in repr(resolved)


def test_accounting_class_uses_resolved_access_accept_identity() -> None:
    accept = parse_database_compatible_record(
        _line(packet_type="2", status=""),
    )
    binding = build_class_identity_binding(
        accept,
        source_instance_id="radius-radius01-1",
        exact_principal_key="sid:S-1-5-21-100000003-200000003-300000003-1101",
    )
    assert binding is not None
    accounting = parse_database_compatible_record(_line())
    observation = build_session_observation(
        accounting,
        source_instance_id="radius-radius01-1",
        class_identity_binding=binding,
    )
    assert observation is not None
    assert observation.session_identity_ready is True
    assert observation.exact_principal_key == (
        "sid:S-1-5-21-100000003-200000003-300000003-1101"
    )


def test_class_binding_mismatch_fails_closed() -> None:
    accept = parse_database_compatible_record(
        _line(
            packet_type="2",
            status="",
            class_attribute="class-a",
        ),
    )
    binding = build_class_identity_binding(
        accept,
        source_instance_id="radius-radius01-1",
    )
    assert binding is not None
    accounting = parse_database_compatible_record(
        _line(class_attribute="class-b"),
    )
    with pytest.raises(RadiusAccountingContractError) as caught:
        build_session_observation(
            accounting,
            source_instance_id="radius-radius01-1",
            class_identity_binding=binding,
        )
    assert caught.value.code == "class_binding_mismatch"


def test_explicit_source_timezone_makes_record_timestamp_ready() -> None:
    observation = build_session_observation(
        parse_database_compatible_record(_line()),
        source_instance_id="radius-radius01-1",
        source_timezone_id="N. Central Asia Standard Time",
        source_utc_offset_minutes=420,
    )
    assert observation is not None
    assert observation.timestamp_ready is True
    assert observation.observed_at_utc == "2026-07-30T02:30:00+00:00"
    assert observation.timestamp_basis == (
        "record_date_time_plus_observed_source_timezone"
    )


def test_session_identity_uses_session_nas_principal_and_source_scope() -> None:
    record = parse_database_compatible_record(_line())

    def key(
        *,
        source: str = "radius-radius01-1",
        principal: str = "sid:S-1-5-21-100000003-200000003-300000003-1101",
        line: str | None = None,
    ) -> str:
        item = parse_database_compatible_record(line) if line else record
        observation = build_session_observation(
            item,
            source_instance_id=source,
            exact_principal_key=principal,
        )
        assert observation is not None
        assert observation.session_identity_key is not None
        return observation.session_identity_key

    baseline = key()
    assert key() == baseline
    assert key(source="radius-radius01-2") != baseline
    assert key(principal="sid:S-1-5-21-100000003-200000003-300000003-1102") != baseline
    assert key(line=_line(session_id="opaque-session-002")) != baseline
    assert key(line=_line(nas_identifier="VPN-GW-02")) != baseline


@pytest.mark.parametrize(
    ("line", "code"),
    [
        ("", "record_required"),
        ("a,b,c", "database_compatible_shape_required"),
        (_line(status=""), "accounting_status_unsupported_or_missing"),
        (_line(status="9"), "accounting_status_unsupported_or_missing"),
    ],
)
def test_parser_fails_closed_on_unknown_shapes_and_lifecycle(
    line: str,
    code: str,
) -> None:
    with pytest.raises(RadiusAccountingContractError) as caught:
        parse_database_compatible_record(line)
    assert caught.value.code == code


@pytest.mark.parametrize(
    ("line", "code"),
    [
        (_line(session_id=""), "account_session_id_required"),
        (
            _line(nas_identifier="").replace("192.0.2.1", ""),
            "nas_identity_required",
        ),
    ],
)
def test_observation_fails_closed_without_session_scope(
    line: str,
    code: str,
) -> None:
    record = parse_database_compatible_record(line)
    with pytest.raises(RadiusAccountingContractError) as caught:
        build_session_observation(
            record,
            source_instance_id="radius-radius01-1",
        )
    assert caught.value.code == code
