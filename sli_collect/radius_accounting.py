from __future__ import annotations

"""Pure RADIUS Accounting record contract for the Stage 9 source-only pilot.

This module parses one already supplied Microsoft NPS database-compatible CSV
record.  It does not open files, contact NPS, maintain a cursor, write a
database, start a worker, or infer a timestamp timezone.  Runtime acquisition
remains a later gated component.
"""

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256

ADAPTER_CONTRACT_ID = "radius-accounting-database-compatible-v1"
EXPECTED_FIELD_COUNT = 66
MAX_RECORD_CHARACTERS = 65_536
ACCOUNTING_REQUEST_PACKET_TYPE = 4
ACCESS_ACCEPT_PACKET_TYPE = 2

DATABASE_COMPATIBLE_COLUMNS = (
    "ComputerName",
    "ServiceName",
    "Record-Date",
    "Record-Time",
    "Packet-Type",
    "User-Name",
    "Fully-Qualified-Distinguished-Name",
    "Called-Station-Id",
    "Calling-Station-Id",
    "Callback-Number",
    "Framed-IP-Address",
    "NAS-Identifier",
    "NAS-IP-Address",
    "NAS-Port",
    "Client-Vendor",
    "Client-IP-Address",
    "Client-Friendly-Name",
    "Event-Timestamp",
    "Port-Limit",
    "NAS-Port-Type",
    "Connect-Info",
    "Framed-Protocol",
    "Service-Type",
    "Authentication-Type",
    "NP-Policy-Name",
    "Reason-Code",
    "Class",
    "Session-Timeout",
    "Idle-Timeout",
    "Termination-Action",
    "EAP-Friendly-Name",
    "Acct-Status-Type",
    "Acct-Delay-Time",
    "Acct-Input-Octets",
    "Acct-Output-Octets",
    "Acct-Session-Id",
    "Acct-Authentic",
    "Acct-Session-Time",
    "Acct-Input-Packets",
    "Acct-Output-Packets",
    "Acct-Terminate-Cause",
    "Acct-Multi-Session-Id",
    "Acct-Link-Count",
    "Acct-Interim-Interval",
    "Tunnel-Type",
    "Tunnel-Medium-Type",
    "Tunnel-Client-Endpt",
    "Tunnel-Server-Endpt",
    "Acct-Tunnel-Conn",
    "Tunnel-Pvt-Group-ID",
    "Tunnel-Assignment-ID",
    "Tunnel-Preference",
    "MS-Acct-Auth-Type",
    "MS-Acct-EAP-Type",
    "MS-RAS-Version",
    "MS-RAS-Vendor",
    "MS-CHAP-Error",
    "MS-CHAP-Domain",
    "MS-MPPE-Encryption-Types",
    "MS-MPPE-Encryption-Policy",
    "Proxy-Policy-Name",
    "Provider-Type",
    "Provider-Name",
    "Remote-Server-Address",
    "MS-RAS-Client-Name",
    "MS-RAS-Client-Version",
)

_COLUMN_INDEX = {
    name: index for index, name in enumerate(DATABASE_COMPATIBLE_COLUMNS)
}
_SERVICE_NAMES = frozenset({
    "ias",
    "nps",
    "ras",
    "routing and remote access service",
})
_SOURCE_INSTANCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_STATUS_BY_VALUE = {
    "1": "start",
    "2": "stop",
    "3": "interim_update",
    "7": "accounting_on",
    "8": "accounting_off",
}
_ACCOUNTING_CONTROL_STATUSES = frozenset({"accounting_on", "accounting_off"})


class RadiusAccountingContractError(ValueError):
    """Closed-code parser failure safe for aggregate diagnostics."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ParsedRadiusAccountingRecord:
    adapter_contract_id: str
    packet_type: int
    accounting_status: str | None
    record_date: str = field(repr=False)
    record_time: str = field(repr=False)
    account_session_id: str | None = field(repr=False)
    nas_identifier: str | None = field(repr=False)
    nas_ip_address: str | None = field(repr=False)
    user_name: str | None = field(repr=False)
    distinguished_name: str | None = field(repr=False)
    class_attribute: str | None = field(repr=False)
    canonical_record_sha256: str

    @property
    def is_accounting_request(self) -> bool:
        return self.packet_type == ACCOUNTING_REQUEST_PACKET_TYPE

    @property
    def is_accounting_control_event(self) -> bool:
        return (
            self.is_accounting_request
            and self.accounting_status in _ACCOUNTING_CONTROL_STATUSES
        )

    @property
    def nas_identity(self) -> str | None:
        return self.nas_identifier or self.nas_ip_address


@dataclass(frozen=True)
class RadiusSessionObservation:
    """One lifecycle observation; not a persisted session aggregate."""

    adapter_contract_id: str
    source_instance_id: str
    lifecycle_event: str
    canonical_record_sha256: str
    account_session_id: str = field(repr=False)
    nas_identity: str = field(repr=False)
    principal_observation: str | None = field(repr=False)
    exact_principal_key: str | None = field(repr=False)
    observed_at_utc: str | None
    timestamp_basis: str | None
    session_identity_key: str | None
    session_confirmed_by_accounting: bool
    session_identity_ready: bool
    timestamp_ready: bool


@dataclass(frozen=True)
class RadiusClassIdentityBinding:
    """One Access-Accept Class→identity observation kept outside payload."""

    adapter_contract_id: str
    source_instance_id: str
    canonical_record_sha256: str
    class_attribute: str = field(repr=False)
    principal_observation: str = field(repr=False)
    exact_principal_key: str | None = field(repr=False)
    identity_lookup_ready: bool
    exact_identity_ready: bool


def is_database_compatible_row(row: list[str] | tuple[str, ...]) -> bool:
    """Recognize only the exact 66-column shape accepted by evidence 34."""

    if len(row) != EXPECTED_FIELD_COUNT:
        return False
    service_name = row[_COLUMN_INDEX["ServiceName"]].strip().casefold()
    packet_type = row[_COLUMN_INDEX["Packet-Type"]].strip()
    return (
        service_name in _SERVICE_NAMES
        and packet_type.isdigit()
        and 0 <= int(packet_type) <= 255
    )


def parse_database_compatible_record(
    line: str,
) -> ParsedRadiusAccountingRecord:
    """Parse one line without performing lifecycle or identity resolution."""

    if not isinstance(line, str) or not line.strip():
        raise RadiusAccountingContractError("record_required")
    if len(line) > MAX_RECORD_CHARACTERS:
        raise RadiusAccountingContractError("record_too_large")
    if "\x00" in line or "\n" in line or "\r" in line:
        raise RadiusAccountingContractError("single_text_record_required")
    try:
        row = next(csv.reader([line], strict=True))
    except (csv.Error, StopIteration) as exc:
        raise RadiusAccountingContractError("invalid_csv") from exc
    if not is_database_compatible_row(row):
        raise RadiusAccountingContractError(
            "database_compatible_shape_required"
        )

    packet_type = int(_value(row, "Packet-Type") or "0")
    status_raw = _value(row, "Acct-Status-Type")
    accounting_status = _STATUS_BY_VALUE.get(status_raw)
    if packet_type == ACCOUNTING_REQUEST_PACKET_TYPE and accounting_status is None:
        raise RadiusAccountingContractError(
            "accounting_status_unsupported_or_missing"
        )

    return ParsedRadiusAccountingRecord(
        adapter_contract_id=ADAPTER_CONTRACT_ID,
        packet_type=packet_type,
        accounting_status=accounting_status,
        record_date=_value(row, "Record-Date") or "",
        record_time=_value(row, "Record-Time") or "",
        account_session_id=_value(row, "Acct-Session-Id"),
        nas_identifier=_value(row, "NAS-Identifier"),
        nas_ip_address=_value(row, "NAS-IP-Address"),
        user_name=_value(row, "User-Name"),
        distinguished_name=_value(
            row,
            "Fully-Qualified-Distinguished-Name",
        ),
        class_attribute=_value(row, "Class"),
        # This is a deterministic hash of the decoded canonical record text,
        # not a claim about the original file-byte encoding.
        canonical_record_sha256=sha256(line.encode("utf-8")).hexdigest(),
    )


def build_session_observation(
    record: ParsedRadiusAccountingRecord,
    *,
    source_instance_id: str,
    exact_principal_key: str | None = None,
    class_identity_binding: RadiusClassIdentityBinding | None = None,
    source_timezone_id: str | None = None,
    source_utc_offset_minutes: int | None = None,
) -> RadiusSessionObservation | None:
    """Build a lifecycle observation without inventing principal identity.

    Access Request/Accept/Reject records are intentionally ignored.  An exact
    session identity is emitted only when an external identity-spine lookup
    supplies an already canonical principal key.  The parser never upgrades
    ``User-Name`` into exact identity by itself.
    """

    if not record.is_accounting_request or record.is_accounting_control_event:
        return None
    source_instance = str(source_instance_id or "").strip()
    if _SOURCE_INSTANCE.fullmatch(source_instance) is None:
        raise RadiusAccountingContractError("source_instance_id_invalid")
    session_id = str(record.account_session_id or "").strip()
    if not session_id:
        raise RadiusAccountingContractError("account_session_id_required")
    nas_identity = str(record.nas_identity or "").strip()
    if not nas_identity:
        raise RadiusAccountingContractError("nas_identity_required")
    lifecycle_event = str(record.accounting_status or "").strip()
    if lifecycle_event not in {"start", "interim_update", "stop"}:
        raise RadiusAccountingContractError("accounting_status_required")

    principal_key = str(exact_principal_key or "").strip() or None
    principal_observation = record.distinguished_name or record.user_name
    if class_identity_binding is not None:
        if principal_key is not None:
            raise RadiusAccountingContractError(
                "principal_sources_are_mutually_exclusive"
            )
        if class_identity_binding.source_instance_id != source_instance:
            raise RadiusAccountingContractError(
                "class_binding_source_mismatch"
            )
        if (
            not record.class_attribute
            or record.class_attribute
            != class_identity_binding.class_attribute
        ):
            raise RadiusAccountingContractError(
                "class_binding_mismatch"
            )
        principal_key = class_identity_binding.exact_principal_key
        principal_observation = (
            class_identity_binding.principal_observation
        )
    observed_at_utc, timestamp_basis = _record_timestamp(
        record,
        source_timezone_id=source_timezone_id,
        source_utc_offset_minutes=source_utc_offset_minutes,
    )
    session_identity_key = (
        _session_identity_key(
            source_instance_id=source_instance,
            nas_identity=nas_identity,
            account_session_id=session_id,
            exact_principal_key=principal_key,
        )
        if principal_key is not None
        else None
    )
    return RadiusSessionObservation(
        adapter_contract_id=record.adapter_contract_id,
        source_instance_id=source_instance,
        lifecycle_event=lifecycle_event,
        canonical_record_sha256=record.canonical_record_sha256,
        account_session_id=session_id,
        nas_identity=nas_identity,
        principal_observation=principal_observation,
        exact_principal_key=principal_key,
        observed_at_utc=observed_at_utc,
        timestamp_basis=timestamp_basis,
        session_identity_key=session_identity_key,
        session_confirmed_by_accounting=True,
        session_identity_ready=session_identity_key is not None,
        timestamp_ready=observed_at_utc is not None,
    )


def build_class_identity_binding(
    record: ParsedRadiusAccountingRecord,
    *,
    source_instance_id: str,
    exact_principal_key: str | None = None,
) -> RadiusClassIdentityBinding | None:
    """Build the Microsoft-documented Access-Accept Class bridge.

    ``Class`` is treated as an opaque exact value.  A distinguished name is
    only an identity-spine lookup input; it is not promoted to a canonical
    principal key by this parser.
    """

    if record.packet_type != ACCESS_ACCEPT_PACKET_TYPE:
        return None
    source_instance = str(source_instance_id or "").strip()
    if _SOURCE_INSTANCE.fullmatch(source_instance) is None:
        raise RadiusAccountingContractError("source_instance_id_invalid")
    class_attribute = str(record.class_attribute or "")
    if not class_attribute:
        raise RadiusAccountingContractError(
            "access_accept_class_required"
        )
    principal_observation = str(record.distinguished_name or "").strip()
    if not principal_observation:
        raise RadiusAccountingContractError(
            "access_accept_distinguished_name_required"
        )
    principal_key = str(exact_principal_key or "").strip() or None
    return RadiusClassIdentityBinding(
        adapter_contract_id=record.adapter_contract_id,
        source_instance_id=source_instance,
        canonical_record_sha256=record.canonical_record_sha256,
        class_attribute=class_attribute,
        principal_observation=principal_observation,
        exact_principal_key=principal_key,
        identity_lookup_ready=True,
        exact_identity_ready=principal_key is not None,
    )


def _value(row: list[str], column: str) -> str | None:
    value = row[_COLUMN_INDEX[column]].strip()
    return value or None


def _record_timestamp(
    record: ParsedRadiusAccountingRecord,
    *,
    source_timezone_id: str | None,
    source_utc_offset_minutes: int | None,
) -> tuple[str | None, str | None]:
    timezone_id = str(source_timezone_id or "").strip()
    if source_utc_offset_minutes is None and not timezone_id:
        return None, None
    if source_utc_offset_minutes is None or not timezone_id:
        raise RadiusAccountingContractError(
            "source_timezone_context_incomplete"
        )
    offset = int(source_utc_offset_minutes)
    if not -840 <= offset <= 840:
        raise RadiusAccountingContractError(
            "source_timezone_offset_invalid"
        )
    try:
        # Accounting timestamps are local wall time; the observed source
        # offset is applied explicitly below, never the collector's timezone.
        local = datetime.strptime(  # noqa: DTZ007
            f"{record.record_date} {record.record_time}",
            "%m/%d/%Y %H:%M:%S",
        )
    except ValueError as exc:
        raise RadiusAccountingContractError(
            "record_local_timestamp_invalid"
        ) from exc
    observed = (local - timedelta(minutes=offset)).replace(
        tzinfo=timezone.utc
    )
    return (
        observed.isoformat(),
        "record_date_time_plus_observed_source_timezone",
    )


def _session_identity_key(
    *,
    source_instance_id: str,
    nas_identity: str,
    account_session_id: str,
    exact_principal_key: str,
) -> str:
    material = json.dumps(
        {
            "source_instance_id": source_instance_id.casefold(),
            "nas_identity": nas_identity.casefold(),
            # Session IDs are opaque and deliberately remain case-sensitive.
            "account_session_id": account_session_id,
            "exact_principal_key": exact_principal_key,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"radius-session:{sha256(material).hexdigest()}"
