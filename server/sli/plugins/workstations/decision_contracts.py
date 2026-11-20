"""Inactive WR22 pure contracts. No authorization, persistence or runtime caller.

Trusted inputs are assertions supplied by a future integration, not ACL evidence
produced here. Fixture policies do not establish an approved runtime TTL policy.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal

_CODES = frozenset({
    "request_shape_invalid", "request_id_invalid", "scope_unsupported", "action_unsupported",
    "finding_pin_invalid", "reason_invalid", "ttl_invalid", "policy_invalid", "binding_invalid",
    "finding_conflict", "station_conflict", "binding_denied", "time_invalid", "expiry_invalid",
    "intent_invalid", "replay_key_invalid", "receipt_invalid", "receipt_denied", "replay_conflict",
})
_ACTIONS = ("reviewed", "exception")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_PIN_FIELDS = frozenset({"id", "station_id", "check_id", "rule_version", "episode_id", "revision",
                         "condition_sha256", "subject_id", "subject_ref"})


class DecisionContractError(ValueError):
    """Only a stable, non-sensitive code is exposed, including in repr/args."""

    def __init__(self, code: str):
        self.code = code if type(code) is str and code in _CODES else "request_shape_invalid"
        super().__init__(self.code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise DecisionContractError(code)


def _text(value: object, maximum: int | None = None) -> bool:
    if type(value) is not str or not value.strip() or "\0" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return maximum is None or len(value.strip()) <= maximum


def _positive(value: object, maximum: int | None = None) -> bool:
    return type(value) is int and value > 0 and (maximum is None or value <= maximum)


def _hash(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _action(value: object) -> None:
    _require(type(value) is str and value in _ACTIONS, "action_unsupported")


def _request_id(value: object, maximum: int | None = None) -> None:
    _require(_text(value) and (maximum is None or (_positive(maximum) and len(value) <= maximum)),
             "request_id_invalid")


def _json_value(value: object) -> None:
    if type(value) is dict:
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError
            _json_value(key)
            _json_value(child)
    elif type(value) is list:
        for child in value:
            _json_value(child)
    elif type(value) is str:
        if "\0" in value:
            raise ValueError
        value.encode("utf-8")
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError
    elif value is not None and type(value) not in (bool, int):
        raise ValueError


def _json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _subject_storage_size(value: object) -> int:
    """Bound schema 252 jsonb::text bytes, including numeric exponent expansion.

    PostgreSQL JSONB uses numeric output rather than scientific notation.
    Negative zero can conservatively overcount by one byte.
    """
    if type(value) is float:
        return len(format(Decimal(str(value)), "f"))
    if type(value) is list:
        return 2 + max(0, len(value) - 1) * 2 + sum(_subject_storage_size(child) for child in value)
    if type(value) is dict:
        return (2 + max(0, len(value) - 1) * 2
                + sum(len(_json_bytes(key)) + 2 + _subject_storage_size(child) for key, child in value.items()))
    return len(_json_bytes(value))


def _subject_bytes(value: object) -> bytes:
    try:
        if type(value) is not dict:
            raise ValueError
        _json_value(value)
        if _subject_storage_size(value) > 8192:
            raise ValueError
        return _json_bytes(value)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise DecisionContractError("finding_pin_invalid") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _subject(value: object) -> dict:
    try:
        if type(value) is not bytes:
            raise ValueError
        decoded = json.loads(value.decode("utf-8"), object_pairs_hook=_unique_object)
        # The type promises canonical bytes. Reject spelling that would silently
        # round/underflow a number or otherwise lose data on JSON decoding.
        if _subject_bytes(decoded) != value:
            raise ValueError
        return decoded
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise DecisionContractError("finding_pin_invalid") from None


@dataclass(frozen=True)
class FindingPin:
    """Exact finding identity plus a bounded, immutable subject snapshot."""

    id: str
    station_id: str
    check_id: str
    rule_version: int
    episode_id: str
    revision: int
    condition_sha256: str
    subject_id: str | None
    subject_json: bytes = field(repr=False)

    def __post_init__(self):
        _require(_hash(self.id) and _text(self.station_id, 256)
                 and type(self.check_id) is str and self.check_id in tuple(f"C{n:02}" for n in range(1, 11))
                 and _positive(self.rule_version, 2**31 - 1) and _hash(self.episode_id)
                 and _positive(self.revision, 2**63 - 1) and _hash(self.condition_sha256)
                 and (self.subject_id is None or _text(self.subject_id, 256)), "finding_pin_invalid")
        object.__setattr__(self, "subject_json", _subject_bytes(_subject(self.subject_json)))


@dataclass(frozen=True)
class StationRequest:
    """Untrusted station-only intent; construction grants no authority."""

    request_id: str
    action: str
    expected_pin: FindingPin
    station_id: str
    reason: str = field(repr=False)
    requested_ttl_seconds: int

    def __post_init__(self):
        _request_id(self.request_id)
        _action(self.action)
        _require(type(self.expected_pin) is FindingPin, "finding_pin_invalid")
        _require(_text(self.station_id, 256), "scope_unsupported")
        _require(_text(self.reason) and len(self.reason.strip()) <= 2000, "reason_invalid")
        object.__setattr__(self, "reason", self.reason.strip())
        _require(_positive(self.requested_ttl_seconds), "ttl_invalid")


def parse_station_request(raw: Mapping[str, object], *, request_id_max_chars: int) -> StationRequest:
    """Parse only client data. No access check, resolver or TTL policy is applied."""
    fields = {"request_id", "action", "expected_pin", "scope", "reason", "requested_ttl_seconds"}
    _require(isinstance(raw, Mapping) and set(raw) == fields, "request_shape_invalid")
    _require(_positive(request_id_max_chars), "request_id_invalid")
    _request_id(raw["request_id"], request_id_max_chars)
    scope = raw["scope"]
    _require(isinstance(scope, Mapping) and set(scope) == {"kind", "station_id"}
             and type(scope["kind"]) is str and scope["kind"] == "station", "scope_unsupported")
    pin = raw["expected_pin"]
    _require(isinstance(pin, Mapping) and set(pin) == _PIN_FIELDS, "finding_pin_invalid")
    expected = FindingPin(**{key: pin[key] for key in _PIN_FIELDS if key != "subject_ref"},
                          subject_json=_subject_bytes(pin["subject_ref"]))
    return StationRequest(raw["request_id"], raw["action"], expected, scope["station_id"],
                          raw["reason"], raw["requested_ttl_seconds"])


def canonical_payload(request: StationRequest) -> bytes:
    """Versioned semantic payload; the request ID belongs to the replay key."""
    _require(type(request) is StationRequest, "request_shape_invalid")
    pin = request.expected_pin
    expected = {key: getattr(pin, key) for key in _PIN_FIELDS if key != "subject_ref"}
    expected["subject_ref"] = _subject(pin.subject_json)
    return _json_bytes({"canonicalization_version": 1, "action": request.action,
                        "expected_pin": expected, "scope": {"kind": "station", "station_id": request.station_id},
                        "reason": request.reason, "requested_ttl_seconds": request.requested_ttl_seconds})


def payload_fingerprint(request: StationRequest) -> str:
    """SHA-256 of canonical semantic bytes, without a clock or current policy."""
    return hashlib.sha256(canonical_payload(request)).hexdigest()


@dataclass(frozen=True)
class DecisionPolicy:
    """Explicit injected limits; there are no runtime defaults in this module."""

    version: str
    reviewed_max_ttl_seconds: int
    exception_max_ttl_seconds: int
    request_id_max_chars: int

    def __post_init__(self):
        _require(_text(self.version) and _positive(self.reviewed_max_ttl_seconds)
                 and _positive(self.exception_max_ttl_seconds) and _positive(self.request_id_max_chars),
                 "policy_invalid")


@dataclass(frozen=True)
class TrustedStationBinding:
    """Injected resolver/access assertion, never proof of actual production ACL.

    Installation/principal IDs are opaque server-issued ID strings. A future
    integration must supply the exact registered agent and current authorization
    result; station IDs, display names and read grants cannot establish them.
    """

    installation_id: str
    principal_id: str
    station_id: str
    agent_key: str
    action: str
    finding_pin: FindingPin
    authorization_outcome: str
    unique_association: bool

    def __post_init__(self):
        _require(_text(self.installation_id) and _text(self.principal_id)
                 and _text(self.station_id, 256) and _text(self.agent_key, 256)
                 and type(self.action) is str and self.action in _ACTIONS
                 and type(self.finding_pin) is FindingPin
                 and type(self.authorization_outcome) is str
                 and self.authorization_outcome in ("allowed", "denied", "unresolved")
                 and type(self.unique_association) is bool, "binding_invalid")


def _utc(value: object, code: str) -> datetime:
    try:
        if type(value) is datetime and value.tzinfo is not None and value.utcoffset() == timedelta(0):
            return value.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        pass
    raise DecisionContractError(code)


def _preparation(request, current, binding, policy, now):
    _require(type(request) is StationRequest, "request_shape_invalid")
    _require(type(current) is FindingPin, "finding_pin_invalid")
    _require(request.expected_pin == current, "finding_conflict")
    _require(request.station_id == current.station_id, "station_conflict")
    _require(type(binding) is TrustedStationBinding, "binding_invalid")
    _require(binding.station_id == request.station_id and binding.action == request.action
             and binding.finding_pin == current, "binding_invalid")
    _require(binding.authorization_outcome == "allowed" and binding.unique_association, "binding_denied")
    _require(type(policy) is DecisionPolicy, "policy_invalid")
    _request_id(request.request_id, policy.request_id_max_chars)
    maximum = policy.reviewed_max_ttl_seconds if request.action == "reviewed" else policy.exception_max_ttl_seconds
    _require(_positive(request.requested_ttl_seconds) and request.requested_ttl_seconds <= maximum, "ttl_invalid")
    server_time = _utc(now, "time_invalid")
    try:
        expiry = server_time + timedelta(seconds=request.requested_ttl_seconds)
    except (OverflowError, ValueError):
        raise DecisionContractError("expiry_invalid") from None
    return server_time, expiry


@dataclass(frozen=True)
class PreparedStationIntent:
    """Validated intent only: authorizes nothing and persists nothing.

    The immutable policy snapshot makes direct construction validate the same
    finite lifetime and binding consistency as preparation. It proves no ACL,
    transaction, audit write or committed result exists.
    """

    request: StationRequest
    installation_id: str
    principal_id: str
    server_time: datetime
    expires_at: datetime
    policy_version: str
    binding_snapshot: TrustedStationBinding
    payload_fingerprint: str
    policy: DecisionPolicy = field(repr=False)

    def __post_init__(self):
        _require(type(self.request) is StationRequest, "request_shape_invalid")
        _require(_text(self.installation_id) and _text(self.principal_id) and _text(self.policy_version)
                 and _hash(self.payload_fingerprint), "intent_invalid")
        server_time, expiry = _preparation(self.request, self.request.expected_pin,
                                           self.binding_snapshot, self.policy, self.server_time)
        _require(self.installation_id == self.binding_snapshot.installation_id
                 and self.principal_id == self.binding_snapshot.principal_id
                 and self.policy_version == self.policy.version
                 and _utc(self.expires_at, "intent_invalid") == expiry
                 and self.payload_fingerprint == payload_fingerprint(self.request), "intent_invalid")
        object.__setattr__(self, "server_time", server_time)
        object.__setattr__(self, "expires_at", expiry)


def prepare_station_intent(request: StationRequest, *, current: FindingPin,
                           binding: TrustedStationBinding | None, policy: DecisionPolicy | None,
                           now: datetime) -> PreparedStationIntent:
    """Check injected facts and prepare an inactive intent, without resolving access."""
    server_time, expiry = _preparation(request, current, binding, policy, now)
    return PreparedStationIntent(request, binding.installation_id, binding.principal_id,
                                 server_time, expiry, policy.version, binding,
                                 payload_fingerprint(request), policy)


@dataclass(frozen=True)
class ReplayKey:
    """Caller-supplied server identity boundary plus action and client request ID."""

    installation_id: str
    principal_id: str
    operation: str
    request_id: str

    def __post_init__(self):
        _require(_text(self.installation_id) and _text(self.principal_id)
                 and type(self.operation) is str and self.operation in _ACTIONS
                 and _text(self.request_id), "replay_key_invalid")


@dataclass(frozen=True)
class CommittedReceipt:
    """Previously committed caller data. This module never generates a receipt."""

    key: ReplayKey
    payload_fingerprint: str
    result_reference: str
    created_at: datetime
    expires_at: datetime

    def __post_init__(self):
        _require(type(self.key) is ReplayKey and _hash(self.payload_fingerprint)
                 and _text(self.result_reference), "receipt_invalid")
        created = _utc(self.created_at, "receipt_invalid")
        expiry = _utc(self.expires_at, "receipt_invalid")
        _require(expiry > created, "receipt_invalid")
        object.__setattr__(self, "created_at", created)
        object.__setattr__(self, "expires_at", expiry)


def replay_receipt(request: StationRequest, *, key: ReplayKey, receipt: CommittedReceipt,
                   receipt_visible: bool) -> CommittedReceipt:
    """Return the original visible committed receipt or conflict, with no renewal.

    Visibility and identity are trusted caller assertions. No policy, current
    finding, clock, preparation, persistence or concurrency mechanism is used.
    """
    _require(type(receipt_visible) is bool and receipt_visible, "receipt_denied")
    _require(type(request) is StationRequest, "request_shape_invalid")
    _require(type(key) is ReplayKey, "replay_key_invalid")
    _require(type(receipt) is CommittedReceipt, "receipt_invalid")
    _require(key == receipt.key and key.operation == request.action and key.request_id == request.request_id
             and receipt.payload_fingerprint == payload_fingerprint(request), "replay_conflict")
    return receipt
