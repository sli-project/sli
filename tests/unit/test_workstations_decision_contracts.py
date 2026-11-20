"""Inactive WR22 contract, using synthetic identities and fixture TTLs only."""

import hashlib
import json
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest

from server.sli.plugins.workstations import decision_contracts as dc


def raw_request():
    return {
        "request_id": "synthetic-request", "action": "reviewed",
        "expected_pin": {
            "id": "a" * 64, "station_id": "synthetic-station", "check_id": "C02",
            "rule_version": 1, "episode_id": "b" * 64, "revision": 2,
            "condition_sha256": "c" * 64, "subject_id": "synthetic-subject",
            "subject_ref": {"kind": "local_account", "ref": {"sid": "synthetic-sid"},
                            "observations": ["first", "second"]},
        },
        "scope": {"kind": "station", "station_id": "synthetic-station"},
        "reason": "  synthetic review\nwith  inner spacing  ",
        "requested_ttl_seconds": 60,
    }


def parse(raw=None):
    return dc.parse_station_request(raw_request() if raw is None else raw, request_id_max_chars=80)


def rejected(call, code):
    with pytest.raises(dc.DecisionContractError) as caught:
        call()
    assert caught.value.code == code
    assert str(caught.value) == code
    assert "synthetic review" not in repr(caught.value)
    assert "synthetic-sid" not in repr(caught.value)


def test_parser_normalizes_only_outer_reason_and_has_immutable_snapshot():
    raw = raw_request()
    request = parse(raw)
    before = dc.canonical_payload(request)
    raw["expected_pin"]["subject_ref"]["ref"]["sid"] = "changed"
    assert dc.canonical_payload(request) == before
    assert request.reason == "synthetic review\nwith  inner spacing"
    assert request.station_id == "synthetic-station"
    assert json.loads(request.expected_pin.subject_json)["ref"]["sid"] == "synthetic-sid"
    with pytest.raises(FrozenInstanceError):
        request.reason = "changed"
    with pytest.raises(FrozenInstanceError):
        request.expected_pin.revision = 3


@pytest.mark.parametrize("field", ["principal_id", "created_by", "now", "expires_at", "permissions",
                                   "binding", "policy", "account_id", "ou_id", "domain_id", "bulk"])
def test_unknown_request_fields_cannot_supply_authority(field):
    raw = raw_request()
    raw[field] = "untrusted"
    rejected(lambda: parse(raw), "request_shape_invalid")


@pytest.mark.parametrize("scope", [{"kind": "account"}, {"kind": "ou"}, {"kind": "domain"},
                                  {"kind": "bulk"}, {"kind": "station", "station_id": "s",
                                                     "include_descendants": True}])
def test_unsupported_scope_is_never_partially_accepted(scope):
    raw = raw_request()
    raw["scope"] = scope
    rejected(lambda: parse(raw), "scope_unsupported")


@pytest.mark.parametrize("action", ["revoke", "expire", "review", "bulk", True])
def test_unsupported_action_fails(action):
    raw = raw_request()
    raw["action"] = action
    rejected(lambda: parse(raw), "action_unsupported")


@pytest.mark.parametrize("field,value", [
    ("id", "A" * 64), ("id", "a" * 63), ("episode_id", "x" * 64),
    ("condition_sha256", ""), ("station_id", "s" * 257), ("station_id", " "),
    ("subject_id", "s" * 257), ("subject_id", ""), ("check_id", "C11"),
    ("rule_version", True), ("rule_version", 0), ("rule_version", 2**31),
    ("revision", True), ("revision", 0), ("revision", 2**63),
    ("subject_ref", []), ("subject_ref", {"secret": "x" * 8192}),
])
def test_finding_schema_bounds_are_enforced(field, value):
    raw = raw_request()
    raw["expected_pin"][field] = value
    rejected(lambda: parse(raw), "finding_pin_invalid")


@pytest.mark.parametrize("reason", ["", " \t\n", "x\0y", "\U0001f680" * 2001, None, True])
def test_invalid_reason_fails_without_echo(reason):
    raw = raw_request()
    raw["reason"] = reason
    rejected(lambda: parse(raw), "reason_invalid")


def test_reason_bound_is_unicode_code_points():
    raw = raw_request()
    raw["reason"] = "\U0001f680" * 2000
    assert len(parse(raw).reason) == 2000


@pytest.mark.parametrize("ttl", [None, True, 0, -1, 1.0, float("inf"), "60"])
def test_ttl_requires_explicit_positive_integer(ttl):
    raw = raw_request()
    raw["requested_ttl_seconds"] = ttl
    rejected(lambda: parse(raw), "ttl_invalid")


@pytest.mark.parametrize("bound", [None, True, 0, -1, 1.0])
def test_request_id_bound_is_explicit_and_valid(bound):
    rejected(lambda: dc.parse_station_request(raw_request(), request_id_max_chars=bound), "request_id_invalid")


def test_request_id_exact_bound_and_unknown_nested_fields():
    raw = raw_request()
    assert dc.parse_station_request(raw, request_id_max_chars=len(raw["request_id"]))
    rejected(lambda: dc.parse_station_request(raw, request_id_max_chars=len(raw["request_id"]) - 1),
             "request_id_invalid")
    raw["expected_pin"]["author"] = "untrusted"
    rejected(lambda: parse(raw), "finding_pin_invalid")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object(), {1: "numeric key"},
                                  ("tuple",), {"bad": "\ud800"}, {"bad": "\0"}])
def test_non_json_or_unstorable_subject_is_rejected(value):
    raw = raw_request()
    raw["expected_pin"]["subject_ref"] = {"nested": value}
    rejected(lambda: parse(raw), "finding_pin_invalid")


def test_subject_bound_counts_storage_numeric_expansion_and_separator_spaces():
    raw = raw_request()
    raw["expected_pin"]["subject_ref"] = {"numbers": [1e308] * 28}
    rejected(lambda: parse(raw), "finding_pin_invalid")
    raw["expected_pin"]["subject_ref"] = {"x": "x" * 8183}
    assert parse(raw)
    raw["expected_pin"]["subject_ref"]["x"] += "x"
    rejected(lambda: parse(raw), "finding_pin_invalid")


def test_scope_kind_requires_json_string_even_for_direct_python_callers():
    class PretendStation:
        def __eq__(self, other):
            return other == "station"

    raw = raw_request()
    raw["scope"]["kind"] = PretendStation()
    rejected(lambda: parse(raw), "scope_unsupported")


def test_direct_subject_bytes_cannot_silently_lose_numeric_precision():
    rejected(lambda: replace(parse().expected_pin, subject_json=b'{"x":1e-10000}'), "finding_pin_invalid")
    rejected(lambda: replace(parse().expected_pin, subject_json=b'{"x":0.100000000000000001}'),
             "finding_pin_invalid")


PIN_CHANGES = [("id", "d" * 64), ("station_id", "other-station"), ("check_id", "C03"),
               ("rule_version", 2), ("episode_id", "e" * 64), ("revision", 3),
               ("condition_sha256", "f" * 64), ("subject_id", "other-subject"),
               ("subject_ref", {"kind": "other"})]


@pytest.mark.parametrize("field,value", PIN_CHANGES)
def test_every_finding_pin_field_affects_semantic_payload(field, value):
    raw = raw_request()
    raw["expected_pin"][field] = value
    assert dc.canonical_payload(parse(raw)) != dc.canonical_payload(parse())


@pytest.mark.parametrize("field,value", [("reason", "another reason"), ("requested_ttl_seconds", 61),
                                       ("action", "exception"), ("scope", {"kind": "station", "station_id": "other"})])
def test_reason_duration_action_scope_affect_semantic_payload(field, value):
    raw = raw_request()
    raw[field] = value
    assert dc.payload_fingerprint(parse(raw)) != dc.payload_fingerprint(parse())


def test_canonical_json_has_version_and_structured_subject_and_ignores_request_id():
    request = parse()
    payload = dc.canonical_payload(request)
    decoded = json.loads(payload)
    assert decoded["canonicalization_version"] == 1
    assert decoded["expected_pin"]["subject_ref"]["ref"] == {"sid": "synthetic-sid"}
    assert b'": ' not in payload
    assert dc.payload_fingerprint(request) == hashlib.sha256(payload).hexdigest()
    assert dc.canonical_payload(replace(request, request_id="different")) == payload
    reordered = raw_request()
    reordered["expected_pin"]["subject_ref"] = dict(reversed(list(reordered["expected_pin"]["subject_ref"].items())))
    assert dc.canonical_payload(parse(reordered)) == payload
    reordered["expected_pin"]["subject_ref"]["observations"].reverse()
    assert dc.canonical_payload(parse(reordered)) != payload


def test_direct_construction_cannot_bypass_parser_checks():
    request = parse()
    rejected(lambda: replace(request, requested_ttl_seconds=True), "ttl_invalid")
    rejected(lambda: replace(request, reason="\0"), "reason_invalid")
    rejected(lambda: replace(request, action="revoke"), "action_unsupported")
    rejected(lambda: replace(request, expected_pin={}), "finding_pin_invalid")
    rejected(lambda: replace(request.expected_pin, revision=True), "finding_pin_invalid")
    rejected(lambda: replace(request.expected_pin, subject_json=b'{"bad":NaN}'), "finding_pin_invalid")
    rejected(lambda: replace(request.expected_pin, subject_json=b'{"x":1,"x":2}'), "finding_pin_invalid")
    rejected(lambda: replace(request.expected_pin, subject_json=bytearray(b'{}')), "finding_pin_invalid")


def test_subject_optional_identity_and_upper_schema_boundaries():
    raw = raw_request()
    raw["expected_pin"].update(subject_id=None, subject_ref={}, station_id="s" * 256,
                                rule_version=2**31 - 1, revision=2**63 - 1)
    assert parse(raw).expected_pin.subject_id is None


@pytest.mark.parametrize("raw", [None, [], {}, {"action": "reviewed"}])
def test_incomplete_or_nonmapping_request_fails_closed(raw):
    rejected(lambda: dc.parse_station_request(raw, request_id_max_chars=80), "request_shape_invalid")


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def fixture_policy():
    # Synthetic limits only: no approved runtime policy is implied.
    return dc.DecisionPolicy("synthetic-policy-v1", reviewed_max_ttl_seconds=60,
                             exception_max_ttl_seconds=120, request_id_max_chars=80)


def fixture_binding(request=None):
    request = parse() if request is None else request
    return dc.TrustedStationBinding(
        installation_id="synthetic-installation", principal_id="synthetic-principal",
        station_id=request.station_id, agent_key="synthetic-registered-agent",
        action=request.action, finding_pin=request.expected_pin,
        authorization_outcome="allowed", unique_association=True,
    )


def prepare(request=None, **overrides):
    request = parse() if request is None else request
    arguments = {"current": request.expected_pin, "binding": fixture_binding(request),
                 "policy": fixture_policy(), "now": NOW}
    arguments.update(overrides)
    return dc.prepare_station_intent(request, **arguments)


@pytest.mark.parametrize("action,seconds", [("reviewed", 60), ("exception", 120)])
def test_exact_trusted_inputs_prepare_only_finite_immutable_intent(action, seconds):
    request = replace(parse(), action=action, requested_ttl_seconds=seconds)
    current = deepcopy(request.expected_pin)
    binding = fixture_binding(request)
    intent = prepare(request, current=current, binding=binding)
    assert intent.request == request
    assert intent.installation_id == "synthetic-installation"
    assert intent.principal_id == "synthetic-principal"
    assert intent.server_time == NOW
    assert intent.expires_at == NOW + timedelta(seconds=seconds)
    assert intent.policy_version == "synthetic-policy-v1"
    assert intent.binding_snapshot == binding
    assert intent.binding_snapshot.agent_key == "synthetic-registered-agent"
    assert intent.payload_fingerprint == dc.payload_fingerprint(request)
    assert current == request.expected_pin
    assert not any(hasattr(intent, name) for name in ("quality", "status", "secure", "applied"))
    with pytest.raises(FrozenInstanceError):
        intent.expires_at = NOW
    with pytest.raises(FrozenInstanceError):
        intent.binding_snapshot.agent_key = "changed"


@pytest.mark.parametrize("field,value", PIN_CHANGES)
def test_current_finding_must_match_every_pin_field(field, value):
    raw = raw_request()
    raw["expected_pin"][field] = value
    rejected(lambda: prepare(current=parse(raw).expected_pin), "finding_conflict")


def test_explicit_selected_station_must_match_finding():
    request = replace(parse(), station_id="other-station")
    rejected(lambda: prepare(request), "station_conflict")


@pytest.mark.parametrize("outcome", ["denied", "unresolved"])
def test_binding_denial_or_unresolved_outcome_fails_closed(outcome):
    binding = replace(fixture_binding(), authorization_outcome=outcome)
    rejected(lambda: prepare(binding=binding), "binding_denied")


def test_missing_binding_and_nonunique_association_fail_closed():
    rejected(lambda: prepare(binding=None), "binding_invalid")
    rejected(lambda: prepare(binding=replace(fixture_binding(), unique_association=False)), "binding_denied")
    rejected(lambda: prepare(binding={"allowed": True}), "binding_invalid")


@pytest.mark.parametrize("field,value", [("station_id", "other"), ("action", "exception")])
def test_trusted_binding_cannot_be_reused_for_another_station_or_action(field, value):
    rejected(lambda: prepare(binding=replace(fixture_binding(), **{field: value})), "binding_invalid")


@pytest.mark.parametrize("field,value", PIN_CHANGES)
def test_trusted_binding_cannot_be_reused_for_another_pin(field, value):
    raw = raw_request()
    raw["expected_pin"][field] = value
    binding = replace(fixture_binding(), finding_pin=parse(raw).expected_pin)
    rejected(lambda: prepare(binding=binding), "binding_invalid")


@pytest.mark.parametrize("field,value", [("installation_id", ""), ("principal_id", ""),
                                       ("principal_id", True), ("agent_key", ""),
                                       ("agent_key", "a" * 257), ("unique_association", 1),
                                       ("authorization_outcome", "read_only"), ("finding_pin", {})])
def test_binding_constructor_cannot_smuggle_incomplete_or_read_only_authority(field, value):
    rejected(lambda: replace(fixture_binding(), **{field: value}), "binding_invalid")


def test_binding_has_no_affirmative_authorization_defaults():
    with pytest.raises(TypeError):
        dc.TrustedStationBinding("i", "p", "s", "agent", "reviewed", parse().expected_pin)


@pytest.mark.parametrize("field,value", [("version", ""), ("version", True),
                                       ("reviewed_max_ttl_seconds", 0), ("reviewed_max_ttl_seconds", True),
                                       ("exception_max_ttl_seconds", -1), ("exception_max_ttl_seconds", 1.5),
                                       ("request_id_max_chars", True), ("request_id_max_chars", 0)])
def test_invalid_policy_construction_fails_closed(field, value):
    rejected(lambda: replace(fixture_policy(), **{field: value}), "policy_invalid")


@pytest.mark.parametrize("policy", [None, {}, True])
def test_missing_or_untyped_policy_fails_closed(policy):
    rejected(lambda: prepare(policy=policy), "policy_invalid")


@pytest.mark.parametrize("action,seconds", [("reviewed", 61), ("exception", 121)])
def test_ttl_cannot_exceed_explicit_action_policy(action, seconds):
    request = replace(parse(), action=action, requested_ttl_seconds=seconds)
    rejected(lambda: prepare(request), "ttl_invalid")


def test_prepare_applies_policy_request_id_bound_to_direct_requests():
    request = replace(parse(), request_id="x" * 81)
    rejected(lambda: prepare(request), "request_id_invalid")


@pytest.mark.parametrize("now", [NOW.replace(tzinfo=None),
                                datetime(2026, 1, 1, tzinfo=timezone(timedelta(hours=1))),
                                "2026-01-01T00:00:00Z", None])
def test_only_utc_aware_server_time_is_accepted(now):
    rejected(lambda: prepare(now=now), "time_invalid")


def test_expiry_overflow_fails_closed_even_with_explicit_huge_policy():
    rejected(lambda: prepare(now=datetime.max.replace(tzinfo=timezone.utc)), "expiry_invalid")
    huge = replace(parse(), requested_ttl_seconds=10**100)
    policy = replace(fixture_policy(), reviewed_max_ttl_seconds=10**100)
    rejected(lambda: prepare(huge, policy=policy), "expiry_invalid")


def test_client_time_cannot_determine_expiry_and_parser_applies_no_ttl_policy():
    raw = raw_request()
    raw["requested_ttl_seconds"] = 121
    assert parse(raw).requested_ttl_seconds == 121
    raw["created_at"] = "client-time"
    rejected(lambda: parse(raw), "request_shape_invalid")


def test_prepared_intent_constructor_cannot_bypass_consistency_checks():
    intent = prepare()
    rejected(lambda: replace(intent, expires_at=NOW), "intent_invalid")
    rejected(lambda: replace(intent, principal_id="other"), "intent_invalid")
    rejected(lambda: replace(intent, installation_id="other"), "intent_invalid")
    rejected(lambda: replace(intent, policy_version="other"), "intent_invalid")
    rejected(lambda: replace(intent, payload_fingerprint="f" * 64), "intent_invalid")


@pytest.mark.parametrize("field", ["installation_id", "principal_id", "policy_version", "payload_fingerprint"])
def test_prepared_intent_rejects_mutable_equality_spoofed_strings(field):
    class Equal:
        def __init__(self):
            self.mutable = []

        def __eq__(self, other):
            return True

    rejected(lambda: replace(prepare(), **{field: Equal()}), "intent_invalid")


def fixture_key():
    return dc.ReplayKey("synthetic-installation", "synthetic-principal", "reviewed", "synthetic-request")


def fixture_receipt():
    # Already expired when NOW is used elsewhere: replay must preserve it.
    return dc.CommittedReceipt(fixture_key(), dc.payload_fingerprint(parse()), "synthetic-result-id",
                               datetime(2020, 1, 1, tzinfo=timezone.utc),
                               datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc))


def replay(request=None, **overrides):
    arguments = {"key": fixture_key(), "receipt": fixture_receipt(), "receipt_visible": True}
    arguments.update(overrides)
    return dc.replay_receipt(parse() if request is None else request, **arguments)


def test_replay_returns_original_committed_expired_receipt_without_renewal():
    receipt = fixture_receipt()
    assert replay(receipt=receipt) is receipt
    assert receipt.created_at == datetime(2020, 1, 1, tzinfo=timezone.utc)
    assert receipt.expires_at == datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc)
    with pytest.raises(FrozenInstanceError):
        receipt.result_reference = "changed"


@pytest.mark.parametrize("field,value", [("reason", "changed"), ("requested_ttl_seconds", 61),
                                       ("scope", {"kind": "station", "station_id": "other"})])
def test_changed_semantic_request_conflicts_on_replay(field, value):
    raw = raw_request()
    raw[field] = value
    rejected(lambda: replay(parse(raw)), "replay_conflict")


@pytest.mark.parametrize("field,value", PIN_CHANGES)
def test_each_changed_finding_pin_conflicts_on_replay(field, value):
    raw = raw_request()
    raw["expected_pin"][field] = value
    rejected(lambda: replay(parse(raw)), "replay_conflict")


@pytest.mark.parametrize("field,value", [("installation_id", "foreign-installation"),
                                       ("principal_id", "foreign-principal"),
                                       ("operation", "exception"), ("request_id", "foreign-request")])
def test_full_replay_key_is_mandatory_independent_of_payload(field, value):
    key = replace(fixture_key(), **{field: value})
    rejected(lambda: replay(key=key), "replay_conflict")


@pytest.mark.parametrize("field,value", [("request_id", "other"), ("operation", "exception")])
def test_request_id_and_operation_must_match_key_even_if_receipt_key_matches(field, value):
    key = replace(fixture_key(), **{field: value})
    receipt = replace(fixture_receipt(), key=key)
    rejected(lambda: replay(key=key, receipt=receipt), "replay_conflict")


@pytest.mark.parametrize("visible", [False, None, 1, "true"])
def test_visibility_is_checked_before_receipt_key_or_payload(visible):
    rejected(lambda: replay(receipt_visible=visible), "receipt_denied")
    rejected(lambda: dc.replay_receipt(None, key=None, receipt=None, receipt_visible=visible), "receipt_denied")
    rejected(lambda: replay(replace(parse(), reason="different"), receipt_visible=visible), "receipt_denied")


def test_replay_does_not_apply_current_policy_finding_or_clock():
    request = parse()
    # A newly injected policy would reject this request, but is not a replay input.
    policy = replace(fixture_policy(), reviewed_max_ttl_seconds=1)
    rejected(lambda: prepare(request, policy=policy), "ttl_invalid")
    assert replay(request).expires_at == datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc)
    for context in ({"policy": policy}, {"current": replace(request.expected_pin, revision=99)}, {"now": NOW}):
        with pytest.raises(TypeError):
            dc.replay_receipt(request, key=fixture_key(), receipt=fixture_receipt(), receipt_visible=True, **context)


@pytest.mark.parametrize("field,value", [("installation_id", ""), ("principal_id", True),
                                       ("operation", "revoke"), ("request_id", " ")])
def test_direct_replay_key_validation(field, value):
    rejected(lambda: replace(fixture_key(), **{field: value}), "replay_key_invalid")


@pytest.mark.parametrize("field,value", [("key", {}), ("payload_fingerprint", "invalid"),
                                       ("result_reference", {}), ("created_at", NOW.replace(tzinfo=None)),
                                       ("expires_at", datetime(2019, 1, 1, tzinfo=timezone.utc))])
def test_direct_receipt_validation_cannot_bypass_immutable_types(field, value):
    rejected(lambda: replace(fixture_receipt(), **{field: value}), "receipt_invalid")


def test_public_functions_reject_untyped_inputs_with_fixed_codes():
    rejected(lambda: dc.canonical_payload({}), "request_shape_invalid")
    rejected(lambda: prepare(current={}), "finding_pin_invalid")
    rejected(lambda: dc.prepare_station_intent({}, current=None, binding=None, policy=None, now=None),
             "request_shape_invalid")
    rejected(lambda: replay(receipt={}), "receipt_invalid")
    rejected(lambda: replay(key={}), "replay_key_invalid")
    rejected(lambda: dc.replay_receipt({}, key=fixture_key(), receipt=fixture_receipt(), receipt_visible=True),
             "request_shape_invalid")
