"""ES02 semantic checks use synthetic projections and never query a database."""
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from server.sli.events import evsearch_normalizer as normalizer
from server.sli.events.evsearch_contract import ContractError


NOW = datetime(2026, 10, 19, 12, 30, tzinfo=timezone.utc)


def request(conditions=None, **overrides):
    return {"contract_version": "evsearch.v1", "conditions": conditions or [], **overrides}


def normalize(conditions=None, **overrides):
    return normalizer.normalize_request(request(conditions, **overrides), now=NOW)


def account(entity_id, role="target", **kwargs):
    return normalizer.AccountParticipant(entity_id, role, **kwargs)


def event(event_id, **overrides):
    return {"provider": "Microsoft-Windows-Security-Auditing", "channel": "Security",
            "event_id": event_id, **overrides}


def condition(field, operator, value=None, **kwargs):
    result = {"field": field, "operator": operator, **kwargs}
    if operator not in {"exists", "missing"}:
        result["value"] = value
    return result


@pytest.mark.parametrize("preset,start", [
    ("24h", "2026-10-18T12:30:00Z"),
    ("7d", "2026-10-12T12:30:00Z"),
    ("30d", "2026-09-19T12:30:00Z"),
])
def test_relative_period_is_pinned_once_and_replays_as_a_fixed_window(preset, start):
    from server.sli.events.evsearch_normalizer import normalize_request

    result = normalize_request({
        "contract_version": "evsearch.v1",
        "period": {"preset": preset, "timezone": "UTC"},
    }, now=datetime(2026, 10, 19, 12, 30, tzinfo=timezone.utc))
    fixed = result.as_request()
    assert fixed["period"] == {
        "preset": "custom", "from": start, "to": "2026-10-19T12:30:00Z", "timezone": "UTC",
    }
    assert normalize_request(fixed, now=datetime(2027, 1, 1, tzinfo=timezone.utc)) == result


def test_default_is_an_explicit_day_even_with_text_or_entity_context():
    result = normalize(q="synthetic-token", entry_context={"kind": "entity", "entity_id": 11, "role": "target"})
    assert result.period.as_request() == {
        "preset": "custom", "from": "2026-10-18T12:30:00Z", "to": "2026-10-19T12:30:00Z", "timezone": "UTC",
    }
    assert not result.exclude_machine_system
    assert result.account_role == "target"
    assert "q" in result.required_fields


@pytest.mark.parametrize("period,start,end", [
    ({"preset": "custom", "from": "2026-10-01", "to": "2026-10-01", "timezone": "Asia/Bangkok"},
     "2026-09-30T17:00:00Z", "2026-10-01T17:00:00Z"),
    ({"preset": "custom", "from": "2026-10-01T12:00:00+07:00", "to": "2026-10-01T13:00:00+07:00", "timezone": "Asia/Bangkok"},
     "2026-10-01T05:00:00Z", "2026-10-01T06:00:00Z"),
    ({"preset": "custom", "from": "2026-03-29", "to": "2026-03-29", "timezone": "Europe/Berlin"},
     "2026-03-28T23:00:00Z", "2026-03-29T22:00:00Z"),
])
def test_custom_window_uses_the_shared_local_date_and_dst_contract(period, start, end):
    fixed = normalize(period=period).period.as_request()
    assert (fixed["from"], fixed["to"]) == (start, end)


@pytest.mark.parametrize("period", [
    {"preset": "24h", "timezone": "Not/AZone"},
    {"preset": "custom", "from": "invalid", "to": "2026-10-19", "timezone": "UTC"},
    {"preset": "custom", "from": "2026-10-19T00:00Z", "to": "2026-10-19T00:00Z", "timezone": "UTC"},
    {"preset": "custom", "from": "2026-10-20", "to": "2026-10-18", "timezone": "UTC"},
    {"preset": "custom", "from": "2026-03-29T02:30", "to": "2026-03-29T04:00", "timezone": "Europe/Berlin"},
    {"preset": "custom", "from": "2026-10-25T02:30", "to": "2026-10-25T04:00", "timezone": "Europe/Berlin"},
    {"preset": "custom", "from": "2026-10-01", "timezone": "UTC"},
    {"preset": "all", "timezone": "UTC"},
])
def test_invalid_time_never_falls_back_to_a_broader_window(period):
    with pytest.raises(ContractError):
        normalize(period=period)


def test_ninety_day_limit_and_dataset_boundaries_reject_without_clipping():
    period = {"preset": "custom", "from": "2026-01-01T00:00Z", "to": "2026-04-01T00:00Z", "timezone": "UTC"}
    assert normalize(period=period).period.start == datetime(2026, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(ContractError, match="period_too_wide"):
        normalize(period={**period, "to": "2026-04-01T00:00:00.000001Z"})
    allowed = normalizer.Period(datetime(2026, 10, 18, tzinfo=timezone.utc), NOW, "UTC")
    result = normalizer.normalize_request(request(), now=NOW, allowed_period=allowed)
    assert result.period.end == NOW
    with pytest.raises(ContractError, match="period_outside_scope"):
        normalizer.normalize_request(request(period={"preset": "7d", "timezone": "UTC"}), now=NOW, allowed_period=allowed)
    with pytest.raises(ContractError, match="period_outside_scope"):
        normalizer.normalize_request(request(), now=NOW.replace(hour=13), allowed_period=allowed)
    with pytest.raises(ContractError, match="invalid_period"):
        normalizer.normalize_request(request(), now=NOW.replace(tzinfo=None))


def test_same_field_values_are_or_other_fields_are_and_and_last_selection_wins():
    result = normalize([
        condition("server_id", "eq", 7), condition("server_id", "in", [8, 7]),
        condition("server_id", "not_in", [7, 9]), condition("server_id", "eq", 7),
        condition("channel", "eq", "Security"),
    ])
    assert result.as_request()["conditions"] == [
        condition("channel", "in", ["Security"]),
        condition("server_id", "in", [7, 8]), condition("server_id", "not_in", [9]),
    ]
    rows = [{"server_id": 7, "channel": "Security"}, {"server_id": 8, "channel": "Security"},
            {"server_id": 9, "channel": "Security"}, {"server_id": 7, "channel": "System"}]
    assert [normalizer.matches_conditions(result.conditions, row) for row in rows] == [True, True, False, False]
    assert normalize(result.as_request()["conditions"]) == result


@pytest.mark.parametrize("field,role,missing,present", [
    ("server_id", {}, {}, {"server_id": 11}),
    ("account", {"role": "target"}, {"accounts": ()}, {"accounts": (account(11),)}),
])
def test_not_in_keeps_null_until_exists_is_explicit(field, role, missing, present):
    result = normalize([condition(field, "not_in", [11], **role)])
    assert normalizer.matches_conditions(result.conditions, missing)
    assert normalizer.matches_conditions(result.conditions, {field: None} if field != "account" else {"accounts": None})
    assert not normalizer.matches_conditions(result.conditions, present)
    exists = normalize([condition(field, "not_in", [11], **role), condition(field, "exists", **role)])
    assert not normalizer.matches_conditions(exists.conditions, missing)
    unknown = normalize([condition(field, "missing", **role)])
    assert normalizer.matches_conditions(unknown.conditions, missing)
    assert not normalizer.matches_conditions(unknown.conditions, present)


def test_conflicting_presence_and_unknown_inputs_fail_closed():
    with pytest.raises(ContractError, match="invalid_condition"):
        normalize([condition("account", "exists", role="target"), condition("account", "missing", role="target")])
    with pytest.raises(ContractError, match="unsupported_field"):
        normalize([condition("unknown", "eq", 11)])
    with pytest.raises(ContractError, match="invalid_condition"):
        normalize([condition("account", "eq", "synthetic-display-name", role="any")])
    with pytest.raises(ContractError, match="event_context_required"):
        normalize([condition("event_id", "eq", 4625)])
    # Removing the last positive channel cannot leave an Event ID unqualified.
    with pytest.raises(ContractError, match="event_context_required"):
        normalize([condition("event_id", "eq", 4625), condition("channel", "eq", "Security"),
                   condition("channel", "not_in", ["Security"])])


@pytest.mark.parametrize("overrides,code", [
    ({"scope": {"kind": "all"}}, "invalid_request"),
    ({"contract_version": "evsearch.v2"}, "unsupported_version"),
    ({"page_size": 101}, "invalid_request"),
    ({"conditions": [condition("ip", "eq", "synthetic-invalid-ip")]}, "invalid_condition"),
    ({"conditions": [condition("channel", "contains", "Security")]}, "unsupported_operator"),
    ({"entry_context": {"kind": "entity", "entity_id": 11, "return_to": "https://example.invalid/"}}, "invalid_request"),
])
def test_normalizer_enforces_the_shared_wire_contract(overrides, code):
    with pytest.raises(ContractError) as error:
        normalizer.normalize_request(request(**overrides), now=NOW)
    assert error.value.code == f"evsearch.{code}"


def test_accounts_with_equal_display_names_remain_distinct_in_each_role():
    rows = [event(4625, accounts=(account(11), account(21, "actor")), display_name="synthetic-same-name"),
            event(4625, accounts=(account(12), account(11, "actor")), display_name="synthetic-same-name")]
    targets = normalize([condition("account", "eq", 11, role="target")])
    actors = normalize([condition("account", "eq", 11, role="actor")])
    assert [normalizer.matches_conditions(targets.conditions, row) for row in rows] == [True, False]
    assert [normalizer.matches_conditions(actors.conditions, row) for row in rows] == [False, True]
    both = normalize([condition("account", "eq", 11, role="target"), condition("account", "eq", 21, role="actor")])
    assert [normalizer.matches_conditions(both.conditions, row) for row in rows] == [True, False]


def test_any_role_exclusion_rejects_an_event_with_any_forbidden_participant():
    row = event(4625, accounts=(account(12), account(11), account(12), account(11, "actor")))
    excluded = normalize([condition("account", "not_in", [11], role="any")])
    assert not normalizer.matches_conditions(excluded.conditions, row)
    target_only = normalize([condition("account", "not_in", [21], role="target")])
    assert normalizer.matches_conditions(target_only.conditions, row)
    included = normalize([condition("account", "in", [12, 11], role="any")])
    assert normalizer.matches_conditions(included.conditions, row)


def test_null_account_projection_has_the_same_missing_semantics_as_no_participants():
    excluded = normalize([condition("account", "not_in", [11], role="any")])
    included = normalize([condition("account", "in", [11], role="any")])
    exists = normalize([condition("account", "exists", role="any")])
    row = {"accounts": None}
    assert normalizer.matches_conditions(excluded.conditions, row)
    assert not normalizer.matches_conditions(included.conditions, row)
    assert not normalizer.matches_conditions(exists.conditions, row)
    assert normalizer.matches_account_kind(normalize(exclude_machine_system=True), row)


def test_ip_values_are_canonicalized_without_mutating_the_wire_request():
    raw = request([condition("ip", "in", ["2001:db8::1", "2001:0db8:0:0:0:0:0:1"])])
    result = normalizer.normalize_request(raw, now=NOW)
    assert result.conditions[0].values == ("2001:db8::1",)
    assert len(raw["conditions"][0]["value"]) == 2
    assert normalizer.matches_conditions(result.conditions, {"ip": "2001:db8::1"})


@pytest.mark.parametrize("event_id,outcome,want", [
    (4625, None, True), (4740, "failure", False), (4624, "failure", False),
    (4771, None, True), (6273, None, True), (6272, "success", False),
    (4776, "failure", True), (4776, "success", False), (4776, None, False),
])
def test_failed_logons_excludes_lockouts_and_successful_credential_validation(event_id, outcome, want):
    question = normalize(question_id="failed_logons").question
    assert normalizer.matches_question(question, event(event_id, outcome=outcome)) is want


def test_question_event_ids_are_provider_and_channel_qualified():
    question = normalize(question_id="failed_logons").question
    assert not normalizer.matches_question(question, event(4625, provider="synthetic-other-provider"))
    assert not normalizer.matches_question(question, event(4625, channel="System"))
    assert not normalizer.matches_question(question, {"event_id": 4625})
    with pytest.raises(ContractError, match="unsupported_question"):
        normalize(question_id="synthetic-unknown-question")


def test_admin_questions_require_confirmed_target_privilege_and_new_effective_grant():
    admin = normalize(question_id="admin_logons").question
    assert not normalizer.matches_question(admin, event(4624, accounts=(account(11), account(21, "actor", privileged=True))))
    assert normalizer.matches_question(admin, event(4624, accounts=(account(11, privileged=True),)))
    assert not normalizer.matches_question(admin, event(4624, display_name="synthetic-admin-prefix"))
    new = normalize(question_id="new_admins").question
    assert not normalizer.matches_question(new, event(4728))
    assert not normalizer.matches_question(new, event(4728, privilege_grant_confirmed="true"))
    assert normalizer.matches_question(new, event(4732, privilege_grant_confirmed=True))
    assert not normalizer.matches_question(new, event(4729, privilege_grant_confirmed=True))
    assert {"account", "account_privileged"} <= admin.required_fields
    assert "privilege_grant_confirmed" in new.required_fields


@pytest.mark.parametrize("question_id,row,want", [
    ("lockouts", event(4740), True), ("lockouts", event(4625), False),
    ("group_changes", event(4728), True), ("group_changes", event(4729), True),
    ("group_changes", event(4720), False), ("log_cleared", event(1102), True),
    ("log_cleared", event(104, provider="Microsoft-Windows-Eventlog", channel="System"), True),
    ("log_cleared", event(104), False),
])
def test_other_general_questions_have_separate_predicates(question_id, row, want):
    assert normalizer.matches_question(normalize(question_id=question_id).question, row) is want


def test_changing_question_preserves_explicit_conditions_and_replaces_only_its_predicate():
    first = normalize([condition("server_id", "eq", 7)], question_id="failed_logons")
    second = normalize(first.as_request()["conditions"], question_id="lockouts")
    assert first.conditions == second.conditions
    assert not normalizer.matches_question(second.question, event(4625))
    assert normalizer.matches_question(second.question, event(4740))
    assert {"server_id", "event_id", "channel", "provider", "outcome"} <= first.required_fields
    assert "outcome" not in second.required_fields


@pytest.mark.parametrize("kind,want", [("human", True), ("service", True), ("unknown", True), ("machine", False), ("system", False)])
def test_account_kind_switch_uses_the_authentication_target_not_the_machine_actor(kind, want):
    search = normalize(question_id="failed_logons", exclude_machine_system=True)
    row = event(4625, accounts=(account(11, kind=kind), account(21, "actor", kind="machine")))
    assert normalizer.matches_account_kind(search, row) is want
    assert normalizer.matches_account_kind(search, event(4625))
    assert {"account", "account_kind"} <= search.required_fields


def test_entity_entry_keeps_all_accounts_by_default_and_uses_explicit_role_when_enabled():
    row = event(4625, accounts=(account(11, kind="human"), account(21, "actor", kind="machine")))
    context = {"kind": "entity", "entity_id": 11, "role": "target", "return_to": "/app/entities/11"}
    default = normalize(entry_context=context)
    assert normalizer.matches_account_kind(default, row)
    assert normalizer.matches_account_kind(normalize(entry_context=context, exclude_machine_system=True), row)
    assert not normalizer.matches_account_kind(normalize(exclude_machine_system=True), row)
    context["role"] = "actor"
    assert default.entry_context["role"] == "target"
    assert default.as_request()["entry_context"]["return_to"] == "/app/entities/11"


def test_legacy_eq_only_predicates_remain_valid_and_executable():
    result = normalize([condition("legacy_journal_view", "eq", "authentication")])
    assert result.as_request()["conditions"] == [condition("legacy_journal_view", "eq", "authentication")]
    assert normalizer.matches_conditions(result.conditions, {"legacy_journal_view": "authentication"})
    assert not normalizer.matches_conditions(result.conditions, {"legacy_journal_view": "accounts"})


def test_new_error_codes_have_both_server_translations():
    root = Path(__file__).resolve().parents[2]
    for language in ("ru", "en"):
        messages = json.loads((root / f"config/i18n/server.{language}.json").read_text(encoding="utf-8"))
        for code in (
            "invalid_request", "unsupported_version", "invalid_period", "invalid_condition",
            "unsupported_field", "unsupported_operator", "event_context_required",
            "unsupported_action", "policy_denied", "unsupported_question",
            "period_too_wide", "period_outside_scope",
        ):
            assert messages[f"evsearch.{code}"]
