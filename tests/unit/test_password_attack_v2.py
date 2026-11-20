"""Pure v2 contracts; native XML and IDs are synthetic fixture data only."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
import json

import pytest

from server.sli.storage.evidence_ref import EvidenceScope

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCOPE = EvidenceScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "fixture", "1")


def api():
    return importlib.import_module("server.sli.semantic.password_attack_v2")


def event(native_id, second, *, account="a", ip="203.0.113.1", status="0xc000006a",
          event_id=4625, host=None, extra="", scope=SCOPE, extra_fields=None):
    at = BASE + timedelta(seconds=second)
    fields = {"TargetUserName": account, "TargetDomainName": "fixture", "Status": status}
    if ip is not None:
        fields["IpAddress"] = ip
    if host is not None:
        fields["Workstation" if event_id == 4776 else "WorkstationName"] = host
    fields.update(extra_fields or {})
    data = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in fields.items())
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           f'<System><EventID>{event_id}</EventID><EventRecordID>{native_id}</EventRecordID>'
           f'<TimeCreated SystemTime="{at.isoformat()}"/><Computer>fixture-collector</Computer></System>'
           f'<EventData>{data}<Data Name="Padding">{extra}</Data></EventData></Event>')
    return api().NativeEvent.from_row(scope, {"source_event_id": native_id, "event_id": event_id,
        "occurred_at_utc": at, "sha256": f"{native_id:064x}", "source_xml": xml})


def run(events, *, kind="brute", state=None, second=200, history=(), retained=()):
    module = api()
    return module.advance(module.Rule(SCOPE, kind), state or module.State(), tuple(events),
        now=BASE + timedelta(seconds=second), history=tuple(history), retained=tuple(retained))


def test_rolling_brute_ten_and_source_isolation():
    rows = [event(i + 1, i * 60) for i in range(10)]
    assert not run(rows[:9], second=800).emissions
    result = run(rows, second=660)
    assert len(result.emissions) == 1
    assert result.emissions[0].known_bad_password == 10
    mixed = [event(i + 1, i, ip=f"203.0.113.{1 + i % 2}") for i in range(10)]
    assert not run(mixed).emissions


@pytest.mark.parametrize("span,expected", [(600, 1), (601, 0)])
def test_rolling_window_includes_exact_six_hundred(span, expected):
    rows = [event(i + 1, 0 if i < 9 else span) for i in range(10)]
    assert len(run(rows, second=span + 120).emissions) == expected


def test_spray_five_names_needs_only_five_attempts_and_keeps_classes():
    rows = [event(i + 1, i, account=f"attempted-{i}", status="0xc0000064" if i < 2 else "0xc000006a")
            for i in range(5)]
    assert not run(rows[:4], kind="spray").emissions
    emission, = run(rows, kind="spray").emissions
    assert (emission.known_bad_password, emission.unknown_account) == (3, 2)
    assert emission.distinct_names == 5
    document = json.dumps(emission.document)
    assert "attempted-" not in document and "203.0.113" not in document


@pytest.mark.parametrize("ip", [None, "-", "not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.1"])
def test_missing_client_is_coverage_not_collector_fallback(ip):
    proposal = run([event(i + 1, i, ip=ip) for i in range(10)])
    assert not proposal.emissions
    assert dict(proposal.diagnostics)["missing_client"] == 10


def test_native_workstation_fallback_is_brute_only():
    rows = [event(i + 1, i, ip=None, event_id=4776, host="fixture-client") for i in range(10)]
    assert len(run(rows).emissions) == 1
    assert not run(rows, kind="spray").emissions
    fields = [event(i + 1, i, ip=None) for i in range(10)]
    assert not run(fields).emissions


def test_mapped_ip_and_client_ip_have_one_entity_but_two_hosts_do_not():
    rows = [event(i + 1, i, ip="::ffff:203.0.113.1" if i < 5 else "203.0.113.1") for i in range(10)]
    assert len(run(rows).emissions) == 1
    hosts = [event(i + 1, i, ip=None, host=f"fixture-{i % 2}") for i in range(10)]
    assert not run(hosts).emissions


@pytest.mark.parametrize("status,category", [("0xc0000064", "unknown_account"),
    ("0xc000006a", "known_bad_password"), ("0xc0000234", "other_failure")])
def test_failure_classes_remain_distinct(status, category):
    emission, = run([event(i + 1, i, status=status) for i in range(10)]).emissions
    assert getattr(emission, category) == 10


def test_success_and_malformed_required_status_do_not_count():
    assert not run([event(i + 1, i, status="0x0", event_id=4776) for i in range(10)]).emissions
    assert not run([event(i + 1, i, status="bad-status", event_id=4776) for i in range(10)]).emissions


def test_kerberos_and_generic_status_refinement_and_conflicts():
    kerberos, = run([event(i + 1, i, status="0x18", event_id=4771) for i in range(10)]).emissions
    assert kerberos.known_bad_password == 10
    unknown, = run([event(i + 1, i, status="0x6", event_id=4771) for i in range(10)]).emissions
    assert unknown.unknown_account == 10
    refined, = run([event(i + 1, i, status="0xc000006d", extra_fields={"SubStatus": "0xc0000064"})
                    for i in range(10)]).emissions
    assert refined.unknown_account == 10
    assert not run([event(i + 1, i, extra_fields={"SubStatus": "0xc0000064"}) for i in range(10)]).emissions
    assert not run([event(i + 1, i, extra_fields={"ClientAddress": "203.0.113.2"}) for i in range(10)]).emissions


def test_holdback_pending_late_replay_and_steady_late_stream():
    rows = [event(i + 1, i) for i in range(10)]
    pending = run(rows, second=100)
    assert not pending.emissions and pending.state.watermark == BASE - timedelta(seconds=20)
    ready = run(rows, state=pending.state, second=200)
    assert len(ready.emissions) == 1
    replay = run(rows, state=ready.state, second=201, history=ready.emissions, retained=rows)
    assert not replay.emissions
    late = run([event(99, 50)], state=ready.state, second=202, history=ready.emissions, retained=rows)
    assert not late.emissions and dict(late.diagnostics)["too_late"] == 1
    # Poll cadence10s with continuous180s ingestion delay loses every new event.
    state = run([], second=200).state
    for second in range(210, 310, 10):
        lost = run([event(second, second - 180)], state=state, second=second)
        assert not lost.emissions and dict(lost.diagnostics)["too_late"] == 1
        state = lost.state


def test_horizon_gap_and_clock_regression_are_explicit():
    first = run([], second=200)
    gap = run([], state=first.state, second=1000)
    assert gap.state.epoch == first.state.epoch + 1
    assert dict(gap.diagnostics)["coverage_gap"] == 1
    regressed = run([], state=gap.state, second=999)
    assert regressed.state == gap.state
    assert dict(regressed.diagnostics)["clock_regression"] == 1


def test_restart_native_chain_every_five_hundred_ninety_seconds():
    module = api()
    rows = [event(i + 1, i) for i in range(10)]
    proposal = run(rows)
    chain = list(proposal.emissions)
    state = module.State.from_document(json.loads(json.dumps(proposal.state.document)))
    key = chain[0].episode_key
    for index in range(1, 8):
        second = 9 + 590 * index
        new = event(100 + index, second)
        rows.append(new)
        proposal = run([new], state=state, second=second + 120, history=chain, retained=rows)
        emission, = proposal.emissions
        assert emission.episode_key == key and emission.predecessor.ref == chain[-1].endpoint.ref
        chain.append(emission)
        module.verify_chain(module.Rule(SCOPE, "brute"), tuple(chain), tuple(rows))
        state = module.State.from_document(json.loads(json.dumps(proposal.state.document)))
    assert chain[-1].sequence == 8
    assert state.episodes[0].budget.ref_occurrences == 10 + 2 * 7
    with pytest.raises(ValueError, match="native_unavailable"):
        module.verify_chain(module.Rule(SCOPE, "brute"), tuple(chain), tuple(row for row in rows if row.ref.native_id != "103"))
    broken = replace(chain[-1], predecessor=chain[0].endpoint)
    with pytest.raises(ValueError, match="continuity"):
        module.verify_chain(module.Rule(SCOPE, "brute"), tuple(chain[:-1] + [broken]), tuple(rows))


def test_a_real_gap_creates_a_different_episode_with_native_gap_proof():
    rows = [event(i + 1, i) for i in range(10)]
    first = run(rows)
    second_rows = [event(100 + i, 610 + i) for i in range(10)]
    second = run(second_rows, state=first.state, second=740, history=first.emissions, retained=rows)
    assert second.emissions[0].episode_key != first.emissions[0].episode_key


def test_native_hash_conflict_and_cross_scope_block_the_whole_proposal():
    rows = [event(i + 1, i) for i in range(10)]
    pending = run(rows, second=100)
    original = pending.state.document
    with pytest.raises(ValueError, match="conflict"):
        run([event(1, 0, account="changed")], state=pending.state)
    wrong = replace(SCOPE, source_generation="other")
    with pytest.raises(ValueError, match="scope"):
        run([event(99, 0, scope=wrong)], state=pending.state)
    assert pending.state.document == original


@pytest.mark.parametrize("field,limit", [("ref_occurrences", 10000), ("portions", 256), ("xml_bytes", 33554432)])
def test_exact_budget_and_one_over_fail_atomically(field, limit):
    module = api()
    budget = replace(module.Budget(), **{field: limit - 1})
    delta = {"ref_occurrences": 0, "portions": 0, "xml_bytes": 0}
    delta[field] = 1
    full = budget.reserve(**delta)
    assert getattr(full, field) == limit
    with pytest.raises(ValueError, match="budget_exhausted"):
        full.reserve(**delta)
    assert getattr(budget, field) == limit - 1


def test_exhaustion_freezes_same_episode_and_does_not_admit_a_portion():
    module = api()
    rows = [event(i + 1, i) for i in range(10)]
    first = run(rows)
    episode = first.state.episodes[0]
    chain = list(first.emissions)
    for index in range(1, 256):
        native = event(100 + index, 9 + 590 * index)
        rows.append(native)
        previous = chain[-1]
        chain.append(replace(previous, sequence=index + 1, root_proof=(),
            new_events=(native.member.witness,), predecessor=previous.endpoint,
            previous_id=previous.emission_id, known_bad_password=1, unknown_account=0,
            other_failure=0, distinct_names=1, origin=()))
    budget = module.verify_chain(module.Rule(SCOPE, "brute"), tuple(chain), rows)
    assert budget.portions == 256 and budget.ref_occurrences == 520
    full = replace(episode, budget=budget, sequence=256, last=chain[-1].endpoint,
                   last_emission=chain[-1].emission_id)
    state = replace(first.state, episodes=(full,), window=(rows[-1].member,), watermark=rows[-1].at)
    second = 9 + 590 * 256
    new = event(1000, second)
    result = run([new], state=state, second=second + 120, history=chain, retained=rows)
    assert not result.emissions
    frozen = result.state.episodes[0]
    assert frozen.key == episode.key and frozen.frozen
    assert frozen.budget == full.budget
    assert dict(result.diagnostics)["episode_evidence_budget_exhausted"] == 1
    last = event(1001, second + 590)
    again = run([last], state=result.state, second=second + 710,
        history=chain, retained=rows + [new])
    assert not again.emissions and again.state.episodes[0].key == episode.key
    idle = run([], state=again.state, second=second + 1090).state
    new_episode_rows = [event(2000 + i, second + 1191 + i) for i in range(10)]
    resumed = run(new_episode_rows, state=idle, second=second + 1320,
                  history=chain, retained=rows + [new, last])
    assert not resumed.state.episodes[0].frozen
    assert resumed.state.epoch == again.state.epoch
    assert resumed.emissions[0].episode_key != episode.key


def test_occurrences_include_repeated_endpoints_and_portions_are_bounded():
    module = api()
    rows = [event(i + 1, i / 10) for i in range(300)]
    result = run(rows)
    emission, = result.emissions
    assert len(emission.occurrences) == 300 and emission.portions == 2
    assert [len(portion) for portion in emission.ref_portions] == [256, 44]
    assert result.state.episodes[0].budget.xml_bytes == sum(w.xml_bytes for w in emission.occurrences)
    module.verify_chain(module.Rule(SCOPE, "brute"), result.emissions, rows)


def test_pin_contains_versions_bounds_and_state_rejects_other_rule():
    module = api()
    brute, spray = module.Rule(SCOPE, "brute"), module.Rule(SCOPE, "spray")
    assert brute.execution["rule_version"] == 2
    assert brute.execution["version"] == "sli.qw.execution.v1"
    assert brute.execution != spray.execution
    state = run([], second=200).state
    with pytest.raises(ValueError, match="state_scope"):
        run([], kind="spray", state=state, second=201)


def test_equal_timestamp_members_are_counted_once_and_proof_order_is_enforced():
    module = api()
    rows = [event(i + 1, 0) for i in range(10)]
    result = run(rows)
    emission, = result.emissions
    assert len(emission.occurrences) == 10
    with pytest.raises(ValueError, match="continuity"):
        module.verify_chain(module.Rule(SCOPE, "brute"),
            (replace(emission, root_proof=tuple(reversed(emission.root_proof))),), rows)


def test_changed_native_xml_and_duplicate_retained_identity_cannot_hide_conflict():
    module = api()
    rows = [event(i + 1, i) for i in range(10)]
    first = run(rows)
    changed = event(1, 0, account="different")
    with pytest.raises(ValueError, match="conflict"):
        module.verify_chain(module.Rule(SCOPE, "brute"), first.emissions, (changed, *rows))
    with pytest.raises(ValueError, match="conflict"):
        module.verify_chain(module.Rule(SCOPE, "brute"), first.emissions, (changed, *rows[1:]))


def test_reader_limits_are_actual_bytes_and_preserve_original_state():
    module = api()
    empty = run([], second=200).state
    sentinel = run([event(i + 1, 100) for i in range(10001)], state=empty)
    assert sentinel.state is empty and not sentinel.emissions
    assert dict(sentinel.diagnostics)["reader_bound"] == 1
    row = event(1, 100)
    forged = replace(row, source_xml=row.source_xml + " " * module.MAX_XML_BYTES)
    bounded = run([forged], state=empty)
    assert bounded.state is empty and dict(bounded.diagnostics)["reader_bound"] == 1


def test_real_native_xml_budget_freezes_without_partial_emission_or_state_mutation():
    rows = [event(i + 1, i, extra="x" * (3 * 1024 * 1024)) for i in range(10)]
    first = run(rows)
    old_document = first.state.document
    native = event(100, 599)
    frozen = run([native], state=first.state, second=719,
                 history=first.emissions, retained=rows)
    assert not frozen.emissions
    assert frozen.state.episodes[0].frozen
    assert frozen.state.episodes[0].key == first.emissions[0].episode_key
    assert frozen.state.episodes[0].budget == first.state.episodes[0].budget
    assert first.state.document == old_document


def prequalification_prefix():
    rows, state = [], None
    for index, second in enumerate((0, 590, 1180, 1770), 1):
        native = event(index, second)
        proposal = run([native], state=state, second=second + 120, retained=rows)
        assert not proposal.emissions
        rows.append(native)
        state = proposal.state
    return rows, state


def test_official_producer_root_contains_complete_native_prequalification_origin():
    module = api()
    rows, state = prequalification_prefix()
    final = [event(100 + index, 1771 + index) for index in range(9)]
    proposal = run(final, state=state, second=1899, retained=rows)
    emission, = proposal.emissions
    assert [int((w.at - BASE).total_seconds()) for w in emission.occurrences] == [
        0, 590, 1180, *range(1770, 1780)]
    assert module.verify_chain(module.Rule(SCOPE, "brute"), (emission,), rows + final).ref_occurrences == 13
    with pytest.raises(ValueError, match="native_unavailable"):
        module.verify_chain(module.Rule(SCOPE, "brute"), (emission,), rows[:1] + rows[2:] + final)


def test_official_producer_missing_prequalification_bridge_fails_closed_without_rename():
    rows, state = prequalification_prefix()
    final = [event(100 + index, 1771 + index) for index in range(9)]
    result = run(final, state=state, second=1899, retained=rows[:1] + rows[2:])
    assert not result.emissions
    assert dict(result.diagnostics)["prequalification_native_unavailable"] == 1
    assert result.state is state
    assert result.state.episodes[0].key == state.episodes[0].key


def test_official_future_seed_cannot_rename_an_existing_qualifying_proof():
    module = api()
    rows = [event(i + 1, i) for i in range(10)]
    root, = run(rows).emissions
    future = event(99, 3600)
    rule = module.Rule(SCOPE, "brute")
    forged = replace(root, seed=future.member.witness,
        episode_key=module._digest([rule.pin, root.epoch, root.entity, future.ref.params]))
    with pytest.raises(ValueError, match="continuity"):
        module.verify_chain(rule, (forged,), rows + [future])


def test_official_continuation_requires_a_new_native_endpoint():
    module = api()
    rows = [event(i + 1, i) for i in range(10)]
    root, = run(rows).emissions
    empty = replace(root, sequence=2, root_proof=(), new_events=(),
        predecessor=root.endpoint, previous_id=root.emission_id,
        known_bad_password=0, unknown_account=0, other_failure=0, distinct_names=0)
    with pytest.raises(ValueError, match="continuity"):
        module.verify_chain(module.Rule(SCOPE, "brute"), (root, empty), rows)


@pytest.mark.parametrize("event_id,status,extra_fields", [
    (4625, "0xc0000234", {"SubStatus": "0xc000006a"}),
    (4625, "0xc000006a", {"ResultCode": "0x0"}),
    (4776, "0xc000006a", {"ResultCode": "0x0"}),
    (4771, "0x18", {"ResultCode": "0x0"}),
    (4771, "0x18", {"FailureCode": "0x0"}),
])
def test_official_contradictory_family_statuses_are_diagnostic(event_id, status, extra_fields):
    result = run([event(i + 1, i, event_id=event_id, status=status, extra_fields=extra_fields)
                  for i in range(10)])
    assert not result.emissions
    assert dict(result.diagnostics)["ambiguous_failure"] == 10


@pytest.mark.parametrize("status,category", [("0xc000006a", "known_bad_password"),
    ("0xc0000064", "unknown_account"), ("0xc000006d", "other_failure"), ("0xc0000234", "other_failure")])
def test_official_zero_substatus_is_a_normal_sentinel(status, category):
    emission, = run([event(i + 1, i, status=status, extra_fields={"SubStatus": "0x0"})
                     for i in range(10)]).emissions
    assert getattr(emission, category) == 10


def test_prequalification_cannot_resume_from_cached_last_seen_without_native_origin():
    module = api()
    rows, state = prequalification_prefix()
    document = state.document
    for episode in document["episodes"]:
        episode.pop("prequalification")
    legacy = module.State.from_document(json.loads(json.dumps(document)))
    result = run([event(100 + i, 1771 + i) for i in range(9)],
                 state=legacy, second=1899, retained=rows)
    assert not result.emissions
    assert result.state is legacy
    assert dict(result.diagnostics)["prequalification_native_unavailable"] == 1
    assert result.state.episodes[0].key == state.episodes[0].key


def test_prequalification_native_origin_survives_serialization_and_detects_changed_bridge():
    module = api()
    rows, state = prequalification_prefix()
    restored = module.State.from_document(json.loads(json.dumps(state.document)))
    assert restored == state
    changed = event(2, 590, account="different")
    with pytest.raises(ValueError, match="continuity_native_conflict"):
        run([event(100 + i, 1771 + i) for i in range(9)], state=restored, second=1899,
            retained=[rows[0], changed, *rows[2:]])


def test_prequalification_xml_budget_exhaustion_does_not_rename_or_publish():
    rows = [event(i + 1, i, account="same-name", extra="x" * (3 * 1024 * 1024)) for i in range(10)]
    first = run(rows, kind="spray")
    assert not first.emissions
    original = first.state.document
    next_native = event(100, 599, account="same-name", extra="x" * (3 * 1024 * 1024))
    exhausted = run([next_native], kind="spray", state=first.state, second=719, retained=rows)
    assert not exhausted.emissions
    assert exhausted.state.episodes[0].frozen
    assert exhausted.state.episodes[0].key == first.state.episodes[0].key
    assert exhausted.state.episodes[0].budget == first.state.episodes[0].budget
    assert dict(exhausted.diagnostics)["prequalification_proof_budget_exhausted"] == 1
    assert first.state.document == original


def test_origin_cannot_be_renamed_through_an_unrelated_native_gap_endpoint():
    rows, state = prequalification_prefix()
    unrelated = event(999, 0, account="another-name")
    forged = replace(state, episodes=(replace(state.episodes[0], last=unrelated.member.witness),))
    with pytest.raises(ValueError, match="continuity"):
        run([event(100 + i, 1771 + i) for i in range(10)], state=forged, second=1900,
            retained=rows + [unrelated])


def test_missing_real_gap_native_endpoint_does_not_rename_the_episode():
    rows = [event(i + 1, i) for i in range(10)]
    first = run(rows)
    result = run([event(100 + i, 610 + i) for i in range(10)], state=first.state,
                 second=740, history=first.emissions, retained=rows[:-1])
    assert not result.emissions
    assert result.state is first.state
    assert dict(result.diagnostics)["gap_native_unavailable"] == 1
