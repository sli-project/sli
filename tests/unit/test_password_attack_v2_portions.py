"""Transport-only tests using actual pure emissions and synthetic native fixtures."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib
import json

import pytest

from server.sli.semantic import password_attack_v2 as pure
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
SCOPE = EvidenceScope("00000000-0000-0000-0000-000000000001", "sli.windows.ad-dc", "fixture", "1")


def codec():
    try:
        return importlib.import_module("server.sli.semantic.password_attack_v2_portions")
    except ModuleNotFoundError as error:
        if error.name == "server.sli.semantic.password_attack_v2_portions":
            pytest.fail("Password v2 compact portion codec is not implemented")
        raise


def event(native_id, *, at=None, scope=SCOPE):
    at = at or BASE + timedelta(microseconds=native_id)
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
           f'<System><EventID>4625</EventID><EventRecordID>{native_id}</EventRecordID>'
           f'<TimeCreated SystemTime="{at.isoformat()}"/></System><EventData>'
           '<Data Name="TargetUserName">synthetic</Data><Data Name="TargetDomainName">fixture</Data>'
           '<Data Name="Status">0xc000006a</Data><Data Name="IpAddress">203.0.113.1</Data>'
           '</EventData></Event>')
    return pure.NativeEvent.from_row(scope, {"source_event_id": native_id, "event_id": 4625,
        "occurred_at_utc": at, "sha256": f"{native_id:064x}", "source_xml": xml})


def root(count=300, scope=SCOPE):
    rows = tuple(event(index + 1, scope=scope) for index in range(count))
    proposal = pure.advance(pure.Rule(scope, "brute"), pure.State(), rows,
                            now=BASE + timedelta(seconds=200))
    emission, = proposal.emissions
    return emission, proposal.state, rows


@pytest.fixture(scope="module")
def ordinary():
    return root()


@pytest.fixture(scope="module")
def largest():
    # Extend a real pure emission: the producer state byte cap is a separate gate.
    emission = root()[0]
    extra = tuple(event(index).member.witness for index in range(301, 10001))
    return replace(emission, new_events=emission.new_events + extra)


def test_actual_emission_roundtrip_preserves_every_field_and_exact_pure_slices(ordinary):
    emission, _, _ = ordinary
    before = deepcopy(emission.document)
    api = codec()
    contexts = api.contexts_from_emission(emission)
    assert type(contexts) is tuple and len(contexts) == 2
    assert [len(context["occurrences"]) for context in contexts] == [256, 44]
    assert [context["occurrence_from"] for context in contexts] == [0, 256]
    assert [context["portion_index"] for context in contexts] == [0, 1]
    assert all(context["root_id"] == emission.emission_id for context in contexts)
    wire = tuple(json.loads(json.dumps(context)) for context in contexts)
    rebuilt = api.reassemble(SCOPE, wire)
    assert rebuilt == emission and rebuilt.document == before
    assert rebuilt.emission_id == emission.emission_id
    assert emission.document == before


def test_actual_prequalification_origin_and_qualifying_suffix_are_not_flattened():
    rows, state = [], pure.State()
    rule = pure.Rule(SCOPE, "brute")
    for index, second in enumerate((0, 590, 1180, 1770), 1):
        item = event(index, at=BASE + timedelta(seconds=second))
        proposal = pure.advance(rule, state, (item,), now=item.at + timedelta(seconds=120), retained=tuple(rows))
        assert not proposal.emissions
        rows.append(item)
        state = proposal.state
    final = tuple(event(100 + i, at=BASE + timedelta(seconds=1771 + i)) for i in range(9))
    emission, = pure.advance(rule, state, final, now=BASE + timedelta(seconds=1899), retained=tuple(rows)).emissions
    api = codec()
    context, = api.contexts_from_emission(emission)
    assert (context["origin_count"], context["root_from"], context["root_count"], context["new_from"]) == (12, 2, 10, 12)
    assert api.reassemble(SCOPE, (context,)) == emission


def test_actual_continuation_requires_explicit_original_root_id(ordinary):
    first, state, rows = ordinary
    new = event(999, at=BASE + timedelta(seconds=590))
    continuation, = pure.advance(pure.Rule(SCOPE, "brute"), state, (new,),
        now=BASE + timedelta(seconds=710), history=(first,), retained=rows).emissions
    api = codec()
    with pytest.raises(ValueError):
        api.contexts_from_emission(continuation)
    for bad in ("", "A" * 64, first.emission_id[:-1], True):
        with pytest.raises(ValueError):
            api.contexts_from_emission(continuation, original_root_id=bad)
    context, = api.contexts_from_emission(continuation, original_root_id=first.emission_id)
    assert context["root_id"] == first.emission_id
    assert context["previous_id"] == first.emission_id
    assert (context["origin_count"], context["root_count"], context["new_from"], context["new_count"]) == (0, 0, 1, 1)
    assert api.reassemble(SCOPE, (context,)) == continuation


def test_qw_ref_set_permutation_preserves_native_witness_order(ordinary):
    emission, _, _ = ordinary
    api = codec()
    context = api.contexts_from_emission(emission)[0]
    witnesses = emission.ref_portions[0]
    shuffled = tuple(w.ref for w in reversed(witnesses))
    assert api.match_qw_refs(SCOPE, context, shuffled) == witnesses
    for bad in (shuffled[:-1], shuffled[:-1] + shuffled[:1], list(shuffled)):
        with pytest.raises(ValueError):
            api.match_qw_refs(SCOPE, context, bad)
    foreign = replace(SCOPE, source_generation="foreign")
    refs = (EvidenceRef("core_event", witnesses[0].ref.native_id, witnesses[0].ref.sha256, foreign),) + shuffled[1:]
    with pytest.raises(ValueError):
        api.match_qw_refs(SCOPE, context, refs)


@pytest.mark.parametrize("field,value", [("installation_id", "00000000-0000-0000-0000-000000000002"),
    ("source_instance_id", "other"), ("source_generation", "other"), ("plugin_id", "sli.vpn-nps"),
    ("collection_scope_id", "other")])
def test_reassembly_binds_all_scope_dimensions(ordinary, field, value):
    emission, _, _ = ordinary
    api = codec()
    contexts = api.contexts_from_emission(emission)
    with pytest.raises(ValueError):
        api.reassemble(replace(SCOPE, **{field: value}), contexts)


@pytest.mark.parametrize("change", ["missing", "duplicate", "reverse", "foreign", "header", "ordinal", "tuple_order"])
def test_incomplete_or_mixed_portions_reject_whole_proposal_without_mutation(ordinary, change):
    emission, _, _ = ordinary
    api = codec()
    contexts = api.contexts_from_emission(emission)
    damaged = deepcopy(contexts)
    if change == "missing":
        damaged = damaged[:-1]
    elif change == "duplicate":
        damaged = (damaged[0], damaged[0])
    elif change == "reverse":
        damaged = damaged[::-1]
    elif change == "foreign":
        other, _, _ = root(300, replace(SCOPE, source_generation="foreign"))
        damaged = (damaged[0], api.contexts_from_emission(other)[1])
    elif change == "header":
        damaged[1]["known_bad_password"] += 1
    elif change == "ordinal":
        damaged[1]["occurrence_from"] -= 1
    else:
        damaged[0]["occurrences"][0], damaged[0]["occurrences"][1] = damaged[0]["occurrences"][1], damaged[0]["occurrences"][0]
    before = deepcopy(damaged)
    with pytest.raises(ValueError):
        api.reassemble(SCOPE, damaged)
    assert damaged == before


@pytest.mark.parametrize("index,value", [(0, "01"), (1, "A" * 64), (2, "z_equivalent"),
    (2, "offset_equivalent"), (3, True), (3, "float_equivalent"), (4, "f" * 63)])
def test_compact_tuple_types_hashes_and_canonical_utc_are_strict(ordinary, index, value):
    emission, _, _ = ordinary
    api = codec()
    damaged = deepcopy(api.contexts_from_emission(emission))
    if value == "z_equivalent":
        value = damaged[0]["occurrences"][0][2].replace("+00:00", "Z")
    elif value == "offset_equivalent":
        stamp = datetime.fromisoformat(damaged[0]["occurrences"][0][2])
        value = stamp.astimezone(timezone(timedelta(hours=1))).isoformat()
    elif value == "float_equivalent":
        value = float(damaged[0]["occurrences"][0][3])
    damaged[0]["occurrences"][0][index] = value
    with pytest.raises(ValueError):
        api.reassemble(SCOPE, damaged)


def test_context_exact_shape_rejects_unknown_keys_and_python_tuple_rows(ordinary):
    emission, _, _ = ordinary
    api = codec()
    contexts = api.contexts_from_emission(emission)
    for name in ("extra", "row_tuple", "row_short", "bool_ordinal", "false_hash"):
        damaged = deepcopy(contexts)
        if name == "extra":
            damaged[0]["unrecognized"] = "x"
        elif name == "row_tuple":
            damaged[0]["occurrences"][0] = tuple(damaged[0]["occurrences"][0])
        elif name == "row_short":
            damaged[0]["occurrences"][0].pop()
        elif name == "bool_ordinal":
            damaged[0]["portion_index"] = False
        else:
            for context in damaged:
                context["emission_id"] = "f" * 64
                context["root_id"] = "f" * 64
        with pytest.raises(ValueError):
            api.reassemble(SCOPE, damaged)


def test_encoder_rejects_non_tuple_emission_roles_without_mutation(ordinary):
    emission, _, _ = ordinary
    api = codec()
    for field in ("origin", "root_proof", "new_events"):
        bad = replace(emission, **{field: list(getattr(emission, field))})
        before = deepcopy(bad.document)
        with pytest.raises(ValueError):
            api.contexts_from_emission(bad)
        assert bad.document == before


@pytest.mark.parametrize("count,sizes", [(256, [256]), (257, [256, 1])])
def test_portion_boundary_preserves_existing_pure_cost(count, sizes):
    emission, _, _ = root(count)
    api = codec()
    contexts = api.contexts_from_emission(emission)
    assert [len(context["occurrences"]) for context in contexts] == sizes
    assert api.reassemble(SCOPE, contexts) == emission


def test_ten_thousand_occurrences_pass_and_ten_thousand_one_rejects_whole_emission(largest):
    api = codec()
    contexts = api.contexts_from_emission(largest)
    assert len(contexts) == 40 and len(contexts[-1]["occurrences"]) == 16
    assert api.reassemble(SCOPE, contexts) == largest
    extra = event(10001).member.witness
    over = replace(largest, new_events=largest.new_events + (extra,))
    before = deepcopy(over.document)
    with pytest.raises(ValueError):
        api.contexts_from_emission(over)
    assert over.document == before


def test_portion_collection_and_declared_total_are_bounded(ordinary):
    emission, _, _ = ordinary
    api = codec()
    contexts = api.contexts_from_emission(emission)
    with pytest.raises(ValueError):
        api.reassemble(SCOPE, (contexts[0],) * 257)
    damaged = deepcopy(contexts)
    for context in damaged:
        context["portion_total"] = 257
    with pytest.raises(ValueError):
        api.reassemble(SCOPE, damaged)


def test_max_unicode_scope_uses_compact_ascii_canonical_contexts_and_unchanged_hash():
    scope = replace(SCOPE, source_instance_id="я😀" * 128, source_generation="世😀" * 256)
    emission, _, _ = root(257, scope)
    api = codec()
    contexts = api.contexts_from_emission(emission)
    sizes = [len(json.dumps(context, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("utf-8")) for context in contexts]
    assert max(sizes) <= 65536
    rebuilt = api.reassemble(scope, tuple(json.loads(json.dumps(context)) for context in contexts))
    assert rebuilt.document == emission.document and rebuilt.emission_id == emission.emission_id


def test_context_byte_cap_rejects_whole_proposal_without_rechunk_or_mutation(ordinary):
    emission, _, _ = ordinary
    # Declared positive integer metadata is not native XML measurement. Large
    # metadata makes a correctly hashed transport proposal exceed the byte cap.
    expanded = {w: replace(w, xml_bytes=10 ** 300) for w in emission.occurrences}
    over = replace(emission, seed=expanded[emission.seed],
        origin=tuple(expanded[w] for w in emission.origin),
        root_proof=tuple(expanded[w] for w in emission.root_proof),
        new_events=tuple(expanded[w] for w in emission.new_events))
    before = deepcopy(over.document)
    with pytest.raises(ValueError):
        codec().contexts_from_emission(over)
    assert over.document == before


def test_root_role_integrity_is_checked_even_with_self_consistent_emission_hash(ordinary):
    emission, _, _ = ordinary
    api = codec()
    for bad in (replace(emission, seed=emission.origin[1]),
                replace(emission, root_proof=emission.root_proof[:-1]),
                replace(emission, predecessor=emission.origin[0]),
                replace(emission, previous_id="f" * 64)):
        with pytest.raises(ValueError):
            api.contexts_from_emission(bad)