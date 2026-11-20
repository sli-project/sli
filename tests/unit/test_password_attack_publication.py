"""Password v2 publication with actual pure emissions/XML and bounded fake SQL storage.

These are unit tests. The cursor represents SQL API rows, not a PG authority proof.
"""
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
import importlib
import json

import pytest

from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic import password_attack_v2_portions as codec
from server.sli.semantic import qw_input as qw
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from tests.unit.test_password_attack_v2_portions import BASE, SCOPE, event, root
from tests.unit.test_qw_publication import Cursor as PublicationCursor
from tests.unit.test_qw_semantic_input import policy


def signals_for(emission, *, root_id=None):
    scope = emission.seed.ref.scope
    rule = pure.Rule(scope, "brute" if emission.pin == pure.Rule(scope, "brute").pin else "spray")
    contexts = codec.contexts_from_emission(emission, original_root_id=root_id)
    return tuple(qw.QWSignal(kind="threshold", rule_id=rule.execution["rule_id"], rule_version=2,
        rule_sha256=rule.execution["rule_sha256"], policy_revision=1, evaluation_mode="enabled",
        entity_key=emission.entity, episode_key=emission.episode_key, occurred_at_utc=emission.endpoint.at,
        base_severity="high", effective_severity="high",
        received_at_utc=BASE, evidence_refs=tuple(w.ref for w in portion),
        evidence_total=len(emission.occurrences), password_context=context)
        for context, portion in zip(contexts, emission.ref_portions))


def adapter():
    return importlib.import_module("server.sli.semantic.password_attack_runtime")


@pytest.fixture(autouse=True)
def no_live_database(monkeypatch):
    from server.sli.core import database, postgres_runtime_pipeline
    def forbidden(*args, **kwargs):
        pytest.fail("unexpected live database connection")
    monkeypatch.setattr(database, "query_rows", forbidden)
    monkeypatch.setattr(postgres_runtime_pipeline, "connect", forbidden)
    monkeypatch.setattr(runtime, "record_scenario_identity_supersessions", lambda *a, **kw: None)
    monkeypatch.setattr(runtime, "record_finding_identity_supersessions", lambda *a, **kw: None)


def test_password_signal_uses_frozen_context_and_arrival_independent_identity():
    emission, _, _ = root(10)
    signal, = signals_for(emission)
    assert signal.password_context["emission_id"] == emission.emission_id
    assert signal.execution == pure.Rule(SCOPE, "brute").execution
    assert replace(signal, received_at_utc=BASE + timedelta(days=1)).signal_id == signal.signal_id
    assert "password_context" in signal.document


@pytest.mark.parametrize("change", ["missing", "foreign_rule", "v1", "float_version", "wrong_pin", "mixed", "refs", "ordinal"])
def test_exclusive_builtin_password_dispatch_rejects_invalid_transport(change):
    emission, _, _ = root(10)
    signal, = signals_for(emission)
    if change == "missing": values = {"password_context": None}
    elif change == "foreign_rule": values = {"rule_id": "qw.fixture"}
    elif change == "v1": values = {"rule_version": 1}
    elif change == "float_version": values = {"rule_version": 2.0}
    elif change == "wrong_pin": values = {"rule_sha256": "f" * 64}
    elif change == "mixed": values = {"watch_context": {}}
    elif change == "refs": values = {"evidence_refs": signal.evidence_refs[:-1]}
    else:
        context = deepcopy(signal.password_context)
        context["portion_index"] = True
        values = {"password_context": context}
    with pytest.raises(ValueError):
        replace(signal, **values)


class Cursor(PublicationCursor):
    def __init__(self, emissions, natives):
        self.emissions = emissions
        self.password_signals = tuple(s for emission in emissions for s in signals_for(emission,
            root_id=emissions[0].emission_id if emission.sequence > 1 else None))
        super().__init__(self.password_signals[0])
        self.policies = [(policy(self.password_signals[0], scenario_kind=self.password_signals[0].rule_id), "enabled")]
        self.native = {item.ref.native_id: item for item in natives}
        self.native_passes = 0
        self.barrier_asserts = []
        self.frozen = False
        self.mutate_on_pass = None
        self.release_metadata = {}
        self.episode_rows = [{"signal_id": s.signal_id, "document_json": s.document} for s in self.password_signals]
        self.signals = {s.signal_id: {"signal_id": s.signal_id, "evaluation_mode": s.evaluation_mode,
                                     "document_json": s.document} for s in self.password_signals}
        self.allowed.update(ref.params for s in self.password_signals for ref in s.evidence_refs)

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()).lower()
        if normalized.startswith(("savepoint ", "rollback to savepoint ", "release savepoint ")):
            self.calls.append((normalized, params))
            self.rows = []
        elif "from semantic_risk_evaluation_results result" in normalized:
            super().execute(sql, params)
            job = next(row for row in self.jobs.values() if row["job_id"] == params[0])
            self.rows = [row | {"qw_signal_id": job["qw_signal_id"],
                                "source_kind": getattr(self, "result_source_kind", "qw_signal")} for row in self.rows]
        elif "read_password_episode_portions_v2(" in normalized:
            self.calls.append((normalized, params))
            self.rows = deepcopy(self.episode_rows)
        elif "lock_password_publication_v2(" in normalized or "assert_password_publication_entity_v2(" in normalized:
            self.calls.append((normalized, params))
            if self.frozen:
                raise RuntimeError("episode_frozen")
            last = self.password_signals[-1].password_context
            if "assert_password_publication_entity_v2(" in normalized:
                self.barrier_asserts.append(params[3])
            budget = pure.Budget()
            for emission in self.emissions:
                budget = budget.reserve(ref_occurrences=len(emission.occurrences), portions=emission.portions,
                                        xml_bytes=sum(w.xml_bytes for w in emission.occurrences))
            self.rows = [{"publication": {"episode_key": last["episode_key"], "entity": last["entity"],
                "epoch": last["epoch"], "root_id": last["root_id"], "last_sequence": last["sequence"],
                "last_emission_id": last["emission_id"], "totals": {"ref_occurrences": budget.ref_occurrences,
                    "portions": budget.portions, "xml_bytes": budget.xml_bytes}, "frozen": False,
                "predecessor_episode_key": None} | deepcopy(self.release_metadata)}]
        elif "read_password_retained_proof_v2(" in normalized:
            self.calls.append((normalized, params))
            self.native_passes += 1
            witnesses = json.loads(params[1])
            self.rows = []
            for index, witness in enumerate(witnesses, 1):
                item = self.native[witness["ref"]["native_id"]]
                xml = item.source_xml
                if self.mutate_on_pass == self.native_passes:
                    xml = xml.replace("0xc000006a", "0xc0000064")
                self.rows.append({"occurrence_index": index, "source_event_id": int(item.ref.native_id),
                    "event_id": item.event_id, "occurred_at_utc": item.at, "sha256": item.ref.sha256,
                    "source_xml": xml, "xml_bytes": len(xml.encode()), "xml_sha256": item.member.witness.xml_sha256})
        elif "select distinct signal.signal_id" in normalized and "semantic_scenario_steps" in normalized:
            self.calls.append((normalized, params))
            ids = {row["qw_signal_id"] for row in self.steps.values() if row["scenario_id"] == params[0]
                   and row.get("source_kind", "qw_signal") == "qw_signal"}
            if "left join" in normalized and any(key not in self.signals for key in ids):
                self.rows = [{"signal_id": None}]
                return
            ids &= self.signals.keys()
            if "document_json ? 'password_context'" in normalized:
                ids = {key for key in ids if "password_context" in self.signals[key]["document_json"]
                       or self.signals[key]["document_json"]["rule_id"] in adapter().RULES
                       and self.signals[key]["document_json"]["rule_version"] == 2}
            self.rows = [self.signals[key] for key in sorted(ids)]
        elif "select 1 as invalid from semantic_scenario_steps step" in normalized:
            self.calls.append((normalized, params))
            invalid = any(row.get("source_kind", "qw_signal") != "qw_signal"
                or row.get("qw_signal_id") not in self.signals
                for row in self.steps.values() if row["scenario_id"] == params[0])
            self.rows = [{"invalid": 1}] if invalid else []
        elif "select distinct qw_signal_id from semantic_scenario_steps" in normalized:
            self.calls.append((normalized, params))
            ids = {row["qw_signal_id"] for row in self.steps.values() if row["scenario_id"] == params[0]}
            self.rows = [{"qw_signal_id": key} for key in sorted(ids)][:257]
        elif normalized == "select scenario_id from semantic_security_scenarios where scenario_key=%s":
            self.calls.append((normalized, params))
            self.rows = [row for row in self.scenarios.values() if row["scenario_key"] == params[0]]
        elif "set evidence_state='evidence_pending'" in normalized:
            self.calls.append((normalized, params))
            self.scenarios[params[0]]["evidence_state"] = "evidence_pending"
            self.rows = []
        else:
            super().execute(sql, params)

    def seed_password_publication(self, emission):
        scenario = "forged-scenario"
        self.results["forged-job"] = {"evaluation_mode": "enabled", "conclusion_state": "observed",
                                      "scenario_id": scenario}
        self.jobs["forged-job"] = {"job_id": "forged-job", "qw_signal_id": self.password_signals[-1].signal_id}
        self.scenarios[scenario] = {"scenario_id": scenario, "scenario_key": b"password-fixture",
            "identity_key": b"password-writer-identity",
            "scenario_kind": self.password_signals[0].rule_id, "strict_keys_json": {"kind": "threshold",
                "entity": emission.entity, "episode": emission.episode_key}, "title": "Synthetic password",
            "explanation": "Native proof required", "first_seen_utc": emission.seed.at,
            "last_seen_utc": emission.endpoint.at, "risk_class": "medium", "confidence_score": 80,
            "evidence_state": "ready"}
        for index, item in enumerate(self.password_signals):
            step_id = f"00000000-0000-0000-0000-{index + 1:012d}"
            self.steps[step_id] = {"scenario_id": scenario, "step_id": step_id, "qw_signal_id": item.signal_id,
                                   "source_kind": "qw_signal"}


def test_native_adapter_reassembles_and_reparses_actual_xml_without_verdict_flags():
    emission, _, natives = root(257)
    cur = Cursor((emission,), natives)
    assert adapter().verify_signal(cur, cur.password_signals[0]) == emission.ref_portions[0]
    assert cur.native_passes == 1


@pytest.mark.parametrize("damage", ["missing", "reverse", "duplicate", "overflow"])
def test_indexed_chain_lookup_requires_all_exact_ordered_portions(damage):
    emission, _, natives = root(257)
    cur = Cursor((emission,), natives)
    if damage == "missing": cur.episode_rows.pop()
    elif damage == "reverse": cur.episode_rows.reverse()
    elif damage == "duplicate": cur.episode_rows[1] = cur.episode_rows[0]
    else: cur.episode_rows *= 257
    with pytest.raises((ValueError, RuntimeError)):
        adapter().load_episode(cur, cur.password_signals[0])
    assert cur.native_passes == 0


def evaluate(cur, signal):
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=jobs[0], lease_token="fixture-lease")
    return runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)


def test_enabled_publication_has_two_fresh_whole_passes_and_entity_assertions():
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    result = evaluate(cur, cur.password_signals[0])
    assert result.finding_created and len(cur.findings) == len(cur.outbox) == 1
    assert cur.barrier_asserts == [emission.entity, emission.entity]
    locks = [sql for sql, _ in cur.calls if "advisory" in sql or "lock_password_publication" in sql]
    first_ledger = next(index for index, sql in enumerate(locks) if "lock_password_publication" in sql)
    assert first_ledger > 0 and all("advisory" in sql for sql in locks[:first_ledger])
    assert not any("semantic_password_checkpoints" in sql or
                   "semantic_password_episode_budgets" in sql and "for update" in sql for sql, _ in cur.calls)


@pytest.mark.parametrize("forgery", ["entity", "threshold"])
def test_publisher_independently_rejects_self_consistent_semantic_forgery(forgery):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    if forgery == "entity":
        entity = "b" * 64
        emission = replace(emission, entity=entity, episode_key=pure._key(pure.Rule(SCOPE, "brute"), 0, entity, emission.seed))
    else:
        proof = emission.origin[:5]
        emission = replace(emission, origin=proof, root_proof=proof, new_events=(), known_bad_password=5)
    cur = Cursor((emission,), natives)
    # Owner-style fake storage seed bypasses producer and proposal checks on purpose.
    cur.seed_password_publication(emission)
    before = deepcopy(cur.scenarios)
    with pytest.raises((ValueError, RuntimeError), match="password_v2_continuity"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert not cur.findings and not cur.outbox and not cur.links
    assert cur.scenarios == before


def test_multportion_publication_does_exactly_two_full_reads_and_no_redundant_resolver_loop():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(257)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    reads = [json.loads(params[1]) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    assert [len(rows) for rows in reads] == [257, 257]
    assert cur.native_passes == 2 and cur.barrier_asserts == [emission.entity] * 2
    assert sum("link_finding_evidence_ref(" in sql for sql, _ in cur.calls) == 257
    assert not any("resolve_finding_evidence_ref(" in sql for sql, _ in cur.calls)


def test_out_of_order_continuation_is_pending_until_root_step_arrives():
    first, state, natives = root(10)
    new = event(100, at=BASE + timedelta(seconds=590))
    second, = pure.advance(pure.Rule(SCOPE, "brute"), state, (new,), now=BASE + timedelta(seconds=710),
                           history=(first,), retained=natives).emissions
    cur = Cursor((first, second), (*natives, new))
    pending = evaluate(cur, cur.password_signals[-1])
    assert pending.publication_state == "evidence_pending" and not cur.findings and not cur.outbox
    result = evaluate(cur, cur.password_signals[0])
    assert result.finding_created and len(cur.findings) == len(cur.outbox) == 1
    reads = [len(json.loads(params[1])) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    assert reads[-2:] == [12, 12]


def test_frozen_job_finishes_before_expired_native_content_or_scenario_write():
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=cur.password_signals[0])
    cur.frozen, cur.native = True, {}
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
    before = cur.native_passes
    result = runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    assert result.publication_state == "episode_frozen" and result.scenario_id is None
    assert cur.native_passes == before and not cur.scenarios and not cur.findings and not cur.outbox
    assert any("rollback to savepoint" in sql for sql, _ in cur.calls)
    assert any("last_error_code='episode_frozen'" in sql and "evaluation_status='completed'" in sql for sql, _ in cur.calls)


@contextmanager
def fake_transaction(cur):
    # Unit cursor rollback models caller ownership; this is NOT PG integration.
    names = ("findings", "links", "core_ids", "publications", "outbox", "history")
    saved = {name: deepcopy(getattr(cur, name)) for name in names}
    try:
        yield
    except Exception:
        for name, value in saved.items():
            setattr(cur, name, value)
        raise


def test_native_mutation_on_second_pass_requires_caller_rollback_of_all_output():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    cur.mutate_on_pass = 2
    with pytest.raises(RuntimeError, match="password_v2_native_content_conflict"), fake_transaction(cur):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.native_passes == 2 and not cur.findings and not cur.links and not cur.publications and not cur.outbox


@pytest.mark.parametrize("kind,extra", [("occurrences", 0), ("occurrences", 1), ("bytes", 0), ("bytes", 1)])
def test_exact_whole_proof_budget_bound_before_native_transfer(kind, extra):
    emission, _, _ = root(10)
    witness = emission.seed
    if kind == "occurrences":
        witnesses = (witness,) * (10000 + extra)
    else:
        witnesses = (replace(witness, xml_bytes=4194304),) * 7 + (replace(witness, xml_bytes=4194304 + extra),)
    class StopAtTransfer:
        reached = False
        def execute(self, *args):
            self.reached = True
            raise RuntimeError("unit_transfer_boundary")
    cur = StopAtTransfer()
    with pytest.raises(RuntimeError, match="password_v2_proof_budget_exceeded" if extra else "unit_transfer_boundary"):
        adapter()._read_native(cur, SCOPE, witnesses)
    assert cur.reached is (extra == 0)


def test_external_frozen_gap_endpoint_is_fresh_in_both_passes_and_within_same_cap(monkeypatch):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    predecessor = event(900, at=BASE - timedelta(seconds=601))
    cur = Cursor((emission,), (*natives, predecessor))
    cur.seed_password_publication(emission)
    cur.release_metadata = {"predecessor_episode_key": "a" * 64,
        "predecessor_endpoint": adapter()._witness_document(predecessor.member.witness),
        "successor_seed": adapter()._witness_document(emission.seed), "successor_epoch": emission.epoch,
        "predecessor_tracking_through": emission.seed.at.isoformat()}
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    reads = [json.loads(params[1]) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    assert [len(rows) for rows in reads] == [11, 11]
    blocked = Cursor((emission,), (*natives, predecessor))
    blocked.seed_password_publication(emission)
    blocked.release_metadata = cur.release_metadata
    monkeypatch.setattr(adapter(), "MAX_ROWS", 10)
    with pytest.raises(RuntimeError, match="password_v2_proof_budget_exceeded"):
        publish_enabled_scenario_finding(blocked, job_id="forged-job", scenario_id="forged-scenario")
    assert blocked.native_passes == 0 and not blocked.findings and not blocked.outbox


def test_full_qw_wire_rejects_oversize_even_with_bounded_compact_context():
    scope = replace(SCOPE, source_instance_id="😀" * 256, source_generation="😀" * 512)
    emission, _, _ = root(256, scope)
    assert len(codec.contexts_from_emission(emission)) == 1
    with pytest.raises(ValueError, match="password_v2_signal_invalid"):
        signals_for(emission)


def test_direct_proposal_verifier_locks_and_rejects_frozen_before_native_access():
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=cur.password_signals[0])
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
    cur.frozen, cur.native = True, {}
    before = cur.native_passes
    with pytest.raises(adapter().PasswordEpisodeFrozen, match="episode_frozen"):
        qw.verify_qw_proposal(cur, proposal=work.proposal)
    assert cur.native_passes == before and not cur.scenarios


def test_password_linker_normalizes_private_sql_errors():
    from server.sli.storage.evidence_ref import EvidenceRefError
    emission, _, _ = root(10)
    class Denied:
        def execute(self, *args):
            raise RuntimeError("private native diagnostic")
    with pytest.raises(EvidenceRefError, match="^evidence_link_failed$"):
        adapter().link_password_evidence(Denied(), finding_id=1, batches=((emission.seed.ref,),))


def test_many_590s_windows_and_serialized_restart_retain_complete_native_chain():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    first, state, original = root(10)
    chain, natives = [first], list(original)
    rule = pure.Rule(SCOPE, "brute")
    for index, second in enumerate((590, 1180, 1770), 100):
        state = pure.State.from_document(state.document)
        native = event(index, at=BASE + timedelta(seconds=second))
        proposal = pure.advance(rule, state, (native,), now=native.at + timedelta(seconds=120),
                                history=tuple(chain), retained=tuple(natives))
        emission, = proposal.emissions
        chain.append(emission)
        natives.append(native)
        state = proposal.state
    cur = Cursor(tuple(chain), tuple(natives))
    cur.seed_password_publication(chain[-1])
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.native_passes == 2 and len(cur.findings) == len(cur.outbox) == 1
    reads = [len(json.loads(params[1])) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    assert reads == [16, 16]


def test_spray_uses_same_native_implementation_and_five_distinct_accounts():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    natives = []
    for index in range(1, 6):
        native = event(index)
        natives.append(pure.NativeEvent.from_row(SCOPE, {"source_event_id": index, "event_id": 4625,
            "occurred_at_utc": native.at, "sha256": native.ref.sha256,
            "source_xml": native.source_xml.replace(">synthetic<", f">synthetic-{index}<")}))
    emission, = pure.advance(pure.Rule(SCOPE, "spray"), pure.State(), tuple(natives),
                             now=BASE + timedelta(seconds=200)).emissions
    cur = Cursor((emission,), tuple(natives))
    cur.seed_password_publication(emission)
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.password_signals[0].rule_id == "qw.password-spray" and cur.native_passes == 2
    assert len(cur.findings) == len(cur.outbox) == 1


def stored_signals(cur, signals):
    cur.password_signals = tuple(signals)
    cur.episode_rows = [{"signal_id": item.signal_id, "document_json": item.document} for item in signals]
    cur.signals = {item.signal_id: {"signal_id": item.signal_id, "evaluation_mode": item.evaluation_mode,
                                  "document_json": item.document} for item in signals}


def two_emissions():
    first, state, natives = root(10)
    new = event(100, at=BASE + timedelta(seconds=590))
    second, = pure.advance(pure.Rule(SCOPE, "brute"), state, (new,), now=BASE + timedelta(seconds=710),
                           history=(first,), retained=natives).emissions
    return first, second, (*natives, new)


def test_lifetime_metadata_may_change_mode_and_revision_without_new_root_or_budget():
    first, second, natives = two_emissions()
    cur = Cursor((first, second), natives)
    old, new = cur.password_signals
    stored_signals(cur, (replace(old, evaluation_mode="shadow"), replace(new, policy_revision=2)))
    episode = adapter().load_episode(cur, cur.password_signals[-1])
    assert episode.emissions == (first, second) and cur.native_passes == 0


def test_shadow_ancestor_cannot_publish_an_enabled_partial_chain():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    first, second, natives = two_emissions()
    cur = Cursor((first, second), natives)
    old, new = cur.password_signals
    stored_signals(cur, (replace(old, evaluation_mode="shadow"), new))
    cur.seed_password_publication(second)
    with pytest.raises(RuntimeError, match="qw_signal_source_mismatch"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert not cur.findings and not cur.links and not cur.outbox


def test_emission_metadata_must_agree_across_all_its_portions():
    emission, _, natives = root(257)
    cur = Cursor((emission,), natives)
    first, last = cur.password_signals
    stored_signals(cur, (first, replace(last, severity_reasons=("different",))))
    with pytest.raises(RuntimeError, match="password_v2_chain_invalid"):
        adapter().load_episode(cur, first)
    assert cur.native_passes == 0


def test_legacy_job_cannot_route_managed_password_steps_through_ref_only_publication():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    entity = "b" * 64
    emission = replace(emission, entity=entity, episode_key=pure._key(pure.Rule(SCOPE, "brute"), 0, entity, emission.seed))
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    legacy = qw.QWSignal(kind="threshold", rule_id="qw.password-brute-force", rule_version=1,
        rule_sha256="1" * 64, policy_revision=1, evaluation_mode="enabled", entity_key=entity,
        episode_key=emission.episode_key, occurred_at_utc=emission.endpoint.at, received_at_utc=BASE,
        evidence_refs=cur.password_signals[0].evidence_refs)
    cur.signals[legacy.signal_id] = {"signal_id": legacy.signal_id, "evaluation_mode": "enabled",
                                    "document_json": legacy.document}
    cur.jobs["forged-job"]["qw_signal_id"] = legacy.signal_id
    with pytest.raises((ValueError, RuntimeError), match="password_v2_continuity"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert not cur.findings and not cur.links and not cur.outbox


def test_mixed_legacy_and_password_scenario_steps_fail_closed():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    managed = cur.password_signals[0]
    legacy = qw.QWSignal(kind="threshold", rule_id=managed.rule_id, rule_version=1, rule_sha256="1" * 64,
        policy_revision=1, evaluation_mode="enabled", entity_key=emission.entity, episode_key=emission.episode_key,
        occurred_at_utc=emission.endpoint.at, received_at_utc=BASE, evidence_refs=managed.evidence_refs)
    cur.signals[legacy.signal_id] = {"signal_id": legacy.signal_id, "evaluation_mode": "enabled",
                                    "document_json": legacy.document}
    step_id = "00000000-0000-0000-0000-999999999999"
    cur.steps[step_id] = {"scenario_id": "forged-scenario", "step_id": step_id, "qw_signal_id": legacy.signal_id}
    cur.jobs["forged-job"]["qw_signal_id"] = legacy.signal_id
    with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.native_passes == 0 and not cur.findings and not cur.links and not cur.outbox


def test_non_qw_result_cannot_bypass_managed_password_scenario_guard():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    cur.result_source_kind = "canonical_action"
    with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.native_passes == 0 and not cur.findings and not cur.links and not cur.outbox


@pytest.mark.parametrize("frozen", [False, True])
@pytest.mark.parametrize("incoming_kind", ["canonical_action", "legacy_qw"])
def test_non_qw_collision_is_rejected_before_any_scenario_persistence(monkeypatch, frozen, incoming_kind):
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    signal = cur.password_signals[0]
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
    if incoming_kind == "canonical_action":
        step = replace(work.proposal.step, source_kind=ScenarioSourceKind.CANONICAL_ACTION,
                       normalized_event_ids=("normalized-fixture",), evidence_refs=())
    else:
        legacy = replace(signal, rule_version=1, rule_sha256="1" * 64, password_context=None)
        cur.signals[legacy.signal_id] = {"signal_id": legacy.signal_id, "evaluation_mode": "enabled",
                                        "document_json": legacy.document}
        step = replace(work.proposal.step, source_id=legacy.signal_id)
    proposal = replace(work.proposal, step=step, contribution=replace(work.proposal.contribution,
        source_kind=step.source_kind, source_id=step.source_id))
    work = replace(work, proposal=proposal)
    cur.seed_password_publication(emission)
    cur.scenarios["forged-scenario"].update(scenario_key=proposal.identity_sha256,
        identity_key=proposal.identity_sha256, scenario_status="open", result_class=proposal.result_class.value,
        partition_key=proposal.partition_key, strict_keys_json=dict(proposal.strict_keys),
        merge_window_seconds=int(proposal.merge_window.total_seconds()))
    cur.frozen, cur.native = frozen, {}
    before = deepcopy((cur.scenarios, cur.steps, cur.results, cur.findings, cur.links, cur.outbox))
    writes = []
    def persist(*args, **kwargs):
        writes.append("scenario/evidence/context")
        raise RuntimeError("persistence_reached")
    monkeypatch.setattr(runtime, "persist_scenario_proposal", persist)
    cur.native_passes = 0
    cur.calls.clear()
    with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
        runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    assert not writes and cur.native_passes == 0
    assert (cur.scenarios, cur.steps, cur.results, cur.findings, cur.links, cur.outbox) == before
    assert not any(sql.startswith(("insert ", "update ", "delete ")) for sql, _ in cur.calls)


@pytest.mark.parametrize("base,effective", [("medium", "medium"), ("critical", "critical"),
                                         ("medium", "high"), ("high", "critical")])
def test_managed_severity_is_fixed_high_at_constructor_and_load(monkeypatch, base, effective):
    emission, _, natives = root(10)
    signal, = signals_for(emission)
    with pytest.raises(ValueError, match="password_v2_signal_invalid"):
        replace(signal, base_severity=base, effective_severity=effective)
    document = signal.document | {"base_severity": base, "effective_severity": effective}
    key = qw._digest({name: value for name, value in document.items() if name != "received_at_utc"})
    cur = Cursor((emission,), natives)
    cur.signals[key] = {"signal_id": key, "evaluation_mode": "enabled", "document_json": document}
    with pytest.raises(RuntimeError, match="qw_signal_conflict"):
        qw.load_qw_signal(cur, signal_id=key)
    from server.sli.semantic.semantic_risk_policy import compile_risk_policy
    with pytest.raises(RuntimeError, match="qw_signal_conflict"):
        qw.qw_signal_proposal(cur, policy=compile_risk_policy(cur.policies[0][0]), source_id=key)
    assert not cur.jobs and not cur.scenarios and not cur.findings


@pytest.mark.parametrize("incoming,existing", [("managed", "canonical_action"), ("managed", "legacy_qw"),
                                             ("canonical_action", "managed"), ("legacy_qw", "managed")])
@pytest.mark.parametrize("frozen", [False, True])
def test_actual_merge_target_rejects_mixing_before_native_or_persistence(monkeypatch, incoming, existing, frozen):
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    signal = cur.password_signals[0]
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
    legacy = replace(signal, rule_version=1, rule_sha256="1" * 64, password_context=None)
    cur.signals[legacy.signal_id] = {"signal_id": legacy.signal_id, "evaluation_mode": "enabled",
                                    "document_json": legacy.document}
    if incoming == "canonical_action":
        step = replace(work.proposal.step, source_kind=ScenarioSourceKind.CANONICAL_ACTION,
                       normalized_event_ids=("normalized-fixture",), evidence_refs=())
    else:
        step = replace(work.proposal.step, source_id=legacy.signal_id if incoming == "legacy_qw" else signal.signal_id)
    proposal = replace(work.proposal, step=step, contribution=replace(work.proposal.contribution,
        source_kind=step.source_kind, source_id=step.source_id))
    work = replace(work, proposal=proposal)
    cur.seed_password_publication(emission)
    target = cur.scenarios["forged-scenario"]
    old_kind = ScenarioSourceKind.CANONICAL_ACTION if existing == "canonical_action" else ScenarioSourceKind.QW_SIGNAL
    old_id = legacy.signal_id if existing == "legacy_qw" else signal.signal_id
    old_contribution = replace(proposal.contribution, source_kind=old_kind, source_id=old_id,
                               contribution_key="old-target-contribution")
    target.update(identity_key=proposal.identity_sha256,
        scenario_key=sha256(proposal.identity_sha256 + old_contribution.contribution_sha256).digest()
                     if old_kind is ScenarioSourceKind.CANONICAL_ACTION else proposal.identity_sha256,
        scenario_status="open", result_class=proposal.result_class.value, partition_key=proposal.partition_key,
        strict_keys_json=dict(proposal.strict_keys), merge_window_seconds=int(proposal.merge_window.total_seconds()))
    cur.steps.clear()
    cur.steps["old"] = {"scenario_id": "forged-scenario", "step_id": "old", "source_kind": old_kind.value,
                        "qw_signal_id": old_id if old_kind is ScenarioSourceKind.QW_SIGNAL else None}
    cur.frozen, cur.native = frozen, {}
    before = deepcopy((cur.scenarios, cur.steps, cur.results, cur.findings, cur.links, cur.outbox))
    writes = []
    def persist(*args, **kwargs):
        writes.append("persistence")
        raise RuntimeError("persistence_reached")
    monkeypatch.setattr(runtime, "persist_scenario_proposal", persist)
    cur.native_passes = 0
    cur.calls.clear()
    with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
        runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    assert not writes and cur.native_passes == 0
    assert (cur.scenarios, cur.steps, cur.results, cur.findings, cur.links, cur.outbox) == before
    assert not any(sql.startswith(("insert ", "update ", "delete ")) for sql, _ in cur.calls)


@pytest.mark.parametrize("damage", ["non_qw", "orphan", "overflow"])
def test_preseeded_non_qw_step_cannot_hide_behind_managed_subset(damage):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    if damage == "overflow":
        for index in range(257):
            signal = replace(cur.password_signals[0], policy_revision=index + 1)
            cur.signals[signal.signal_id] = {"signal_id": signal.signal_id, "evaluation_mode": "enabled",
                                             "document_json": signal.document}
            cur.steps[f"extra-{index}"] = {"scenario_id": "forged-scenario", "step_id": f"extra-{index}",
                "source_kind": "qw_signal", "qw_signal_id": signal.signal_id}
    else:
        cur.steps["non-qw"] = {"scenario_id": "forged-scenario", "step_id": "non-qw",
            "source_kind": "canonical_action" if damage == "non_qw" else "qw_signal",
            "qw_signal_id": None if damage == "non_qw" else "missing-qw"}
    before = deepcopy(cur.scenarios)
    with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert cur.native_passes == 0 and not cur.findings and not cur.links and not cur.outbox
    assert cur.scenarios == before


def test_publisher_uses_stored_writer_identity_not_legacy_scenario_key():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    locks = [params[0] for sql, params in cur.calls if "pg_advisory_xact_lock" in sql]
    assert locks[0] == cur.scenarios["forged-scenario"]["identity_key"].hex()
    assert locks[0] != cur.scenarios["forged-scenario"]["scenario_key"].hex()


def test_readonly_target_replay_and_miss_do_not_lock_or_mutate():
    from server.sli.semantic.semantic_risk_repository import _existing_scenario
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    signal = cur.password_signals[0]
    first = evaluate(cur, signal)
    job, = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
    cur.calls.clear()
    target = _existing_scenario(cur, proposal=work.proposal)
    assert target["scenario_id"] == first.scenario_id
    missing = replace(work.proposal, strict_keys={**work.proposal.strict_keys, "entity": "f" * 64},
        contribution=replace(work.proposal.contribution, contribution_key="new-readonly-miss"))
    assert _existing_scenario(cur, proposal=missing) is None
    assert cur.calls and all(sql.startswith("select ") and "for update" not in sql and "advisory" not in sql
                             for sql, _ in cur.calls)


def test_two_real_policy_jobs_share_one_immutable_signal_and_bounded_publication():
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    first_policy, mode = cur.policies[0]
    cur.policies.append((replace(first_policy, policy_id="second-password-policy"), mode))
    signal = cur.password_signals[0]
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    assert len(jobs) == 2 and len(set(jobs)) == 2
    works = [runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease") for job in jobs]
    assert works[0].proposal.identity_sha256 == works[1].proposal.identity_sha256
    assert works[0].proposal.step.step_key != works[1].proposal.step.step_key
    first = runtime.execute_risk_evaluation(cur, work=works[0], evaluation_ms=1, create_finding=True)
    cur.calls.clear()
    second = runtime.execute_risk_evaluation(cur, work=works[1], evaluation_ms=1, create_finding=True)
    assert first.scenario_id == second.scenario_id and first.finding_id == second.finding_id
    assert len(cur.steps) == 2 and len(cur.findings) == len(cur.outbox) == 1
    assert {row["qw_signal_id"] for row in cur.steps.values()} == {signal.signal_id}
    reads = [json.loads(params[1]) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    # One ingress/proposal subset, then exactly two whole proof passes; no step multiplicity.
    assert [len(batch) for batch in reads] == [10, 10, 10]
    assert sum("assert_password_publication_entity_v2(" in sql for sql, _ in cur.calls) == 2
    assert sum("link_finding_evidence_ref(" in sql for sql, _ in cur.calls) == 10


@pytest.mark.parametrize("damage", [None, "non_qw", "null", "orphan"])
def test_raw_duplicate_policy_steps_do_not_hide_invalid_members_or_spend_portion_budget(damage):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    emission, _, natives = root(10)
    cur = Cursor((emission,), natives)
    cur.seed_password_publication(emission)
    for index in range(300):
        cur.steps[f"duplicate-{index:04d}"] = {"scenario_id": "forged-scenario",
            "step_id": f"duplicate-{index:04d}", "source_kind": "qw_signal",
            "qw_signal_id": cur.password_signals[0].signal_id}
    if damage is not None:
        cur.steps["zz-hidden"] = {"scenario_id": "forged-scenario", "step_id": "zz-hidden",
            "source_kind": "canonical_action" if damage == "non_qw" else "qw_signal",
            "qw_signal_id": None if damage in {"non_qw", "null"} else "missing-qw"}
        before = deepcopy(cur.scenarios)
        with pytest.raises(RuntimeError, match="password_v2_scenario_invalid"):
            publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
        assert cur.native_passes == 0 and not cur.findings and not cur.links and not cur.outbox
        assert cur.scenarios == before
        assert not any("select distinct qw_signal_id" in sql for sql, _ in cur.calls)
    else:
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
        assert len(cur.steps) == 301 and cur.native_passes == 2
        assert len(cur.findings) == len(cur.outbox) == 1 and len(cur.links) == 10




def historical_cursor(gap=601):
    emission, _, natives = root(10)
    barrier = event(900, at=emission.endpoint.at + timedelta(seconds=gap))
    cur = Cursor((emission,), (*natives, barrier))
    cur.release_metadata["historical_barrier"] = {
        "version": "sli.password.v2.historical-barrier.1", "barrier_episode_key": "b" * 64,
        "barrier_first_ledger_revision": 11, "barrier_seed": adapter()._witness_document(barrier.member.witness),
        "target_last_admitted_revision": 10, "target_last_sequence": emission.sequence,
        "target_last_emission_id": emission.emission_id}
    cur.seed_password_publication(emission)
    return cur, emission, barrier


def test_historical_publication_reads_external_seed_twice_and_links_only_old_a():
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    cur, emission, barrier = historical_cursor()
    before = deepcopy(cur.release_metadata)
    publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    reads = [json.loads(params[1]) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
    assert [len(batch) for batch in reads] == [11, 11]
    assert all(batch[-1]["ref"] == adapter()._witness_document(barrier.member.witness)["ref"] for batch in reads)
    assertions = [params for sql, params in cur.calls if "assert_password_publication_entity_v2(" in sql]
    assert all(len(params) == 5 and json.loads(params[-1]) == before["historical_barrier"] for params in assertions)
    assert len(cur.links) == 10 and len(cur.findings) == len(cur.outbox) == 1
    assert cur.release_metadata == before and emission.entity == barrier.member.entity(pure.Rule(SCOPE, "brute"))


@pytest.mark.parametrize("damage", ["gap600", "missing", "second_pass", "scope", "metadata", "bool_revision", "extra"])
def test_historical_invalid_native_or_descriptor_fails_closed(damage):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    cur, _, barrier = historical_cursor(600 if damage == "gap600" else 601)
    descriptor = cur.release_metadata["historical_barrier"]
    if damage == "missing": del cur.native[barrier.ref.native_id]
    elif damage == "second_pass": cur.mutate_on_pass = 2
    elif damage == "scope": descriptor["barrier_seed"]["ref"]["scope"]["source_instance_id"] = "other"
    elif damage == "metadata": descriptor["target_last_sequence"] += 1
    elif damage == "bool_revision": descriptor["target_last_admitted_revision"] = True
    elif damage == "extra": descriptor["verified"] = True
    with pytest.raises((RuntimeError, ValueError, KeyError)), fake_transaction(cur):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert not cur.findings and not cur.links and not cur.outbox and not cur.publications



@pytest.mark.parametrize("kind,overflow", [("rows", False), ("rows", True), ("bytes", False), ("bytes", True)])
def test_historical_external_predecessor_and_barrier_share_one_actual_budget(monkeypatch, kind, overflow):
    cur, emission, _ = historical_cursor()
    predecessor = event(901, at=emission.seed.at - timedelta(seconds=601))
    cur.native[predecessor.ref.native_id] = predecessor
    cur.release_metadata.update(predecessor_episode_key="c" * 64,
        predecessor_endpoint=adapter()._witness_document(predecessor.member.witness),
        successor_seed=adapter()._witness_document(emission.seed), successor_epoch=emission.epoch,
        predecessor_tracking_through=emission.seed.at.isoformat())
    # Small REAL XML fixtures exercise the same inclusive accumulator; no verifier stub.
    limit = 12 if kind == "rows" else sum(len(n.source_xml.encode()) for n in cur.native.values())
    monkeypatch.setattr(adapter(), "MAX_ROWS" if kind == "rows" else "MAX_XML_BYTES", limit - int(overflow))
    if overflow:
        with pytest.raises(RuntimeError, match="password_v2_proof_budget_exceeded"):
            adapter().verify_scenario(cur, scenario_id="forged-scenario")
        assert cur.native_passes == 0
    else:
        batches = adapter().verify_scenario(cur, scenario_id="forged-scenario")
        assert sum(map(len, batches)) == 10 and cur.native_passes == 1
        reads = [json.loads(params[1]) for sql, params in cur.calls if "read_password_retained_proof_v2(" in sql]
        assert len(reads[0]) == 12


@pytest.mark.parametrize("damage", ["entity", "changed_b_only", "descriptor_changed", "missing_chain"])
def test_historical_proof_requires_current_b_and_complete_latest_a(damage):
    from server.sli.semantic.semantic_findings import publish_enabled_scenario_finding
    cur, emission, barrier = historical_cursor()
    if damage == "entity":
        from tests.unit.test_password_attack_v2 import event as other_event
        other = other_event(902, 700, account="other")
        cur.native[other.ref.native_id] = other
        cur.release_metadata["historical_barrier"]["barrier_seed"] = adapter()._witness_document(other.member.witness)
    elif damage == "missing_chain": cur.episode_rows.clear()
    original_execute = cur.execute
    def execute(sql, params=()):
        if "read_password_retained_proof_v2(" in sql and cur.native_passes == 1:
            if damage == "changed_b_only":
                changed = barrier.source_xml.replace("synthetic", "different")
                cur.native[barrier.ref.native_id] = pure.NativeEvent.from_row(SCOPE, {
                    "source_event_id": int(barrier.ref.native_id), "event_id": barrier.event_id,
                    "occurred_at_utc": barrier.at, "sha256": barrier.ref.sha256, "source_xml": changed})
            elif damage == "descriptor_changed":
                cur.release_metadata["historical_barrier"]["barrier_first_ledger_revision"] += 1
        original_execute(sql, params)
    cur.execute = execute
    with pytest.raises((RuntimeError, ValueError)), fake_transaction(cur):
        publish_enabled_scenario_finding(cur, job_id="forged-job", scenario_id="forged-scenario")
    assert not cur.findings and not cur.links and not cur.outbox



def test_historical_two_policy_jobs_and_replay_keep_single_a_evidence_set():
    cur, _, barrier = historical_cursor()
    cur.scenarios.clear()
    cur.steps.clear()
    cur.results.clear()
    cur.jobs.clear()
    first_policy, mode = cur.policies[0]
    cur.policies.append((replace(first_policy, policy_id="historical-second-policy"), mode))
    signal = cur.password_signals[0]
    jobs = qw.enqueue_qw_signal_risk_jobs(cur, signal=signal)
    assert len(jobs) == 2
    for job in jobs:
        work = runtime.load_risk_evaluation_work_item(cur, job_id=job, lease_token="fixture-lease")
        runtime.execute_risk_evaluation(cur, work=work, evaluation_ms=1, create_finding=True)
    before = deepcopy((cur.findings, cur.links, cur.outbox, cur.release_metadata))
    assert qw.enqueue_qw_signal_risk_jobs(cur, signal=signal) == jobs
    assert (cur.findings, cur.links, cur.outbox, cur.release_metadata) == before
    assert len(cur.steps) == 2 and len(cur.findings) == len(cur.outbox) == 1 and len(cur.links) == 10
    assert all(params[3] != barrier.ref.native_id for sql, params in cur.calls if "link_finding_evidence_ref(" in sql)
