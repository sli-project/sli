"""Public B2 completion on disposable PostgreSQL; no owner final-State bypass."""
from dataclasses import asdict, replace
from datetime import datetime, timedelta
import json

import pytest

from server.sli.semantic import password_attack_v2 as pure
from tests.migrations.test_password_attacks_v2_reservation_migration import (
    EXECUTION, POLICY, RULE, SCOPE, _begin, _connection, _digest, _j, _jobs,
    _documents as _storage_documents,
    _continue, _historical, _native, _replace_xml, _reserve, _root, _seed, _xml,
    acl_pg as acl_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
VERSION = "sli.password.v2.producer-batch.1"


def _documents(emission, root_id=None):
    # Storage-only reservation fixtures predate frozen publisher/QW validation.
    # Preserve those fixtures; public queue uses the actual typed signal shape.
    documents = _storage_documents(emission, root_id)
    for document in documents:
        document.update(base_severity="high", effective_severity="high",
            evidence_total=document["password_context"]["occurrence_total"])
    return documents


@pytest.fixture
def coordinator_pg(reservation_pg):
    with _connection(reservation_pg) as admin:
        # Actual050/153 privileges omitted by reduced unrelated fixture265.
        # The LOGIN remains exclusively semantic; no role switching or new grant.
        admin.execute("grant select,insert,update on semantic_risk_evaluation_jobs,semantic_risk_policies to adlog_semantic_worker")
        admin.execute("grant select on semantic_risk_policy_subscriptions to adlog_semantic_worker")
        admin.execute("grant select on semantic_policy_admission to adlog_semantic_worker")
        admin.execute("""alter table semantic_risk_evaluation_jobs
            add column canonical_action_id uuid references canonical_actions(canonical_action_id),
            add column correlation_candidate_id uuid references semantic_correlation_candidates(candidate_id),
            add column control_health_id uuid,
            add column detection_match_id text references semantic_detection_matches(match_id)""")
    return reservation_pg


def _prepare(worker, begun, entities):
    return worker.execute("select prepare_password_producer_batch_v2(%s::jsonb,%s::jsonb,%s,%s,%s::text[]) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], begun["state_revision"], entities)).fetchone()["v"]


def _complete(worker, begun, payload, mode="advance"):
    return worker.execute("select complete_password_producer_batch_v2(%s::jsonb,%s::jsonb,%s,%s,%s,%s::jsonb) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], begun["state_revision"], mode, _j(payload))).fetchone()["v"]


def _read(worker):
    rows = worker.execute("select * from read_default_password_window_v2(%s::jsonb)", (_j(asdict(SCOPE)),)).fetchall()
    metadata = dict(rows[0]["metadata"])
    for name in ("read_from", "read_to", "finalizable_through"):
        metadata[name] = datetime.fromisoformat(metadata[name]).isoformat()
    events = tuple(pure.NativeEvent.from_row(SCOPE, row) for row in rows[1:])
    return metadata, events


def _payload(proposal, metadata):
    return dict(version=VERSION, state=proposal.state.document, window=metadata,
        diagnostics={code: dict(count=n, **{"from": None, "to": None}) for code, n in proposal.diagnostics},
        touched_episode_keys=[e.key for e in proposal.state.episodes])


def _queue(worker, documents, policies=None):
    if policies is None:
        from server.sli.semantic.semantic_risk import ScenarioSourceKind
        from server.sli.semantic.semantic_risk_runtime_repository import _enqueue_source
        for document in documents:
            signal_id = _digest({k: v for k, v in document.items() if k != "received_at_utc"})
            _enqueue_source(worker.cursor(), source_kind=ScenarioSourceKind.QW_SIGNAL, source_id=signal_id)
    else:
        # Deliberately incomplete queue for negative all-policy guard tests.
        for policy in policies:
            _jobs(worker, documents, policy=policy)


def _seed_recent(source, count=10):
    with _connection(source) as admin:
        at = admin.execute("select clock_timestamp()-interval '300 seconds' as t").fetchone()["t"]
        _seed(admin, count, at=at)


def _advance(worker, begun, *, state=None, jobs=True, mutate=None, history=(), retained=(), policies=None):
    metadata, events = _read(worker)
    proposal = pure.advance(RULE, state or pure.State(), events,
        now=datetime.fromisoformat(metadata["read_to"]), history=history, retained=retained)
    _prepare(worker, begun, sorted({e.entity for e in proposal.state.episodes}))
    for emission in proposal.emissions:
        old = next((e for e in (state.episodes if state else ()) if e.key == emission.episode_key and e.sequence), None)
        documents = _documents(emission, old.root_id if old else None)
        expected = None if old is None else dict(asdict(old.budget), last_sequence=old.sequence, last_emission_id=old.last_emission)
        _reserve(worker, begun["token"], begun["state_revision"], documents, expected)
        if jobs:
            _queue(worker, documents, policies)
    payload = _payload(proposal, metadata)
    if mutate:
        mutate(payload)
    return _complete(worker, begun, payload), proposal


def test_public_completion_commits_actual_root_jobs_state_members_and_health(coordinator_pg):
    _seed_recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        begun = _begin(worker)  # autocommit TxA
        with worker.transaction():
            result, proposal = _advance(worker, begun)
            assert result["status"] == "staged" and result["revision"] == 1
    with _connection(coordinator_pg) as admin:
        row = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert row["state_document"] == json.loads(_j(proposal.state.document))
        assert row["last_observed_token"] == begun["token"]
        assert row["health_status"] == "healthy"
        assert admin.execute("select count(*) as n from semantic_password_window_members").fetchone()["n"] == 10
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 1
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert ledger["first_ledger_revision"] == ledger["admitted_revision"] == 1


def test_public_completion_new_empty_poll_but_same_token_rejects(coordinator_pg):
    import psycopg
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            result, proposal = _advance(worker, begun)
        assert result["status"] == "staged"
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="attempt_conflict"):
            _complete(worker, begun, {})
        newer = _begin(worker)
        with worker.transaction():
            result, _ = _advance(worker, newer, state=proposal.state)
        assert result["revision"] == 2 and result["health"]["status"] == "healthy"


def test_public_completion_missing_job_rolls_back_then_same_token_failure(coordinator_pg):
    import psycopg
    _seed_recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="jobs_incomplete"):
            with worker.transaction():
                _advance(worker, begun, jobs=False)
        observed = worker.execute("select observe_password_failure_v2(%s::jsonb,%s::jsonb,%s,%s::jsonb) as v",
            (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], _j({"source_error": {"count": 1, "from": None, "to": None}}))).fetchone()["v"]
        assert observed is True
    with _connection(coordinator_pg) as admin:
        c = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert c["state_revision"] == 0 and c["watermark"] is None and c["health_status"] == "error"
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


@pytest.mark.parametrize("mutation", ["incomplete", "counter", "future", "attempt_time", "cutoff", "frozen_zero"])
def test_public_completion_rejects_invalid_observation_atomically(coordinator_pg, mutation):
    import psycopg
    if mutation == "frozen_zero":
        _seed_recent(coordinator_pg, count=1)
    def mutate(payload):
        if mutation == "incomplete": payload["window"]["native_checks_complete"] = False
        elif mutation == "counter": payload["window"]["native_checked_count"] = True
        elif mutation == "future":
            payload["window"]["read_to"] = (datetime.fromisoformat(payload["window"]["read_to"]) + timedelta(days=1)).isoformat()
        elif mutation == "attempt_time":
            for field in ("read_to", "read_from", "finalizable_through"):
                payload["window"][field] = (datetime.fromisoformat(payload["window"][field]) - timedelta(days=1)).isoformat()
            payload["state"]["watermark"] = payload["window"]["finalizable_through"]
        elif mutation == "cutoff": payload["state"]["watermark"] = payload["window"]["read_to"]
        else: payload["state"]["episodes"][0]["frozen"] = True
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.Error):
            with worker.transaction():
                _advance(worker, begun, mutate=mutate)
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select state_revision from semantic_password_checkpoints").fetchone()["state_revision"] == 0


def test_public_context_requires_token_and_bounds_entities(coordinator_pg):
    import psycopg
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        for entities in (["bad"], ["a" * 64] * 10001):
            with pytest.raises(psycopg.Error):
                _prepare(worker, begun, entities)
        with worker.transaction():
            assert _prepare(worker, begun, ["a" * 64])["barriers"] == []
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            _prepare(worker, dict(begun, token=begun["token"] + 1), [])


@pytest.mark.parametrize("case", ["proved", "unproved", "missing_native", "wrong_predecessor"])
def test_public_qualified_denial_uses_actual_minimum_delta_and_preserves_snapshot(coordinator_pg, case):
    import psycopg
    chain = [_root()]
    if case != "unproved":
        while len(chain) < 256:
            chain.append(_continue(chain[-1]))
    candidate = _continue(chain[-1])
    with _connection(coordinator_pg) as admin:
        # Consistent previously admitted immutable history; this is NOT the
        # successful public completion acceptance exercised by the first test.
        _historical(admin, chain)
        _native(admin, candidate.occurrences)
        before = admin.execute("select * from semantic_password_checkpoints").fetchone()
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        if case == "missing_native":
            admin.execute("delete from events_v2_core where id=%s", (int(candidate.endpoint.ref.native_id),))
        n_jobs = admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"]
    payload = dict(version=VERSION, episode_key=candidate.episode_key,
        predecessor=asdict(candidate.predecessor), endpoint=asdict(candidate.endpoint))
    if case == "wrong_predecessor":
        payload["predecessor"] = asdict(chain[0].seed)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        if case == "proved":
            with worker.transaction():
                _prepare(worker, begun, [candidate.entity])
                result = _complete(worker, begun, payload, "qualified_denial")
            assert result["status"] == "staged" and result["health"]["status"] == "partial"
        else:
            with pytest.raises(psycopg.Error):
                with worker.transaction():
                    _prepare(worker, begun, [candidate.entity])
                    _complete(worker, begun, payload, "qualified_denial")
    with _connection(coordinator_pg) as admin:
        after = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert after["watermark"] == before["watermark"]
        assert after["last_successful_cutoff"] == before["last_successful_cutoff"]
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == n_jobs
        current = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        for field in ("root_id", "last_sequence", "last_emission_id", "reserved_xml_bytes", "admitted_revision", "first_ledger_revision", "last_admitted_as_of"):
            assert current[field] == ledger[field]
        assert current["frozen"] is (case == "proved")
        frozen_state = pure.State.from_document(after["state_document"])
    if case == "proved":
        # Valid current empty reader after an old committed horizon: pure drops
        # the old working pointer, storage must retain AND track its barrier.
        with _connection(coordinator_pg, worker=True) as worker:
            newer = _begin(worker)
            with worker.transaction():
                context = _prepare(worker, newer, [])
                assert context["prelocked_entities"] == [candidate.entity]
                assert context["barriers"][0]["episode_key"] == candidate.episode_key
                result, proposal = _advance(worker, newer, state=frozen_state)
            assert proposal.state.episodes == () and proposal.state.epoch == 1
            assert result["health"]["status"] == "partial"
        with _connection(coordinator_pg) as admin:
            current = admin.execute("select * from semantic_password_episode_budgets").fetchone()
            assert current["tracking_epoch"] == 1
            assert current["tracking_through"] == proposal.state.watermark
            assert current["successor_episode_key"] is None


@pytest.mark.parametrize("reason", ["missing_target", "unclassified_failure", "ambiguous_failure", "conflicting_client", "missing_client"])
def test_public_completion_semantic_unattributed_loss_advances_partial_without_threshold(coordinator_pg, reason):
    _seed_recent(coordinator_pg, count=1)
    with _connection(coordinator_pg) as admin:
        at = admin.execute("select time_created_utc as t from events_v2_core where id=1").fetchone()["t"]
        xml = _xml(at)
        if reason == "missing_target": xml = xml.replace("fixture-account", "-")
        elif reason == "unclassified_failure": xml = xml.replace("0xc000006a", "garbage")
        elif reason == "ambiguous_failure": xml = xml.replace("</EventData>", '<Data Name="ResultCode">0</Data></EventData>')
        elif reason == "conflicting_client": xml = xml.replace("</EventData>", '<Data Name="ClientAddress">203.0.113.2</Data></EventData>')
        else: xml = xml.replace("203.0.113.1", "-")
        _replace_xml(admin, 1, xml)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            result, proposal = _advance(worker, begun)
        assert proposal.emissions == () and proposal.state.episodes == ()
        assert result["health"]["status"] == "partial"
        assert result["health"]["loss"][reason]["count_lower_bound"] == 1
        if reason == "missing_target":
            newer = _begin(worker)
            with worker.transaction():
                empty_result, empty = _advance(worker, newer, state=proposal.state)
            assert empty.emissions == () and empty_result["health"]["status"] == "partial"
            assert empty_result["health"]["loss"][reason]["count_lower_bound"] == 1
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select state_revision from semantic_password_checkpoints").fetchone()["state_revision"] == (2 if reason == "missing_target" else 1)
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


def _current_chain(admin, count, *, age=300):
    base = admin.execute("select clock_timestamp()-%s*interval '1 second' as t", (age,)).fetchone()["t"]
    def event(n):
        at = base + timedelta(microseconds=n)
        return pure.NativeEvent.from_row(SCOPE, dict(source_event_id=n, event_id=4625, occurred_at_utc=at,
            sha256=f"{n:064x}", source_xml=_xml(at, n)))
    origin_events = tuple(event(n) for n in range(1, 11))
    origin = tuple(e.member.witness for e in origin_events)
    entity = origin_events[0].member.entity(RULE)
    root = replace(_root(), entity=entity, episode_key=pure._key(RULE, 0, entity, origin[0]),
        seed=origin[0], root_proof=origin, origin=origin)
    chain = [root]
    for n in range(11, count + 10):
        previous = chain[-1]
        chain.append(replace(previous, sequence=previous.sequence + 1, root_proof=(), origin=(),
            predecessor=previous.endpoint, previous_id=previous.emission_id, new_events=(event(n).member.witness,),
            known_bad_password=1))
    candidate = event(count + 10)
    return chain, candidate


def test_public_normal_qualified_freeze_from_real_pure_has_no_emission_or_new_cost(coordinator_pg):
    with _connection(coordinator_pg) as admin:
        chain, candidate = _current_chain(admin, 256)
        _historical(admin, chain)
        _native(admin, tuple(w for e in chain for w in e.occurrences) + (candidate.member.witness,))
        state = pure.State.from_document(admin.execute("select state_document from semantic_password_checkpoints").fetchone()["state_document"])
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        jobs = admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"]
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            result, proposal = _advance(worker, begun, state=state, history=chain)
        assert proposal.emissions == () and proposal.state.episodes[0].frozen
        assert proposal.state.episodes[0].last == candidate.member.witness
        assert result["health"]["status"] == "partial"
    with _connection(coordinator_pg) as admin:
        current = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert current["frozen"] and current["tracking_through"] == proposal.state.watermark
        for field in ("reserved_ref_occurrences", "reserved_portions", "reserved_xml_bytes", "last_sequence", "last_admitted_as_of", "admitted_revision", "first_ledger_revision"):
            assert current[field] == ledger[field]
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == jobs


def test_public_reservation_freeze_without_atomic_final_state_cannot_commit(coordinator_pg):
    import psycopg
    chain = [_root()]
    while len(chain) < 256:
        chain.append(_continue(chain[-1]))
    candidate = _continue(chain[-1])
    with _connection(coordinator_pg) as admin:
        totals = _historical(admin, chain)
        _native(admin, candidate.occurrences)
    expected = dict(totals, last_sequence=256, last_emission_id=chain[-1].emission_id)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="freeze_completion_incomplete"):
            with worker.transaction():
                _prepare(worker, begun, [candidate.entity])
                result = _reserve(worker, begun["token"], begun["state_revision"], _documents(candidate, chain[0].emission_id), expected)
                assert result["status"] == "frozen"
    with _connection(coordinator_pg) as admin:
        assert not admin.execute("select frozen from semantic_password_episode_budgets").fetchone()["frozen"]


def _event(native_id, at):
    return pure.NativeEvent.from_row(SCOPE, dict(source_event_id=native_id, event_id=4625,
        occurred_at_utc=at, sha256=f"{native_id:064x}", source_xml=_xml(at, native_id)))


def _frozen_history(admin, *, age=820, covered=400):
    # Consistent committed past lifetime + completed coverage, not public
    # completion evidence. A later real reader and public finalizer are tested.
    chain, rejected = _current_chain(admin, 256, age=age)
    _historical(admin, chain)
    _native(admin, (chain[0].seed, chain[-1].endpoint, rejected.member.witness))
    old = pure.State.from_document(admin.execute("select state_document from semantic_password_checkpoints").fetchone()["state_document"])
    episode = replace(old.episodes[0], frozen=True, last=rejected.member.witness)
    through = episode.last.at + timedelta(seconds=covered)
    state = replace(old, watermark=through, episodes=(episode,))
    begun = _begin(admin)
    with admin.transaction():
        admin.execute("""update semantic_password_episode_budgets set frozen=true,frozen_at=clock_timestamp(),
            frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,
            tracking_endpoint=%s::jsonb,tracking_epoch=0,tracking_through=%s""", (_j(episode.last), through))
        admin.execute("""update semantic_password_checkpoints set state_document=%s::jsonb,state_revision=state_revision+1,
            watermark=%s,last_observed_token=%s,health_status='partial',health_reason='episode_evidence_budget_exhausted'""",
            (_j(state.document), through, begun["token"]))
    return chain, state


def test_public_frozen_tracking_uses_bridging_500_then_700_in_one_real_window(coordinator_pg):
    with _connection(coordinator_pg) as admin:
        chain, state = _frozen_history(admin)
        old_endpoint = state.episodes[0].last
        bridge = _event(1001, old_endpoint.at + timedelta(seconds=500))
        last = _event(1002, old_endpoint.at + timedelta(seconds=700))
        _native(admin, (bridge.member.witness, last.member.witness))
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            result, proposal = _advance(worker, begun, state=state)
        assert proposal.emissions == () and proposal.state.episodes[0].key == state.episodes[0].key
        assert proposal.state.episodes[0].last == last.member.witness
        assert result["health"]["status"] == "partial"
    with _connection(coordinator_pg) as admin:
        row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert row["successor_episode_key"] is None and row["barrier_unresolved"]
        assert row["tracking_endpoint"] == json.loads(_j(last.member.witness))
        assert row["tracking_through"] == proposal.state.watermark
        assert row["last_emission_id"] == chain[-1].emission_id


def test_public_provisional_601_seed_holds_barrier_without_authorization(coordinator_pg):
    with _connection(coordinator_pg) as admin:
        _, state = _frozen_history(admin)
        old = state.episodes[0]
        pending = _event(1001, old.last.at + timedelta(seconds=601))
        _native(admin, (pending.member.witness,))
        retained = (_event(int(old.last.ref.native_id), old.last.at),)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            result, proposal = _advance(worker, begun, state=state, retained=retained)
        assert proposal.emissions == () and proposal.state.episodes[0].sequence == 0
        assert proposal.state.episodes[0].seed == pending.member.witness
        assert result["health"]["status"] == "partial"
    with _connection(coordinator_pg) as admin:
        row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert row["successor_episode_key"] is None and row["barrier_unresolved"]
        assert row["tracking_endpoint"] == json.loads(_j(old.last))
        assert row["tracking_through"] == proposal.state.watermark


def _track(worker, begun, key, witness, metadata, epoch=0):
    return worker.execute("select track_password_frozen_entity_v2(%s::jsonb,%s::jsonb,%s,%s,%s,%s::jsonb,%s,%s,%s) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], begun["state_revision"], key,
         _j(witness), epoch, datetime.fromisoformat(metadata["read_from"]), datetime.fromisoformat(metadata["finalizable_through"]))).fetchone()["v"]


def test_public_601_then_empty_coverage_1200_admits_only_actual_1202_successor(coordinator_pg):
    import psycopg
    with _connection(coordinator_pg) as admin:
        _, frozen = _frozen_history(admin, age=1800, covered=1200)
        barrier = frozen.episodes[0]
        pending = _event(1000, barrier.last.at + timedelta(seconds=601))
        _native(admin, (pending.member.witness,))
        provisional = pure.Episode(pure._key(RULE, 0, barrier.entity, pending.member.witness), barrier.entity,
            pending.member.witness, pending.member.witness, prequalification=(pending.member.witness,))
        # Stored valid past empty-poll snapshot W1200: K601 is retained at
        # window lower600, with no release relation. First-seed behavior itself
        # is public-tested above; no fake DB clock or current reader is used.
        state = replace(frozen, window=(pending.member,), episodes=(provisional,))
        begun = _begin(admin)
        with admin.transaction():
            admin.execute("update semantic_password_checkpoints set state_document=%s::jsonb,state_revision=state_revision+1,last_observed_token=%s",
                (_j(state.document), begun["token"]))
            admin.execute("insert into semantic_password_window_members(scope_digest,pin,member_document) select scope_digest,pin,%s::jsonb from semantic_password_checkpoints",
                (_j(pending.member),))
        current = tuple(_event(1001 + n, barrier.last.at + timedelta(seconds=1202, microseconds=n)) for n in range(10))
        _native(admin, tuple(event.member.witness for event in current))
    retained = (pending, _event(int(barrier.last.ref.native_id), barrier.last.at))
    with _connection(coordinator_pg, worker=True) as worker:
        speculative = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="successor_admission_incomplete"):
            with worker.transaction():
                metadata, _ = _read(worker)
                _prepare(worker, speculative, [barrier.entity])
                assert _track(worker, speculative, barrier.key, pending.member.witness, metadata)["status"] == "successor_authorized"
        begun = _begin(worker)
        with worker.transaction():
            metadata, incoming = _read(worker)
            proposal = pure.advance(RULE, state, incoming, retained=retained, now=datetime.fromisoformat(metadata["read_to"]))
            assert len(proposal.emissions) == 1 and proposal.emissions[0].seed == current[0].member.witness
            _prepare(worker, begun, [barrier.entity])
            assert _track(worker, begun, barrier.key, proposal.emissions[0].seed, metadata)["status"] == "successor_authorized"
            documents = _documents(proposal.emissions[0])
            _reserve(worker, begun["token"], begun["state_revision"], documents)
            _queue(worker, documents)
            result = _complete(worker, begun, _payload(proposal, metadata))
        assert result["status"] == "staged"
    with _connection(coordinator_pg) as admin:
        rows = admin.execute("select * from semantic_password_episode_budgets order by first_ledger_revision").fetchall()
        assert len(rows) == 2 and not rows[0]["barrier_unresolved"]
        assert rows[0]["successor_episode_key"] == rows[1]["episode_key"] == proposal.emissions[0].episode_key
        assert rows[0]["successor_episode_key"] != provisional.key
        assert rows[1]["predecessor_episode_key"] == barrier.key
        assert rows[0]["first_ledger_revision"] == rows[0]["admitted_revision"] == 1
        assert rows[1]["first_ledger_revision"] == rows[1]["admitted_revision"] == result["revision"]


def test_public_root_continuation_replay_and_genuinely_new_empty_observation(coordinator_pg):
    _seed_recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with worker.transaction():
            _, first = _advance(worker, begun)
        with _connection(coordinator_pg) as admin:
            before = admin.execute("select state_revision,last_completed_at,last_successful_cutoff from semantic_password_checkpoints").fetchone()
        replay_token = _begin(worker)
        replay = _reserve(worker, replay_token["token"], replay_token["state_revision"], _documents(first.emissions[0]))
        assert replay["status"] == "replay" and replay["delta"] == dict(ref_occurrences=0, portions=0, xml_bytes=0)
        with _connection(coordinator_pg) as admin:
            assert admin.execute("select state_revision,last_completed_at,last_successful_cutoff from semantic_password_checkpoints").fetchone() == before
            at = admin.execute("select clock_timestamp()-interval '120.000001 seconds' as t").fetchone()["t"]
            _seed(admin, start=11, at=at)
        begun = _begin(worker)
        with worker.transaction():
            _, second = _advance(worker, begun, state=first.state, history=first.emissions)
        assert len(second.emissions) == 1 and second.emissions[0].sequence == 2
        newer = _begin(worker)
        with worker.transaction():
            result, empty = _advance(worker, newer, state=second.state, history=first.emissions + second.emissions)
        assert empty.emissions == () and result["revision"] == 3
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 2
        row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert row["first_ledger_revision"] == 1 and row["admitted_revision"] == 2


@pytest.mark.parametrize("direction", ["producer_first", "publisher_first"])
def test_public_context_and_publisher_hold_both_lock_directions(coordinator_pg, direction):
    import psycopg
    _seed_recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as producer:
        initial = _begin(producer)
        with producer.transaction():
            _, first = _advance(producer, initial)
        episode = first.state.episodes[0]
        begun = _begin(producer)
        with _connection(coordinator_pg, worker=True) as publisher:
            producer.execute("set lock_timeout='200ms'")
            publisher.execute("set lock_timeout='200ms'")
            def publication_lock():
                return publisher.execute("select lock_password_publication_v2(%s::jsonb,%s::jsonb,%s)",
                    (_j(asdict(SCOPE)), _j(EXECUTION), episode.key)).fetchone()
            if direction == "producer_first":
                with producer.transaction():
                    _prepare(producer, begun, [episode.entity])
                    with pytest.raises(psycopg.errors.LockNotAvailable):
                        with publisher.transaction():
                            publication_lock()
            else:
                with publisher.transaction():
                    publication_lock()
                    with pytest.raises(psycopg.errors.LockNotAvailable):
                        with producer.transaction():
                            _prepare(producer, begun, [episode.entity])


@pytest.mark.parametrize("all_jobs", [True, False])
def test_public_completion_requires_all_policies_and_all_immutable_portions(coordinator_pg, all_jobs):
    import psycopg
    second = "fixture-password-second-coordinator"
    definition = {"source_selector": {"execution": EXECUTION}}
    digest = bytes.fromhex(_digest(definition))
    with _connection(coordinator_pg) as admin:
        admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values(%s,1,'qw_signal','draft',%s::jsonb,%s)",
            (second, _j(definition), digest))
        admin.execute("insert into semantic_risk_policy_subscriptions values(%s,1,'qw_signal',%s,%s)", (second, EXECUTION["rule_id"], digest))
        admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id=%s", (second,))
        admin.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled) values(%s,1,true)", (second,))
    _seed_recent(coordinator_pg, count=300 if all_jobs else 10)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        if all_jobs:
            with worker.transaction():
                result, _ = _advance(worker, begun)
            assert result["status"] == "staged"
        else:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="jobs_incomplete"):
                with worker.transaction():
                    _advance(worker, begun, policies=(POLICY,))
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == (2 if all_jobs else 0)
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == (4 if all_jobs else 0)


def test_public_completion_rechecks_native_after_reservation_before_state(coordinator_pg):
    import psycopg
    _seed_recent(coordinator_pg)
    def mutate(_):
        with _connection(coordinator_pg) as admin:
            at = admin.execute("select time_created_utc as t from events_v2_core where id=1").fetchone()["t"]
            _replace_xml(admin, 1, _xml(at, 1).replace("fixture-account", "fixture-accounx"))
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="retained_unavailable"):
            with worker.transaction():
                _advance(worker, begun, mutate=mutate)
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select state_revision from semantic_password_checkpoints").fetchone()["state_revision"] == 0
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 0


def test_public_completion_staged_result_then_real_deferred_commit_failure_rolls_back(coordinator_pg):
    import psycopg
    _seed_recent(coordinator_pg)
    with _connection(coordinator_pg) as admin:
        # Test-only PostgreSQL COMMIT fault, not an owner final-State substitute.
        admin.execute("""create function public.fixture_b2_commit_fault() returns trigger language plpgsql as $$
            begin raise exception 'fixture_b2_commit_fault' using errcode='55000'; end $$;
            create constraint trigger fixture_b2_commit_fault after insert on semantic_password_window_members
                deferrable initially deferred for each row execute function fixture_b2_commit_fault()""")
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="fixture_b2_commit_fault"):
            with worker.transaction():
                result, _ = _advance(worker, begun)
                assert result["status"] == "staged"
        assert worker.execute("select observe_password_failure_v2(%s::jsonb,%s::jsonb,%s,%s::jsonb) as v",
            (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], _j({"source_error": {"count": 1, "from": None, "to": None}}))).fetchone()["v"]
    with _connection(coordinator_pg) as admin:
        row = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert row["state_revision"] == 0 and row["last_successful_cutoff"] is None
        assert row["health_status"] == "error"
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


def test_public_completion_requires_prelock_and_keeps_standalone_state_closed(coordinator_pg):
    import psycopg
    _seed_recent(coordinator_pg, count=1)
    with _connection(coordinator_pg, worker=True) as worker:
        begun = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="entity_prelock_required"):
            with worker.transaction():
                metadata, incoming = _read(worker)
                proposal = pure.advance(RULE, pure.State(), incoming, now=datetime.fromisoformat(metadata["read_to"]))
                _complete(worker, begun, _payload(proposal, metadata))
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="state_authority_unavailable"):
            worker.execute("select commit_password_state_v2(%s::jsonb,%s::jsonb,%s,%s,%s::jsonb)",
                (_j(asdict(SCOPE)), _j(EXECUTION), begun["token"], 0, _j(proposal.state.document)))
    with _connection(coordinator_pg) as admin:
        for name in ("prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[])",
                     "complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)"):
            for role in ("adlog_user", "adlog_storage_worker"):
                assert not admin.execute("select has_function_privilege(%s,%s,'EXECUTE') as yes", (role, name)).fetchone()["yes"]
        assert not admin.execute("select has_table_privilege('adlog_semantic_worker','semantic_password_checkpoints','UPDATE') as yes").fetchone()["yes"]
