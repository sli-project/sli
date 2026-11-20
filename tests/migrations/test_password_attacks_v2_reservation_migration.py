"""Lifetime storage: actual native candidate costs, immutable history and atomic PG guards.

Owner-only historical/next-State fixtures explicitly model the absent B2 coordinator;
no public State success or independently SQL-verified detector semantics is claimed.
"""
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import NAMESPACE_URL, uuid5

import pytest

from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic.password_attack_v2_portions import contexts_from_emission
from server.sli.semantic.qw_input import _digest
from server.sli.storage.evidence_ref import EvidenceRef
from tests.migrations.test_password_attacks_v2_migration import (
    SCOPE, _connection, _replace_xml, _seed, _xml,
    acl_pg as acl_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
RULE = pure.Rule(SCOPE, "brute")
EXECUTION = RULE.execution
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)
POLICY = "fixture-password-storage"


def _j(value):
    return json.dumps(pure._pack(value), sort_keys=True, ensure_ascii=True, allow_nan=False)


def _begin(conn):
    return conn.execute("select public.begin_password_attempt(%s::jsonb,%s::jsonb) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION))).fetchone()["v"]


def _reserve(conn, token, revision, documents, expected=None):
    return conn.execute("select public.reserve_password_episode_emission(%s::jsonb,%s::jsonb,%s,%s,%s::jsonb,%s::jsonb) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), token, revision, None if expected is None else _j(expected), _j(documents))).fetchone()["v"]


def _witness(native_id):
    at = BASE + timedelta(microseconds=native_id)
    xml = _xml(at, native_id)
    return pure.Witness(EvidenceRef("core_event", str(native_id), f"{native_id:064x}", SCOPE),
        at, sha256(xml.encode()).hexdigest(), len(xml.encode()))


def _root(n=10):
    origin = tuple(_witness(i) for i in range(1, n + 1))
    return pure.Emission(pure._key(RULE, 0, "a" * 64, origin[0]), RULE.pin, 0, "a" * 64, 1,
        origin[0], origin, (), None, None, n, 0, 0, 1, origin)


def _continue(previous):
    fresh = _witness(int(previous.endpoint.ref.native_id) + 1)
    return replace(previous, sequence=previous.sequence + 1, root_proof=(), origin=(),
        predecessor=previous.endpoint, previous_id=previous.emission_id, new_events=(fresh,),
        known_bad_password=1, unknown_account=0, other_failure=0, distinct_names=1)


def _documents(emission, root_id=None):
    result = []
    for context, portion in zip(contexts_from_emission(emission, original_root_id=root_id), emission.ref_portions):
        result.append(dict(kind="threshold", rule_id=EXECUTION["rule_id"], rule_version=2,
            rule_sha256=EXECUTION["rule_sha256"], policy_revision=1, evaluation_mode="enabled",
            entity_key=emission.entity, episode_key=emission.episode_key,
            occurred_at_utc=emission.endpoint.at.isoformat(), received_at_utc=BASE.isoformat(),
            evidence_refs=[asdict(w.ref) for w in sorted(portion, key=lambda w: w.ref.params)],
            base_severity="medium", effective_severity="medium", severity_reasons=[], quality="good",
            conclusion_state="observed", password_context=context))
    return result


@pytest.fixture
def reservation_pg(password_pg):
    with _connection(password_pg) as admin:
        # Native265's unrelated queue was reduced to five columns. Restore only
        # real029 identities/constraints +228 QW FK needed by THIS new PG suite.
        admin.execute("""alter table semantic_risk_evaluation_jobs
            add column job_id uuid primary key,
            add column source_reference text not null check(length(source_reference) between 1 and 320),
            add column idempotency_key bytea not null unique check(octet_length(idempotency_key)=32),
            add column evaluation_status text not null default 'queued',
            add constraint fixture_password_qw_fk foreign key(qw_signal_id) references semantic_qw_signals(signal_id) on delete restrict,
            add constraint fixture_password_job_identity unique(policy_id,policy_version,source_kind,source_reference,evaluation_mode)""")
        # Current admin is bound ONLY in the disposable fixture, so owner-only
        # historical/state seeds can exercise final deferred checks honestly.
        admin.execute("""insert into finding_evidence_source_bindings
            select oid,rolname,%s,%s,%s,%s,'','core_event',7,null,agent_id
            from pg_roles cross join (select agent_id from finding_evidence_source_bindings limit 1) b
            where rolname=session_user""",
            (SCOPE.installation_id, SCOPE.plugin_id, SCOPE.source_instance_id, SCOPE.source_generation))
        definition = {"source_selector": {"execution": EXECUTION}}
        digest = bytes.fromhex(_digest(definition))
        admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values(%s,1,'qw_signal','draft',%s::jsonb,%s)",
            (POLICY, _j(definition), digest))
        admin.execute("insert into semantic_risk_policy_subscriptions values(%s,1,'qw_signal',%s,%s)",
            (POLICY, EXECUTION["rule_id"], digest))
        admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id=%s", (POLICY,))
        admin.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled) values(%s,1,true)", (POLICY,))
    return password_pg


def _native(admin, witnesses):
    for witness in {w.ref.native_id: w for w in witnesses}.values():
        native_id = int(witness.ref.native_id)
        _seed(admin, start=native_id, at=witness.at)
        _replace_xml(admin, native_id, _xml(witness.at, native_id))


def _jobs(admin, documents, wrong=False, *, policy=POLICY):
    definition = {"source_selector": {"execution": EXECUTION}}
    for document in documents:
        signal_id = _digest({k: v for k, v in document.items() if k != "received_at_utc"})
        identity = bytes.fromhex(_digest(dict(policy_id=policy, policy_version=1, policy_sha256=_digest(definition),
            source_kind="qw_signal", source_id=signal_id, evaluation_mode="enabled")))
        admin.execute("""insert into semantic_risk_evaluation_jobs(job_id,policy_id,policy_version,source_kind,
            source_reference,evaluation_mode,idempotency_key,qw_signal_id) values(%s,%s,1,'qw_signal',%s,'enabled',%s,%s)""",
            (str(uuid5(NAMESPACE_URL, "adlog:risk-evaluation:" + identity.hex())), policy, signal_id,
             bytes.fromhex("0" * 64) if wrong else identity, signal_id))


def _owner_final_state(admin, emission, totals, token, revision, root_id):
    episode = pure.Episode(emission.episode_key, emission.entity, emission.seed, emission.endpoint,
        root_id=root_id, last_emission=emission.emission_id, sequence=emission.sequence,
        budget=pure.Budget(**totals))
    state = pure.State(RULE.pin, emission.endpoint.at, emission.epoch, (), (episode,)).document
    admin.execute("""update semantic_password_checkpoints set state_document=%s::jsonb,state_revision=%s,
        watermark=%s,coverage_epoch=%s,history_started=true,last_observed_token=%s
        where pin=%s""", (_j(state), revision, emission.endpoint.at, emission.epoch, token, RULE.pin))


def _owner_complete_frozen_state(admin, episode_keys):
    # OWNER storage fixture only: complete the ledger freeze in the same tx.
    # This does not stand in for the public producer/completion protocol.
    assert admin.info.transaction_status == 2
    checkpoint = admin.execute("select * from semantic_password_checkpoints where pin=%s for update",
        (RULE.pin,)).fetchone()
    rows = admin.execute("""select * from semantic_password_episode_budgets
        where pin=%s and episode_key=any(%s) order by episode_key""",
        (RULE.pin, list(episode_keys))).fetchall()
    assert {row["episode_key"] for row in rows} == set(episode_keys)
    assert len({row["entity"] for row in rows}) == len(rows)
    current = pure.State.from_document(checkpoint["state_document"])
    episodes = {episode.entity: episode for episode in current.episodes}
    for row in rows:
        assert row["frozen"] and row["last_sequence"] > 0
        assert row["tracking_endpoint"] is not None
        episodes[row["entity"]] = pure.Episode(row["episode_key"], row["entity"],
            pure._witness(row["seed"]), pure._witness(row["tracking_endpoint"]),
            root_id=row["root_id"], last_emission=row["last_emission_id"], sequence=row["last_sequence"],
            budget=pure.Budget(row["reserved_ref_occurrences"], row["reserved_portions"], row["reserved_xml_bytes"]),
            frozen=True)
    # One working episode per entity; retain all other entities and the window.
    state = replace(current, episodes=tuple(episodes[entity] for entity in sorted(episodes)),
        watermark=max(current.watermark, *(episodes[row["entity"]].last.at for row in rows)))
    revision = max(checkpoint["state_revision"], *(row["admitted_revision"] for row in rows)) + 1
    admin.execute("""update semantic_password_checkpoints set state_document=%s::jsonb,state_revision=%s,
        watermark=%s,coverage_epoch=%s,history_started=true,last_observed_token=%s where pin=%s""",
        (_j(state.document), revision, state.watermark, state.epoch, checkpoint["active_token"], RULE.pin))


def _admit(admin, emission, root_id=None, expected=None, jobs=True):
    begun = _begin(admin)
    documents = _documents(emission, root_id)
    with admin.transaction():
        result = _reserve(admin, begun["token"], begun["state_revision"], documents, expected)
        if result["status"] == "reserved":
            _owner_final_state(admin, emission, result["totals"], begun["token"], begun["state_revision"] + 1,
                emission.emission_id if emission.sequence == 1 else root_id)
            if jobs: _jobs(admin, documents)
        elif result["status"] == "frozen":
            _owner_complete_frozen_state(admin, (emission.episode_key,))
    return result


def _ledger(admin):
    row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
    return dict(last_sequence=row["last_sequence"], last_emission_id=row["last_emission_id"],
        ref_occurrences=row["reserved_ref_occurrences"], portions=row["reserved_portions"], xml_bytes=row["reserved_xml_bytes"])


def _historical(admin, chain, omit_last_portion=False, *, revision=1, first_revision=None):
    # Already-admitted immutable historical fixture, not a public past native
    # admission claim. The next candidate's actual content is always freshly read.
    first_revision = revision if first_revision is None else first_revision
    token = _begin(admin)
    first, last = chain[0], chain[-1]
    totals = dict(ref_occurrences=sum(len(e.occurrences) for e in chain),
        portions=sum(e.portions for e in chain), xml_bytes=sum(w.xml_bytes for e in chain for w in e.occurrences))
    with admin.transaction():
        admin.execute("""insert into semantic_password_episode_budgets(scope_digest,pin,episode_key,scope_json,execution_json,
            coverage_epoch,entity,seed,root_id,last_sequence,last_emission_id,last_admitted_endpoint,
            reserved_ref_occurrences,reserved_portions,reserved_xml_bytes,last_admitted_as_of,admitted_revision,first_ledger_revision,
            admitted_attempt_token,admission_xid,admission_first_sequence)
            select scope_digest,pin,%s,%s::jsonb,%s::jsonb,0,%s,%s::jsonb,%s,%s,%s,%s::jsonb,%s,%s,%s,clock_timestamp(),%s,%s,%s,pg_current_xact_id(),%s
            from semantic_password_checkpoints""", (first.episode_key, _j(asdict(SCOPE)), _j(EXECUTION), first.entity,
            _j(asdict(first.seed)), first.emission_id, last.sequence, last.emission_id, _j(asdict(last.endpoint)),
            totals["ref_occurrences"], totals["portions"], totals["xml_bytes"], revision, first_revision, token["token"], last.sequence))
        for emission in chain:
            documents = _documents(emission, first.emission_id)
            for d in (documents[:-1] if omit_last_portion else documents):
                signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
                admin.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,'enabled',%s::jsonb)",
                    (signal_id, _j(d)))
        _owner_final_state(admin, last, totals, token["token"], revision, first.emission_id)
        _jobs(admin, _documents(last, first.emission_id)[:-1] if omit_last_portion else _documents(last, first.emission_id))
    return totals


def test_episode_lookup_absent_fails_closed(password_pg):
    import psycopg
    with _connection(password_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_episode_absent"):
            worker.execute("select * from public.read_password_episode_portions_v2(%s::jsonb,%s::jsonb,%s)",
                (_j(asdict(SCOPE)), _j(EXECUTION), "a" * 64)).fetchall()


def test_actual_native_root_stage_and_reserve_only_commit_roll_back(reservation_pg):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin: _native(admin, emission.occurrences)
    with _connection(reservation_pg, worker=True) as worker:
        token = _begin(worker)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="checkpoint_admission_incomplete"):
            with worker.transaction():
                result = _reserve(worker, token["token"], 0, _documents(emission))
                assert result["status"] == "reserved"
                assert result["delta"]["xml_bytes"] == sum(w.xml_bytes for w in emission.occurrences)
    with _connection(reservation_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_password_episode_budgets").fetchone()["n"] == 0
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0
        assert admin.execute("select state_revision from semantic_password_checkpoints").fetchone()["state_revision"] == 0


def test_owner_simulated_coordinator_commits_complete_storage_and_reads_exact_documents(reservation_pg):
    emission = _root(300)
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        result = _admit(admin, emission)
        assert result["status"] == "reserved" and result["totals"]["portions"] == 2
    with _connection(reservation_pg, worker=True) as worker:
        rows = worker.execute("select * from read_password_episode_portions_v2(%s::jsonb,%s::jsonb,%s)",
            (_j(asdict(SCOPE)), _j(EXECUTION), emission.episode_key)).fetchall()
        assert [row["document_json"] for row in rows] == _documents(emission)
        assert [row["signal_id"] for row in rows] == result["signal_ids"]


@pytest.mark.parametrize("case", ["missing_jobs", "wrong_job_identity"])
def test_final_state_without_exact_jobs_fails_atomic_commit(reservation_pg, case):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        begun = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="jobs_incomplete"):
            with admin.transaction():
                result = _reserve(admin, begun["token"], 0, _documents(emission))
                _owner_final_state(admin, emission, result["totals"], begun["token"], 1, emission.emission_id)
                if case == "wrong_job_identity": _jobs(admin, _documents(emission), wrong=True)
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


@pytest.mark.parametrize("case", ["xml_digest", "xml_length", "normalized", "receipt", "unavailable"])
def test_current_candidate_native_commitments_are_not_caller_costs(reservation_pg, case):
    import psycopg
    emission = _root()
    documents = _documents(emission)
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        if case in ("xml_digest", "xml_length"):
            original = _xml(emission.endpoint.at, int(emission.endpoint.ref.native_id))
            changed = original.replace("fixture-account", "fixture-accounx") if case == "xml_digest" else original + " "
            _replace_xml(admin, int(emission.endpoint.ref.native_id), changed)
        elif case == "normalized": admin.execute("update events_v2_core set normalized_hash=decode(repeat('f',64),'hex') where id=10")
        elif case == "receipt": admin.execute("delete from sli_agent_receipts where packet_id=md5('password-v2-fixture-10')::uuid")
        else: admin.execute("delete from events_v2_core where id=10")
        begun = _begin(admin)
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="retained_unavailable"):
            _reserve(admin, begun["token"], 0, documents)
        assert admin.execute("select count(*) as n from semantic_password_episode_budgets").fetchone()["n"] == 0


@pytest.mark.parametrize("mutation", ["emission_hash", "counter", "tuple_type", "portion_gap", "ref_order", "foreign_scope", "missing_context", "extra_context", "null_severity"])
def test_sql_typed_full_emission_hash_and_portion_guards(reservation_pg, mutation):
    import psycopg
    documents = _documents(_root())
    d = documents[0]
    if mutation == "emission_hash": d["password_context"]["emission_id"] = "f" * 64
    elif mutation == "counter": d["password_context"]["known_bad_password"] += 1
    elif mutation == "tuple_type": d["password_context"]["occurrences"][0][3] = True
    elif mutation == "portion_gap": d["password_context"]["portion_index"] = 1
    elif mutation == "ref_order": d["evidence_refs"].reverse()
    elif mutation == "foreign_scope": d["evidence_refs"][0]["scope"]["source_generation"] = "foreign"
    elif mutation == "missing_context": d.pop("password_context")
    elif mutation == "extra_context": d["password_context"]["verified"] = True
    else: d["base_severity"] = None
    with _connection(reservation_pg) as admin:
        begun = _begin(admin)
        with pytest.raises(psycopg.Error): _reserve(admin, begun["token"], 0, documents)


def test_exact_older_replay_does_not_reserve_enqueue_or_update_state(reservation_pg):
    first, = (_root(),)
    second = _continue(first)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences + second.occurrences)
        _admit(admin, first)
        _admit(admin, second, first.emission_id, _ledger(admin))
        before = admin.execute("select state_revision,state_document from semantic_password_checkpoints").fetchone()
        count = admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"]
        token = _begin(admin)
        docs = _documents(first)
        docs[0]["received_at_utc"] = (BASE + timedelta(days=1)).isoformat()
        replay = _reserve(admin, token["token"], before["state_revision"], docs)
        assert replay["status"] == "replay" and replay["delta"] == dict(ref_occurrences=0, portions=0, xml_bytes=0)
        assert admin.execute("select state_revision,state_document from semantic_password_checkpoints").fetchone() == before
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == count


@pytest.mark.parametrize("bound,over", [("refs", False), ("refs", True), ("portions", False), ("portions", True), ("bytes", False), ("bytes", True)])
def test_actual_candidate_delta_hits_lifetime_boundary_or_freezes_whole_emission(reservation_pg, bound, over):
    if bound == "refs":
        chain = [_root(9999 if over else 9998)]
    elif bound == "portions":
        chain = [_root()]
        while len(chain) < (256 if over else 255): chain.append(_continue(chain[-1]))
    else:
        first = _root()
        candidate = _continue(first)
        desired = 33554432 - sum(w.xml_bytes for w in candidate.occurrences) + int(over)
        witnesses = list(first.origin)
        extra = desired - sum(w.xml_bytes for w in witnesses)
        for index in range(9):
            amount = min(extra, 4194304 - witnesses[index].xml_bytes)
            witnesses[index] = replace(witnesses[index], xml_bytes=witnesses[index].xml_bytes + amount)
            extra -= amount
        assert extra == 0
        first = replace(first, origin=tuple(witnesses), root_proof=tuple(witnesses), seed=witnesses[0])
        # Changes to Witness seed commitments do not change seed.ref-based episode key.
        chain = [first]
    first, last = chain[0], chain[-1]
    candidate = _continue(last)
    with _connection(reservation_pg) as admin:
        _historical(admin, chain)
        _native(admin, candidate.occurrences)
        before = _ledger(admin)
        result = _admit(admin, candidate, first.emission_id, before)
        if over:
            assert result["status"] == "frozen" and result["totals"] == {k: before[k] for k in ("ref_occurrences", "portions", "xml_bytes")}
            assert result["delta"] == dict(ref_occurrences=0, portions=0, xml_bytes=0)
            assert _ledger(admin) == before
            row = admin.execute("select frozen,barrier_unresolved from semantic_password_episode_budgets").fetchone()
            assert row == dict(frozen=True, barrier_unresolved=True)
        else:
            assert result["status"] == "reserved"
            assert result["totals"][dict(refs="ref_occurrences", portions="portions", bytes="xml_bytes")[bound]] == dict(refs=10000, portions=256, bytes=33554432)[bound]
        assert result["delta"]["xml_bytes"] in (0, sum(w.xml_bytes for w in candidate.occurrences))


def test_private_ledger_and_helpers_are_not_runtime_or_report_authority(reservation_pg):
    import psycopg
    with _connection(reservation_pg, worker=True) as worker:
        for query in ("select * from semantic_password_episode_budgets", "select public.password_v2_native_cost('{}','[]')"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege): worker.execute(query)
    with _connection(reservation_pg) as admin:
        for role in ("adlog_user", "adlog_storage_worker", "adlog_semantic_worker"):
            assert not admin.execute("select has_table_privilege(%s,'semantic_password_episode_budgets','SELECT') as ok", (role,)).fetchone()["ok"]


def test_public_state_commit_remains_blocked_with_lifetime_objects(reservation_pg):
    import psycopg
    with _connection(reservation_pg, worker=True) as worker:
        token = _begin(worker)
        state = pure.State(RULE.pin).document
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="state_authority_unavailable"):
            worker.execute("select commit_password_state_v2(%s::jsonb,%s::jsonb,%s,0,%s::jsonb)",
                (_j(asdict(SCOPE)), _j(EXECUTION), token["token"], _j(state)))

def _freeze(admin):
    with admin.transaction():
        rows = admin.execute("""update semantic_password_episode_budgets set frozen=true,frozen_at=clock_timestamp(),
            frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,
            tracking_endpoint=last_admitted_endpoint,tracking_epoch=coverage_epoch,
            tracking_through=(last_admitted_endpoint->>'at')::timestamptz returning episode_key""").fetchall()
        _owner_complete_frozen_state(admin, tuple(row["episode_key"] for row in rows))


def _lock(conn, episode):
    return conn.execute("select public.lock_password_publication_v2(%s::jsonb,%s::jsonb,%s) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), episode)).fetchone()["v"]


def _track(conn, token, revision, episode, endpoint, epoch, start, end):
    return conn.execute("select public.track_password_frozen_entity_v2(%s::jsonb,%s::jsonb,%s,%s,%s,%s::jsonb,%s,%s,%s) as v",
        (_j(asdict(SCOPE)), _j(EXECUTION), token, revision, episode, _j(asdict(endpoint)), epoch, start, end)).fetchone()["v"]


def _at(native_id, seconds):
    at = BASE + timedelta(seconds=seconds)
    xml = _xml(at, native_id)
    return pure.Witness(EvidenceRef("core_event", str(native_id), f"{native_id:064x}", SCOPE),
        at, sha256(xml.encode()).hexdigest(), len(xml.encode()))


def _new_root(witnesses, epoch=1, entity="a" * 64):
    return pure.Emission(pure._key(RULE, epoch, entity, witnesses[0]), RULE.pin, epoch, entity, 1,
        witnesses[0], tuple(witnesses), (), None, None, len(witnesses), 0, 0, 1, tuple(witnesses))


@pytest.mark.parametrize("legacy", [False, True])
def test_direct_qw_orphan_rejected_but_legacy_insert_preserved(reservation_pg, legacy):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin: _native(admin, emission.occurrences)
    d = _documents(emission)[0]
    if legacy:
        d.pop("password_context")
        d["rule_version"] = 1
    signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
    with _connection(reservation_pg, worker=True) as worker:
        if legacy:
            worker.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,'enabled',%s::jsonb)", (signal_id, _j(d)))
        else:
            with pytest.raises(psycopg.errors.CheckViolation, match="password_v2_qw_identity"):
                worker.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,'enabled',%s::jsonb)", (signal_id, _j(d)))


def test_ledger_cas_and_conflicting_replay_do_not_mutate_committed_history(reservation_pg):
    import psycopg
    first = _root()
    second = _continue(first)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences + second.occurrences)
        _admit(admin, first)
        before = _ledger(admin)
        token = _begin(admin)
        wrong = before | {"xml_bytes": before["xml_bytes"] - 1}
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="ledger_cas_conflict"):
            _reserve(admin, token["token"], token["state_revision"], _documents(second, first.emission_id), wrong)
        forged = replace(first, known_bad_password=first.known_bad_password - 1, unknown_account=1)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="replay_conflict"):
            _reserve(admin, token["token"], token["state_revision"], _documents(forged))
        assert _ledger(admin) == before


@pytest.mark.parametrize("case", ["partial_portions", "wrong_totals", "wrong_state_budget", "job_deleted_before_commit"])
def test_deferred_guards_reject_consistent_looking_partial_direct_storage(reservation_pg, case):
    import psycopg
    emission = _root(300 if case == "partial_portions" else 10)
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        begun = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
            with admin.transaction():
                result = _reserve(admin, begun["token"], 0, _documents(emission))
                totals = dict(result["totals"])
                if case == "wrong_state_budget": totals["xml_bytes"] -= 1
                _owner_final_state(admin, emission, totals, begun["token"], 1, emission.emission_id)
                _jobs(admin, _documents(emission))
                if case == "wrong_totals": admin.execute("update semantic_password_episode_budgets set reserved_xml_bytes=reserved_xml_bytes+1")
                elif case == "job_deleted_before_commit": admin.execute("delete from semantic_risk_evaluation_jobs")
                elif case == "partial_portions":
                    # Native immutable mutation guard itself rejects deletion;
                    # a QW-only incomplete emission is tested below without bypassing it.
                    admin.execute("update semantic_password_episode_budgets set last_sequence=2")
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


def test_direct_incomplete_qw_with_owner_seeded_ledger_fails_deferred_completeness(reservation_pg):
    import psycopg
    emission = _root(300)
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        begun = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="portion_invalid|admission_incomplete"):
            with admin.transaction():
                documents = _documents(emission)
                # Reserve creates all portions; test a direct orphan new sequence
                # whose identity is valid, but ledger sequence/whole hash is unchanged.
                result = _reserve(admin, begun["token"], 0, documents)
                _owner_final_state(admin, emission, result["totals"], begun["token"], 1, emission.emission_id)
                _jobs(admin, documents)
                continuation = _continue(emission)
                d = _documents(continuation, emission.emission_id)[0]
                signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
                admin.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) values(%s,'enabled',%s::jsonb)", (signal_id, _j(d)))


def test_publisher_share_blocks_freeze_without_checkpoint_lock_and_frozen_blocks_jobs(reservation_pg):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        _admit(admin, emission)
    with _connection(reservation_pg, worker=True) as publisher, _connection(reservation_pg) as freezer:
        with publisher.transaction():
            publisher.execute("select pg_advisory_xact_lock(hashtextextended('fixture-scenario',0))")
            locked = _lock(publisher, emission.episode_key)
            assert locked["entity"] == emission.entity and not locked["frozen"]
            pid = publisher.execute("select pg_backend_pid() as pid").fetchone()["pid"]
            assert not freezer.execute("select exists(select 1 from pg_locks where pid=%s and relation='semantic_password_checkpoints'::regclass) as yes", (pid,)).fetchone()["yes"]
            freezer.execute("set lock_timeout='200ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable): _freeze(freezer)
        _freeze(freezer)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _lock(publisher, emission.episode_key)
        freezer.execute("delete from semantic_risk_evaluation_jobs")
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _jobs(freezer, _documents(emission))


def test_entity_assert_is_not_an_alternative_to_fresh_python_semantic_proof(reservation_pg):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        _admit(admin, emission)
    with _connection(reservation_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="publication_entity_conflict"):
            worker.execute("select assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s)",
                (_j(asdict(SCOPE)), _j(EXECUTION), emission.episode_key, "b" * 64))
        # SQL compares persisted working identity. B3 independently recomputes
        # entity from native XML, including the two root-required forgery cases.
        assert worker.execute("select assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s) as v",
            (_j(asdict(SCOPE)), _j(EXECUTION), emission.episode_key, emission.entity)).fetchone()["v"]["entity"] == emission.entity


def test_cross_epoch_barrier_holds_then_continuously_covered_native_gap_releases_exact_successor(reservation_pg):
    import psycopg
    first = _root()
    anchor, seed = _at(11, 1000), _at(12, 1601)
    witnesses = (seed,) + tuple(_at(i, 1601 + (i - 12) / 1000) for i in range(13, 22))
    successor = _new_root(witnesses)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences)
        _admit(admin, first)
        _freeze(admin)
        token = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
            _reserve(admin, token["token"], token["state_revision"], _documents(successor))
        _native(admin, (anchor,) + witnesses)
        held = _track(admin, token["token"], token["state_revision"], first.episode_key, anchor, 1,
            BASE + timedelta(seconds=400), BASE + timedelta(seconds=1000))
        assert held == dict(status="held", successor_episode_key=None)  # Lost horizon is NOT a gap proof.
        held = _track(admin, token["token"], token["state_revision"], first.episode_key, anchor, 1,
            BASE + timedelta(seconds=1000), BASE + timedelta(seconds=1300))
        assert held["status"] == "held"
        with admin.transaction():
            release = _track(admin, token["token"], token["state_revision"], first.episode_key, seed, 1,
                BASE + timedelta(seconds=1300), BASE + timedelta(seconds=1601))
            assert release == dict(status="successor_authorized", successor_episode_key=successor.episode_key)
            result = _admit(admin, successor)
            assert result["status"] == "reserved"
        locked = _lock(admin, successor.episode_key)
        assert locked["predecessor_episode_key"] == first.episode_key
        assert locked["predecessor_endpoint"] == asdict(anchor) | {"at": anchor.at.isoformat()}
        assert locked["successor_seed"]["at"] == seed.at.isoformat()
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _lock(admin, first.episode_key)


@pytest.mark.parametrize("case", ["delete", "reset_budget", "unfreeze"])
def test_frozen_lifetime_cannot_reset_or_delete(reservation_pg, case):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin:
        _native(admin, emission.occurrences)
        _admit(admin, emission)
        _freeze(admin)
        query = {"delete": "delete from semantic_password_episode_budgets",
            "reset_budget": "update semantic_password_episode_budgets set reserved_ref_occurrences=0",
            "unfreeze": "update semantic_password_episode_budgets set frozen=false"}[case]
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="lifetime_immutable"): admin.execute(query)

@pytest.mark.parametrize("large", [False, True])
def test_dedicated_sql_emitter_matches_python_unicode_and_rejects_whole_oversize_qw(reservation_pg, large):
    import psycopg
    scope = replace(SCOPE, source_generation='generation-"\\\x7fĀ😀' + '😀' * 480)
    rule = pure.Rule(scope, "brute")
    original = _root(300 if large else 10)
    witnesses = tuple(replace(w, ref=replace(w.ref, scope=scope)) for w in original.origin)
    emission = replace(original, pin=rule.pin, seed=witnesses[0], origin=witnesses, root_proof=witnesses,
        episode_key=pure._key(rule, 0, original.entity, witnesses[0]))
    documents = _documents(emission)
    with _connection(reservation_pg) as admin:
        admin.execute("""insert into finding_evidence_source_bindings
            select principal_oid,principal_name,installation_id,plugin_id,source_instance_id,%s,
                collection_scope_id,storage_kind,log_source_id,agent_key,agent_id
            from finding_evidence_source_bindings where principal_name=session_user""", (scope.source_generation,))
        if large:
            with pytest.raises(psycopg.errors.InvalidParameterValue):
                admin.execute("select password_v2_decode(%s::jsonb,%s::jsonb,%s::jsonb)",
                    (_j(asdict(scope)), _j(rule.execution), _j(documents)))
        else:
            decoded = admin.execute("select password_v2_decode(%s::jsonb,%s::jsonb,%s::jsonb) as v",
                (_j(asdict(scope)), _j(rule.execution), _j(documents))).fetchone()["v"]
            assert decoded["emission"] == emission.document
            assert decoded["emission_id"] == emission.emission_id
            assert len(json.dumps(emission.document, sort_keys=True, separators=(",", ":")).encode()) > 49152


def test_checkpoint_only_fake_episode_budget_cannot_bypass_new_deferred_guard(reservation_pg):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin:
        token = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="state_ledger_conflict"):
            _owner_final_state(admin, emission, dict(ref_occurrences=10, portions=1,
                xml_bytes=sum(w.xml_bytes for w in emission.occurrences)), token["token"], 1, emission.emission_id)


def test_partial_new_portion_commit_fails_without_mutation_guard_bypass(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        with pytest.raises(psycopg.errors.InvalidParameterValue, match="portion_invalid"):
            _historical(admin, [_root(300)], omit_last_portion=True)
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0

def test_digest_trigger_is_owner_definer_with_private_exec_and_session_authority(reservation_pg):
    with _connection(reservation_pg) as admin:
        row = admin.execute("""select pg_get_userbyid(proowner) as owner,prosecdef,proconfig
            from pg_proc where oid='password_v2_qw_index_key()'::regprocedure""").fetchone()
        assert row == dict(owner="adlog_storage_owner", prosecdef=True, proconfig=["search_path=pg_catalog, pg_temp"])
        for role in ("adlog_user", "adlog_storage_worker", "adlog_semantic_worker", reservation_pg[1]):
            assert not admin.execute("select has_function_privilege(%s,'password_v2_qw_index_key()','EXECUTE') as yes", (role,)).fetchone()["yes"]
            assert not admin.execute("select has_function_privilege(%s,'password_v2_scope_key(jsonb)','EXECUTE') as yes", (role,)).fetchone()["yes"]


def test_supplied_lookup_digest_is_erased_for_legacy_and_rederived_for_managed_v2(reservation_pg):
    first = _root()
    second = _continue(first)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences + second.occurrences)
        _admit(admin, first)
        expected = bytes.fromhex(_digest(asdict(SCOPE)))
    with _connection(reservation_pg, worker=True) as worker:
        d = _documents(first)[0]
        d.pop("password_context")
        d["rule_version"] = 1
        signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
        worker.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json,password_scope_digest) values(%s,'enabled',%s::jsonb,%s)",
            (signal_id, _j(d), bytes.fromhex("f" * 64)))
        assert worker.execute("select password_scope_digest from semantic_qw_signals where signal_id=%s", (signal_id,)).fetchone()["password_scope_digest"] is None
        with worker.transaction(force_rollback=True):
            d = _documents(second, first.emission_id)[0]
            signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
            worker.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json,password_scope_digest) values(%s,'enabled',%s::jsonb,%s)",
                (signal_id, _j(d), bytes.fromhex("f" * 64)))
            assert worker.execute("select password_scope_digest from semantic_qw_signals where signal_id=%s", (signal_id,)).fetchone()["password_scope_digest"] == expected
            # Roll back the intentionally orphan staged row; public direct COMMIT
            # completeness rejection is independently exercised above.


def test_cross_scope_digest_and_guc_cannot_spoof_current_login_binding(reservation_pg):
    import psycopg
    emission = _root()
    with _connection(reservation_pg) as admin: _native(admin, emission.occurrences)
    d = _documents(emission)[0]
    for ref in d["evidence_refs"]: ref["scope"]["source_generation"] = "foreign"
    signal_id = _digest({k: v for k, v in d.items() if k != "received_at_utc"})
    with _connection(reservation_pg, worker=True) as worker:
        worker.execute("select set_config('sli.principal','adlog_storage_owner',false)")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json,password_scope_digest) values(%s,'enabled',%s::jsonb,%s)",
                (signal_id, _j(d), bytes.fromhex(_digest(asdict(SCOPE)))))


def test_source_unauthorized_lookup_does_not_authorize_by_definer_owner(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        admin.execute("delete from finding_evidence_source_bindings where principal_name=%s", (reservation_pg[1],))
    with _connection(reservation_pg, worker=True) as worker:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="source_denied"):
            _lock(worker, "a" * 64)


def test_lifetime_new_private_objects_revoke_real_default_report_grants(password_base_pg):
    import psycopg
    from pathlib import Path
    from psycopg.rows import dict_row
    path = Path(__file__).resolve().parents[2] / "config/postgres_migrations/273_password_attacks_v2.sql"
    with psycopg.connect(password_base_pg, autocommit=True, row_factory=dict_row) as admin:
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant select on tables to adlog_user")
        admin.execute("alter default privileges for role adlog_storage_owner in schema public grant execute on functions to adlog_user")
        try:
            admin.execute(path.read_text("utf-8"))
            assert not admin.execute("select has_table_privilege('adlog_user','semantic_password_episode_budgets','SELECT') as yes").fetchone()["yes"]
            for function in ("password_v2_qw_index_key()", "password_v2_decode(jsonb,jsonb,jsonb)", "lock_password_publication_v2(jsonb,jsonb,text)"):
                assert not admin.execute("select has_function_privilege('adlog_user',%s,'EXECUTE') as yes", (function,)).fetchone()["yes"]
        finally:
            admin.execute("alter default privileges for role adlog_storage_owner in schema public revoke select on tables from adlog_user")
            admin.execute("alter default privileges for role adlog_storage_owner in schema public revoke execute on functions from adlog_user")


def test_working_prune_and_epoch_does_not_erase_frozen_barrier(reservation_pg):
    import psycopg
    first = _root()
    successor = _new_root(tuple(_at(i, 1100 + i) for i in range(11, 21)))
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences)
        _admit(admin, first)
        _freeze(admin)
        state = pure.State(RULE.pin, BASE + timedelta(seconds=1000), 1).document
        admin.execute("update semantic_password_checkpoints set state_document=%s::jsonb,watermark=%s,coverage_epoch=1,state_revision=2",
            (_j(state), BASE + timedelta(seconds=1000)))
        begun = _begin(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
            _reserve(admin, begun["token"], 2, _documents(successor))
        assert admin.execute("select barrier_unresolved from semantic_password_episode_budgets").fetchone()["barrier_unresolved"]

def test_publication_share_guards_absent_same_entity_barrier_against_other_episode_freeze(reservation_pg):
    import psycopg
    first = _root()
    candidate = _continue(first)
    desired = 33554432 - sum(w.xml_bytes for w in candidate.occurrences) + 1
    origin = list(first.origin)
    extra = desired - sum(w.xml_bytes for w in origin)
    for i in range(9):
        amount = min(extra, 4194304 - origin[i].xml_bytes)
        origin[i] = replace(origin[i], xml_bytes=origin[i].xml_bytes + amount)
        extra -= amount
    assert extra == 0
    first = replace(first, origin=tuple(origin), root_proof=tuple(origin), seed=origin[0])
    candidate = _continue(first)
    newer = _new_root(tuple(_at(i, 1000 + i / 1000) for i in range(100, 110)))
    with _connection(reservation_pg) as admin:
        _historical(admin, [first])
        _native(admin, candidate.occurrences + newer.occurrences)
        expected = _ledger(admin)
        _admit(admin, newer)
        begun = _begin(admin)
    with _connection(reservation_pg, worker=True) as publisher, _connection(reservation_pg) as producer:
        with publisher.transaction():
            publisher.execute("select pg_advisory_xact_lock(hashtextextended('fixture-scenario-newer',0))")
            _lock(publisher, newer.episode_key)  # No unresolved barrier exists yet.
            producer.execute("set lock_timeout='200ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, first.emission_id), expected)
        with producer.transaction():
            frozen = _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, first.emission_id), expected)
            assert frozen["status"] == "frozen"
            _owner_complete_frozen_state(producer, (first.episode_key,))

def _two_episode_freeze_case(admin):
    first = _root()
    candidate = _continue(first)
    desired = 33554432 - sum(w.xml_bytes for w in candidate.occurrences) + 1
    origin = list(first.origin)
    extra = desired - sum(w.xml_bytes for w in origin)
    for i in range(9):
        amount = min(extra, 4194304 - origin[i].xml_bytes)
        origin[i] = replace(origin[i], xml_bytes=origin[i].xml_bytes + amount)
        extra -= amount
    assert extra == 0
    first = replace(first, origin=tuple(origin), root_proof=tuple(origin), seed=origin[0])
    candidate = _continue(first)
    newer = _new_root(tuple(_at(i, 1000 + i / 1000) for i in range(100, 110)))
    _historical(admin, [first])
    _native(admin, candidate.occurrences + newer.occurrences)
    expected = _ledger(admin)
    _admit(admin, newer)
    return first, candidate, newer, expected, _begin(admin)


def test_frozen_result_without_state_completion_rolls_back_all_storage(reservation_pg):
    import psycopg

    def snapshot(conn):
        tables = ("semantic_password_episode_budgets", "semantic_password_checkpoints", "semantic_qw_signals",
            "semantic_risk_evaluation_jobs", "semantic_password_window_members")
        return {table: conn.execute(f"select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),'[]'::jsonb) as v from {table} t").fetchone()["v"]
            for table in tables}

    with _connection(reservation_pg) as admin:
        first, candidate, _, expected, begun = _two_episode_freeze_case(admin)
        before = snapshot(admin)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="password_v2_freeze_completion_incomplete"), admin.transaction():
            result = _reserve(admin, begun["token"], begun["state_revision"], _documents(candidate, first.emission_id), expected)
            assert result["status"] == "frozen"
            assert admin.execute("select frozen from semantic_password_episode_budgets where episode_key=%s",
                (first.episode_key,)).fetchone()["frozen"] is True
            # Deliberately omit OWNER completion: the real deferred guard must reject COMMIT.
        assert admin.info.transaction_status == 0
        assert snapshot(admin) == before


def test_entity_freeze_exclusive_first_blocks_publisher_then_rejects_barrier(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        first, candidate, newer, expected, begun = _two_episode_freeze_case(admin)
    with _connection(reservation_pg) as producer, _connection(reservation_pg, worker=True) as publisher:
        publisher.execute("set lock_timeout='200ms'")
        with producer.transaction():
            result = _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, first.emission_id), expected)
            assert result["status"] == "frozen"
            with pytest.raises(psycopg.errors.LockNotAvailable): _lock(publisher, newer.episode_key)
            _owner_complete_frozen_state(producer, (first.episode_key,))
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
            _lock(publisher, newer.episode_key)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _lock(publisher, first.episode_key)


def test_multi_entity_prelock_has_stable_deduped_namespace_and_no_state_progress(reservation_pg):
    with _connection(reservation_pg, worker=True) as worker, _connection(reservation_pg) as admin:
        token = _begin(worker)
        with worker.transaction():
            worker.execute("select lock_password_reservation_entities_v2(%s::jsonb,%s::jsonb,%s,0,%s::text[])",
                (_j(asdict(SCOPE)), _j(EXECUTION), token["token"], ["b" * 64, "a" * 64, "b" * 64]))
            keys = [row["k"] for row in admin.execute("select password_v2_entity_key(password_v2_scope_key(%s::jsonb),%s,k) as k from unnest(%s::text[]) k",
                (_j(asdict(SCOPE)), RULE.pin, ["a" * 64, "b" * 64])).fetchall()]
            assert len(set(keys)) == 2
        assert admin.execute("select state_revision,state_document from semantic_password_checkpoints").fetchone() == dict(state_revision=0, state_document=None)


def test_historical_publication_earlier_genuine_episode_has_provisional_gate_after_later_barrier(reservation_pg):
    """SQL eligibility is provisional; fresh Python A-chain/B-seed proof remains mandatory."""
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, later = _historical_pair(admin)
    with _connection(reservation_pg, worker=True) as publisher:
        with publisher.transaction():
            publisher.execute("select pg_advisory_xact_lock(hashtextextended('fixture-historical-scenario',0))")
            gate = _lock(publisher, earlier.episode_key)
            descriptor = gate["historical_barrier"]
            assert descriptor == dict(version="sli.password.v2.historical-barrier.1", barrier_episode_key=later.episode_key,
                barrier_first_ledger_revision=2, barrier_seed=json.loads(_j(asdict(later.seed))),
                target_last_admitted_revision=1, target_last_sequence=1, target_last_emission_id=earlier.emission_id)
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="descriptor_conflict"):
                with publisher.transaction():
                    _historical_assert(publisher, earlier.episode_key, earlier.entity, four=True)
            assert _historical_assert(publisher, earlier.episode_key, earlier.entity, descriptor) == gate
            assert _historical_assert(publisher, earlier.episode_key, earlier.entity, descriptor) == gate
    with _connection(reservation_pg) as admin:
        assert _order(admin, earlier.episode_key) == dict(first_ledger_revision=1, admitted_revision=1, last_sequence=1, frozen=False)
        assert _order(admin, later.episode_key) == dict(first_ledger_revision=2, admitted_revision=2, last_sequence=1, frozen=True)

@pytest.mark.parametrize("omit_earlier_jobs", [True, False])
def test_two_emissions_one_transaction_requires_jobs_for_every_new_sequence(reservation_pg, omit_earlier_jobs):
    import psycopg
    first = _root()
    second = _continue(first)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences + second.occurrences)
        begun = _begin(admin)
        def stage():
            with admin.transaction():
                _reserve(admin, begun["token"], 0, _documents(first))
                expected = _ledger(admin)
                result = _reserve(admin, begun["token"], 0, _documents(second, first.emission_id), expected)
                _owner_final_state(admin, second, result["totals"], begun["token"], 1, first.emission_id)
                if not omit_earlier_jobs: _jobs(admin, _documents(first))
                _jobs(admin, _documents(second, first.emission_id))
        if omit_earlier_jobs:
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="jobs_incomplete"): stage()
        else:
            stage()
            assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 2

def test_native_cost_bound_oversized_manifest_rejects_before_first_native_read(reservation_pg):
    import psycopg
    first = _root()
    witnesses = tuple(replace(w, xml_bytes=4194304) for w in first.origin)
    emission = replace(first, seed=witnesses[0], origin=witnesses, root_proof=witnesses)
    # No native rows exist: reaching the reader would produce42501, not54000.
    with _connection(reservation_pg, worker=True) as worker, _connection(reservation_pg) as admin:
        begun = _begin(worker)
        before = admin.execute("select to_jsonb(c) as v from semantic_password_checkpoints c").fetchone()["v"]
        with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_proof_budget_exceeded"):
            _reserve(worker, begun["token"], 0, _documents(emission))
        assert admin.execute("select to_jsonb(c) as v from semantic_password_checkpoints c").fetchone()["v"] == before
        for table in ("semantic_password_episode_budgets", "semantic_qw_signals", "semantic_risk_evaluation_jobs"):
            assert admin.execute(f"select count(*) as n from {table}").fetchone()["n"] == 0


def test_native_cost_bound_exact_actual_32mib_root_can_stage(reservation_pg):
    first = _root()
    tail_bytes = sum(w.xml_bytes for w in first.origin[8:])
    sizes = [4194304] * 7 + [4194304 - tail_bytes] + [w.xml_bytes for w in first.origin[8:]]
    witnesses = []
    with _connection(reservation_pg) as admin:
        for w, size in zip(first.origin, sizes):
            native_id = int(w.ref.native_id)
            xml = _xml(w.at, native_id, size=size)
            _seed(admin, start=native_id, at=w.at)
            _replace_xml(admin, native_id, xml)
            witnesses.append(replace(w, xml_bytes=size, xml_sha256=sha256(xml.encode()).hexdigest()))
        emission = replace(first, seed=witnesses[0], origin=tuple(witnesses), root_proof=tuple(witnesses))
        begun = _begin(admin)
        with admin.transaction(force_rollback=True):
            result = _reserve(admin, begun["token"], 0, _documents(emission))
            assert result["status"] == "reserved"
            assert result["delta"] == dict(ref_occurrences=10, portions=1, xml_bytes=33554432)
        assert admin.execute("select count(*) as n from semantic_password_episode_budgets").fetchone()["n"] == 0
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 0


def test_native_cost_bound_actual_overflow_stops_before_remaining_native_rows(reservation_pg):
    import psycopg
    first = _root()
    witnesses = []
    with _connection(reservation_pg) as admin:
        for index, w in enumerate(first.origin):
            if index == 9:
                witnesses.append(replace(w, xml_bytes=1))  # Remaining native row deliberately absent.
                continue
            size = 4194302 if index == 7 else 4194304
            native_id = int(w.ref.native_id)
            xml = _xml(w.at, native_id, size=size)
            _seed(admin, start=native_id, at=w.at)
            _replace_xml(admin, native_id, xml)
            witnesses.append(replace(w, xml_bytes=size if index < 8 else 1,
                xml_sha256=sha256(xml.encode()).hexdigest()))
        # Declared sum is exactly32MiB; actual ninth XML crosses it. The tenth
        # missing source must never be read. Only this disposable owner fixture
        # wraps190, delegates to its real body and pins/restores its definition/ACL.
        snapshot_sql = """select oid,proowner,proacl::text as acl,pg_get_functiondef(oid) as definition
            from pg_proc where oid='public.read_agent_semantic_source_v190(bigint)'::regprocedure"""
        before = admin.execute(snapshot_sql).fetchone()
        admin.execute("create temporary sequence fixture_password_native_reads minvalue 0 start 0")
        admin.execute("alter function public.read_agent_semantic_source_v190(bigint) rename to fixture_password_original_v190")
        try:
            admin.execute("""create function public.read_agent_semantic_source_v190(p_event_id bigint) returns jsonb
                language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
                begin
                    perform nextval('pg_temp.fixture_password_native_reads');
                    return public.fixture_password_original_v190(p_event_id);
                end $$""")
            with pytest.raises(psycopg.errors.ProgramLimitExceeded, match="password_v2_proof_budget_exceeded"):
                admin.execute("select public.password_v2_native_cost(%s::jsonb,%s::jsonb)",
                    (_j(asdict(SCOPE)), _j([asdict(w) for w in witnesses])))
            counter = admin.execute("select last_value,is_called from pg_temp.fixture_password_native_reads").fetchone()
            assert counter == dict(last_value=8, is_called=True)  # Sequence starts0: nine reads, no tenth.
        finally:
            admin.execute("drop function if exists public.read_agent_semantic_source_v190(bigint)")
            admin.execute("alter function public.fixture_password_original_v190(bigint) rename to read_agent_semantic_source_v190")
            assert admin.execute(snapshot_sql).fetchone() == before
        for table in ("semantic_password_checkpoints", "semantic_password_episode_budgets", "semantic_qw_signals", "semantic_risk_evaluation_jobs"):
            assert admin.execute(f"select count(*) as n from {table}").fetchone()["n"] == 0


def _historical_assert(conn, episode_key, entity, descriptor=None, *, four=False):
    params = (_j(asdict(SCOPE)), _j(EXECUTION), episode_key, entity)
    if four:
        return conn.execute("select assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s) as v", params).fetchone()["v"]
    return conn.execute("select assert_password_publication_entity_v2(%s::jsonb,%s::jsonb,%s,%s,%s::jsonb) as v",
        params + (None if descriptor is None else _j(descriptor),)).fetchone()["v"]


def _freeze_episode(admin, episode_key):
    with admin.transaction():
        admin.execute("""update semantic_password_episode_budgets set frozen=true,frozen_at=clock_timestamp(),
            frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,
            tracking_endpoint=last_admitted_endpoint,tracking_epoch=coverage_epoch,
            tracking_through=(last_admitted_endpoint->>'at')::timestamptz where episode_key=%s""", (episode_key,))
        _owner_complete_frozen_state(admin, (episode_key,))


def _historical_pair(admin, *, freeze=True):
    earlier = _root()
    later = _new_root(tuple(_at(i, 1000 + i / 1000) for i in range(100, 110)))
    _native(admin, earlier.occurrences + later.occurrences)
    _admit(admin, earlier)
    _admit(admin, later)
    if freeze: _freeze_episode(admin, later.episode_key)
    return earlier, later


def _order(admin, episode_key):
    return admin.execute("""select first_ledger_revision,admitted_revision,last_sequence,frozen
        from semantic_password_episode_budgets where episode_key=%s""", (episode_key,)).fetchone()


def _expected_ledger(admin, episode_key):
    row = admin.execute("select * from semantic_password_episode_budgets where episode_key=%s", (episode_key,)).fetchone()
    return dict(last_sequence=row["last_sequence"], last_emission_id=row["last_emission_id"],
        ref_occurrences=row["reserved_ref_occurrences"], portions=row["reserved_portions"], xml_bytes=row["reserved_xml_bytes"])


def test_historical_publication_latest_admission_after_barrier_creation_cannot_use_old_timestamps(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, later = _historical_pair(admin, freeze=False)
        continuation = _continue(earlier)
        _native(admin, (continuation.endpoint,))
        _admit(admin, continuation, earlier.emission_id, _expected_ledger(admin, earlier.episode_key))
        _freeze_episode(admin, later.episode_key)
        assert _order(admin, earlier.episode_key)["admitted_revision"] == 3
        assert _order(admin, later.episode_key)["first_ledger_revision"] == 2
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
            _lock(admin, earlier.episode_key)


def test_historical_publication_same_revision_ambiguity_is_denied(reservation_pg):
    import psycopg
    earlier = _root()
    later = _new_root(tuple(_at(i, 1000 + i / 1000) for i in range(100, 110)), epoch=0)
    with _connection(reservation_pg) as admin:
        _native(admin, earlier.occurrences + later.occurrences)
        _admit(admin, earlier)
        # Explicit owner-only ambiguous historical bucket; not public coordinator progress.
        _historical(admin, [later], revision=1, first_revision=1)
        _freeze_episode(admin, later.episode_key)
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
            _lock(admin, earlier.episode_key)


@pytest.mark.parametrize("case", ["first_changed", "last_decreased", "frozen_last_changed"])
def test_historical_publication_first_order_immutable_and_last_order_monotone(reservation_pg, case):
    import psycopg
    first = _root()
    second = _continue(first)
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences + second.occurrences)
        _admit(admin, first)
        _admit(admin, second, first.emission_id, _expected_ledger(admin, first.episode_key))
        assert _order(admin, first.episode_key) == dict(first_ledger_revision=1, admitted_revision=2, last_sequence=2, frozen=False)
        if case == "frozen_last_changed": _freeze_episode(admin, first.episode_key)
        assignment = {"first_changed": "first_ledger_revision=2", "last_decreased": "admitted_revision=1",
            "frozen_last_changed": "admitted_revision=3"}[case]
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="lifetime_immutable"):
            admin.execute(f"update semantic_password_episode_budgets set {assignment} where episode_key=%s", (first.episode_key,))


def test_historical_publication_replay_preserves_order_but_new_contributions_still_block(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, later = _historical_pair(admin)
        before = (_order(admin, earlier.episode_key), _order(admin, later.episode_key))
        begun = _begin(admin)
        replay = _reserve(admin, begun["token"], begun["state_revision"], _documents(earlier))
        assert replay["status"] == "replay" and replay["delta"] == dict(ref_occurrences=0, portions=0, xml_bytes=0)
        assert (_order(admin, earlier.episode_key), _order(admin, later.episode_key)) == before
        for documents, expected in ((_documents(_continue(earlier), earlier.emission_id), _expected_ledger(admin, earlier.episode_key)),
                (_documents(_new_root(tuple(_at(i, -1000 + i / 1000) for i in range(200, 210)))), None)):
            with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="barrier_unresolved"):
                _reserve(admin, begun["token"], begun["state_revision"], documents, expected)
        assert (_order(admin, earlier.episode_key), _order(admin, later.episode_key)) == before


@pytest.mark.parametrize("case", ["null", "seed", "order", "extra", "entity"])
def test_historical_publication_explicit_assert_binds_exact_descriptor_and_entity(reservation_pg, case):
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, _ = _historical_pair(admin)
    with _connection(reservation_pg, worker=True) as worker:
        gate = _lock(worker, earlier.episode_key)
        descriptor = json.loads(json.dumps(gate["historical_barrier"]))
        if case == "null": descriptor = None
        elif case == "seed": descriptor["barrier_seed"]["xml_bytes"] += 1
        elif case == "order": descriptor["barrier_first_ledger_revision"] += 1
        elif case == "extra": descriptor["verified"] = True
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="descriptor_conflict|publication_entity_conflict"):
            _historical_assert(worker, earlier.episode_key, "b" * 64 if case == "entity" else earlier.entity, descriptor)


def test_historical_publication_overload_has_no_defaults_and_narrow_source_authority(reservation_pg):
    import psycopg
    first = _root()
    with _connection(reservation_pg) as admin:
        _native(admin, first.occurrences)
        _admit(admin, first)
        rows = admin.execute("""select pronargs,pronargdefaults,prosecdef,pg_get_userbyid(proowner) as owner,proconfig
            from pg_proc where pronamespace='public'::regnamespace and proname='assert_password_publication_entity_v2'
            order by pronargs""").fetchall()
        assert rows == [dict(pronargs=n, pronargdefaults=0, prosecdef=True, owner="adlog_storage_owner",
            proconfig=["search_path=pg_catalog, pg_temp"]) for n in (4, 5)]
        for signature in ("jsonb,jsonb,text,text", "jsonb,jsonb,text,text,jsonb"):
            name = f"assert_password_publication_entity_v2({signature})"
            for role in ("adlog_user", "adlog_storage_worker"):
                assert not admin.execute("select has_function_privilege(%s,%s,'EXECUTE') as yes", (role, name)).fetchone()["yes"]
            assert admin.execute("select has_function_privilege('adlog_semantic_worker',%s,'EXECUTE') as yes", (name,)).fetchone()["yes"]
        with _connection(reservation_pg, worker=True) as worker:
            assert _historical_assert(worker, first.episode_key, first.entity)["historical_barrier"] is None
            assert _historical_assert(worker, first.episode_key, first.entity, four=True)["historical_barrier"] is None
            admin.execute("delete from finding_evidence_source_bindings where principal_name=%s", (reservation_pg[1],))
            worker.execute("select set_config('sli.principal','adlog_storage_owner',false)")
            with pytest.raises(psycopg.errors.InsufficientPrivilege, match="source_denied"):
                _historical_assert(worker, first.episode_key, first.entity)


def test_historical_publication_additional_policy_job_on_old_qw_is_valid_but_frozen_target_is_not(reservation_pg):
    import psycopg
    second_policy = "fixture-password-storage-second"
    definition = {"source_selector": {"execution": EXECUTION}}
    digest = bytes.fromhex(_digest(definition))
    with _connection(reservation_pg) as admin:
        earlier, later = _historical_pair(admin)
        admin.execute("insert into semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256) values(%s,1,'qw_signal','draft',%s::jsonb,%s)",
            (second_policy, _j(definition), digest))
        admin.execute("insert into semantic_risk_policy_subscriptions values(%s,1,'qw_signal',%s,%s)", (second_policy, EXECUTION["rule_id"], digest))
        admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id=%s", (second_policy,))
        admin.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled) values(%s,1,true)", (second_policy,))
        before = _order(admin, earlier.episode_key)
        _jobs(admin, _documents(earlier), policy=second_policy)
        assert _order(admin, earlier.episode_key) == before
        signal_id = _digest({k: v for k, v in _documents(earlier)[0].items() if k != "received_at_utc"})
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs where qw_signal_id=%s", (signal_id,)).fetchone()["n"] == 2
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _jobs(admin, _documents(later), policy=second_policy)
        gate = _lock(admin, earlier.episode_key)
        assert _historical_assert(admin, earlier.episode_key, earlier.entity, gate["historical_barrier"]) == gate


def _historical_ordered_freeze_case(admin):
    earlier = _new_root(tuple(_at(i, -1000 + (i - 100) / 1000) for i in range(100, 110)), epoch=0)
    later = _root()
    candidate = _continue(later)
    desired = 33554432 - sum(w.xml_bytes for w in candidate.occurrences) + 1
    origin = list(later.origin)
    extra = desired - sum(w.xml_bytes for w in origin)
    for index in range(9):
        amount = min(extra, 4194304 - origin[index].xml_bytes)
        origin[index] = replace(origin[index], xml_bytes=origin[index].xml_bytes + amount)
        extra -= amount
    assert extra == 0
    later = replace(later, origin=tuple(origin), root_proof=tuple(origin), seed=origin[0])
    candidate = _continue(later)
    _native(admin, earlier.occurrences + candidate.occurrences)
    _admit(admin, earlier)
    # Already-admitted historical B budget is a storage fixture, not fresh past XML proof.
    _historical(admin, [later], revision=2)
    return earlier, later, candidate, _expected_ledger(admin, later.episode_key), _begin(admin)


def test_historical_publication_shared_entity_prevents_later_barrier_phantom(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, later, candidate, expected, begun = _historical_ordered_freeze_case(admin)
    with _connection(reservation_pg, worker=True) as publisher, _connection(reservation_pg) as producer:
        producer.execute("set lock_timeout='200ms'")
        with publisher.transaction():
            publisher.execute("select pg_advisory_xact_lock(hashtextextended('fixture-historical-scenario',0))")
            assert _lock(publisher, earlier.episode_key)["historical_barrier"] is None
            with pytest.raises(psycopg.errors.LockNotAvailable):
                _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, later.emission_id), expected)
        with producer.transaction():
            assert _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, later.emission_id), expected)["status"] == "frozen"
            _owner_complete_frozen_state(producer, (later.episode_key,))
        with publisher.transaction():
            gate = _lock(publisher, earlier.episode_key)
            assert gate["historical_barrier"]["barrier_episode_key"] == later.episode_key
            assert _historical_assert(publisher, earlier.episode_key, earlier.entity, gate["historical_barrier"]) == gate


def test_historical_publication_freeze_first_blocks_then_returns_only_provisional_earlier_gate(reservation_pg):
    import psycopg
    with _connection(reservation_pg) as admin:
        earlier, later, candidate, expected, begun = _historical_ordered_freeze_case(admin)
    with _connection(reservation_pg) as producer, _connection(reservation_pg, worker=True) as publisher:
        publisher.execute("set lock_timeout='200ms'")
        with producer.transaction():
            assert _reserve(producer, begun["token"], begun["state_revision"], _documents(candidate, later.emission_id), expected)["status"] == "frozen"
            with pytest.raises(psycopg.errors.LockNotAvailable): _lock(publisher, earlier.episode_key)
            _owner_complete_frozen_state(producer, (later.episode_key,))
        gate = _lock(publisher, earlier.episode_key)
        assert gate["historical_barrier"]["barrier_first_ledger_revision"] == 2
        assert _historical_assert(publisher, earlier.episode_key, earlier.entity, gate["historical_barrier"]) == gate
        with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="episode_frozen"):
            _lock(publisher, later.episode_key)
