"""Historical590-chain fixture -> actual native publication; disposable PG only.

Initial owner ledger/QW/job/State is explicitly historical. This is not past
producer/ordinary enqueue or wall-time endurance evidence. No product is patched.
"""
from contextlib import contextmanager
from dataclasses import asdict
from datetime import timedelta
from hashlib import sha256
import json

import pytest

from server.sli.semantic import password_attack_policy as factory
from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attack_runtime as password_runtime
from server.sli.semantic import password_attack_v2 as pure
from server.sli.semantic import semantic_risk_runtime_repository as runtime
from server.sli.semantic.semantic_risk import ScenarioSourceKind
from server.sli.semantic.semantic_governance import set_policy_admission
from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
from tests.migrations.test_password_managed_conveyor import (
    _authority, _identity, _publication_authority,
    acl_pg as acl_pg, conveyor_pg as conveyor_pg, coordinator_pg as coordinator_pg,
    coverage_pg as coverage_pg, managed_base_pg as managed_base_pg,
    managed_pg as managed_pg, native_pg as native_pg, original_base as original_base,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)
from tests.migrations.test_password_attacks_v2_migration import SCOPE, _seed, _xml, _replace_xml
from tests.migrations.test_password_attacks_v2_reservation_migration import POLICY as OLD_POLICY

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]
RULE = pure.Rule(SCOPE, "brute")


@contextmanager
def _connection(source, *, worker=False):
    import psycopg
    from psycopg.conninfo import make_conninfo
    from psycopg.rows import dict_row
    with psycopg.connect(make_conninfo(source[0], user=source[1]) if worker else source[0],
                         autocommit=True, row_factory=dict_row) as conn:
        if worker:
            conn.execute("set role adlog_semantic_worker")
            assert assert_semantic_worker_least_privilege(conn.cursor())["exclusive_worker_membership"]
            assert _identity(conn)["principal"] == source[1]
        yield conn


def _j(value):
    return json.dumps(pure._pack(value), sort_keys=True)


def _initial_historical_chain(source):
    # Only this helper may seed initial CP/ledger/QW/job state. The native rows
    # use the ORIGINAL source scope with pre-existing exact admin/worker bindings.
    with _connection(source) as admin:
        now = admin.execute("select clock_timestamp() as t").fetchone()["t"]
        base = now - timedelta(seconds=2000)
        events = []
        for native_id in (*range(1, 11), 100, 101, 102):
            at = base + (timedelta(microseconds=native_id) if native_id <= 10
                         else timedelta(seconds=(native_id - 99)*590))
            xml = _xml(at, native_id)
            _seed(admin, 1, at=at, start=native_id)
            _replace_xml(admin, native_id, xml)
            events.append(pure.NativeEvent.from_row(SCOPE, dict(source_event_id=native_id,
                event_id=4625, occurred_at_utc=at, sha256=f"{native_id:064x}", source_xml=xml)))
        authority, publication = _authority(admin), _publication_authority(admin)
    root = pure.advance(RULE, pure.State(), tuple(events[:10]), now=base+timedelta(seconds=200))
    first, = root.emissions
    chain, state = [first], root.state
    for event in events[10:]:
        # JSON roundtrip explicitly discards all Python object identity/cache.
        state = pure.State.from_document(json.loads(_j(state.document)))
        proposal = pure.advance(RULE, state, (event,), now=event.at+timedelta(seconds=120),
                                history=tuple(chain), retained=tuple(events))
        emission, = proposal.emissions
        chain.append(emission)
        state = proposal.state
    assert [e.sequence for e in chain] == [1, 2, 3, 4]
    assert sum(len(e.occurrences) for e in chain) == 16
    assert len({w.ref.native_id for e in chain for w in e.occurrences}) == 13
    policy = factory.risk_policy(RULE)
    audit_events = []
    # Initial metadata only, ordinary register/subscription/lifecycle/governance.
    # Existing SQL153 audit trigger remains real; the callback below records the
    # setup application's requested audit event, not HTTP/authentication proof.
    with _connection(source) as admin, admin.transaction(), admin.cursor() as cur:
        # Root-authorized INITIAL-only exception: this owner-seeded minimal
        # placeholder cannot compile as a real policy. Preserve its body/hash
        # and guards; disable only its admission, with real153/275 audit.
        minimal = {"source_selector": {"execution": RULE.execution}}
        old = cur.execute("select p.definition_json,p.definition_sha256,a.enabled from semantic_risk_policies p "
            "join semantic_policy_admission a using(policy_id,policy_version) where p.policy_id=%s "
            "and p.policy_version=1", (OLD_POLICY,)).fetchone()
        assert old["definition_json"] == minimal and old["enabled"] is True
        assert bytes(old["definition_sha256"]) == sha256(json.dumps(
            minimal, sort_keys=True, separators=(",", ":")).encode()).digest()
        for table in ("semantic_qw_signals", "semantic_risk_evaluation_jobs", "semantic_password_episode_budgets"):
            assert cur.execute("select count(*) as n from " + table).fetchone()["n"] == 0
        old_target = OLD_POLICY+":1"
        audit_before = cur.execute("select count(*) as n from semantic_control_audit "
            "where action='policy_admission' and target=%s", (old_target,)).fetchone()["n"]
        cur.execute("update semantic_policy_admission set enabled=false,updated_by='session:4242' "
            "where policy_id=%s and policy_version=1 and enabled is true", (OLD_POLICY,))
        assert cur.rowcount == 1
        assert cur.execute("select enabled from semantic_policy_admission where policy_id=%s "
            "and policy_version=1", (OLD_POLICY,)).fetchone()["enabled"] is False
        audit_rows = cur.execute("select actor,details from semantic_control_audit "
            "where action='policy_admission' and target=%s order by id", (old_target,)).fetchall()
        assert len(audit_rows) == audit_before+1
        assert audit_rows[-1]["actor"] == "session:4242" and audit_rows[-1]["details"]["enabled"] is False
        assert audit_rows[-1]["details"]["previous"] is True
        runtime.register_risk_policy(cur, policy=policy)
        for status in ("validated", "test", "shadow"):
            runtime.transition_risk_policy(cur, policy_id=policy.policy_id, policy_version=1, target_status=status)
        set_policy_admission(cur, policy.policy_id, 1, True, actor="session:42",
            reason="Synthetic initial publication policy", audit=lambda *args: audit_events.append(args[1:]))
        runtime.transition_risk_policy(cur, policy_id=policy.policy_id, policy_version=1, target_status="enabled")
        assert audit_events[0][0] == "semantic_policy_admission"
        assert cur.execute("select count(*) as n from semantic_control_audit where action='policy_admission' "
            "and target=%s", (policy.policy_id+":1",)).fetchone()["n"] == 1
    with _connection(source, worker=True) as worker:
        with worker.transaction(), worker.cursor() as cur:
            attempt = producer._call(cur, "begin_password_attempt", asdict(SCOPE), RULE.execution)
    signals = tuple(s for e in chain for s in producer._signals(
        RULE, e, first.emission_id if e.sequence > 1 else None, now))
    totals = dict(ref_occurrences=16, portions=4,
                  xml_bytes=sum(w.xml_bytes for e in chain for w in e.occurrences))
    # Accepted _historical initial shape, ORIGINAL SCOPE/current valid policy.
    # Existing source triggers/ACL/deferred checks remain; no binding is added.
    with _connection(source) as admin, admin.transaction():
        admin.execute("""insert into semantic_password_episode_budgets(
            scope_digest,pin,episode_key,scope_json,execution_json,coverage_epoch,entity,seed,
            root_id,last_sequence,last_emission_id,last_admitted_endpoint,reserved_ref_occurrences,
            reserved_portions,reserved_xml_bytes,last_admitted_as_of,admitted_revision,first_ledger_revision,
            admitted_attempt_token,admission_xid,admission_first_sequence)
            select scope_digest,pin,%s,%s::jsonb,%s::jsonb,0,%s,%s::jsonb,%s,4,%s,%s::jsonb,
                16,4,%s,clock_timestamp(),4,1,%s,pg_current_xact_id(),1
            from semantic_password_checkpoints where pin=%s""",
            (first.episode_key, _j(asdict(SCOPE)), _j(RULE.execution), first.entity,
             _j(asdict(first.seed)), first.emission_id, chain[-1].emission_id,
             _j(asdict(chain[-1].endpoint)), totals["xml_bytes"], attempt["token"], RULE.pin))
        for signal in signals:
            admin.execute("insert into semantic_qw_signals(signal_id,evaluation_mode,document_json) "
                "values(%s,'enabled',%s::jsonb)", (signal.signal_id, _j(signal.document)))
        admin.execute("""update semantic_password_checkpoints set state_document=%s::jsonb,
            state_revision=4,watermark=%s,coverage_epoch=0,history_started=true,last_observed_token=%s
            where pin=%s""", (_j(state.document), state.watermark, attempt["token"], RULE.pin))
        # Historical State's canonical window projection is mandatory too;
        # this initial-only mirror is never repaired during normal consumption.
        for member in state.window:
            admin.execute("insert into semantic_password_window_members(scope_digest,pin,member_document) "
                "select scope_digest,pin,%s::jsonb from semantic_password_checkpoints where pin=%s",
                (_j(member), RULE.pin))
        # Actual queue builder creates exact current-policy/job identities, but
        # this owner initial-baseline call is NOT ordinary runtime enqueue proof.
        for index, signal in enumerate(signals, 1):
            with admin.cursor() as cur:
                job, = runtime._enqueue_source(cur, source_kind=ScenarioSourceKind.QW_SIGNAL,
                                               source_id=signal.signal_id)
            # Explicit initial FIFO order only; all are already available.
            admin.execute("update semantic_risk_evaluation_jobs set available_at=%s where job_id=%s",
                          (base+timedelta(microseconds=index), job))
    return tuple(chain), signals, tuple(events), authority, publication


def _effects(admin):
    # Fixed bounded synthetic tables; compare full transaction effects rather
    # than assuming a possible prefix publication is globally absent.
    tables = ("semantic_password_checkpoints", "semantic_password_window_members",
        "semantic_password_episode_budgets", "semantic_qw_signals",
        "semantic_risk_evaluation_jobs", "semantic_security_scenarios", "semantic_scenario_steps",
        "semantic_scenario_evidence", "semantic_risk_contributions", "semantic_scenario_coverage_history",
        "semantic_risk_evaluation_results", "semantic_finding_publications", "findings",
        "finding_evidence_refs", "finding_evidence", "finding_entities", "finding_status_history",
        "notification_outbox", "notification_attempts")
    return {table: admin.execute("select coalesce(jsonb_agg(to_jsonb(t) order by to_jsonb(t)::text),"
        "'[]'::jsonb) as v from " + table + " t").fetchone()["v"] for table in tables}


def _consume(worker, claim):
    with worker.transaction():
        work = runtime.load_risk_evaluation_work_item(worker.cursor(),
            job_id=claim["job_id"], lease_token=claim["lease_token"])
        return runtime.execute_risk_evaluation(worker.cursor(), work=work,
                                               evaluation_ms=0, create_finding=True)


def test_actual_590_chain_fresh_native_publication_after_session_restart(conveyor_pg):
    import psycopg
    chain, signals, events, authority, publication = _initial_historical_chain(conveyor_pg)
    # Every initial setup session has closed. No CP/State/ledger/job repair below.
    with _connection(conveyor_pg, worker=True) as worker:
        identity = _identity(worker)
        for sequence in (1, 2, 3):
            with worker.transaction():
                claim, = runtime.claim_risk_evaluation_jobs(worker.cursor())
            assert claim["qw_signal_id"] == signals[sequence-1].signal_id
            result = _consume(worker, claim)
            assert not result.finding_created and result.publication_state == "evidence_pending"
            assert _identity(worker) == identity and worker.info.transaction_status == 0
        with worker.transaction():
            claim, = runtime.claim_risk_evaluation_jobs(worker.cursor())
        assert claim["qw_signal_id"] == signals[3].signal_id
        intermediate = events[10]
        assert intermediate.ref.native_id == "100"
        with _connection(conveyor_pg) as observer:
            _replace_xml(observer, 100, intermediate.source_xml.replace("fixture-account", "fixture-accounu"))
            before_failed = _effects(observer)
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="password_v2_retained_unavailable"):
            _consume(worker, claim)
        assert worker.info.transaction_status == 0 and _identity(worker) == identity
        with _connection(conveyor_pg) as observer:
            assert _effects(observer) == before_failed
            _replace_xml(observer, 100, intermediate.source_xml)
        # Same unexpired committed lease is valid after evaluation rollback.
        # Re-load from PG normally; no raw status/token/attempt reset or requeue.
        result = _consume(worker, claim)
        assert result.finding_created and result.finding_id is not None
        assert _identity(worker) == identity and worker.info.transaction_status == 0
        with worker.transaction():
            signal = password_runtime.scenario_password_signal(worker.cursor(), result.scenario_id)
            episode = password_runtime.load_episode(worker.cursor(), signal)
            assert episode.rule == RULE and episode.emissions == chain and episode.signals == signals
            batches = password_runtime.verify_scenario(worker.cursor(), scenario_id=result.scenario_id)
            assert sum(map(len, batches)) == 16
            assert len({ref for batch in batches for ref in batch}) == 13
        assert _identity(worker) == identity
    with _connection(conveyor_pg) as observer:
        assert _authority(observer) == authority and _publication_authority(observer) == publication
        assert observer.execute("select count(*) as n from semantic_security_scenarios").fetchone()["n"] == 1
        finding, = observer.execute("select * from findings").fetchall()
        published, = observer.execute("select * from semantic_finding_publications").fetchall()
        outbox, = observer.execute("select * from notification_outbox").fetchall()
        refs = observer.execute("select * from finding_evidence_refs order by native_id::bigint").fetchall()
        assert finding["id"] == published["finding_id"] == result.finding_id
        assert finding["evidence_count"] == published["published_evidence_count"] == len(refs) == 13
        assert {r["native_id"] for r in refs} == {e.ref.native_id for e in events}
        for ref in refs:
            event, = [e for e in events if e.ref.native_id == ref["native_id"]]
            assert ref["sha256"] == event.ref.sha256
            assert {key: str(ref[key]) for key in asdict(SCOPE)} == asdict(SCOPE)
        assert observer.execute("select count(*) as n from finding_evidence").fetchone()["n"] == 13
        assert outbox["object_kind"] == "semantic_finding" and outbox["state"] == "pending" and outbox["attempts"] == 0
        assert str(outbox["object_id"]) == str(outbox["publication_scenario_id"]) == str(result.scenario_id)
        assert observer.execute("select count(*) as n from notification_attempts").fetchone()["n"] == 0
        jobs = observer.execute("select * from semantic_risk_evaluation_jobs").fetchall()
        assert len(jobs) == 4 and all(j["evaluation_status"] == "completed" for j in jobs)
        assert all(j["attempt_count"] == 1 and j["lease_token"] is None for j in jobs)
