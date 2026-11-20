"""Actual producer -> public SQL -> actual queue in disposable PostgreSQL only."""
from datetime import timedelta

import pytest

from server.sli.semantic import password_attack_producer as producer
from tests.migrations.test_password_attacks_v2_coordinator_migration import (
    RULE, _connection, _seed, _xml, _replace_xml,
    acl_pg as acl_pg, coordinator_pg as coordinator_pg, native_pg as native_pg,
    password_base_pg as password_base_pg, password_pg as password_pg,
    reservation_pg as reservation_pg,
)

pytestmark = [pytest.mark.postgres_integration, pytest.mark.postgres_empty]


def _recent(source, count=10, start=1, *, seconds=300, size=None):
    with _connection(source) as admin:
        at = admin.execute("select clock_timestamp() as t").fetchone()["t"] - timedelta(seconds=seconds)
        _seed(admin, count, at=at, start=start)
        if size:
            for native_id in range(start, start + count):
                _replace_xml(admin, native_id, _xml(at, native_id, size=size))
        return at


def _identity(worker):
    return worker.execute("select current_user as role,session_user as principal,"
        "(select oid from pg_roles where rolname=session_user) as principal_oid").fetchone()


def _after_watermark(source, *, start=11, size=None):
    with _connection(source) as admin:
        at = admin.execute("select watermark from semantic_password_checkpoints").fetchone()["watermark"] + timedelta(microseconds=1)
        _seed(admin, 1, start=start, at=at)
        if size:
            _replace_xml(admin, start, _xml(at, start, size=size))


def test_actual_producer_commits_root_all_portions_all_policies_and_genuine_empty_poll(coordinator_pg):
    _recent(coordinator_pg, count=300)
    with _connection(coordinator_pg) as admin:
        definition = {"source_selector": {"execution": RULE.execution}}
        # Exact existing enabled v1 subscription, independent second policy.
        admin.execute("""insert into semantic_risk_policies
            select 'fixture-second-password',policy_version,source_kind,'draft',definition_json,
                definition_sha256,updated_at from semantic_risk_policies limit 1""")
        admin.execute("""insert into semantic_risk_policy_subscriptions
            select 'fixture-second-password',policy_version,source_kind,selector_value,definition_sha256
            from semantic_risk_policy_subscriptions limit 1""")
        admin.execute("update semantic_risk_policies set lifecycle_status='enabled' where policy_id='fixture-second-password'")
        admin.execute("insert into semantic_policy_admission(policy_id,policy_version,enabled) values('fixture-second-password',1,true)")
        assert definition["source_selector"]["execution"] == RULE.execution
    with _connection(coordinator_pg, worker=True) as worker:
        from server.sli.semantic.semantic_worker_connection import assert_semantic_worker_least_privilege
        assert assert_semantic_worker_least_privilege(worker.cursor())["exclusive_worker_membership"]
        original = _identity(worker)
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed and first.jobs == 4 and first.revision == 1
        assert first.work["native_items"] == first.work["reservation_occurrences"] == 300
        assert first.work["retained_queries"] == 0
        assert _identity(worker) == original
        # The same fully reread existing native window is a new successful poll;
        # it must not manufacture another root, cost or set of jobs.
        second = producer.run_password_producer(worker, rule=RULE)
        assert not second.failed and second.jobs == 0 and second.revision == 2
        assert _identity(worker) == original
    with _connection(coordinator_pg) as admin:
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 2
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 4
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert ledger["last_sequence"] == ledger["first_ledger_revision"] == ledger["admitted_revision"] == 1


def test_actual_producer_restart_continuation_reuses_current_window_native_proof(coordinator_pg):
    _recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed and first.jobs == 1
    # First process has ended; the next connection loads canonical State and
    # immutable codec history. No Python object/cache survives between entries.
    _after_watermark(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        second = producer.run_password_producer(worker, rule=RULE)
        assert not second.failed and second.jobs == 1 and second.revision == 2
        assert second.work["native_items"] == 11 and second.work["retained_queries"] == 0
        assert second.work["reservation_occurrences"] == 2
    with _connection(coordinator_pg) as admin:
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert ledger["last_sequence"] == 2 and ledger["reserved_ref_occurrences"] == 12
        assert ledger["first_ledger_revision"] == 1 and ledger["admitted_revision"] == 2


@pytest.mark.parametrize("failure", ["queue", "commit"])
def test_actual_producer_queue_or_deferred_commit_failure_rolls_back_and_restores_identity(coordinator_pg, monkeypatch, failure):
    from server.sli.semantic import semantic_risk_runtime_repository as queue
    _recent(coordinator_pg)
    if failure == "queue":
        def broken(cur, **kwargs):
            cur.execute("select 1/0")
        monkeypatch.setattr(queue, "_enqueue_source", broken)
    else:
        with _connection(coordinator_pg) as admin:
            admin.execute("""create function public.fixture_producer_commit_failure() returns trigger
                language plpgsql as $$begin raise exception 'fixture deferred failure'; end$$;
                create constraint trigger fixture_producer_commit_failure after insert on semantic_risk_evaluation_jobs
                deferrable initially deferred for each row execute function public.fixture_producer_commit_failure()""")
    with _connection(coordinator_pg, worker=True) as worker:
        original = _identity(worker)
        outcome = producer.run_password_producer(worker, rule=RULE)
        assert outcome.failed and outcome.jobs == 0 and outcome.failure_observed
        assert _identity(worker) == original
    with _connection(coordinator_pg) as admin:
        checkpoint = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert checkpoint["state_revision"] == 0 and checkpoint["watermark"] is None
        assert checkpoint["active_token"] == checkpoint["last_observed_token"]
        # Existing B1 records completion of a FAILED attempt too. Successful
        # cutoff/State/W/healthy must remain absent; completion time is not proof
        # of a successful source observation.
        assert checkpoint["last_completed_at"] >= checkpoint["last_attempt_at"]
        assert checkpoint["last_successful_cutoff"] is None
        assert checkpoint["health_status"] == "error"
        for table in ("semantic_qw_signals", "semantic_risk_evaluation_jobs", "semantic_password_episode_budgets"):
            assert admin.execute("select count(*) as n from " + table).fetchone()["n"] == 0


def test_actual_producer_qualified_no_emission_freeze_preserves_admission_and_jobs(coordinator_pg):
    # Every current native item is freshly parsed. The lifetime repeats its last
    # admitted anchor, so a continuation overflows while the shared fresh set
    # still fits (11 * 3,000,000 < 32 MiB; lifetime 10+2 occurrences > 32 MiB).
    _recent(coordinator_pg, size=3_000_000)
    with _connection(coordinator_pg, worker=True) as worker:
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed
    with _connection(coordinator_pg) as admin:
        before = admin.execute("select * from semantic_password_episode_budgets").fetchone()
    _after_watermark(coordinator_pg, size=3_000_000)
    with _connection(coordinator_pg, worker=True) as worker:
        frozen = producer.run_password_producer(worker, rule=RULE)
        assert not frozen.failed and frozen.jobs == 0 and frozen.health["status"] == "partial"
        assert frozen.work["native_items"] == 11 and frozen.work["xml_bytes"] == 33_000_000
        assert frozen.work["reservation_occurrences"] == 0
    with _connection(coordinator_pg) as admin:
        after = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert after["frozen"] and after["barrier_unresolved"]
        for key in ("root_id", "last_sequence", "last_emission_id", "reserved_ref_occurrences", "reserved_portions",
                    "reserved_xml_bytes", "last_admitted_as_of", "first_ledger_revision", "admitted_revision"):
            assert after[key] == before[key]
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 1
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 1


def _boundary_root(source, size=None):
    with _connection(source) as admin:
        stamp = admin.execute("select clock_timestamp() as t").fetchone()["t"]
        early, late = stamp-timedelta(seconds=710), stamp-timedelta(seconds=121)
        _seed(admin, 10, at=early)
        _seed(admin, 1, at=late, start=11)
        if size:
            for native_id in range(1, 12):
                _replace_xml(admin, native_id, _xml(early if native_id <= 10 else late, native_id, size=size))
    with _connection(source, worker=True) as worker:
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed and first.jobs == 1 and first.work["reservation_occurrences"] == 11
    with _connection(source) as admin:
        ledger = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        checkpoint = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert ledger["last_sequence"] == 1 and ledger["reserved_ref_occurrences"] == 11 and not ledger["frozen"]
        if size:
            assert ledger["reserved_xml_bytes"] == 11*size == 33_000_000 < 33_554_432
    return early, first, ledger, checkpoint


def _wait_until_early_events_leave_actual_window(source, early):
    import time
    deadline = time.monotonic() + 30
    with _connection(source) as admin:
        while admin.execute("select clock_timestamp() as t").fetchone()["t"] <= early + timedelta(seconds=720.01):
            assert time.monotonic() < deadline, "actual DB clock boundary did not arrive"
            time.sleep(.1)


def test_actual_db_clock_boundary_reads_fresh_retained_history_after_restart(coordinator_pg):
    early, _, _, _ = _boundary_root(coordinator_pg)
    _wait_until_early_events_leave_actual_window(coordinator_pg, early)
    _after_watermark(coordinator_pg, start=12)
    with _connection(coordinator_pg, worker=True) as worker:
        continued = producer.run_password_producer(worker, rule=RULE)
        assert not continued.failed and continued.jobs == 1 and continued.revision == 2
        assert continued.work["native_items"] == 12
        assert continued.work["retained_queries"] == 1 and continued.work["reservation_occurrences"] == 2
        assert continued.work["reservation_calls"] == continued.work["completion_calls"] == 1
    with _connection(coordinator_pg) as admin:
        row = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        assert row["last_sequence"] == 2 and row["reserved_ref_occurrences"] == 13


def test_actual_qualified_denial_when_full_fresh_history_exceeds_shared_budget(coordinator_pg):
    early, _, before, checkpoint = _boundary_root(coordinator_pg, size=3_000_000)
    _wait_until_early_events_leave_actual_window(coordinator_pg, early)
    _after_watermark(coordinator_pg, start=12, size=3_000_000)
    with _connection(coordinator_pg, worker=True) as worker:
        denied = producer.run_password_producer(worker, rule=RULE)
        assert not denied.failed and denied.jobs == 0 and denied.revision == 2
        assert denied.health["status"] == "partial"
        # Incoming predecessor/new endpoint are already fresh in this SAME pass.
        # The 36MB full set is rejected before any old retained XML transfer.
        assert denied.work["native_items"] == 2 and denied.work["xml_bytes"] == 6_000_000
        assert denied.work["retained_queries"] == denied.work["reservation_calls"] == 0
        assert denied.work["reservation_occurrences"] == 0 and denied.work["completion_calls"] == 1
    with _connection(coordinator_pg) as admin:
        after = admin.execute("select * from semantic_password_episode_budgets").fetchone()
        state = admin.execute("select * from semantic_password_checkpoints").fetchone()
        assert after["frozen"] and after["barrier_unresolved"]
        for key in ("root_id", "last_sequence", "last_emission_id", "reserved_ref_occurrences", "reserved_portions",
                    "reserved_xml_bytes", "last_admitted_as_of", "first_ledger_revision", "admitted_revision"):
            assert after[key] == before[key]
        assert state["watermark"] == checkpoint["watermark"]
        assert state["last_successful_cutoff"] == checkpoint["last_successful_cutoff"]
        assert state["state_document"]["window"] == checkpoint["state_document"]["window"]
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 1
        assert admin.execute("select count(*) as n from semantic_risk_evaluation_jobs").fetchone()["n"] == 1


@pytest.mark.parametrize("first", ["publisher", "producer"])
def test_actual_producer_and_publication_lock_in_both_directions(coordinator_pg, monkeypatch, first):
    from dataclasses import asdict
    import json
    import threading
    import time
    _recent(coordinator_pg)
    with _connection(coordinator_pg, worker=True) as worker:
        assert not producer.run_password_producer(worker, rule=RULE).failed
    _after_watermark(coordinator_pg)
    with _connection(coordinator_pg) as admin:
        key = admin.execute("select episode_key from semantic_password_episode_budgets").fetchone()["episode_key"]
    held, release = threading.Event(), threading.Event()
    pids, outcomes, errors = {}, {}, []
    original_call = producer._call
    def call(cur, name, *args):
        result = original_call(cur, name, *args)
        if first == "producer" and name == "prepare_password_producer_batch_v2":
            held.set()
            assert release.wait(20), "publisher did not reach the held producer entity lock"
        return result
    monkeypatch.setattr(producer, "_call", call)
    def produce():
        try:
            with _connection(coordinator_pg, worker=True) as worker:
                pids["producer"] = worker.execute("select pg_backend_pid() as pid").fetchone()["pid"]
                outcomes["producer"] = producer.run_password_producer(worker, rule=RULE)
        except Exception as error:
            errors.append(type(error).__name__)
    def publish():
        try:
            with _connection(coordinator_pg, worker=True) as worker:
                pids["publisher"] = worker.execute("select pg_backend_pid() as pid").fetchone()["pid"]
                with worker.transaction():
                    outcomes["publisher"] = worker.execute("""select lock_password_publication_v2(
                        %s::jsonb,%s::jsonb,%s) as v""", (json.dumps(asdict(RULE.scope)),
                        json.dumps(RULE.execution), key)).fetchone()["v"]
                    if first == "publisher":
                        held.set()
                        assert release.wait(20), "producer did not reach the held publisher entity lock"
        except Exception as error:
            errors.append(type(error).__name__)
    threads = {"producer": threading.Thread(target=produce), "publisher": threading.Thread(target=publish)}
    second = "publisher" if first == "producer" else "producer"
    try:
        threads[first].start()
        assert held.wait(15), "first transaction did not acquire its entity lock"
        threads[second].start()
        deadline = time.monotonic() + 15
        with _connection(coordinator_pg) as admin:
            while True:
                pid = pids.get(second)
                row = admin.execute("select wait_event_type,wait_event from pg_stat_activity where pid=%s", (pid,)).fetchone() if pid else None
                if row and row["wait_event_type"] == "Lock" and row["wait_event"] == "advisory":
                    break
                assert time.monotonic() < deadline, "second transaction did not wait for the same entity"
                time.sleep(.02)
    finally:
        release.set()
        for thread in threads.values():
            if thread.ident is not None:
                thread.join(30)
    assert not any(thread.is_alive() for thread in threads.values()) and not errors
    assert not outcomes["producer"].failed and outcomes["producer"].jobs == 1
    assert outcomes["publisher"]["frozen"] is False


def test_actual_empty_window_freshly_checks_retained_unaffected_episode_commitments(coordinator_pg):
    with _connection(coordinator_pg) as admin:
        early = admin.execute("select clock_timestamp()-interval '710 seconds' as t").fetchone()["t"]
        _seed(admin, 10, at=early)
    with _connection(coordinator_pg, worker=True) as worker:
        first = producer.run_password_producer(worker, rule=RULE)
        assert not first.failed and first.jobs == 1
    _wait_until_early_events_leave_actual_window(coordinator_pg, early)
    with _connection(coordinator_pg, worker=True) as worker:
        empty = producer.run_password_producer(worker, rule=RULE)
        assert not empty.failed and empty.jobs == 0 and empty.revision == 2
        assert empty.work["native_items"] == 2 and empty.work["retained_queries"] == 1
        assert empty.work["reservation_calls"] == 0
    with _connection(coordinator_pg) as admin:
        checkpoint = admin.execute("select * from semantic_password_checkpoints").fetchone()
        state = checkpoint["state_document"]
        assert not state["window"] and len(state["episodes"]) == 1
        assert state["episodes"][0]["sequence"] == 1 and not state["episodes"][0]["frozen"]
        assert state["episodes"][0]["seed"]["ref"]["native_id"] == "1"
        assert state["episodes"][0]["last"]["ref"]["native_id"] == "10"
        assert checkpoint["last_successful_cutoff"] == checkpoint["watermark"]
        assert admin.execute("select count(*) as n from semantic_qw_signals").fetchone()["n"] == 1
