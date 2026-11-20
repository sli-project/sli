"""Connection ownership and actual native planning; no live sources."""
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest

from server.sli.semantic import password_attack_producer as producer
from server.sli.semantic import password_attack_v2 as pure
from tests.unit.test_password_attack_v2_portions import BASE, SCOPE, event


class Connection:
    def __init__(self, commit_error=None):
        self.info = SimpleNamespace(transaction_status=0)
        self.transactions = []
        self.commit_error = commit_error

    @contextmanager
    def transaction(self):
        index = len(self.transactions) + 1
        self.transactions.append([index, "open"])
        self.info.transaction_status = 2
        try:
            yield
            if self.commit_error == index:
                raise RuntimeError("private source contents must never escape")
            self.transactions[-1][1] = "commit"
        except Exception:
            self.transactions[-1][1] = "rollback"
            raise
        finally:
            self.info.transaction_status = 0

    @contextmanager
    def cursor(self):
        yield self


def wiring(monkeypatch, conn, *, batch_error=None, observe=True):
    calls = []
    def call(cur, name, *args):
        calls.append((len(conn.transactions), name, args))
        if name == "begin_password_attempt":
            return {"token": 7, "attempted_at": BASE.isoformat(), "state_revision": 2}
        if name == "observe_password_failure_v2":
            return observe
        pytest.fail(name)
    def batch(cur, rule, attempt):
        calls.append((len(conn.transactions), "batch", attempt["token"]))
        if batch_error:
            raise batch_error
        return {"status": "staged", "revision": 3, "health": {"status": "healthy"}}, 5, {}
    monkeypatch.setattr(producer, "_call", call)
    monkeypatch.setattr(producer, "_batch", batch)
    return calls


def test_entry_commits_issue_and_counts_jobs_only_after_second_commit(monkeypatch):
    conn = Connection()
    calls = wiring(monkeypatch, conn)
    result = producer.run_password_producer(conn, rule=pure.Rule(SCOPE, "brute"))
    assert result.jobs == 5 and not result.failed and result.status == "committed"
    assert conn.transactions == [[1, "commit"], [2, "commit"]]
    assert [item[0] for item in calls] == [1, 2]


@pytest.mark.parametrize("commit_error,batch_error", [(2, None), (None, ValueError("native private payload"))])
def test_rollback_then_failure_uses_same_committed_token(monkeypatch, commit_error, batch_error):
    conn = Connection(commit_error)
    calls = wiring(monkeypatch, conn, batch_error=batch_error)
    result = producer.run_password_producer(conn, rule=pure.Rule(SCOPE, "brute"))
    assert result.failed and result.jobs == 0 and result.failure_observed
    assert conn.transactions == [[1, "commit"], [2, "rollback"], [3, "commit"]]
    failure = calls[-1]
    assert failure[1] == "observe_password_failure_v2" and failure[2][2] == 7
    assert "private" not in repr(result) and "private" not in repr(failure)


def test_stale_failure_observation_does_not_change_failure_to_success(monkeypatch):
    conn = Connection(2)
    wiring(monkeypatch, conn, observe=False)
    result = producer.run_password_producer(conn, rule=pure.Rule(SCOPE, "brute"))
    assert result.failed and not result.failure_observed and result.jobs == 0


def test_issue_commit_failure_has_no_second_attempt_or_failure_observation(monkeypatch):
    conn = Connection(1)
    calls = wiring(monkeypatch, conn)
    result = producer.run_password_producer(conn, rule=pure.Rule(SCOPE, "brute"))
    assert result.failed and len(calls) == len(conn.transactions) == 1


def test_dirty_connection_rejected_before_any_transaction():
    conn = Connection()
    conn.info.transaction_status = 2
    with pytest.raises(ValueError, match="connection_not_idle"):
        producer.run_password_producer(conn, rule=pure.Rule(SCOPE, "brute"))
    assert not conn.transactions


def metadata(n=1):
    stamp = BASE + timedelta(seconds=200)
    return {"version": "sli.password.v2.window.1", "read_from": (stamp-timedelta(seconds=720)).isoformat(),
        "read_to": stamp.isoformat(), "finalizable_through": (stamp-timedelta(seconds=120)).isoformat(),
        "candidate_count": n, "truncated": False, "native_checked_count": n, "native_checks_complete": True,
        "unverifiable_count": 0, "oversized_count": 0, "error_code": None}


@pytest.mark.parametrize("delta", [{"native_checks_complete": False}, {"native_checked_count": 0},
    {"candidate_count": True}, {"error_code": "password_v2_native_unavailable"},
    {"truncated": True}, {"oversized_count": 1}, {"read_from": BASE.isoformat()}])
def test_window_requires_all_metadata_including_last_candidate_fatal(delta):
    with pytest.raises(producer.ProducerFailure):
        producer._window_metadata(metadata() | delta, attempted_at=BASE)


def test_shared_budget_reuses_current_pass_overlap_and_never_renews_quota():
    native = event(1)
    budget = producer.NativeBudget((native,))
    assert budget.plan((native.member.witness,)) == ()
    assert budget.count == 1 and budget.xml_bytes == len(native.source_xml.encode())
    budget.count = pure.MAX_ROWS
    with pytest.raises(producer.ProducerFailure, match="proof_bound"):
        budget.plan((event(2).member.witness,))


def test_retained_plan_checks_total_bytes_with_incoming_before_query():
    native = event(1)
    budget = producer.NativeBudget((native,))
    budget.xml_bytes = pure.MAX_XML_BYTES
    with pytest.raises(producer.ProducerFailure, match="proof_bound"):
        budget.plan((event(2).member.witness,))


def test_reuse_rejects_changed_commitment_in_same_pass():
    from dataclasses import replace
    native = event(1)
    with pytest.raises(producer.ProducerFailure, match="native_content_conflict"):
        producer.NativeBudget((native,)).plan((replace(native.member.witness, xml_bytes=3),))


def test_failed_window_stops_before_context_or_retained_work(monkeypatch):
    calls = []
    class Cursor:
        def execute(self, sql, args):
            calls.append(sql)
        def fetchall(self):
            return [{"record_kind": "metadata", "metadata": metadata() | {"error_code": "password_v2_native_unavailable"}}]
    def call(cur, name, *args):
        calls.append(name)
        assert name == "read_password_checkpoint_v2"
        return {"active_token": 7, "last_observed_token": 0, "state_revision": 0, "state_document": None}
    monkeypatch.setattr(producer, "_call", call)
    with pytest.raises(producer.ProducerFailure):
        producer._batch(Cursor(), pure.Rule(SCOPE, "brute"), {"token": 7, "state_revision": 0, "attempted_at": BASE.isoformat()})
    assert len(calls) == 2


class BatchCursor:
    def __init__(self, events, document=None):
        self.events = events
        self.metadata = document or metadata(len(events))
        self.queries = []

    def execute(self, sql, args=None):
        self.queries.append((sql, args))
        assert ("read_default_password_window_v2" in sql or "previous_role" in sql
                or "set local role" in sql or "set_config('role'" in sql or "bound_login" in sql)

    def fetchone(self):
        return {"previous_role": "adlog_semantic_worker", "semantic_usage": True, "storage_usage": True,
                "bound_login": True}

    def fetchall(self):
        return [{"record_kind": "metadata", "metadata": self.metadata}] + [
            {"record_kind": "event", "source_event_id": int(e.ref.native_id), "event_id": e.event_id,
                "occurred_at_utc": e.at, "sha256": e.ref.sha256, "source_xml": e.source_xml} for e in self.events]


def batch_wiring(monkeypatch, *, state=None, barriers=()):
    from server.sli.semantic import semantic_risk_runtime_repository as queue
    calls, jobs = [], []
    def call(cur, name, *args):
        calls.append((name, args))
        if name == "read_password_checkpoint_v2":
            return {"state_revision": 0, "active_token": 7, "last_observed_token": 0,
                        "state_document": state.document if state else None}
        if name == "prepare_password_producer_batch_v2":
            return {"status": "prepared", "state_revision": 0, "barriers": list(barriers),
                    "prelocked_entities": sorted(set(args[-1]) | {b["entity"] for b in barriers})}
        if name == "reserve_password_episode_emission":
            return {"status": "reserved", "signal_ids": [producer._signal(d).signal_id for d in args[-1]]}
        if name == "complete_password_producer_batch_v2":
            return {"status": "staged", "revision": 1, "watermark": args[-1].get("state", {}).get("watermark"),
                        "health": {"status": "partial" if barriers else "healthy"}}
        if name == "track_password_frozen_entity_v2":
            endpoint = pure._witness(args[5])
            barrier = next(b for b in barriers if b["episode_key"] == args[4])
            old = pure._witness(barrier["tracking_endpoint"])
            if endpoint.at - old.at > timedelta(seconds=600):
                return {"status": "successor_authorized", "successor_episode_key":
                        pure._key(pure.Rule(SCOPE, "brute"), args[6], barrier["entity"], endpoint)}
            return {"status": "held", "successor_episode_key": None}
        pytest.fail(name)
    def enqueue(cur, *, source_kind, source_id):
        jobs.append(source_id)
        return ("policy-a:" + source_id, "policy-b:" + source_id)
    monkeypatch.setattr(producer, "_call", call)
    monkeypatch.setattr(queue, "_enqueue_source", enqueue)
    return calls, jobs


def attempt():
    return {"token": 7, "state_revision": 0, "attempted_at": BASE.isoformat()}


def test_actual_root_all_portions_and_policy_jobs_use_single_reservation(monkeypatch):
    natives = tuple(event(i) for i in range(1, 301))
    cur = BatchCursor(natives)
    calls, jobs = batch_wiring(monkeypatch)
    completed, count, work = producer._batch(cur, pure.Rule(SCOPE, "brute"), attempt())
    reservations = [args for name, args in calls if name == "reserve_password_episode_emission"]
    assert len(reservations) == 1 and len(reservations[0][-1]) == 2
    assert len(jobs) == 2 and count == 4
    assert work["native_items"] == 300 and work["retained_queries"] == 0
    assert work["reservation_occurrences"] == 300
    assert len(cur.queries) == 1 and completed["status"] == "staged"
    payload = calls[-1][1][-1]
    assert payload["state"]["episodes"][0]["sequence"] == 1
    assert payload["window"]["native_checks_complete"] is True


def test_genuine_empty_poll_uses_new_window_completion_without_reservation(monkeypatch):
    calls, jobs = batch_wiring(monkeypatch)
    result, count, work = producer._batch(BatchCursor(()), pure.Rule(SCOPE, "brute"), attempt())
    assert count == 0 and not jobs and result["status"] == "staged"
    assert [name for name, _ in calls] == ["read_password_checkpoint_v2", "prepare_password_producer_batch_v2",
                                         "complete_password_producer_batch_v2"]
    assert work["native_items"] == 0 and calls[-1][1][-1]["state"]["watermark"] == metadata(0)["finalizable_through"]


@pytest.mark.parametrize("offsets,sequence", [((601,), 0), ((500, 700), 1)])
def test_nonqualifying_seed_does_not_authorize_a_successor(monkeypatch, offsets, sequence):
    from dataclasses import asdict, replace

    from tests.unit.test_password_attack_v2_portions import root
    _emission, state, natives = root(10)
    # The last successful admitted endpoint is frozen; a single later event
    # across a covered >600s gap is still only provisional prequalification.
    frozen = replace(state.episodes[0], frozen=True)
    state = replace(state, episodes=(frozen,), watermark=BASE + timedelta(seconds=300))
    incoming = tuple(event(11+i, at=BASE+timedelta(seconds=offset)) for i, offset in enumerate(offsets))
    endpoint = incoming[-1]
    now = BASE + timedelta(seconds=offsets[-1] + 200)
    window = metadata(len(incoming)) | {"read_from": (now-timedelta(seconds=720)).isoformat(), "read_to": now.isoformat(),
                               "finalizable_through": (now-timedelta(seconds=120)).isoformat()}
    barrier = {"episode_key": frozen.key, "entity": frozen.entity, "coverage_epoch": state.epoch,
        "seed": asdict(frozen.seed), "root_id": frozen.root_id, "last_sequence": frozen.sequence,
        "last_emission_id": frozen.last_emission, "last_admitted_endpoint": asdict(frozen.last),
        "totals": asdict(frozen.budget), "last_admitted_as_of": BASE.isoformat(), "admitted_revision": 1,
        "first_ledger_revision": 1, "tracking_endpoint": asdict(frozen.last), "tracking_epoch": state.epoch,
        "tracking_through": state.watermark.isoformat(), "successor_episode_key": None, "successor_seed": None, "successor_epoch": None}
    calls, _ = batch_wiring(monkeypatch, state=state, barriers=(barrier,))
    def fetch(self, cur, scope, witnesses):
        for item in natives:
            if item.member.witness in witnesses:
                self.add(item)
        self.plan(witnesses)
    monkeypatch.setattr(producer.NativeBudget, "fetch", fetch)
    _, count, _ = producer._batch(BatchCursor(incoming, window), pure.Rule(SCOPE, "brute"), attempt())
    assert count == 0
    tracking = [args for name, args in calls if name == "track_password_frozen_entity_v2"]
    assert not tracking
    next_episode = calls[-1][1][-1]["state"]["episodes"][0]
    assert next_episode["sequence"] == sequence
    if sequence == 0:
        assert next_episode["seed"]["at"] == endpoint.at.isoformat()
    else:
        assert next_episode["key"] == frozen.key and next_episode["frozen"]
        assert next_episode["last"]["at"] == endpoint.at.isoformat()
        assert next_episode["budget"] == asdict(frozen.budget)


@pytest.mark.parametrize("reason,old,new", [
    ("missing_target", '<Data Name="TargetUserName">synthetic</Data>', ''),
    ("unclassified_failure", '<Data Name="Status">0xc000006a</Data>', ''),
    ("ambiguous_failure", '<Data Name="Status">0xc000006a</Data>',
        '<Data Name="Status">0xc000006a</Data><Data Name="ResultCode">0xc0000064</Data>'),
    ("conflicting_client", '<Data Name="IpAddress">203.0.113.1</Data>',
        '<Data Name="IpAddress">203.0.113.1</Data><Data Name="ClientAddress">203.0.113.2</Data>'),
    ("missing_client", '<Data Name="IpAddress">203.0.113.1</Data>', ''),
])
def test_native_authorized_unattributed_member_advances_with_exact_partial_loss(monkeypatch, reason, old, new):
    native = event(1)
    native = pure.NativeEvent.from_row(SCOPE, dict(source_event_id=1, event_id=native.event_id,
        occurred_at_utc=native.at, sha256=native.ref.sha256, source_xml=native.source_xml.replace(old, new)))
    assert native.member.reason == reason
    calls, jobs = batch_wiring(monkeypatch)
    _, count, _ = producer._batch(BatchCursor((native,)), pure.Rule(SCOPE, "brute"), attempt())
    assert not jobs and count == 0
    payload = calls[-1][1][-1]
    assert payload["diagnostics"] == {reason: {"count": 1, "from": metadata()["read_from"],
                                             "to": metadata()["finalizable_through"]}}
    assert payload["state"]["watermark"] == metadata()["finalizable_through"]
    assert not payload["state"]["episodes"]


def test_queue_uses_same_semantic_cursor_without_role_switch_or_extra_membership(monkeypatch):
    from server.sli.semantic import semantic_risk_runtime_repository as queue
    from tests.unit.test_password_attack_v2_portions import root
    emission, _, _ = root(10)
    signals = producer._signals(pure.Rule(SCOPE, "brute"), emission, None, BASE)
    cur = object()
    seen = []
    def enqueue(current, *, source_kind, source_id):
        assert current is cur
        seen.append(source_id)
        return ("job",)
    monkeypatch.setattr(queue, "_enqueue_source", enqueue)
    assert producer._enqueue_all(cur, signals) == len(signals)
    assert seen == [signal.signal_id for signal in signals]


def test_queue_failure_never_issues_restore_sql_in_aborted_transaction(monkeypatch):
    from server.sli.semantic import semantic_risk_runtime_repository as queue
    from tests.unit.test_password_attack_v2_portions import root
    emission, _, _ = root(10)
    cur = BatchCursor(())
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic queue failure")
    monkeypatch.setattr(queue, "_enqueue_source", fail)
    with pytest.raises(RuntimeError, match="synthetic queue failure"):
        producer._enqueue_all(cur, producer._signals(pure.Rule(SCOPE, "brute"), emission, None, BASE))
    assert not any("set_config" in sql for sql, _ in cur.queries)


def test_covered_speculative_k601_cannot_strand_actual_k1202_admission(monkeypatch):
    from dataclasses import asdict, replace
    from tests.unit.test_password_attack_v2_portions import root
    rule = pure.Rule(SCOPE, "brute")
    _, state, originals = root(10)
    frozen = replace(state.episodes[0], frozen=True)
    state = replace(state, episodes=(frozen,), watermark=BASE + timedelta(seconds=300))
    barrier = dict(episode_key=frozen.key, entity=frozen.entity, coverage_epoch=0,
        seed=asdict(frozen.seed), root_id=frozen.root_id, last_sequence=frozen.sequence,
        last_emission_id=frozen.last_emission, last_admitted_endpoint=asdict(frozen.last),
        totals=asdict(frozen.budget), last_admitted_as_of=BASE.isoformat(), admitted_revision=1,
        first_ledger_revision=1, tracking_endpoint=asdict(frozen.last), tracking_epoch=0,
        tracking_through=state.watermark.isoformat(), successor_episode_key=None, successor_seed=None, successor_epoch=None)
    k601 = event(11, at=BASE + timedelta(seconds=601))
    current = list(originals) + [k601]
    def fetch(self, cur, scope, witnesses):
        self.plan(witnesses)
        for item in current:
            if item.member.witness in witnesses:
                self.add(item)
        assert not self.plan(witnesses)
    monkeypatch.setattr(producer.NativeBudget, "fetch", fetch)
    all_calls = []
    for tick, incoming in [(801, (k601,)), (1320, ()),
            (1402, tuple(event(20+i, at=BASE+timedelta(seconds=1202, microseconds=i)) for i in range(10)))]:
        current.extend(incoming)
        stamp = BASE + timedelta(seconds=tick)
        window = metadata(len(incoming)) | dict(read_from=(stamp-timedelta(seconds=720)).isoformat(),
            read_to=stamp.isoformat(), finalizable_through=(stamp-timedelta(seconds=120)).isoformat())
        calls, _ = batch_wiring(monkeypatch, state=state, barriers=(barrier,))
        _, count, _ = producer._batch(BatchCursor(incoming, window), rule, attempt())
        all_calls.append(calls)
        state = pure.State.from_document(calls[-1][1][-1]["state"])
        barrier["tracking_through"] = window["finalizable_through"]
        if tick < 1402:
            assert count == 0 and state.episodes[0].sequence == 0
    tracking = [[args for name, args in calls if name == "track_password_frozen_entity_v2"] for calls in all_calls]
    assert not tracking[0] and not tracking[1]
    assert pure._witness(tracking[2][0][5]).at == BASE + timedelta(seconds=1202)
    assert state.episodes[0].sequence == 1 and count == 2


@pytest.mark.parametrize("overflow", [False, True])
def test_scaled_shared_budget_includes_unaffected_episode_finalizer_commitments(monkeypatch, overflow):
    """8KiB scaled unit cap; actual XML lengths, real immutable pure State."""
    monkeypatch.setattr(pure, "MAX_XML_BYTES", 8192)
    rule = pure.Rule(SCOPE, "brute")
    old = tuple(event(i, at=BASE-timedelta(seconds=800)) for i in range(1, 11))
    state = pure.advance(rule, pure.State(), old, now=BASE-timedelta(seconds=600)).state
    state = pure.advance(rule, state, old, now=BASE-timedelta(seconds=200)).state
    state = pure.advance(rule, state, (), now=BASE+timedelta(seconds=200)).state
    assert not state.window and state.episodes[0].sequence == 1
    previous = state.document
    required = (state.episodes[0].seed, state.episodes[0].last)
    old_bytes = sum(w.xml_bytes for w in required)
    total = 8192 if overflow else 8192-old_bytes
    natives = []
    for index, size in enumerate((total//2, total-total//2), 21):
        item = event(index, at=BASE+timedelta(seconds=100))
        xml = item.source_xml.replace('>synthetic</Data>', '>other</Data>')
        padding = '<Data Name="Padding"></Data>'
        length = size-len((xml+padding).encode())
        assert length >= 0
        xml = xml.replace('</EventData>', padding.replace('></Data>', '>'+'x'*length+'</Data>')+'</EventData>')
        native = pure.NativeEvent.from_row(SCOPE, dict(source_event_id=index, event_id=item.event_id,
            occurred_at_utc=item.at, sha256=item.ref.sha256, source_xml=xml))
        assert native.member.witness.xml_bytes == size
        natives.append(native)
    assert all(n.member.entity(rule) != state.episodes[0].entity for n in natives)
    stamp = BASE+timedelta(seconds=250)
    win = metadata(2) | dict(read_from=(stamp-timedelta(seconds=720)).isoformat(), read_to=stamp.isoformat(),
                            finalizable_through=(stamp-timedelta(seconds=120)).isoformat())
    calls, jobs = batch_wiring(monkeypatch, state=state)
    transfers = []
    def fetch(self, cur, scope, witnesses):
        missing = self.plan(witnesses)
        if missing:
            transfers.extend(missing)
            self.retained_reads += 1
        for native in old:
            if native.member.witness in missing:
                self.add(native)
        assert not self.plan(witnesses)
    monkeypatch.setattr(producer.NativeBudget, "fetch", fetch)
    def no_history(*args):
        pytest.fail("unaffected episode whole immutable history must not be loaded")
    monkeypatch.setattr(producer, "_history", no_history)
    if overflow:
        with pytest.raises(producer.ProducerFailure, match="proof_bound"):
            producer._batch(BatchCursor(tuple(natives), win), rule, attempt())
        assert not transfers and not jobs and state.document == previous
        assert not any(name == "complete_password_producer_batch_v2" for name, _ in calls)
    else:
        _, count, work = producer._batch(BatchCursor(tuple(natives), win), rule, attempt())
        assert count == 0 and not jobs and set(transfers) == set(required)
        assert work["xml_bytes"] == 8192 and work["native_items"] == 4 and work["retained_queries"] == 1
