"""Automated checks for the single-production-owner invariant.

Collection: scripts/runtime/collection_worker.py is the sole designated
production owner; the in-process HTTP-server scheduler must stay off unless
explicitly opted into, and even then must never run a cycle concurrently
with the external worker.

Post-collection: scripts/runtime/post_collection_worker.py is the sole
designated production owner; the in-process ThreadPoolExecutor may still do
local/dev work, but only through the same atomic claim, so it can never
double-process a row the durable worker already claimed.
"""
from __future__ import annotations

import pathlib
from contextlib import contextmanager

from server.jobs import collector


def test_post_collection_worker_mode_is_external_when_external_worker_enabled(monkeypatch):
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "1")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")

    assert collector.post_collection_worker_mode() == "external"


def test_post_collection_worker_mode_is_in_process_when_only_opted_in(monkeypatch):
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")

    assert collector.post_collection_worker_mode() == "in_process"


def test_post_collection_worker_mode_is_disabled_when_neither_is_enabled(monkeypatch):
    monkeypatch.delenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", raising=False)
    monkeypatch.delenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", raising=False)

    assert collector.post_collection_worker_mode() == "disabled"


def test_collection_and_scheduler_runtime_status_report_the_same_post_collection_mode(monkeypatch):
    """Both status surfaces must never disagree with each other or with the
    single source of truth — a diagnostic that contradicts itself is worse
    than one that is merely wrong."""
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.delenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", raising=False)
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(collector, "_postgres_collection_enabled", lambda: True)
    monkeypatch.setattr(collector, "_collection_block_reason", lambda: None)

    collection_status = collector.get_collection_runtime_status()
    scheduler_status = collector.get_scheduler_runtime_status()

    assert collection_status["post_collection_worker_mode"] == "disabled"
    assert scheduler_status["post_collection_worker_mode"] == "disabled"


def test_startup_resume_of_persisted_post_collection_jobs_requires_the_opt_in():
    """server/api/http_server.py::run_server must not call
    resume_persisted_post_collection_jobs() on a plain boot: it is the same
    in-process rollback/diagnostic path as _enqueue_post_collection's local
    executor, and needs the same explicit opt-in instead of running whenever
    the external worker just happens to be off."""
    source = pathlib.Path("server/api/http_server.py").read_text(encoding="utf-8")
    startup_block = source[source.index("def run_server"):]
    resume_call = startup_block.index("resume_persisted_post_collection_jobs(")
    guard = startup_block.index("inprocess_post_collection_opt_in_enabled()")
    assert guard < resume_call, (
        "resume_persisted_post_collection_jobs() must be textually guarded by "
        "inprocess_post_collection_opt_in_enabled() in the startup block"
    )


def test_scheduler_is_disabled_by_default_with_no_environment(monkeypatch):
    monkeypatch.delenv("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER", raising=False)
    monkeypatch.delenv("ADLOG_DISABLE_SCHEDULER", raising=False)
    monkeypatch.delenv("ADLOG_ENABLE_POSTGRES_COLLECTION", raising=False)
    monkeypatch.delenv("ADLOG_POSTGRES_RUNTIME_COLLECTION", raising=False)

    status = collector.get_scheduler_runtime_status()

    assert status["scheduler_enabled"] is False
    assert status["disabled_reason"] == (
        "inprocess_scheduler_requires_ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"
    )
    assert status["inprocess_scheduler_opt_in"] is False


def test_scheduler_opt_in_alone_is_not_enough_without_postgres_collection_enabled(monkeypatch):
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER", "1")
    monkeypatch.delenv("ADLOG_DISABLE_SCHEDULER", raising=False)
    monkeypatch.delenv("ADLOG_ENABLE_POSTGRES_COLLECTION", raising=False)
    monkeypatch.delenv("ADLOG_POSTGRES_RUNTIME_COLLECTION", raising=False)
    monkeypatch.setattr(collector, "_runtime_db_backend", lambda: "postgres")

    status = collector.get_scheduler_runtime_status()

    assert status["inprocess_scheduler_opt_in"] is True
    assert status["scheduler_enabled"] is False
    assert status["disabled_reason"] == "postgres_runtime_collection_guard"


def test_scheduler_tick_skips_when_external_worker_holds_the_lock(monkeypatch):
    """Even if the opt-in flag were mistakenly set alongside a live external
    worker, a tick that cannot take the shared advisory lock must not start
    a second collection cycle."""
    calls: list[str] = []

    @contextmanager
    def lock_held_elsewhere(_connect, _name):
        yield False

    monkeypatch.setattr(collector, "session_advisory_lock", lock_held_elsewhere)
    monkeypatch.setattr(collector, "create_collect_job", lambda **k: calls.append(k) or {"id": 1})
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *a, **k: "ERR")
    monkeypatch.setattr(collector, "time", type("T", (), {"sleep": staticmethod(lambda *_: (_ for _ in ()).throw(StopIteration))})())

    try:
        collector._scheduler_loop(interval_seconds=1, hours=1, max_events_per_channel=10)
    except StopIteration:
        pass

    assert calls == []


def test_manual_collect_now_skips_when_another_process_holds_the_lock(monkeypatch):
    """Manual "Collect Now" (server/api/routes/runtime.py calling
    create_collect_job(reason="manual")) used to bypass
    COLLECTION_OWNER_LOCK_NAME entirely: create_collect_job() only spawns a
    background thread and returns immediately, so nothing upstream of that
    thread could hold the lock for the job's whole async duration the way
    the scheduler/collection_worker.py do. The thread itself now acquires
    the lock for exactly its own duration when reason == "manual"."""
    now = collector.utc_now()
    job = collector.Job(id=9001, kind="collect_all_dc_logs:manual", status="queued", servers=["DC1"], hours=1, max_events_per_channel=10, created_at=now, updated_at=now)
    with collector._lock:
        collector._jobs[job.id] = job

    @contextmanager
    def lock_held_elsewhere(_connect, _name):
        yield False

    body_calls: list[int] = []
    monkeypatch.setattr(collector, "session_advisory_lock", lock_held_elsewhere)
    monkeypatch.setattr(collector, "_run_collect_job_body", lambda job_id: body_calls.append(job_id))
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)

    try:
        collector._run_collect_job(job.id, "manual")
        result = collector.get_job(job.id)
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert body_calls == [], "the job body must never run once another process is confirmed to hold ownership"
    assert result["status"] == "skipped"
    assert result["skipped_reason"] == "external_owner_active"


def test_manual_collect_now_runs_when_the_lock_is_free(monkeypatch):
    now = collector.utc_now()
    job = collector.Job(id=9002, kind="collect_all_dc_logs:manual", status="queued", servers=["DC1"], hours=1, max_events_per_channel=10, created_at=now, updated_at=now)
    with collector._lock:
        collector._jobs[job.id] = job

    @contextmanager
    def lock_free(_connect, _name):
        yield True

    body_calls: list[int] = []
    monkeypatch.setattr(collector, "session_advisory_lock", lock_free)
    monkeypatch.setattr(collector, "_run_collect_job_body", lambda job_id: body_calls.append(job_id))

    try:
        collector._run_collect_job(job.id, "manual")
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert body_calls == [job.id]


def test_scheduled_and_external_worker_reasons_do_not_double_acquire_the_lock(monkeypatch):
    """The scheduler and collection_worker.py already hold
    COLLECTION_OWNER_LOCK_NAME themselves around their own call into
    create_collect_job() for the whole cycle. _run_collect_job() must not
    also try to acquire it a second time (on a different connection) for
    these two reasons -- that would misreport the caller's own held lock as
    "owned by someone else" and skip a legitimate cycle."""
    now = collector.utc_now()
    job = collector.Job(id=9003, kind="collect_all_dc_logs:scheduled", status="queued", servers=["DC1"], hours=1, max_events_per_channel=10, created_at=now, updated_at=now)
    with collector._lock:
        collector._jobs[job.id] = job

    def explode(*_a, **_k):
        raise AssertionError("session_advisory_lock must not be called for non-manual reasons")

    body_calls: list[int] = []
    monkeypatch.setattr(collector, "session_advisory_lock", explode)
    monkeypatch.setattr(collector, "_run_collect_job_body", lambda job_id: body_calls.append(job_id))

    try:
        collector._run_collect_job(job.id, "scheduled")
    finally:
        with collector._lock:
            collector._jobs.pop(job.id, None)

    assert body_calls == [job.id]


def test_scheduler_tick_runs_and_waits_for_terminal_when_lock_is_free(monkeypatch):
    calls: list[str] = []

    @contextmanager
    def lock_free(_connect, _name):
        yield True

    monkeypatch.setattr(collector, "session_advisory_lock", lock_free)
    monkeypatch.setattr(collector, "create_collect_job", lambda **k: calls.append("created") or {"id": 42})
    monkeypatch.setattr(collector, "get_job", lambda job_id: {"status": "completed"})
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(collector, "log_internal_error", lambda *a, **k: "ERR")
    monkeypatch.setattr(collector, "time", type("T", (), {"sleep": staticmethod(lambda *_: (_ for _ in ()).throw(StopIteration))})())

    try:
        collector._scheduler_loop(interval_seconds=1, hours=1, max_events_per_channel=10)
    except StopIteration:
        pass

    assert calls == ["created"]


def test_scheduler_wait_gives_up_after_its_bound_instead_of_holding_the_lock_forever(monkeypatch):
    """A stuck cycle must not hold the advisory lock forever and starve
    collection_worker.py of it — that would be worse than the race this
    guard exists to close."""
    logged: list[str] = []
    monkeypatch.setattr(collector, "get_job", lambda job_id: {"status": "running"})
    monkeypatch.setattr(
        collector, "log_internal_error",
        lambda _component, code, *_a, **_k: logged.append(code) or "ERR",
    )
    ticks = iter([0.0, 1.0, 2.0])
    monkeypatch.setattr(collector.time, "monotonic", lambda: next(ticks, 2.0))
    monkeypatch.setattr(collector.time, "sleep", lambda *_: None)

    collector._wait_for_scheduled_job_terminal(1, poll_seconds=0.1, max_wait_seconds=1.5)

    assert logged == ["scheduler_tick_wait_timed_out"]


def test_inprocess_post_collection_opt_in_defaults_to_false(monkeypatch):
    monkeypatch.delenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", raising=False)

    assert collector.inprocess_post_collection_opt_in_enabled() is False


def test_inprocess_post_collection_opt_in_rejects_garbage_values(monkeypatch):
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "banana")

    assert collector.inprocess_post_collection_opt_in_enabled() is False


def test_inprocess_post_collection_opt_in_accepts_truthy_value(monkeypatch):
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")

    assert collector.inprocess_post_collection_opt_in_enabled() is True


def test_post_collection_stays_queued_without_opt_in_and_without_external_worker(monkeypatch):
    """Neither the external worker nor the in-process opt-in is configured:
    the row must be queued for a later owner, and the in-process executor
    must not touch it at all (no claim attempt, nothing submitted)."""
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.delenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", raising=False)
    submitted: list[tuple] = []
    claimed_calls: list[str] = []
    queued_calls: list[str] = []
    events: list[str] = []

    class Immediate:
        def submit(self, fn, *args):
            submitted.append(args)

    monkeypatch.setattr(collector, "_post_collection_executor", Immediate())
    monkeypatch.setattr(
        collector, "queue_post_collection_job",
        lambda **k: queued_calls.append(k["durable_job_id"]) or {},
    )
    monkeypatch.setattr(
        collector, "claim_post_collection_job",
        lambda durable_job_id, **k: claimed_calls.append(durable_job_id) or {"durable_job_id": durable_job_id, "attempt_count": 1},
    )
    monkeypatch.setattr(collector, "log_event", lambda _component, code, *a, **k: events.append(code))
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-952")

    collector._enqueue_post_collection(952, ["DC1"], "t")

    assert queued_calls == ["runtime-952"]
    assert claimed_calls == []
    assert submitted == []
    assert "post_collection_inprocess_not_opted_in" in events


def test_post_collection_in_process_path_stands_down_when_row_claimed_elsewhere(monkeypatch):
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")
    submitted: list[tuple] = []

    class Immediate:
        def submit(self, fn, *args):
            submitted.append(args)

    monkeypatch.setattr(collector, "_post_collection_executor", Immediate())
    monkeypatch.setattr(collector, "queue_post_collection_job", lambda **k: {})
    monkeypatch.setattr(collector, "claim_post_collection_job", lambda durable_job_id, **k: None)
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-950")

    collector._enqueue_post_collection(950, ["DC1"], "t")

    assert submitted == []


def test_post_collection_in_process_path_runs_only_after_a_successful_claim(monkeypatch):
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "0")
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")
    submitted: list[tuple] = []

    class Immediate:
        def submit(self, fn, *args):
            submitted.append(args)

    monkeypatch.setattr(collector, "_post_collection_executor", Immediate())
    monkeypatch.setattr(collector, "queue_post_collection_job", lambda **k: {})
    monkeypatch.setattr(
        collector, "claim_post_collection_job",
        lambda durable_job_id, **k: {"durable_job_id": durable_job_id, "attempt_count": 1},
    )
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    with collector._post_collection_guard:
        collector._post_collection_active.discard("runtime-951")

    collector._enqueue_post_collection(951, ["DC1"], "t")

    assert len(submitted) == 1
    # job_id, servers, trace_id, durable_job_id, worker_id, claim_attempt
    assert submitted[0][3] == "runtime-951"
    assert submitted[0][4].startswith("inprocess-")
    assert submitted[0][5] == 1
