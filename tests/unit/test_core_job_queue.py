from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.core import job_executor as executor
from server.sli.core import job_queue as queue
from server.sli.core.job_registry import HandlerRegistry, pilot_registry, schedule_jobs, slot

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("error,expected", [
    (ValueError("executor_secret_missing"), {"error_type": "ValueError", "error_code": "executor_secret_missing"}),
    (RuntimeError("synthetic-password=private-value"), {"error_type": "RuntimeError", "error_code": "unexpected_error"}),
    (ValueError("synthetic-token=private-value"), {"error_type": "ValueError", "error_code": "unexpected_error"}),
    (OSError(13, "synthetic-private-path"), {"error_type": "PermissionError", "error_code": "os_error", "errno": 13}),
])
def test_executor_failure_reports_safe_reason_without_exception_text(monkeypatch, capsys, error, expected):
    def fail(*_args, **_kwargs):
        raise error

    monkeypatch.setattr(executor, "serve", fail)
    assert executor.main(["--profile", "light", "--once"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    event, payload = captured.err.strip().split(" ", 1)
    assert event == "core_executor_failed"
    assert json.loads(payload) == expected
    assert "private" not in captured.err
    assert "Traceback" not in captured.err


def test_executor_database_failure_reports_sqlstate_without_sql_or_rows(monkeypatch, capsys):
    from psycopg.errors import CheckViolation

    def fail(*_args, **_kwargs):
        raise CheckViolation("synthetic-password=private-value; failing row contains synthetic-identity")

    monkeypatch.setattr(executor, "serve", fail)
    assert executor.main(["--profile", "light", "--once"]) == 1
    event, payload = capsys.readouterr().err.strip().split(" ", 1)
    assert event == "core_executor_failed"
    assert json.loads(payload) == {
        "error_type": "CheckViolation", "error_code": "database_error", "sqlstate": "23514",
    }


def test_child_contract_failure_keeps_permanent_error_response(monkeypatch, capsys):
    def fail(*_args, **_kwargs):
        raise ValueError("synthetic-token=private-value")

    monkeypatch.setattr(executor, "child_main", fail)
    assert executor.main(["--profile", "light", "--child", "handler"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"status": "permanent_error", "error_code": "job_contract_invalid"}
    assert captured.err == ""


def test_executor_failure_hides_custom_type_names_and_malformed_sqlstate(monkeypatch, capsys):
    from psycopg import Error

    private_error = type("synthetic_private_identity", (Exception,), {})
    malformed_state = type("SyntheticDatabaseError", (Error,), {"sqlstate": "23514\nsynthetic-private"})
    for error, expected in (
        (private_error("private-value"), {"error_type": "Exception", "error_code": "unexpected_error"}),
        (malformed_state("private-value"), {"error_type": "Exception", "error_code": "database_error"}),
    ):
        def fail(*_args, **_kwargs):
            raise error

        monkeypatch.setattr(executor, "serve", fail)
        assert executor.main(["--profile", "light", "--once"]) == 1
        assert json.loads(capsys.readouterr().err.strip().split(" ", 1)[1]) == expected


class Connection:
    """Fake transaction boundary: effects must roll back after a failed fence."""
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.effects = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    @contextmanager
    def transaction(self):
        before = list(self.effects)
        try:
            yield
        except Exception:
            self.effects[:] = before
            raise

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchone(self):
        return (self.responses.pop(0),)


def job():
    registry = pilot_registry()
    handler = registry.handlers[next(key for key in registry.handlers if key[1] == "radius-session-observation")]
    spec = {**handler, "job_type": handler["kind"], "plugin_id": "sli.remote-access", "source_instance_id": "synthetic-source",
            "job_id": "00000000-0000-0000-0000-000000000001", "lease_token": "00000000-0000-0000-0000-000000000002",
            "lease_generation": 2, "remaining_seconds": 60,
            "partition_key": "radius-session-observation", "input_sha256": "a" * 64,
            "pinned_input": {"subscription_id": "synthetic-subscription", "delivery_ids": [1]}}
    spec["input_sha256"] = queue.digest(spec["pinned_input"])
    return spec


def test_enqueue_duplicate_conflict_and_claim_pin():
    spec = job()
    conn = Connection([spec["job_id"], spec["job_id"], None, spec])
    assert queue.enqueue(conn, spec) == queue.enqueue(conn, spec)
    with pytest.raises(queue.JobConflict, match="job_identity_conflict"):
        queue.enqueue(conn, {**spec, "input_sha256": "b" * 64})
    assert queue.claim(conn, "light", "synthetic-executor", pilot_registry().identities("light")) == spec
    assert "manifest_sha256" in conn.calls[-1][1][-1]


def test_idempotency_excludes_attempt_and_lease_and_tracks_input_range():
    spec = job()
    pinned = {"generation": "1", "input_range": [0, 50], "policy_revision": "1", "continuation": None}
    key = queue.idempotency_key(spec, pinned)
    assert queue.idempotency_key({**spec, "lease_token": "other", "attempts": 3}, pinned) == key
    assert queue.idempotency_key(spec, {**pinned, "input_range": [50, 100]}) != key


@pytest.mark.parametrize("state", ["lost", None])
def test_lost_fence_never_invokes_effects(state):
    conn = Connection([state])
    with pytest.raises(queue.LeaseLost):
        queue.publish(conn, job(), {"status": "success"}, lambda *_: conn.effects.append("effect"))
    assert not conn.effects
    assert len(conn.calls) == 1


def test_expiry_during_publication_rolls_back_every_effect():
    conn = Connection(["publish", False])
    with pytest.raises(queue.LeaseLost):
        queue.publish(conn, job(), {"status": "success"}, lambda *_: conn.effects.append("checkpoint"))
    assert not conn.effects
    assert "begin_core_job_result" in conn.calls[0][0]
    assert "finish_core_job_result" in conn.calls[1][0]


def test_publish_once_then_duplicate_or_conflict_without_reapplying():
    conn = Connection(["publish", True, "duplicate", "conflict"])
    def effect(*_):
        conn.effects.append("receipt")
    result = {"status": "partial", "delivery_ids": [1]}
    assert queue.publish(conn, job(), result, effect) == "committed"
    assert queue.publish(conn, job(), result, effect) == "duplicate"
    assert queue.publish(conn, job(), {**result, "delivery_ids": [2]}, effect) == "conflict"
    assert conn.effects == ["receipt"]
    stored = json.loads(conn.calls[1][1][-2])
    assert stored["result_sha256"] == conn.calls[0][1][-1]
    from server.sli.core.job_registry import validate_shape
    schema = json.loads((ROOT / "config/plugin_architecture_v3.json").read_text("utf-8"))
    validate_shape(stored, schema["$defs"]["result"], schema)


def test_heartbeat_and_failure_use_both_fence_coordinates():
    conn = Connection([True, True, False, False])
    queue.heartbeat(conn, job())
    queue.fail(conn, job(), "job_child_failed", permanent=True)
    assert conn.calls[0][1] == queue.fence(job())
    assert conn.calls[1][1] == (*queue.fence(job()), "job_child_failed", True)
    with pytest.raises(queue.LeaseLost):
        queue.heartbeat(conn, job())
    with pytest.raises(queue.LeaseLost):
        queue.fail(conn, job(), "job_child_failed")


@pytest.mark.parametrize("change", [
    {"handler_version": "9.0.0"}, {"manifest_sha256": "b" * 64},
    {"rights_profile": "ad-read"}, {"budget": {"wall_seconds": 999}},
])
def test_registry_never_reassigns_old_jobs_or_changes_their_rights(change):
    with pytest.raises(ValueError, match="handler_version_unavailable"):
        pilot_registry().resolve({**job(), **change})


def test_manifest_validates_handlers_and_schedule_references_before_registration():
    registry = HandlerRegistry()
    manifest = deepcopy(pilot_registry().manifests[0])
    manifest["handlers"][0]["handler_id"] = "unreviewed-handler"
    with pytest.raises(ValueError, match="handler_not_allowlisted"):
        registry.register(manifest)
    assert not registry.handlers
    manifest = deepcopy(pilot_registry().manifests[0])
    manifest["schedules"][0]["handler_id"] = "missing"
    with pytest.raises(ValueError, match="schedule_reference_invalid"):
        registry.register(manifest)
    assert not registry.handlers


def test_profile_budgets_are_minimum_of_manifest_and_core():
    manifest = deepcopy(pilot_registry().manifests[0])
    manifest["handlers"][1]["budget"]["memory_bytes"] = 10**12
    registry = HandlerRegistry()
    registry.register(manifest)
    handler = next(h for h in registry.handlers.values() if h["handler_id"] == "radius-session-observation")
    assert handler["budget"]["memory_bytes"] == 256 * 1024 * 1024
    assert handler["budget"]["max_db_connections"] == 1


def test_periodic_scheduler_replays_same_slot_and_skips_acquisition():
    source = {"source_instance_id": "synthetic-source", "subscription_id": "synthetic-subscription",
              "revision": "1", "access_scope": {"mode": "restricted"}}
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    conn = Connection([now, "synthetic-job", now, "synthetic-job"])
    schedule_jobs(conn, pilot_registry(), "light", source)
    schedule_jobs(conn, pilot_registry(), "light", source)
    calls = [json.loads(params[0]) for sql, params in conn.calls if "enqueue_core_job" in sql]
    assert len(calls) == 2
    assert calls[0]["idempotency_key"] == calls[1]["idempotency_key"]
    assert all(spec["handler_id"] == "radius-session-observation" for spec in calls)
    assert calls[0]["source_instance_id"] == source["source_instance_id"]


def test_calendar_repeated_hour_has_one_identity_and_input_trigger_requires_input():
    schedule = {"trigger": "calendar", "timezone": "America/New_York", "calendar": {"local_times": ["01:30"]}}
    first = datetime(2026, 11, 1, 5, 30, tzinfo=timezone.utc)
    second = datetime(2026, 11, 1, 6, 30, tzinfo=timezone.utc)
    assert slot(schedule, first) == slot(schedule, second)
    assert slot({"trigger": "input_available"}, first) is None
    assert slot({"trigger": "input_available"}, first, "generation-1") == "generation-1"


def test_timeout_kills_child_group_and_passes_only_its_profile_identity(monkeypatch):
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", "synthetic-file")
    monkeypatch.setattr(executor, "connection_settings", lambda profile, purpose: {"user": f"synthetic-{profile}-{purpose}"})
    monkeypatch.setenv("ADLOG_PG_DSN", "synthetic-admin")
    monkeypatch.setenv("SLI_JOB_PUBLISHER_HEAVY_PASSWORD", "synthetic-other-profile")
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", "/opt/sli/plugins")
    monkeypatch.setenv("SLI_PLUGIN_LOCK_DIR", "/opt/sli/plugin-locks")
    ticks = iter([0, 0, 1, 3])
    seen = []
    killed = []
    process = SimpleNamespace(pid=123, poll=lambda: None)
    def popen(argv, **kwargs):
        seen.append((argv, kwargs))
        return process
    with pytest.raises(TimeoutError, match="job_deadline_exceeded"):
        executor.run_child(job(), "handler", deadline=2, clock=lambda: next(ticks),
                           sleep=lambda _: None, popen=popen, terminate=killed.append)
    assert killed == [process]
    assert seen[0][1]["start_new_session"] is True
    assert seen[0][1]["env"]["SLI_PLUGIN_RUNTIME_DIR"] == "/opt/sli/plugins"
    assert seen[0][1]["env"]["SLI_PLUGIN_LOCK_DIR"] == "/opt/sli/plugin-locks"
    assert "ADLOG_PG_DSN" not in seen[0][1]["env"]
    assert "SLI_JOB_PUBLISHER_HEAVY_PASSWORD" not in seen[0][1]["env"]
    assert json.loads(seen[0][1]["env"]["SLI_JOB_CHILD_CONNECTION"])["user"] == "synthetic-light-executor"


def test_lost_lease_while_child_runs_always_kills_group(monkeypatch):
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", "synthetic-file")
    monkeypatch.setattr(executor, "connection_settings", lambda *_: {})
    ticks = iter([0, 11])
    killed = []
    process = SimpleNamespace(pid=123, poll=lambda: None)
    def heartbeat():
        raise queue.LeaseLost("job_lease_lost")
    with pytest.raises(queue.LeaseLost):
        executor.run_child(job(), "handler", deadline=100, heartbeat=heartbeat,
                           clock=lambda: next(ticks), popen=lambda *_, **__: process,
                           terminate=killed.append)
    assert killed == [process]


def test_group_kill_uses_sigkill_and_waits_for_stopped_process(monkeypatch):
    calls = []
    monkeypatch.setattr(executor.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    process = SimpleNamespace(pid=123, wait=lambda: calls.append("stopped"))
    executor.kill_group(process)
    assert calls == [(123, executor.signal.SIGKILL), "stopped"]


def test_successful_child_also_cleans_up_descendants_and_records_core_usage(monkeypatch):
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", "synthetic-file")
    monkeypatch.setattr(executor, "connection_settings", lambda *_: {})
    stopped = []
    process = SimpleNamespace(pid=123, returncode=0, poll=lambda: 0)
    def popen(_argv, **kwargs):
        kwargs["stdout"].write(b'{"status":"partial","delivery_ids":[1]}')
        kwargs["stdout"].flush()
        return process
    result = executor.run_child(job(), "handler", deadline=1, clock=lambda: 0,
                                popen=popen, terminate=stopped.append)
    assert stopped == [process]
    assert result["delivery_ids"] == [1]
    assert result["resource_usage"]["wall_seconds"] >= 0


def test_shutdown_drains_without_claiming_new_jobs(monkeypatch):
    monkeypatch.setattr(executor, "STOP", SimpleNamespace(is_set=lambda: True))
    monkeypatch.setattr(executor, "connect", lambda *_: pytest.fail("claim during drain"))
    assert executor.serve("light", once=True) == 0


def test_staged_input_hash_is_checked_before_handler_execution():
    with pytest.raises(ValueError, match="job_input_hash_conflict"):
        pilot_registry().resolve({**job(), "input_sha256": "0" * 64})


@pytest.mark.parametrize("error,permanent", [(TimeoutError(), False), (RuntimeError(), False), (ValueError(), True)])
def test_executor_classifies_retry_or_quarantine_and_never_publishes_after_failure(monkeypatch, error, permanent):
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    conn = Connection([True, True])
    calls = []
    def child(_job, purpose, **_kwargs):
        calls.append(purpose)
        raise error
    executor.execute_job(conn, pilot_registry(), job(), child=child, clock=lambda: 0)
    assert calls == ["handler"]
    assert conn.calls[-1][1][-1] is permanent


def test_flag_off_does_not_connect_or_schedule(monkeypatch):
    monkeypatch.delenv(executor.FLAG, raising=False)
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(executor, "connect", lambda *_: pytest.fail("default path touched database"))
    assert executor.serve("light", once=True) == 0
    assert not executor.pilot_enabled()


def test_pilot_schedules_only_the_explicit_source_binding(monkeypatch):
    from contextlib import nullcontext
    source = {"source_instance_id": "synthetic-source", "subscription_id": "synthetic-subscription",
              "revision": "1", "delivery_ids": [1], "access_scope": {"mode": "restricted"}}
    conn = Connection([True, source, datetime(2026, 1, 1, tzinfo=timezone.utc), "synthetic-job", None])
    monkeypatch.setenv(executor.FLAG, "1")
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    monkeypatch.setenv("SLI_CORE_JOB_RADIUS_SOURCE_INSTANCE_ID", "synthetic-source")
    monkeypatch.setattr(executor, "connect", lambda *_: nullcontext(conn))
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    assert executor.serve("light", once=True) == 0
    binding = next(params for sql, params in conn.calls if "read_radius_job_source_v1" in sql)
    assert binding == ("synthetic-source",)


def test_acquisition_is_blocked_without_opening_source_or_db():
    spec = {**job(), "handler_id": "radius-acquisition"}
    result = executor.stage_radius(None, spec)
    assert result["status"] == "blocked" and result["error_code"] == "acquisition_disabled"
    assert result["coverage_state"] == "not_collected"


def test_retryable_handler_result_consumes_attempt_but_does_not_publish(monkeypatch):
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_args, **_kwargs: None)
    conn = Connection([True, True])
    calls = []
    def child(_job, purpose, **_kwargs):
        calls.append(purpose)
        return {"status": "retryable_error"}
    executor.execute_job(conn, pilot_registry(), job(), child=child, clock=lambda: 0)
    assert calls == ["handler"]
    assert conn.calls[-1][1][-1] is False


def test_cancelled_result_has_no_radius_effect(radius_admission):
    executor.apply_radius(None, job(), {"status": "cancelled"})
    assert radius_admission[0] == []


@pytest.fixture
def radius_admission(monkeypatch):
    from server.sli.plugins.remote_access import jobs as radius_jobs

    calls = []
    lease = object()
    def acquire(_conn, **kwargs):
        calls.append(("acquire", kwargs))
        return lease
    def release(_conn, **kwargs):
        calls.append(("release", kwargs))
        return True
    monkeypatch.setattr(radius_jobs, "acquire_component_lease", acquire)
    monkeypatch.setattr(radius_jobs, "release_component_lease", release)
    return calls, lease


def test_radius_publication_reuses_consumer_inside_fence_without_set_role(monkeypatch, radius_admission):
    from server.source_packs.radius import session_consumer as consumer
    calls = []
    monkeypatch.setattr(consumer, "load_consumer_contract", lambda **_: {"subscription_id": "synthetic-subscription"})
    def claim(conn, **kwargs):
        calls.append(kwargs)
        return [SimpleNamespace(delivery_id=1, lease_token="synthetic-token")]
    monkeypatch.setattr(consumer, "claim_radius_deliveries", claim)
    monkeypatch.setattr(consumer, "process_radius_delivery", lambda conn, **kwargs: calls.append(kwargs))
    executor.apply_radius(None, job(), {"status": "partial", "delivery_ids": [1]})
    assert calls[0]["delivery_ids"] == (1,)
    assert all(call["activate_role"] is False for call in calls)
    admission, lease = radius_admission
    assert [action for action, _ in admission] == ["acquire", "release"]
    assert all(params["activate_role"] is False for _, params in admission)
    assert admission[0][1]["component_id"] == "radius-session-observation"
    assert admission[0][1]["holder_key"] == admission[1][1]["holder_key"]
    assert admission[1][1]["lease"] is lease


def test_radius_publication_rejects_mismatched_source_and_changed_input(monkeypatch, radius_admission):
    from server.source_packs.radius import session_consumer as consumer
    monkeypatch.setattr(consumer, "load_consumer_contract", lambda **_: {"subscription_id": "different-subscription"})
    with pytest.raises(ValueError, match="radius_source_binding_conflict"):
        executor.apply_radius(None, job(), {"status": "partial", "delivery_ids": [1]})
    monkeypatch.setattr(consumer, "load_consumer_contract", lambda **_: {"subscription_id": "synthetic-subscription"})
    monkeypatch.setattr(consumer, "claim_radius_deliveries", lambda *_args, **_kwargs: [])
    with pytest.raises(ValueError, match="radius_input_changed"):
        executor.apply_radius(None, job(), {"status": "partial", "delivery_ids": [1]})
    assert [action for action, _ in radius_admission[0]] == ["acquire"]


def test_radius_publication_rejects_failed_component_lease_release(monkeypatch, radius_admission):
    from server.sli.plugins.remote_access import jobs as radius_jobs
    from server.sli.sources.plugin_runtime_admission import PluginRuntimeAdmissionError
    from server.source_packs.radius import session_consumer as consumer

    monkeypatch.setattr(consumer, "load_consumer_contract", lambda **_: {"subscription_id": "synthetic-subscription"})
    monkeypatch.setattr(consumer, "claim_radius_deliveries", lambda *_a, **_kw: [
        SimpleNamespace(delivery_id=1, lease_token="synthetic-token"),
    ])
    monkeypatch.setattr(consumer, "process_radius_delivery", lambda *_a, **_kw: None)
    monkeypatch.setattr(radius_jobs, "release_component_lease", lambda *_a, **_kw: False)
    with pytest.raises(PluginRuntimeAdmissionError, match="component_lease_release_invalid"):
        executor.apply_radius(None, job(), {"status": "partial", "delivery_ids": [1]})


def test_legacy_consumer_lease_blocks_core_publication_before_delivery_claim(monkeypatch):
    from psycopg.errors import UniqueViolation
    from server.sli.plugins.remote_access import jobs as radius_jobs
    from server.source_packs.radius import session_consumer as consumer
    monkeypatch.setattr(consumer, "load_consumer_contract", lambda **_: {"subscription_id": "synthetic-subscription"})
    monkeypatch.setattr(consumer, "claim_radius_deliveries", lambda *_a, **_kw: pytest.fail("second consumer claimed deliveries"))
    def busy(*_args, **_kwargs):
        raise UniqueViolation("component_busy")
    monkeypatch.setattr(radius_jobs, "acquire_component_lease", busy)
    with pytest.raises(UniqueViolation):
        executor.apply_radius(None, job(), {"status": "partial", "delivery_ids": [1]})


def test_pilot_cannot_schedule_or_claim_while_legacy_host_holds_lock(monkeypatch):
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    from contextlib import nullcontext
    conn = Connection([False])
    monkeypatch.setenv(executor.FLAG, "1")
    monkeypatch.setattr(executor, "write_heartbeat", lambda *_a, **_kw: None)
    monkeypatch.setattr(executor, "connect", lambda *_: nullcontext(conn))
    assert executor.serve("light", once=True) == 0
    assert len(conn.calls) == 1
    assert conn.calls[0][1] == ("sli.remote-access:radius-session-observation:host:v1",)
