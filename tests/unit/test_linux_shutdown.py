"""Linux update fences finish active work without consuming durable backlogs."""
import signal
import subprocess
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from deploy.linux import entrypoint
from scripts.runtime import semantic_production_worker as semantic
from server.sli.ops import shutdown


@pytest.mark.parametrize('kind', ['default', 'sigma'])
def test_semantic_detection_batches_stop_between_committed_items(monkeypatch, kind):
    from server.sli.semantic import default_detections as defaults
    from server.sli.sigma import live_runtime as sigma

    calls = []

    class Cursor:
        def execute(self, *args):
            pass

        def fetchall(self):
            return [{'source': {'scope': {'synthetic': 'source'}}, 'policy_id': 'fixture', 'policy_version': 1}] * 3

        def fetchone(self):
            return {'page': {'items': []}}

    def evaluate(*args, **kwargs):
        calls.append('work')
        signal.raise_signal(signal.SIGTERM)
        return defaults.SourceOutcome(jobs=1) if kind == 'default' else 1

    conn = SimpleNamespace(transaction=lambda: nullcontext(), cursor=lambda: nullcontext(Cursor()))
    monkeypatch.setattr(defaults, 'require_password_connection_idle', lambda conn: None)
    monkeypatch.setattr(defaults, 'run_source', evaluate)
    monkeypatch.setattr(sigma, 'evaluate_revision', evaluate)
    with shutdown.graceful_shutdown():
        result = defaults.run_default_detections(conn) if kind == 'default' else sigma.run_sigma_detections(conn)
    assert calls == ['work'] and result['jobs'] == 1 and result['failed'] == 0


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("stuck", [False, True])
def test_api_supervisor_forwards_stop_and_bounds_all_child_threads(monkeypatch, capsys, sig, stuck):
    previous = {value: signal.getsignal(value) for value in (signal.SIGTERM, signal.SIGINT)}
    clock = [0.0]
    calls = []

    class Child:
        def terminate(self):
            calls.append("terminate")

        def kill(self):
            calls.append("kill")

        def wait(self, timeout=None):
            if not calls:
                calls.append("running")
                signal.raise_signal(sig)
                raise subprocess.TimeoutExpired("fixture", timeout)
            if stuck and "kill" not in calls:
                clock[0] += entrypoint.API_SHUTDOWN_SECONDS
                signal.raise_signal(sig)  # Repeated signals must not renew the deadline.
                raise subprocess.TimeoutExpired("fixture", timeout)
            return -9 if stuck else 0

    def spawn(argv):
        assert argv == [entrypoint.sys.executable, "-m", "scripts.run_server", "--port", "8443"]
        return nullcontext(Child())

    monkeypatch.setattr(entrypoint.subprocess, "Popen", spawn)
    monkeypatch.setattr(entrypoint.time, "monotonic", lambda: clock[0])
    assert entrypoint.run_api(["--port", "8443"]) == (1 if stuck else 0)
    assert calls == ["running", "terminate", *(["kill"] if stuck else [])]
    assert capsys.readouterr().err == ("api_shutdown_timeout\n" if stuck else "")
    assert all(signal.getsignal(value) == handler for value, handler in previous.items())


@pytest.mark.parametrize("code,expected", [(0, 0), (7, 7), (-15, 1)])
def test_api_supervisor_preserves_child_failure(monkeypatch, code, expected):
    monkeypatch.setattr(entrypoint.subprocess, "Popen", lambda argv: nullcontext(
        SimpleNamespace(wait=lambda **kwargs: code)))
    assert entrypoint.run_api([]) == expected


def test_api_supervisor_allows_active_request_longer_than_old_stop_budget(monkeypatch):
    clock = [0.0]

    class Child:
        def terminate(self):
            pass

        def kill(self):
            pytest.fail("an active request must have more than the old 20-second budget")

        def wait(self, timeout=None):
            if clock[0] == 0:
                signal.raise_signal(signal.SIGTERM)
                clock[0] = 30.0
                raise subprocess.TimeoutExpired("fixture", timeout)
            return 0

    monkeypatch.setattr(entrypoint.subprocess, "Popen", lambda _: nullcontext(Child()))
    monkeypatch.setattr(entrypoint.time, "monotonic", lambda: clock[0])
    assert entrypoint.run_api([]) == 0


@pytest.mark.parametrize("active", [False, True])
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_backup_stop_wakes_idle_loop_and_joins_current_backup(tmp_path, monkeypatch, active, sig):
    from datetime import datetime, timezone
    from pathlib import Path
    from threading import Event

    from deploy.linux import backup

    started, committed = Event(), Event()
    calls = []
    now = datetime(2026, 10, 18, 2, tzinfo=timezone.utc)

    def run_backup(*args, **kwargs):
        calls.append("backup")
        started.set()
        assert shutdown._STOP.wait(2)
        committed.set()
        return Path("fixture-backup")

    def heartbeat(*args, next_backup):
        if active:
            assert next_backup is None
            assert started.wait(2)
            assert not committed.is_set()
        else:
            assert next_backup > now
        signal.raise_signal(sig)

    monkeypatch.setattr(backup, "backup_root", lambda: tmp_path)
    monkeypatch.setattr(backup, "scheduled_backup", run_backup)
    monkeypatch.setattr(backup, "heartbeat", heartbeat)
    # Zero startup delay permits a backup only at the configured daily slot.
    monkeypatch.setattr(backup, "utc_now", lambda: now)
    monkeypatch.setenv("SLI_BACKUP_TIME", now.astimezone().strftime("%H:%M"))
    monkeypatch.setenv("SLI_BACKUP_START_DELAY_SECONDS", "0" if active else "300")
    assert backup.main([]) == 0
    assert calls == (["backup"] if active else [])
    assert committed.is_set() == active
    assert not shutdown.requested()


@pytest.mark.parametrize("service", entrypoint.WORKERS)
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_linux_worker_entrypoint_installs_and_restores_signals(service, monkeypatch, sig):
    previous = {value: signal.getsignal(value) for value in (signal.SIGTERM, signal.SIGINT)}
    calls = []

    def main():
        assert not shutdown.requested()
        signal.raise_signal(sig)
        assert shutdown.requested()
        shutdown.wait(60, sleep=lambda _: pytest.fail("shutdown must wake idle workers immediately"))
        calls.append("batch_finished")
        return 0

    monkeypatch.setattr(entrypoint.sys, "argv", ["entrypoint", service])
    monkeypatch.setattr(entrypoint.importlib, "import_module", lambda _: SimpleNamespace(main=main))
    assert entrypoint.main() == 0
    assert calls == ["batch_finished"] and not shutdown.requested()
    assert all(signal.getsignal(value) == handler for value, handler in previous.items())


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_worker_shutdown_handler_covers_import_and_restores_on_failure(monkeypatch, sig):
    previous = {value: signal.getsignal(value) for value in (signal.SIGTERM, signal.SIGINT)}

    def import_module(_):
        signal.raise_signal(sig)
        assert shutdown.requested()
        raise RuntimeError("fixture_startup_failed")

    monkeypatch.setattr(entrypoint.sys, "argv", ["entrypoint", "semantic"])
    monkeypatch.setattr(entrypoint.importlib, "import_module", import_module)
    with pytest.raises(RuntimeError, match="fixture_startup_failed"):
        entrypoint.main()
    assert not shutdown.requested()
    assert all(signal.getsignal(value) == handler for value, handler in previous.items())


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_semantic_backlog_continues_after_version_restart(monkeypatch, sig):
    queue = {"pending": 176000, "completed": 0, "leased": 0}
    beats = []
    monkeypatch.setattr(semantic, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(semantic, "postgres_secret_parts", lambda *_: {"configured": True})
    monkeypatch.setattr(semantic, "_singleton_lock", lambda: nullcontext(True))
    monkeypatch.setattr(semantic, "_archive_reader", lambda: object())
    monkeypatch.setattr(semantic, "stop_requested", lambda *_: False)
    monkeypatch.setattr(semantic, "semantic_runtime_mode_from_env", lambda: semantic.FACTS_MODE)
    monkeypatch.setattr(semantic, "semantic_v2_quarantine_repair_plan_digest_from_env", lambda: None)
    monkeypatch.setattr(semantic, "validate_semantic_runtime_settings", lambda *_: None)
    monkeypatch.setattr(semantic, "_details", lambda **_: {})
    monkeypatch.setattr(semantic, "record_worker_heartbeat", lambda **kw: beats.append(kw))

    def finish_batch(**kwargs):
        queue["pending"] -= 1
        queue["leased"] += 1
        signal.raise_signal(sig)
        # The signal does not interrupt the active transaction/lease completion.
        assert shutdown.requested() and queue["leased"] == 1
        queue["leased"] -= 1
        queue["completed"] += 1
        return {"completed": 1, "claimed": 1, "failed": 0}

    monkeypatch.setattr(semantic, "run_production_once", finish_batch)
    monkeypatch.setattr(semantic, "semantic_cycle_has_work", lambda _: True)
    for expected in (1, 2):
        with shutdown.graceful_shutdown():
            assert semantic.run(once=False, poll_seconds=60, limit=1) == 0
        assert queue == {"pending": 176000 - expected, "completed": expected, "leased": 0}
        assert beats[-1]["phase"] == "production_stop_requested"


def test_http_sigterm_closes_admission_and_keeps_request_threads_joinable():
    from threading import Event

    class Server:
        daemon_threads = True
        stopped = Event()

        def shutdown(self):
            self.stopped.set()

    server = Server()
    previous = signal.getsignal(signal.SIGTERM)
    with shutdown.http_shutdown(server):
        assert not server.daemon_threads
        signal.raise_signal(signal.SIGTERM)
        assert server.stopped.wait(2)
        assert server.sli_stopping
    assert signal.getsignal(signal.SIGTERM) == previous


@pytest.mark.parametrize("kind", ["entity", "projection", "storage"])
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_projection_workers_finish_one_cycle_on_stop(kind, monkeypatch, sig):
    from scripts.runtime import entity_state_worker as entity
    from scripts.runtime import storage_lifecycle_worker as storage
    from scripts.runtime import what_where_when_projection_worker as projection

    calls = []

    def cycle(**kwargs):
        calls.append("cycle_finished")
        signal.raise_signal(sig)
        return {"status": "ok", "failed": 0}

    worker = {"entity": entity, "projection": projection, "storage": storage}[kind]
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **_: None)
    if kind == "entity":
        monkeypatch.setattr(entity, "log_event", lambda *a, **kw: None)
        monkeypatch.setattr(entity, "entity_state_worker_lock", lambda: nullcontext(True))
        monkeypatch.setattr(entity, "run_once", cycle)
        run = lambda: entity.run(once=False, poll_seconds=60, limit=1)
    elif kind == "projection":
        monkeypatch.setattr(projection, "session_advisory_lock", lambda *a: nullcontext(True))
        monkeypatch.setattr(projection, "run_projection_cycle", cycle)
        run = lambda: projection.run(once=False, batch_limit=1, retention_limit=1)
    else:
        monkeypatch.setattr(storage, "lifecycle_lock", lambda: nullcontext(True))
        monkeypatch.setattr(storage, "_capacity_evidence", dict)
        monkeypatch.setattr(storage, "_prior_successful_watermark", lambda: (None, None))
        monkeypatch.setattr(storage, "run_cycle", cycle)
        run = lambda: storage.run(once=False, interval_seconds=21600)
    with shutdown.graceful_shutdown():
        assert run() == 0
    assert calls == ["cycle_finished"]


@pytest.mark.parametrize("kind", ["coordinator", "remote"])
@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_idle_acquisition_workers_wake_on_stop(kind, monkeypatch, sig):
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as coordinator
    from scripts.runtime import remote_access_plugin_host as remote

    monkeypatch.setenv("ADLOG_ACQUISITION_DISABLED", "1")
    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", "0")
    calls = []

    def heartbeat(*args, **kwargs):
        calls.append("idle")
        signal.raise_signal(sig)

    monkeypatch.setattr(coordinator, "record_worker_heartbeat", heartbeat)
    monkeypatch.setattr(remote, "_write_heartbeat", heartbeat)
    with shutdown.graceful_shutdown():
        result = coordinator.main(["--no-initial-delay"]) if kind == "coordinator" else remote.run_host("radius-session-observation")
        assert result == 0
    assert calls == ["idle"]


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_post_collection_stop_finishes_current_agent_batch_before_next_import(monkeypatch, sig):
    from scripts.runtime import post_collection_worker as worker

    queue = {"pending": 2, "committed": 0}

    def batch(**kwargs):
        signal.raise_signal(sig)
        assert shutdown.requested()
        queue["pending"] -= 1
        queue["committed"] += 1
        return {"scanned": 1}

    monkeypatch.setattr(worker, "legacy_collection_disabled", lambda: True)
    monkeypatch.setattr(worker, "post_collection_worker_lock", lambda: nullcontext(True))
    monkeypatch.setattr(worker, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: None)
    monkeypatch.setattr(worker, "AgentPacketConsumer", lambda: SimpleNamespace(run_once=batch))
    monkeypatch.setattr(worker, "plugin_hook", lambda *a: pytest.fail("must stop before another importer"))
    with shutdown.graceful_shutdown():
        assert worker.run(once=False, poll_seconds=60, limit=1) == 0
    assert queue == {"pending": 1, "committed": 1}
