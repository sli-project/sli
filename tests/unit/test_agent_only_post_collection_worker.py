"""Core inbox imports must survive the server-side acquisition cutover."""
from contextlib import contextmanager
import os
from pathlib import Path
import subprocess
import sys
from textwrap import dedent
from types import SimpleNamespace

import pytest

from scripts.runtime import post_collection_worker as worker
from server.sli.sources import ad_dc_agent_import
from server.sli.ops import shutdown


@pytest.fixture
def agent_only(monkeypatch):
    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", "1")
    calls = []
    heartbeats = []
    monkeypatch.setattr(worker, "_worker_id", lambda: "synthetic-worker")
    monkeypatch.setattr(worker, "log_event", lambda *a, **kw: None)
    monkeypatch.setattr(worker, "record_worker_heartbeat", lambda **kw: heartbeats.append(kw))
    monkeypatch.setattr(worker, "run_persisted_post_collection_worker_once",
                        lambda **kw: pytest.fail("legacy queue reached"))
    monkeypatch.setattr(worker, "resolve_storage_route",
                        lambda **kw: pytest.fail("legacy Findings route reached"))
    monkeypatch.setattr(worker, "log_internal_error",
                        lambda *a, **kw: pytest.fail("private exception logger reached"))

    class Poller:
        def run_once(self, *, limit):
            calls.append(("consumer", limit))
            return {"imported": 1, "scanned": 1, "snapshots": {"published": 1}}

    def ad_import(*, limit):
        calls.append(("ad", limit))
        return 1

    def accounting_import(*, limit):
        calls.append(("accounting", limit))
        return 1

    monkeypatch.setattr(worker, "AgentPacketConsumer", Poller)
    monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once", ad_import)
    monkeypatch.setattr(worker, "plugin_hook", lambda plugin, hook: (
        ad_dc_agent_import.run_agent_import_once if plugin == "sli.ad" else accounting_import))
    return calls, heartbeats


@pytest.mark.parametrize("flag", ["1", "invalid"])
def test_disabled_legacy_still_imports_all_agent_inputs(agent_only, monkeypatch, capsys, flag):
    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", flag)
    calls, heartbeats = agent_only
    assert worker._run_locked(once=True, poll_seconds=30, limit=2) == 0
    assert calls == [("consumer", worker.AGENT_PACKET_BATCH_LIMIT), ("ad", 2), ("accounting", 2)]
    assert heartbeats[-1]["status"] == "idle"
    assert heartbeats[-1]["details"]["agent_packets"]["snapshots"] == {"published": 1}
    output = capsys.readouterr().out
    assert '"agent_packets_imported": 1' in output
    assert '"agent_accounting_packets_imported": 1' in output


def test_sigterm_finishes_current_import_and_does_not_claim_next_batch(agent_only, monkeypatch):
    import signal

    calls, _ = agent_only

    class Poller:
        def run_once(self, **kwargs):
            calls.append("import_started")
            signal.raise_signal(signal.SIGTERM)
            calls.append("import_committed")
            return {"imported": 1, "scanned": worker.AGENT_PACKET_BATCH_LIMIT}

    monkeypatch.setattr(worker, "AgentPacketConsumer", Poller)
    with shutdown.graceful_shutdown():
        assert worker._run_locked(once=False, poll_seconds=60, limit=2) == 0
    assert calls == ["import_started", "import_committed"]


def test_worker_uses_registered_ad_importer_instead_of_compatibility_alias(agent_only, monkeypatch):
    calls, _ = agent_only
    lookup = worker.plugin_hook

    def ad_import(*, limit):
        calls.append(("registered-ad", limit))
        return 1

    monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once",
                        lambda **kw: pytest.fail("compatibility importer reached"))
    monkeypatch.setattr(worker, "plugin_hook", lambda plugin, hook: (
        ad_import if (plugin, hook) == ("sli.ad", "run_agent_import_once") else lookup(plugin, hook)))
    assert worker._run_locked(once=True, poll_seconds=30, limit=2) == 0
    assert calls == [("consumer", worker.AGENT_PACKET_BATCH_LIMIT), ("registered-ad", 2), ("accounting", 2)]


def test_deferred_legacy_executor_preserves_arguments_and_result(monkeypatch):
    from server.jobs import collector

    calls = []
    result = {"failed": 0, "processed": 1}
    monkeypatch.setattr(collector, "run_persisted_post_collection_worker_once",
                        lambda **kw: calls.append(kw) or result)
    args = {"worker_id": "synthetic-worker", "limit": 2, "authorization": None,
            "progress_callback": lambda _: None}
    assert worker.run_persisted_post_collection_worker_once(**args) is result
    assert calls == [args]


@pytest.mark.parametrize("failure", ["consumer", "projection", "ad", "accounting"])
def test_agent_only_failures_return_nonzero_without_private_diagnostics(
    agent_only, monkeypatch, capsys, failure,
):
    _, heartbeats = agent_only

    def fail(**kw):
        raise RuntimeError("synthetic-private-diagnostic")

    if failure in {"consumer", "projection"}:
        result = {"pending_reasons": {"agent_projection_failed": 1}}
        monkeypatch.setattr(worker, "AgentPacketConsumer",
                            lambda: SimpleNamespace(run_once=fail if failure == "consumer" else lambda **kw: result))
    elif failure == "ad":
        monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once", fail)
    else:
        monkeypatch.setattr(worker, "plugin_hook", lambda *a: fail)
    assert worker._run_locked(once=True, poll_seconds=30, limit=1) == 1
    assert heartbeats[-1]["status"] == "failed"
    assert "synthetic-private-diagnostic" not in capsys.readouterr().out
    assert "synthetic-private-diagnostic" not in repr(heartbeats)


def test_agent_only_worker_continues_after_import_failure(agent_only, monkeypatch):
    calls, heartbeats = agent_only
    attempts = 0

    def ad_import(*, limit):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("synthetic-private-diagnostic")
        calls.append(("ad", limit))
        return 1

    class StopPolling(Exception):
        pass

    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise StopPolling()

    monkeypatch.setattr(ad_dc_agent_import, "run_agent_import_once", ad_import)
    monkeypatch.setattr(worker.time, "sleep", sleep)
    with pytest.raises(StopPolling):
        worker._run_locked(once=False, poll_seconds=30, limit=1)
    assert attempts == 2
    assert sleeps == [30, 30]
    assert [row["status"] for row in heartbeats if row["phase"] == "sleep"] == ["failed", "idle"]
    assert ("accounting", 1) in calls


def test_agent_only_drains_full_batches_before_sleeping(agent_only, monkeypatch):
    calls, _ = agent_only
    scans = iter((worker.AGENT_PACKET_BATCH_LIMIT, 0))

    class Poller:
        def run_once(self, *, limit):
            scanned = next(scans)
            calls.append(("consumer", scanned))
            return {"scanned": scanned, "pending_reasons": {"agent_plugin_disabled": scanned}}

    class StopPolling(Exception):
        pass

    def sleep(seconds):
        assert seconds == 30
        raise StopPolling()

    monkeypatch.setattr(worker, "AgentPacketConsumer", Poller)
    monkeypatch.setattr(worker.time, "sleep", sleep)
    with pytest.raises(StopPolling):
        worker._run_locked(once=False, poll_seconds=30, limit=1)
    assert calls == [("consumer", worker.AGENT_PACKET_BATCH_LIMIT), ("ad", 1), ("accounting", 1),
                     ("consumer", 0), ("ad", 1), ("accounting", 1)]


@pytest.mark.parametrize("acquired", [False, True])
def test_agent_only_cli_preserves_single_process_lock(agent_only, monkeypatch, acquired):
    calls, _ = agent_only

    @contextmanager
    def lock():
        yield acquired

    monkeypatch.setattr(worker, "post_collection_worker_lock", lock)
    assert worker.main(["--once", "--limit", "2"]) == (0 if acquired else 9)
    assert bool(calls) is acquired


def test_supervisor_can_start_core_import_after_legacy_disable(monkeypatch, tmp_path):
    from scripts.maintenance import worker_supervisor

    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", "1")
    monkeypatch.setattr(worker_supervisor, "ROOT", tmp_path)
    monkeypatch.setattr(worker_supervisor, "OWNED_CHILDREN", {})
    children = []

    def spawn(args, **kw):
        children.append(args)
        return SimpleNamespace(pid=123)

    monkeypatch.setattr(worker_supervisor.subprocess, "Popen", spawn)
    result = worker_supervisor._start("post_collection")
    assert result["started"] is True
    assert len(children) == 1
    assert "post_collection_worker.py" in children[0][1]


@pytest.mark.parametrize("flag", ["1", "invalid"])
def test_core_worker_runs_without_ad_package_or_legacy_collector(monkeypatch, flag):
    monkeypatch.setenv("SLI_LEGACY_COLLECTION_DISABLED", flag)
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    probe = dedent("""
        from contextlib import nullcontext
        from datetime import datetime, timezone
        import importlib.abc
        import sys
        from types import SimpleNamespace

        class MissingAD(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if (fullname == 'server.sli.plugins.ad' or fullname.startswith('server.sli.plugins.ad.')
                        or fullname.startswith('server.jobs.collector')
                        or fullname == 'server.sli.sources.ad_dc_agent_import'):
                    raise ModuleNotFoundError('synthetic package unavailable')

        sys.meta_path.insert(0, MissingAD())
        from server.sli.plugins import registry
        discover = registry.discover_plugins
        registry.discover_plugins = lambda: tuple(row for row in discover() if row[0] != 'sli.ad')
        from scripts.runtime import post_collection_worker as worker
        from server.sli.agents.consumer import dispatch_packet
        from server.sli.agents.import_authorization import PacketPending

        writes = []
        cursor = SimpleNamespace(execute=lambda *args: writes.append(args))
        connection = SimpleNamespace(cursor=lambda: nullcontext(cursor))
        assert worker.record_worker_heartbeat(
            worker_name='post_collection', worker_id='synthetic-worker', status='idle', phase='sleep',
            expected_interval_seconds=30, started_at=datetime.now(timezone.utc),
            connection_factory=lambda: nullcontext(connection),
        ) == {'status': 'ok'}
        assert len(writes) == 1 and 'insert into runtime_worker_heartbeats' in writes[0][0]

        calls = []
        heartbeats = []
        def accounting_import(*, limit):
            calls.append(('accounting', limit))
            return 1
        registry.registered_plugins()['sli.remote-access'].hooks['run_accounting_import_once'] = accounting_import

        class Poller:
            def run_once(self, *, limit):
                calls.append(('consumer', limit))
                try:
                    dispatch_packet(None, [], packet={}, envelope={'module_id': 'sli.windows.ad-dc'})
                except PacketPending as exc:
                    assert str(exc) == 'agent_plugin_not_installed'
                else:
                    raise AssertionError('missing AD must leave its packet pending')
                return {'scanned': 2, 'imported': 1, 'pending_reasons': {'agent_plugin_not_installed': 1}}

        worker.AgentPacketConsumer = Poller
        worker._worker_id = lambda: 'synthetic-worker'
        worker.log_event = lambda *a, **kw: None
        worker.record_worker_heartbeat = lambda **kw: heartbeats.append(kw)
        for _ in range(2):
            assert worker._run_locked(once=True, poll_seconds=30, limit=2) == 0
        assert calls == [('consumer', worker.AGENT_PACKET_BATCH_LIMIT), ('accounting', 2)] * 2
        assert heartbeats[-1]['status'] == 'idle'
        assert heartbeats[-1]['details']['agent_packets']['pending_reasons'] == {'agent_plugin_not_installed': 1}
        assert not any(name.startswith('server.sli.plugins.ad.') or name.startswith('server.jobs.collector')
                       for name in sys.modules)
    """)
    result = subprocess.run(
        [os.environ.get("SLI_TEST_PYTHON", sys.executable), "-c", probe],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
