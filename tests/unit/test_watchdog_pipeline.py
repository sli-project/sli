"""Pipeline maintenance tests use fake process inventories and temporary locks only."""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/maintenance/watchdog/watchdog_pipeline.py"
SPEC = importlib.util.spec_from_file_location("watchdog_pipeline", SOURCE)
pipeline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pipeline)
NOW = 100_000


def row(pid, kind, age=0, parent=0, ticks=None, directory=""):
    return {"pid": pid, "kind": kind, "started": NOW - age, "parent": parent,
            "ticks": ticks or pid * 100, "directory": directory}


@pytest.mark.parametrize("kind", ["curl", "git", "gh"])
def test_hung_network_clients_are_scoped_and_strictly_expire(kind):
    rows = [row(1, "worker", 2000), row(2, kind, 601, 1),
            row(3, kind, 600, 1), row(4, kind, 4000)]
    plan, _ = pipeline.process_plan(rows, NOW, {})
    assert [item["pid"] for item in plan] == [2]


@pytest.mark.parametrize("kind", sorted(pipeline.QUEUE_KINDS))
def test_orphan_wrapper_requires_twenty_minutes_without_codex(kind):
    rows = [row(1, kind, 4000), row(2, "other", 3000, 1)]
    plan, state = pipeline.process_plan(rows, NOW, {})
    assert not plan
    assert state == {"1:100": NOW}
    assert not pipeline.process_plan(rows, NOW + 1200, state)[0]
    assert {item["pid"] for item in pipeline.process_plan(rows, NOW + 1201, state)[0]} == {1, 2}


def test_nested_live_codex_resets_orphan_clock_and_recycled_pid_does_not_inherit_it():
    rows = [row(1, "run_qmv3", 4000), row(2, "other", 3000, 1), row(3, "codex", 1, 2)]
    assert pipeline.process_plan(rows, NOW, {"1:100": NOW - 4000}) == ([], {})
    rows.pop()
    rows[0]["ticks"] = 101
    assert pipeline.process_plan(rows, NOW, {"1:100": NOW - 4000})[0] == []


def test_runtime_update_tree_is_protected_from_both_modes():
    rows = [row(1, "watchdog", 4000), row(2, "update", 3000, 1),
            row(3, "git", 2000, 2), row(4, "run_qmv3", 2000, 2)]
    assert pipeline.process_plan(rows, NOW, {"4:400": NOW - 1500})[0] == []
    assert [item["pid"] for item in pipeline.process_plan(rows, NOW, {}, guard=True)[0]] == [1]


def test_guard_age_boundary_and_younger_descendants():
    rows = [row(1, "watchdog", 1500), row(2, "gh", 901, 1), row(3, "git", 900, 1),
            row(4, "codex", 10, 1), row(5, "worker", 9000)]
    assert {item["pid"] for item in pipeline.process_plan(rows, NOW, {}, guard=True)[0]} == {1, 2}


def test_previously_observed_client_is_cleaned_after_parent_exits_but_recycled_pid_is_safe():
    rows = [row(2, "gh", 601), row(3, "git", 900, ticks=301)]
    plan, _ = pipeline.process_plan(rows, NOW, {}, known_scope={"2:200", "3:300"})
    assert [item["pid"] for item in plan] == [2]


def test_windows_stop_command_is_bounded_and_requires_birth_identity(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(pipeline.subprocess, "run", lambda args, **kwargs: calls.append((args, kwargs)))
    runtime = pipeline.Runtime(tmp_path, tmp_path, "bash.exe")
    runtime.stop(row(5, "gh"))
    args, options = calls[0]
    assert args[-6:] == ["-Mode", "stop", "-WinPid", "5", "-StartTicks", "500"]
    assert options["check"] and options["timeout"] == 25 and options["capture_output"]


@pytest.mark.parametrize("name", list(pipeline.LOCK_TTLS))
@pytest.mark.parametrize("live", [False, True])
def test_expired_locks_require_dead_owners(tmp_path, name, live):
    lock = tmp_path / name
    if name != "watchdog.lock":
        lock.mkdir()
        owner = lock / "owner"
    else:
        owner = lock
    owner.write_text("123\t1\tfixture\n")
    ttl = pipeline.LOCK_TTLS[name]
    os.utime(lock, (NOW - ttl - 1, NOW - ttl - 1))
    assert pipeline.reclaim_lock(lock, ttl, NOW, lambda pid: live) is not live
    assert lock.exists() is live


@pytest.mark.parametrize("name", list(pipeline.LOCK_TTLS))
def test_fresh_and_ownerless_live_locks_are_preserved(tmp_path, name):
    lock = tmp_path / name
    lock.mkdir()
    ttl = pipeline.LOCK_TTLS[name]
    os.utime(lock, (NOW - ttl, NOW - ttl))
    assert not pipeline.reclaim_lock(lock, ttl, NOW, lambda pid: False)
    os.utime(lock, (1, 1))
    assert not pipeline.reclaim_lock(lock, ttl, NOW, lambda pid: False, fallback_alive=True)
    assert pipeline.reclaim_lock(lock, ttl, NOW, lambda pid: False, dry=True)
    assert lock.is_dir()
    assert pipeline.reclaim_lock(lock, ttl, NOW, lambda pid: False)


def test_lock_recheck_and_unexpected_directory_contents_are_preserved(tmp_path):
    lock = tmp_path / "update.lock"
    lock.mkdir()
    (lock / "owner").write_text("123\t1\ttoken")
    os.utime(lock, (1, 1))
    replies = iter([False, True])
    assert not pipeline.reclaim_lock(lock, 1, NOW, lambda pid: next(replies))
    (lock / "unexpected").write_text("keep")
    os.utime(lock, (1, 1))
    assert not pipeline.reclaim_lock(lock, 1, NOW, lambda pid: False)
    assert (lock / "owner").exists()


class FakeRuntime:
    def __init__(self, home, rows=()):
        self.home = home
        self.rows = list(rows)
        self.stopped = []
        self.restarts = 0
        self.logs = []
        self.live_owner = False

    def snapshot(self):
        return self.rows.copy()

    def stop(self, item):
        self.stopped.append(item["pid"])
        self.rows = [row for row in self.rows if row["pid"] != item["pid"]]

    def restart(self):
        self.restarts += 1

    def owner_alive(self, pid):
        return self.live_owner

    def log(self, text):
        self.logs.append(text)


def status(home, age):
    path = home / "STATUS.md"
    path.write_text("fixture")
    os.utime(path, (NOW - age, NOW - age))


def test_fresh_guard_does_nothing_at_boundary(tmp_path):
    status(tmp_path, 1200)
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000)])
    assert pipeline.guard_pass(runtime, NOW) == "fresh"
    assert not runtime.stopped and not runtime.restarts


def test_stale_guard_removes_lock_restarts_and_records_notice(tmp_path):
    status(tmp_path, 1201)
    (tmp_path / "watchdog.lock").write_text("123\t1\tfixture")
    (tmp_path / "watchdog.lock.guard").mkdir()
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000), row(2, "gh", 3000, 1)])
    assert pipeline.guard_pass(runtime, NOW) == "restarted"
    assert set(runtime.stopped) == {1, 2} and runtime.restarts == 1
    assert not (tmp_path / "watchdog.lock").exists()
    assert "Надзор перезапустил сторожа:" in (tmp_path / "guard-notice.txt").read_text()
    assert any("restart" in line for line in runtime.logs)


def test_guard_preserves_live_owner_and_younger_children(tmp_path):
    status(tmp_path, 1500)
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000), row(2, "gh", 5, 1)])
    assert pipeline.guard_pass(runtime, NOW) == "deferred"
    assert not runtime.restarts and runtime.rows[0]["pid"] == 2
    (tmp_path / "watchdog.lock").write_text("123\t1\tfixture")
    runtime.rows = []
    runtime.live_owner = True
    assert pipeline.guard_pass(runtime, NOW) == "deferred"
    assert (tmp_path / "watchdog.lock").exists()


def test_guard_remembers_young_children_until_their_age_limit_after_parent_is_gone(tmp_path):
    status(tmp_path, 1500)
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000), row(2, "gh", 5, 1)])
    assert pipeline.guard_pass(runtime, NOW) == "deferred"
    assert pipeline.guard_pass(runtime, NOW + 896) == "restarted"
    assert runtime.stopped == [1, 2] and runtime.restarts == 1


def test_guard_dry_run_has_no_mutations_or_restarts(tmp_path):
    status(tmp_path, 1500)
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000)])
    before = list(tmp_path.iterdir())
    assert "DRY-RUN" in pipeline.guard_pass(runtime, NOW, dry=True)
    assert not runtime.stopped and not runtime.restarts and not runtime.logs
    assert list(tmp_path.iterdir()) == before


def test_guard_two_failed_recoveries_raise_alert_and_fresh_pass_resets(tmp_path):
    status(tmp_path, 4000)
    runtime = FakeRuntime(tmp_path)
    pipeline.guard_pass(runtime, NOW)
    pipeline.guard_pass(runtime, NOW + 1500)
    assert not (tmp_path / "ALERT.txt").exists()
    pipeline.guard_pass(runtime, NOW + 3000)
    assert (tmp_path / "ALERT.txt").exists()
    status(tmp_path, 0)
    pipeline.guard_pass(runtime, NOW)
    assert json.loads((tmp_path / "guard-state.json").read_text())["failures"] == 0


def test_janitor_dry_run_and_live_pass(tmp_path):
    runtime = FakeRuntime(tmp_path, [row(1, "worker", 4000), row(2, "curl", 601, 1)])
    heavy, update = tmp_path / "heavy", tmp_path / "update"
    heavy.mkdir(); update.mkdir()
    (heavy / "heavy.lock").mkdir()
    os.utime(heavy / "heavy.lock", (1, 1))
    assert len(pipeline.janitor_pass(runtime, NOW, heavy, update, dry=True)) == 2
    assert not runtime.stopped and not (tmp_path / "orphan-since.json").exists()
    assert len(pipeline.janitor_pass(runtime, NOW, heavy, update)) == 2
    assert runtime.stopped == [2] and not (heavy / "heavy.lock").exists()


def test_update_clients_are_never_recorded_for_later_orphan_termination(tmp_path):
    runtime = FakeRuntime(tmp_path, [row(1, "watchdog", 4000), row(2, "update", 3000, 1),
                                     row(3, "git", 2000, 2), row(4, "gh", 20, 1)])
    pipeline.janitor_pass(runtime, NOW, tmp_path / "heavy", tmp_path / "update")
    assert json.loads((tmp_path / "scoped-processes.json").read_text()) == ["4:400"]


WATCHDOG = Path(os.environ.get("WATCHDOG_SOURCE", str(SOURCE.parent)))


@pytest.mark.parametrize("failed", ["", "github.com", "api.openai.com"])
def test_network_requires_both_endpoints_and_uses_external_kill_timeout(tmp_path, failed):
    curl = tmp_path / "curl"
    curl.write_text('#!/bin/bash\n[[ "$*" != *"$FAILED_HOST"* || -z "$FAILED_HOST" ]] || exit 1\nprintf 401\n')
    curl.chmod(0o755)
    timeout = tmp_path / "timeout"
    timeout.write_text('#!/bin/bash\n[[ "$1 $2 $3" == "-k 2 15" ]] || exit 9\nshift 3\nexec "$@"\n')
    timeout.chmod(0o755)
    script = 'source "$1/network.sh"; note() { echo "$*"; }; watchdog_network; rc=$?; echo "$NETWORK"; exit "$rc"'
    result = subprocess.run(["bash", "-c", script, "test", str(WATCHDOG)], capture_output=True,
                            text=True, env={**os.environ, "FAILED_HOST": failed,
                                            "PATH": str(tmp_path) + ":" + os.environ["PATH"]})
    assert result.returncode == int(bool(failed))
    assert ("Сеть: нет ответа (перезапустите VPN)" in result.stdout) is bool(failed)
    assert ("offline" if failed else "online") in result.stdout


def test_dashboard_snapshot_publishes_network_failure(tmp_path):
    spec = importlib.util.spec_from_file_location("dashboard_data", WATCHDOG / "dashboard_data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "STATUS.md").write_text("Сеть: нет ответа (перезапустите VPN)\n")
    snapshot = module.generate(tmp_path, tmp_path, tmp_path, tmp_path / "reports", NOW, True, "network_error")
    assert snapshot["network"] == "offline" and snapshot["result"] == "network_error"
    assert not snapshot["prs_available"]
