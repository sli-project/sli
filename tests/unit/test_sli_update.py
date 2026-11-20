"""Signed update and interruption contracts; no Docker daemon or real database."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import stat
import subprocess
import tarfile
import zipfile
from contextlib import nullcontext
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from deploy.linux import sli_update as update
from deploy.linux import update_checkpoint as checkpoint
from server.sli import release_package as package
from tools.build_update_package import build
from tools import build_update_package as builder


PRIVATE_ERROR_MARKER = "private-error-marker"


def draining_host(release, monkeypatch, *, active=None, backlog=None, stop_codes=None):
    """Use the real Docker drain with fake services, clock and database probes."""
    _, fake, *_ = release
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None, timeout=3, drain_timeout=3)
    calls = []
    clock = [0.0]
    rows = [{"ID": name + "-id", "Service": name, "State": "running", "ExitCode": 0}
            for name in ("api", "semantic", "backup")]

    def compose(args, override=None, **kwargs):
        calls.append(args)
        if args[0] == "exec" and backlog is not None:
            sql = args[-1]
            if "FROM pg_attribute" in sql:
                return " UNION ALL ".join(
                    f"SELECT count(*) AS n FROM public.{name} WHERE lease_until > statement_timestamp()"
                    for name in backlog)
            # Model pending rows with NULL leases. A query counting backlog
            # instead of live ownership would make this update time out.
            counts = 0 if sql.count("WHERE lease_until > statement_timestamp()") == len(backlog) else sum(backlog.values())
            return json.dumps({"leases": counts, "transactions": 0})
        assert args[0] == "stop"
        for row in rows:
            if row["Service"] in args[3:]:
                row["State"] = "exited"

    def command(args, **kwargs):
        assert args[:6] == ["docker", "container", "stop", "--signal", "SIGINT", "--time"]
        assert args[6] == "-1"
        assert 0 < kwargs["timeout"] <= 25
        calls.append(args)
        for row in rows:
            if row["ID"] in args[7:]:
                row["State"] = "exited"
                row["ExitCode"] = (stop_codes or {}).get(row["Service"], 0)

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "backup_activity", lambda: {"busy": False})
    if backlog is None:
        monkeypatch.setattr(host, "in_flight", active or (lambda: {"leases": 0, "transactions": 0}))
    monkeypatch.setattr(update.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(update.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))

    def drain(journal):
        host.drain(journal)
        fake.stopped = True

    monkeypatch.setattr(fake, "drain", drain)
    return host, calls, clock


def test_large_durable_backlog_does_not_block_update_and_is_preserved(release, monkeypatch):
    updater, fake, archive, *_ = release
    # Pending work is durable DB state, independent of the currently running services.
    backlog = {"outbox": 200000, "inbox": 30000, "semantic": 176000}
    before = dict(backlog)
    host, calls, _ = draining_host(release, monkeypatch, backlog=backlog)
    assert updater.apply(archive) == "committed"
    assert fake.active == "candidate" and not fake.stopped
    assert calls[0] == ["docker", "container", "stop", "--signal", "SIGINT", "--time", "-1", "api-id"]
    assert calls[1] == ["docker", "container", "stop", "--signal", "SIGINT", "--time", "-1", "semantic-id", "backup-id"]
    assert backlog == before
    assert package.read_json(updater.journal_path.read_bytes())["drain_in_flight"] == {"leases": 0, "transactions": 0}
    assert host.timeout == 3


@pytest.mark.parametrize("active,reason", [
    ({"leases": 1, "transactions": 0}, "update_drain_lease_timeout"),
    ({"leases": 0, "transactions": 1}, "update_drain_transaction_timeout"),
])
def test_unfinished_work_times_out_and_rolls_back_without_redraining(release, monkeypatch, active, reason):
    updater, fake, archive, *_ = release
    _, calls, clock = draining_host(release, monkeypatch, active=lambda: dict(active))
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == reason and journal["drain_in_flight"] == active
    assert not journal["migration_started"] and journal["backup_id"] is None
    assert "migrate" not in fake.calls and "restore" not in fake.calls
    assert fake.active == "previous" and not fake.stopped
    assert len(calls) == 2  # No second drain blocks restarting the unchanged version.
    assert clock[0] == 3


def test_drain_waits_for_current_lease_and_import_transaction(release, monkeypatch):
    updater, _, archive, *_ = release
    states = iter([{"leases": 1, "transactions": 1}, {"leases": 0, "transactions": 1},
                   {"leases": 0, "transactions": 0}])
    draining_host(release, monkeypatch, active=lambda: next(states, {"leases": 0, "transactions": 0}))
    assert updater.apply(archive) == "committed"


@pytest.mark.parametrize("code", [1, 130, 137])
def test_forced_service_stop_is_not_a_successful_drain(release, monkeypatch, code):
    updater, fake, archive, *_ = release
    draining_host(release, monkeypatch, stop_codes={"semantic": code})
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == "update_drain_service_timeout"
    assert any(row["Service"] == "semantic" and row["ExitCode"] == code
               for attempt in journal["drain_services"] for row in attempt["containers"])
    assert fake.active == "previous" and not {"checkpoint", "migrate", "restore"} & set(fake.calls)


def legacy_draining_host(release, monkeypatch, *, codes=None, elapsed=0, changed=None, before=None):
    updater, fake, *_ = release
    host, calls, clock = draining_host(release, monkeypatch, stop_codes=codes or {"semantic": 130, "backup": 130})
    revision = "b" * 40
    monkeypatch.setattr(update, "LEGACY_INTERRUPT_REVISIONS", {revision})
    previous = package.read_json(updater.installed_path.read_bytes())
    previous["source_commit"] = revision
    update.atomic_json(updater.installed_path, previous)
    observed = {"id": "semantic-id", "image": previous["image_digest"], "revision": revision,
                "project": "sli", "service": "semantic", "status": "exited", "exit_code": 130,
                "started_at": "2026-10-17T00:00:00Z", "finished_at": "2026-10-17T00:01:00Z", "restart_count": 0,
                "oom_killed": False, "error_empty": True}
    observed.update(changed or {})
    stop = host.command
    if before:
        before(host.containers())

    def command(args, **kwargs):
        if args[:2] == ["docker", "exec"]:
            return "SigCgt:\t0000000000004002\n"  # Exercise SIGINT separately from the TERM bridge.
        if args[:2] == ["docker", "inspect"]:
            assert kwargs["timeout"] == 10
            assert ".Config.Env" not in args[3]
            service = args[-1].removesuffix("-id")
            return json.dumps({**observed, "id": args[-1], "service": service, **(changed or {})})
        stop(args, **kwargs)
        if "semantic-id" in args:
            clock[0] += elapsed

    monkeypatch.setattr(host, "command", command)
    return host, calls, clock


def test_verified_legacy_interrupt_commits_and_preserves_real_exit_codes(release, monkeypatch):
    updater, fake, archive, *_ = release
    legacy_draining_host(release, monkeypatch, elapsed=0.5)
    assert updater.apply(archive) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    workers = next(attempt["containers"] for attempt in journal["drain_services"] if "semantic" in attempt["services"])
    assert [row["ExitCode"] for row in workers] == [130, 130]
    assert all(row["legacy_interrupt"]["oom_killed"] is False for row in workers)
    assert all(row["legacy_interrupt"]["elapsed_ms"] == 500 for row in workers)
    assert fake.calls.index("checkpoint") < fake.calls.index("migrate")
    assert journal["drain_in_flight"] == {"leases": 0, "transactions": 0}


@pytest.mark.parametrize("changed", [
    {"started_at": "2026-10-17T01:00:00Z"}, {"finished_at": "2026-10-17T01:01:00Z"}, {"restart_count": 1},
])
def test_second_drain_rejects_container_restarted_after_accepted_interrupt(release, monkeypatch, changed):
    updater, fake, archive, *_ = release
    changes = {}
    legacy_draining_host(release, monkeypatch, changed=changes)
    checkpoint = fake.checkpoint

    def checkpoint_then_restart(journal):
        result = checkpoint(journal)
        changes.update(changed)
        return result

    monkeypatch.setattr(fake, "checkpoint", checkpoint_then_restart)
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == "update_drain_service_timeout" and not journal["migration_started"]
    assert "checkpoint" in fake.calls and not {"migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("changed", [
    {"oom_killed": True}, {"oom_killed": None}, {"error_empty": False},
    {"image": "sha256:" + "c" * 64}, {"revision": "c" * 40},
    {"project": "other"}, {"service": "api"}, {"id": "replacement-id"},
    {"status": "running"}, {"exit_code": 137},
])
def test_legacy_interrupt_requires_exact_stopped_image_without_oom(release, monkeypatch, changed):
    updater, fake, archive, *_ = release
    legacy_draining_host(release, monkeypatch, changed=changed)
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == "update_drain_service_timeout" and not journal["migration_started"]
    assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("elapsed", [3, 3.1])
def test_legacy_interrupt_at_or_after_stop_limit_is_rejected(release, monkeypatch, elapsed):
    updater, fake, archive, *_ = release
    legacy_draining_host(release, monkeypatch, elapsed=elapsed)
    assert updater.apply(archive) == "rolled_back"
    assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("state", ["exited", "restarting", "paused"])
def test_legacy_interrupt_requires_updater_to_signal_running_container(release, monkeypatch, state):
    updater, fake, archive, *_ = release

    def before(rows):
        rows[1].update(State=state, ExitCode=130)

    legacy_draining_host(release, monkeypatch, before=before)
    assert updater.apply(archive) == "rolled_back"
    assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("service,code", [("api", 130), ("semantic", 1), ("semantic", 137)])
def test_legacy_revision_does_not_relax_other_exit_failures(release, monkeypatch, service, code):
    updater, fake, archive, *_ = release
    legacy_draining_host(release, monkeypatch, codes={service: code})
    assert updater.apply(archive) == "rolled_back"
    assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("active,reason", [
    ({"leases": 1, "transactions": 0}, "update_drain_lease_timeout"),
    ({"leases": 0, "transactions": 1}, "update_drain_transaction_timeout"),
])
def test_accepted_legacy_interrupt_still_requires_no_active_work(release, monkeypatch, active, reason):
    updater, fake, archive, *_ = release
    host, _, _ = legacy_draining_host(release, monkeypatch)
    monkeypatch.setattr(host, "in_flight", lambda: active)
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == reason and journal["drain_in_flight"] == active
    assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)


@pytest.mark.parametrize("code", [1, 137])
def test_api_failed_stop_records_service_and_does_not_signal_workers(release, monkeypatch, code):
    updater, fake, archive, *_ = release
    host, calls, _ = draining_host(release, monkeypatch)
    monkeypatch.setattr(host, "containers", lambda: [{"Service": "api", "State": "exited", "ExitCode": code,
                                                     "private": PRIVATE_ERROR_MARKER}])
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["drain_services"] == [{"services": ["api"], "timeout_seconds": 3,
                                        "stop_signal": "SIGINT", "elapsed_ms": 0,
                                        "failed_services": ["api"], "failure_reason": "exit_code",
                                        "failure_resolved": False,
                                        "containers": [{"Service": "api", "State": "exited", "ExitCode": code}]}]
    assert not calls and fake.active == "previous"
    assert PRIVATE_ERROR_MARKER not in json.dumps(journal)


def test_drain_budget_is_independent_from_health_timeout(release, monkeypatch):
    updater, _, archive, *_ = release
    host, calls, _ = draining_host(release, monkeypatch)
    host.timeout = 1
    host.drain_timeout = 20
    assert updater.apply(archive) == "committed"
    assert calls[0][6] == "-1"  # Docker itself may never escalate a soft stop.


@pytest.mark.parametrize("finishes", [False, True])
def test_nightly_backup_finishes_before_any_service_stop(release, monkeypatch, finishes):
    updater, _, archive, *_ = release
    host, calls, clock = draining_host(release, monkeypatch)
    host.drain_timeout = 10
    observed = []

    def activity():
        observed.append(clock[0])
        assert not calls, "no ingress or writer stop while the backup is busy"
        return {"busy": not finishes or clock[0] < 5}

    # A second drain observes the already stopped backup and needs no probe.
    monkeypatch.setattr(host, "backup_activity", activity)
    assert updater.apply(archive) == ("committed" if finishes else "rejected")
    journal = updater.operation()
    assert observed[0] == 0 and observed[-1] == (5 if finishes else 10)
    if not finishes:
        assert journal["reason"] == "update_backup_busy"
        assert not journal.get("drain_services") and not journal["migration_started"]
        assert not calls


def test_backup_activity_probe_runs_in_older_image_without_importing_new_module(monkeypatch):
    host = update.DockerHost([], "https://127.0.0.1/api/health/ready", None)
    calls = []
    monkeypatch.setattr(host, "compose", lambda args, **kw:
                        (calls.append((args, kw)), '{"busy": true}')[1])
    assert host.backup_activity() == {"busy": True}
    assert calls[0][0][:5] == ["exec", "-T", "backup", "python", "-c"]
    assert "def activity" in calls[0][0][5] and calls[0][1] == {"timeout": 10}


def test_precheck_crossing_next_backup_slot_does_not_stop_writers(release, monkeypatch):
    updater, _, archive, *_ = release
    host, calls, _ = draining_host(release, monkeypatch)
    upcoming = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
    monkeypatch.setattr(host, "backup_activity", lambda: {"busy": False, "next_backup_at_utc": upcoming})
    assert updater.apply(archive) == "rejected"
    journal = updater.operation()
    assert journal["reason"] == "update_backup_busy"
    assert not calls and not journal.get("drain_services") and not journal["migration_started"]


def test_slow_legacy_workers_use_total_budget_after_cli_timeout(release, monkeypatch):
    updater, fake, archive, *_ = release
    host, calls, clock = legacy_draining_host(release, monkeypatch)
    host.drain_timeout = 60
    rows = host.containers()
    command = host.command

    def slow_stop(args, **kwargs):
        if args[:3] == ["docker", "container", "stop"] and "semantic-id" in args:
            calls.append(args)
            assert kwargs["timeout"] == 25
            clock[0] = 25
            raise subprocess.TimeoutExpired(args, 25)
        return command(args, **kwargs)

    def sleep(seconds):
        clock[0] += seconds
        if clock[0] >= 30:
            for row in rows:
                if row["Service"] in {"semantic", "backup"}:
                    row.update(State="exited", ExitCode=130)

    monkeypatch.setattr(host, "command", slow_stop)
    monkeypatch.setattr(update.time, "sleep", sleep)
    assert updater.apply(archive) == "committed"
    journal = updater.operation()
    attempt = journal["drain_services"][0]
    assert attempt["command_timed_out"] and attempt["stop_pending"] is False
    assert attempt["elapsed_ms"] == 30000
    assert all(row["legacy_interrupt"]["accepted"] for row in attempt["containers"])
    assert "migrate" in fake.calls and not any("SIGKILL" in call for call in calls)


def test_pending_daemon_stop_blocks_rollback_restart_until_resume(release, monkeypatch):
    updater, fake, archive, *_ = release
    host, _, clock = draining_host(release, monkeypatch)
    rows = host.containers()

    def pending_stop(args, **kwargs):
        clock[0] += kwargs["timeout"]
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(host, "command", pending_stop)
    monkeypatch.setattr(fake, "settle_stops", host.settle_stops, raising=False)
    assert updater.apply(archive) == "recovery_required"
    journal = updater.operation()
    assert journal["drain_services"][0]["stop_pending"] is True
    assert not {"previous", "fence", "migrate", "restore"} & set(fake.calls)
    assert not journal["migration_started"] and journal["backup_id"] is None
    # The daemon finishes after the failed attempt. Resume restarts only the
    # unchanged release and never restores a checkpoint over newly arrived data.
    rows[0].update(State="exited", ExitCode=0)
    assert updater.resume() == "rolled_back"
    assert updater.operation()["drain_services"][0]["stop_pending"] is False
    assert "previous" in fake.calls and not {"restore", "migrate", "fence"} & set(fake.calls)


@pytest.mark.parametrize("rejected_apply", [False, True])
def test_explicit_rollback_repairs_late_stop_of_previous_release_without_restore(release, monkeypatch, rejected_apply):
    updater, fake, archive, *_ = release

    def timeout(_):
        raise update.UpdateError("update_drain_service_timeout")

    monkeypatch.setattr(fake, "drain", timeout)
    assert updater.apply(archive) == "rolled_back"
    operation = updater.operation()["operation"]
    if rejected_apply:
        monkeypatch.setattr(fake, "inspect_installation", lambda _: (_ for _ in ()).throw(
            update.UpdateError("update_incomplete_installation")))
        assert updater.apply(archive) == "rejected"
    calls = list(fake.calls)
    assert updater.resume(operation_id=operation) == "rolled_back"
    assert fake.calls == calls  # Ordinary resume of a terminal operation stays inert.
    assert updater.resume(rollback=True, operation_id=operation) == "rolled_back"
    assert fake.calls[len(calls):].count("previous") == 1
    assert not {"restore", "migrate", "fence", "checkpoint"} & set(fake.calls[len(calls):])
    assert updater.operation()["reason"] == "update_operator_rollback"


def test_late_stop_repair_cannot_supersede_another_staged_operation(release, monkeypatch):
    updater, fake, archive, *_ = release
    drain = fake.drain
    monkeypatch.setattr(fake, "drain", lambda _: (_ for _ in ()).throw(
        update.UpdateError("update_drain_service_timeout")))
    assert updater.apply(archive) == "rolled_back"
    operation = updater.operation()["operation"]
    monkeypatch.setattr(fake, "drain", drain)
    monkeypatch.setattr(updater, "run", lambda _: "running")
    assert updater.apply(archive) == "running"
    calls = list(fake.calls)
    with pytest.raises(update.UpdateError, match="update_operation_not_active"):
        updater.resume(rollback=True, operation_id=operation)
    assert fake.calls == calls


@pytest.mark.parametrize("rpc_timeout", [False, True])
def test_stop_rpc_result_is_followed_by_stopped_container_readback(release, monkeypatch, rpc_timeout):
    _, fake, *_ = release
    host, _, clock = draining_host(release, monkeypatch)
    rows = host.containers()
    rows[:] = [rows[0]]
    monkeypatch.setattr(update, "checked_override", lambda *_: None)

    def stop(args, **kwargs):
        if rpc_timeout:
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    def sleep(seconds):
        clock[0] += seconds
        rows[0].update(State="exited", ExitCode=0)

    monkeypatch.setattr(host, "command", stop)
    monkeypatch.setattr(update.time, "sleep", sleep)
    journal = {"services": ["api"]}
    host.drain(journal)
    assert clock[0] == 1
    assert journal["drain_services"][0]["stop_pending"] is False
    assert journal["drain_in_flight"] == {"leases": 0, "transactions": 0}
    assert fake.active == "previous"


@pytest.mark.parametrize("change", ["missing", "replacement", "wrong_service"])
def test_pending_stop_readback_requires_the_addressed_incarnation(release, monkeypatch, change):
    host, _, _ = draining_host(release, monkeypatch)
    rows = host.containers()
    attempt = {"stop_pending": True, "addressed_containers": [{"ID": "api-id", "Service": "api"}]}
    if change == "missing":
        rows.pop(0)
    elif change == "replacement":
        rows[0]["ID"] = "replacement-id"
    else:
        rows[0]["Service"] = "other"
    with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
        host.wait_stopped(attempt, 3)
    assert attempt["stop_pending"] is True


def test_api_and_worker_stop_budgets_are_below_thirty_seconds(release, monkeypatch):
    updater, _, archive, *_ = release
    host, calls, _ = draining_host(release, monkeypatch)
    host.drain_timeout = 300
    assert updater.apply(archive) == "committed"
    assert calls[0][6] == "-1"
    assert calls[1][:7] == ["docker", "container", "stop", "--signal", "SIGINT", "--time", "-1"]
    assert set(calls[1][7:]) == {"semantic-id", "backup-id"}


@pytest.mark.parametrize("service", sorted(update.INTERRUPT_SERVICES - {"api"}))
@pytest.mark.parametrize("code", [0, 130, 137])
@pytest.mark.parametrize("legacy", [False, True])
def test_worker_compatibility_stop_is_bounded_scoped_and_preserves_exit_code(release, monkeypatch, service, code, legacy):
    _, fake, *_ = release
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None, drain_timeout=300)
    monkeypatch.setattr(host, "backup_activity", lambda: {"busy": False})
    worker_id = "a" * 12  # Compose ps uses short IDs; inspect returns the full ID.
    rows = [{"ID": worker_id, "Service": service, "State": "running", "ExitCode": 0},
            {"ID": "data-id", "Service": "postgres", "State": "running", "ExitCode": 0}]
    calls = []

    def stop(args, **kwargs):
        if args[:2] == ["docker", "inspect"]:
            return json.dumps({"id": "a" * 64, "image": "sha256:" + "a" * 64, "revision": "b" * 40,
                               "project": "sli", "service": service, "status": "exited", "exit_code": code,
                               "started_at": "2026-10-17T00:00:00Z", "finished_at": "2026-10-17T00:01:00Z",
                               "restart_count": 0,
                               "oom_killed": False, "error_empty": True})
        calls.append(args)
        assert kwargs["timeout"] == 25
        rows[0].update(State="exited", ExitCode=code)

    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "command", stop)
    monkeypatch.setattr(host, "in_flight", lambda: {"leases": 0, "transactions": 0})
    monkeypatch.setattr(update, "checked_override", lambda *args: None)
    monkeypatch.setattr(update, "LEGACY_INTERRUPT_REVISIONS", {"b" * 40})
    journal = {"services": [service]}
    journal["previous"] = {"source_commit": ("b" if legacy else "c") * 40, "image_digest": "sha256:" + "a" * 64}
    if code and not (legacy and code == 130):
        with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
            host.drain(journal)
        assert "drain_in_flight" not in journal
    else:
        host.drain(journal)
    assert calls == [["docker", "container", "stop", "--signal", "SIGINT", "--time", "-1", worker_id]]
    diagnostic = journal["drain_services"][0]["containers"][0]
    assert {key: diagnostic[key] for key in ("Service", "State", "ExitCode")} == {
        "Service": service, "State": "exited", "ExitCode": code}
    assert ("legacy_interrupt" in diagnostic) == (legacy and code == 130)
    assert rows[1]["State"] == "running"


def test_executor_keeps_sigterm_stop_with_twenty_five_second_budget(release, monkeypatch):
    _, fake, *_ = release
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None, drain_timeout=300)
    rows = [{"ID": "executor-id", "Service": "executor-light", "State": "running", "ExitCode": 0}]
    calls = []

    def compose(args, override, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 25
        rows[0]["State"] = "exited"

    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "in_flight", lambda: {"leases": 0, "transactions": 0})
    monkeypatch.setattr(update, "checked_override", lambda *args: None)
    host.drain({"services": ["executor-light"]})
    assert calls == [["stop", "--timeout", "-1", "executor-light"]]


def test_stop_command_timeout_records_safe_diagnostics_and_rolls_back(release, monkeypatch):
    updater, fake, archive, *_ = release
    host, _, _ = draining_host(release, monkeypatch)

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("fixture", 3, output=PRIVATE_ERROR_MARKER)

    monkeypatch.setattr(host, "command", timeout)
    assert updater.apply(archive) == "rolled_back"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == "update_drain_service_timeout"
    assert journal["drain_services"][0]["command_timed_out"]
    assert journal["drain_services"][0]["containers"] == [{"Service": "api", "State": "running", "ExitCode": 0}]
    assert PRIVATE_ERROR_MARKER not in json.dumps(journal)
    assert fake.active == "previous"


def legacy_term_host(monkeypatch, *, services=None, revision="b" * 40, mask="0000000000000002",
                     active=None, changed=None, soft_exit=False, early_return=False):
    host = update.DockerHost([], "https://127.0.0.1/api/health/ready", None, drain_timeout=300)
    monkeypatch.setattr(host, "backup_activity", lambda: {"busy": False})
    services = services or ["api"]
    rows = [{"ID": name + "-id", "Service": name, "State": "running", "ExitCode": 0}
            for name in [*services, *sorted(update.INFRA)]]
    identities = {row["ID"]: {"id": row["ID"], "image": "sha256:" + "a" * 64, "revision": revision,
        "project": "sli", "service": row["Service"], "status": "running", "exit_code": 0,
        "started_at": "2026-10-17T00:00:00Z", "finished_at": "0001-01-01T00:00:00Z", "restart_count": 0,
        "oom_killed": False, "error_empty": True} for row in rows}
    calls, persisted, clock = [], [], [0.0]

    def command(args, **kwargs):
        if args[:2] == ["docker", "inspect"]:
            assert ".Config.Env" not in args[3]
            return json.dumps(identities[args[-1]])
        if args[:2] == ["docker", "exec"]:
            return "Name:\tpython\nSigCgt:\t" + mask + "\n"
        calls.append(args)
        identifier = args[-1]
        if args[:3] == ["docker", "container", "stop"]:
            assert args[6] == "-1"
            if args[4] == "SIGINT" and all(identities[item]["service"] != "api" for item in args[7:]):
                for item in args[7:]:
                    identities[item].update(status="exited", exit_code=130, finished_at="2026-10-17T00:01:00Z")
                    next(row for row in rows if row["ID"] == item).update(State="exited", ExitCode=130)
                clock[0] += 0.1
                return identifier
            if soft_exit:
                identities[identifier].update({"status": "exited", "exit_code": 0,
                                              "finished_at": "2026-10-17T00:01:00Z", **(changed or {})})
                next(row for row in rows if row["ID"] == identifier).update(State="exited", ExitCode=0)
                return identifier
            if early_return:
                return identifier
            clock[0] += kwargs["timeout"]
            raise subprocess.TimeoutExpired("fixture", kwargs["timeout"], output=PRIVATE_ERROR_MARKER)
        if args[:2] == ["docker", "kill"]:
            assert persisted[-1]["drain_services"][-1]["legacy_term_stops"][-1]["force_signal"] == "SIGKILL"
            assert persisted[-1]["drain_services"][-1]["legacy_term_stops"][-1]["accepted"] is False
            identities[identifier].update({"status": "exited", "exit_code": 137,
                                          "finished_at": "2026-10-17T00:01:00Z", **(changed or {})})
            next(row for row in rows if row["ID"] == identifier).update(State="exited", ExitCode=137)
            return identifier
        assert args[:2] == ["docker", "wait"]
        return "137"

    monkeypatch.setattr(update, "LEGACY_INTERRUPT_REVISIONS", {"b" * 40})
    monkeypatch.setattr(update, "checked_override", lambda *_: None)
    monkeypatch.setattr(update.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(update.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "in_flight", lambda: active or {"leases": 0, "transactions": 0})
    def compose(args, override, **kwargs):
        assert args[:3] == ["stop", "--timeout", "-1"] and kwargs["timeout"] <= 25
        calls.append(args)
        for row in rows:
            if row["Service"] in args[3:]:
                row.update(State="exited", ExitCode=0)
    monkeypatch.setattr(host, "compose", compose)
    host.persist_drain = lambda journal: persisted.append(copy.deepcopy(journal))
    journal = {"services": services, "previous": {"source_commit": revision, "image_digest": "sha256:" + "a" * 64}}
    return host, journal, calls, persisted, identities, clock


def test_legacy_whole_runtime_stops_once_with_durable_force_audit_and_rechecks(monkeypatch):
    host, journal, calls, persisted, identities, clock = legacy_term_host(
        monkeypatch, services=[*sorted(update.INTERRUPT_SERVICES), "executor-light"])
    host.drain(journal)
    assert clock[0] == 25.1 < host.drain_timeout
    assert all(row["State"] == "exited" and row["ExitCode"] == (
        0 if row["Service"] == "executor-light" else 137 if row["Service"] == "api" else 130)
               for row in host.containers() if row["Service"] not in update.INFRA)
    assert all(row["State"] == "running" for row in host.containers() if row["Service"] in update.INFRA)
    force_records = [entry for entry in persisted if any(
        proof.get("force_signal") == "SIGKILL" for attempt in entry["drain_services"]
        for proof in attempt.get("legacy_term_stops", []))]
    assert len(force_records) == 2
    assert calls[0][3:7] == ["--signal", "SIGINT", "--time", "-1"] and "api-id" not in calls[0]
    assert all(proof["accepted"] and proof["sigcgt"] == "0000000000000002"
               and proof["in_flight"] == {"leases": 0, "transactions": 0}
               for attempt in journal["drain_services"] for proof in attempt.get("legacy_term_stops", []))
    assert PRIVATE_ERROR_MARKER not in json.dumps(journal)
    before = list(calls)
    host.drain(journal)  # Checkpoint's second fence must not signal or kill again.
    assert calls == before
    identities["api-id"]["restart_count"] += 1
    with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
        host.drain(journal)


@pytest.mark.parametrize("active,reason", [
    ({"leases": 1, "transactions": 0}, "update_drain_lease_timeout"),
    ({"leases": 0, "transactions": 1}, "update_drain_transaction_timeout"),
])
def test_legacy_force_is_forbidden_before_active_work_finishes(monkeypatch, active, reason):
    host, journal, calls, persisted, *_ = legacy_term_host(monkeypatch, active=active)
    with pytest.raises(update.UpdateError, match=reason):
        host.drain(journal)
    assert persisted[-1]["drain_services"][0]["stop_pending"] is True
    assert not any(call[:2] == ["docker", "kill"] for call in calls)
    assert host.containers()[0]["State"] == "running"


def test_legacy_api_waits_for_current_request_after_other_writers_stop(monkeypatch):
    host, journal, calls, _, _, clock = legacy_term_host(
        monkeypatch, services=[*sorted(update.INTERRUPT_SERVICES), "executor-light"])
    states = iter([{"leases": 0, "transactions": 1}, {"leases": 0, "transactions": 0}])
    def active():
        assert all(row["State"] == "exited" for row in host.containers()
                   if row["Service"] not in update.INFRA | {"api"})
        return next(states, {"leases": 0, "transactions": 0})
    monkeypatch.setattr(host, "in_flight", active)
    host.drain(journal)
    assert clock[0] == 26.1
    assert [call[-1] for call in calls if call[:2] == ["docker", "kill"]] == ["api-id"]
    assert journal["drain_services"][-1]["legacy_term_stops"][0]["in_flight"] == {"leases": 0, "transactions": 0}


def test_legacy_stop_rpc_returning_running_waits_full_grace_before_force(monkeypatch):
    host, journal, calls, persisted, _, clock = legacy_term_host(monkeypatch, early_return=True)
    host.drain(journal)
    assert clock[0] == 25
    assert calls[0][3:7] == ["--signal", "SIGINT", "--time", "-1"]
    proof = persisted[-1]["drain_services"][0]["legacy_term_stops"][0]
    assert proof["elapsed_ms"] == 25000 and proof["accepted"]


@pytest.mark.parametrize("revision,mask", [
    ("c" * 40, "0000000000000002"), ("b" * 40, "0000000000004002"),
    ("b" * 40, "invalid"),
])
def test_new_or_handled_or_unknown_signal_state_never_allows_force(monkeypatch, revision, mask):
    host, journal, calls, persisted, *_ = legacy_term_host(monkeypatch, revision=revision, mask=mask)
    with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
        host.drain(journal)
    assert not any(attempt.get("legacy_term_stops") for entry in persisted for attempt in entry["drain_services"])
    assert not any(call[:2] == ["docker", "kill"] for call in calls)
    assert calls[0][3:7] == ["--signal", "SIGINT", "--time", "-1"]


@pytest.mark.parametrize("changed", [
    {"oom_killed": True}, {"exit_code": 1}, {"image": "other"}, {"revision": "c" * 40},
    {"project": "other"}, {"service": "other"}, {"started_at": "2026-10-17T01:00:00Z"},
    {"restart_count": 1}, {"error_empty": False},
])
def test_forced_legacy_exit_requires_exact_identity_and_no_oom(monkeypatch, changed):
    host, journal, _, persisted, *_ = legacy_term_host(monkeypatch, changed=changed)
    with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
        host.drain(journal)
    assert persisted[-1]["drain_services"][0]["legacy_term_stops"][0]["accepted"] is False


def test_real_host_persists_authenticated_force_intent(release):
    updater, fake, *_ = release
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    real_updater = update.Updater(updater.runtime, updater.trust_store, host)
    journal = {"force_signal": "SIGKILL"}
    host.persist_drain(journal)
    assert real_updater.read_journal(real_updater.journal_path) == journal


@pytest.mark.parametrize("changed", [{}, {"oom_killed": True}, {"restart_count": 1}])
def test_legacy_term_can_exit_softly_but_must_keep_its_identity(monkeypatch, changed):
    host, journal, calls, persisted, *_ = legacy_term_host(monkeypatch, soft_exit=True, changed=changed)
    if changed:
        with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
            host.drain(journal)
    else:
        host.drain(journal)
        assert host.containers()[0]["ExitCode"] == 0
    assert not any(proof.get("force_signal") for entry in persisted for attempt in entry["drain_services"]
                   for proof in attempt.get("legacy_term_stops", []))
    assert not any(call[:2] == ["docker", "kill"] for call in calls)


@pytest.mark.parametrize("change", ["restart", "handler", "deadline"])
def test_force_rechecks_incarnation_handler_and_deadline_before_kill(monkeypatch, change):
    host, journal, calls, persisted, identities, clock = legacy_term_host(monkeypatch)
    original = host.command

    def command(args, **kwargs):
        try:
            return original(args, **kwargs)
        except subprocess.TimeoutExpired:
            if change == "restart":
                identities["api-id"]["restart_count"] += 1
            elif change == "handler":
                monkeypatch.setattr(host, "unhandled_term", lambda _: None)
            else:
                clock[0] = 300
            raise
    monkeypatch.setattr(host, "command", command)
    with pytest.raises(update.UpdateError, match="update_drain_service_timeout"):
        host.drain(journal)
    assert persisted[-1]["drain_services"][0]["stop_pending"] is True
    assert not any(call[:2] == ["docker", "kill"] for call in calls)


@pytest.mark.parametrize("active,expected", [
    ({"leases": 0, "transactions": 0}, "committed"),
    ({"leases": 0, "transactions": 1}, "rolled_back"),
])
def test_legacy_force_controls_checkpoint_and_migration(release, monkeypatch, active, expected):
    updater, fake, archive, *_ = release
    host, _, _, _, identities, _ = legacy_term_host(monkeypatch, services=["api", "backup", "semantic"], active=active)
    previous = package.read_json(updater.installed_path.read_bytes())
    previous["source_commit"] = "b" * 40
    update.atomic_json(updater.installed_path, previous)
    for identity in identities.values():
        identity["image"] = previous["image_digest"]
    record = host.persist_drain
    def persist(journal):
        record(journal)
        updater.save(journal)
    host.persist_drain = persist

    def drain(journal):
        host.drain(journal)
        fake.stopped = True
    monkeypatch.setattr(fake, "drain", drain)
    result = updater.apply(archive)
    assert result == expected, updater.read_journal(updater.journal_path).get("reason")
    journal = updater.read_journal(updater.journal_path)
    if expected == "committed":
        assert fake.calls.index("checkpoint") < fake.calls.index("migrate")
        assert sum(proof["accepted"] for attempt in journal["drain_services"]
                   for proof in attempt.get("legacy_term_stops", [])) == 1
    else:
        assert journal["reason"] == "update_drain_transaction_timeout"
        assert not {"checkpoint", "migrate", "restore"} & set(fake.calls)
        assert not journal["migration_started"]


def test_in_flight_probes_only_live_leases_and_transactions(monkeypatch):
    host = update.DockerHost([], "https://127.0.0.1/api/health/ready", None)
    queries = []

    def compose(args, **kwargs):
        sql = args[-1]
        queries.append(sql)
        assert sql.startswith("BEGIN READ ONLY; SET LOCAL statement_timeout=")
        if "FROM pg_attribute" in sql:
            return "SELECT count(*) AS n FROM public.semantic_processing_outbox WHERE lease_until > statement_timestamp()"
        return '{"leases":0,"transactions":0}'

    monkeypatch.setattr(host, "compose", compose)
    assert host.in_flight() == {"leases": 0, "transactions": 0}
    assert "lease_until > statement_timestamp()" in queries[1]
    assert "xact_start IS NOT NULL" in queries[1] and "pid<>pg_backend_pid()" in queries[1]
    assert "UPDATE " not in "".join(queries) and "DELETE " not in "".join(queries)


def tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, value in files.items():
            member = tarfile.TarInfo(name)
            if isinstance(value, tarfile.TarInfo):
                archive.addfile(value)
            else:
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))
    return stream.getvalue()


def write_tar(path, files):
    path.write_bytes(tar_bytes(files))


def write_zip(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, body in files.items():
            if isinstance(body, tarfile.TarInfo):
                item = zipfile.ZipInfo(name)
                item.create_system = 3
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(item, body.linkname)
            else:
                archive.writestr(name, body)


def contents(path):
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            return {name: archive.read(name) for name in archive.namelist()}
    with tarfile.open(path) as archive:
        return {item.name: archive.extractfile(item).read() for item in archive}


def make_image(path, *, sql=b"insert into schema_migrations(version,name) values(1,'example');", label="1.1.0", extra=None):
    migration = "config/postgres_migrations/001_example.sql"
    layer = tar_bytes({"opt/sli/" + migration: sql, **(extra or {})})
    config = package.canonical_json({"os": "linux", "architecture": "amd64",
                                "config": {"Labels": {"org.opencontainers.image.version": label}},
                                "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]}})
    digest = hashlib.sha256(config).hexdigest()
    write_tar(path, {digest + ".json": config, "layer.tar": layer,
                     "manifest.json": package.canonical_json([{"Config": digest + ".json", "Layers": ["layer.tar"],
                                                          "RepoTags": ["sli-running:local"]}]),
                     "repositories": b'{"sli-running":{"local":"old"}}'})
    return {"path": "image.tar", "digest": "sha256:" + digest}, {migration: hashlib.sha256(sql).hexdigest()}


class FakeHost:
    validate_snapshot_binding = update.DockerHost.validate_snapshot_binding
    operation_override = update.DockerHost.operation_override

    def validate_operation_overrides(self, journal):
        if hasattr(self, "configuration"):
            return update.DockerHost.validate_operation_overrides(self, journal)
        for key in ("previous_override", "candidate_override"):
            self.operation_override(journal, key)
        return {}

    def __init__(self, compose):
        self.files = [compose]
        self.calls = []
        self.active = "previous"
        self.stopped = False
        self.fail = None
        self.installed = None
        self.staged_manifest = None
        self.running_tag = None
        self.active_override = None
        self.ledger = 1
        self.plugins = []
        self.exact_ledger = None
        self.installed_release = None
        self.checkpoint_registry = None

    def observe(self):
        self.call("observe")
        version = self.installed["version"] if self.active == "previous" else self.staged_manifest["to_version"]
        digest = self.installed["image_digest"] if self.active == "previous" else self.staged_manifest["image"]["digest"]
        return {"migration_ledger_max": self.ledger, "plugins": self.plugins,
                "migration_ledger": copy.deepcopy(self.exact_ledger or self.installed["migration_ledger"]),
                "installed_release": copy.deepcopy(self.installed_release),
                "services": {name: {"version": version, "image_digest": digest, "image_tag": self.running_tag}
                             for name in ("api", "backup", "semantic")}}

    def preflight(self, installed, manifest):
        self.call("preflight")
        self.inspect_installation(installed)
        return self.observe()

    def ensure_secrets(self, installed):
        self.call("ensure_secrets")
        assert self.active == "previous" and not self.stopped

    def publish_installed(self, previous, candidate, operation):
        from deploy.linux.installed_state import inventory, installation_key
        self.call("publish")
        if self.installed_release:
            assert self.installed_release["inventory"] in (inventory(previous), inventory(candidate))
        self.installed_release = {"installation_key": installation_key(candidate),
                                  "operation": operation, "inventory": inventory(candidate)}
        for row in self.plugins:
            if row["installed"]:
                row["version"] = candidate["plugins"][row["plugin_id"]]["version"]

    def runtime_matches(self, journal, previous=False):
        observed = self.observe()
        target = journal["previous"] if previous else {
            "version": journal["manifest"]["to_version"], "image_tag": journal["candidate_tag"],
            "image_digest": journal["manifest"]["image"]["digest"]}
        assert all(row == {key: target[key] for key in ("version", "image_tag", "image_digest")}
                   for row in observed["services"].values())
        return observed

    def call(self, phase):
        self.calls.append(phase)
        if self.fail == phase:
            self.fail = None
            raise RuntimeError(f"{PRIVATE_ERROR_MARKER}: synthetic private error")

    def inspect_installation(self, installed):
        self.call("inspect")
        return ["api", "backup", "semantic"]

    def deployment_fingerprint(self):
        return "fingerprint"

    def stop_operation(self, journal):
        self.call("stop_operation")

    def stage(self, directory, manifest, tag):
        self.call("stage")
        assert tag.startswith("sli-update:candidate-")
        assert self.active == "previous" and not self.stopped
        self.staged_manifest = manifest

    def drain(self, journal):
        self.call("drain")
        self.stopped = True

    def check_backup(self, journal):
        self.call("check_backup")
        assert not self.stopped and self.active == "previous"

    def checkpoint(self, journal):
        self.call("checkpoint")
        assert self.stopped
        self.checkpoint_registry = copy.deepcopy(self.installed_release)
        return {"backup_id": "update-checkpoints/" + journal["operation"] + "/20261006T010000.000000Z",
                "checkpoint_sha256": "a" * 64}

    def migrate(self, journal):
        self.call("migrate")
        assert self.stopped and journal["backup_id"] and journal["migration_started"]
        self.ledger = max(int(Path(path).name.split("_", 1)[0]) for path in journal["manifest"]["migrations"])
        self.exact_ledger = copy.deepcopy(journal["candidate_ledger"])

    def activate(self, journal, previous=False):
        self.call("previous" if previous else "activate")
        self.active = "previous" if previous else "candidate"
        self.running_tag = journal["previous"]["image_tag"] if previous else journal["candidate_tag"]
        self.active_override = journal["previous_override"] if previous else journal["candidate_override"]
        self.stopped = False

    def health(self, journal):
        self.call("health")

    def restore(self, journal):
        self.call("restore")
        assert self.stopped and journal["backup_id"]
        self.ledger = journal["manifest"]["compatibility"]["migration_ledger_max"]
        self.exact_ledger = copy.deepcopy(journal["previous"]["migration_ledger"])
        self.installed_release = copy.deepcopy(self.checkpoint_registry)

    def fence(self, journal):
        self.call("fence")
        self.stopped = True


@pytest.fixture
def release(tmp_path, monkeypatch):
    payload_root = tmp_path / "release"
    payload_root.mkdir()
    image, migrations = make_image(payload_root / "image.tar")
    key = Ed25519PrivateKey.generate()
    private = tmp_path / "offline.key"
    private.write_bytes(key.private_bytes_raw())
    public = tmp_path / "trust.json"
    public.write_bytes(package.canonical_json({"schema_version": 1, "keys": [{
        "key_id": "test-only", "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "package_ids": ["sli.core", "sli.agent"], "revoked": False,
    }]}))
    manifest = {"schema_version": 2, "package_type": "core-update", "package_id": "sli.core",
                "version": "1.1.0", "platform": "linux-amd64", "source_commit": "a" * 40,
                "build_id": "synthetic-1", "minimum_updater": 1, "deletions": [], "restart_profile": "docker-compose",
                "component": "server", "from_version": "1.0.0", "to_version": "1.1.0",
                "compatibility": {"core_api": 1, "ui_api": 1, "from_version": "1.0.0",
                                  "min_version": "1.0.0", "max_version": "1.0.0", "os": "linux", "architecture": "amd64",
                                  "migration_ledger_max": 1, "plugins": {}},
                "required_free_disk": 1024, "files": [{"path": "image.tar"}], "image": image,
                "migrations": migrations, "compose_delta": None, "config_delta": None}
    draft = tmp_path / "manifest.json"
    version_file = tmp_path / "VERSION"
    version_file.write_text("1.1.0\n")
    monkeypatch.setattr(builder, "VERSION_FILE", version_file)
    draft.write_bytes(package.canonical_json(manifest))
    output = tmp_path / "sli-update-1.0.0-1.1.0.zip"
    manifest = build(draft, payload_root, private, output, key_id="test-only")
    runtime = tmp_path / "runtime"
    installed = {"component": "server", "version": "1.0.0", "os": "linux", "architecture": "amd64",
                 "image_tag": "sli-running:local", "image_digest": "sha256:" + "a" * 64, "migrations": migrations,
                 "compose_project": "sli", "volumes": {}}
    installed["migration_ledger"] = [{"version": 1, "name": "example", "sha256": next(iter(migrations.values()))}]
    update.atomic_json(runtime / "state/installed.json", installed)
    compose = tmp_path / "compose.yml"
    compose.write_text("services: {}\n")
    host = FakeHost(compose)
    host.installed = installed
    host.running_tag = installed["image_tag"]
    updater = update.Updater(runtime, public, host)
    return updater, host, output, manifest, key, payload_root


def verify(release, installed=None, disk=10**9):
    updater, _, output, _, _, _ = release
    installed = installed or package.read_json(updater.installed_path.read_bytes())
    return package.verify_package(output, updater.trust_store, installed=installed, free_bytes=disk).manifest


def resign(release, change):
    _, _, output, _, key, _ = release
    files = contents(output)
    manifest = json.loads(files[package.MANIFEST_NAME])
    change(manifest)
    files[package.MANIFEST_NAME] = package.canonical_json(manifest)
    files[package.SIGNATURE_NAME] = package.canonical_json({"algorithm": "ed25519", "key_id": "test-only",
        "signature": base64.b64encode(key.sign(package.SIGNING_CONTEXT + files[package.MANIFEST_NAME])).decode()})
    write_zip(output, files)


def test_signed_package_and_builder_never_publish_key(release):
    assert verify(release) == release[3]
    assert set(contents(release[2])) == {package.MANIFEST_NAME, package.SIGNATURE_NAME, "payload/image.tar"}
    with pytest.raises(FileExistsError):
        build(release[2].parent / "manifest.json", release[5], release[2].parent / "offline.key", release[2], key_id="test-only")


def test_ui_only_update_has_checkpoint_without_migration_or_database_rollback(release):
    updater, host, output, _, _, _ = release
    resign(release, lambda manifest: manifest.update(recovery_profile="ui-only"))
    host.fail = "health"
    assert updater.apply(output) == "rolled_back"
    journal = updater.operation()
    assert journal["backup_id"] and journal["manifest"]["recovery_profile"] == "ui-only"
    assert not journal["migration_started"]
    assert "checkpoint" in host.calls and "migrate" not in host.calls and "restore" not in host.calls
    assert "previous" in host.calls


@pytest.mark.parametrize("profile", ["history", "files"])
def test_data_profile_rolls_back_after_partial_activation(release, profile):
    updater, host, output, _, _, _ = release
    resign(release, lambda manifest: manifest.update(recovery_profile=profile))
    host.fail = "activate"
    assert updater.apply(output) == "rolled_back"
    assert "migrate" not in host.calls and "restore" in host.calls
    assert updater.operation()["rollback_restored"]


@pytest.mark.parametrize("profile", ["ui-only", "history", "files"])
def test_narrow_profile_cannot_add_migrations(release, profile):
    def change(manifest):
        manifest["recovery_profile"] = profile
        manifest["migrations"]["config/postgres_migrations/002_synthetic.sql"] = "b" * 64
    resign(release, change)
    with pytest.raises(package.PackageError, match="requires_postgres"):
        verify(release)


@pytest.mark.parametrize("profile", ["unknown", None, [], {}])
def test_invalid_signed_recovery_profile_is_rejected(release, profile):
    resign(release, lambda manifest: manifest.update(recovery_profile=profile))
    with pytest.raises(package.PackageError, match="invalid_recovery_profile"):
        verify(release)


def test_ui_only_profile_cannot_change_configuration(release):
    resign(release, lambda manifest: manifest.update(recovery_profile="ui-only", config_delta="settings.json"))
    with pytest.raises(package.PackageError, match="invalid_recovery_profile"):
        verify(release)


@pytest.mark.parametrize("version,reason", [("2026.10.2", "build_version_mismatch"), ("invalid", "invalid version")])
def test_builder_reads_the_checkout_version_and_refuses_drift(release, version, reason):
    builder.VERSION_FILE.write_text(version + "\n")
    output = release[2].parent / "mismatched.zip"
    with pytest.raises(package.PackageError, match=reason):
        build(release[2].parent / "manifest.json", release[5], release[2].parent / "offline.key", output, key_id="test-only")
    assert not output.exists()


def test_builder_fills_versions_from_version_file(release):
    draft = release[2].parent / "manifest.json"
    metadata = package.read_json(draft.read_bytes())
    del metadata["version"], metadata["to_version"]
    draft.write_bytes(package.canonical_json(metadata))
    result = build(draft, release[5], release[2].parent / "offline.key", release[2].parent / "filled.zip", key_id="test-only")
    assert result["to_version"] == result["version"] == builder.VERSION_FILE.read_text().strip()


def test_builder_cannot_follow_a_payload_link_to_the_signing_key(release):
    root = release[5]
    (root / "image.tar").unlink()
    (root / "image.tar").symlink_to(release[2].parent / "offline.key")
    output = release[2].parent / "linked.zip"
    with pytest.raises(package.PackageError, match="source must be inside input root"):
        build(release[2].parent / "manifest.json", root, release[2].parent / "offline.key", output, key_id="test-only")
    assert not output.exists()


def test_update_signature_requires_the_existing_signing_context(release):
    files = contents(release[2])
    files[package.SIGNATURE_NAME] = package.canonical_json({"algorithm": "ed25519", "key_id": "test-only",
        "signature": base64.b64encode(release[4].sign(files[package.MANIFEST_NAME])).decode()})
    write_zip(release[2], files)
    with pytest.raises(package.PackageError, match="signature"):
        verify(release)


@pytest.mark.parametrize("policy", [{"revoked": True}, {"key_id": "unknown"}, {"package_ids": ["sli.agent"]}])
def test_docker_updates_obey_the_existing_trust_policy(release, policy):
    updater, host, output, _, _, _ = release
    trust = package.read_json(updater.trust_store.read_bytes())
    trust["keys"][0].update(policy)
    updater.trust_store.write_bytes(package.canonical_json(trust))
    with pytest.raises(package.PackageError, match="signer"):
        updater.apply(output)
    assert host.calls == []


def test_staging_uses_verified_snapshot_and_can_resume(release, tmp_path):
    verified = package.verify_package(release[2], release[0].trust_store)
    release[2].write_bytes(b"changed after verification")
    destination = tmp_path / "stage"
    package.extract_payload(verified, destination)
    assert (destination / "image.tar").read_bytes() == (release[5] / "image.tar").read_bytes()
    package.extract_payload(verified, destination)
    (destination / "image.tar").write_bytes(b"changed after staging")
    with pytest.raises(package.PackageError, match="staged payload changed"):
        package.extract_payload(verified, destination)


def test_maintenance_apply_and_rollback_use_the_same_journal(release):
    from scripts.maintenance.apply_update import apply_update
    from scripts.maintenance.rollback_update import rollback

    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    args = {"runtime": updater.runtime, "host": host, "trust_store": updater.trust_store}
    result = apply_update(output, **args)
    assert result["status"] == "committed" and result["installed"]
    result = rollback(**args)
    assert result["status"] == "rolled_back"
    assert updater.installed_path.read_bytes() == original


def test_public_host_cli_routes_apply_and_rollback_to_one_journal(release, monkeypatch, capsys):
    from scripts.maintenance import apply_update, rollback_update

    updater, host, output, _, _, _ = release
    monkeypatch.setattr(update, "DockerHost", lambda *_, **kwargs: host)
    args = ["--runtime", str(updater.runtime), "--trust-store", str(updater.trust_store),
            "--compose", str(host.files[0]), "--ca-file", "synthetic-ca.pem", "--json"]
    assert apply_update.main(["--package", str(output), *args]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "committed"
    assert rollback_update.main(args) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "rolled_back"
    assert package.read_json(updater.journal_path.read_bytes())["status"] == "rolled_back"


def test_cli_apply_and_rollback_keep_operation_id_and_tls_policy(release, monkeypatch, capsys):
    updater, host, output, _, _, _ = release
    constructors = []

    def docker_host(*args, **kwargs):
        constructors.append((args, kwargs))
        return host

    monkeypatch.setattr(update, "DockerHost", docker_host)
    operation = "b" * 32
    args = ["--runtime", str(updater.runtime), "--trust-store", str(updater.trust_store),
            "--compose", str(host.files[0]), "--ca-file", "synthetic-ca.pem",
            "--tls-min-validity-seconds", "172800", "--drain-timeout", "600", "--json"]
    assert update.main(["apply", "--package", str(output), "--operation-id", operation, *args]) == 0
    assert json.loads(capsys.readouterr().out)["operation"] == operation
    assert update.main(["rollback", "--operation-id", "c" * 32, *args]) == 1
    assert json.loads(capsys.readouterr().out)["reason_code"] == "update_operation_not_found"
    assert package.read_json(updater.journal_path.read_bytes())["status"] == "committed"
    assert update.main(["rollback", "--operation-id", operation, *args]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "rolled_back"
    assert all(arguments[-1] == 172800 and keywords == {"drain_timeout": 600}
               for arguments, keywords in constructors)


def test_verify_only_checks_image_and_preflight_without_state_changes(release):
    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    result = update.apply_update(output, trust_store=updater.trust_store, dry_run=True,
                                 runtime=updater.runtime, host=host)
    assert result["status"] == "verified" and not result["installed"]
    assert host.calls == ["preflight", "inspect", "observe"] and not updater.journal_path.exists()
    assert updater.installed_path.read_bytes() == original


@pytest.mark.parametrize("kind", ["manifest", "signature", "payload", "extra", "missing", "wrong_key"])
def test_rejection_before_any_docker_operation(release, kind):
    updater, host, output, _, _, _ = release
    files = contents(output)
    if kind == "manifest":
        files[package.MANIFEST_NAME] += b" "
    elif kind == "signature":
        files[package.SIGNATURE_NAME] = b"x" * 64
    elif kind == "payload":
        files["payload/image.tar"] += b"corruption"
    elif kind == "extra":
        files["payload/undeclared"] = b"data"
    elif kind == "missing":
        files.pop(package.SIGNATURE_NAME)
    else:
        trust = package.read_json(updater.trust_store.read_bytes())
        trust["keys"][0]["public_key"] = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
        updater.trust_store.write_bytes(package.canonical_json(trust))
    write_zip(output, files)
    with pytest.raises(package.PackageError):
        updater.apply(output)
    assert host.calls == []
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["status"] == "rejected" and journal["phase"] == "verify"


@pytest.mark.parametrize("field,value", [("from_version", "0.9.0"), ("to_version", "1.0.0"),
                                         ("component", "unknown"), ("package_id", "sli.unknown"),
                                         ("required_free_disk", -1), ("schema_version", 3)])
def test_manifest_and_version_refusal(release, field, value):
    resign(release, lambda manifest: manifest.update({field: value}))
    with pytest.raises(package.PackageError):
        verify(release)


def test_min_max_platform_disk_and_immutable_migration_checks(release):
    with pytest.raises(package.PackageError, match="insufficient_disk"):
        verify(release, disk=1)
    installed = package.read_json(release[0].installed_path.read_bytes())
    installed["architecture"] = "arm64"
    with pytest.raises(package.PackageError, match="platform"):
        verify(release, installed)
    installed["architecture"] = "amd64"
    installed["migrations"][next(iter(installed["migrations"]))] = "c" * 64
    with pytest.raises(package.PackageError, match="published_migration"):
        verify(release, installed)
    resign(release, lambda manifest: manifest["compatibility"].update(min_version="1.0.1", max_version="1.0.2"))
    with pytest.raises(package.PackageError, match="incompatible_version"):
        verify(release)


@pytest.mark.parametrize("path", ["../file", "/file", "payload/a/../../b", "payload\\file", "payload/C:drive", "payload//file"])
def test_traversal_refused(release, path):
    files = contents(release[2])
    files[path] = b"data"
    write_zip(release[2], files)
    with pytest.raises(package.PackageError, match="path"):
        verify(release)


@pytest.mark.filterwarnings("ignore:Duplicate name.*:UserWarning")
def test_symlink_and_duplicate_archive_members_refused(release):
    files = contents(release[2])
    member = tarfile.TarInfo("payload/link")
    member.type = tarfile.SYMTYPE
    member.linkname = "../outside"
    files["payload/link"] = member
    write_zip(release[2], files)
    with pytest.raises(package.PackageError, match="link|duplicate"):
        verify(release)
    with zipfile.ZipFile(release[2], "w") as archive:
        for _ in range(2):
            archive.writestr(package.MANIFEST_NAME, b"{}")
    with pytest.raises(package.PackageError, match="duplicate"):
        verify(release)



def test_image_tag_stripping_and_real_inventory(release, tmp_path):
    manifest, root = release[3], release[5]
    sanitized = tmp_path / "clean.tar"
    update.image_inventory(root / "image.tar", manifest, sanitized)
    saved = contents(sanitized)
    assert "repositories" not in saved
    assert json.loads(saved["manifest.json"])[0]["RepoTags"] == []
    bad = dict(manifest, migrations={})
    with pytest.raises(package.PackageError, match="image_migrations"):
        update.image_inventory(root / "image.tar", bad, sanitized)
    bad = dict(manifest, image={"path": manifest["image"]["path"], "digest": "sha256:" + "f" * 64})
    with pytest.raises(package.PackageError, match="digest"):
        update.image_inventory(root / "image.tar", bad, sanitized)


@pytest.mark.parametrize("file_newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("ledger_newline", [b"\n", b"\r\n"])
def test_update_preserves_applied_newline_hash(release, tmp_path, monkeypatch, file_newline, ledger_newline):
    from deploy.linux import installed_state

    updater, host, _, manifest, _, root = release
    sql = b"select 1;\ninsert into schema_migrations(version,name) values(1,'example');\n"
    body = sql.replace(b"\n", file_newline)
    image, migrations = make_image(root / "image.tar", sql=body)
    draft = root.parent / "manifest.json"
    draft.write_bytes(package.canonical_json({**manifest, "image": image, "migrations": migrations}))
    output = tmp_path / "newline-update.zip"
    build(draft, root, root.parent / "offline.key", output, key_id="test-only")
    path = next(iter(migrations))
    source = tmp_path / "source" / path
    source.parent.mkdir(parents=True)
    source.write_bytes(body)
    monkeypatch.setattr(installed_state, "ROOT", tmp_path / "source")
    historical = hashlib.sha256(sql.replace(b"\n", ledger_newline)).hexdigest()
    host.installed["migrations"] = migrations
    host.installed["migration_ledger"][0]["sha256"] = historical
    original_ledger = copy.deepcopy(host.installed["migration_ledger"])
    update.atomic_json(updater.installed_path, host.installed)

    assert updater.apply(output) == "committed"
    assert updater.operation()["candidate_ledger"] == original_ledger
    assert host.exact_ledger == original_ledger
    assert package.read_json(updater.installed_path.read_bytes())["migration_ledger"] == original_ledger
    assert source.read_bytes() == body


@pytest.mark.parametrize("bad", ["content", "name", "mixed", "lone_cr", "missing_hash"])
def test_image_rejects_real_applied_migration_mismatch(release, tmp_path, bad):
    sql = b"select 1;\ninsert into schema_migrations(version,name) values(1,'example');\n"
    image, migrations = make_image(tmp_path / "image.tar", sql=sql)
    historical = sql.replace(b"\n", b"\r\n")
    name = "example"
    if bad == "content":
        historical = historical.replace(b"select 1", b"select 2")
    elif bad == "name":
        name = "foreign"
    elif bad == "mixed":
        historical = historical.replace(b"\r\n", b"\n", 1)
    elif bad == "lone_cr":
        historical = historical.replace(b"\r\n", b"\r")
    row = {"version": 1, "name": name,
           "sha256": None if bad == "missing_hash" else hashlib.sha256(historical).hexdigest()}
    original = copy.deepcopy(row)
    manifest = {**release[3], "image": image, "migrations": migrations}
    with pytest.raises(package.PackageError, match="migration_ledger_mismatch"):
        update.image_inventory(tmp_path / "image.tar", manifest, tmp_path / "clean.tar", applied_ledger=[row])
    assert row == original


@pytest.mark.parametrize("valid_final", [True, False])
def test_applied_hash_is_checked_against_final_image_layer(release, tmp_path, valid_final):
    sql = b"select 1;\ninsert into schema_migrations(version,name) values(1,'example');\n"
    changed = sql.replace(b"select 1", b"select 2")
    first, final = (changed, sql) if valid_final else (sql, changed)
    path = "config/postgres_migrations/001_example.sql"
    layers = [tar_bytes({"opt/sli/" + path: body}) for body in (first, final)]
    config = package.canonical_json({
        "os": "linux", "architecture": "amd64",
        "config": {"Labels": {"org.opencontainers.image.version": "1.1.0"}},
        "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest() for layer in layers]}})
    digest = hashlib.sha256(config).hexdigest()
    image = tmp_path / "layers.tar"
    write_tar(image, {digest + ".json": config, "first.tar": layers[0], "final.tar": layers[1],
                      "manifest.json": package.canonical_json([{
                          "Config": digest + ".json", "Layers": ["first.tar", "final.tar"], "RepoTags": []}])})
    manifest = {**release[3], "image": {"path": "layers.tar", "digest": "sha256:" + digest},
                "migrations": {path: hashlib.sha256(final).hexdigest()}}
    previous = [{"version": 1, "name": "example", "sha256": hashlib.sha256(sql.replace(b"\n", b"\r\n")).hexdigest()}]
    if valid_final:
        assert update.image_inventory(image, manifest, tmp_path / "clean.tar", applied_ledger=previous) == previous
    else:
        with pytest.raises(package.PackageError, match="migration_ledger_mismatch"):
            update.image_inventory(image, manifest, tmp_path / "clean.tar", applied_ledger=previous)


@pytest.mark.parametrize("kind", ["version", "layer", "whiteout", "symlink"])
def test_image_compatibility_rejected_before_candidate_code(release, kind, tmp_path):
    path = tmp_path / "bad.tar"
    extra = {}
    if kind == "whiteout":
        extra["opt/sli/config/.wh.postgres_migrations"] = b""
    if kind == "symlink":
        item = tarfile.TarInfo("opt/sli/config")
        item.type = tarfile.SYMTYPE
        item.linkname = "elsewhere"
        extra[item.name] = item
    image, migrations = make_image(path, label="9.9.9" if kind == "version" else "1.1.0", extra=extra)
    manifest = dict(release[3], image=image, migrations=migrations)
    if kind == "layer":
        files = contents(path)
        files["layer.tar"] += b"damage"
        write_tar(path, files)
    with pytest.raises(package.PackageError):
        update.image_inventory(path, manifest, tmp_path / "clean.tar")


def test_deltas_restrict_host_paths_commands_and_secrets(release):
    root, manifest = release[5], dict(release[3], compose_delta="delta.json")
    path = root / "delta.json"
    path.write_text('{"backup":{"SLI_BACKUP_RETENTION":"9"}}')
    assert update.load_deltas(root, manifest) == {"SLI_BACKUP_RETENTION": "9"}
    for delta in ({"api": {"entrypoint": "untrusted"}}, {"backup": {"PASSWORD": "synthetic"}},
                  {"backup": {"SLI_BACKUP_RETENTION": "0"}}, {"backup": {"SLI_BACKUP_INTERVAL_SECONDS": "2"}}):
        path.write_bytes(package.canonical_json(delta))
        with pytest.raises(package.PackageError):
            update.load_deltas(root, manifest)


@pytest.mark.parametrize("value", ["00:00", "02:00", "23:59", "24:00", "2:00", "02:60", "02:00\n", 200, None])
def test_deltas_validate_backup_time(release, value):
    root, manifest = release[5], dict(release[3], config_delta="delta.json")
    (root / "delta.json").write_bytes(package.canonical_json({"backup": {"SLI_BACKUP_TIME": value}}))
    if value in ("00:00", "02:00", "23:59"):
        assert update.load_deltas(root, manifest) == {"SLI_BACKUP_TIME": value}
        manifest["compose_delta"] = "delta.json"
    with pytest.raises(package.PackageError):
        update.load_deltas(root, manifest)


def test_success_one_journal_and_no_in_place_overwrite(release):
    updater, host, output, manifest, _, _ = release
    original = updater.installed_path.read_bytes()
    compose = host.files[0].read_bytes()
    assert updater.apply(output) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["completed"] == list(update.PHASES)
    assert journal["completed"] == ["verify", "stage", "checkpoint", "drain", "migrate", "activate", "health", "commit"]
    assert host.calls.index("drain") < host.calls.index("checkpoint") < host.calls.index("migrate")
    assert host.active == "candidate"
    assert package.read_json(updater.installed_path.read_bytes())["version"] == manifest["to_version"]
    assert host.files[0].read_bytes() == compose
    assert package.canonical_json(journal["previous"]) == original
    previous = package.read_json(Path(journal["previous_override"]).read_bytes())
    assert previous["services"]["api"]["image"] == journal["previous"]["image_tag"]
    assert updater.resume() == "committed"
    assert updater.resume(rollback=True) == "rolled_back"
    assert updater.installed_path.read_bytes() == original


@pytest.mark.parametrize("version", [177, 179])
def test_legacy_preflight_requires_installed_release_migration179(release, monkeypatch, version):
    updater, host, _, manifest, _, _ = release
    installed = package.read_json(updater.installed_path.read_bytes())
    observed = host.observe()
    observed["installed_release_available"] = False
    monkeypatch.setattr(host, "preflight", lambda *_: observed)
    manifest = copy.deepcopy(manifest)
    manifest["migrations"][f"config/postgres_migrations/{version:03d}_installed_release.sql"] = "c" * 64
    if version == 179:
        updater.preflight(installed, manifest)
    else:
        with pytest.raises(update.UpdateError, match="update_installed_registry_required"):
            updater.preflight(installed, manifest)
    assert not updater.journal_path.exists()


@pytest.mark.parametrize("bad", ["hole", "name", "checksum", "registry", "foreign"])
def test_u5_mismatch_is_refused_before_external_changes(release, bad):
    from deploy.linux.installed_state import inventory, installation_key
    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    installed = package.read_json(original)
    if bad in {"registry", "foreign"}:
        host.installed_release = {"installation_key": installation_key(installed), "operation": "b" * 32,
                                  "inventory": inventory(installed)}
        if bad == "registry":
            host.installed_release["inventory"]["image_digest"] = "sha256:" + "f" * 64
        else:
            host.installed_release["installation_key"] = "f" * 64
    else:
        host.exact_ledger = copy.deepcopy(installed["migration_ledger"])
        if bad == "hole":
            host.exact_ledger.append({"version": 2, "name": "untracked", "sha256": "f" * 64})
        elif bad == "name":
            host.exact_ledger[0]["name"] = "another_marker"
        else:
            host.exact_ledger[0]["sha256"] = "f" * 64
    assert updater.apply(output) == "rejected"
    assert updater.installed_path.read_bytes() == original
    assert not {"stage", "drain", "checkpoint", "migrate", "activate", "publish"} & set(host.calls)


def test_u5_restart_after_db_commit_recovers_installed_cache(release, monkeypatch):
    from deploy.linux.installed_state import inventory
    updater, host, output, manifest, _, _ = release
    original = updater.installed_path.read_bytes()
    publish = host.publish_installed
    def power_loss(*args):
        publish(*args)
        raise PowerLoss()
    monkeypatch.setattr(host, "publish_installed", power_loss)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    assert updater.installed_path.read_bytes() == original
    assert host.installed_release["inventory"]["version"] == manifest["to_version"]
    monkeypatch.setattr(host, "publish_installed", publish)
    restarted = update.Updater(updater.runtime, updater.trust_store, host)
    assert restarted.resume() == "committed"
    installed = package.read_json(updater.installed_path.read_bytes())
    assert host.installed_release["inventory"] == inventory(installed)
    status = restarted.status()
    assert status["readiness"] == {"ready": True, "reason_code": None}
    assert status["active_build"]["build_id"] == manifest["build_id"]
    assert status["active_build"]["image_digest"] == manifest["image"]["digest"]


def test_u5_resume_refuses_changed_ledger_before_drain(release, monkeypatch):
    updater, host, output, _, _, _ = release
    step = updater.step
    def crash(journal, phase):
        step(journal, phase)
        if phase == "stage":
            raise PowerLoss()
    monkeypatch.setattr(updater, "step", crash)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    host.exact_ledger = copy.deepcopy(host.installed["migration_ledger"])
    host.exact_ledger[0]["name"] = "foreign_marker"
    host.calls.clear()
    with pytest.raises(package.PackageError, match="migration_ledger_mismatch"):
        update.Updater(updater.runtime, updater.trust_store, host).resume()
    assert not {"drain", "checkpoint", "migrate", "activate", "restore", "publish"} & set(host.calls)


def test_u5_rollback_does_not_overwrite_foreign_authority(release):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    original = updater.installed_path.read_bytes()
    host.installed_release["installation_key"] = "f" * 64
    registry = copy.deepcopy(host.installed_release)
    host.calls.clear()
    assert updater.resume(rollback=True) == "recovery_required"
    assert updater.operation()["rollback_error"] == "update_foreign_installation"
    assert host.installed_release == registry and updater.installed_path.read_bytes() == original
    assert not {"drain", "restore", "activate", "previous", "publish", "fence"} & set(host.calls)


def test_u5_status_reports_observed_digest_and_mismatch_without_mutation(release):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    original = updater.installed_path.read_bytes(), updater.journal_path.read_bytes()
    host.staged_manifest = copy.deepcopy(host.staged_manifest)
    host.staged_manifest["image"]["digest"] = "sha256:" + "f" * 64
    status = updater.status()
    assert status["active_build"]["image_digest"] == "sha256:" + "f" * 64
    assert "build_id" not in status["active_build"]
    assert status["readiness"] == {"ready": False, "reason_code": "update_running_version_mismatch"}
    assert original == (updater.installed_path.read_bytes(), updater.journal_path.read_bytes())


@pytest.mark.parametrize("fresh_install", [False, True])
def test_publication_streams_large_inventory_without_linux_argument_limit(monkeypatch, fresh_install):
    from deploy.linux.installation import InstallationHost

    host_type = InstallationHost if fresh_install else update.DockerHost
    host = host_type([], "https://127.0.0.1:8443/api/health/ready", Path("synthetic-ca"))
    installed = {"compose_project": "sli", "volumes": {}, "plugins": {}, "migrations": {
        f"config/postgres_migrations/{n:03d}_synthetic.sql": "a" * 64 for n in range(1, 214)},
        "migration_ledger": [{"version": n, "name": f"{n:03d}_synthetic.sql", "sha256": "a" * 64}
                             for n in range(1, 214)]}
    monkeypatch.setattr(host, "ownership_preflight", lambda *_: None)
    statements = []

    def run(args, **kwargs):
        assert max(len(arg.encode()) for arg in args) < 131072
        if "psql" in args:
            assert "--command" not in args and args[-2:] == ["--file", "-"]
            statement = kwargs["input"].decode("utf-8")
            assert len(statement) > 131072
            payload = statement.split("decode('", 1)[1].split("'", 1)[0]
            assert json.loads(bytes.fromhex(payload))["candidate"]["migration_ledger"] == installed["migration_ledger"]
            statements.append(statement)
        return SimpleNamespace(returncode=0, stdout=b"{}")

    monkeypatch.setattr(update.subprocess, "run", run)
    host.publish_installed(installed, installed, "b" * 32)
    assert len(statements) == 1


def test_u5_publication_uses_ownership_and_one_guarded_transaction(release, monkeypatch):
    updater, fake, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    host = update.DockerHost(fake.files, "https://127.0.0.1:8443/api/health/ready", Path("synthetic-ca"))
    calls = []
    def compose(args, *, stdin=None):
        calls.append((args, stdin))
        return '{}' if args[0] == 'config' else ''
    ownership = []
    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "ownership_preflight", lambda installed, config: ownership.append(installed))
    candidate = updater.candidate(journal)
    host.publish_installed(journal["previous"], candidate, journal["operation"])
    assert ownership == [candidate]
    assert calls[-1][0][-2:] == ['--file', '-']
    statement = calls[-1][1].decode('utf-8')
    assert statement.startswith("BEGIN;") and statement.endswith("COMMIT;")
    assert "FOR UPDATE" in statement and "pg_advisory_xact_lock" in statement
    assert "sli_installed_release_v179" in statement
    assert "current.inventory=p->'previous'" in statement
    assert "current.operation=p->>'operation'" in statement
    assert "actual IS DISTINCT FROM p->'candidate'->'migration_ledger'" in statement
    assert "SET package_version=" in statement
    assert "desired_activation=" not in statement and "component_runtime=" not in statement


def test_console_recover_uses_checkpoint_when_api_is_down(release, monkeypatch, capsys):
    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    assert updater.apply(output) == "committed"
    host.calls.clear()

    def api_down(_):
        pytest.fail("Console recovery must not call API readiness")

    def recovery_health(journal):
        host.call("recovery_readback")
        assert host.active == "previous"
        assert journal["recovery_api_unchecked"]

    monkeypatch.setattr(host, "health", api_down)
    monkeypatch.setattr(host, "recovery_health", recovery_health, raising=False)
    monkeypatch.setattr(update, "DockerHost", lambda *_, **kwargs: host)
    # No CA or trust-store is needed to restore a trusted local checkpoint.
    assert update.main(["recover", "--rollback-server", "--runtime", str(updater.runtime),
                        "--compose", str(host.files[0])]) == 0
    text = capsys.readouterr().out
    assert "Состояние локальных журналов" in text and "Готовность API не проверена" in text
    assert "restore" in host.calls and "recovery_readback" in host.calls
    assert "health" not in host.calls
    assert updater.installed_path.read_bytes() == original
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["status"] == "rolled_back" and journal["rollback_restored"]
    assert journal["recovery_api_unchecked"]


def test_console_recover_failure_retains_checkpoint_and_retry_intent(release, monkeypatch, capsys):
    from deploy.linux.update_recovery import recover_server

    updater, host, output, _, _, _ = release
    updater.apply(output)
    host.fail = "restore"
    monkeypatch.setattr(host, "recovery_health", lambda _: host.call("recovery_readback"), raising=False)
    assert recover_server(updater.runtime, None, host)["status"] == "recovery_required"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["status"] == "recovery_required" and journal["backup_id"]
    assert journal["rollback_runtime"] == "stopped" and host.stopped
    host.fail = "restore"
    monkeypatch.setattr(update, "DockerHost", lambda *_, **__: host)
    assert update.main(["recover", "--rollback-server", "--runtime", str(updater.runtime),
                        "--compose", str(host.files[0])]) == 1
    text = capsys.readouterr().out
    assert "Восстановление не завершено" in text and "Сервисы приложения остановлены" in text
    assert "Причина незавершённого отката: update_rollback_failed" in text
    assert "Отклонённая операция" not in text and PRIVATE_ERROR_MARKER not in text
    assert recover_server(updater.runtime, None, host)["status"] == "rolled_back"


def test_status_is_read_only_without_database_or_host(release, monkeypatch, capsys):
    updater, host, output, _, _, _ = release
    updater.apply(output)
    before = {str(path): path.read_bytes() for path in updater.state.rglob("*") if path.is_file()}
    host.calls.clear()

    def forbidden(*_, **__):
        pytest.fail("Status must not construct a host, lock state, or connect to a service")

    monkeypatch.setattr(update, "DockerHost", forbidden)
    monkeypatch.setattr(update, "operation_lock", forbidden)
    assert update.main(["status", "--runtime", str(updater.runtime), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["journals"]["server"]["status"] == "committed"
    assert result["journals"]["server"]["checkpoint_available"]
    assert result["server_version"] == "1.1.0"
    assert "package" not in result["journals"]["server"]
    assert host.calls == []
    assert before == {str(path): path.read_bytes() for path in updater.state.rglob("*") if path.is_file()}


def test_status_on_absent_installation_creates_nothing(tmp_path, capsys):
    runtime = tmp_path / "absent"
    assert update.main(["status", "--runtime", str(runtime), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["journals"]["server"]["status"] == "absent"
    assert not runtime.exists()


def test_console_status_does_not_disclose_raw_journal_data(tmp_path, capsys):
    update.atomic_json(tmp_path / "state/update-journal.json", {
        "status": "synthetic-private-error", "phase": "synthetic-private-error",
        "reason": "synthetic-private-error", "package": "synthetic-private-error",
        "completed": ["verify", "synthetic-private-error"], "backup_id": "synthetic-private-error",
    })
    assert update.main(["recover", "--runtime", str(tmp_path), "--json"]) == 0
    text = capsys.readouterr().out
    assert "synthetic-private-error" not in text
    assert json.loads(text)["journals"]["server"]["status"] == "unknown"


def test_corrupt_journal_is_visible_in_read_only_diagnostics(tmp_path, capsys):
    state = tmp_path / "state"
    state.mkdir()
    (state / "update-journal.json").write_text("invalid-json")
    update.atomic_json(state / "updater-journal.json", {"status": "committed", "phase": "commit"})
    assert update.main(["status", "--runtime", str(tmp_path), "--json"]) == 0
    journals = json.loads(capsys.readouterr().out)["journals"]
    assert journals["server"]["status"] == "unreadable"
    assert journals["updater"]["status"] == "committed"


def test_recovery_docker_readback_never_probes_https(tmp_path, monkeypatch):
    host = update.DockerHost([tmp_path / "compose.yml"], "https://127.0.0.1/api/health/ready", None)
    rows = [{"Service": name, "State": "running", "Health": "healthy", "ID": name} for name in update.INFRA]
    rows.append({"Service": "api", "State": "running", "Health": "unhealthy", "ID": "synthetic-api"})
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "command", lambda _: "sha256:" + "a" * 64)

    def forbidden(*_, **__):
        pytest.fail("Recovery must not contact the unavailable HTTPS API")

    monkeypatch.setattr(update, "urlopen", forbidden)
    host.recovery_health({"services": ["api"], "previous": {"image_digest": "sha256:" + "a" * 64}})
    monkeypatch.setattr(host, "command", lambda _: "sha256:" + "b" * 64)
    with pytest.raises(package.PackageError, match="image_mismatch"):
        host.recovery_health({"services": ["api"], "previous": {"image_digest": "sha256:" + "a" * 64}})


class PowerLoss(BaseException):
    pass


def test_bundled_registration_is_pinned_to_reviewed_migration():
    path = "config/postgres_migrations/221_sigma_chain_plugins.sql"
    body = (Path(__file__).resolve().parents[2] / path).read_bytes()
    lf = body.replace(b"\r\n", b"\n")
    for encoding in (lf, lf.replace(b"\n", b"\r\n")):
        manifest = {"component": "server", "migrations": {path: hashlib.sha256(encoding).hexdigest()}}
        assert update.bundled_core_plugins(manifest) == {"sli.sigma": {"version": "1.0.0", "migrations": {}}}
        assert update.bundled_core_plugins(manifest, applied_ledger=[{"version": 221}]) == {}
    with pytest.raises(update.UpdateError, match="update_plugin_registration_mismatch"):
        update.bundled_core_plugins({"component": "server", "migrations": {path: "a" * 64}})
    assert update.bundled_core_plugins({"component": "server", "migrations": {}}) == {}


@pytest.mark.parametrize("failure", [None, "health", "interrupt"])
def test_core_registration_survives_commit_rollback_and_resume(release, monkeypatch, failure):
    updater, host, archive, *_ = release
    monkeypatch.setattr(update, "bundled_core_plugins", lambda _, **kw: {"sli.sigma": {"version": "1.0.0", "migrations": {}}})
    migrate, restore = host.migrate, host.restore

    def register(journal):
        migrate(journal)
        host.plugins.append({"plugin_id": "sli.sigma", "version": "1.0.0", "installed": True, "enabled": False})
        if failure == "interrupt":
            raise PowerLoss()

    def restore_plugins(journal):
        restore(journal)
        host.plugins = []

    monkeypatch.setattr(host, "migrate", register)
    monkeypatch.setattr(host, "restore", restore_plugins)
    if failure == "health":
        host.fail = "health"
    if failure == "interrupt":
        with pytest.raises(PowerLoss):
            updater.apply(archive)
        assert updater.resume() == "rolled_back"
    else:
        assert updater.apply(archive) == ("committed" if failure is None else "rolled_back")
    installed = package.read_json(updater.installed_path.read_bytes())
    if failure is None:
        assert installed["plugins"] == {"sli.sigma": {"version": "1.0.0", "migrations": {}}}
    else:
        assert installed.get("plugins", {}) == {} and host.plugins == []
        assert host.calls.count("restore") == 1 and host.active == "previous"


@pytest.mark.parametrize("foreign", ["unreviewed", "wrong_version", "before_migration"])
def test_core_recovery_rejects_foreign_registration(release, monkeypatch, foreign):
    updater, host, archive, *_ = release
    monkeypatch.setattr(update, "bundled_core_plugins", lambda _, **kw: {"sli.sigma": {"version": "1.0.0", "migrations": {}}})
    original = updater.step

    def interrupt(journal, phase):
        original(journal, phase)
        if phase == ("stage" if foreign == "before_migration" else "migrate"):
            host.plugins = [{"plugin_id": "sli.foreign" if foreign == "unreviewed" else "sli.sigma",
                             "version": "2.0.0" if foreign == "wrong_version" else "1.0.0",
                             "installed": True, "enabled": False}]
            raise PowerLoss()

    monkeypatch.setattr(updater, "step", interrupt)
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    if foreign == "before_migration":
        with pytest.raises(update.UpdateError, match="update_plugin_registry_mismatch"):
            updater.resume()
        assert "restore" not in host.calls
        return
    assert updater.resume() == "recovery_required"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["rollback_error"] == "update_plugin_registry_mismatch"
    assert "restore" not in host.calls


@pytest.mark.parametrize("phase", update.PHASES)
@pytest.mark.parametrize("after", [False, True])
def test_resume_interruption_at_every_phase(release, monkeypatch, phase, after):
    updater, host, output, _, _, _ = release
    step = updater.step
    def interrupted(journal, current):
        if current == phase and not after:
            raise PowerLoss()
        step(journal, current)
        if current == phase and after:
            raise PowerLoss()
    monkeypatch.setattr(updater, "step", interrupted)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    monkeypatch.setattr(updater, "step", step)
    operation = package.read_json(updater.journal_path.read_bytes())["operation"]
    recovered = updater.resume(operation_id=operation)
    expected = "rolled_back" if phase in {"migrate", "activate", "health"} else "committed"
    assert recovered == expected
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["status"] == expected
    if expected == "rolled_back":
        assert host.active == "previous"
        assert ("restore" in host.calls) == (phase != "migrate" or after)
        assert package.read_json(updater.installed_path.read_bytes()) == journal["previous"]
    installed = package.read_json(updater.installed_path.read_bytes())
    override = package.read_json(Path(host.active_override).read_bytes())
    assert override["services"]["api"]["image"] == host.running_tag == installed["image_tag"]
    assert all(row["version"] == installed["version"] and row["image_digest"] == installed["image_digest"]
               for row in host.observe()["services"].values())
    if expected == "committed":
        calls = list(host.calls)
        assert updater.resume(operation_id=operation) == "committed"
        assert updater.apply(output, operation_id=operation) == "committed"
        assert host.calls == calls


@pytest.mark.parametrize("failure", ["inspect", "stage", "drain", "checkpoint", "migrate", "activate", "health"])
def test_automatic_rollback_paths_and_redacted_reason(release, failure):
    updater, host, output, manifest, _, _ = release
    assert PRIVATE_ERROR_MARKER not in package.canonical_json(manifest).decode()
    host.fail = failure
    assert updater.apply(output) == ("rejected" if failure == "inspect" else "rolled_back")
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["reason"] == "update_phase_failed"
    assert PRIVATE_ERROR_MARKER not in updater.journal_path.read_text()
    assert journal["manifest"]["build_id"] == manifest["build_id"]
    assert host.active == "previous"
    assert ("restore" in host.calls) == (failure in {"migrate", "activate", "health"})


def test_failed_rollback_is_resumable(release, monkeypatch):
    updater, host, output, _, _, _ = release
    host.fail = "health"
    restore = host.restore
    def fail_restore(journal):
        raise RuntimeError("synthetic private failure")
    monkeypatch.setattr(host, "restore", fail_restore)
    assert updater.apply(output) == "recovery_required"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["status"] == "recovery_required"
    assert journal["rollback_runtime"] == "stopped" and host.stopped
    monkeypatch.setattr(host, "restore", restore)
    assert updater.resume() == "rolled_back"


def test_unhealthy_previous_release_has_terminal_version_readback_and_can_recover(release, monkeypatch):
    from deploy.linux.update_recovery import console_status

    updater, host, output, manifest, *_ = release
    previous = updater.installed_path.read_bytes()

    def drain(_):
        raise update.UpdateError("update_drain_service_timeout")

    def health(_):
        raise update.UpdateError("update_health_timeout")

    monkeypatch.setattr(host, "drain", drain)
    monkeypatch.setattr(host, "health", health)
    result = update.apply_update(output, trust_store=updater.trust_store, runtime=updater.runtime, host=host)
    assert result["status"] == "recovery_required" and not result["installed"] and result["executed"]
    assert result["source_commit"] == manifest["source_commit"]
    assert result["reason_code"] == "update_rollback_failed"
    assert result["update_reason_code"] == "update_drain_service_timeout"
    assert result["rollback_reason_code"] == "update_health_timeout"
    assert result["rollback_runtime"] == "previous"
    assert updater.installed_path.read_bytes() == previous
    assert host.active == "previous" and not host.stopped
    assert not {"restore", "migrate", "fence"} & set(host.calls)
    assert console_status(updater.runtime)["journals"]["server"] == {
        "status": "recovery_required", "phase": "checkpoint", "completed": ["verify", "stage"],
        "checkpoint_available": False, "migration_started": False, "api_readiness": "unknown",
        "rollback_runtime": "previous", "reason": "update_drain_service_timeout", "rollback_error": "update_health_timeout",
    }
    with pytest.raises(package.PackageError, match="update_resume_required"):
        updater.apply(output)
    # An idempotent apply of this operation must report the same target and
    # rollback diagnostics, rather than re-entering the candidate phases.
    retry = update.apply_update(output, trust_store=updater.trust_store, runtime=updater.runtime,
                                host=host, operation_id=result["operation"])
    assert retry["status"] == "recovery_required" and retry["source_commit"] == manifest["source_commit"]
    assert retry["rollback_reason_code"] == "update_health_timeout"
    monkeypatch.setattr(host, "health", lambda _: None)
    assert updater.resume() == "rolled_back"
    assert "rollback_error" not in updater.operation()


@pytest.mark.parametrize("failure", ["activate", "readback", "publish"])
def test_partial_previous_activation_is_fenced_and_resume_only_retries_rollback(release, monkeypatch, failure):
    updater, host, output, *_ = release
    previous = updater.installed_path.read_bytes()
    assert updater.apply(output) == "committed"
    method = {"activate": "activate", "readback": "runtime_matches", "publish": "publish_installed"}[failure]
    original = getattr(host, method)

    def fail(*args, **kwargs):
        if failure == "activate":
            # Compose recreated a subset before failing. The remaining services
            # still run the candidate image until containment stops all writers.
            host.active = "candidate"
            host.stopped = False
        raise RuntimeError(PRIVATE_ERROR_MARKER)

    monkeypatch.setattr(host, method, fail)
    assert updater.resume(rollback=True) == "recovery_required"
    journal = updater.operation()
    assert journal["rollback_runtime"] == "stopped" and host.stopped
    assert journal["rollback_restored"] and journal["backup_id"]
    assert PRIVATE_ERROR_MARKER not in updater.journal_path.read_text()
    calls = host.calls.count("restore"), host.calls.count("migrate")
    monkeypatch.setattr(host, method, original)
    assert updater.resume() == "rolled_back"
    assert (host.calls.count("restore"), host.calls.count("migrate")) == calls
    assert updater.installed_path.read_bytes() == previous and host.active == "previous" and not host.stopped


def test_failed_fence_reports_unverified_runtime_without_exposing_exception(release, monkeypatch, capsys):
    updater, host, output, manifest, *_ = release
    host.fail = "health"

    def fail(_):
        raise RuntimeError(PRIVATE_ERROR_MARKER)

    monkeypatch.setattr(host, "restore", fail)
    monkeypatch.setattr(host, "fence", fail)
    monkeypatch.setattr(update, "DockerHost", lambda *_, **__: host)
    args = ["--runtime", str(updater.runtime), "--trust-store", str(updater.trust_store),
            "--compose", str(host.files[0]), "--ca-file", "unused.pem", "--json"]
    assert update.main(["apply", "--package", str(output), *args]) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "recovery_required" and result["source_commit"] == manifest["source_commit"]
    assert result["rollback_runtime"] == "unverified"
    assert result["rollback_fence_reason_code"] == "update_rollback_fence_failed"
    assert result["executed"] and not result["installed"]
    assert PRIVATE_ERROR_MARKER not in json.dumps(result) + updater.journal_path.read_text()
    migrations = host.calls.count("migrate")
    assert update.main(["resume", *args]) == 1
    retry = json.loads(capsys.readouterr().out)
    assert retry["status"] == "recovery_required" and retry["reason_code"] == "update_rollback_failed"
    assert host.calls.count("migrate") == migrations


@pytest.mark.parametrize("stuck,stop_timeout", [(False, False), (True, False), (True, True)])
def test_recovery_fence_stops_all_app_containers_but_preserves_data_services(release, monkeypatch, stuck, stop_timeout):
    updater, fake, output, *_ = release
    assert updater.apply(output) == "committed"
    journal = updater.operation()
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    rows = [{"ID": name, "Service": name, "State": "running"} for name in [*journal["services"], *update.INFRA]]
    calls = []

    def compose(args, override, **kwargs):
        assert override == journal["previous_override"] and kwargs["timeout"] == 20
        assert args == ["stop", "--timeout", "10", *journal["services"]]
        if stop_timeout:
            raise subprocess.TimeoutExpired("fixture", 20, stderr=PRIVATE_ERROR_MARKER)
        for row in rows:
            if row["Service"] not in update.INFRA and not stuck:
                row["State"] = "exited"

    def command(args, **kwargs):
        calls.append(args)
        assert kwargs["timeout"] == 15 and args[:5] == ["docker", "container", "stop", "--time", "0"]
        assert args[-1] not in update.INFRA
        next(row for row in rows if row["ID"] == args[-1])["State"] = "exited"

    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "containers", lambda: rows)
    host.fence(journal)
    assert all(row["State"] == ("running" if row["Service"] in update.INFRA else "exited") for row in rows)
    assert len(calls) == (len(journal["services"]) if stuck else 0)


def test_recovery_fence_does_not_claim_success_when_a_container_restarts(release, monkeypatch):
    updater, fake, output, *_ = release
    assert updater.apply(output) == "committed"
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    monkeypatch.setattr(host, "compose", lambda *_, **__: None)
    monkeypatch.setattr(host, "command", lambda *_, **__: None)
    monkeypatch.setattr(host, "containers", lambda: [{"ID": "api", "Service": "api", "State": "restarting"}])
    with pytest.raises(package.PackageError, match="update_rollback_fence_failed"):
        host.fence(updater.operation())


def test_recovery_fence_attempts_remaining_services_after_one_stop_fails(release, monkeypatch):
    updater, fake, output, *_ = release
    assert updater.apply(output) == "committed"
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    rows = [{"ID": name, "Service": name, "State": "running"} for name in ("api", "backup", "semantic")]
    attempts = []

    def command(args, **_):
        attempts.append(args[-1])
        if args[-1] == "api":
            raise update.UpdateError("update_docker_failed")
        next(row for row in rows if row["ID"] == args[-1])["State"] = "exited"

    monkeypatch.setattr(host, "compose", lambda *_, **__: None)
    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "containers", lambda: rows)
    with pytest.raises(package.PackageError, match="update_rollback_fence_failed"):
        host.fence(updater.operation())
    assert attempts == ["api", "backup", "semantic"]
    assert [row["State"] for row in rows] == ["running", "exited", "exited"]


@pytest.mark.parametrize("failure", [None, "up", "readback", "missing_worker"])
def test_rollback_opens_api_only_after_all_workers_have_previous_image(release, monkeypatch, failure):
    updater, fake, output, *_ = release
    assert updater.apply(output) == "committed"
    journal = updater.operation()
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    rows = [{"ID": name, "Service": name, "State": "exited"} for name in journal["services"]]
    images = dict.fromkeys(journal["services"], journal["manifest"]["image"]["digest"])
    previous = journal["previous"]["image_digest"]
    starts = []

    def compose(args, override):
        assert override == journal["previous_override"]
        services = args[args.index("never") + 1:]
        starts.append(services)
        if services == ["api"]:
            assert all(images[name] == previous for name in images if name != "api")
        for row in rows:
            if row["Service"] in services:
                row["State"] = "running"
                images[row["Service"]] = previous
                if failure == "up":
                    raise update.UpdateError("update_docker_failed")
        if failure == "readback":
            images["semantic"] = journal["manifest"]["image"]["digest"]

    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "image_id", lambda _: previous)
    monkeypatch.setattr(host, "containers", lambda: [row for row in rows if failure != "missing_worker" or row["Service"] != "semantic"])
    monkeypatch.setattr(host, "command", lambda args: images[args[-1]])
    if failure:
        with pytest.raises(package.PackageError):
            host.activate(journal, previous=True)
        assert all("api" not in services for services in starts)
        assert next(row for row in rows if row["Service"] == "api")["State"] == "exited"
    else:
        host.activate(journal, previous=True)
        assert starts == [["backup", "semantic"], ["api"]]
        assert all(image == previous for image in images.values())


def test_resume_rejects_changed_compose_or_package(release, monkeypatch):
    updater, host, output, _, _, _ = release
    step = updater.step
    monkeypatch.setattr(updater, "step", lambda *_: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.apply(output)
    monkeypatch.setattr(updater, "step", step)
    host.files[0].write_text("changed")
    with pytest.raises(package.PackageError, match="compose_changed"):
        updater.resume()
    host.files[0].write_text("services: {}\n")
    journal = package.read_json(updater.journal_path.read_bytes())
    Path(journal["package"]).write_bytes(b"changed")
    with pytest.raises(package.PackageError, match="package_changed"):
        updater.resume()


def test_agent_uses_same_signature_contract_and_server_refuses_agent(release):
    updater, _, output, _, _, _ = release
    resign(release, lambda manifest: manifest.update(component="agent", package_type="plugin-update", package_id="sli.agent", restart_profile="none", image=None, migrations={}))
    installed = {"component": "agent", "version": "1.0.0", "os": "linux", "architecture": "amd64"}
    assert package.verify_package(output, updater.trust_store, installed=installed, free_bytes=10**9, component="agent").manifest["component"] == "agent"
    with pytest.raises(package.PackageError, match="component_mismatch"):
        updater.apply(output)


def test_docker_adapter_never_starts_dependencies_or_builds(release, monkeypatch):
    updater, _, _, manifest, _, root = release
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    calls = []
    def command(args):
        calls.append(args)
        if args[1:3] == ["image", "inspect"] or args[1] == "inspect":
            return manifest["image"]["digest"]
        return ""
    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "containers", lambda: [{"ID": "backup", "Service": "backup", "State": "running"}])
    host.stage(root, manifest, "sli-update:candidate-test")
    journal = {"previous_override": "previous.json", "candidate_override": "candidate.json", "services": ["api", "backup"],
               "operation": "a" * 32, "candidate_tag": "sli-update:candidate-test", "manifest": manifest,
               "previous": {"image_tag": "sli-running:local", "image_digest": manifest["image"]["digest"]}}
    for key in ("previous_override", "candidate_override"):
        path = root / journal[key]
        path.write_bytes(package.canonical_json({"services": {}}))
        journal[key] = str(path)
        journal[key + "_sha256"] = update.sha256(path)
    host.migrate(journal)
    host.activate(journal)
    host.activate(journal, previous=True)
    compose_calls = [args for args in calls if args[1] == "compose"]
    assert all(args[2:4] == ["-p", "sli"] for args in compose_calls)
    assert all("--no-deps" in args for args in compose_calls)
    assert all("--pull" not in args for args in compose_calls if "run" in args)
    assert all(args[args.index("--pull") + 1] == "never" for args in compose_calls if "up" in args)
    assert all("--no-build" in args for args in compose_calls if "up" in args)
    assert not any("down" in args or "build" in args for args in calls)


def test_daily_backup_metadata_is_checked_before_any_service_is_drained(release):
    updater, host, archive, *_ = release
    assert updater.apply(archive) == "committed"
    assert host.calls.index("stage") < host.calls.index("check_backup") < host.calls.index("drain")
    assert host.calls.index("drain") < host.calls.index("checkpoint") < host.calls.index("migrate")


def test_failed_daily_backup_check_does_not_stop_or_restart_previous_release(release):
    updater, host, archive, *_ = release
    host.fail = "check_backup"
    assert updater.apply(archive) == "rolled_back"
    assert host.active == "previous" and not host.stopped
    assert not {"drain", "checkpoint", "migrate", "previous", "restore"} & set(host.calls)


@pytest.mark.parametrize("profile", ["ui-only", "postgres", "full", "history", "files"])
def test_docker_requires_checked_daily_backup_for_every_profile(release, monkeypatch, profile):
    updater, fake, archive, *_ = release
    assert updater.apply(archive) == "committed"
    journal = updater.operation()
    journal["manifest"]["recovery_profile"] = profile
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    selected = {"backup_id": "20261006T010000.000000Z", "migration_ledger_max_version": max(
        row["version"] for row in journal["previous"]["migration_ledger"])}
    calls = []
    def helper(journal, action, identity):
        calls.append(action)
        assert json.loads(identity) == {key: journal[key] for key in ("operation", "checkpoint_key")}
        return json.dumps({"status": "verified", "daily_backup": selected})
    monkeypatch.setattr(host, "helper", helper)
    host.check_backup(journal)
    assert calls == ["check"] and journal["daily_backup"] == selected
    assert journal["backup_verification"] == "nightly"
    monkeypatch.setattr(host, "helper", lambda *_: '{"status":"waiting"}')
    with pytest.raises(package.PackageError, match="update_fresh_daily_backup_required"):
        host.check_backup(journal)


def test_daily_backup_of_an_older_schema_cannot_be_rollback_point(release, monkeypatch):
    updater, fake, archive, *_ = release
    assert updater.apply(archive) == "committed"
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    monkeypatch.setattr(host, "helper", lambda *_: json.dumps({"status": "verified", "daily_backup": {
        "backup_id": "20261006T010000.000000Z", "migration_ledger_max_version": 0}}))
    with pytest.raises(package.PackageError, match="update_daily_backup_schema_mismatch"):
        host.check_backup(updater.operation())


@pytest.mark.parametrize("reason", ["update_fresh_daily_backup_required", "update_daily_backup_schema_mismatch"])
@pytest.mark.parametrize("phase", ["stage", "checkpoint"])
def test_daily_copy_refusal_rejects_update_before_drain(release, monkeypatch, reason, phase):
    updater, host, archive, *_ = release
    def refuse(journal):
        raise update.UpdateError(reason)
    monkeypatch.setattr(host, "check_backup" if phase == "stage" else "drain", refuse)
    assert updater.apply(archive) == "rejected"
    journal = updater.operation()
    assert journal["status"] == "rejected" and journal["phase"] == phase
    assert journal["reason"] == reason
    assert journal["desired_activation"] == {key: journal["previous"][key]
                                             for key in ("version", "image_tag", "image_digest")}
    assert updater.operation_result(journal)["reason_code"] == reason
    assert not journal["migration_started"] and not journal.get("drain_services")
    assert not {"drain", "checkpoint", "migrate", "stop_operation", "previous", "restore"} & set(host.calls)
    assert host.active == "previous" and not host.stopped


@pytest.mark.parametrize("reason", ["update_fresh_daily_backup_required", "update_daily_backup_schema_mismatch"])
def test_next_apply_creates_new_operation_after_daily_copy_rejection(release, monkeypatch, reason):
    updater, host, archive, *_ = release
    original_check = host.check_backup
    def refuse(journal):
        raise update.UpdateError(reason)
    monkeypatch.setattr(host, "check_backup", refuse)
    assert updater.apply(archive) == "rejected"
    rejected = updater.operation()
    monkeypatch.setattr(host, "check_backup", original_check)

    assert updater.apply(archive) == "committed"
    assert updater.operation()["operation"] != rejected["operation"]
    archived = updater.operation(rejected["operation"])
    assert archived["status"] == "rejected" and archived["reason"] == reason


@pytest.mark.parametrize("reason", ["update_fresh_daily_backup_required", "update_daily_backup_schema_mismatch"])
def test_daily_copy_refusal_after_service_drain_keeps_existing_recovery(release, monkeypatch, reason):
    updater, host, archive, *_ = release
    def refuse(journal):
        journal["drain_services"] = [{"services": ["api"]}]
        raise update.UpdateError(reason)
    monkeypatch.setattr(host, "checkpoint", refuse)
    if reason.endswith("mismatch"):
        with pytest.raises(update.UpdateError, match=reason):
            updater.apply(archive)
        assert updater.operation()["status"] == "running"
    else:
        assert updater.apply(archive) == "rolled_back"
        assert host.active == "previous" and not host.stopped


def test_other_stage_mismatch_still_requires_resume(release, monkeypatch):
    updater, host, archive, *_ = release
    def refuse(journal):
        raise update.UpdateError("update_running_version_mismatch")
    monkeypatch.setattr(host, "check_backup", refuse)
    with pytest.raises(update.UpdateError, match="update_running_version_mismatch"):
        updater.apply(archive)
    journal = updater.operation()
    assert journal["status"] == "running" and journal["phase"] == "stage"
    assert journal["reason"] == "update_running_version_mismatch"


@pytest.mark.parametrize("restored", [False, True])
@pytest.mark.parametrize("receipt_registry", [False, True])
def test_nightly_registry_from_an_earlier_core_release_is_used_only_after_restore(
        release, monkeypatch, restored, receipt_registry):
    from deploy.linux.installed_state import installation_key, inventory

    updater, host, archive, *_ = release
    nightly = {"installation_key": installation_key(host.installed),
               "inventory": {**inventory(host.installed), "version": "0.9.0", "build_id": "nightly-core"}}
    original_check = host.check_backup
    original_restore = host.restore
    def check(journal):
        original_check(journal)
        journal["daily_backup"] = {"backup_id": "20261006T010000.000000Z",
                                   "backup_started_at_utc": "2026-10-06T01:00:00+00:00",
                                   "installed_release": nightly if receipt_registry else None}
    def restore(journal):
        original_restore(journal)
        host.installed_release = {**copy.deepcopy(nightly), "operation": "c" * 32}
    monkeypatch.setattr(host, "check_backup", check)
    monkeypatch.setattr(host, "restore", restore)
    if restored:
        host.fail = "health"
        assert updater.apply(archive) == "rolled_back"
        journal = updater.operation()
        assert journal["rollback_restored"]
        assert host.installed_release["inventory"] == inventory(journal["previous"])
        assert updater.operation_result(journal)["daily_backup"]["backup_id"] == "20261006T010000.000000Z"
    else:
        assert updater.apply(archive) == "committed"
        journal = updater.operation()
        host.installed_release = {**copy.deepcopy(nightly), "operation": "c" * 32}
        with pytest.raises(update.UpdateError, match="update_installed_registry_mismatch"):
            updater.publish(journal, updater.candidate(journal))


@pytest.mark.parametrize("defect", [None, "installation", "ledger", "plugins"])
def test_daily_registry_allows_same_schema_core_updates_only(release, monkeypatch, defect):
    from deploy.linux.installed_state import installation_key, inventory

    updater, fake, archive, *_ = release
    assert updater.apply(archive) == "committed"
    journal = updater.operation()
    saved = {**inventory(journal["previous"]), "version": "0.9.0"}
    registry = {"installation_key": installation_key(journal["previous"]), "inventory": saved}
    if defect == "installation":
        registry["installation_key"] = "f" * 64
    elif defect == "ledger":
        saved["migration_ledger"] = []
    elif defect == "plugins":
        saved["plugins"] = {"sli.synthetic": {"version": "0.1.0"}}
    selected = {"migration_ledger_max_version": 1, "installed_release": registry}
    host = update.DockerHost(fake.files, "https://127.0.0.1/api/health/ready", None)
    monkeypatch.setattr(host, "helper", lambda *_: json.dumps({"status": "verified", "daily_backup": selected}))
    if defect:
        with pytest.raises(update.UpdateError, match="update_daily_backup_schema_mismatch"):
            host.check_backup(journal)
    else:
        host.check_backup(journal)
        assert journal["daily_backup"] == selected


def seal_checkpoint(root, identifier):
    with checkpoint.snapshot(root, identifier) as (copy, inventory):
        manifest = json.loads((copy / "manifest.json").read_bytes())
    operation = identifier.split("/")[1]
    manifest.update(operation=operation, content_checksums=inventory)
    checkpoint_key = "b" * 64
    manifest["authentication"] = checkpoint.authenticate(manifest, checkpoint_key)
    path = root / identifier / "manifest.json"
    path.write_bytes(package.canonical_json(manifest))
    return {"backup_id": identifier, "operation": operation, "checkpoint_sha256": update.sha256(path),
            "checkpoint_key": checkpoint_key}


@pytest.mark.skipif(os.name == "nt", reason="Linux checkpoint descriptors")
def test_postgres_restore_recreates_database_and_checks_real_ledger(tmp_path, monkeypatch):
    identifier = "update-checkpoints/" + "a" * 32 + "/20261006T010000.000000Z"
    path = tmp_path / identifier
    (path / "postgres").mkdir(parents=True)
    (path / "postgres/toc.dat").write_bytes(b"fake")
    (path / "manifest.json").write_bytes(package.canonical_json({"status": "success", "backup_id": path.name,
        "components": {"postgres": {"row_counts": {"schema_migrations": 1}}}, "migration_ledger_max_version": 1}))
    identity = seal_checkpoint(tmp_path, identifier)
    sql, tools = [], []
    class Connection:
        def execute(self, statement):
            sql.append(statement)
            return self
        def fetchone(self):
            return (1,)
    monkeypatch.setattr(checkpoint.backup, "backup_lock", lambda *_: nullcontext())
    monkeypatch.setattr(checkpoint.backup, "pg_passfile", lambda: nullcontext(Path("passfile")))
    monkeypatch.setattr(checkpoint.backup, "pg_connect", lambda *args, **kwargs: nullcontext(Connection()))
    monkeypatch.setattr(checkpoint.backup, "pg_tool", lambda args, _: tools.append(args))
    monkeypatch.setattr(checkpoint.backup, "row_counts", lambda _: {"schema_migrations": 1})
    checkpoint.restore(tmp_path, **identity)
    assert sql[:2] == ["DROP DATABASE IF EXISTS sli WITH (FORCE)", "CREATE DATABASE sli OWNER sli_migration TEMPLATE template0"]
    assert tools[0][0] == "pg_restore" and "--no-owner" not in tools[0] and "--no-acl" not in tools[0]
    assert all("INSERT" not in statement and "UPDATE" not in statement for statement in sql)
    monkeypatch.setattr(checkpoint.backup, "row_counts", lambda _: {"schema_migrations": 2})
    with pytest.raises(RuntimeError, match="readback_failed"):
        checkpoint.restore(tmp_path, **identity)


def test_duplicate_json_and_published_id_reuse_rejected(release):
    with pytest.raises(package.PackageError):
        package.read_json(b'{"component":"server","component":"agent"}')
    resign(release, lambda manifest: manifest["migrations"].update({
        "config/postgres_migrations/001_second_name.sql": "a" * 64}))
    with pytest.raises(package.PackageError, match="duplicate_migration_id"):
        verify(release)


def test_signed_new_migration_cannot_fill_a_published_id_hole(release):
    updater = release[0]
    installed = package.read_json(updater.installed_path.read_bytes())
    installed["migrations"]["config/postgres_migrations/003_later.sql"] = "a" * 64
    resign(release, lambda manifest: manifest["migrations"].update({
        "config/postgres_migrations/003_later.sql": "a" * 64,
        "config/postgres_migrations/002_hole.sql": "b" * 64}))
    with pytest.raises(package.PackageError, match="published_migration_id_reused"):
        verify(release, installed)


def test_compressed_oci_style_layer_is_verified_without_running_code(release, tmp_path):
    import gzip
    source = release[5] / "image.tar"
    files = contents(source)
    files["layer.tar"] = gzip.compress(files["layer.tar"])
    source = tmp_path / "gzip-image.tar"
    write_tar(source, files)
    update.image_inventory(source, release[3], tmp_path / "sanitized.tar")


@pytest.mark.parametrize("phase", ["restore", "previous", "health"])
def test_interrupted_rollback_does_not_restore_twice_after_previous_activation(release, monkeypatch, phase):
    updater, host, output, _, _, _ = release
    host.fail = "activate"
    method = "activate" if phase == "previous" else phase
    original = getattr(host, method)
    interrupted = False
    def die(*args, **kwargs):
        nonlocal interrupted
        result = original(*args, **kwargs)
        if not interrupted and (phase != "previous" or kwargs.get("previous")):
            interrupted = True
            raise PowerLoss()
        return result
    monkeypatch.setattr(host, method, die)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    count = host.calls.count("restore")
    monkeypatch.setattr(host, method, original)
    assert updater.resume() == "rolled_back"
    assert host.calls.count("restore") == count + (1 if phase == "restore" else 0)


def test_rollback_does_not_require_an_intact_candidate_package(release, monkeypatch):
    updater, host, output, _, _, _ = release
    original = updater.step
    def die(journal, phase):
        original(journal, phase)
        if phase == "migrate":
            raise PowerLoss()
    monkeypatch.setattr(updater, "step", die)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    journal = package.read_json(updater.journal_path.read_bytes())
    Path(journal["package"]).unlink()
    assert updater.resume() == "rolled_back" and host.active == "previous"


def test_commit_write_failure_restores_checkpoint(release, monkeypatch):
    updater, host, output, _, _, _ = release
    original = update.atomic_json
    failed = False
    def write(path, value):
        nonlocal failed
        if path == updater.installed_path and value["version"] == "1.1.0" and not failed:
            failed = True
            raise OSError("synthetic private failure")
        return original(path, value)
    monkeypatch.setattr(update, "atomic_json", write)
    assert updater.apply(output) == "rolled_back"
    assert host.calls.count("restore") == 1 and host.active == "previous"


def test_active_journal_refuses_second_apply(release, monkeypatch):
    updater, host, output, _, _, _ = release
    monkeypatch.setattr(updater, "step", lambda *_: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.apply(output)
    with pytest.raises(package.PackageError, match="resume_required"):
        updater.apply(output)


def test_health_requires_readiness_and_every_service_healthy(release, monkeypatch):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"), timeout=4)
    rows = [{"Service": name, "State": "running", "Health": "healthy"}
            for name in ["api", "backup", *update.INFRA]]
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(update.ssl, "create_default_context", lambda **_: "verified-tls-context")
    calls = []
    def urlopen(url, *, context, timeout):
        calls.append((url, context))
        return nullcontext(SimpleNamespace(status=200))
    monkeypatch.setattr(update, "urlopen", urlopen)
    monkeypatch.setattr(update.time, "sleep", lambda _: None)
    ticks = iter(range(10))
    monkeypatch.setattr(update.time, "monotonic", lambda: next(ticks))
    host.health({"services": ["api", "backup"]})
    assert calls == [(host.health_url, "verified-tls-context")]
    rows.append({"Service": "api", "State": "running", "Health": "unhealthy"})
    ticks = iter(range(10))
    with pytest.raises(package.PackageError, match="health_timeout"):
        host.health({"services": ["api", "backup"]})
    assert len(calls) == 1


def test_host_fences_only_its_named_one_off_containers(release, monkeypatch):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    calls = []
    def command(args):
        calls.append(args)
        return "container-id" if "ls" in args else ""
    monkeypatch.setattr(host, "command", command)
    host.stop_operation({"operation": "a" * 32})
    removed = [args[-1] for args in calls if "rm" in args]
    assert removed == ["sli-update-" + action + "-" + "a" * 32 for action in ("migrate", "backup", "restore", "check")]
    assert all("postgres" not in args and "clickhouse" not in args for args in calls)


@pytest.mark.parametrize("bad", [None, "digest", "mount", "incomplete"])
def test_current_installation_is_checked_before_candidate_execution(release, monkeypatch, bad):
    installed = package.read_json(release[0].installed_path.read_bytes())
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    services = ["api", "backup", "migrate"]
    config = {"services": {name: {"healthcheck": {"test": ["CMD", "true"]}, "volumes": []} for name in services}}
    rows = [{"Service": name, "State": "running", "ID": name} for name in ["api", "backup", *update.INFRA]]
    if bad == "mount":
        config["services"]["migrate"]["volumes"] = [{"target": "/opt/sli/config", "source": "/untrusted"}]
    if bad == "incomplete":
        rows = [row for row in rows if row["Service"] != "postgres"]
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "compose", lambda _: package.canonical_json(config))
    monkeypatch.setattr(host, "image_id", lambda _: installed["image_digest"])
    monkeypatch.setattr(host, "command", lambda _: "sha256:" + "b" * 64 if bad == "digest" else installed["image_digest"])
    if bad is None:
        assert host.inspect_installation(installed) == ["api", "backup"]
    else:
        with pytest.raises(package.PackageError):
            host.inspect_installation(installed)


@pytest.mark.parametrize("target,setting", [
    ("/opt/sli/plugins", "SLI_PLUGIN_RUNTIME_DIR"),
    ("/opt/sli/plugin-locks", "SLI_PLUGIN_LOCK_DIR"),
])
@pytest.mark.parametrize("bad", [None, "writable", "unspecified_mode", "volume", "environment", "child", "code"])
def test_current_installation_allows_only_declared_read_only_plugin_binds(monkeypatch, target, setting, bad):
    host = update.DockerHost([], "https://127.0.0.1:8443/api/health/ready", None)
    digest = "sha256:" + "a" * 64
    mount = {"type": "bind", "source": "/runtime/plugins", "target": target, "read_only": True}
    service = {"healthcheck": {"test": ["CMD", "true"]}, "volumes": [mount], "environment": {setting: target}}
    config = {"services": {"api": service, "backup": {"healthcheck": service["healthcheck"]}, "migrate": {}}}
    if bad == "writable":
        mount["read_only"] = False
    elif bad == "unspecified_mode":
        mount.pop("read_only")
    elif bad == "volume":
        mount["type"] = "volume"
    elif bad == "environment":
        service["environment"][setting] = "/unrelated"
    elif bad == "child":
        mount["target"] += "/nested.py"
    elif bad == "code":
        mount["target"] = "/opt/sli/server/sli/plugins/file_audit/importer.py"
    rows = [{"Service": name, "State": "running", "ID": name} for name in ["api", "backup", *update.INFRA]]
    monkeypatch.setattr(host, "containers", lambda: rows)
    monkeypatch.setattr(host, "compose", lambda _: package.canonical_json(config))
    monkeypatch.setattr(host, "image_id", lambda _: digest)
    monkeypatch.setattr(host, "command", lambda _: digest)
    installed = {"image_digest": digest, "image_tag": "sli:installed"}
    if bad is None:
        assert host.inspect_installation(installed) == ["api", "backup"]
    else:
        with pytest.raises(package.PackageError, match="^update_code_mount_forbidden$"):
            host.inspect_installation(installed)


@pytest.mark.parametrize("phase", update.PHASES)
@pytest.mark.parametrize("after", [False, True])
def test_fake_host_crash_at_phase_side_effect_resumes_consistently(release, monkeypatch, phase, after):
    updater, host, output, _, _, _ = release
    operation = "b" * 32
    armed = True

    def interrupt(effect):
        def wrapped(*args, **kwargs):
            nonlocal armed
            current = package.read_json(updater.journal_path.read_bytes())["phase"]
            crash = armed and current == phase
            if crash:
                armed = False
                if not after:
                    raise PowerLoss()
            result = effect(*args, **kwargs)
            if crash:
                raise PowerLoss()
            return result
        return wrapped

    if phase == "commit":
        atomic = update.atomic_json
        interrupted = interrupt(atomic)
        monkeypatch.setattr(update, "atomic_json", lambda path, value:
                            interrupted(path, value) if path == updater.installed_path else atomic(path, value))
    else:
        method = "preflight" if phase == "verify" else phase
        monkeypatch.setattr(host, method, interrupt(getattr(host, method)))
    with pytest.raises(PowerLoss):
        updater.apply(output, operation_id=operation)
    # A new host-updater process uses only the durable journal and external state.
    restarted = update.Updater(updater.runtime, updater.trust_store, host)
    status = restarted.resume(operation_id=operation)
    assert status == ("rolled_back" if phase in {"migrate", "activate", "health"} else "committed")
    installed = package.read_json(updater.installed_path.read_bytes())
    override = package.read_json(Path(host.active_override).read_bytes())
    assert override["services"]["api"]["image"] == host.running_tag == installed["image_tag"]
    assert all(row["version"] == installed["version"] and row["image_digest"] == installed["image_digest"]
               for row in host.observe()["services"].values())
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), list(host.calls)
    assert restarted.resume(operation_id=operation) == status
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), host.calls)


@pytest.mark.parametrize("bad", ["version", "ledger", "plugin", "disabled_plugin", "expectations"])
def test_preflight_refuses_incompatibility_before_stage_or_runtime_changes(release, monkeypatch, bad):
    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    if bad == "version":
        observe = host.observe
        def wrong_version():
            value = observe()
            value["services"]["api"]["version"] = "0.9.0"
            return value
        monkeypatch.setattr(host, "observe", wrong_version)
    elif bad == "ledger":
        host.ledger = 2
    elif bad in {"plugin", "disabled_plugin"}:
        host.plugins = [{"plugin_id": "sli.example", "version": "0.1.0", "installed": True, "enabled": bad == "plugin"}]
    else:
        resign(release, lambda manifest: manifest["compatibility"].pop("migration_ledger_max"))
    assert updater.apply(output) == "rejected"
    assert updater.installed_path.read_bytes() == original
    assert not {"stage", "drain", "checkpoint", "migrate", "activate"} & set(host.calls)
    assert host.active == "previous" and not host.stopped


def test_ensure_failure_rejects_update_without_stopping_previous_runtime(release):
    updater, host, output, _, _, _ = release
    original = updater.installed_path.read_bytes()
    host.fail = "ensure_secrets"
    assert updater.apply(output) == "rejected"
    assert host.calls == ["ensure_secrets"]
    assert host.active == "previous" and not host.stopped
    assert updater.installed_path.read_bytes() == original
    assert updater.operation()["completed"] == []


def test_ensure_precedes_update_preflight_and_container_changes(release):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    assert host.calls.index("ensure_secrets") < host.calls.index("preflight") < host.calls.index("stage")
    assert host.calls.index("ensure_secrets") < host.calls.index("drain") < host.calls.index("migrate")
    assert host.calls.index("migrate") < host.calls.index("activate")


def test_preflight_checks_installed_and_enabled_plugin_policy(release):
    updater, host, _, manifest, _, _ = release
    installed = package.read_json(updater.installed_path.read_bytes())
    host.plugins = [{"plugin_id": "sli.example", "version": "0.1.0", "installed": True, "enabled": True}]
    installed["plugins"] = {"sli.example": {"version": "0.1.0"}}
    manifest["compatibility"]["plugins"] = {"sli.example": {"min_version": "0.1.0", "max_version": "0.2.0", "enabled": False}}
    with pytest.raises(package.PackageError, match="plugin_incompatible|plugin_registry_mismatch"):
        updater.preflight(installed, manifest)
    manifest["compatibility"]["plugins"]["sli.example"]["enabled"] = True
    assert updater.preflight(installed, manifest)["plugins"] == host.plugins
    host.plugins[0]["version"] = "0.3.0"
    with pytest.raises(package.PackageError, match="plugin_incompatible|plugin_registry_mismatch"):
        updater.preflight(installed, manifest)


def test_operation_id_and_status_keep_package_ledger_and_runtime_separate(release, monkeypatch, capsys):
    updater, host, output, manifest, _, _ = release
    operation = "c" * 32
    assert updater.apply(output, operation_id=operation) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    assert journal["package_version"] == manifest["to_version"]
    assert journal["migration_ledger"] == {"max_version": 1}
    assert journal["desired_activation"]["image_tag"] == host.running_tag
    assert journal["observed_runtime"]["services"]["api"]["version"] == manifest["to_version"]
    expected_tag = f"git tag -a sli-{manifest['to_version']} {manifest['source_commit']}"
    assert journal["tag_command"] == expected_tag
    monkeypatch.setattr(update, "DockerHost", lambda *_, **kwargs: host)
    args = ["--runtime", str(updater.runtime), "--trust-store", str(updater.trust_store),
            "--compose", str(host.files[0]), "--ca-file", "synthetic-ca.pem", "--operation-id", operation]
    assert update.main(["resume", *args]) == 0
    assert expected_tag in capsys.readouterr().out
    host.ledger = 2
    assert update.main(["status", *args]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["migration_ledger"] == {"max_version": 2}
    assert result["package_version"] == manifest["to_version"]
    assert package.read_json(updater.journal_path.read_bytes())["migration_ledger"] == {"max_version": 1}
    with pytest.raises(package.PackageError, match="operation_not_found"):
        updater.resume(operation_id="d" * 32)
    with pytest.raises(package.PackageError, match="invalid_operation"):
        updater.resume(operation_id="../invalid")


@pytest.mark.parametrize("bad", ["project", "registry", "volume_label", "consumer"])
def test_compose_and_volume_ownership_refuse_foreign_installation(release, monkeypatch, bad):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    installed = {"compose_project": "sli", "volumes": {"data": "sli-data"}}
    config = {"name": "sli", "volumes": {"data": {"name": "sli-data", "external": True}}}
    if bad == "project":
        installed["compose_project"] = "foreign"
    elif bad == "registry":
        installed["volumes"] = {}
    monkeypatch.setattr(host, "containers", lambda: [])
    def command(args):
        if args[1] == "volume":
            return json.dumps([{"Labels": {"com.docker.compose.project": "foreign" if bad == "volume_label" else "sli"}}])
        if args[1] == "ps":
            return "synthetic-container" if bad == "consumer" else ""
        return json.dumps({"com.docker.compose.project": "foreign"})
    monkeypatch.setattr(host, "command", command)
    with pytest.raises(package.PackageError, match="foreign_installation|volume_ownership"):
        host.ownership_preflight(installed, config)


def test_pinned_external_volume_without_project_label_is_allowed(release, monkeypatch):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    monkeypatch.setattr(host, "containers", lambda: [])
    monkeypatch.setattr(host, "command", lambda args: json.dumps([{"Labels": None}]) if args[1] == "volume" else "")
    host.ownership_preflight({"compose_project": "sli", "volumes": {"data": "sli-data"}},
                             {"name": "sli", "volumes": {"data": {"name": "sli-data", "external": True}}})


@pytest.mark.parametrize("bad", ["secret", "empty_secret", "unreadable_secret", "disk", "engine_disk", "tls"])
def test_host_preflight_refuses_missing_resources_without_mutation(release, monkeypatch, tmp_path, bad):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    secret = tmp_path / "synthetic-secret"
    if bad != "secret":
        secret.write_text("" if bad == "empty_secret" else "synthetic-test-value")
    if bad == "unreadable_secret":
        monkeypatch.setattr(update.os, "access", lambda *_: False)
    config = {"services": {name: {"secrets": [{"source": "runtime_password"}]} for name in ("api", "backup", "migrate", *update.INFRA)},
              "secrets": {"runtime_password": {"file": str(secret)}}}
    monkeypatch.setattr(host, "inspect_installation", lambda _: [])
    monkeypatch.setattr(host, "ownership_preflight", lambda *_: None)
    monkeypatch.setattr(host, "containers", lambda: [])
    calls = []
    def compose(args):
        calls.append(args)
        return json.dumps(config if args[0] == "config" else {"free": 10**9 if bad == "engine_disk" else 0})
    monkeypatch.setattr(host, "compose", compose)
    def tls():
        if bad == "tls":
            raise package.PackageError("update_tls_validity_window")
    monkeypatch.setattr(host, "tls_preflight", tls)
    monkeypatch.setattr(host, "observe", lambda: {"engine_free_bytes": 0})
    reason = "required_secret_missing" if "secret" in bad else {
        "disk": "insufficient_backup_disk", "engine_disk": "insufficient_engine_disk", "tls": "tls_validity_window"}[bad]
    with pytest.raises(package.PackageError, match=reason):
        host.preflight({}, release[3])
    assert all(args[0] in {"config", "exec"} for args in calls)


@pytest.mark.parametrize("before,after,valid", [(-60, 600, True), (60, 600, False), (-60, -1, False), (-60, 100, False)])
def test_tls_preflight_checks_current_and_update_validity_window(release, monkeypatch, before, after, valid):
    from cryptography import x509

    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"), timeout=300, tls_min_validity=300)
    now = datetime.now(timezone.utc)
    certificate = SimpleNamespace(not_valid_before_utc=now + timedelta(seconds=before),
                                  not_valid_after_utc=now + timedelta(seconds=after))
    monkeypatch.setattr(x509, "load_der_x509_certificate", lambda _: certificate)
    monkeypatch.setattr(update.socket, "create_connection", lambda *_args, **_kwargs: nullcontext(object()))
    calls = []
    def wrap(connection, server_hostname):
        calls.append(server_hostname)
        return nullcontext(SimpleNamespace(getpeercert=lambda **_: b"synthetic-cert"))
    monkeypatch.setattr(update.ssl, "create_default_context", lambda **_: SimpleNamespace(wrap_socket=wrap))
    if valid:
        host.tls_preflight()
    else:
        with pytest.raises(package.PackageError, match="tls_validity_window"):
            host.tls_preflight()
    assert calls == ["127.0.0.1"]


def test_observation_uses_existing_postgres_and_omits_private_inspect_fields(release, monkeypatch):
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    commands = []
    def compose(args):
        commands.append(args)
        if "psql" in args:
            return json.dumps({"migration_ledger_max": 1, "plugins": []})
        return "Avail\n1000000000\n"
    monkeypatch.setattr(host, "compose", compose)
    monkeypatch.setattr(host, "containers", lambda: [{"Service": "api", "State": "running", "ID": "synthetic-api"}])
    def command(args):
        if args[1] == "inspect":
            return json.dumps([{"Image": "sha256:" + "a" * 64, "Config": {"Image": "sli-running:local", "Env": [PRIVATE_ERROR_MARKER]}}])
        return json.dumps([{"Config": {"Labels": {"org.opencontainers.image.version": "1.0.0"}}}])
    monkeypatch.setattr(host, "command", command)
    observed = host.observe()
    assert observed["services"]["api"]["version"] == "1.0.0"
    assert PRIVATE_ERROR_MARKER not in json.dumps(observed)
    assert all(args[:3] == ["exec", "-T", "postgres"] for args in commands)
    assert "BEGIN READ ONLY" in commands[0][-1]
    monkeypatch.setattr(host, "containers", lambda: [])
    assert host.observe()["services"] == {}


@pytest.mark.parametrize("phase", update.PHASES)
def test_resume_after_durable_phase_completion(release, monkeypatch, phase):
    updater, host, output, _, _, _ = release
    save = updater.save
    armed = True
    def die(journal):
        nonlocal armed
        save(journal)
        if armed and journal["phase"] == phase and phase in journal["completed"]:
            armed = False
            raise PowerLoss()
    monkeypatch.setattr(updater, "save", die)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    journal = package.read_json(updater.journal_path.read_bytes())
    restarted = update.Updater(updater.runtime, updater.trust_store, host)
    assert restarted.resume(operation_id=journal["operation"]) == "committed"
    installed = package.read_json(updater.installed_path.read_bytes())
    assert installed["image_tag"] == host.running_tag
    assert package.read_json(Path(installed["override"]).read_bytes())["services"]["api"]["image"] == host.running_tag


@pytest.mark.parametrize("field,value", [("migration_ledger_max", -1), ("migration_ledger_max", True),
                                         ("plugins", []), ("plugins", {"sli.example": {"enabled": True}})])
def test_signed_preflight_expectations_are_validated(release, field, value):
    resign(release, lambda manifest: manifest["compatibility"].update({field: value}))
    with pytest.raises(package.PackageError):
        verify(release)


def test_committed_operation_is_cli_noop_even_without_original_package(release, monkeypatch, capsys):
    updater, host, output, _, _, _ = release
    operation = "e" * 32
    assert updater.apply(output, operation_id=operation) == "committed"
    output.unlink()
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), list(host.calls)
    monkeypatch.setattr(update, "DockerHost", lambda *_, **kwargs: host)
    assert update.main(["apply", "--package", str(output), "--operation-id", operation, "--json",
        "--runtime", str(updater.runtime), "--trust-store", str(updater.trust_store),
        "--compose", str(host.files[0]), "--ca-file", "synthetic-ca.pem"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "committed" and not result["executed"]
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), host.calls)


def test_archived_committed_operation_is_noop_after_another_operation(release):
    updater, host, output, _, _, _ = release
    operation = "e" * 32
    assert updater.apply(output, operation_id=operation) == "committed"
    output.write_bytes(b"invalid synthetic package")
    with pytest.raises(package.PackageError):
        updater.apply(output, operation_id="f" * 32)
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), list(host.calls)
    assert updater.resume(operation_id=operation) == "committed"
    assert updater.apply(output, operation_id=operation) == "committed"
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), host.calls)


def test_status_before_first_operation_and_during_drain(release, monkeypatch):
    updater, host, output, _, _, _ = release
    assert updater.status()["status"] == "idle"
    step = updater.step
    def die(journal, phase):
        step(journal, phase)
        if phase == "drain":
            raise PowerLoss()
    monkeypatch.setattr(updater, "step", die)
    with pytest.raises(PowerLoss):
        updater.apply(output)
    observe = host.observe
    def stopped():
        value = observe()
        value["services"] = {}
        return value
    monkeypatch.setattr(host, "observe", stopped)
    result = updater.status()
    assert result["phase"] == "drain" and result["status"] == "running"
    assert result["observed_runtime"]["services"] == {}
    assert result["migration_ledger"] == {"max_version": 1}


@pytest.mark.parametrize("bad", ["version", "tag", "digest", "ledger", "missing"])
def test_commit_readback_refuses_mixed_runtime(release, monkeypatch, bad):
    updater, _, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    observed = dict(journal["observed_runtime"])
    observed["services"] = {name: dict(row) for name, row in observed["services"].items()}
    if bad == "ledger":
        observed["migration_ledger_max"] += 1
    elif bad == "missing":
        del observed["services"]["api"]
    else:
        key, value = {"version": ("version", "0.9.0"), "tag": ("image_tag", "foreign:local"),
                      "digest": ("image_digest", "sha256:" + "b" * 64)}[bad]
        observed["services"]["api"][key] = value
    host = update.DockerHost([release[1].files[0]], "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    monkeypatch.setattr(host, "observe", lambda: observed)
    with pytest.raises(package.PackageError, match="runtime_mismatch|migration_ledger_mismatch"):
        host.runtime_matches(journal)


@pytest.mark.parametrize("action,method", [("backup", "checkpoint"), ("check", "check_backup")])
def test_checkpoint_cli_never_logs_raw_private_errors(monkeypatch, capsys, action, method):
    identity = json.dumps({"operation": "a" * 32, "checkpoint_key": "b" * 64})
    monkeypatch.setattr(checkpoint.sys, "argv", ["checkpoint", action, identity])
    def fail(*_):
        raise RuntimeError("synthetic private error")
    monkeypatch.setattr(checkpoint, method, fail)
    assert checkpoint.main() == 1
    result = capsys.readouterr()
    assert result.out == "" and result.err == "update_checkpoint_failed\n"


@pytest.mark.parametrize("attack", ["override_and_hash", "phase_prefix", "foreign_backup"])
def test_unauthenticated_journal_changes_refused_before_docker(release, attack):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = package.read_json(updater.journal_path.read_bytes())
    if attack == "override_and_hash":
        path = Path(journal["previous_override"])
        override = package.read_json(path.read_bytes())
        override["services"]["api"].update(privileged=True, entrypoint="untrusted", volumes=["/:/host"])
        path.write_bytes(package.canonical_json(override))
        journal["previous_override_sha256"] = update.sha256(path)
    elif attack == "phase_prefix":
        journal["completed"] = ["verify", "activate"]
    else:
        journal["backup_id"] = "update-checkpoints/" + "f" * 32 + "/20261006T010000.000000Z"
    update.atomic_json(updater.journal_path, journal)
    host.calls.clear()
    with pytest.raises(package.PackageError, match="journal_authentication_failed"):
        updater.resume(rollback=True)
    assert host.calls == []


def test_override_changed_after_verification_refused_at_activation(release, monkeypatch):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = updater.operation()
    path = Path(journal["candidate_override"])
    path.write_bytes(b'{"services":{"api":{"privileged":true}}}')
    docker = update.DockerHost(host.files, "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    calls = []
    monkeypatch.setattr(docker, "command", lambda args: calls.append(args))
    with pytest.raises(package.PackageError, match="override_changed"):
        docker.activate(journal)
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="Linux ownership and modes")
@pytest.mark.parametrize("attack", ["state_write", "parent_write", "state_link", "journal_link", "journal_hardlink",
                                  "override_link", "override_hardlink", "key_read", "owner"])
def test_unsafe_host_state_refused_before_docker(release, tmp_path, monkeypatch, attack):
    updater, host, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = updater.operation()
    if attack == "state_write":
        updater.state.chmod(0o770)
    elif attack == "parent_write":
        updater.runtime.chmod(0o777)
    elif attack == "state_link":
        target = updater.runtime / "saved-state"
        updater.state.rename(target)
        updater.state.symlink_to(target, target_is_directory=True)
    elif attack == "key_read":
        (updater.state / "update-journal.key").chmod(0o644)
    elif attack == "owner":
        uid = os.geteuid()
        monkeypatch.setattr(update.os, "geteuid", lambda: uid + 1)
    else:
        path = updater.journal_path if attack.startswith("journal") else Path(journal["previous_override"])
        target = tmp_path / "linked-record"
        path.rename(target)
        if attack.endswith("hardlink"):
            os.link(target, path)
        else:
            path.symlink_to(target)
    host.calls.clear()
    with pytest.raises(package.PackageError, match="unsafe_state"):
        updater.resume(rollback=True)
    assert host.calls == []


@pytest.mark.skipif(os.name == "nt", reason="Linux checkpoint descriptors")
@pytest.mark.parametrize("attack", ["foreign_operation", "manifest", "dump", "missing_chunk", "extra_chunk",
                                  "nested_link", "hardlink", "parent_link"])
def test_checkpoint_attacks_refused_before_superuser_restore(tmp_path, monkeypatch, attack):
    identifier = "update-checkpoints/" + "a" * 32 + "/20261006T010000.000000Z"
    path = tmp_path / identifier
    (path / "postgres").mkdir(parents=True)
    (path / "postgres/toc.dat").write_bytes(b"fake-toc")
    chunk = path / "postgres/1.dat"
    chunk.write_bytes(b"original")
    manifest_path = path / "manifest.json"
    manifest_path.write_bytes(package.canonical_json({"status": "success", "backup_id": path.name,
        "components": {"postgres": {"row_counts": {"schema_migrations": 1}}}, "migration_ledger_max_version": 1}))
    identity = seal_checkpoint(tmp_path, identifier)
    if attack == "foreign_operation":
        identity["operation"] = "b" * 32
    elif attack == "manifest":
        manifest = json.loads(manifest_path.read_bytes())
        manifest["migration_ledger_max_version"] = 2
        manifest_path.write_bytes(package.canonical_json(manifest))
    elif attack == "dump":
        chunk.write_bytes(b"tampered")  # Same size and unchanged row counts/ledger.
    elif attack == "missing_chunk":
        chunk.unlink()
    elif attack == "extra_chunk":
        (path / "postgres/2.dat").write_bytes(b"extra")
    elif attack == "parent_link":
        parent = path.parent
        target = tmp_path / "moved-checkpoints"
        parent.rename(target)
        parent.symlink_to(target, target_is_directory=True)
    else:
        target = tmp_path / "replacement"
        chunk.rename(target)
        if attack == "hardlink":
            os.link(target, chunk)
        else:
            chunk.symlink_to(target)
    calls = []
    monkeypatch.setattr(checkpoint.backup, "backup_lock", lambda *_: nullcontext())
    monkeypatch.setattr(checkpoint.backup, "pg_passfile", lambda: calls.append("credentials"))
    monkeypatch.setattr(checkpoint.backup, "pg_connect", lambda *_args, **_kwargs: calls.append("connect"))
    monkeypatch.setattr(checkpoint.backup, "pg_tool", lambda *_: calls.append("pg_restore"))
    with pytest.raises((ValueError, OSError), match="checkpoint|symbolic|directory"):
        checkpoint.restore(tmp_path, **identity)
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="Linux checkpoint descriptors")
def test_restore_uses_verified_snapshot_despite_shared_dump_replacement(tmp_path, monkeypatch):
    identifier = "update-checkpoints/" + "a" * 32 + "/20261006T010000.000000Z"
    path = tmp_path / identifier
    (path / "postgres").mkdir(parents=True)
    (path / "postgres/toc.dat").write_bytes(b"original")
    (path / "manifest.json").write_bytes(package.canonical_json({"status": "success", "backup_id": path.name,
        "components": {"postgres": {"row_counts": {"schema_migrations": 1}}}, "migration_ledger_max_version": 1}))
    identity = seal_checkpoint(tmp_path, identifier)
    class Connection:
        def execute(self, _statement):
            (path / "postgres/toc.dat").write_bytes(b"tampered")
            return self
        def fetchone(self):
            return (1,)
    def pg_tool(args, _passfile):
        restored = Path(args[-1])
        assert restored != path / "postgres"
        assert restored.joinpath("toc.dat").read_bytes() == b"original"
        assert restored.parent.stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(checkpoint.backup, "backup_lock", lambda *_: nullcontext())
    monkeypatch.setattr(checkpoint.backup, "pg_passfile", lambda: nullcontext(Path("passfile")))
    monkeypatch.setattr(checkpoint.backup, "pg_connect", lambda *_args, **_kwargs: nullcontext(Connection()))
    monkeypatch.setattr(checkpoint.backup, "pg_tool", pg_tool)
    monkeypatch.setattr(checkpoint.backup, "row_counts", lambda _: {"schema_migrations": 1})
    checkpoint.restore(tmp_path, **identity)


@pytest.mark.skipif(os.name == "nt", reason="Linux checkpoint descriptors")
def test_preseeded_checkpoint_cannot_be_adopted_by_new_operation(tmp_path, monkeypatch):
    identifier = "update-checkpoints/" + "a" * 32 + "/20261006T010000.000000Z"
    path = tmp_path / identifier
    (path / "postgres").mkdir(parents=True)
    (path / "postgres/toc.dat").write_bytes(b"fake")
    (path / "manifest.json").write_bytes(package.canonical_json({"status": "success", "backup_id": path.name}))
    seal_checkpoint(tmp_path, identifier)  # Valid receipt for a different operation key.
    monkeypatch.setattr(checkpoint.backup, "backup_lock", lambda *_: nullcontext())
    calls = []
    monkeypatch.setattr(checkpoint.backup, "run_backup", lambda *_args, **_kwargs: calls.append("backup"))
    with pytest.raises(ValueError, match="invalid_checkpoint"):
        checkpoint.checkpoint(tmp_path, "a" * 32, "c" * 64)
    assert calls == []


@pytest.mark.skipif(os.name == "nt", reason="Linux helper bind permissions")
def test_helper_receives_bound_identity_and_private_disk_mount(release, monkeypatch):
    updater, fake, output, _, _, _ = release
    assert updater.apply(output) == "committed"
    journal = updater.operation()
    host = update.DockerHost(fake.files, "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    monkeypatch.setattr(host, "stop_operation", lambda _: None)
    owners = []
    if os.name != "nt":
        monkeypatch.setattr(update.os, "chown", lambda path, uid, gid: owners.append((uid, gid)))
    calls = []
    def compose(args, override, stdin=None):
        calls.append(args)
        assert override == journal["previous_override"] and b"update_checkpoint" in stdin
        assert args[0] == "run" and "--pull" not in args
        source, destination = args[args.index("--volume") + 1].rsplit(":", 1)
        assert destination == "/update-snapshot"
        assert Path(source).is_relative_to(journal["directory"])
        assert Path(source).stat().st_mode & 0o077 == 0
        identity = json.loads(args[-1])
        assert identity["operation"] == journal["operation"]
        assert identity["checkpoint_key"] == journal["checkpoint_key"]
        if args[-2] == "restore":
            assert identity["backup_id"] == journal["backup_id"]
            assert identity["checkpoint_sha256"] == journal["checkpoint_sha256"]
        return json.dumps({"backup_id": journal["backup_id"], "checkpoint_sha256": journal["checkpoint_sha256"]})
    monkeypatch.setattr(host, "compose", compose)
    assert host.checkpoint(journal)["checkpoint_sha256"] == journal["checkpoint_sha256"]
    host.restore(journal)
    assert len(calls) == 2
    if os.name != "nt":
        assert owners == [(10001, 10001), (10001, 10001)]


@pytest.mark.parametrize("alias", ["opt//sli/config/postgres_migrations/001_example.sql",
                                   "opt/sli/./config/postgres_migrations/001_example.sql",
                                   "././opt/sli/config/postgres_migrations/001_example.sql",
                                   "./opt/sli/config/postgres_migrations/001_example.sql",
                                   "opt//sli/config/.wh.postgres_migrations"])
@pytest.mark.parametrize("kind", ["file", "symlink", "hardlink"])
def test_layer_path_aliases_refused_by_verifier_and_builder(release, tmp_path, alias, kind):
    root = release[5]
    entry = b"SELECT 2;"
    if kind != "file":
        entry = tarfile.TarInfo(alias)
        entry.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        entry.linkname = "untrusted"
    image, migrations = make_image(root / "image.tar", extra={alias: entry})
    manifest = {**release[3], "image": image, "migrations": migrations}
    with pytest.raises(package.PackageError, match="unsafe_path"):
        update.image_inventory(root / "image.tar", manifest, tmp_path / "clean.tar")
    draft = tmp_path / "alias-manifest.json"
    draft.write_bytes(package.canonical_json(manifest))
    with pytest.raises(package.PackageError, match="unsafe_path"):
        build(draft, root, tmp_path / "offline.key", tmp_path / "alias.zip", key_id="test-only")
    assert not (tmp_path / "alias.zip").exists()


@pytest.mark.parametrize("limit", ["layer_bytes", "total_bytes", "ratio", "entries", "layers", "outer_directories"])
def test_image_expansion_and_entry_budgets_refuse_before_docker_load(release, tmp_path, monkeypatch, limit):
    import gzip

    image_path = release[5] / "image.tar"
    manifest = release[3]
    limits = package.ImageLimits()
    if limit == "entries":
        extra = {}
        for index in range(8):
            entry = tarfile.TarInfo(f"directory-{index}")
            entry.type = tarfile.DIRTYPE
            extra[entry.name] = entry
        image, migrations = make_image(image_path, extra=extra)
        manifest = {**manifest, "image": image, "migrations": migrations}
        limits = replace(limits, max_entries=8)
    files = contents(image_path)
    files["layer.tar"] = gzip.compress(files["layer.tar"])
    if limit == "outer_directories":
        for index in range(8):
            entry = tarfile.TarInfo(f"outer-{index}")
            entry.type = tarfile.DIRTYPE
            files[entry.name] = entry
        limits = replace(limits, max_entries=4)
    elif limit == "layer_bytes":
        limits = replace(limits, max_layer_bytes=100)
    elif limit == "total_bytes":
        limits = replace(limits, max_total_bytes=100)
    elif limit == "ratio":
        limits = replace(limits, max_ratio=1)
    elif limit == "layers":
        limits = replace(limits, max_layers=0)
    write_tar(image_path, files)
    inspect = update.image_inventory
    monkeypatch.setattr(update, "image_inventory", lambda source, metadata, target: inspect(source, metadata, target, limits=limits))
    host = update.DockerHost(release[1].files, "https://127.0.0.1:8443/api/health/ready", Path("ca.pem"))
    calls = []
    monkeypatch.setattr(host, "command", lambda args: calls.append(args))
    with pytest.raises(package.PackageError, match="expansion_limit|entry_limit|inventory_invalid"):
        host.stage(release[5], manifest, "sli-update:candidate-test")
    assert calls == []

# Storage identity regressions use real updater/ownership code with read-only Docker fakes.
def retained_volume_overlay(release, monkeypatch):
    updater, host, *_ = release
    keys = ("postgres-data", "sli-data", "storage-evidence", "history-data", "history-backups", "warm-data")
    definitions = {key: {"name": "sli_" + key, "external": False,
                         "driver": "local", "driver_opts": {"opaque": "preserve-" + key}} for key in keys}
    base = {"name": "sli", "volumes": {key: {"name": "default-" + key, "external": True} for key in keys},
            "services": {}}
    update.atomic_json(host.files[0], base)
    target = updater.state / "install-compose.json"
    update.atomic_json(target, {"volumes": definitions, "services": {
        "api": {"labels": {"preserved": "yes"}, "volumes": [
            {"type": "bind", "source": "/fixture/operator", "target": "/operator", "read_only": True}]},
        "backup": {"environment": {"OPERATOR_SETTING": "preserved"}},
        "postgres": {"image": "postgres:pinned"},
        "notification-delivery": {"image": "retained-notification"}}})
    host.files.append(target)
    installed = package.read_json(updater.installed_path.read_bytes())
    prior = updater.state / "partial-candidate.json"
    update.atomic_json(prior, {"services": {"api": {"image": installed["image_tag"], "volumes": [
        {"type": "bind", "source": "/fixture/control", "target": "/run/notification-setup", "read_only": True}]},
                                         "backup": {"environment": {"SLI_BACKUP_RETENTION": "9"}}}})
    installed.update(volumes={key: value["name"] for key, value in definitions.items()}, override=str(prior))
    update.atomic_json(updater.installed_path, installed)
    host.installed = installed
    docker_calls = []

    def merge(left, right):
        result = copy.deepcopy(left)
        for key, value in right.items():
            result[key] = merge(result[key], value) if isinstance(value, dict) and isinstance(result.get(key), dict) else copy.deepcopy(value)
        return result

    def configuration(replacement=None):
        result = {}
        for path in host.files:
            result = merge(result, package.read_json(Path((replacement or {}).get(str(path), path)).read_bytes()))
        return result

    def command(args, **kwargs):
        docker_calls.append(args)
        if args[:3] == ["docker", "volume", "inspect"]:
            labels = {"com.docker.compose.project": "sli"}
            return json.dumps(labels if "--format" in args else [{"Labels": labels}])
        if args[:3] == ["docker", "ps", "-aq"]:
            return "owned-consumer"
        if args[:2] == ["docker", "inspect"]:
            return json.dumps({"com.docker.compose.project": "sli"})
        pytest.fail("Unexpected Docker mutation or non-metadata call: " + repr(args))

    monkeypatch.setattr(host, "configuration", configuration, raising=False)
    monkeypatch.setattr(host, "deployment_fingerprint", lambda replacement=None: hashlib.sha256(
        package.canonical_json(configuration(replacement))).hexdigest())
    monkeypatch.setattr(host, "command", command, raising=False)
    monkeypatch.setattr(host, "containers", lambda: [], raising=False)
    ownership = update.DockerHost.ownership_preflight
    monkeypatch.setattr(host, "ownership_preflight", lambda installed, config: ownership(
        host, installed, config), raising=False)
    preflight = host.preflight

    def checked_preflight(installed, manifest):
        host.ownership_preflight(installed, configuration())
        return preflight(installed, manifest)

    monkeypatch.setattr(host, "preflight", checked_preflight)
    return target, definitions, docker_calls


@pytest.mark.parametrize("rollback", [False, True])
def test_retained_volume_overlay_survives_notification_publish_and_next_update(release, monkeypatch, rollback):
    updater, host, archive, manifest, key, payload = release
    target, definitions, calls = retained_volume_overlay(release, monkeypatch)
    if rollback:
        host.fail = "health"
    assert updater.apply(archive) == ("rolled_back" if rollback else "committed")
    first = updater.read_journal(updater.journal_path)
    for name in ("previous_override", "candidate_override"):
        saved = package.read_json(Path(first[name]).read_bytes())
        assert saved["volumes"] == definitions
        assert saved["services"]["postgres"]["image"] == "postgres:pinned"
        assert saved["services"]["backup"]["environment"] == {"OPERATOR_SETTING": "preserved", "SLI_BACKUP_RETENTION": "9"}
        assert {mount["target"] for mount in saved["services"]["api"]["volumes"]} == {"/operator", "/run/notification-setup"}
    assert package.read_json(target.read_bytes())["volumes"] == definitions
    assert package.read_json(target.read_bytes())["services"]["api"]["labels"] == {"preserved": "yes"}
    assert first["notification_compose_switch"]["after"] == update.sha256(target)
    assert first["notification_compose_switch"]["acknowledged"]
    if not rollback:
        installed = package.read_json(updater.installed_path.read_bytes())
        host.installed, host.active = installed, "previous"
        image, migrations = make_image(payload / "image.tar", label="1.2.0")
        draft = copy.deepcopy(manifest)
        draft.update(version="1.2.0", to_version="1.2.0", from_version="1.1.0", image=image, migrations=migrations)
        draft["compatibility"].update(from_version="1.1.0", min_version="1.1.0", max_version="1.1.0")
        (updater.runtime.parent / "VERSION").write_text("1.2.0\n")
        draft_path = updater.runtime.parent / "next-manifest.json"
        draft_path.write_bytes(package.canonical_json(draft))
        next_archive = updater.runtime.parent / "next-update.zip"
        build(draft_path, payload, updater.runtime.parent / "offline.key", next_archive, key_id="test-only")
        assert updater.apply(next_archive) == "committed"
        assert package.read_json(target.read_bytes())["volumes"] == definitions
        host.ownership_preflight(package.read_json(updater.installed_path.read_bytes()), host.configuration())
    assert calls and all(args[1] in {"volume", "inspect", "ps"} for args in calls)


def broken_notification_overlay(release, monkeypatch):
    updater, host, archive, *_ = release
    # Establish a real authenticated completed operation, then model the historic
    # services-only publication and its exact signed switch evidence.
    assert updater.apply(archive) == "committed"
    journal = updater.read_journal(updater.journal_path)
    target, definitions, calls = retained_volume_overlay(release, monkeypatch)
    journal["previous"]["volumes"] = {key: value["name"] for key, value in definitions.items()}
    partial = {"services": {"api": {"image": journal["candidate_tag"]},
                             "notification-delivery": {"image": journal["candidate_tag"]}}}
    update.atomic_json(Path(journal["candidate_override"]), partial)
    journal["candidate_override_sha256"] = update.sha256(journal["candidate_override"])
    update.atomic_json(target, partial)
    journal["compose_files"] = {str(path): update.sha256(path) for path in host.files}
    journal["notification_compose_switch"] = {"path": str(target), "before": "1" * 64,
        "after": update.sha256(target), "fingerprint": host.deployment_fingerprint(), "acknowledged": True}
    journal["deployment_fingerprint"] = host.deployment_fingerprint()
    installed = updater.candidate(journal)
    update.atomic_json(updater.installed_path, installed)
    host.installed, host.active, host.running_tag = installed, "previous", installed["image_tag"]
    updater.save(journal)
    updater.save(journal, path=Path(journal["directory"]) / "journal.json")
    return journal, target, definitions, calls


def test_volume_reconciliation_is_metadata_only_authenticated_and_idempotent(release, monkeypatch):
    updater, host, *_ = release
    journal, target, definitions, calls = broken_notification_overlay(release, monkeypatch)
    before, installed_before = target.read_bytes(), updater.installed_path.read_bytes()
    latest_before = updater.journal_path.read_bytes()
    assert updater.reconcile_volumes(journal["operation"], dry_run=True) == "dry_run"
    assert target.read_bytes() == before
    assert not (updater.state / "volume-reconciliation.json").exists()
    assert updater.reconcile_volumes(journal["operation"]) == "reconciled"
    expected = {key: {"name": value["name"], "external": True} for key, value in definitions.items()}
    assert package.read_json(target.read_bytes())["volumes"] == expected
    intent = updater.read_journal(updater.state / "volume-reconciliation.json")
    assert base64.b64decode(intent["before_bytes"]) == before
    assert intent["before"] == hashlib.sha256(before).hexdigest()
    assert intent["after"] == update.sha256(target) and intent["status"] == "committed"
    first = target.read_bytes()
    assert updater.reconcile_volumes(journal["operation"]) == "reconciled"
    assert target.read_bytes() == first and updater.installed_path.read_bytes() == installed_before
    assert updater.journal_path.read_bytes() == latest_before
    host.ownership_preflight(host.installed, host.configuration())
    assert all(args[1] in {"volume", "inspect", "ps"} for args in calls)


@pytest.mark.parametrize("bad", ["unacknowledged", "uncommitted", "candidate", "inventory", "base", "target", "keys", "duplicate", "foreign", "unlabelled", "consumer", "missing", "active", "signature"])
def test_volume_reconciliation_rejects_unattested_or_foreign_state(release, monkeypatch, bad):
    updater, host, *_ = release
    journal, target, _, calls = broken_notification_overlay(release, monkeypatch)
    before = target.read_bytes()
    if bad in {"unacknowledged", "uncommitted", "keys", "duplicate"}:
        if bad == "unacknowledged":
            journal["notification_compose_switch"]["acknowledged"] = False
        elif bad == "uncommitted":
            journal["status"] = "rolled_back"
        elif bad == "keys":
            journal["previous"]["volumes"].pop("warm-data")
        else:
            journal["previous"]["volumes"]["warm-data"] = journal["previous"]["volumes"]["history-data"]
        updater.save(journal, path=Path(journal["directory"]) / "journal.json")
    elif bad == "candidate":
        Path(journal["candidate_override"]).write_bytes(b"{}")
    elif bad == "inventory":
        changed = dict(host.installed, source_commit="f" * 40)
        update.atomic_json(updater.installed_path, changed)
    elif bad == "base":
        update.atomic_json(host.files[0], {"name": "sli", "volumes": {}})
    elif bad == "target":
        target.write_bytes(before + b" ")
        before = target.read_bytes()
    elif bad == "active":
        updater.save(dict(journal, status="running"))
    elif bad == "signature":
        raw = package.read_json((Path(journal["directory"]) / "journal.json").read_bytes())
        raw["authentication"] = "0" * 64
        update.atomic_json(Path(journal["directory"]) / "journal.json", raw)
    else:
        command = host.command

        def wrong_owner(args, **kwargs):
            if bad == "missing" and args[:3] == ["docker", "volume", "inspect"]:
                raise update.UpdateError("update_docker_failed")
            if bad in {"foreign", "unlabelled"} and args[:3] == ["docker", "volume", "inspect"]:
                labels = {} if bad == "unlabelled" else {"com.docker.compose.project": "foreign"}
                return json.dumps(labels if "--format" in args else [{"Labels": labels}])
            if bad == "consumer" and args[:2] == ["docker", "inspect"]:
                return json.dumps({"com.docker.compose.project": "foreign"})
            return command(args, **kwargs)

        monkeypatch.setattr(host, "command", wrong_owner)
    with pytest.raises(update.UpdateError):
        updater.reconcile_volumes(journal["operation"])
    assert target.read_bytes() == before
    assert not (updater.state / "volume-reconciliation.json").exists()
    assert all(args[1] in {"volume", "inspect", "ps"} for args in calls)


@pytest.mark.parametrize("crash", ["intent", "replace", "ack"])
def test_volume_reconciliation_resumes_only_exact_durable_before_after(release, monkeypatch, crash):
    updater, _, *_ = release
    journal, target, _, _ = broken_notification_overlay(release, monkeypatch)
    atomic, save = update.atomic_json, updater.save
    armed = [True]

    def die_write(path, value):
        atomic(path, value)
        if armed[0] and crash == "replace" and Path(path) == target:
            armed[0] = False
            raise PowerLoss()

    def die_save(value, *, path=None):
        if path == updater.state / "volume-reconciliation.json" and armed[0] and crash == "ack" and value["status"] == "committed":
            armed[0] = False
            raise PowerLoss()
        save(value, path=path)
        if path == updater.state / "volume-reconciliation.json" and armed[0] and crash == "intent":
            armed[0] = False
            raise PowerLoss()

    monkeypatch.setattr(update, "atomic_json", die_write)
    monkeypatch.setattr(updater, "save", die_save)
    with pytest.raises(PowerLoss):
        updater.reconcile_volumes(journal["operation"])
    assert updater.reconcile_volumes(journal["operation"]) == "reconciled"
    intent = updater.read_journal(updater.state / "volume-reconciliation.json")
    assert intent["status"] == "committed" and update.sha256(target) == intent["after"]


def test_volume_reconciliation_resume_refuses_edit_after_intent(release, monkeypatch):
    updater, _, *_ = release
    journal, target, _, _ = broken_notification_overlay(release, monkeypatch)
    save = updater.save

    def die(value, *, path=None):
        save(value, path=path)
        if path == updater.state / "volume-reconciliation.json":
            raise PowerLoss()

    monkeypatch.setattr(updater, "save", die)
    with pytest.raises(PowerLoss):
        updater.reconcile_volumes(journal["operation"])
    target.write_bytes(target.read_bytes() + b" ")
    changed = target.read_bytes()
    with pytest.raises(update.UpdateError):
        updater.reconcile_volumes(journal["operation"])
    assert target.read_bytes() == changed


@pytest.mark.parametrize("crash", ["intent", "replace", "ack"])
def test_notification_volume_publication_crash_resumes_with_exact_overlay(release, monkeypatch, crash):
    updater, _, archive, *_ = release
    target, definitions, _ = retained_volume_overlay(release, monkeypatch)
    save, atomic = updater.save, update.atomic_json
    armed = [True]

    def die_save(journal, *, path=None):
        switch = journal.get("notification_compose_switch") or {}
        if armed[0] and crash == "ack" and switch.get("acknowledged"):
            armed[0] = False
            raise PowerLoss()
        save(journal, path=path)
        if armed[0] and crash == "intent" and switch:
            armed[0] = False
            raise PowerLoss()

    def die_write(path, value):
        atomic(path, value)
        if armed[0] and crash == "replace" and Path(path) == target:
            armed[0] = False
            raise PowerLoss()

    monkeypatch.setattr(updater, "save", die_save)
    monkeypatch.setattr(update, "atomic_json", die_write)
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    assert updater.resume() == "committed"
    final = updater.read_journal(updater.journal_path)
    assert final["notification_compose_switch"]["acknowledged"]
    assert update.sha256(target) == final["notification_compose_switch"]["after"]
    assert package.read_json(target.read_bytes())["volumes"] == definitions


@pytest.mark.parametrize("changed", ["target", "base"])
def test_notification_volume_publication_crash_rejects_arbitrary_edit(release, monkeypatch, changed):
    updater, host, archive, *_ = release
    target, _, _ = retained_volume_overlay(release, monkeypatch)
    atomic = update.atomic_json

    def die_write(path, value):
        atomic(path, value)
        if Path(path) == target:
            raise PowerLoss()

    monkeypatch.setattr(update, "atomic_json", die_write)
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    modified = target if changed == "target" else host.files[0]
    modified.write_bytes(modified.read_bytes() + b" ")
    with pytest.raises(update.UpdateError, match="update_compose_changed|update_configuration_changed"):
        updater.resume()


def test_volume_reconciliation_cli_uses_terminal_reject_and_normal_operation_lock(release, monkeypatch, capsys):
    updater, host, *_ = release
    journal, target, _, _ = broken_notification_overlay(release, monkeypatch)
    updater.save({"operation": "e" * 32, "status": "rejected", "phase": "verify",
                  "reason": "update_volume_ownership", "migration_started": False, "previous": host.installed})
    lock = update.operation_lock
    locks = []

    def observed_lock(state):
        locks.append(state)
        return lock(state)

    monkeypatch.setattr(update, "operation_lock", observed_lock)
    monkeypatch.setattr(update, "DockerHost", lambda *_, **__: host)
    args = ["reconcile-volumes", "--operation-id", journal["operation"], "--runtime", str(updater.runtime), "--json"]
    for path in host.files:
        args.extend(["--compose", str(path)])
    before = target.read_bytes()
    assert update.main([*args, "--dry-run"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "dry_run"
    assert target.read_bytes() == before
    assert update.main(args) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "reconciled", "installed": False, "executed": False}
    assert locks == [updater.state, updater.state]
    assert update.main([*args[:2], "../untrusted", *args[3:]]) == 1
    assert json.loads(capsys.readouterr().out)["reason_code"] == "update_invalid_operation"


def test_pending_volume_intent_fences_normal_update_until_reconciliation_ack(release, monkeypatch):
    updater, _, archive, *_ = release
    journal, _, _, _ = broken_notification_overlay(release, monkeypatch)
    save = updater.save

    def die(value, *, path=None):
        save(value, path=path)
        if path == updater.state / "volume-reconciliation.json":
            raise PowerLoss()

    monkeypatch.setattr(updater, "save", die)
    with pytest.raises(PowerLoss):
        updater.reconcile_volumes(journal["operation"])
    with pytest.raises(update.UpdateError, match="update_volume_reconciliation_required"):
        updater.apply(archive)


def test_volume_overlay_publication_rollback_removes_added_notification_services(release, monkeypatch):
    updater, _, archive, *_ = release
    target, definitions, _ = retained_volume_overlay(release, monkeypatch)
    assert updater.apply(archive) == "committed"
    journal = updater.read_journal(updater.journal_path)
    previous_path = Path(journal["previous_override"])
    previous = package.read_json(previous_path.read_bytes())
    previous["services"].pop("notification-delivery")
    update.atomic_json(previous_path, previous)
    journal["previous_override_sha256"] = update.sha256(previous_path)
    updater.sync_notification_compose(journal, previous=True)
    restored = package.read_json(target.read_bytes())
    assert "notification-delivery" not in restored["services"]
    assert restored["volumes"] == definitions


@pytest.mark.parametrize("field,value", [("source", "/other"), ("type", "volume"), ("read_only", False)])
def test_complete_overlay_refuses_operator_mount_conflict(field, value):
    mount = {"type": "bind", "source": "/operator", "target": "/operator", "read_only": True}
    current = {"services": {"api": {"volumes": [mount]}}}
    prior = {"services": {"api": {"volumes": [dict(mount, **{field: value})]}}}
    with pytest.raises(update.UpdateError, match="update_overlay_conflict"):
        update.complete_overlay(current, prior)


def test_complete_overlay_replaces_only_bounded_managed_mount_and_secret():
    old = {"type": "bind", "source": "/old", "target": "/run/notification-setup", "read_only": False,
           "bind": {"propagation": "rprivate"}}
    new = {"type": "bind", "source": "/new", "target": "/run/notification-setup", "read_only": True}
    current = {"services": {"api": {"volumes": [old]}, "migrate": {"secrets": [
        {"source": "notification_db_password", "target": "old-control-secret", "mode": 256}]}}}
    prior = {"services": {"api": {"volumes": [new]}, "migrate": {"secrets": ["notification_db_password"]}}}
    merged = update.complete_overlay(current, prior)
    assert merged["services"]["api"]["volumes"] == [new]
    assert merged["services"]["migrate"]["secrets"] == ["notification_db_password"]


def test_two_signed_updates_preserve_current_operator_edit_without_changing_prior(release, monkeypatch):
    updater, host, archive, manifest, _, payload = release
    target, definitions, _ = retained_volume_overlay(release, monkeypatch)
    first_command = ["postgres", "-c", "max_wal_size=4GB", "-c", "checkpoint_timeout=15min",
                     "-c", "checkpoint_completion_target=0.9"]
    initial = package.read_json(target.read_bytes())
    initial["services"]["postgres"]["command"] = first_command
    update.atomic_json(target, initial)
    assert updater.apply(archive) == "committed"
    installed = package.read_json(updater.installed_path.read_bytes())
    prior = Path(installed["override"])
    sealed = prior.read_bytes()
    current = package.read_json(target.read_bytes())
    assert current["services"]["postgres"]["command"] == first_command
    operator_command = ["postgres", "-c", "max_wal_size=6GB", "-c", "checkpoint_timeout=10min",
                        "-c", "checkpoint_completion_target=0.8", "-c", "log_checkpoints=on"]
    current["services"]["postgres"]["command"] = operator_command
    current["services"]["backup"]["environment"]["OPERATOR_SETTING"] = "operator-new"
    update.atomic_json(target, current)
    host.installed, host.active = installed, "previous"
    image, migrations = make_image(payload / "image.tar", label="1.2.0")
    draft = copy.deepcopy(manifest)
    draft.update(version="1.2.0", to_version="1.2.0", from_version="1.1.0", image=image, migrations=migrations)
    draft["compatibility"].update(from_version="1.1.0", min_version="1.1.0", max_version="1.1.0")
    (updater.runtime.parent / "VERSION").write_text("1.2.0\n")
    draft_path = updater.runtime.parent / "operator-edit-manifest.json"
    draft_path.write_bytes(package.canonical_json(draft))
    signed = updater.runtime.parent / "operator-edit-update.zip"
    build(draft_path, payload, updater.runtime.parent / "offline.key", signed, key_id="test-only")
    assert updater.apply(signed) == "committed"
    assert prior.read_bytes() == sealed
    final = package.read_json(target.read_bytes())
    second = updater.operation()
    previous = package.read_json(Path(second["previous_override"]).read_bytes())
    assert final["volumes"] == definitions and previous["volumes"] == definitions
    assert (previous["services"]["backup"]["environment"]["OPERATOR_SETTING"],
            final["services"]["backup"]["environment"]["OPERATOR_SETTING"]) == ("operator-new", "operator-new")

    assert previous["services"]["postgres"]["command"] == operator_command
    assert final["services"]["postgres"]["command"] == operator_command
    # Exercise the real activation path, replacing only the Docker boundary.
    docker = update.DockerHost(host.files, "https://example.invalid/api/health/ready", None)
    commands = []
    monkeypatch.setattr(docker, "image_id", lambda _: second["manifest"]["image"]["digest"])
    monkeypatch.setattr(docker, "command", lambda args, **kwargs: commands.append(args))
    docker.activate(second)
    assert len(commands) == 1
    activation = commands[0][commands[0].index("up"):]
    assert activation == ["up", "-d", "--no-deps", "--no-build", "--pull", "never", *sorted(second["services"])]
    assert not {"postgres", "clickhouse", "warm-tier"} & set(activation)


@pytest.mark.parametrize("interrupt", [False, True])
@pytest.mark.parametrize("notifications", [False, True])
def test_rollback_removes_new_backup_delta_before_activation_and_publication(release, monkeypatch, interrupt, notifications):
    updater, host, _, manifest, _, payload = release
    target, definitions, _ = retained_volume_overlay(release, monkeypatch)
    if not notifications:
        current = package.read_json(target.read_bytes())
        current["services"].pop("notification-delivery")
        update.atomic_json(target, current)
    (payload / "delta.json").write_bytes(package.canonical_json({"backup": {"SLI_BACKUP_TIME": "23:59"}}))
    draft = copy.deepcopy(manifest)
    draft["config_delta"] = "delta.json"
    draft["files"].append({"path": "delta.json"})
    draft_path = updater.runtime.parent / "new-backup-delta-manifest.json"
    draft_path.write_bytes(package.canonical_json(draft))
    signed = updater.runtime.parent / "new-backup-delta.zip"
    build(draft_path, payload, updater.runtime.parent / "offline.key", signed, key_id="test-only")
    assert updater.apply(signed) == "committed"
    journal = updater.operation()
    previous_path = Path(journal["previous_override"])
    previous = package.read_json(previous_path.read_bytes())
    assert "SLI_BACKUP_TIME" not in previous["services"]["backup"].get("environment", {})
    assert package.read_json(target.read_bytes())["services"]["backup"]["environment"]["SLI_BACKUP_TIME"] == "23:59"
    activate = host.activate
    effective_activation = []
    armed = [interrupt]

    def observe_activation(value, previous=False):
        if previous:
            if armed[0]:
                armed[0] = False
                raise PowerLoss()
            # Model Compose's actual environment-map merge: an absent key in
            # previous_override cannot remove one from the current installation.
            effective = copy.deepcopy(host.configuration()["services"]["backup"].get("environment", {}))
            override = package.read_json(Path(value["previous_override"]).read_bytes())
            effective.update(override["services"]["backup"].get("environment", {}))
            effective_activation.append(effective)
        activate(value, previous=previous)

    monkeypatch.setattr(host, "activate", observe_activation)
    if interrupt:
        with pytest.raises(PowerLoss):
            updater.resume(rollback=True)
        assert updater.resume() == "rolled_back"
    else:
        assert updater.resume(rollback=True) == "rolled_back"
    published = package.read_json(target.read_bytes())
    assert published["volumes"] == definitions
    assert effective_activation and effective_activation[-1]["OPERATOR_SETTING"] == "preserved"
    assert ("SLI_BACKUP_TIME" in effective_activation[-1],
            "SLI_BACKUP_TIME" in published["services"]["backup"].get("environment", {})) == (False, False)


def complete_snapshot_host(tmp_path):
    runtime = tmp_path / "runtime"
    base, installation, operator = runtime / "compose/compose.json", runtime / "state/install-compose.json", runtime / "operator.json"
    directory = runtime / "state/updates" / ("1" * 32)
    snapshot = directory / "previous.json"
    for path, value in ((base, {"services": {"api": {"image": "base"}}}),
                        (installation, {"services": {"api": {"security_opt": ["no-new-privileges:true"]}}}),
                        (operator, {"services": {"api": {"environment": {"OPERATOR": "preserved"}}}}),
                        (snapshot, {"services": {"api": {"security_opt": ["no-new-privileges:true"], "image": "previous"}}})):
        update.atomic_json(path, value)
    host = update.DockerHost([base, installation, operator], "https://example.invalid/api/health/ready", None)
    journal = {"operation": "1" * 32, "directory": str(directory),
               "compose_files": {str(path): update.sha256(path) for path in host.files},
               "previous_override": str(snapshot), "previous_override_sha256": update.sha256(snapshot),
               "compose_snapshot": {"mode": "replace-installation-v1", "path": str(installation)}}
    return host, journal, (base, installation, operator), snapshot


def test_complete_snapshot_replaces_bound_layer_once_in_original_order(tmp_path, monkeypatch):
    host, journal, (base, installation, operator), snapshot = complete_snapshot_host(tmp_path)
    commands = []
    monkeypatch.setattr(host, "command", lambda args, **kwargs: commands.append(args) or "{}")
    override = host.operation_override(journal, "previous_override")
    host.compose(["run", "--rm", "--no-deps", "backup"], override)
    host.configuration({str(installation): snapshot})
    for command in commands:
        files = [command[index + 1] for index, value in enumerate(command) if value == "-f"]
        assert files == [str(base), str(snapshot), str(operator)]
        assert str(installation) not in files and files.count(str(snapshot)) == 1
    assert package.read_json(snapshot.read_bytes())["services"]["api"]["security_opt"] == ["no-new-privileges:true"]


@pytest.mark.parametrize("attack", ["unknown_mode", "null_mode", "wrong_target", "missing_target", "duplicate_layer",
                                  "changed_snapshot", "changed_installation", "unrecorded_installation"])
def test_complete_snapshot_binding_rejects_before_command(tmp_path, monkeypatch, attack):
    host, journal, (_, installation, _), snapshot = complete_snapshot_host(tmp_path)
    if attack == "unknown_mode":
        journal["compose_snapshot"]["mode"] = "guess-from-shape"
    elif attack == "null_mode":
        journal["compose_snapshot"] = None
    elif attack == "wrong_target":
        journal["compose_snapshot"]["path"] = str(snapshot)
    elif attack == "missing_target":
        host.files.remove(installation)
    elif attack == "duplicate_layer":
        host.files.append(installation)
    elif attack == "changed_installation":
        installation.write_text("{}")
    elif attack == "unrecorded_installation":
        journal["compose_files"].pop(str(installation))
    else:
        snapshot.write_text("{}")
    commands = []
    monkeypatch.setattr(host, "command", lambda args, **kwargs: commands.append(args))
    with pytest.raises(update.UpdateError, match="update_(compose_override|override_changed)"):
        host.operation_override(journal, "previous_override")
    assert not commands


def test_legacy_partial_snapshot_keeps_append_semantics(tmp_path, monkeypatch):
    host, journal, files, snapshot = complete_snapshot_host(tmp_path)
    journal.pop("compose_snapshot")
    # The original producer also emitted named volume definitions: their
    # presence must never infer replacement authority for an old journal.
    update.atomic_json(snapshot, {"services": {"api": {"image": "old"}},
                                  "volumes": {"legacy": {"name": "sli_legacy"}}})
    journal["previous_override_sha256"] = update.sha256(snapshot)
    commands = []
    monkeypatch.setattr(host, "command", lambda args, **kwargs: commands.append(args) or "{}")
    host.compose(["config", "--format", "json"], host.operation_override(journal, "previous_override"))
    selected = [commands[0][index + 1] for index, value in enumerate(commands[0]) if value == "-f"]
    assert selected == [*[str(path) for path in files], str(snapshot)]


def test_complete_snapshot_render_failure_rejects_before_stage(release, monkeypatch):
    updater, host, archive, *_ = release
    retained_volume_overlay(release, monkeypatch)
    configuration = host.configuration
    rendered = []

    def reject_prospective(replacement=None):
        if replacement:
            rendered.append(replacement)
            raise update.UpdateError("update_docker_failed")
        return configuration()
    monkeypatch.setattr(host, "configuration", reject_prospective)
    assert updater.apply(archive) == "rejected"
    assert rendered and "stage" not in host.calls and "check_backup" not in host.calls
    assert updater.operation()["phase"] == "verify"


@pytest.mark.parametrize("action", ["helper", "migrate", "activate", "rollback", "fence", "drain"])
def test_complete_snapshot_operation_commands_use_same_file_selection(tmp_path, monkeypatch, action):
    host, journal, (base, installation, operator), snapshot = complete_snapshot_host(tmp_path)
    candidate = snapshot.with_name("candidate.json")
    update.atomic_json(candidate, {"services": {"worker": {"image": "candidate"}}})
    journal.update(candidate_override=str(candidate), candidate_override_sha256=update.sha256(candidate),
                   candidate_tag="sli-update:candidate-test", previous={"image_tag": "previous", "image_digest": "digest"},
                   manifest={"image": {"digest": "digest"}}, services=["worker"], added_services=["notification-delivery"])
    commands = []
    stopped = [False]

    def command(args, **kwargs):
        commands.append(args)
        stopped[0] = True
        return "{}"

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "stop_operation", lambda value: None)
    monkeypatch.setattr(host, "containers", lambda: [])
    monkeypatch.setattr(host, "image_id", lambda value: "digest")
    if action == "drain":
        monkeypatch.setattr(host, "containers", lambda: [{"ID": "fixture", "Service": "worker",
                            "State": "exited" if stopped[0] else "running", "ExitCode": 0}])
        monkeypatch.setattr(host, "wait_backup_idle", lambda *args: None)
        monkeypatch.setattr(host, "wait_stopped", lambda *args: None)
        monkeypatch.setattr(host, "in_flight", lambda: {"leases": 0, "transactions": 0})
    if os.name != "nt":
        monkeypatch.setattr(update.os, "chown", lambda *args: None)
    if action == "helper":
        host.helper(journal, "check", "synthetic")
    elif action == "rollback":
        host.activate(journal, previous=True)
    else:
        getattr(host, action)(journal)
    assert commands
    for command in commands:
        prefix = command[:command.index(str(operator)) + 1]
        files = [prefix[index + 1] for index, value in enumerate(prefix) if value == "-f"]
        expected = candidate if action in {"migrate", "activate"} or command[-1] == "notification-delivery" else snapshot
        assert files == [str(base), str(expected), str(operator)]
        assert str(installation) not in files


@pytest.mark.parametrize("legacy", [False, True])
def test_snapshot_render_failure_on_resume_preserves_pending_without_mutations(release, monkeypatch, legacy):
    updater, host, archive, *_ = release
    if not legacy:
        retained_volume_overlay(release, monkeypatch)
    monkeypatch.setattr(host, "stage", lambda *args: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    journal = updater.operation()
    assert journal["phase"] == "stage" and journal["completed"] == ["verify"]
    assert ("compose_snapshot" not in journal) == legacy
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), list(host.calls)
    rendered = []

    def reject_render(*args, **kwargs):
        rendered.append((args, kwargs))
        raise update.UpdateError("update_docker_failed")

    monkeypatch.setattr(host, "configuration", reject_render, raising=False)
    monkeypatch.setattr(host, "compose", reject_render, raising=False)
    with pytest.raises(update.UpdateError, match="update_docker_failed"):
        updater.resume()
    assert rendered
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes(), host.calls)


def test_complete_snapshots_render_and_attest_both_before_stage(release, monkeypatch):
    updater, host, archive, *_ = release
    target, _, _ = retained_volume_overlay(release, monkeypatch)
    installation = package.read_json(target.read_bytes())
    installation["services"]["notification-delivery"]["security_opt"] = ["no-new-privileges:true"]
    update.atomic_json(target, installation)
    configuration = host.configuration
    rendered = []

    def capture(replacement=None):
        if replacement:
            rendered.append(str(replacement[str(target)]))
        return configuration(replacement)

    def stage(*args):
        journal = updater.operation()
        assert journal["compose_snapshot"] == {"mode": "replace-installation-v1", "path": str(target)}
        assert rendered == [journal["previous_override"], journal["candidate_override"]]
        assert journal["snapshot_fingerprints"] == {
            key: hashlib.sha256(package.canonical_json(configuration({str(target): journal[key]}))).hexdigest()
            for key in ("previous_override", "candidate_override")}
        for key in ("previous_override", "candidate_override"):
            assert configuration({str(target): journal[key]})["services"]["notification-delivery"]["security_opt"] == ["no-new-privileges:true"]
        raise PowerLoss()

    monkeypatch.setattr(host, "configuration", capture)
    monkeypatch.setattr(host, "stage", stage)
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    assert "stage" not in host.calls and "check_backup" not in host.calls


def test_complete_snapshot_changed_render_fingerprint_rejects_resume(release, monkeypatch):
    updater, host, archive, *_ = release
    retained_volume_overlay(release, monkeypatch)
    monkeypatch.setattr(host, "stage", lambda *args: (_ for _ in ()).throw(PowerLoss()))
    with pytest.raises(PowerLoss):
        updater.apply(archive)
    configuration = host.configuration
    before = updater.journal_path.read_bytes(), updater.installed_path.read_bytes()
    mutations = [value for value in host.calls if value in {"stage", "check_backup", "drain", "activate", "restore"}]

    def changed(replacement=None):
        rendered = configuration(replacement)
        if replacement:
            rendered["services"]["api"]["labels"]["unexpected"] = "changed"
        return rendered

    monkeypatch.setattr(host, "configuration", changed)
    with pytest.raises(update.UpdateError, match="update_configuration_changed"):
        updater.resume()
    assert before == (updater.journal_path.read_bytes(), updater.installed_path.read_bytes())
    assert mutations == [value for value in host.calls if value in {"stage", "check_backup", "drain", "activate", "restore"}]


def test_checkpoint_helper_sends_program_on_stdin(tmp_path, monkeypatch):
    host, journal, *_ = complete_snapshot_host(tmp_path)
    journal.update(previous={"image_tag": "previous", "image_digest": "digest"},
                   manifest={"image": {"digest": "digest"}}, services=["worker"], added_services=[])
    seen = []

    def command(args, **kwargs):
        seen.append((args, kwargs))
        return "{}"

    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "stop_operation", lambda value: None)
    if os.name != "nt":
        monkeypatch.setattr(update.os, "chown", lambda *args: None)
    host.helper(journal, "check", "synthetic")
    args, kwargs = seen[-1]
    assert args[-3:] == ["-", "check", "synthetic"] and "-c" not in args
    assert max(len(value) for value in args) < 4096
    program = kwargs["stdin"].decode("utf-8")
    assert "update_checkpoint.main()" in program and len(program) > 100_000

