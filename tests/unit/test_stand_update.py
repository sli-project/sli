"""Main-only dispatch and fail-closed deployment with fake Git/Docker/SSH."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import stand_update as stand


SHA = "b" * 40
PREVIOUS = "a" * 40


class FakeDeployment(stand.Deployment):
    def __init__(self, tmp_path, *, supports=True, drift=True, committed=True):
        super().__init__({"home": str(tmp_path), "repository": str(tmp_path / "checkout"),
            "scratch": str(tmp_path / "scratch"), "runtime": "/srv/example", "remote_home": "/srv/example-updates",
            "signing_key": str(tmp_path / "private.key"), "key_id": "test-only", "trust_store": "/etc/example/trust.json",
            "target": "synthetic-target", "key": "synthetic-key"})
        self.supports, self.drift, self.committed = supports, drift, committed
        self.calls = []
        self.applied = False
        self.directory = None

    def installed(self):
        return {"source_commit": SHA if self.applied else PREVIOUS,
                "version": "2026.10.13", "migration_ledger": [{"version": 1}], "plugins": {}}

    def run(self, args, **kwargs):
        self.calls.append(args)
        if "ls-remote" in args or "rev-parse" in args:
            return SHA.encode()
        if "show" in args:
            return b"1800000000" if "--format=%ct" in args else b"2026.10.16"
        if "export_source" in str(args):
            self.directory = Path(args[-1]).parent
            source = self.directory / "source/deploy/linux"
            source.mkdir(parents=True)
            (source / "sli_update.py").write_text("def reconcile(self," if self.supports else "old updater")
        if "PACKAGE_BUILD" in str(args):
            raise AssertionError("Builder code should be passed directly")
        if stand.PACKAGE_BUILD in args:
            config = json.loads((self.directory / "build-input.json").read_text())
            assert config["actual_max"] == (2 if self.drift else 1)
            (self.directory / "manifest.json").write_text(json.dumps({"migrations": {
                "config/postgres_migrations/001_example.sql": "a" * 64,
                "config/postgres_migrations/002_later.sql": "b" * 64}}))
            (self.directory / "update.zip").write_bytes(b"synthetic package")
        if stand.HOST_LIBRARIES in args:
            (self.directory / "host-libs").mkdir()
        if "inspect" in args:
            return ("sha256:" + "c" * 64).encode()
        return b""

    def remote(self, args, **kwargs):
        self.calls.append(args)
        if "psql" in args:
            return b"2" if self.drift else b"1"
        if "reconcile" in args:
            return b'{"status":"reconciled"}'
        if "apply" in args:
            self.applied = self.committed
            return json.dumps({"status": "committed" if self.committed else "rejected", "source_commit": SHA,
                               "operation": "d" * 32}).encode()
        if stand.PENDING_JOURNAL in args:
            return b'{"status":"absent"}'
        if "curl" in args:
            return b"200"
        if "ps" in args:
            return b'{"Service":"api","State":"running","Health":"healthy"}\n{"Service":"migrate","State":"exited"}'
        if stand.METRICS in args:
            return b'{"semantic":{"queued":12,"completed":34},"last_cycle":{"completed":2},"inbox":{"pending":0}}'
        return b""

    def provision_trust(self):
        self.calls.append(["provision_trust"])


@pytest.fixture
def fake(tmp_path, monkeypatch):
    monkeypatch.setattr(stand.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
    return FakeDeployment(tmp_path)


def test_success_reconciles_before_native_apply_and_reads_back(fake):
    assert fake.execute() == "verified"
    actions = [action for args in fake.calls for action in ("reconcile", "apply", "curl") if action in args]
    assert actions == ["reconcile", "apply", "curl"]
    assert fake.state["healthy_services"] == 1
    assert fake.state["source_commit"] == SHA
    assert "Обновление SLI на стенде: verified" in (fake.home / "LAST-STAND.md").read_text()


def test_old_main_builds_package_but_cannot_change_stand(tmp_path):
    deployment = FakeDeployment(tmp_path, supports=False)
    with pytest.raises(stand.DeploymentError, match="stand_main_reconciliation_required"):
        deployment.execute()
    assert (deployment.directory / "update.zip").exists()
    assert not any("apply" in args or "reconcile" in args or "provision_trust" in args for args in deployment.calls)


def test_without_drift_old_main_can_use_existing_native_updater(tmp_path, monkeypatch):
    monkeypatch.setattr(stand.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=0))
    deployment = FakeDeployment(tmp_path, supports=False, drift=False)
    assert deployment.execute() == "verified"
    assert not any("reconcile" in args for args in deployment.calls)


def test_rejected_native_apply_never_reports_verified(fake):
    fake.committed = False
    with pytest.raises(stand.DeploymentError, match="stand_update_not_committed"):
        fake.execute()
    assert fake.state["result"] != "verified"
    assert not any("curl" in args for args in fake.calls)


def test_terminal_native_result_returns_without_waiting_on_running_journal(fake, monkeypatch):
    operation = "c" * 32
    result = {"status": "rejected", "operation": operation,
              "reason_code": "update_daily_backup_schema_mismatch"}
    def remote(args, **kwargs):
        if "apply" in args:
            return json.dumps(result).encode()
        if stand.PENDING_JOURNAL in args:
            return json.dumps({"status": "running", "operation": operation}).encode()
        raise AssertionError("No polling is needed after the native updater exits")
    monkeypatch.setattr(fake, "remote", remote)
    monkeypatch.setattr(stand.time, "sleep", lambda *_: pytest.fail("terminal result must not wait"))

    assert fake.native_result("/trusted-main", "apply", "/package.zip") == result


@pytest.mark.parametrize("status", ["rolling_back", "recovery_required"])
def test_pending_unmutated_rollback_resumes_without_creating_backup(fake, monkeypatch, status):
    calls = []

    def remote(args, **kwargs):
        calls.append((args, kwargs))
        if stand.PENDING_JOURNAL in args:
            return json.dumps({"status": status, "operation": "c" * 32,
                               "migration_started": False, "recovery_started": False}).encode()
        assert "resume" in args and args[-2:] == ["--operation-id", "c" * 32]
        assert kwargs["check"] is False
        return json.dumps({"status": "rolled_back", "operation": "c" * 32}).encode()

    monkeypatch.setattr(fake, "remote", remote)
    fake.resume_pending("/trusted-main", "/package.zip")
    assert len(calls) == 2
    assert fake.state["stage"] == "resume"


@pytest.mark.parametrize("status,flags,reason", [
    ("committed", {}, None), ("rolled_back", {}, None), ("rejected", {}, None),
    ("running", {}, "update_resume_required"),
    ("rolling_back", {"migration_started": True}, "stand_recovery_restore_requires_operator"),
    ("recovery_required", {"recovery_started": True}, "stand_recovery_restore_requires_operator"),
])
def test_resume_never_rolls_back_committed_or_mutated_data(fake, monkeypatch, status, flags, reason):
    calls = []

    def remote(args, **kwargs):
        calls.append(args)
        return json.dumps({"status": status, "operation": "c" * 32,
                           "migration_started": False, "recovery_started": False, **flags}).encode()

    monkeypatch.setattr(fake, "remote", remote)
    if reason:
        with pytest.raises(stand.DeploymentError, match=reason):
            fake.resume_pending("/trusted-main", "/package.zip")
    else:
        fake.resume_pending("/trusted-main", "/package.zip")
    assert len(calls) == 1


def test_native_failure_reason_precedes_missing_commit(fake, monkeypatch):
    original = fake.remote

    def remote(args, **kwargs):
        if "apply" in args:
            return b'{"status":"failed","reason_code":"update_resume_required"}'
        return original(args, **kwargs)

    monkeypatch.setattr(fake, "remote", remote)
    with pytest.raises(stand.DeploymentError, match="^update_resume_required$"):
        fake.execute()
    assert fake.state["result"] != "verified"


def test_native_resume_failure_does_not_apply(fake, monkeypatch):
    def remote(args, **kwargs):
        if stand.PENDING_JOURNAL in args:
            return json.dumps({"status": "recovery_required", "operation": "c" * 32,
                               "migration_started": False, "recovery_started": False}).encode()
        assert "resume" in args
        return b'{"status":"recovery_required","reason_code":"update_rollback_failed"}'

    monkeypatch.setattr(fake, "remote", remote)
    with pytest.raises(stand.DeploymentError, match="update_rollback_failed"):
        fake.resume_pending("/trusted-main", "/package.zip")


def test_dispatcher_resumes_before_reconcile_and_apply(fake, monkeypatch):
    original = fake.remote
    actions = []

    def remote(args, **kwargs):
        if stand.PENDING_JOURNAL in args:
            return json.dumps({"status": "rolling_back", "operation": "c" * 32,
                               "migration_started": False, "recovery_started": False}).encode()
        for action in ("resume", "reconcile", "apply"):
            if action in args:
                actions.append(action)
        if "resume" in args:
            return json.dumps({"status": "rolled_back", "operation": "c" * 32}).encode()
        return original(args, **kwargs)

    monkeypatch.setattr(fake, "remote", remote)
    assert fake.execute() == "verified"
    assert actions == ["resume", "reconcile", "apply"]


def test_native_reason_rejects_private_exception_text():
    with pytest.raises(stand.DeploymentError, match="^stand_update_not_committed$"):
        stand.Deployment.require_native({"status": "failed", "reason_code": "private detail"},
                                        "committed", "stand_update_not_committed")


def test_successful_native_apply_still_requires_exact_commit(fake, monkeypatch):
    original = fake.remote

    def remote(args, **kwargs):
        if "apply" in args:
            return json.dumps({"status": "committed", "source_commit": PREVIOUS}).encode()
        return original(args, **kwargs)

    monkeypatch.setattr(fake, "remote", remote)
    with pytest.raises(stand.DeploymentError, match="stand_update_commit_mismatch"):
        fake.execute()


@pytest.mark.parametrize("reason", ["update_fresh_daily_backup_required", "update_daily_backup_schema_mismatch"])
def test_no_fresh_daily_copy_waits_next_window_and_never_reports_success(fake, monkeypatch, reason):
    original = fake.remote
    def remote(args, **kwargs):
        if "apply" in args:
            return json.dumps({"status": "rejected", "reason_code": reason}).encode()
        return original(args, **kwargs)
    monkeypatch.setattr(fake, "remote", remote)
    assert fake.execute() == "waiting"
    assert fake.state["result"] == "waiting" and fake.state["reason_code"] == reason
    report = (fake.home / "LAST-STAND.md").read_text()
    assert "нет свежей суточной копии" in report and "следующего окна" in report
    assert not any("--once" in args or "curl" in args for args in fake.calls)


def test_report_records_daily_rollback_point_and_honest_agent_replay_limit(fake, monkeypatch):
    original = fake.remote
    selected = {"backup_id": "20261018T020000.000000Z", "backup_started_at_utc": "2026-10-18T02:00:00+00:00"}
    def remote(args, **kwargs):
        result = original(args, **kwargs)
        if "apply" in args:
            return json.dumps({**json.loads(result), "daily_backup": selected}).encode()
        return result
    monkeypatch.setattr(fake, "remote", remote)
    assert fake.execute() == "verified"
    report = (fake.home / "LAST-STAND.md").read_text()
    assert selected["backup_id"] in report and selected["backup_started_at_utc"] in report
    assert "подтверждённые пакеты удалены" in report and "не гарантирована" in report
    assert fake.state["daily_backup"] == selected


def test_dry_run_has_no_writes_or_builds(fake):
    assert fake.execute(dry_run=True) == "dry_run"
    assert not (fake.home / "stand.lock").exists()
    assert not any("build" in args or "apply" in args for args in fake.calls)


@pytest.mark.parametrize("current", [False, True])
def test_check_only_compares_main_without_writes_or_update(fake, current):
    fake.applied = current
    before = set(fake.home.iterdir())
    assert fake.execute(check_only=True) == ("current" if current else "update_available")
    assert set(fake.home.iterdir()) == before
    assert not any("build" in args or "fetch" in args or "apply" in args for args in fake.calls)


def test_failed_check_only_preserves_update_status(tmp_path, monkeypatch, capsys):
    config = tmp_path / "config.json"
    config.write_text("{}")
    def fail(*args, **kwargs):
        raise stand.DeploymentError("stand_check_failed")
    monkeypatch.setattr(stand, "Deployment", lambda _: SimpleNamespace(execute=fail))
    assert stand.main(["--config", str(config), "--check-only"]) == 1
    assert capsys.readouterr().out == "stand_check_failed\n"


def test_interval_prevents_build(fake):
    (fake.home / "stand-last-attempt").write_text(str(int(stand.time.time())))
    assert fake.execute() == "cooldown"
    assert not any("build" in args or "fetch" in args for args in fake.calls)


def test_force_never_bypasses_live_lock(fake):
    with stand.deployment_lock(fake.home):
        with pytest.raises((BlockingIOError, OSError)):
            fake.execute(force=True)
    assert not any("build" in args for args in fake.calls)


def test_repeated_version_file_gets_distinct_main_build_versions():
    assert stand.release_version("2026.10.16", 1800000000) == "2026.10.1800000000"
    assert stand.release_version("2026.10.16", 1800000001) != stand.release_version("2026.10.16", 1800000000)


@pytest.mark.parametrize("raw", ['[{"Service":"api"}]', '{"Service":"api"}\n'])
def test_compose_output_variants(raw):
    assert stand.container_rows(raw) == [{"Service": "api"}]


def test_package_builder_uses_saved_config_digest_and_absolute_source_paths(tmp_path):
    import subprocess
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from tests.unit.test_sli_update import make_image
    directory = tmp_path / "build"
    source = directory / "source"
    migrations = source / "config/postgres_migrations"
    migrations.mkdir(parents=True)
    (directory / "payload").mkdir()
    sql = b"insert into schema_migrations(version,name) values(1,'example');"
    (migrations / "001_example.sql").write_bytes(sql)
    image, inventory = make_image(directory / "image.tar", label="2026.10.1800000000")
    private = directory / "private.key"
    private.write_bytes(Ed25519PrivateKey.generate().private_bytes_raw())
    (directory / "build-input.json").write_text(json.dumps({"installed": {"version": "1.0.0", "plugins": {},
        "migration_ledger": [{"version": 1, "name": "example", "sha256": next(iter(inventory.values()))}]},
        "version": "2026.10.1800000000", "sha": SHA, "actual_max": 1,
        "image_digest": "sha256:" + "f" * 64, "key": str(private), "key_id": "test-only"}))
    root = Path(__file__).resolve().parents[2]
    subprocess.run([stand.sys.executable, "-c", stand.PACKAGE_BUILD, str(directory)], cwd=source,
                   env={**stand.os.environ, "PYTHONPATH": str(root)}, capture_output=True, check=True)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["image"]["digest"] == image["digest"]
    assert manifest["migrations"] == inventory
    assert (directory / "update.zip").exists()


def test_metrics_preserve_one_snapshot_and_exclude_private_log_fields(monkeypatch, capsys):
    import subprocess
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        if "psql" in args:
            return SimpleNamespace(stdout=b'{"observed_utc":"2026-10-16T00:00:00+00:00","semantic":{"queued":12}}')
        return SimpleNamespace(stdout=b'2026-10-15T23:59:59Z {"worker_id":"private-marker","completed":16,"processing":{"completed":16,"private":"private-marker"}}\n', stderr=b'')

    monkeypatch.setattr(subprocess, "run", run)
    exec(stand.METRICS, {})
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["last_completed_cycle_from_log"]["completed"] == 16
    assert "private-marker" not in output
    assert len([args for args, _ in calls if "psql" in args]) == 1
    assert b"REPEATABLE READ READ ONLY" in calls[0][1]["input"]
    assert calls[1][0][calls[1][0].index("--until") + 1] == result["observed_utc"]


def test_export_preserves_blob_bytes_with_crlf_checkout_configuration(tmp_path, monkeypatch):
    import subprocess
    repository = tmp_path / "objects.git"
    subprocess.run(["git", "init", "--bare", str(repository)], capture_output=True, check=True)

    def git(*args, data=None):
        return subprocess.run(["git", "--git-dir", str(repository), *args], input=data,
                              capture_output=True, check=True).stdout.strip()

    body = b"select 1;\nselect 2;\n"
    blob = git("hash-object", "-w", "--stdin", data=body)
    leaf = git("mktree", data=b"100644 blob " + blob + b"\timmutable.sql\n")
    tree = git("mktree", data=b"040000 tree " + leaf + b"\tserver\n").decode()
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.autocrlf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    root = Path(__file__).resolve().parents[2]
    code = "from pathlib import Path;from tools.release_artifacts import export_source;import sys;export_source(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]))"
    destination = tmp_path / "export"
    subprocess.run([stand.sys.executable, "-c", code, str(repository), tree, str(destination)],
                   env={**stand.export_environment(), "PYTHONPATH": str(root)}, capture_output=True, check=True)
    assert (destination / "server/immutable.sql").read_bytes() == body
    assert stand.os.environ["GIT_CONFIG_VALUE_0"] == "true"


def test_watchdog_stand_route_preserves_pc_hold_and_dry_mode(tmp_path):
    import subprocess
    root = Path(__file__).resolve().parents[2]
    script = root / "scripts/maintenance/watchdog/deployment.sh"
    # Windows bind mounts may contain CRLF; exercise the same shell text as LF.
    normalized = tmp_path / "deployment.sh"
    normalized.write_text(script.read_text(), newline="\n")
    config = tmp_path / "stand-config.json"
    config.write_text("{}")
    hold = tmp_path / "MIGRATION_HOLD"
    hold.touch()
    result = subprocess.run(["bash", "-c", 'note() { printf "%s\\n" "$*"; }; DRY=1; source "$1"; watchdog_update',
                             "test", str(normalized)], env={**stand.os.environ,
        "WATCHDOG_STAND_CONFIG": str(config), "WATCHDOG_HOLD_FILE": str(hold)}, capture_output=True, text=True, check=True)
    assert "Обновление SLI на стенде" in result.stdout
    assert "DRY-RUN" in result.stdout
    assert hold.exists()
