"""Core registration/scheduling/publication of the finite WR05 job, with fakes."""
from contextlib import nullcontext
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import migrate
from server.sli.core import job_executor, job_queue, job_registry
from server.sli.plugins import registry
from server.sli.plugins.workstations import jobs, projection, projection_jobs
from tests.unit.test_workstation_projection import PG, evaluator, prepare


@pytest.fixture
def admitted(monkeypatch):
    for flag in (jobs.FLAG, "SLI_CORE_JOB_AD_GPO_PILOT", "SLI_CORE_JOB_RADIUS_PILOT",
                 "SLI_PLUGIN_RUNTIME_DIR", "SLI_PLUGIN_LOCK_DIR"):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.delenv(projection_jobs.FLAG, raising=False)
    monkeypatch.setattr(projection, "projectors", lambda: (evaluator(),))
    handlers = job_registry.pilot_registry()
    identity = next(item for item in handlers.identities("light") if item["handler_id"] == projection_jobs.HANDLER_ID)
    declared = handlers.handlers[tuple(identity[key] for key in (
        "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256"))]
    pinned, partition = jobs.job_source(declared, {"revision": "1"}, "fixture-slot")
    job = {**identity, **declared, "job_type": declared["kind"], "source_instance_id": projection_jobs.SOURCE,
           "available_at_utc": "2026-10-19T00:00:00+00:00", "pinned_input": pinned,
           "input_sha256": job_queue.digest(pinned), "partition_key": partition,
           "job_id": "00000000-0000-4000-8000-000000000001",
           "lease_token": "00000000-0000-4000-8000-000000000002", "lease_generation": 1}
    return handlers, job, registry.plugin_job_handlers(jobs.PLUGIN, projection_jobs.HANDLER_ID)


def test_default_registers_pinned_light_job_with_finite_budget_and_no_new_worker(admitted):
    handlers, job, _ = admitted
    assert handlers.resolve(job)["handler_id"] == projection_jobs.HANDLER_ID
    assert job["budget"]["max_records"] == 100 and job["budget"]["statement_timeout_ms"] == 5000
    assert job["budget"]["max_db_connections"] == 1
    manifest = next(item for item in handlers.manifests
                    if any(h["handler_id"] == projection_jobs.HANDLER_ID for h in item["handlers"]))
    assert manifest["own_permanent_workers"] is False


def test_flag_off_does_not_register_projection_job(monkeypatch):
    monkeypatch.setenv(projection_jobs.FLAG, "0")
    assert not projection_jobs.enabled()
    assert not any(item["handler_id"] == projection_jobs.HANDLER_ID
                   for item in job_registry.pilot_registry().identities("light"))


def test_default_projection_preserves_vpn_generation_and_retained_job_pins(tmp_path, monkeypatch):
    from server.sli.plugins import update_runtime

    for flag in (jobs.FLAG, projection_jobs.FLAG, "SLI_CORE_JOB_AD_GPO_PILOT", "SLI_CORE_JOB_RADIUS_PILOT"):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(tmp_path))
    # No executable generations are loaded in this registry/queue contract.
    monkeypatch.setattr(job_registry, "plugin_installed", lambda _: True)
    monkeypatch.setattr(jobs, "plugin_installed", lambda _: True)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    remote = "sli.remote-access"
    bundled_path = job_registry.ROOT / f"config/plugin_packages/{remote}.jobs-v3.json"
    bundled = json.loads(bundled_path.read_text("utf-8"))
    previous = {**bundled, "plugin_version": "1.1.0"}
    current = {**bundled, "plugin_version": "1.2.0"}
    for identity, manifest in (("a" * 64, previous), ("b" * 64, current)):
        directory = tmp_path / remote / "versions" / identity
        (directory / "backend").mkdir(parents=True)
        (directory / "backend/jobs-v3.json").write_text(json.dumps(manifest), encoding="utf-8")
        (directory / "release.json").write_text("{}", encoding="utf-8")
    (tmp_path / remote / "active.json").write_text(json.dumps({"generation": "b" * 64}), encoding="utf-8")
    handlers = job_registry.pilot_registry()
    assert [item["plugin_version"] for item in handlers.manifests if item["plugin_id"] == remote] == ["1.2.0"]
    assert any(item["plugin_id"] == jobs.PLUGIN for item in handlers.manifests)
    for manifest in (bundled, previous, current):
        handler = manifest["handlers"][0]
        key = (remote, handler["handler_id"], handler["handler_version"], manifest["plugin_version"], job_queue.digest(manifest))
        assert key in handlers.handlers
    update_runtime.pin_job(remote, "1.1.0", job_queue.digest(previous), bundled_path)
    assert update_runtime.generation(remote) == tmp_path / remote / "versions" / ("a" * 64)
    with pytest.raises(ValueError, match="^handler_version_unavailable$"):
        update_runtime.pin_job(remote, "1.1.0", "f" * 64, bundled_path)


def test_registered_job_stage_returns_only_ids_and_publication_is_atomic_on_lost_lease(admitted):
    _, job, (stage, apply) = admitted
    pg = PG()
    prepare(pg, projection.projectors())
    pg.add_fact("fixture-input")
    staged = stage(pg, job)
    assert staged["work_ids"] == [1]
    assert "fixture-agent" not in json.dumps(staged) and "payload" not in json.dumps(staged)
    assert pg.findings == []
    pg.finish = False
    before = deepcopy(pg.receipts)
    with pytest.raises(job_queue.LeaseLost):
        job_queue.publish(pg, job, staged, apply)
    assert pg.findings == [] and pg.receipts == before and pg.checkpoints == {}
    pg.finish = True
    assert job_queue.publish(pg, job, staged, apply) == "committed"
    assert len(pg.findings) == 1
    # Even a different core job replay cannot apply the same input twice.
    assert job_queue.publish(pg, job, staged, apply) == "committed"
    assert len(pg.findings) == 1
    fence = next(index for index, (sql, _) in enumerate(pg.calls) if "begin_core_job_result_v1" in sql)
    effects = next(index for index, (sql, _) in enumerate(pg.calls) if "set_config('sli.job_id'" in sql)
    assert fence < effects


def test_no_evaluator_is_blocked_without_data_access_or_acknowledgement(admitted, monkeypatch):
    _, job, (stage, apply) = admitted
    monkeypatch.setattr(projection, "projectors", lambda: ())
    result = stage(SimpleNamespace(), job)
    assert result["status"] == "blocked" and result["coverage_state"] == "not_proven"
    apply(SimpleNamespace(), job, result)


def test_projection_only_schedule_uses_its_own_source_and_never_schedules_retention(admitted, monkeypatch):
    handlers, _, _ = admitted
    queued = []
    class Dispatcher:
        def cursor(self):
            return nullcontext(self)
        def execute(self, sql, params=()):
            self.sql = sql
            if "enqueue_core_job" in sql:
                queued.append(json.loads(params[0]))
        def fetchone(self):
            if "read_workstation_projection" in self.sql:
                return ({"plugin_id": jobs.PLUGIN, "source_instance_id": projection_jobs.SOURCE,
                         "revision": "1", "access_scope": {"mode": "restricted"}},)
            if "clock_timestamp" in self.sql:
                from datetime import datetime, timezone
                return (datetime(2026, 10, 19, tzinfo=timezone.utc),)
            return ("00000000-0000-4000-8000-000000000003",)
        def fetchall(self):
            assert "read_workstation_inventory_job_sources_v1" in self.sql
            return [({"plugin_id": jobs.PLUGIN, "source_instance_id": "workstations:inventory:11",
                      "revision": "1", "access_scope": {"mode": "restricted"}},)]
    monkeypatch.setattr(job_executor, "connect", lambda *_: nullcontext(Dispatcher()))
    monkeypatch.setattr(job_executor, "write_heartbeat", lambda *_, **__: None)
    monkeypatch.setattr(job_executor, "pilot_registry", lambda: handlers)
    monkeypatch.setattr(job_executor, "STOP", SimpleNamespace(is_set=lambda: False))
    claims = []
    def claim(cur, profile, executor_id, allowed):
        claims.extend(allowed)
    monkeypatch.setattr(job_queue, "claim", claim)
    assert job_executor.serve("light", once=True) == 0
    assert len(queued) == 2
    assert all(item["handler_id"] == projection_jobs.HANDLER_ID for item in queued)
    assert queued[0]["source_instance_id"] == projection_jobs.SOURCE
    assert queued[1]["partition_key"] == "workstations:inventory:11"
    assert projection_jobs.HANDLER_ID in {item["handler_id"] for item in claims}


def test_projection_only_bootstrap_configures_light_logins_without_history(admitted, monkeypatch):
    calls = []
    class Connection:
        def transaction(self):
            return nullcontext()
        def execute(self, sql, params=()):
            calls.append((str(sql), params))
            return SimpleNamespace(fetchone=lambda: (False,))
    monkeypatch.setattr(migrate, "secret_value", lambda _: "fixture-password")
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.setenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", "fixture-file")
    migrate.configure_job_logins(Connection())
    assert {params[0] for _, params in calls if params} == {
        "sli_job_dispatcher_light", "sli_job_executor_light", "sli_job_publisher_light"}
    monkeypatch.setattr("server.sli.storage.workstation_history.configured_history",
                        lambda: pytest.fail("projection must not initialize history"))
    migrate.configure_workstation_history()


@pytest.mark.parametrize("flag", [None, "0", "1"])
def test_child_keeps_projection_flag_without_activating_retention(admitted, monkeypatch, flag):
    _, job, _ = admitted
    if flag is not None:
        monkeypatch.setenv(projection_jobs.FLAG, flag)
    monkeypatch.setenv("SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE", "fixture-file")
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE", "fixture-history-file")
    monkeypatch.setenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "90")
    monkeypatch.setattr(job_executor, "connection_settings", lambda *_: {})
    seen = []
    def popen(_argv, **kwargs):
        seen.append(kwargs["env"])
        kwargs["stdout"].write(b'{"status":"success"}')
        kwargs["stdout"].flush()
        return SimpleNamespace(pid=123, returncode=0, poll=lambda: 0)
    job_executor.run_child(job, "handler", deadline=1, clock=lambda: 0, popen=popen, terminate=lambda _: None)
    assert seen[0][projection_jobs.FLAG] == ("0" if flag == "0" else "1")
    assert jobs.FLAG not in seen[0]
    assert "ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE" not in seen[0]
    assert "SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS" not in seen[0]


@pytest.mark.parametrize("flag", ["0", "1"])
def test_compose_projection_is_disabled_by_default_and_installation_preserves_the_choice(tmp_path, monkeypatch, flag):
    from deploy.linux import installation

    # Host topology is synthetic here; volume refusal has dedicated policy tests.
    monkeypatch.setattr(installation, 'restore_check_directory', lambda runtime, environment: runtime / 'backups/.restore-check')
    root = Path(__file__).resolve().parents[2]
    compose = yaml.safe_load((root / "deploy/linux/docker-compose.yml").read_text("utf-8"))
    for service in ("migrate", "executor-light", "post-collection"):
        assert compose["services"][service]["environment"][projection_jobs.FLAG] == "${SLI_CORE_JOB_WORKSTATIONS_PROJECTION:-0}"
    monkeypatch.setattr(installation.os, "chown", lambda *_: None, raising=False)
    host = installation.InstallationHost([], "https://127.0.0.1:8443/api/health/ready", None)
    config = {"services": {"executor-light": {"environment": {projection_jobs.FLAG: flag}}}}
    installation.preserve_compose(tmp_path, host, config)
    saved = json.loads((tmp_path / "compose/compose.json").read_text())
    assert saved["services"]["executor-light"]["environment"][projection_jobs.FLAG] == "${SLI_CORE_JOB_WORKSTATIONS_PROJECTION:-" + flag + "}"
    assert f'SLI_CORE_JOB_WORKSTATIONS_PROJECTION="{flag}"' in (tmp_path / "runtime.env").read_text()
