"""Production registration -> fenced transfer -> old report evidence, with fakes."""
from __future__ import annotations

import copy
import json
from contextlib import contextmanager, nullcontext
from datetime import timedelta
from types import SimpleNamespace

import pytest
import yaml

from deploy.linux import migrate
from server.sli.core import job_executor, job_queue, job_registry
from server.sli.plugins import registry, update_runtime
from server.sli.plugins.workstations import jobs, reports, retention
from server.sli.storage import purge_audit, workstation_history as history
from tests.storage.test_workstation_history import NOW, PG, context, observation, stores  # noqa: F401


class CorePG(PG):
    def __init__(self, rows, **kwargs):
        super().__init__(rows, **kwargs)
        self.finish = True
        self.begin = "publish"

    def cursor(self, **kwargs):
        return nullcontext(self)

    @contextmanager
    def transaction(self):
        saved = copy.deepcopy(self.rows)
        try:
            yield
        except Exception:
            self.rows = saved
            raise

    def execute(self, sql, params=()):
        compact = " ".join(sql.split())
        if "begin_core_job_result_v1" in sql or "finish_core_job_result_v1" in sql:
            self.calls.append((compact, params))
            self.one = (self.begin if "begin_core" in sql else self.finish,)
        elif compact.startswith("select observation.*"):
            self.calls.append((compact, params))
            exact = params[1] if "id=any(%s)" in sql else None
            selected = [copy.deepcopy(row) for row in self.rows
                        if row["observed_at"] < params[0] and row["family"] in {"processes", "usb"}
                        and row["id"] not in self.holds and (exact is None or row["id"] in exact)]
            selected.sort(key=lambda row: (row["observed_at"], row["id"]))
            self.selected = selected[:params[-1]]
            if "purge_row_bytes" in sql:
                self.selected = [{**row, "purge_row_bytes": 256} for row in self.selected]
        else:
            super().execute(sql, params)


@pytest.fixture
def admitted(monkeypatch):
    monkeypatch.setenv(jobs.FLAG, "1")
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    monkeypatch.delenv("SLI_CORE_JOB_AD_GPO_PILOT", raising=False)
    monkeypatch.delenv("SLI_CORE_JOB_RADIUS_PILOT", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    handlers = job_registry.pilot_registry()
    identity = next(item for item in handlers.identities("light") if item["plugin_id"] == jobs.PLUGIN)
    declared = handlers.handlers[tuple(identity[key] for key in (
        "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256"))]
    pinned, _ = jobs.job_source(declared, {"revision": "1"}, "fixture-slot")
    job = {**identity, **declared, "job_type": declared["kind"], "source_instance_id": jobs.SOURCE,
           "available_at_utc": NOW.isoformat(), "pinned_input": pinned,
           "input_sha256": job_queue.digest(pinned), "partition_key": retention.HANDLER_ID,
           "job_id": "00000000-0000-4000-8000-000000000001",
           "lease_token": "00000000-0000-4000-8000-000000000002", "lease_generation": 1}
    return job, registry.plugin_job_handlers(jobs.PLUGIN, retention.HANDLER_ID)


@pytest.mark.parametrize("family", ["processes", "usb"])
def test_registered_job_boundary_and_old_report_detail(stores, admitted, monkeypatch, family):
    ch, adapter = stores
    monkeypatch.setattr(history, "configured_history", lambda: adapter)
    job, (stage, apply) = admitted
    old = observation(1, age=366, family=family)
    rows = [old, observation(2, age=90, family=family), observation(3, age=89, family=family)]
    pg = CorePG(rows)
    staged = stage(pg, job)
    assert list(staged["candidates"]) == [old["id"]]
    assert ch.inserts == 0 and pg.rows == rows
    assert "source_xml" not in json.dumps(staged) and "fixture-agent" not in json.dumps(staged)
    assert job_queue.publish(pg, job, staged, apply) == "committed"
    assert len(pg.rows) == 2 and ch.inserts == 1
    assert any("set_config('sli.job_id'" in sql for sql, _ in pg.calls)
    monkeypatch.setattr(reports, "connect", lambda: nullcontext(pg))
    ctx = context(adapter, family)
    ctx.params["period"]["from_utc"] = (NOW - timedelta(days=730)).isoformat()
    definition = reports.make_report(family)
    page = definition.query(ctx)
    assert page["items"][0]["id"] == old["id"] and page["coverage"]["history"] == "loaded"
    detail = definition.detail.query(ctx, old["id"])
    assert detail["items"][0]["source_xml"] == old["source_xml"]


@pytest.mark.parametrize("failure", ["unavailable", "corrupt", "durable", "missing", "hold", "settings", "changed", "lease"])
def test_registered_publication_blocks_loss_and_rolls_back(stores, admitted, monkeypatch, failure):
    ch, adapter = stores
    job, (stage, apply) = admitted
    pg = CorePG([observation(1, age=366), observation(2, age=366)])
    staged = stage(pg, job)
    monkeypatch.setattr(history, "configured_history", lambda: None if failure == "missing" else adapter)
    if failure in {"unavailable", "corrupt", "durable"}:
        setattr(ch, failure, failure != "durable")
    elif failure == "hold":
        pg.holds.add(observation(2)["id"])
    elif failure == "settings":
        pg.days = 400
    elif failure == "changed":
        pg.rows[0]["ad_computer_id"] = 29
    elif failure == "lease":
        pg.finish = False
    before = copy.deepcopy(pg.rows)
    with pytest.raises((RuntimeError, ValueError)):
        job_queue.publish(pg, job, staged, apply)
    assert pg.rows == before
    if failure in {"unavailable", "corrupt", "durable", "missing", "settings", "changed", "hold"}:
        assert not any(sql.startswith("delete") for sql, _ in pg.calls)
    if failure in {"settings", "hold"}:
        assert purge_audit.last_purge_runs()["runs"][0]["reason"] == "workstation_retention_plan_changed"
    if failure == "lease":
        # A retry can use the acknowledged CH copy without overwriting it.
        assert ch.inserts == 2
        pg.finish = True
        assert job_queue.publish(pg, job, staged, apply) == "committed"
        assert pg.rows == [] and ch.inserts == 2


def test_hold_before_staging_and_custom_retention(stores, admitted, monkeypatch):
    _, adapter = stores
    job, (stage, apply) = admitted
    monkeypatch.setattr(history, "configured_history", lambda: adapter)
    pg = CorePG([observation(1, age=181), observation(2, age=180), observation(3, age=366)],
                days=180, holds=[observation(3)["id"]])
    staged = stage(pg, job)
    assert staged["retention_days"] == 180 and list(staged["candidates"]) == [observation(1)["id"]]
    assert job_queue.publish(pg, job, staged, apply) == "committed"
    assert [row["id"] for row in pg.rows] == [observation(2)["id"], observation(3)["id"]]


def test_drain_between_stage_and_publication_blocks_delete(stores, admitted, monkeypatch, tmp_path):
    ch, adapter = stores
    job, (stage, apply) = admitted
    pg = CorePG([observation()])
    staged = stage(pg, job)
    monkeypatch.setattr(history, "configured_history", lambda: adapter)
    plugin_dir = tmp_path / jobs.PLUGIN
    plugin_dir.mkdir()
    (plugin_dir / "draining.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(tmp_path))
    with pytest.raises(RuntimeError, match="plugin_update_draining"):
        job_queue.publish(pg, job, staged, apply)
    assert len(pg.rows) == 1 and ch.inserts == 0
    assert not any(sql.startswith("delete") for sql, _ in pg.calls)


def test_off_and_missing_package_exclude_runtime_jobs(monkeypatch):
    monkeypatch.delenv(jobs.FLAG, raising=False)
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    assert not jobs.enabled()
    assert not any(m["plugin_id"] == jobs.PLUGIN for m in job_registry.pilot_registry().manifests)
    monkeypatch.delenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", raising=False)
    monkeypatch.setenv(jobs.FLAG, "1")
    monkeypatch.setattr(jobs, "plugin_installed", lambda _: False)
    assert not jobs.enabled()
    assert not any(m["plugin_id"] == jobs.PLUGIN for m in job_registry.pilot_registry().manifests)


def test_dispatcher_schedules_and_claims_workstations_without_other_pilots(admitted, monkeypatch):
    from server.sli.sources import ad_gpo_jobs

    job, _ = admitted
    queued = []
    class Dispatcher:
        def cursor(self):
            return nullcontext(self)
        def execute(self, sql, params=()):
            self.sql = sql
            if "enqueue_core_job" in sql:
                queued.append(json.loads(params[0]))
        def fetchone(self):
            if "read_workstation" in self.sql:
                return ({"plugin_id": jobs.PLUGIN, "source_instance_id": jobs.SOURCE,
                         "revision": "1", "access_scope": {"mode": "restricted"}},)
            if "clock_timestamp" in self.sql:
                return (NOW,)
            return (job["job_id"],)
    monkeypatch.setattr(job_executor, "connect", lambda *_: nullcontext(Dispatcher()))
    monkeypatch.setattr(job_executor, "write_heartbeat", lambda *_, **__: None)
    monkeypatch.setattr(ad_gpo_jobs, "enabled", lambda: False)
    monkeypatch.setattr(job_executor, "STOP", SimpleNamespace(is_set=lambda: False))
    identities = []
    def claim(cur, profile, executor_id, allowed):
        identities.extend(allowed)
        return None
    monkeypatch.setattr(job_queue, "claim", claim)
    assert job_executor.serve("light", once=True) == 0
    assert len(queued) == 1 and queued[0]["handler_id"] == retention.HANDLER_ID
    assert queued[0]["source_instance_id"] == jobs.SOURCE
    assert {item["plugin_id"] for item in identities} == {jobs.PLUGIN}
    assert queued[0]["budget"]["max_records"] == 50


@pytest.mark.parametrize("purpose", ["handler", "publisher"])
def test_child_receives_history_secret_file_only_for_workstation_publisher(admitted, monkeypatch, purpose):
    job, _ = admitted
    for identity in ("EXECUTOR", "PUBLISHER"):
        monkeypatch.setenv(f"SLI_JOB_{identity}_LIGHT_PASSWORD_FILE", "fixture-file")
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE", "fixture-history-file")
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_PASSWORD", "fixture-password")
    monkeypatch.setenv("ADLOG_HISTORY_CLICKHOUSE_PORT", "8123")
    monkeypatch.setenv("SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS", "180")
    monkeypatch.setenv("ADLOG_PG_DSN", "fixture-admin")
    monkeypatch.setenv("ADLOG_DATA_DIR", "fixture-data")
    monkeypatch.setattr(job_executor, "connection_settings", lambda *_: {})
    seen = []
    def popen(_argv, **kwargs):
        seen.append(kwargs["env"])
        kwargs["stdout"].write(b'{"status":"success"}')
        kwargs["stdout"].flush()
        return SimpleNamespace(pid=123, returncode=0, poll=lambda: 0)
    job_executor.run_child(job, purpose, deadline=1, clock=lambda: 0, popen=popen, terminate=lambda _: None)
    env = seen[0]
    assert env[jobs.FLAG] == "1" and env["SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS"] == "180"
    assert ("ADLOG_HISTORY_CLICKHOUSE_PASSWORD_FILE" in env) == (purpose == "publisher")
    assert ("ADLOG_DATA_DIR" in env) == (purpose == "publisher")
    assert "ADLOG_HISTORY_CLICKHOUSE_PASSWORD" not in env and "ADLOG_PG_DSN" not in env


def test_workstation_only_bootstrap_provisions_light_logins_and_history(admitted, monkeypatch):
    calls = []
    monkeypatch.setattr(migrate, "secret_value", lambda _: "fixture-password")
    for purpose in ("DISPATCHER", "EXECUTOR", "PUBLISHER"):
        monkeypatch.setenv(f"SLI_JOB_{purpose}_LIGHT_PASSWORD_FILE", "fixture-file")
    class LoginConnection:
        def transaction(self):
            return nullcontext()
        def execute(self, sql, params=None):
            if params:
                calls.append(params[0])
            return SimpleNamespace(fetchone=lambda: (False,))
    migrate.configure_job_logins(LoginConnection())
    assert set(calls) == {"sli_job_dispatcher_light", "sli_job_executor_light", "sli_job_publisher_light"}
    monkeypatch.setattr(history, "configured_history", lambda: SimpleNamespace(port=8123))
    provisioned = []
    monkeypatch.setattr(history, "ensure_schema", provisioned.append)
    migrate.configure_workstation_history()
    assert provisioned == [8123]
    monkeypatch.setattr(history, "configured_history", lambda: None)
    with pytest.raises(RuntimeError, match="history_unavailable"):
        migrate.configure_workstation_history()


def test_release_overrides_retain_history_secret_for_bootstrap():
    root = job_registry.ROOT / "deploy/linux"
    for name in ("docker-compose.yml", "docker-compose.executor.yml", "docker-compose.ad-jobs.yml"):
        compose = yaml.safe_load((root / name).read_text("utf-8"))
        assert "history_password" in compose["services"]["migrate"]["secrets"]
        if name == "docker-compose.yml":
            key = "SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS"
            assert compose["services"]["api"]["environment"][key] == compose[
                "services"]["executor-light"]["environment"][key]
