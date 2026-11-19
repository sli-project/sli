from contextlib import contextmanager, nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from server.sli.core import job_executor, job_queue, job_registry
from server.sli.sources import ad_gpo_jobs, ad_snapshot_projection
from tests.unit.test_core_job_queue import Connection

pytestmark = pytest.mark.posix_only

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_ID = "00000000-0000-4000-8000-000000000501"


def job(handler_id="ad-snapshot-manifest-coordinator"):
    registry = ad_gpo_jobs.registry()
    profile = "long" if handler_id.startswith("gpo-") else "heavy"
    identity = next(item for item in registry.identities(profile)
                    if item["handler_id"] == handler_id)
    handler = registry.handlers[tuple(identity[key] for key in (
        "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256"))]
    pinned = {"manifest_id": MANIFEST_ID, "snapshot_sha256": "a" * 64,
              "domain_id": 1, "generation": MANIFEST_ID, "input_range": [MANIFEST_ID],
              "policy_revision": "1", "continuation": None}
    return {**identity, **{key: handler[key] for key in (
        "budget", "resource_profile", "rights_profile", "max_attempts", "input_contract", "result_contract")},
        "job_type": handler["kind"], "job_id": "00000000-0000-4000-8000-000000000502",
        "lease_token": "00000000-0000-4000-8000-000000000503", "lease_generation": 1,
        "pinned_input": pinned, "input_sha256": job_queue.digest(pinned),
        "source_instance_id": "ad-domain:1", "partition_key": "ad-snapshot",
        "remaining_seconds": 300}


def stored_manifest():
    return {"manifest_id": MANIFEST_ID, "manifest_sha256": "a" * 64, "coverage_state": "complete",
            "domain_id": 1, "members": [{"family": "ad_context_base",
            "source_id": "00000000-0000-4000-8000-000000000504", "payload_sha256": "b" * 64}]}


def test_off_keeps_radius_registry_and_does_not_replace_old_loops(monkeypatch):
    monkeypatch.delenv(ad_gpo_jobs.FLAG, raising=False)
    assert not ad_gpo_jobs.enabled()
    assert {m["plugin_id"] for m in job_registry.pilot_registry().manifests} == {"sli.remote-access", "sli.workstations"}
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    assert {m["plugin_id"] for m in job_registry.pilot_registry().manifests} == {
        "sli.remote-access", "sli.workstations", "sli.ad", "sli.gpo"}


def test_stored_input_has_same_projection_identity_and_hash_as_old_path(monkeypatch):
    from server.ad_context import repository
    manifest = stored_manifest()
    exact = {"run_id": manifest["members"][0]["source_id"], "status": "completed"}
    monkeypatch.setattr(repository, "load_projection_manifest", lambda *_: deepcopy(manifest))
    monkeypatch.setattr(repository, "load_exact_projection_source", lambda *_, **__: deepcopy(exact))
    expected = ad_snapshot_projection.project_exact_manifest(
        manifest, load_exact=lambda *_: exact, projection_keys=("ad.state",))
    result = ad_gpo_jobs.stage(None, job())
    assert result["projection_results"] == expected
    assert result["status"] == "success"
    assert exact["run_id"] not in json.dumps(result)  # Only output refs/hashes leave the handler.


@pytest.mark.parametrize("handler_id", ["ad-context-snapshot", "computers-v6-source", "gpo-acquisition"])
def test_linux_acquisition_is_explicitly_blocked_without_a_connection(handler_id, monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs.sys, "platform", "linux")
    result = ad_gpo_jobs.stage(None, {"handler_id": handler_id, "job_type": "acquire",
        "result_contract": "sli.ad-snapshot-job-output.v1"})
    assert result["status"] == "blocked"
    assert result["error_code"] == "acquisition_disabled_on_linux"


@pytest.mark.parametrize("change", [
    {"manifest_sha256": "c" * 64}, {"domain_id": 2},
])
def test_stored_input_cannot_change_hash_or_source_binding(change, monkeypatch):
    from server.ad_context import repository
    manifest = {**stored_manifest(), **change}
    monkeypatch.setattr(repository, "load_projection_manifest", lambda *_: manifest)
    with pytest.raises(ValueError, match="snapshot_input_changed"):
        ad_gpo_jobs.stage(None, job())


def test_same_snapshot_replay_has_one_key_and_all_ad_handlers_share_partition(monkeypatch):
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    source = {"plugin_id": "sli.ad", "source_instance_id": "ad-domain:1", "domain_id": 1,
              "manifest_id": MANIFEST_ID, "snapshot_sha256": "a" * 64,
              "revision": "1", "access_scope": {"mode": "restricted"}}
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    calls = []
    monkeypatch.setattr(job_registry, "enqueue", lambda _cur, spec: calls.append(spec))
    job_registry.schedule_jobs(Connection([now]), ad_gpo_jobs.registry(), "heavy", source)
    job_registry.schedule_jobs(Connection([now]), ad_gpo_jobs.registry(), "heavy", source)
    processing = [spec for spec in calls if spec["job_type"] != "acquire"]
    assert len(processing) == 6
    assert len({spec["idempotency_key"] for spec in processing}) == 3
    assert {spec["partition_key"] for spec in processing} == {"ad-snapshot"}
    assert {spec["pinned_input"]["generation"] for spec in processing} == {MANIFEST_ID}
    assert not any(spec["plugin_id"] == "sli.gpo" for spec in calls)


def test_gpo_is_independent_of_ad_scheduling(monkeypatch):
    source = {"plugin_id": "sli.gpo", "source_instance_id": "ad-domain:1", "domain_id": 1,
              "manifest_id": MANIFEST_ID, "snapshot_sha256": "a" * 64,
              "revision": "1", "access_scope": {"mode": "restricted"}}
    calls = []
    monkeypatch.setattr(job_registry, "enqueue", lambda _cur, spec: calls.append(spec))
    job_registry.schedule_jobs(Connection([datetime(2026, 1, 1, tzinfo=timezone.utc)]),
                               ad_gpo_jobs.registry(), "long", source)
    assert len(calls) == 1
    assert calls[0]["handler_id"] == "gpo-snapshot"
    assert calls[0]["rights_profile"] == "gpo-read"


@pytest.mark.parametrize("fence", ["lost", "duplicate"])
def test_fence_prevents_stale_or_duplicate_snapshot_effects(fence):
    conn = Connection([fence])
    if fence == "lost":
        with pytest.raises(job_queue.LeaseLost):
            job_queue.publish(conn, job(), {"status": "success"}, ad_gpo_jobs.apply)
    else:
        assert job_queue.publish(conn, job(), {"status": "success"}, ad_gpo_jobs.apply) == "duplicate"
    assert len(conn.calls) == 1


def test_publisher_refuses_a_running_legacy_writer(monkeypatch):
    conn = Connection([False])
    with pytest.raises(RuntimeError, match="legacy_snapshot_writer_busy"):
        ad_gpo_jobs.apply(conn, job(), {"status": "success"})
    assert len(conn.calls) == 1


def test_old_entrypoints_exit_before_collection_when_enabled(monkeypatch):
    from scripts.runtime import (
        ad_context_snapshot_worker, ad_snapshot_manifest_coordinator_worker,
        ad_snapshot_projection_worker, computers_v6_source_worker, users_report_v2_snapshot_worker,
    )
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    for module in (ad_context_snapshot_worker, ad_snapshot_manifest_coordinator_worker,
                   ad_snapshot_projection_worker, computers_v6_source_worker):
        assert module.main([]) == 0
    assert users_report_v2_snapshot_worker.main() == 0


def test_compose_switch_preserves_legacy_default_and_excludes_worker_when_on():
    import yaml
    compose = yaml.safe_load((ROOT / "deploy/linux/docker-compose.yml").read_text("utf-8"))
    service = compose["services"]["ad-snapshot-manifest-coordinator"]
    assert "profiles" not in service
    assert service["environment"][ad_gpo_jobs.FLAG].endswith(":-0}")
    override = yaml.safe_load((ROOT / "deploy/linux/docker-compose.ad-jobs.yml").read_text("utf-8"))
    assert override["services"]["ad-snapshot-manifest-coordinator"]["profiles"] == ["legacy-ad"]
    for profile in ("heavy", "long"):
        assert compose["services"][f"executor-{profile}"]["environment"][ad_gpo_jobs.FLAG].endswith(":-0}")


def test_ad_flag_alone_activates_executor_without_radius_source(monkeypatch):
    monkeypatch.delenv(job_executor.FLAG, raising=False)
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    calls = []
    conn = Connection([None])
    monkeypatch.setattr(job_executor, "write_heartbeat", lambda *_args, **kwargs: calls.append(kwargs))
    monkeypatch.setattr(job_executor, "connect", lambda *_: nullcontext(conn))
    monkeypatch.setattr(ad_gpo_jobs, "schedule", lambda *_: None)
    monkeypatch.setattr(job_queue, "claim", lambda *_: None)
    job_executor.STOP.clear()
    assert job_executor.serve("heavy", once=True) == 0
    assert calls == [{"enabled": True}]


def test_default_legacy_projection_shim_still_delegates(monkeypatch):
    from scripts.runtime import ad_snapshot_projection_worker as worker
    monkeypatch.delenv(ad_gpo_jobs.FLAG, raising=False)
    conn = object()
    monkeypatch.setattr(worker, "connect", lambda: nullcontext(conn))
    monkeypatch.setattr(worker, "run_exact_manifest_projection_cycle",
                        lambda connection, **kwargs: {"status": "completed", **kwargs})
    assert worker.run_once(manifest_id=MANIFEST_ID)["manifest_id"] == MANIFEST_ID


class SnapshotConnection:
    """In-memory repository fake; real projector, persistence and cycle run unchanged."""
    def __init__(self, *, finish=True):
        self.manifest = stored_manifest()
        self.manifest["members"] = [
            {"family": family, "source_id": str(index), "payload_sha256": "b" * 64}
            for index, family in enumerate(("ad_context_base", "users_v2", "computers_v6", "gpo_v2"), 1)
        ]
        self.exact = {str(index): {"items": [{"id": index}], "count": 1}
                      for index in range(1, 5)}
        self.receipts = {key: {"manifest_id": MANIFEST_ID, "projection_key": key,
            "projection_version": version, "status": "pending", "attempt_count": 0}
            for key, version in ad_snapshot_projection.PROJECTION_ALLOWLIST.items()}
        self.outputs = {}
        self.calls = []
        self.finish = finish

    @contextmanager
    def transaction(self):
        before = deepcopy((self.receipts, self.outputs))
        try:
            yield
        except Exception:
            self.receipts, self.outputs = before
            raise

    def cursor(self, **kwargs):
        return SnapshotCursor(self)


class SnapshotCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def execute(self, sql, params=None):
        sql = " ".join(sql.lower().split())
        db = self.connection
        db.calls.append((sql, params))
        self.rows = []
        if "begin_core_job_result_v1" in sql:
            self.rows = [("publish",)]
        elif "finish_core_job_result_v1" in sql:
            self.rows = [(db.finish,)]
        elif "pg_try_advisory_lock" in sql:
            self.rows = [(True,)]
        elif "set_config" in sql:
            pass
        elif "from ad_snapshot_manifest_sources" in sql:
            self.rows = deepcopy(db.manifest["members"])
        elif "from ad_snapshot_manifests" in sql:
            self.rows = [deepcopy(db.manifest)]
        elif "with candidates as" in sql:
            keys = params[3] or tuple(db.receipts)
            for key in keys:
                row = db.receipts[key]
                if row["status"] == "pending":
                    row.update(status="running", attempt_count=row["attempt_count"] + 1,
                               lease_owner=params[6])
                    self.rows.append(deepcopy(row))
        elif "insert into ad_snapshot_projection_receipts" in sql:
            pass  # The manifest publication already created these receipts.
        elif "from ad_snapshot_projection_receipts" in sql:
            self.rows = deepcopy(list(db.receipts.values()))
        elif "insert into ad_snapshot_projection_outputs" in sql:
            key = params[1]
            db.outputs.setdefault(key, {
                "manifest_id": params[0], "projection_key": key, "projection_version": params[2],
                "input_sha256": params[3].hex(), "output_sha256": params[4].hex(),
                "output_identity": params[5], "payload_json": json.loads(params[6]),
            })
        elif "from ad_snapshot_projection_outputs" in sql:
            row = db.outputs.get(params[1])
            self.rows = [deepcopy(row)] if row else []
        elif "update ad_snapshot_projection_receipts" in sql and "status='completed'" in sql:
            row = db.receipts[params[4]]
            assert row["lease_owner"] == params[-1]
            row.update(status="completed", input_sha256=bytes.fromhex(params[0]),
                       output_sha256=bytes.fromhex(params[1]), output_identity=params[2], lease_owner=None)
        elif any(f"from {table}" in sql for table in (
            "ad_context_runs", "users_report_v2_snapshots", "computers_v6_source_snapshots",
            "gpo_report_v2_source_snapshots",
        )):
            self.rows = [{"payload_json": deepcopy(db.exact[params[0]]), "payload_sha256": "b" * 64}]
        else:
            raise AssertionError(f"Unexpected repository operation: {sql}")

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


@pytest.mark.parametrize("handler_id,projection_key", [
    ("ad-snapshot-manifest-coordinator", "ad.state"),
    ("ad-snapshot-projection", "ad.computers.v6"),
    ("users-report-v2-snapshot", "ad.users.v2"),
    ("gpo-snapshot", "ad.gpo.v2"),
])
def test_old_cycle_and_fenced_handler_persist_identical_outputs(handler_id, projection_key):
    legacy = SnapshotConnection()
    old_result = ad_snapshot_projection.run_exact_manifest_projection_cycle(
        legacy, manifest_id=MANIFEST_ID, worker_id="synthetic-legacy")
    assert old_result["status"] == "completed"
    queued = SnapshotConnection()
    spec = job(handler_id)
    staged = ad_gpo_jobs.stage(queued, spec)
    assert queued.outputs == {}  # Executor computation has no permanent side effects.
    assert staged["composition"] == {"version": 1, "parts": ["base_ad", "gpo"]}
    assert job_queue.publish(queued, spec, staged, ad_gpo_jobs.apply) == "committed"
    assert json.loads(queued.calls[-1][1][-1])["composition"] == staged["composition"]
    assert queued.outputs == {projection_key: legacy.outputs[projection_key]}
    assert queued.receipts[projection_key]["status"] == "completed"
    assert all(row["status"] == "pending" for key, row in queued.receipts.items() if key != projection_key)
    expected = old_result["projection_results"][projection_key]
    assert staged["projection_results"][projection_key] == {
        key: expected[key] for key in ("input_sha256", "output_sha256", "output_identity")}


def test_expired_publication_rolls_back_snapshot_output_and_receipt():
    queued = SnapshotConnection(finish=False)
    spec = job()
    staged = ad_gpo_jobs.stage(queued, spec)
    with pytest.raises(job_queue.LeaseLost):
        job_queue.publish(queued, spec, staged, ad_gpo_jobs.apply)
    assert queued.outputs == {}
    assert all(row["status"] == "pending" for row in queued.receipts.values())


def test_source_partial_coverage_is_not_promoted_to_complete():
    conn = SnapshotConnection()
    conn.manifest["coverage_state"] = "partial"
    result = ad_gpo_jobs.stage(conn, job())
    assert result["status"] == "partial"
    assert result["coverage_state"] == "partial"


def test_changed_staged_result_rolls_back_before_snapshot_dml():
    conn = SnapshotConnection()
    spec = job()
    result = ad_gpo_jobs.stage(conn, spec)
    result["projection_results"]["ad.state"]["output_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="snapshot_result_changed"):
        job_queue.publish(conn, spec, result, ad_gpo_jobs.apply)
    assert conn.outputs == {}
    assert all(row["status"] == "pending" for row in conn.receipts.values())


def test_projection_record_budget_refuses_oversized_stored_input_without_writes():
    conn = SnapshotConnection()
    spec = job()
    spec["budget"]["max_records"] = 1
    conn.exact["1"]["items"].append({"id": 2})
    with pytest.raises(ValueError, match="snapshot_projection_failed"):
        ad_gpo_jobs.stage(conn, spec)
    assert conn.outputs == {}


def test_projection_failure_does_not_disclose_source_details(monkeypatch):
    from server.ad_context import repository
    monkeypatch.setattr(repository, "load_exact_projection_source",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic-private-field")))
    with pytest.raises(ValueError) as error:
        ad_gpo_jobs.stage(SnapshotConnection(), job())
    assert str(error.value) == "snapshot_projection_failed"


def test_scheduler_respects_independent_gpo_disable(monkeypatch):
    conn = SnapshotConnection()
    registry = ad_gpo_jobs.registry()
    # The bundled navigation declaration is the existing in-place enable axis.
    monkeypatch.setattr(ad_gpo_jobs.json, "loads", lambda *_: {"enabled_plugins": ["sli.ad"]})
    ad_gpo_jobs.schedule(conn, registry, "long")
    assert conn.calls == []


def test_filtered_claim_cannot_escape_plugin_ownership():
    conn = SnapshotConnection()
    with pytest.raises(ad_snapshot_projection.ProjectionConflictError, match="plugin ownership"):
        ad_snapshot_projection.run_exact_manifest_projection_cycle(
            conn, manifest_id=MANIFEST_ID, worker_id="synthetic-core",
            projection_keys=("ad.state",),
            claim_receipts=lambda *_args, **_kwargs: [{"manifest_id": MANIFEST_ID,
                "projection_key": "ad.gpo.v2", "projection_version": 1}],
        )
    assert conn.outputs == {}


@pytest.mark.parametrize("keys", [(), ("unregistered",), ("ad.state", "ad.state")])
def test_cycle_rejects_invalid_projection_selection(keys):
    with pytest.raises(ValueError, match="projection key"):
        ad_snapshot_projection.run_exact_manifest_projection_cycle(
            None, manifest_id=MANIFEST_ID, worker_id="synthetic-core", projection_keys=keys)


def test_disabled_gpo_blocks_its_jobs_without_disabling_ad(monkeypatch):
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad"}))
    conn = SnapshotConnection()
    assert ad_gpo_jobs.stage(conn, job())["status"] == "success"
    result = ad_gpo_jobs.stage(conn, job("gpo-snapshot"))
    assert result["status"] == "blocked" and result["error_code"] == "snapshot_plugin_disabled"
    assert conn.outputs == {}


def test_disable_between_stage_and_publish_prevents_effects(monkeypatch):
    conn = SnapshotConnection()
    spec = job("gpo-snapshot")
    staged = ad_gpo_jobs.stage(conn, spec)
    monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset({"sli.ad"}))
    with pytest.raises(RuntimeError, match="snapshot_plugin_disabled"):
        job_queue.publish(conn, spec, staged, ad_gpo_jobs.apply)
    assert conn.outputs == {}


def test_snapshot_child_receives_only_flag_and_its_profile_credentials(monkeypatch):
    monkeypatch.setenv("SLI_JOB_EXECUTOR_HEAVY_PASSWORD_FILE", "synthetic-file")
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    monkeypatch.setenv("ADLOG_PG_DSN", "synthetic-admin-connection")
    monkeypatch.setattr(job_executor, "connection_settings", lambda *_: {"user": "synthetic-heavy-executor"})
    process = SimpleNamespace(pid=123, returncode=0, poll=lambda: 0)
    environments = []
    def popen(_argv, **kwargs):
        environments.append(kwargs["env"])
        kwargs["stdout"].write(b'{"status":"success"}')
        kwargs["stdout"].flush()
        return process
    job_executor.run_child(job(), "handler", deadline=1, clock=lambda: 0,
                           popen=popen, terminate=lambda _: None)
    assert environments[0][ad_gpo_jobs.FLAG] == "1"
    assert "ADLOG_PG_DSN" not in environments[0]
    assert json.loads(environments[0]["SLI_JOB_CHILD_CONNECTION"])["user"] == "synthetic-heavy-executor"


def test_ad_flag_alone_provisions_existing_profile_logins(monkeypatch):
    from deploy.linux import migrate
    monkeypatch.delenv(job_executor.FLAG, raising=False)
    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    monkeypatch.setattr(migrate, "secret_value", lambda _: "synthetic-password")
    for profile in ("light", "heavy", "long"):
        for purpose in ("dispatcher", "executor", "publisher"):
            monkeypatch.setenv(f"SLI_JOB_{purpose.upper()}_{profile.upper()}_PASSWORD_FILE", "synthetic-file")
    calls = []
    class LoginConnection:
        def transaction(self):
            return nullcontext()
        def execute(self, statement, params=None):
            if isinstance(statement, str) and "from pg_roles" in statement:
                calls.append(params[0])
            return SimpleNamespace(fetchone=lambda: (False,))
    migrate.configure_job_logins(LoginConnection())
    assert set(calls) == {f"sli_job_{purpose}_{profile}" for profile in ("light", "heavy", "long")
                          for purpose in ("dispatcher", "executor", "publisher")}


@pytest.mark.parametrize("handler_id", [
    "ad-snapshot-manifest-coordinator", "ad-snapshot-projection", "users-report-v2-snapshot", "gpo-snapshot",
    "ad-context-snapshot", "computers-v6-source", "gpo-acquisition",
])
@pytest.mark.parametrize("purpose", ["handler", "publisher"])
def test_child_uses_reviewed_registry_pinning_and_admission_through_commit(handler_id, purpose, monkeypatch):
    import io
    import resource

    import psycopg
    from server.sli.plugins import update_runtime

    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    spec = job(handler_id)
    conn = SnapshotConnection()
    spec["staged_result"] = ad_gpo_jobs.stage(conn, spec)
    events = []

    @contextmanager
    def admitted(plugin_id):
        assert plugin_id == spec["plugin_id"]
        events.append("admitted")
        yield
        events.append("released")

    @contextmanager
    def connected(**settings):
        assert events == ["admitted"]
        events.append("connected")
        yield conn
        events.append("committed")

    def pin(*args):
        assert args[:3] == (spec["plugin_id"], spec["plugin_version"], spec["manifest_sha256"])
        assert args[3] == job_registry.ROOT / f"config/plugin_packages/{spec['plugin_id']}.jobs-v3.json"
        events.append("pinned")
        update_runtime.pin_job(*args)

    monkeypatch.setattr(job_executor, "admission", admitted)
    monkeypatch.setattr(job_executor, "pin_job", pin)
    monkeypatch.setattr(psycopg, "connect", connected)
    monkeypatch.setattr(job_executor, "child_connection_settings", lambda *_: {})
    limits = []
    monkeypatch.setattr(resource, "setrlimit", lambda key, value: limits.append((key, value)))
    monkeypatch.setattr(job_executor.sys, "stdin", io.StringIO(json.dumps(spec)))
    monkeypatch.setattr(job_executor.sys, "stdout", io.StringIO())
    assert job_executor.child_main(spec["resource_profile"], purpose) == 0
    actual = json.loads(job_executor.sys.stdout.getvalue())
    expected = spec["staged_result"] if purpose == "handler" else {"status": "committed"}
    assert actual == expected
    assert events == ["admitted", "connected", "pinned", "committed", "released"]
    assert limits == [
        (resource.RLIMIT_AS, (spec["budget"]["memory_bytes"],) * 2),
        (resource.RLIMIT_CPU, (spec["budget"]["cpu_seconds"],) * 2),
        (resource.RLIMIT_FSIZE, (spec["budget"]["max_result_bytes"],) * 2),
        (resource.RLIMIT_CORE, (0, 0)),
    ]


@pytest.mark.parametrize("handler_id", [
    "ad-snapshot-manifest-coordinator", "ad-snapshot-projection", "users-report-v2-snapshot", "gpo-snapshot",
])
@pytest.mark.parametrize("fence", ["drain", "disable", "expired"])
def test_registered_publication_fences_roll_back_output_and_receipts(handler_id, fence, tmp_path, monkeypatch):
    from server.sli.plugins import registry, update_runtime

    monkeypatch.delenv("SLI_PLUGIN_RUNTIME_DIR", raising=False)
    monkeypatch.delenv("SLI_PLUGIN_LOCK_DIR", raising=False)
    monkeypatch.setattr(update_runtime, "_pinned", {})
    conn = SnapshotConnection(finish=fence != "expired")
    spec = job(handler_id)
    stage, apply = registry.plugin_job_handlers(spec["plugin_id"], handler_id)
    staged = stage(conn, spec)
    if fence == "drain":
        base = tmp_path / spec["plugin_id"]
        base.mkdir()
        (base / "draining.json").write_text("{}", encoding="utf-8")
        monkeypatch.setenv("SLI_PLUGIN_RUNTIME_DIR", str(tmp_path))
        error, reason = RuntimeError, "plugin_update_draining"
    elif fence == "disable":
        monkeypatch.setattr(ad_gpo_jobs, "allowed_plugins", lambda: frozenset())
        error, reason = RuntimeError, "snapshot_plugin_disabled"
    else:
        error, reason = job_queue.LeaseLost, "job_lease_lost"
    with pytest.raises(error, match=reason):
        job_queue.publish(conn, spec, staged, apply)
    assert conn.outputs == {}
    assert all(row["status"] == "pending" for row in conn.receipts.values())


@pytest.mark.parametrize("handler_id", [
    "ad-snapshot-manifest-coordinator", "ad-snapshot-projection", "users-report-v2-snapshot", "gpo-snapshot",
])
@pytest.mark.parametrize("field,value", [
    ("manifest_sha256", "f" * 64), ("handler_version", "2.0.0"), ("input_sha256", "f" * 64),
])
def test_child_rejects_changed_identity_before_connect(handler_id, field, value, monkeypatch):
    import io

    import psycopg

    monkeypatch.setenv(ad_gpo_jobs.FLAG, "1")
    spec = {**job(handler_id), field: value}
    monkeypatch.setattr(job_executor.sys, "stdin", io.StringIO(json.dumps(spec)))
    monkeypatch.setattr(psycopg, "connect", lambda **_kwargs: pytest.fail("unresolved job connected"))
    with pytest.raises(ValueError, match="handler_version_unavailable|job_input_hash_conflict"):
        job_executor.child_main(spec["resource_profile"], "handler")
