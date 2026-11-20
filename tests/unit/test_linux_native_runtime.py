"""Native systemd contracts with fake commands/DBs; no installed acceptance."""
import hashlib
import json
import os
from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import healthcheck, native_backup, native_host
from deploy.linux import native_runtime as native
from server.sli.core import job_executor
from server.sli.sources import plugin_runtime_heartbeat

REAL_OBSERVE = native.observe
REAL_RECEIPT = native_host.Host.receipt

@pytest.fixture(autouse=True)
def native_clickhouse_mode(monkeypatch):
    monkeypatch.setattr(native.clickhouse, "configured_mode", lambda root=Path("/"): "native")


@pytest.fixture
def config():
    return {"schema_version": 1, "profiles": ["light"], "radius_pilot": False,
            "bind": "127.0.0.1", "health_url": "https://127.0.0.1:8443/api/health/ready"}


@pytest.fixture
def identity(monkeypatch):
    row = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "42",
           "ExecMainStartTimestampMonotonic": "95000000", "InvocationID": "a" * 32,
           "NRestarts": "0", "ControlGroup": "/sli.slice/sli-api.service"}
    monkeypatch.setattr(native, "systemd", lambda service: dict(row))
    monkeypatch.setattr(native, "process_start", lambda pid: 95.0)
    monkeypatch.setattr(native.time, "monotonic", lambda: 100.0)
    return row


def test_all_writers_have_dependencies_credentials_and_sandbox(config):
    rendered = {**native.units(config), **native.dotnet_units("test", config)}
    inventory = json.loads(Path(native_host.__file__).with_name("secrets-manifest.json").read_text())["secrets"]
    assert "sli-migrate.service" not in rendered
    for service in native.selected(config):
        user = native.SERVICES[service][0]
        body = rendered[native.dotnet_unit_name(service)]
        for setting in ("Type=simple", "PartOf=sli-dotnet.target", "BindsTo=sli-ready.service",
                        "After=sli-ready.service", "Requires=sli-ready.service", f"User={user}",
                        "WorkingDirectory=/opt/sli/dotnet/test", "KillMode=control-group", "Restart=on-failure",
                        "StartLimitIntervalSec=0", "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                        "PrivateDevices=yes", "CapabilityBoundingSet=" + ("CAP_CHOWN" if service == "notification-setup" else ""), "NoNewPrivileges=yes",
                        f"RuntimeDirectory=sli/{service}", "RuntimeDirectoryMode=0700"):
            assert setting + "\n" in body
        assert "SupplementaryGroups=sli-secrets" not in body
        assert "postgres_password" not in body and "platform_owner_password" not in body
        loaded = {line.split("=", 2)[1].split(":")[0] for line in body.splitlines() if line.startswith("LoadCredential=")}
        if service == "notification-delivery":
            assert "LoadCredential=notifications:/etc/sli/secrets/notifications\n" in body
            assert {name for name, spec in inventory.items() if spec["group"] == "notifications"} == {
                "notification_telegram_token", "notification_smtp_password"}
            loaded.remove("notifications")
        assert loaded <= inventory.keys()
        assert body.count("ExecStart=") == 1 and "bash" not in body
    assert "After=" + " ".join(native.dotnet_unit_name(s) for s in native.selected(config) if s != "api") in rendered["sli-dotnet-api.service"]
    for db in native.DATABASES:
        assert db in rendered["sli-ready.service"]
        assert db not in rendered["sli-runtime.target"]
    assert "RemainAfterExit=yes" in rendered["sli-ready.service"]
    assert "ReadWritePaths=/run/sli-native-host.lock" in rendered["sli-ready.service"]


def test_only_selected_profiles_start_and_pilot_omits_legacy(config):
    target = native.dotnet_units("test", config)["sli-dotnet.target"]
    assert "sli-dotnet-executor-light.service" in target
    assert "sli-dotnet-executor-heavy.service" not in target
    assert "sli-dotnet-executor-long.service" not in target
    assert "sli-dotnet-remote-access.service" not in target
    config.update(profiles=["light", "heavy"], radius_pilot=True)
    target = native.dotnet_units("test", config)["sli-dotnet.target"]
    assert "sli-remote-access.service" not in target
    assert "sli-dotnet-executor-heavy.service" in target
    assert "TimeoutStopSec=900s" in native.dotnet_units("test", dict(config, profiles=["light", "heavy", "long"]))["sli-dotnet-executor-long.service"]


@pytest.mark.parametrize("profile", ["light", "heavy", "long"])
def test_executor_secrets_never_cross_profiles(config, profile):
    env, secrets = native.environment(f"executor-{profile}", config)
    assert secrets == {f"job_{purpose}_{profile}" for purpose in ("dispatcher", "executor", "publisher")}
    assert "ADLOG_PG_PASSWORD_FILE" not in env
    assert env["SLI_JOB_PG_HOST"] == "127.0.0.1"
    assert env["SLI_EXECUTOR_STATUS_DIR"] == f"/run/sli/executor-{profile}"
    assert all(not key.endswith("_PASSWORD") for key in env)


def test_native_workstation_defaults_and_explicit_opt_in(config, monkeypatch):
    monkeypatch.delenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", raising=False)
    env, _ = native.environment("executor-light", config)
    assert env["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"] == "0"
    assert env["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] == "0"
    assert env["SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS"] == "90"
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "1")
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_RETENTION", "1")
    for service in ("executor-light", "post-collection"):
        explicit, _ = native.environment(service, config)
        assert explicit["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"] == "1"
        assert explicit["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] == "1"


def test_worker_paths_and_dedicated_logins(config):
    env, secrets = native.environment("post-collection", config)
    assert secrets == {"runtime_password", "storage_password", "context_password"}
    assert "user=sli_storage_login" in env["ADLOG_STORAGE_V2_WORKER_DSN"]
    env, secrets = native.environment("storage-lifecycle", config)
    assert "warm_password" not in secrets
    assert "ADLOG_STORAGE_LIFECYCLE_DELETE_EXECUTION_ENABLED" not in env
    assert not any("CLICKHOUSE" in name for name in env)
    env, _ = native.environment("remote-access", config)
    assert env["SLI_PLUGIN_HEARTBEAT_DIR"] == "/run/sli/remote-access"


def test_agent_issuer_is_opt_in_and_only_given_to_api(config):
    _, secrets = native.environment("api", config)
    assert "agent_issuer_key" not in secrets
    config["agents"] = True
    env, secrets = native.environment("api", config)
    assert env["SLI_AGENT_CA_ISSUER_KEY_FILE"] == "%d/agent_issuer_key"
    assert "agent_root_key" not in secrets
    assert "agent_issuer_key" not in native.environment("post-collection", config)[1]


@pytest.mark.parametrize("field,value", [("ActiveState", "failed"), ("SubState", "auto-restart"),
                                         ("LoadState", "not-found"), ("MainPID", "0"),
                                         ("NRestarts", "5"), ("InvocationID", ""),
                                         ("ExecMainStartTimestampMonotonic", "0")])
def test_health_rejects_crash_loop_and_inactive_unit_before_probe(identity, monkeypatch, field, value):
    identity[field] = value
    monkeypatch.setattr(healthcheck, "healthy", lambda *a, **kw: pytest.fail("must not probe"))
    assert not native.healthy_service("api")


def test_health_rejects_reused_pid_before_probe(identity, monkeypatch):
    monkeypatch.setattr(native, "process_start", lambda pid: 80.0)
    monkeypatch.setattr(healthcheck, "healthy", lambda *a, **kw: pytest.fail("must not probe"))
    assert not native.healthy_service("semantic")


@pytest.mark.parametrize("service,path", [("api", None), ("semantic", None),
    ("executor-light", Path("/run/sli/executor-light/sli-executor-light.json")),
    ("notification-delivery", Path("/run/sli/notification-delivery/heartbeat.json")),
    ("notification-setup", Path("/run/sli/notification-setup/control.sock")),
    ("remote-access", Path("/run/sli/remote-access/plugin-radius-session-observation.json"))])
def test_health_binds_probe_to_main_pid_and_current_start(identity, monkeypatch, service, path):
    calls = []
    monkeypatch.setattr(healthcheck, "healthy", lambda *a, **kw: calls.append((a, kw)) or True)
    assert native.healthy_service(service)
    params = calls[0][1]
    assert params["process_pid"] == 42 and params["status_path"] == path
    assert 4.9 < (datetime.now(timezone.utc) - params["started_at"]).total_seconds() < 5.1


def test_health_rechecks_identity_after_probe(identity, monkeypatch):
    def changed(*args, **kwargs):
        identity["InvocationID"] = "b" * 32
        return True
    monkeypatch.setattr(healthcheck, "healthy", changed)
    assert not native.healthy_service("semantic")


def test_old_restarts_do_not_permanently_reject_recovered_worker(identity, monkeypatch):
    identity.update(NRestarts="5", ExecMainStartTimestampMonotonic="1000000")
    monkeypatch.setattr(native.time, "monotonic", lambda: 500.0)
    monkeypatch.setattr(native, "process_start", lambda pid: 1.0)
    monkeypatch.setattr(healthcheck, "healthy", lambda *a, **kw: True)
    assert native.healthy_service("semantic")


@pytest.mark.parametrize("age,pid,valid", [(0, 42, True), (121, 42, False), (-60, 42, False),
                                         (0, 99, False), (20, 42, False)])
def test_native_executor_heartbeat_requires_freshness_and_start(tmp_path, age, pid, valid):
    now = datetime.now(timezone.utc)
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"profile": "light", "pid": pid, "at_utc": (now - timedelta(seconds=age)).isoformat()}))
    assert healthcheck.healthy("executor-light", process_pid=42, started_at=now - timedelta(seconds=10), status_path=path) is valid


def test_native_remote_heartbeat_cannot_bypass_main_pid_for_pilot(tmp_path, monkeypatch):
    now = datetime.now(timezone.utc)
    path = tmp_path / "remote.json"
    row = {"plugin_id": "sli.remote-access", "component_id": "radius-session-observation", "process_pid": 42,
           "status": "idle", "heartbeat_at_utc": now.isoformat()}
    path.write_text(json.dumps(row))
    monkeypatch.setattr(job_executor, "pilot_enabled", lambda: True)
    assert healthcheck.healthy("radius-session-observation", process_pid=42, started_at=now - timedelta(seconds=1), status_path=path)
    row["process_pid"] = 1
    path.write_text(json.dumps(row))
    assert not healthcheck.healthy("radius-session-observation", process_pid=42, started_at=now - timedelta(seconds=1), status_path=path)


def test_db_health_uses_native_pid_and_start_as_sql_parameters(monkeypatch):
    import psycopg
    captured = []
    conn = SimpleNamespace(execute=lambda sql, params: captured.append((sql, params)) or SimpleNamespace(fetchone=lambda: (True,)))
    monkeypatch.setattr(healthcheck, "load_config", lambda: SimpleNamespace(postgres_dsn="synthetic"))
    monkeypatch.setattr(psycopg, "connect", lambda *a, **kw: nullcontext(conn))
    start = datetime.now(timezone.utc)
    assert healthcheck.healthy("semantic", process_pid=42, started_at=start)
    sql, params = captured[0]
    assert params == ("semantic", 120, 42, start, start)
    assert "process_pid = %s" in sql and "heartbeat_at >= %s" in sql
    assert "heartbeat_at <= now()" in sql and "connect" not in sql.lower()


def test_executor_and_plugin_writers_use_explicit_run_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_EXECUTOR_STATUS_DIR", str(tmp_path))
    monkeypatch.setenv("SLI_PLUGIN_HEARTBEAT_DIR", str(tmp_path))
    job_executor.write_heartbeat("light", enabled=True)
    row = json.loads((tmp_path / "sli-executor-light.json").read_text())
    assert row["pid"] == os.getpid() and row["profile"] == "light"
    assert not list(tmp_path.glob("*.tmp"))
    assert plugin_runtime_heartbeat.plugin_heartbeat_path("component") == tmp_path / "plugin-component.json"
    monkeypatch.delenv("SLI_PLUGIN_HEARTBEAT_DIR")
    assert plugin_runtime_heartbeat.plugin_heartbeat_path("component").parent == plugin_runtime_heartbeat.HEARTBEAT_DIR


@pytest.fixture
def accepted(tmp_path, monkeypatch, config):
    source = tmp_path / "release"
    migrations = source / "config/postgres_migrations"
    migrations.mkdir(parents=True)
    sql = migrations / "001_synthetic.sql"
    sql.write_text("-- synthetic migration\n")
    ledger = [{"version": 1, "name": "synthetic", "sha256": hashlib.sha256(sql.read_bytes()).hexdigest()}]
    manifest = {"schema_version": 1, "migration_ledger": ledger, "plugins": {}, "roles": [["adlog_user", False]],
                "postgres_version": "18.6", "clickhouse_version": "26.8.35.10"}
    installed = {**deepcopy(manifest), "release": str(source), "manifest_sha256": "digest"}
    transactions = tmp_path / "transactions"
    transactions.mkdir()
    monkeypatch.setattr(native, "TRANSACTIONS", transactions)
    monkeypatch.setattr(native, "release", lambda: (source, manifest, "digest"))
    monkeypatch.setattr(native, "document", lambda path: installed if path.name == "installed.json" else json.loads(path.read_text()))
    monkeypatch.setattr(native, "configuration", lambda: config)
    monkeypatch.setattr(native, "observe", lambda root, state: ("18.6", ["26.8.35.10"] * 2, deepcopy(ledger)))
    monkeypatch.setattr(native_host, "administrative_lock", lambda: nullcontext())
    monkeypatch.setattr(native_host.Host, "receipt", lambda self: None)
    monkeypatch.setattr(native_host, "validate_identity", lambda: None)
    return SimpleNamespace(root=source, manifest=manifest, installed=installed, ledger=ledger, transactions=transactions)


def test_ready_checks_inventory_without_migrating(accepted, monkeypatch):
    from deploy.linux import migrate
    monkeypatch.setattr(migrate, "migrate", lambda: pytest.fail("ready must never migrate"))
    assert native.ready()


def test_ready_directory_storage_accepts_readonly_sandbox(accepted, tmp_path, monkeypatch):
    machine = native_host.Host(tmp_path)
    machine.path('/var/lib/sli-db').mkdir(parents=True)
    receipt = machine.path(native_host.STATE + '/host-prepared.json')
    receipt.parent.mkdir(parents=True)
    receipt.write_text(json.dumps({'version': 1, 'mount': '/srv/sli-db', 'uuid': None,
                                  'storage_mode': 'directory', 'directory': '/var/lib/sli-db',
                                  'clickhouse_mode': 'native'}))
    monkeypatch.setattr(machine, 'validate_receipt_file', lambda path: None)
    monkeypatch.setattr(machine, 'backup_trusted', lambda path: None)
    monkeypatch.setattr(machine, 'backup_mounted', lambda source, target: True)
    monkeypatch.setattr(machine, 'vendor_guards', lambda: None)
    monkeypatch.setattr(native_host, 'run', lambda argv: json.dumps({'filesystems': [
        {'fstype': 'ext4', 'options': 'ro,relatime'}]}))
    monkeypatch.setattr(native_host.Host, 'receipt', lambda self: REAL_RECEIPT(machine))
    assert native.ready()


@pytest.mark.parametrize("drift", [None, "unknown", "version", "manifest"])
def test_ready_adopts_docker_ledger_with_bundled_vpn_through_read_only_observer(accepted, monkeypatch, drift):
    import urllib.request

    import psycopg

    from deploy.linux import installed_state, native_pg_inventory, native_plugins

    root = Path(__file__).resolve().parents[2]
    ledger = []
    for line in (root / "tests/fixtures/native_docker_ledger.txt").read_text().splitlines():
        version, name, checksum = line.split("|")
        ledger.append((int(version), name, checksum))
    # Migrations newer than the stand are applied natively (LF digests) before readiness.
    ledger += [(row["version"], row["name"], row["sha256"]) for row in native_pg_inventory.expected_ledger(root)
               if row["version"] > ledger[-1][0]]
    plugins = native_plugins.release_inventory(root, {key: {"version": "1.0.0"} for key in
        ("sli.ad", "sli.gpo", "sli.file-audit", "sli.workstations", "sli.sigma")})
    rows = [(key, value["version"], value.get("manifest_sha256", "other")) for key, value in plugins.items()]
    if drift == "unknown":
        rows.append(("sli.unknown", "0.1.0", "0" * 64))
    elif drift in {"version", "manifest"}:
        rows[-1] = ("sli.remote-access", "9.0.0" if drift == "version" else "0.1.0",
                    "0" * 64 if drift == "manifest" else native_plugins.REMOTE_HASH)
    accepted.manifest.update(migration_ledger=native_pg_inventory.expected_ledger(root), plugins=plugins)
    accepted.installed.update(deepcopy(accepted.manifest), release=str(root))

    class Connection:
        def execute(self, query, params=None):
            assert query.startswith(("SELECT", "SHOW", "SET TRANSACTION"))
            if query.startswith("SHOW"):
                return SimpleNamespace(fetchone=lambda: ("18.6",))
            result = (ledger if "schema_migrations" in query else rows if "plugin_installations" in query
                      else accepted.installed["roles"] if "pg_roles" in query else [])
            return SimpleNamespace(fetchall=lambda: result)

    # Restore the real observer hidden by the generic accepted fixture.
    monkeypatch.setattr(native, "observe", REAL_OBSERVE)
    monkeypatch.setattr(native, "release", lambda: (root, accepted.manifest, "digest"))
    monkeypatch.setattr(psycopg, "connect", lambda **kwargs: nullcontext(Connection()))
    monkeypatch.setattr(native_host, "credential", lambda name: "synthetic-only")
    monkeypatch.setattr(installed_state, "pointers_match", lambda *args: None)
    monkeypatch.setattr(urllib.request, "urlopen", lambda *args, **kwargs: nullcontext(
        SimpleNamespace(status=200, read=lambda limit: b"26.8.35.10")))
    if drift:
        with pytest.raises(ValueError, match="native_plugins_.*mismatch"):
            native.ready()
    else:
        assert native.ready()


@pytest.mark.parametrize("key,value", [("release", "/foreign"), ("manifest_sha256", "different"),
    ("plugins", {"sli.synthetic": {"version": "2"}}), ("migration_ledger", []), ("roles", [])])
def test_ready_rejects_registry_drift_before_sql(accepted, monkeypatch, key, value):
    accepted.installed[key] = value
    monkeypatch.setattr(native, "observe", lambda *a: pytest.fail("must fail before SQL"))
    with pytest.raises(native.RuntimeErrorCode):
        native.ready()


@pytest.mark.parametrize("pg", ["17.9", "18.5"])
def test_ready_requires_exact_postgres_version(accepted, monkeypatch, pg):
    monkeypatch.setattr(native, "observe", lambda *a: (pg, [], accepted.ledger))
    with pytest.raises(native.RuntimeErrorCode, match="version_mismatch"):
        native.ready()


def test_ready_rejects_different_live_ledger(accepted, monkeypatch):
    ledger = deepcopy(accepted.ledger)
    ledger[0]["name"] = "other"
    monkeypatch.setattr(native, "observe", lambda *a: ("18.6", ["26.8.35.10"] * 2, ledger))
    with pytest.raises(Exception, match="ledger_mismatch"):
        native.ready()


@pytest.mark.parametrize("status,valid", [("running", False), ("failed", False), ("committed", True), ("rolled_back", True)])
def test_transaction_requires_durable_terminal_result(accepted, status, valid):
    directory = accepted.transactions / "synthetic"
    directory.mkdir()
    (directory / "result.json").write_text(json.dumps({"schema_version": 1, "status": status}))
    if valid:
        assert native.ready()
    else:
        with pytest.raises(native.RuntimeErrorCode, match="transaction_pending"):
            native.ready()


def test_missing_transaction_result_fences_readiness(accepted):
    (accepted.transactions / "interrupted").mkdir()
    with pytest.raises(OSError):
        native.ready()


@pytest.mark.parametrize('marker,phase,release,allowed', [
    ('synthetic', 'candidate_testing', 'synthetic', True),
    ('other', 'candidate_testing', 'synthetic', False),
    ('synthetic', 'migrating', 'synthetic', False),
    ('synthetic', 'candidate_testing', 'other', False),
])
def test_only_volatile_coordinator_override_admits_testing(accepted, monkeypatch, marker, phase, release, allowed):
    directory = accepted.transactions / 'synthetic'
    directory.mkdir()
    (directory / 'result.json').write_text(json.dumps({'schema_version': 1, 'status': 'checkpoint_verified'}))
    (directory / 'journal.json').write_text(json.dumps({'schema_version': 1, 'status': phase, 'testing_release': release}))
    monkeypatch.setattr(native, 'release', lambda: (Path('/accepted/synthetic'), {}, 'digest'))
    monkeypatch.setenv('SLI_NATIVE_UPGRADE_TRANSACTION', marker)
    if allowed:
        native.no_transaction()
    else:
        with pytest.raises(native.RuntimeErrorCode, match='transaction_pending'):
            native.no_transaction()


def test_health_checks_only_selected_services_after_readiness(accepted, config, monkeypatch):
    calls = []
    monkeypatch.setattr(native_host, "credential", lambda name: "synthetic-not-logged")
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/synthetic/credentials")
    monkeypatch.setattr(native, "healthy_service", lambda s: calls.append(s) or True)
    assert native.health()
    assert calls == list(native.selected(config))
    assert "executor-heavy" not in calls and "executor-long" not in calls


def test_no_health_probe_runs_when_readiness_fails(accepted, monkeypatch):
    accepted.installed["manifest_sha256"] = "wrong"
    monkeypatch.setattr(native, "healthy_service", lambda s: pytest.fail("must not probe"))
    with pytest.raises(native.RuntimeErrorCode):
        native.health()


def test_launch_execs_pinned_python_without_shell(config, monkeypatch):
    captured = {}
    monkeypatch.setattr(native, "release", lambda: (Path("/opt/sli/releases/synthetic"), {"python": "/opt/sli/runtimes/synthetic/bin/python3.14"}, "digest"))
    monkeypatch.setattr(native, "configuration", lambda: config)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/synthetic")
    monkeypatch.setenv("PYTHONPATH", "/untrusted")
    monkeypatch.setenv("SLI_CORE_JOB_WORKSTATIONS_PROJECTION", "0")
    monkeypatch.setattr(native.os, "chdir", lambda path: captured.update(cwd=path))
    monkeypatch.setattr(native.os, "execve", lambda path, argv, env: captured.update(path=path, argv=argv, env=env))
    native.launch("executor-light")
    assert captured["argv"] == [captured["path"], "-B", "-m", "deploy.linux.entrypoint", "executor", "--profile", "light"]
    assert "PYTHONPATH" not in captured["env"]
    assert captured["env"]["SLI_CORE_JOB_WORKSTATIONS_PROJECTION"] == "0"
    assert captured["env"]["SLI_CORE_JOB_WORKSTATIONS_RETENTION"] == "0"
    assert captured["env"]["SLI_WORKSTATION_EVIDENCE_RETENTION_DAYS"] == "90"
    assert captured["env"]["SLI_JOB_EXECUTOR_LIGHT_PASSWORD_FILE"] == "/run/credentials/synthetic/job_executor_light"
    with pytest.raises(native.RuntimeErrorCode, match="profile_disabled"):
        native.launch("executor-heavy")


def test_control_launch_disables_bytecode(config, monkeypatch):
    captured = {}
    monkeypatch.setattr(native, "release", lambda: (Path("/accepted"), {"python": "/pinned/python"}, "digest"))
    monkeypatch.setattr(native, "configuration", lambda: config)
    monkeypatch.setattr(native.os, "chdir", lambda path: None)
    monkeypatch.setattr(native.os, "execve", lambda path, argv, env: captured.update(argv=argv))
    native.launch("ready", control=True)
    assert captured["argv"] == ["/pinned/python", "-B", "-m", "deploy.linux.native_runtime", "ready"]


@pytest.mark.parametrize("mode", ["native", "docker"])
def test_all_native_python_units_disable_bytecode(config, mode):
    bodies = [*native.units(config).values(), *native_host.units(mode).values(), *native_backup.units().values()]
    commands = [line for body in bodies for line in body.splitlines()
                if line.startswith("Exec") and "/usr/bin/python3 " in line]
    assert commands
    assert all(" -B " in line for line in commands)


def test_stop_waits_for_target_and_every_writer_but_keeps_databases(monkeypatch):
    calls = []
    monkeypatch.setattr(native.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)))
    monkeypatch.setattr(native, "systemd", lambda s, **kw: {"ActiveState": "inactive", "MainPID": "0", "ControlGroup": ""})
    assert native.stop_writers()
    assert calls[0][0] == ["systemctl", "stop", "sli-runtime.target", *map(native.unit_name, native.SERVICES)]
    assert not any(db in str(calls) for db in native.DATABASES)


@pytest.mark.parametrize("kind", ["postgres_starting", "postgres_refused", "connection_refused", "timeout"])
def test_ready_waits_for_database_endpoints_without_starting_writers(monkeypatch, kind):
    from urllib.error import URLError

    import psycopg

    class Starting(psycopg.OperationalError):
        sqlstate = "57P03"

    error = {"postgres_starting": Starting("synthetic"),
             "postgres_refused": psycopg.OperationalError("connection failed: Connection refused"),
             "connection_refused": URLError(ConnectionRefusedError()), "timeout": TimeoutError()}[kind]
    expected = ("18.6", ["26.8.35.10"] * 2, [])
    results = iter([error, expected])
    def observe(root, installed):
        result = next(results)
        if isinstance(result, Exception):
            raise result
        return result
    sleeps = []
    monkeypatch.setattr(native, "observe", observe)
    monkeypatch.setattr(native.time, "monotonic", lambda: 0)
    monkeypatch.setattr(native.time, "sleep", sleeps.append)
    assert native.observe_when_available(Path("/synthetic"), {}) == expected
    assert sleeps == [30]


def test_database_startup_wait_has_a_deadline(monkeypatch):
    from urllib.error import URLError

    ticks = iter([0, 900])
    monkeypatch.setattr(native.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(native.time, "sleep", lambda _: pytest.fail("deadline already expired"))
    def unavailable(*args):
        raise URLError(ConnectionRefusedError())
    monkeypatch.setattr(native, "observe", unavailable)
    with pytest.raises(native.RuntimeErrorCode, match="databases_not_ready"):
        native.observe_when_available(Path("/synthetic"), {})


@pytest.mark.parametrize("kind", ["postgres_auth", "postgres_auth_without_sqlstate", "http_auth", "inventory"])
def test_database_startup_does_not_retry_auth_or_inventory_errors(monkeypatch, kind):
    from urllib.error import HTTPError

    import psycopg

    class Authentication(psycopg.OperationalError):
        sqlstate = "28P01"

    error = {"postgres_auth": Authentication("synthetic"),
             "postgres_auth_without_sqlstate": psycopg.OperationalError("password authentication failed"),
             "http_auth": HTTPError("http://127.0.0.1", 401, "synthetic", None, None),
             "inventory": native.RuntimeErrorCode("native_roles_mismatch")}[kind]
    def invalid(*args):
        raise error
    monkeypatch.setattr(native, "observe", invalid)
    monkeypatch.setattr(native.time, "sleep", lambda _: pytest.fail("must fail immediately"))
    with pytest.raises(type(error)) as caught:
        native.observe_when_available(Path("/synthetic"), {})
    assert caught.value is error


@pytest.mark.parametrize("state,pid", [("active", "42"), ("deactivating", "0"), ("failed", "42")])
def test_stop_rejects_live_or_stopping_writers(monkeypatch, state, pid):
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **kw: None)
    monkeypatch.setattr(native, "systemd", lambda s, **kw: {"ActiveState": state, "MainPID": pid, "ControlGroup": ""})
    with pytest.raises(native.RuntimeErrorCode, match="writers_still_running"):
        native.stop_writers()


def test_stop_rejects_populated_descendant_cgroup(monkeypatch):
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **kw: None)
    monkeypatch.setattr(native, "systemd", lambda s, **kw: {"ActiveState": "inactive", "MainPID": "0",
                                                      "ControlGroup": "/sli.slice/sli-api.service"})
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "rglob", lambda self, pattern: [Path("/synthetic/child/cgroup.procs")])
    monkeypatch.setattr(Path, "read_text", lambda self: "99\n")
    with pytest.raises(native.RuntimeErrorCode, match="writers_still_running"):
        native.stop_writers()


@pytest.mark.parametrize("populated", [False, True])
def test_stop_checks_failed_units_even_when_stop_command_fails(monkeypatch, populated):
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **kw: (
        native.subprocess.CompletedProcess(a[0], 1) if not kw.get("check") else
        (_ for _ in ()).throw(native.subprocess.CalledProcessError(1, a[0]))))
    monkeypatch.setattr(native, "systemd", lambda s, **kw: {"ActiveState": "failed", "MainPID": "0",
                                                      "ControlGroup": "/sli.slice/sli-semantic.service"})
    monkeypatch.setattr(Path, "exists", lambda self: True)
    monkeypatch.setattr(Path, "rglob", lambda self, pattern: [self / "cgroup.procs", self / "child/cgroup.procs"])
    monkeypatch.setattr(Path, "read_text", lambda self: "42\n" if populated else "")
    if populated:
        with pytest.raises(native.RuntimeErrorCode, match="writers_still_running"):
            native.stop_writers()
    else:
        assert native.stop_writers()


def test_cli_never_prints_private_exception_text(monkeypatch, capsys):
    monkeypatch.setattr(native.os, "geteuid", lambda: native.ROOT_UID, raising=False)
    def fail():
        raise RuntimeError("synthetic-private-value")
    monkeypatch.setattr(native, "ready", fail)
    assert native.main(["ready"]) == 1
    assert capsys.readouterr().err == "native_runtime_failed reason=RuntimeError\n"


@pytest.mark.parametrize("kind", ["reset", "eof", "http_503", "pg_recovery", "tls_eof"])
def test_ready_survives_cold_start_transport_failures(accepted, monkeypatch, kind):
    import ssl
    from http.client import RemoteDisconnected
    from urllib.error import HTTPError

    import psycopg

    error = {"reset": ConnectionResetError(), "eof": RemoteDisconnected(),
             "http_503": HTTPError("http://127.0.0.1", 503, "private", None, None),
             "pg_recovery": psycopg.OperationalError("server closed the connection unexpectedly"),
             "tls_eof": ssl.SSLEOFError()}[kind]
    results = iter([error, ("18.6", ["26.8.35.10"] * 2, accepted.ledger)])
    def observe(*args):
        result = next(results)
        if isinstance(result, Exception):
            raise result
        return result
    monkeypatch.setattr(native, "observe", observe)
    monkeypatch.setattr(native.time, "sleep", lambda _: None)
    assert native.ready()


@pytest.mark.parametrize("kind", ["certificate", "permission", "http_403", "http_500"])
def test_ready_does_not_retry_permanent_transport_failures(monkeypatch, kind):
    import ssl
    from urllib.error import HTTPError, URLError

    error = {"certificate": URLError(ssl.SSLCertVerificationError("private")),
             "permission": PermissionError("private"),
             "http_403": HTTPError("http://127.0.0.1", 403, "private", None, None),
             "http_500": HTTPError("http://127.0.0.1", 500, "private", None, None)}[kind]
    def observe(*args):
        raise error
    monkeypatch.setattr(native, "observe", observe)
    monkeypatch.setattr(native.time, "sleep", lambda _: pytest.fail("permanent failure must not retry"))
    with pytest.raises(type(error)):
        native.observe_when_available(Path("/synthetic"), {})


def test_cli_prints_fixed_runtime_reason_without_private_text(monkeypatch, capsys):
    monkeypatch.setattr(native.os, "geteuid", lambda: native.ROOT_UID, raising=False)
    def fail():
        raise native.RuntimeErrorCode("native_database_version_mismatch")
    monkeypatch.setattr(native, "ready", fail)
    assert native.main(["ready"]) == 1
    assert capsys.readouterr().err == "native_runtime_failed reason=native_database_version_mismatch\n"


def test_cli_reports_database_deadline(monkeypatch, capsys):
    monkeypatch.setattr(native.os, "geteuid", lambda: native.ROOT_UID, raising=False)
    ticks = iter([0, 900])
    monkeypatch.setattr(native.time, "monotonic", lambda: next(ticks))
    def unavailable(*args):
        raise ConnectionResetError("private")
    monkeypatch.setattr(native, "observe", unavailable)
    monkeypatch.setattr(native, "ready", lambda: native.observe_when_available(Path("/synthetic"), {}))
    assert native.main(["ready"]) == 1
    diagnostic = capsys.readouterr().err
    assert 'No progress' in diagnostic and '"step": "databases_ready"' in diagnostic
    assert diagnostic.endswith("native_runtime_failed reason=native_databases_not_ready\n")


def test_configure_retires_legacy_writers_before_reload_without_starting(config, monkeypatch):
    calls = []
    files = {}
    machine = SimpleNamespace(receipt=lambda: calls.append("receipt"),
                              directory=lambda *a, **kw: calls.append((a, kw)),
                              write=lambda path, body, mode: files.update({path: (body, mode)}))
    monkeypatch.setattr(native_host, "administrative_lock", lambda: nullcontext())
    monkeypatch.setattr(native_host, "Host", lambda: machine)
    monkeypatch.setattr(native_host, "validate_identity", lambda: None)
    monkeypatch.setattr(native_host, "account", lambda name: object())
    monkeypatch.setattr(native_host, "group", lambda name: SimpleNamespace(gr_gid=-1, gr_mem=[]))
    monkeypatch.setattr(native_host, "run", lambda argv, **kw: calls.append(argv) or "")
    monkeypatch.setattr(native_host, "pwd", SimpleNamespace(getpwall=list))
    monkeypatch.setattr(native, "configure_worker_accounts", lambda: None)
    monkeypatch.setattr(native.subprocess, "run", lambda argv, **kw: calls.append(argv))
    monkeypatch.setattr(native, "systemd", lambda service, **kw: {
        "LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0", "ControlGroup": ""})
    native.configure(config)
    stopped = ["systemctl", "stop", *map(native.unit_name, native.SERVICES)]
    disabled = ["systemctl", "disable", *map(native.unit_name, native.SERVICES)]
    assert calls.index(stopped) < calls.index(disabled) < calls.index(["systemctl", "daemon-reload"])
    assert not any(" launch " in body for name, (body, _) in files.items()
                   if name.startswith("/usr/lib/systemd/system/"))
    assert json.loads(files[str(native.CONFIG)][0]) == config
    assert "f /run/sli-native-host.lock 0600 root root" in files["/usr/lib/tmpfiles.d/sli-runtime.conf"][0]
    assert ["systemctl", "daemon-reload"] in calls
    assert not any(isinstance(c, list) and any(v in {"start", "enable", "restart", "apt"} for v in c) for c in calls)
    assert not any("/var/lib/sli/state" in str(c) for c in calls[1:])


@pytest.mark.parametrize("primary", [False, True])
def test_foreign_data_group_refused_before_permission_changes(config, monkeypatch, primary):
    machine = SimpleNamespace(receipt=lambda: None, directory=lambda *a, **kw: pytest.fail("must not modify permissions"))
    monkeypatch.setattr(native_host, "administrative_lock", lambda: nullcontext())
    monkeypatch.setattr(native_host, "Host", lambda: machine)
    monkeypatch.setattr(native_host, "validate_identity", lambda: None)
    monkeypatch.setattr(native_host, "group", lambda name: SimpleNamespace(gr_gid=123, gr_mem=[] if primary else ["foreign"]))
    monkeypatch.setattr(native_host, "pwd", SimpleNamespace(
        getpwall=lambda: [SimpleNamespace(pw_gid=123, pw_name="foreign")] if primary else []))
    with pytest.raises(native.RuntimeErrorCode, match="data_group_conflict"):
        native.configure(config)


@pytest.fixture
def pinned(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX executable/symlink contract; Linux CI")
    releases = tmp_path / "releases"
    release = releases / "synthetic"
    release.mkdir(parents=True)
    python = tmp_path / "runtimes/synthetic/bin/python3.14"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"synthetic-executable")
    python.chmod(0o755)
    current = tmp_path / "current"
    current.symlink_to(release)
    manifest = {"schema_version": 1, "python": str(python), "python_sha256": hashlib.sha256(python.read_bytes()).hexdigest()}
    path = release / "native-runtime.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(native, "CURRENT", current)
    monkeypatch.setattr(native, "RELEASES", releases)
    monkeypatch.setattr(native, "RUNTIMES", tmp_path / "runtimes")
    monkeypatch.setattr(native, "trusted", lambda path: path.read_bytes())
    return SimpleNamespace(root=release, python=python, manifest=manifest, path=path)


def test_release_pins_runtime_binary_before_execution(pinned):
    root, manifest, digest = native.release()
    assert root == pinned.root and manifest == pinned.manifest
    assert digest == hashlib.sha256(pinned.path.read_bytes()).hexdigest()
    pinned.python.write_bytes(b"changed")
    with pytest.raises(native.RuntimeErrorCode, match="python_mismatch"):
        native.release()


@pytest.mark.parametrize("path", ["/usr/bin/python3", "/opt/sli/runtimes/../foreign/bin/python3", "/bin/sh"])
def test_release_refuses_runtime_outside_pinned_prefix(pinned, path):
    pinned.manifest["python"] = path
    pinned.path.write_text(json.dumps(pinned.manifest))
    with pytest.raises(native.RuntimeErrorCode, match="python_invalid"):
        native.release()


def test_runtime_prefix_cannot_be_escaped_with_parent_component(pinned):
    outside = native.RUNTIMES.parent / "bin/python3"
    outside.parent.mkdir()
    outside.write_bytes(pinned.python.read_bytes())
    outside.chmod(0o755)
    pinned.manifest["python"] = str(native.RUNTIMES / "../bin/python3")
    pinned.path.write_text(json.dumps(pinned.manifest))
    with pytest.raises(native.RuntimeErrorCode, match="python_invalid"):
        native.release()


def test_administrative_file_symlinks_and_writable_files_are_rejected(tmp_path, monkeypatch):
    if os.name == "nt":
        pytest.skip("POSIX ownership/modes/symlinks; Linux CI")
    path = tmp_path / "config.json"
    path.write_text("{}")
    path.chmod(0o666)
    monkeypatch.setattr(native, "ROOT_UID", os.geteuid())
    with pytest.raises(native.RuntimeErrorCode, match="untrusted"):
        native.trusted(path)
    link = tmp_path / "link.json"
    link.symlink_to(path)
    with pytest.raises(native.RuntimeErrorCode, match="untrusted"):
        native.trusted(link)


@pytest.mark.parametrize("patch", [{"profiles": ["heavy"]}, {"profiles": ["light", "light"]},
    {"profiles": ["light", "unknown"]}, {"radius_pilot": True}, {"agents": "yes"},
    {"bind": "0.0.0.0", "health_url": "https://0.0.0.0:8443/api/health/ready"},
    {"health_url": "http://127.0.0.1:8443/api/health/ready"}])
def test_invalid_configuration_fails_closed(config, monkeypatch, patch):
    config.update(patch)
    monkeypatch.setattr(native, "document", lambda path: config)
    with pytest.raises(native.RuntimeErrorCode):
        native.configuration()


def test_native_observation_is_read_only_and_needs_no_clickhouse(monkeypatch):
    import urllib.request

    import psycopg

    from deploy.linux import installed_state
    calls = []
    urls = []
    state = {"roles": [["adlog_user", False, False, False, False, False, True]], "plugins": {}}
    class Connection:
        def execute(self, sql, params=None):
            calls.append((sql, params))
            if sql.startswith("SHOW"):
                return SimpleNamespace(fetchone=lambda: ("18.6",))
            rows = []
            if "schema_migrations" in sql:
                rows = [(1, "synthetic", "checksum")]
            elif "pg_roles" in sql:
                rows = state["roles"]
            return SimpleNamespace(fetchall=lambda: rows)
    def connect(**kwargs):
        assert kwargs["host"] == "127.0.0.1" and kwargs["connect_timeout"] == 3
        assert "default_transaction_read_only=on" in kwargs["options"]
        return nullcontext(Connection())
    def urlopen(request, timeout):
        urls.append(request.full_url)
        assert timeout == 5
        return nullcontext(SimpleNamespace(status=200, read=lambda limit: b"26.8.35.10\n"))
    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(native_host, "credential", lambda name: "synthetic-not-logged")
    monkeypatch.setattr(installed_state, "pointers_match", lambda root, installed: None)
    pg, ch, ledger = native.observe(Path("/opt/sli/releases/synthetic"), state)
    assert pg == "18.6" and ch == []
    assert ledger == [{"version": 1, "name": "synthetic", "sha256": "checksum"}]
    assert urls == []
    assert calls[0][0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    assert all(sql.startswith(("SELECT", "SET TRANSACTION", "SHOW")) for sql, _ in calls)
