"""Synthetic capacity/ownership tests: never connect to Docker or a database."""
from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import backup, backup_policy, sli_update
from deploy.linux import backup_restore_check as drill
from tests.unit.test_linux_backup import STAMP

pytestmark = pytest.mark.posix_only

GIB = 1024**3


@pytest.fixture(autouse=True)
def backup_volume(monkeypatch):
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 'backup-device')
    monkeypatch.setattr(backup_policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100 * GIB))



def point():
    return {"cluster_id": "123456789", "postmaster_start": "2026-10-22T00:00:00+00:00",
            "data_directory": "/pg/18/docker", "database_size_bytes": 20 * GIB,
            "tablespaces": [{"oid": 1663, "location": ""}, {"oid": 1664, "location": ""},
                            {"oid": 20000, "location": "/tablespace"}]}


def receipt(free=100 * GIB):
    return backup.pg_capacity_receipt(point(), {
        "data": {"device": "dev1", "free_bytes": free},
        "wal": {"device": "dev2", "free_bytes": free},
        "default": {"device": "dev1", "free_bytes": free},
        "global": {"device": "dev1", "free_bytes": free},
        "tablespace:20000": {"device": "dev3", "free_bytes": free},
    }, observed_at=STAMP.isoformat())


def test_primary_enospc_is_classified_without_path_or_detail():
    raw = b'pg_restore: error: COPY failed: ERROR: could not extend file "base/private": No space left on device\nDETAIL: sensitive\n'
    assert backup.pg_failure_reason(raw) == {"pg_reason": "disk_full"}
    assert backup.pg_failure_reason(b'ERROR: other error\nDETAIL: No space left on device') == {"pg_reason": "unclassified"}


def test_mapping_covers_data_wal_and_all_user_tablespaces():
    assert backup.pg_capacity_paths(point()) == {
        "data": "/pg/18/docker", "wal": "/pg/18/docker/pg_wal", "default": "/pg/18/docker/base",
        "global": "/pg/18/docker/global", "tablespace:20000": "/tablespace"}


def test_capacity_sql_casts_oid_to_json_number_in_both_runtimes():
    # PostgreSQL json_build_object serializes bare oid as a string. The real
    # PostgreSQL integration test checks the returned JSON; this source contract
    # prevents one independently packaged probe from losing the numeric cast.
    assert backup.PG_CAPACITY_SQL == sli_update.PG_CAPACITY_SQL
    assert "'oid', oid::bigint" in backup.PG_CAPACITY_SQL


def test_tablespace_oid_validation_stays_strict_and_supports_unsigned_oid():
    for module in (backup, sli_update):
        value = point()
        value["tablespaces"][-1]["oid"] = 2**32 - 1
        assert module.pg_capacity_paths(value)["tablespace:4294967295"] == "/tablespace"
        for invalid in ("1663", True):
            value = point()
            value["tablespaces"][0]["oid"] = invalid
            with pytest.raises(ValueError):
                module.pg_capacity_paths(value)


@pytest.mark.parametrize("defect", ["stale", "future", "cluster", "restart", "topology", "wal_missing", "negative", "bool", "legacy_size"])
def test_untrusted_or_unusable_capacity_never_admits(tmp_path, monkeypatch, defect):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    value = receipt()
    source = {"database_size_bytes": 25 * GIB}
    if defect == "stale": value["observed_at_utc"] = (STAMP - timedelta(seconds=31)).isoformat()
    elif defect == "future": value["observed_at_utc"] = (STAMP + timedelta(seconds=1)).isoformat()
    elif defect == "cluster": value["cluster_id"] = "987654321"
    elif defect == "restart": value["postmaster_start"] = "2025-01-01T00:00:00Z"
    elif defect == "topology": value["topology_sha256"] = "0" * 64
    elif defect == "wal_missing": del value["filesystems"]["wal"]
    elif defect == "negative": value["filesystems"]["wal"]["free_bytes"] = -1
    elif defect == "bool": value["filesystems"]["wal"]["free_bytes"] = True
    elif defect == "legacy_size": source = {"size_bytes": 1024}
    backup.write_json(tmp_path / ".postgres-capacity.json", value)
    result = drill.postgres_admission(tmp_path, point(), source)
    assert result["status"] == "skipped"
    assert result["reason"] != "insufficient_disk_space"


def test_admission_uses_max_source_and_current_size_and_min_real_filesystem(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    value = receipt()
    monkeypatch.setattr(backup_policy.shutil, "disk_usage", lambda path: SimpleNamespace(free=39 * GIB))
    backup.write_json(tmp_path / ".postgres-capacity.json", value)
    result = drill.postgres_admission(tmp_path, point(), {"database_size_bytes": 25 * GIB})
    assert result == {"status": "skipped", "reason": "insufficient_backup_disk_space", "required_bytes": 40 * GIB,
                      "free_bytes": 39 * GIB, "volume": str(tmp_path)}
    monkeypatch.setattr(backup_policy.shutil, "disk_usage", lambda path: SimpleNamespace(free=40 * GIB))
    backup.write_json(tmp_path / ".postgres-capacity.json", value)
    assert drill.postgres_admission(tmp_path, point(), {"database_size_bytes": 25 * GIB})["status"] == "admitted"


def test_atomic_publisher_excludes_filesystem_paths(tmp_path):
    backup.publish_pg_capacity(tmp_path, {"point": point(), "filesystems": receipt()["filesystems"],
                                          "observed_at_utc": STAMP.isoformat()})
    text = (tmp_path / ".postgres-capacity.json").read_text()
    assert "/pg/" not in text and "/tablespace" not in text
    assert json.loads(text)["cluster_id"] == "123456789"


def test_host_probes_real_paths_with_argv_not_root_or_shell():
    host = sli_update.DockerHost(["compose.yml"], "https://localhost/api/health/ready", None)
    calls = []
    def compose(args, **kwargs):
        calls.append(args)
        if args[:2] == ["ps", "--quiet"]: return "container-id\n"
        if "psql" in args: return json.dumps(point())
        if "readlink" in args: return args[-1] + "\n"
        if "cat" in args: return "1 0 8:1 / / rw - ext4 /dev/synthetic rw\n"
        if "stat" in args: return "4096 26214400 dev1\n"
        if "--publish-pg-capacity" in args: return ""
        pytest.fail(str(args))
    host.compose = compose
    host.publish_pg_capacity()
    stats = [args for args in calls if "stat" in args]
    assert {args[-1] for args in stats} == {"/pg/18/docker", "/pg/18/docker/base", "/pg/18/docker/global", "/pg/18/docker/pg_wal", "/tablespace"}
    assert all("--" in args for args in stats)


def test_capacity_service_is_supervised_without_docker_privileges_added():
    unit = sli_update.capacity_service_unit(["/usr/bin/python3", "/srv/sli/updater_launcher.py", "capacity-watch",
                                             "--compose", "/srv/sli/compose.yml"], user="sli-operator")
    assert "User=sli-operator" in unit
    assert "Restart=always" in unit and "RestartSec=10" in unit
    assert "After=docker.service" in unit and "WantedBy=multi-user.target" in unit
    assert "SupplementaryGroups=" not in unit
    assert "NoNewPrivileges=yes" in unit


class Admin:
    def __init__(self, *, acquired=True):
        self.acquired, self.queries, self.databases = acquired, [], {}
        self.row = None

    def execute(self, statement, params=()):
        rendered = statement if isinstance(statement, str) else statement.as_string()
        self.queries.append(rendered)
        if rendered in {'BEGIN READ ONLY', 'SET TRANSACTION READ ONLY'}:
            pass
        elif "pg_try_advisory_lock" in rendered:
            self.row = (self.acquired,)
        elif "pg_advisory_unlock" in rendered:
            self.row = (True,)
        elif "starts_with" in rendered:
            self.row = (False,)
        elif rendered == backup.PG_CAPACITY_SQL:
            self.row = (point(),)
        elif rendered.startswith("SELECT oid FROM pg_database"):
            self.row = (self.databases[params[0]]["oid"],)
        elif "FROM pg_database d" in rendered:
            value = self.databases.get(params[0])
            self.row = (value["oid"], value["comment"], value["owner"], value["active"]) if value else None
        elif rendered.startswith("CREATE DATABASE"):
            name = rendered.split('"')[1]
            self.databases[name] = {"oid": 23456, "comment": None, "owner": True, "active": False}
        elif rendered.startswith("COMMENT ON DATABASE"):
            name = rendered.split('"')[1]
            self.databases[name]["comment"] = rendered.split(" IS ", 1)[1].strip("'")
        elif rendered.startswith("DROP DATABASE"):
            del self.databases[rendered.split('"')[1]]
        elif rendered.startswith("REVOKE CONNECT"):
            pass
        else:
            pytest.fail(rendered)
        return self

    def fetchone(self):
        return self.row


def test_cluster_lock_busy_never_creates_or_cleans():
    admin = Admin(acquired=False)
    with drill.postgres_restore_lock(admin) as acquired:
        assert not acquired
    assert len(admin.queries) == 1


def test_owned_cleanup_requires_oid_comment_cluster_owner_and_no_active_session(tmp_path):
    admin = Admin()
    with drill.postgres_restore_lock(admin):
        run = drill.create_owned_restore(tmp_path, admin, point())
        assert len(admin.databases) == 1
        for defect in ["oid", "comment", "owner", "active", "cluster"]:
            original = copy.deepcopy(admin.databases[run["database"]])
            if defect == "oid": admin.databases[run["database"]]["oid"] += 1
            elif defect == "comment": admin.databases[run["database"]]["comment"] = "not-owned"
            elif defect == "owner": admin.databases[run["database"]]["owner"] = False
            elif defect == "active": admin.databases[run["database"]]["active"] = True
            current = {**point(), "cluster_id": "987654321"} if defect == "cluster" else point()
            assert drill.cleanup_owned_restores(tmp_path, admin, current)["removed"] == 0
            admin.databases[run["database"]] = original
        assert drill.cleanup_owned_restores(tmp_path, admin, point())["removed"] == 1
    assert not admin.databases
    assert not list((tmp_path / ".restore-runs").glob("*.json"))
    assert not any("FORCE" in query for query in admin.queries)


def test_prefix_alone_is_not_ownership_and_symlink_registry_is_not_read(tmp_path):
    admin = Admin()
    admin.databases["sli_backup_check_unowned"] = {"oid": 3, "comment": None, "owner": True, "active": False}
    assert drill.cleanup_owned_restores(tmp_path, admin, point())["removed"] == 0
    assert not admin.queries
    external = tmp_path / "external"
    external.mkdir()
    (tmp_path / ".restore-runs").symlink_to(external)
    with pytest.raises(ValueError, match="ownership"):
        drill.cleanup_owned_restores(tmp_path, admin, point())
    assert not admin.queries


def test_insufficient_space_writes_skip_without_create_or_pg_restore(tmp_path, monkeypatch):
    from contextlib import nullcontext

    from tests.unit.test_linux_backup import fake_components
    fake_components(monkeypatch, tmp_path)
    selected = backup.run_backup(tmp_path)
    manifest = json.loads((selected / "manifest.json").read_bytes())
    manifest["components"]["postgres"]["database_size_bytes"] = 25 * GIB
    backup.write_json(selected / "manifest.json", manifest)
    backup.write_json(tmp_path / ".postgres-capacity.json", receipt(free=10 * GIB))
    admin = Admin()
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext("unused"))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(admin))
    monkeypatch.setattr(backup, "pg_tool", lambda *a: pytest.fail("must not restore"))
    monkeypatch.setattr(backup_policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=10 * GIB))
    result = drill.restore_check(tmp_path, selected=selected)
    assert result["status"] == "skipped"
    assert result["reason"] == "insufficient_backup_disk_space"
    assert result["components"]["postgres"]["required_bytes"] == 40 * GIB
    assert not any(q.startswith(("CREATE", "DROP")) for q in admin.queries)
    assert json.loads((tmp_path / "restore_check.json").read_bytes()) == result
    assert not (tmp_path / "last_full_restore_check.json").exists()


def prepare_capacity(root, selected, monkeypatch):
    monkeypatch.setattr(backup_policy, 'filesystem', lambda path: 'backup-device')
    monkeypatch.setattr(backup_policy.shutil, 'disk_usage', lambda path: SimpleNamespace(free=100 * GIB))
    monkeypatch.setattr(backup, "utc_now", lambda: STAMP)
    manifest = json.loads((selected / "manifest.json").read_bytes())
    manifest["components"]["postgres"]["database_size_bytes"] = 25 * GIB
    backup.write_json(selected / "manifest.json", manifest)
    backup.write_json(root / ".postgres-capacity.json", receipt())
    return Admin()


@pytest.fixture
def private_postgres(tmp_path_factory, monkeypatch):
    """Exercise the sandbox lifecycle with short paths and fake PG binaries."""
    from contextlib import nullcontext

    work = tmp_path_factory.mktemp('rc')
    monkeypatch.setenv('SLI_RESTORE_CHECK_ROOT', str(work))
    private = SimpleNamespace(commands=[], queries=[], ledger=2)

    def execute(statement):
        private.queries.append(statement)
        value = private.ledger if 'SELECT max(version)' in statement else None
        return SimpleNamespace(fetchone=lambda: (value,))

    private.execute = execute

    def command(args, **kwargs):
        private.commands.append(args)
        tool = Path(args[0]).name
        if tool == 'initdb':
            Path(args[args.index('-D') + 1]).mkdir()
        elif tool == 'pg_ctl':
            pid = Path(args[args.index('-D') + 1]) / 'postmaster.pid'
            if args[-1] == 'start':
                pid.write_text('synthetic')
            elif args[-1] == 'stop':
                pid.unlink()
        else:
            backup.pg_tool(args, Path('synthetic-passfile'))

    def connect(**options):
        assert Path(options['host']).parent == work
        assert options['user'] == 'sli_check'
        return nullcontext(private)

    monkeypatch.setattr(drill.restore_sandbox, 'command', command)
    monkeypatch.setattr(backup.psycopg, 'connect', connect)
    return private


def test_files_backup_does_not_depend_on_postgres_size(tmp_path, monkeypatch):
    from contextlib import nullcontext

    from deploy.linux import update_checkpoint

    source = tmp_path / "source"
    source.mkdir()
    (source / "fixture").write_bytes(b"fake")
    root = tmp_path / "backups"
    root.mkdir()
    monkeypatch.setenv("SLI_BACKUP_FILES_ROOT", str(source))
    monkeypatch.setenv("SLI_BACKUP_ROOT", str(root))
    monkeypatch.setattr(update_checkpoint, "snapshot", lambda *a, **kw: nullcontext((source, None)))
    assert backup.backup_files(root / "copied") == {"size_bytes": 4, "format": "directory"}


def test_lock_release_failure_never_masks_original_restore_error():
    admin = Admin()
    execute = admin.execute
    def broken_unlock(statement, params=()):
        if "pg_advisory_unlock" in statement:
            raise RuntimeError("synthetic dead connection")
        return execute(statement, params)
    admin.execute = broken_unlock
    original = RuntimeError("synthetic restore error")
    with pytest.raises(RuntimeError) as caught, drill.postgres_restore_lock(admin):
        raise original
    assert caught.value is original


def test_supervisor_unit_sets_runtime_working_directory():
    unit = sli_update.capacity_service_unit(["/usr/bin/python3", "/srv/sli/launcher.py"], user="operator",
                                             working_directory="/srv/sli")
    assert 'WorkingDirectory="/srv/sli"' in unit


def test_host_probe_failure_does_not_publish_or_refresh_old_receipt():
    host = sli_update.DockerHost(["compose.yml"], "https://localhost/api/health/ready", None)
    calls = []
    def compose(args, **kwargs):
        calls.append(args)
        if args[:2] == ["ps", "--quiet"]: return "container-id\n"
        if "psql" in args: return json.dumps(point())
        raise RuntimeError("synthetic stat failure")
    host.compose = compose
    with pytest.raises(RuntimeError):
        host.publish_pg_capacity()
    assert not any("--publish-pg-capacity" in args for args in calls)


def test_watcher_retries_fixed_failure_and_stops_without_erasing_receipt(tmp_path, monkeypatch, capsys):
    from contextlib import nullcontext

    class Stop:
        done = False
        def is_set(self): return self.done
        def wait(self, seconds):
            assert seconds == 10
            self.done = True
    def fail():
        raise RuntimeError("private-value")
    monkeypatch.setattr(sli_update, "operation_lock", lambda path: nullcontext())
    assert sli_update.watch_pg_capacity(SimpleNamespace(publish_pg_capacity=fail), tmp_path, stop=Stop()) == {"status": "stopped"}
    assert capsys.readouterr().out == "update_capacity_unavailable\n"
    assert not list(tmp_path.iterdir())


def test_startup_does_not_connect_or_delete_legacy_live_cluster_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: pytest.fail("must not touch live cluster"))
    drill.startup_restore_cleanup(tmp_path)


def test_host_and_backup_mapping_probe_contracts_match():
    assert sli_update.PG_CAPACITY_SQL == backup.PG_CAPACITY_SQL
    assert sli_update.pg_capacity_paths(point()) == backup.pg_capacity_paths(point())


def test_capacity_service_refuses_a_different_operator_identity(tmp_path, capsys):
    launcher = tmp_path / "launcher.py"
    launcher.write_text("# synthetic")
    assert sli_update.main(["capacity-service", "--runtime", str(tmp_path), "--compose", str(tmp_path / "compose.yml"),
                            "--launcher", str(launcher), "--capacity-user", "different-operator"]) == 1
    assert "[Service]" not in capsys.readouterr().out


def test_new_drill_never_cleans_legacy_live_cluster_databases(tmp_path, monkeypatch):
    from contextlib import nullcontext

    from tests.unit.test_linux_backup import fake_components
    fake_components(monkeypatch, tmp_path)
    selected = backup.run_backup(tmp_path)
    admin = prepare_capacity(tmp_path, selected, monkeypatch)
    monkeypatch.setattr(backup, "pg_passfile", lambda: nullcontext("synthetic"))
    monkeypatch.setattr(backup, "pg_connect", lambda *a, **kw: nullcontext(admin))
    monkeypatch.setattr(drill, "cleanup_owned_restores", lambda *a: pytest.fail("must not modify live data"))
    monkeypatch.setattr(drill.restore_sandbox, "restore", lambda *a: None)
    monkeypatch.setattr(drill, 'restore_clickhouse', lambda *a: {'status': 'verified'})
    drill.restore_check(tmp_path, selected=selected)
    assert not any(query.startswith(("CREATE", "DROP", "COMMENT", "REVOKE")) for query in admin.queries)


@pytest.mark.parametrize('artifact', ['valid_run', 'malformed', 'symlink'])
def test_pending_legacy_runs_block_before_capacity_or_live_connection(tmp_path, monkeypatch, artifact):
    from tests.unit.test_linux_backup import fake_components

    fake_components(monkeypatch, tmp_path)
    selected = backup.run_backup(tmp_path)
    registry = tmp_path / '.restore-runs'
    if artifact == 'symlink':
        registry.symlink_to(selected, target_is_directory=True)
    else:
        registry.mkdir()
        token = 'a' * 32
        run = {'format_version': 1, 'token': token, 'database': 'sli_backup_check_' + token,
               'oid': 23456, 'cluster_id': point()['cluster_id']} if artifact == 'valid_run' else {}
        backup.write_json(registry / (token + '.json'), run)
    monkeypatch.setattr(backup, 'pg_connect', lambda *a, **kw: pytest.fail('must not connect'))
    monkeypatch.setattr(drill, 'cleanup_owned_restores', lambda *a: pytest.fail('must not delete'))
    with pytest.raises((RuntimeError, ValueError), match='cleanup_required|invalid_ownership'):
        drill.restore_check(tmp_path, selected=selected)
    result = json.loads((tmp_path / 'restore_check.json').read_bytes())
    assert result['status'] == 'failed'
    if artifact != 'symlink':
        assert result['diagnostic']['error_code'] == 'linux_backup_restore_cleanup_required'
    assert registry.exists()


def test_nested_unmapped_mount_fails_closed_before_receipt_publication():
    host = sli_update.DockerHost(["compose.yml"], "https://localhost/api/health/ready", None)
    calls = []
    def compose(args, **kwargs):
        calls.append(args)
        if args[:2] == ["ps", "--quiet"]: return "container-id\n"
        if "psql" in args: return json.dumps(point())
        if "readlink" in args: return args[-1] + "\n"
        if "cat" in args: return "1 0 8:1 / /tablespace/PG_18_nested rw - ext4 /dev/synthetic rw\n"
        if "stat" in args: return "4096 26214400 dev1\n"
        if "--publish-pg-capacity" in args: return ""
        pytest.fail(str(args))
    host.compose = compose
    with pytest.raises(sli_update.UpdateError, match="update_capacity_unmapped_mount"):
        host.publish_pg_capacity()
    assert not any("--publish-pg-capacity" in args for args in calls)
