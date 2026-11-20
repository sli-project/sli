"""The beta installs one database and preserves retired ClickHouse files."""

import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from deploy.linux import backup, native_backup, native_host, native_install, native_runtime


def test_host_renders_only_postgres_database_services():
    units = native_host.units()
    assert "sli-postgresql.service" in units
    assert not any("clickhouse" in name for name in units)
    assert not any("docker.service" in body for body in units.values())


def test_beta_service_needs_no_clickhouse_credentials():
    env, secrets = native_runtime.environment("api", {"radius_pilot": False, "health_url": "https://192.0.2.10:443/api/health/ready"}, dotnet=True)
    assert env["ADLOG_DB_BACKEND"] == "postgres"
    assert env["ADLOG_PG_PASSWORD_FILE"] == "%d/runtime_password"
    assert "runtime_password" in secrets
    assert not any("CLICKHOUSE" in key for key in env)
    assert not {"history_password", "warm_password"}.intersection(secrets)


def test_native_backup_contains_postgres_and_files_only(monkeypatch):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    assert backup.clickhouse_targets() == ()
    assert not {"history", "warm"}.intersection(backup.default_components())


def test_retirement_disables_existing_units_and_keeps_data(tmp_path, monkeypatch):
    unit = tmp_path / "etc/systemd/system/sli-clickhouse-history.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("[Service]\nExecStart=/synthetic-only\n")
    unit.chmod(0o644)
    real_stat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda path, *a, **k:
                        SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0) if path == unit else real_stat(path, *a, **k))
    data = tmp_path / "srv/sli-db/clickhouse/history/data"
    data.mkdir(parents=True)
    (data / "part.bin").write_bytes(b"retained")
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "list-unit-files" in argv:
            return "sli-clickhouse-history.service enabled\n"
        return ""

    monkeypatch.setattr(native_host, "run", run)
    native_host.retire_clickhouse(tmp_path)
    assert ["systemctl", "disable", "--now", "sli-clickhouse-history.service"] in calls
    assert (data / "part.bin").read_bytes() == b"retained"
    assert not unit.exists()


def test_retirement_rejects_writable_unit_before_stopping_anything(tmp_path, monkeypatch):
    unit = tmp_path / "etc/systemd/system/sli-clickhouse-history.service"
    unit.parent.mkdir(parents=True)
    unit.write_text("synthetic-only")
    unit.chmod(0o666)
    calls = []
    monkeypatch.setattr(native_host, "run", lambda *a, **k: calls.append(a))
    with pytest.raises(native_host.HostError, match="native_untrusted_unit"):
        native_host.retire_clickhouse(tmp_path)
    assert not calls and unit.exists()


def test_retirement_keeps_vendor_mask_and_stops_loaded_orphan(tmp_path, monkeypatch):
    receipt = tmp_path / "var/lib/sli/state/host-prepared.json"
    receipt.parent.mkdir(parents=True)
    receipt.write_text('{"clickhouse_mode":"native"}')
    monkeypatch.setattr(native_host.clickhouse, "trusted_text", lambda path: path.read_text())
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "list-unit-files" in argv:
            return "clickhouse-server.service masked\n"
        if "list-units" in argv:
            return "sli-clickhouse-warm.service loaded active running SLI\n"
        return ""

    monkeypatch.setattr(native_host, "run", run)
    native_host.retire_clickhouse(tmp_path)
    assert ["systemctl", "stop", "clickhouse-server.service"] in calls
    assert ["systemctl", "stop", "sli-clickhouse-warm.service"] in calls
    assert not any(call[:2] == ["systemctl", "disable"] for call in calls)


def test_snapshot_coordinator_uses_writer_credentials_without_deletion_rights():
    config = {"radius_pilot": False, "health_url": "https://192.0.2.10:443/api/health/ready"}
    env, secrets = native_runtime.environment("ad-snapshot-manifest-coordinator", config, dotnet=True)
    assert env["ADLOG_SNAPSHOT_HISTORY_DSN"].endswith("user=sli_storage_lifecycle_login")
    assert env["ADLOG_SNAPSHOT_HISTORY_PASSWORD_FILE"] == "%d/storage_lifecycle_password"
    assert "storage_lifecycle_delete_password" not in secrets
    for service in ("api", "semantic", "post-collection"):
        other, _ = native_runtime.environment(service, config, dotnet=True)
        assert "ADLOG_SNAPSHOT_HISTORY_DSN" not in other


def test_retirement_does_not_stop_foreign_clickhouse(tmp_path, monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return "clickhouse-server.service enabled\n" if "list-unit-files" in argv else ""

    monkeypatch.setattr(native_host, "run", run)
    native_host.retire_clickhouse(tmp_path)
    assert not any(call[:2] in (["systemctl", "disable"], ["systemctl", "stop"]) for call in calls)


def test_backup_does_not_require_retired_clickhouse_credentials(tmp_path, monkeypatch):
    config = tmp_path / "config"
    secrets = config / "secrets"
    secrets.mkdir(parents=True)
    (config / "runtime.json").write_text('{"agents":false}')
    inventory = json.loads(Path(native_backup.__file__).with_name("secrets-manifest.json").read_text())
    for name, spec in inventory["secrets"].items():
        if spec["group"] not in {"offline", "agents", "notifications"} and spec.get("backup") != "exclude" and name not in {"history_password", "warm_password"}:
            (secrets / name).write_text("synthetic-only")
    monkeypatch.setattr(native_backup, "CONFIG", config)
    monkeypatch.setattr(native_install, "trusted", lambda path: path.read_bytes())
    sources = native_backup.secret_sources()
    assert "postgres_password" in sources
    assert not {"history_password", "warm_password"}.intersection(sources)
