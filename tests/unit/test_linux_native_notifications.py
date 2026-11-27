"""Native notification contracts; no provider, systemd or real credential access."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from deploy.linux import healthcheck, native_host, native_install, native_runtime as runtime
from deploy.linux import native_clickhouse_endpoint as site
from deploy.linux import native_backup, notification_health


@pytest.fixture
def config():
    return native_install.runtime_settings(site.parse_site('notification_proxy = "http://proxy.example:3128"'))


@pytest.mark.parametrize(("name", "port", "origin"), [
    ("sli.example.test", 443, "https://sli.example.test"),
    ("sli.example.test", 8443, "https://sli.example.test:8443"),
    ("2001:db8::10", 9443, "https://[2001:db8::10]:9443"),
])
def test_native_install_provisions_notification_public_origin(name, port, origin):
    config = native_install.runtime_settings(site.parse_site(
        f'bind = "0.0.0.0"\nserver_name = "{name}"\nhttps_port = {port}'))
    unit = runtime.dotnet_units("test", config)["sli-dotnet-notification-setup.service"]
    assert f'Environment="SLI_PUBLIC_URL={origin}"\n' in unit


def test_notification_units_credentials_users_and_target(config):
    units = runtime.dotnet_units("test", config)
    body = units["sli-dotnet-notification-delivery.service"]
    assert "User=sli-notify\n" in body
    assert "sli-notify" in native_host.ACCOUNTS
    for setting in ("ProtectSystem=strict", "PrivateTmp=yes", "NoNewPrivileges=yes",
                    "PartOf=sli-dotnet.target", "RuntimeDirectory=sli/notification-delivery",
                    "LoadCredential=notifications:/etc/sli/secrets/notifications"):
        assert setting + "\n" in body
    env, credentials = runtime.environment("notification-delivery", config)
    assert "notifications" in credentials
    assert credentials == {"notifications", "notification_db_password"}
    assert env["ADLOG_PG_DSN"] == "host=127.0.0.1 port=5432 dbname=sli user=sli_notification_login"
    assert env["ADLOG_PG_PASSWORD_FILE"] == "%d/notification_db_password"
    assert native_install.environment()["SLI_NOTIFICATION_DB_PASSWORD_FILE"] == str(native_install.SECRETS / "notification_db_password")
    assert env["SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE"] == "%d/notifications_notification_telegram_token"
    assert env["SLI_NOTIFICATION_SMTP_PASSWORD_FILE"] == "%d/notifications_notification_smtp_password"
    assert env["SLI_NOTIFICATION_PROXY"] == "http://proxy.example:3128"
    assert "sli-dotnet-notification-delivery.service" in units["sli-dotnet.target"]
    assert "sli-dotnet-notification-setup.service" in units["sli-dotnet.target"]
    setup = units["sli-dotnet-notification-setup.service"]
    assert "LoadCredential=" not in setup
    assert "TemporaryFileSystem=/etc/sli:ro\n" in setup
    assert "BindPaths=/etc/sli/secrets/notifications\n" in setup
    for service in runtime.SERVICES:
        settings, _ = runtime.environment(service, config)
        assert not any(key in settings for key in ("SLI_NOTIFICATION_TELEGRAM_TOKEN", "SLI_NOTIFICATION_SMTP_PASSWORD"))
        if service != "notification-delivery":
            assert "SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE" not in settings


@pytest.mark.parametrize("value", ['true', '"https://proxy.example:3128"', '"http://u:p@proxy.example:3128"', '"http://proxy.example:3128/%n"'])
def test_proxy_rejects_invalid_or_unit_injecting_values(value):
    with pytest.raises(ValueError, match="native_site_notification_proxy_invalid"):
        site.parse_site("notification_proxy = " + value)


def test_proxy_defaults_to_direct():
    env, _ = runtime.environment("notification-delivery", native_install.runtime_settings(site.parse_site("")))
    assert env["SLI_NOTIFICATION_PROXY"] == ""


@pytest.mark.parametrize("age,pid,valid", [(0, 42, True), (91, 42, False), (-1, 42, False), (0, 1, False), (20, 42, False)])
def test_delivery_health_binds_pid_and_start(tmp_path, age, pid, valid):
    now = datetime.now(timezone.utc)
    path = tmp_path / "heartbeat.json"
    path.write_text(json.dumps({"pid": pid, "at": (now - timedelta(seconds=age)).timestamp()}))
    probe = dict(process_pid=42, started_at=now - timedelta(seconds=10), status_path=path)
    assert healthcheck.native_healthy("notification-delivery", **probe) is valid


@pytest.mark.parametrize("socket_available", [True, False])
def test_native_notification_setup_health_checks_selected_socket(tmp_path, monkeypatch, socket_available):
    from contextlib import nullcontext

    socket_path = tmp_path / "control.sock"
    client = Mock()
    if not socket_available:
        client.connect.side_effect = OSError("synthetic socket unavailable")
    connect = Mock(return_value=nullcontext(client))
    socket_api = SimpleNamespace(AF_UNIX=object(), SOCK_STREAM=object(), socket=connect)
    monkeypatch.setattr(notification_health, "socket", socket_api)
    assert healthcheck.native_healthy("notification-setup", process_pid=42, started_at=datetime.now(timezone.utc),
                                     status_path=socket_path) is socket_available
    connect.assert_called_once_with(socket_api.AF_UNIX, socket_api.SOCK_STREAM)
    client.connect.assert_called_once_with(str(socket_path))


def test_native_backup_captures_notification_config_and_marker(tmp_path, monkeypatch):
    monkeypatch.setattr(native_backup, "CONFIG", tmp_path)
    monkeypatch.setattr(native_install, "trusted", lambda path: path.read_bytes())
    (tmp_path / "runtime.json").write_text("{}")
    # Other credential sources are synthetic files for this inventory test.
    manifest = json.loads(Path(native_backup.__file__).with_name("secrets-manifest.json").read_text())
    directory = tmp_path / "secrets"
    directory.mkdir()
    for name, spec in manifest["secrets"].items():
        if spec["group"] not in {"offline", "notifications", "agents"} and spec.get("backup") != "exclude":
            (directory / name).write_bytes(b"synthetic")
    notifications = directory / "notifications"
    notifications.mkdir()
    for name in ("telegram.json", "smtp.json", "smtp.ready", "notification_telegram_token", "notification_smtp_password"):
        (notifications / name).write_bytes(b"synthetic")
    sources = native_backup.secret_sources()
    assert {name for name in sources if name.startswith("notifications/")} == {
        "notifications/" + path.name for path in notifications.iterdir()}
    (notifications / "unapproved").write_bytes(b"synthetic")
    with pytest.raises(RuntimeError, match="native_backup_inventory_invalid"):
        native_backup.secret_sources()


def test_candidate_configuration_applies_site_notification_proxy(tmp_path, monkeypatch):
    from deploy.linux import native_upgrade
    captured = []
    monkeypatch.setattr(native_install, "trusted", lambda path: b"validated")
    monkeypatch.setattr(native_install, "command", lambda argv, **kwargs: captured.append(argv))
    monkeypatch.setattr(runtime, "configuration", lambda: {"schema_version": 1, "profiles": ["light"]})
    monkeypatch.setattr(native_install, "site_configuration", lambda: {"notification_proxy": "http://proxy.example:3128"})
    native_upgrade.configure_candidate(tmp_path, {"python": "/pinned/python"})
    assert json.loads(captured[0][-1])["notification_proxy"] == "http://proxy.example:3128"


def test_notification_launch_contains_paths_and_removes_plaintext(config, tmp_path, monkeypatch, capsys):
    captured = {}
    monkeypatch.setattr(runtime, "release", lambda: (tmp_path, {"python": "/pinned/python"}, "digest"))
    monkeypatch.setattr(runtime, "configuration", lambda: config)
    monkeypatch.setenv("CREDENTIALS_DIRECTORY", "/run/credentials/sli-dotnet-notification-delivery.service")
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_TOKEN", "123:synthetic-private-token")
    monkeypatch.setenv("SLI_NOTIFICATION_SMTP_PASSWORD", "synthetic-private-password")
    monkeypatch.setattr(os, "chdir", lambda path: None)
    def execute(python, argv, env):
        captured.update(env)
        raise SystemExit(0)
    monkeypatch.setattr(os, "execve", execute)
    with pytest.raises(SystemExit):
        runtime.launch("notification-delivery")
    assert "SLI_NOTIFICATION_TELEGRAM_TOKEN" not in captured
    assert "SLI_NOTIFICATION_SMTP_PASSWORD" not in captured
    assert captured["SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE"].endswith("/notifications_notification_telegram_token")
    assert "synthetic-private" not in str(captured) + str(capsys.readouterr())
