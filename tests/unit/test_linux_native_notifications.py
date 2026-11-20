"""Native notification contracts; no provider, systemd or real credential access."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from deploy.linux import healthcheck, native_host, native_install, native_runtime as runtime
from deploy.linux import native_clickhouse_endpoint as site, notification_delivery
from deploy.linux import native_backup, telegram_setup
from server.sli.core import notification_smtp, notification_telegram, smtp_setup


@pytest.fixture
def config():
    return native_install.runtime_settings(site.parse_site('notification_proxy = "http://proxy.example:3128"'))


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
    assert healthcheck.healthy("notification-delivery", process_pid=42,
                              started_at=now - timedelta(seconds=10), status_path=path) is valid


def test_delivery_docker_health_still_requires_pid_one(tmp_path, monkeypatch):
    path = tmp_path / "heartbeat.json"
    monkeypatch.setattr(notification_delivery, "STATUS", path)
    path.write_text(json.dumps({"pid": 1, "at": datetime.now(timezone.utc).timestamp()}))
    assert notification_delivery.healthy()
    path.write_text(json.dumps({"pid": 42, "at": datetime.now(timezone.utc).timestamp()}))
    assert not notification_delivery.healthy()


def test_native_smtp_reads_coherent_credential_snapshot(tmp_path, monkeypatch, caplog, capsys):
    config = {"host": "smtp.example.invalid", "port": 587, "username": "synthetic-login",
              "sender": "sender@example.invalid", "recipients": {"2": "recipient@example.invalid"},
              "base_url": "https://sli.example.invalid/app"}
    password = "synthetic-notification-password"
    (tmp_path / "notifications_smtp.json").write_text(json.dumps(config))
    (tmp_path / "notifications_notification_smtp_password").write_text(password)
    marker = tmp_path / "notifications_smtp.ready"
    marker.write_text(smtp_setup.snapshot_marker(config, password, 3))
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setenv("SLI_NOTIFICATION_SMTP_CONFIG_FILE", str(tmp_path / "notifications_smtp.json"))
    monkeypatch.setenv("SLI_NOTIFICATION_SMTP_PASSWORD_FILE", str(tmp_path / "notifications_notification_smtp_password"))
    assert notification_smtp._config(2, 3) == (config, "recipient@example.invalid", password)
    (tmp_path / "notifications_notification_smtp_password").write_text("different-synthetic-password")
    with pytest.raises(smtp_setup.SMTPSetupError, match="smtp_setup_needs_save"):
        notification_smtp._config(2, 3)
    assert password not in caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("proxy", ["", "http://proxy.example:3128"])
def test_native_telegram_uses_site_proxy_for_delivery_and_setup(tmp_path, monkeypatch, proxy):
    path = tmp_path / "telegram.json"
    path.write_text(json.dumps({"base_url": "https://sli.example.invalid/app", "recipients": {"2": "123"},
                                "proxy_url": "http://old-proxy.example:8080"}))
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setenv("SLI_NATIVE_NOTIFICATION_SETUP", "1")
    monkeypatch.setenv("SLI_NOTIFICATION_PROXY", proxy)
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE", str(path))
    assert notification_telegram._config(2)[2] == proxy
    assert telegram_setup.Setup(tmp_path).read()["proxy_url"] == proxy


def test_setup_refreshes_credentials_only_after_mutations(monkeypatch, capsys):
    calls = []
    monkeypatch.setenv("SLI_NATIVE_NOTIFICATION_SETUP", "1")
    monkeypatch.setattr(telegram_setup.subprocess, "run", lambda argv, **kw: calls.append((argv, kw)) or SimpleNamespace(returncode=0))
    for action in ("status", "verify", "chats", "smtp_status"):
        telegram_setup.refresh_delivery({"action": action})
    assert not calls
    for action in ("token", "bind", "smtp_save"):
        telegram_setup.refresh_delivery({"action": action, "token": "synthetic-private-token"})
    assert len(calls) == 3
    assert all(argv == ["/usr/bin/systemctl", "restart", "sli-notification-delivery.service"] for argv, _ in calls)
    assert "synthetic-private-token" not in str(calls) + str(capsys.readouterr())
    monkeypatch.delenv("SLI_NATIVE_NOTIFICATION_SETUP")
    telegram_setup.refresh_delivery({"action": "token"})
    assert len(calls) == 3


def test_setup_socket_grants_only_api_group(tmp_path, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=234) if name == "sli-api" else pytest.fail(name)))
    monkeypatch.setenv("SLI_NATIVE_NOTIFICATION_SETUP", "1")
    ownership = []
    monkeypatch.setattr(os, "chown", lambda *args: ownership.append(args), raising=False)
    path = tmp_path / "notification-setup/control.sock"
    assert telegram_setup.prepare_socket(path) == 234
    assert ownership == [(path.parent, 0, 234)]


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


@pytest.mark.parametrize("implicit_tls", [False, True])
def test_native_smtp_connects_through_site_proxy_with_provider_tls(monkeypatch, implicit_tls):
    monkeypatch.setenv("SLI_DEPLOYMENT_MODE", "native")
    monkeypatch.setenv("SLI_NOTIFICATION_PROXY", "http://proxy.example:3128")
    sock = Mock()
    tunnel = Mock(sock=sock)
    constructor = Mock(return_value=tunnel)
    monkeypatch.setattr(notification_smtp.http.client, "HTTPConnection", constructor)
    context = Mock()
    context.wrap_socket.return_value = sock
    client = (notification_smtp._SMTPSSL(context=context, local_hostname="example.invalid") if implicit_tls
              else notification_smtp._SMTP(local_hostname="example.invalid"))
    client.deadline = notification_smtp.time.monotonic() + 30
    assert client._get_socket("smtp.example.invalid", 465 if implicit_tls else 587, 5) is sock
    constructor.assert_called_once_with("proxy.example", 3128, timeout=5)
    tunnel.set_tunnel.assert_called_once_with("smtp.example.invalid", 465 if implicit_tls else 587)
    tunnel.connect.assert_called_once()
    if implicit_tls:
        context.wrap_socket.assert_called_once_with(sock, server_hostname="smtp.example.invalid")


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


def test_failed_delivery_cycle_does_not_publish_or_log_secrets(tmp_path, monkeypatch, caplog, capsys):
    stop = notification_delivery.threading.Event()
    monkeypatch.setattr(notification_delivery.threading, "Event", lambda: stop)
    monkeypatch.setattr(notification_delivery.signal, "signal", lambda *args: None)
    path = tmp_path / "heartbeat.json"
    monkeypatch.setenv("SLI_NOTIFICATION_STATUS_FILE", str(path))
    def failed_cycle(**kwargs):
        stop.set()
        raise RuntimeError("123:synthetic-private-token")
    monkeypatch.setattr(notification_delivery, "process_one", failed_cycle)
    assert notification_delivery.main() == 0
    assert not path.exists()
    assert "synthetic-private" not in caplog.text + str(capsys.readouterr())
