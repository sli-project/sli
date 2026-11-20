"""Setup contracts with generated credentials, fake DB and fake Bot API."""
import json
import copy
import io
import secrets
from pathlib import Path
from unittest.mock import MagicMock, Mock
from uuid import uuid4
import socket
import ssl

import pytest
import yaml

from deploy.linux import notification_delivery, telegram_setup as writer
from deploy.linux import installation, migrate, sli_update
from server.api import telegram_setup as setup_api
from server.api.routes import notification_channels as routes
from server.sli.core import notification_telegram as transport
from server.sli.core import telegram_setup as setup_client
from server.sli.core.notification_message import message_content
from server.sli.core.messages import catalog
from tests.unit.test_notification_channels import Connection, Handler, access

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("failure, code", [
    (socket.gaierror("synthetic-private-error"), "telegram_setup_network"),
    (ConnectionRefusedError("synthetic-private-error"), "telegram_setup_network"),
    (ssl.SSLError("synthetic-private-error"), "telegram_setup_tls"),
    (TimeoutError("synthetic-private-error"), "telegram_setup_timeout"),
    (ValueError("synthetic-private-error"), "telegram_setup_protocol"),
    (RuntimeError("synthetic-private-error"), "telegram_setup_unavailable"),
])
@pytest.mark.parametrize("step", ["request", "getresponse", "read"])
def test_setup_transport_failure_categories_are_fixed(monkeypatch, caplog, capsys, failure, code, step):
    client = Mock()
    response = client.getresponse.return_value
    response.status = 200
    response.read.return_value = b'{"ok":true,"result":{"is_bot":true}}'
    setattr(client if step != "read" else response, step, Mock(side_effect=failure))
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    token = "123:synthetic-private-token"
    with pytest.raises(ValueError) as caught:
        transport.bot_request(token, "getMe", {})
    assert str(caught.value) == code
    client.close.assert_called_once()
    output = str(caught.value) + caplog.text + str(capsys.readouterr())
    assert token not in output and "synthetic-private-error" not in output


def test_legacy_setup_status_preserves_optional_names_config(setup):
    service, token, chat, _ = setup
    config = {"base_url": "https://example.invalid/app", "recipients": {"1": str(chat), "2": "456"}}
    service.write(config)
    (service.directory / "notification_telegram_token").write_text(token)
    original = (service.directory / "telegram.json").read_bytes()
    result = service.handle({"action": "status", "user_id": 1})
    assert result == {"secret_set": True, "chat_bound": True, "chat_name": None, "proxy_url": ""}
    assert str(chat) not in json.dumps(result)
    assert (service.directory / "telegram.json").read_bytes() == original
    choices = service.handle({"action": "chats", "user_id": 1})
    service.handle({"action": "bind", "user_id": 1, "choice": choices["chats"][0]["choice"]})
    assert service.read()["recipients"] == config["recipients"]
    assert service.read()["names"] == {"1": "Fixture chat"}


@pytest.mark.parametrize("status, payload, code", [
    (401, {"ok": False, "error_code": 401}, "telegram_setup_invalid_token"),
    (404, {"ok": False, "error_code": 404}, "telegram_setup_invalid_token"),
    (401, {"ok": False, "error_code": "401"}, "telegram_setup_protocol"),
    (404, {"ok": False, "error_code": 403}, "telegram_setup_protocol"),
    (403, {"ok": False, "error_code": 403}, "telegram_setup_failed"),
    (409, {"ok": False, "error_code": 409}, "telegram_setup_conflict"),
    (429, {}, "telegram_setup_rate_limited"),
    (503, {}, "telegram_setup_provider_unavailable"),
    (302, {}, "telegram_setup_protocol"),
    (200, {"ok": True}, "telegram_setup_protocol"),
    (200, {"ok": True, "result": {"is_bot": False}}, "telegram_setup_protocol"),
    (200, [], "telegram_setup_protocol"),
])
def test_setup_http_codes_do_not_trust_provider_descriptions(monkeypatch, caplog, capsys, status, payload, code):
    sentinel = "synthetic-private-reply"
    if isinstance(payload, dict):
        payload = {**payload, "description": sentinel}
    client = Mock()
    client.getresponse.return_value.status = status
    client.getresponse.return_value.read.return_value = json.dumps(payload).encode()
    constructor = Mock(return_value=client)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", constructor)
    with pytest.raises(setup_client.TelegramSetupError) as caught:
        transport.bot_request("123:synthetic-token", "getMe", {})
    assert str(caught.value) == code
    assert constructor.call_args.args == ("api.telegram.org",)
    assert constructor.call_args.kwargs["context"].verify_mode == ssl.CERT_REQUIRED
    assert constructor.call_args.kwargs["context"].check_hostname is True
    client.set_debuglevel.assert_called_once_with(0)
    assert client.request.call_count == 1
    client.close.assert_called_once()
    assert sentinel not in str(caught.value) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("raw", [b"not-json-synthetic-private", b"x" * (transport.MAX_RESPONSE + 1)])
def test_setup_malformed_or_oversized_reply_is_fixed_protocol(monkeypatch, raw):
    client = Mock()
    client.getresponse.return_value.status = 200
    client.getresponse.return_value.read.return_value = raw
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_protocol$"):
        transport.bot_request("123:synthetic-token", "getMe", {})
    client.close.assert_called_once()


def test_setup_method_allowlist_does_not_open_connection(monkeypatch):
    constructor = Mock(side_effect=AssertionError("unexpected network access"))
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", constructor)
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_failed$"):
        transport.bot_request("123:synthetic-token", "getWebhookInfo", {})
    constructor.assert_not_called()


def fake_setup_socket(monkeypatch, raw):
    client = MagicMock()
    client.__enter__.return_value = client
    client.makefile.return_value = io.BytesIO(raw)
    monkeypatch.setattr(setup_client.socket, "socket", lambda *a, **k: client)
    return client


@pytest.mark.parametrize("code, http_status", [
    ("telegram_setup_invalid_token", 400), ("telegram_setup_network", 503), ("telegram_setup_tls", 503),
    ("telegram_setup_timeout", 504), ("telegram_setup_unavailable", 503), ("telegram_setup_provider_unavailable", 503),
    ("telegram_setup_rate_limited", 429), ("telegram_setup_conflict", 409), ("telegram_setup_protocol", 502),
    ("telegram_setup_failed", 400),
])
def test_fixed_setup_error_survives_writer_socket_and_route(monkeypatch, code, http_status):
    error = setup_client.TelegramSetupError(setup_client.TelegramSetupCode(code))
    payload = writer.error_response(error)
    assert payload == {"error": code}
    client = fake_setup_socket(monkeypatch, json.dumps(payload).encode() + b"\n")
    never = Mock(side_effect=AssertionError("unexpected status database access"))
    monkeypatch.setattr(setup_api, "connect", never)
    monkeypatch.setattr(setup_api.database, "query_rows", never)
    handler = Handler(payload={})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/status")
    assert handler.status == http_status and handler.response == {"error": code}
    client.settimeout.assert_called_once_with(30)
    never.assert_not_called()


@pytest.mark.parametrize("raw", [
    b'{"error":"synthetic-private-error"}', b'{"error":"telegram_setup_network","extra":"synthetic-private"}',
    b'{"error":["telegram_setup_tls"]}', b'[]', b'not-json', b'x' * 65537,
    b'{"secret_set":true,"chat_name":"synthetic-private"}',
    b'{"secret_set":0,"chat_bound":false}', b'{"secret_set":true,"chat_bound":"yes"}',
    b'{"secret_set":true,"chat_bound":true,"chat_name":5}',
])
def test_setup_socket_untrusted_error_or_status_is_unavailable(monkeypatch, raw, caplog, capsys):
    fake_setup_socket(monkeypatch, raw)
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_unavailable$") as caught:
        setup_client.request("status", 1)
    assert "synthetic-private" not in str(caught.value) + caplog.text + str(capsys.readouterr())


@pytest.mark.parametrize("value", ["telegram_setup_network", "synthetic-private", None, 503, ValueError("synthetic-private")])
def test_setup_error_constructor_and_writer_do_not_trust_strings(value):
    error = setup_client.TelegramSetupError(value)
    assert str(error) == "telegram_setup_unavailable" and error.status == 503
    assert writer.error_response(value) == {"error": "telegram_setup_unavailable"}


@pytest.mark.parametrize("failure, code", [(FileNotFoundError("synthetic-private"), "telegram_setup_unavailable"),
                                          (PermissionError("synthetic-private"), "telegram_setup_unavailable"),
                                          (TimeoutError("synthetic-private"), "telegram_setup_timeout")])
def test_setup_socket_failures_are_distinct_from_provider_network(monkeypatch, failure, code):
    client = fake_setup_socket(monkeypatch, b"{}")
    client.connect.side_effect = failure
    with pytest.raises(setup_client.TelegramSetupError, match="^" + code + "$"):
        setup_client.request("status", 1)


@pytest.mark.parametrize("names", [None, [], "synthetic-private", {"1": 123}])
def test_setup_malformed_names_are_not_silently_erased(setup, names):
    service, _, _, _ = setup
    service.write({"base_url": "https://example.invalid/app", "recipients": {}, "names": names})
    original = (service.directory / "telegram.json").read_bytes()
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_unavailable$"):
        service.handle({"action": "status", "user_id": 1})
    assert (service.directory / "telegram.json").read_bytes() == original


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("SLI_PUBLIC_URL", "https://example.invalid:8443/api/health")
    monkeypatch.setattr(writer, "_publish", lambda path, body, **_: path.write_bytes(body))
    token = str(secrets.randbelow(10**9) + 1) + ":" + secrets.token_urlsafe(32)
    chat = secrets.randbelow(10**10) + 1
    calls = []

    def bot(value, method, body, *, proxy_url=""):
        assert proxy_url == ""
        assert value == token
        calls.append(method)
        if method == "getMe":
            return {"is_bot": True, "first_name": "Fixture bot"}
        return [{"message": {"text": "/start", "chat": {"id": chat, "type": "private", "first_name": "Fixture chat"}}},
                {"message": {"text": "/start", "chat": {"id": -chat, "type": "group", "title": "Excluded"}}}]

    monkeypatch.setattr(writer, "bot_request", bot)
    return writer.Setup(tmp_path), token, chat, calls


def test_write_only_verify_discover_bind_and_rotation(setup):
    service, token, chat, calls = setup
    result = service.handle({"action": "token", "user_id": 1, "token": token})
    assert result == {"secret_set": True, "bot_name": "Fixture bot"}
    choices = service.handle({"action": "chats", "user_id": 1})
    assert len(choices["chats"]) == 1
    assert str(chat) not in json.dumps(choices)
    selection = choices["chats"][0]["choice"]
    with pytest.raises(ValueError):
        service.handle({"action": "bind", "user_id": 2, "choice": selection})
    result = service.handle({"action": "bind", "user_id": 1, "choice": selection})
    assert result == {"chat_name": "Fixture chat", "secret_set": True}
    config = service.read()
    assert config["recipients"] == {"1": str(chat)} and token not in json.dumps(config)
    assert config["base_url"] == "https://example.invalid:8443/app"
    service.handle({"action": "token", "user_id": 1, "token": token})
    assert service.read()["recipients"] == {}
    assert calls == ["getMe", "getUpdates", "getMe"]


def test_expired_or_unoffered_chat_cannot_be_bound(setup, monkeypatch):
    service, token, _, _ = setup
    service.handle({"action": "token", "user_id": 1, "token": token})
    choices = service.handle({"action": "chats", "user_id": 1})
    monkeypatch.setattr(writer.time, "monotonic", lambda: float("inf"))
    with pytest.raises(ValueError):
        service.handle({"action": "bind", "user_id": 1, "choice": choices["chats"][0]["choice"]})


def test_failed_verification_does_not_publish_token(setup, monkeypatch):
    service, token, _, _ = setup
    monkeypatch.setattr(writer, "bot_request", Mock(side_effect=ValueError("telegram_setup_failed")))
    with pytest.raises(ValueError, match="telegram_setup_failed"):
        service.handle({"action": "token", "user_id": 1, "token": token})
    assert not (service.directory / "notification_telegram_token").exists()


@pytest.mark.parametrize("decision", [access(role="viewer"), access(role="operator"), access(actions=("view",)), {}])
def test_setup_denied_before_body_socket_or_db(monkeypatch, decision):
    never = Mock(side_effect=AssertionError("unexpected setup access"))
    monkeypatch.setattr(setup_api, "connect", never)
    monkeypatch.setattr(setup_api.telegram_setup, "request", never)
    handler = Handler(decision, payload={"token": "invalid"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 403 and handler.reads == 0
    never.assert_not_called()


def test_api_requires_csrf_and_session_and_rejects_user_id(monkeypatch):
    never = Mock(side_effect=AssertionError("unexpected setup access"))
    monkeypatch.setattr(setup_api, "connect", never)
    handler = Handler(mutation=False)
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.reads == 0
    handler = Handler(payload={"user_id": 2, "choice": "unoffered"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/bind")
    assert handler.status == 400
    handler = Handler(payload={})
    handler._principal = {"type": "api_key", "id": 1}
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/chats")
    assert handler.status == 403
    never.assert_not_called()


def test_api_token_audited_before_write_never_returned(setup, monkeypatch, caplog):
    service, token, _, _ = setup
    conn = Connection()
    monkeypatch.setattr(setup_api, "connect", lambda: conn)
    audits = []
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kwargs: audits.append(kwargs))

    def request(action, user, **values):
        assert "commit" in conn.events and audits
        return service.handle({"action": action, "user_id": user, **values})

    monkeypatch.setattr(setup_api.telegram_setup, "request", request)
    handler = Handler(payload={"token": token})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 200 and handler.response["secret_set"]
    assert token not in str(handler.response) + str(audits) + caplog.text + str(conn.events)
    assert audits[0]["details"] == {"kind": "telegram", "operation": "token", "phase": "requested"}


def test_audit_failure_prevents_secret_access(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(setup_api, "connect", lambda: conn)
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", Mock(side_effect=RuntimeError))
    request = Mock()
    monkeypatch.setattr(setup_api.telegram_setup, "request", request)
    handler = Handler(payload={"token": "invalid"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 503 and "commit" not in conn.events
    request.assert_not_called()


def test_invalid_replacement_does_not_disable_a_working_channel(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(setup_api, "connect", lambda: conn)
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", Mock())
    monkeypatch.setattr(setup_api.telegram_setup, "request", Mock(side_effect=ValueError("telegram_setup_failed")))
    handler = Handler(payload={"token": "invalid"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 400
    assert not any(isinstance(event, tuple) and "enabled=false" in event[0] for event in conn.events)


def test_bind_creates_current_user_subscription_and_test_uses_queue(monkeypatch):
    conn = Connection()
    monkeypatch.setattr(setup_api, "connect", lambda: conn)
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", Mock())
    monkeypatch.setattr(setup_api.telegram_setup, "request", lambda *a, **k: {"chat_name": "Fixture chat", "secret_set": True})
    monkeypatch.setattr(setup_api.outbox, "list_subscriptions", lambda _: [])
    save = Mock()
    monkeypatch.setattr(setup_api.outbox, "save_subscription", save)
    handler = Handler(payload={"choice": "opaque-fixture"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/bind")
    assert handler.status == 200
    assert save.call_args.args[1:] == (1, {"recipient_user_id": 1, "channel": "telegram", "enabled": True})
    monkeypatch.setattr(setup_api.outbox, "list_subscriptions", lambda _: [{"id": "fixture", "owner_user_id": 1,
        "recipient_user_id": 1, "channel": "telegram", "enabled": True}])
    enqueue = Mock(return_value={"id": "job", "state": "pending"})
    monkeypatch.setattr(setup_api.outbox, "enqueue_test_problem", enqueue)
    handler.payload = {}
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/test")
    assert handler.response == {"job_id": "job", "state": "pending"}
    assert enqueue.call_args.args[1] == "fixture"


def test_transport_setup_errors_redacted_and_no_redirects(monkeypatch):
    response = Mock(status=302)
    response.read.return_value = b"{}"
    client = Mock()
    client.getresponse.return_value = response
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", lambda *a, **k: client)
    with pytest.raises(ValueError, match="^telegram_setup_protocol$"):
        transport.bot_request(secrets.token_urlsafe(), "getMe", {})
    assert client.request.call_count == 1
    client.close.assert_called_once()


@pytest.mark.parametrize("locale", ["ru", "en"])
@pytest.mark.parametrize("category", ["remote_access", "account_decoy", "file_decoy", "account_watch"])
def test_problem_message_explains_category_and_first_step(locale, category):
    _, text = message_content({"id": str(uuid4()), "object_id": str(uuid4()), "finding_id": 17,
        "object_kind": "semantic_finding", "object_severity": "critical", "notification_kind": category,
        "created_at": "2026-10-19T00:00:00Z", "language": locale}, "https://example.invalid/app")
    assert catalog(locale)[f"notifications.problem.{category}.what"] in text
    assert catalog(locale)[f"notifications.problem.{category}.action"] in text
    assert "https://example.invalid/app/report/security.problems?id=17" in text


def _assert_delivery_cycle_options(stop, options):
    stop.set()
    assert options == {"telegram": True, "smtp": True, "notification_only": True, "include_reports": True}


def test_delivery_daemon_health_tracks_successful_db_cycles(monkeypatch, tmp_path):
    monkeypatch.setattr(notification_delivery, "STATUS", tmp_path / "status.json")
    monkeypatch.setattr(notification_delivery.signal, "signal", lambda *a: None)
    monkeypatch.setattr(notification_delivery.os, "getpid", lambda: 1)
    stop = notification_delivery.threading.Event()
    monkeypatch.setattr(notification_delivery.threading, "Event", lambda: stop)

    def cycle(**options):
        _assert_delivery_cycle_options(stop, options)
        return True

    monkeypatch.setattr(notification_delivery, "process_one", cycle)
    assert notification_delivery.main() == 0 and notification_delivery.healthy()
    monkeypatch.setattr(notification_delivery.time, "time", lambda: float("inf"))
    assert not notification_delivery.healthy()


def test_delivery_options_assertion_stops_the_test_daemon_without_waiting(monkeypatch, tmp_path):
    monkeypatch.setattr(notification_delivery, "STATUS", tmp_path / "status.json")
    monkeypatch.setattr(notification_delivery.signal, "signal", lambda *a: None)
    stop = notification_delivery.threading.Event()
    monkeypatch.setattr(notification_delivery.threading, "Event", lambda: stop)
    failures = []

    def bounded_wait(_timeout):
        assert stop.is_set(), "options assertion must stop the test daemon"

    def cycle(**options):
        try:
            _assert_delivery_cycle_options(stop, {**options, "include_reports": False})
        except AssertionError as error:
            failures.append(error)
            raise

    monkeypatch.setattr(stop, "wait", bounded_wait)
    monkeypatch.setattr(notification_delivery, "process_one", cycle)
    assert notification_delivery.main() == 0
    assert len(failures) == 1 and stop.is_set()
    assert not notification_delivery.healthy()


def test_migrator_keeps_layouts_without_delivery_compatible(monkeypatch):
    monkeypatch.setattr(migrate, "WORKER_LOGINS", (("sli_notification_login", "adlog_notification_worker", "SLI_NOTIFICATION_DB_PASSWORD"),))
    monkeypatch.delenv("SLI_NOTIFICATION_DB_PASSWORD_FILE", raising=False)
    monkeypatch.setattr(migrate, "configure_job_logins", Mock())
    connection = Mock()
    migrate.configure_worker_logins(connection)
    connection.execute.assert_not_called()


def test_compose_and_upgrade_mount_only_own_secrets():
    config = yaml.safe_load((ROOT / "deploy/linux/docker-compose.yml").read_text())
    services = config["services"]
    assert not services["notification-setup"].get("secrets")
    assert services["notification-delivery"]["secrets"] == ["notification_db_password"]
    assert all("/notifications:" in mount or "/notification-control:" in mount for mount in services["notification-setup"]["volumes"])
    assert services["notification-delivery"]["volumes"][0].endswith(":ro")
    assert "${SLI_SECRETS_DIR}/notification-control:/run/notification-setup:ro" in services["api"]["volumes"]
    candidate = {"services": {"api": {"image": "fixture"}, "migrate": {"image": "fixture"}}}
    sli_update.add_notification_services(candidate, image="fixture", secret_directory="/fixture/secrets", public_url="https://example.invalid")
    assert set(candidate["services"]) == {"api", "migrate", "notification-setup", "notification-delivery"}
    assert candidate["services"]["notification-delivery"]["volumes"][0]["read_only"]
    assert candidate["services"]["migrate"]["environment"]["SLI_NOTIFICATION_DB_PASSWORD_FILE"].endswith("notification_db_password")
    journal = {"services": ["api"], "added_services": ["notification-setup", "notification-delivery"]}
    assert len(sli_update.active_services(journal)) == 3
    assert sli_update.active_services(journal, True) == ["api"]


def test_installer_preserves_private_notification_binds(tmp_path, monkeypatch):
    # Host topology is synthetic here; volume refusal has dedicated policy tests.
    monkeypatch.setattr(installation, 'restore_check_directory', lambda runtime, environment: runtime / 'backups/.restore-check')
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    config = {"services": {"api": {"volumes": [{"type": "bind", "source": str(runtime / "secrets/notification-control"),
        "target": "/run/notification-setup", "read_only": True}]},
        **sli_update.notification_services("fixture", runtime / "secrets", "https://example.invalid")}}
    host = Mock(environment={})
    installation.preserve_compose(runtime, host, config)
    saved = json.loads((runtime / "compose/compose.json").read_text())
    assert saved["services"]["api"]["volumes"] == config["services"]["api"]["volumes"]
    assert saved["services"]["notification-delivery"]["volumes"] == config["services"]["notification-delivery"]["volumes"]
    mount = saved["services"]["notification-setup"]["volumes"][0]
    assert installation.notification_mount(runtime, "notification-setup", mount)
    assert not installation.notification_mount(runtime, "api", mount)
    assert not installation.notification_mount(runtime, "notification-setup", {**mount, "source": "/unapproved"})


def test_updater_publishes_and_restores_install_compose_with_crash_intent(tmp_path, monkeypatch):
    runtime = tmp_path / "runtime"
    target = runtime / "state/install-compose.json"
    directory = runtime / "state/updates" / ("1" * 32)
    definitions = {
        "data": {"name": "retained-opaque-data", "driver": "local",
                 "driver_opts": {"type": "tmpfs", "device": "tmpfs", "o": "size=32m"}},
        "history": {"name": "retained-history", "external": True},
    }
    old = {"name": "sli", "volumes": definitions, "services": {
        "api": {"image": "old", "environment": {"OPERATOR_SETTING": "preserved"},
                "volumes": [{"type": "volume", "source": "data", "target": "/data"}]},
        "postgres": {"image": "postgres:pinned"},
    }}
    new = {"services": {"api": {"image": "new"}, "notification-delivery": {"image": "new"}}}
    expected = copy.deepcopy(old)
    expected["services"]["api"]["image"] = "new"
    expected["services"]["notification-delivery"] = new["services"]["notification-delivery"]
    previous, candidate = directory / "previous.json", directory / "candidate.json"
    for path, config in [(target, old), (previous, old), (candidate, new)]:
        sli_update.atomic_json(path, config)
    updater = object.__new__(sli_update.Updater)
    updater.runtime = runtime
    host = sli_update.DockerHost([target], "https://example.invalid/api/health/ready", tmp_path / "ca.pem")

    def configuration(replacement=None):
        return json.loads(Path((replacement or {}).get(str(target), target)).read_text())

    calls = []

    def command(args, **kwargs):
        calls.append(args)
        if args[:3] == ["docker", "volume", "inspect"]:
            assert args[3] in {definition["name"] for definition in definitions.values()}
            labels = {} if args[3] == definitions["history"]["name"] else {"com.docker.compose.project": "sli"}
            return json.dumps([{"Labels": labels}])
        if args[:3] == ["docker", "ps", "-aq"]:
            assert args[3:] in [["--filter", "volume=" + definition["name"]] for definition in definitions.values()]
            return "owned-consumer"
        assert args == ["docker", "inspect", "--format", "{{json .Config.Labels}}", "owned-consumer"]
        return json.dumps({"com.docker.compose.project": "sli"})

    monkeypatch.setattr(host, "configuration", configuration)
    monkeypatch.setattr(host, "command", command)
    monkeypatch.setattr(host, "containers", lambda: [{"ID": "owned-consumer"}])
    updater.host = host
    durable = []
    updater.save = lambda journal: durable.append(copy.deepcopy(journal))
    journal = {"operation": "1" * 32, "directory": str(directory),
               "previous": {"compose_project": "sli", "volumes": {key: value["name"] for key, value in definitions.items()}},
               "candidate_override": str(candidate), "previous_override": str(previous),
               "candidate_override_sha256": sli_update.sha256(candidate), "previous_override_sha256": sli_update.sha256(previous),
               "compose_files": {str(target): sli_update.sha256(target)}, "deployment_fingerprint": host.deployment_fingerprint()}
    before = sli_update.sha256(target)
    updater.sync_notification_compose(journal)
    assert json.loads(target.read_text()) == expected
    assert json.loads(candidate.read_text()) == new
    assert sli_update.sha256(candidate) == journal["candidate_override_sha256"]
    intent = durable[0]["notification_compose_switch"]
    assert intent.get("acknowledged") is None and intent["before"] == before
    assert intent["after"] == sli_update.sha256(target)
    assert intent["fingerprint"] == host.deployment_fingerprint()
    assert json.loads((directory / "notification-candidate.json").read_text()) == expected
    resumed = durable[0]
    updater.settle_compose_switch(resumed)
    assert resumed["notification_compose_switch"]["acknowledged"]
    assert resumed["compose_files"][str(target)] == sli_update.sha256(target)
    assert resumed["deployment_fingerprint"] == host.deployment_fingerprint()
    acknowledged = copy.deepcopy(resumed)
    updater.settle_compose_switch(resumed)
    assert resumed == acknowledged
    updater.sync_notification_compose(journal, previous=True)
    assert json.loads(target.read_text()) == old
    assert json.loads((directory / "notification-previous.json").read_text()) == old
    assert journal["notification_compose_switch"]["acknowledged"]
    assert {args[3] for args in calls if args[:3] == ["docker", "volume", "inspect"]} == {
        definition["name"] for definition in definitions.values()}
    target.write_text("{}")
    with pytest.raises(sli_update.UpdateError, match="update_compose_changed"):
        updater.settle_compose_switch(journal)


@pytest.mark.parametrize('legacy_failure', [False, True])
def test_token_route_uses_real_legacy_audit_before_socket_and_preserves_failures(monkeypatch, legacy_failure):
    from datetime import datetime, timezone
    from server.sli.access.access_control_v4 import record_access_audit_with_cursor
    assert routes.record_access_audit_with_cursor is record_access_audit_with_cursor
    class AuditConnection(Connection):
        def execute(self, sql, params=()):
            if legacy_failure and 'insert into access_audit_v4' in sql:
                raise RuntimeError('synthetic mandatory audit failure')
            super().execute(sql, params)
        def fetchone(self):
            return {'id': 81, 'created_at': datetime(2026, 10, 20, tzinfo=timezone.utc)}
    conn = AuditConnection()
    monkeypatch.setattr(setup_api, 'connect', lambda: conn)
    actions = []
    client = MagicMock()
    client.__enter__.return_value = client
    def send(raw):
        value = json.loads(raw)
        assert 'commit' in conn.events
        legacy = [event for event in conn.events if isinstance(event, tuple) and 'insert into access_audit_v4' in event[0]]
        assert legacy and json.loads(legacy[0][1][9]) == {'kind': 'telegram', 'operation': 'token', 'phase': 'requested'}
        actions.append(value['action'])
    client.sendall.side_effect = send
    client.makefile.side_effect = lambda *_: io.BytesIO(json.dumps({'bot_name': 'Fixture'} if actions[-1] == 'verify' else {'secret_set': True}).encode()+b'\n')
    constructor = Mock(return_value=client)
    monkeypatch.setattr(setup_client.socket, 'socket', constructor)
    handler = Handler(payload={'token': '12345:synthetic_token'})
    assert routes.try_handle_post(handler, routes.PREFIX+'/telegram/setup/token') is True
    if legacy_failure:
        assert handler.status == 503 and actions == []
        assert 'rollback' in conn.events and 'commit' not in conn.events
        constructor.assert_not_called()
    else:
        assert handler.status == 200 and handler.response == {'secret_set': True}
        assert actions == ['verify', 'token']
        audits = [event for event in conn.events if isinstance(event, tuple) and 'insert into access_audit_v4' in event[0]]
        assert [json.loads(event[1][9])['phase'] for event in audits] == ['requested', 'verified', 'completed']
        assert '12345:synthetic_token' not in str(conn.events)+str(handler.response)
