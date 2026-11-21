"""TG proxy contracts: synthetic credentials, fake network and setup DB/socket."""
import json
import ssl
from unittest.mock import Mock

import pytest

from deploy.linux import telegram_setup as writer
from server.api import telegram_setup as setup_api
from server.api.routes import notification_channels as routes
from server.sli.core import notification_telegram as transport
from server.sli.core import telegram_setup as setup_client
from tests.unit.test_notification_channels import Connection, Handler
from tests.unit.test_notification_telegram import TOKEN, channel, job

REAL_HTTPS_CONNECTION = transport.http.client.HTTPSConnection
PROXY = "http://proxy.example:3128"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    monkeypatch.setattr(transport.http.client, "HTTPSConnection",
                        Mock(side_effect=AssertionError("unexpected network")))


def config(tmp_path, monkeypatch, proxy=PROXY):
    path, secret = tmp_path / "telegram.json", tmp_path / "token"
    path.write_text(json.dumps({"base_url": "https://example.invalid/app", "recipients": {"2": "123"},
                               "proxy_url": proxy}))
    secret.write_text(TOKEN)
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE", str(path))
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE", str(secret))
    return path


def test_send_proxy_uses_fixed_connect_target_and_verified_tls(tmp_path, monkeypatch, caplog, capsys):
    config(tmp_path, monkeypatch)
    client = Mock()
    client.getresponse.return_value.status = 200
    client.getresponse.return_value.getheader.return_value = ""
    client.getresponse.return_value.read.return_value = b'{"ok":true,"result":{"message_id":1}}'
    constructor = Mock(return_value=client)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", constructor)
    assert transport.send(job(), channel()).code == "accepted"
    assert constructor.call_args.args == ("proxy.example", 3128)
    context = constructor.call_args.kwargs["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    client.set_tunnel.assert_called_once_with("api.telegram.org", 443)
    names = [call[0] for call in client.method_calls]
    assert names.index("set_tunnel") < names.index("connect")
    assert client.request.call_args.args == ("POST", f"/bot{TOKEN}/sendMessage")
    client.set_debuglevel.assert_called_once_with(0)
    client.close.assert_called_once()
    assert not caplog.text and not capsys.readouterr().out


def test_api_token_check_persists_proxy_only_after_getme(tmp_path, monkeypatch):
    monkeypatch.setenv("SLI_PUBLIC_URL", "https://example.invalid")
    monkeypatch.setattr(writer, "_publish", lambda path, data, **_: path.write_bytes(data))
    service = writer.Setup(tmp_path)
    conn = Connection()
    monkeypatch.setattr(setup_api, "connect", lambda: conn)
    audits, calls = [], []
    monkeypatch.setattr(routes, "record_access_audit_with_cursor", lambda **kw: audits.append(kw))

    def bot(token, method, values, *, proxy_url=""):
        assert token == TOKEN and method == "getMe" and proxy_url == PROXY
        assert audits and "commit" in conn.events
        calls.append(method)
        return {"is_bot": True, "first_name": "Synthetic bot"}

    monkeypatch.setattr(writer, "bot_request", bot)
    monkeypatch.setattr(setup_api.telegram_setup, "request",
                        lambda action, user, **values: service.handle({"action": action, "user_id": user, **values}))
    handler = Handler(payload={"token": TOKEN, "proxy_url": PROXY})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 200 and handler.response["secret_set"]
    assert calls == ["getMe", "getMe"]
    assert service.read()["proxy_url"] == PROXY
    assert service.handle({"action": "status", "user_id": 1})["proxy_url"] == PROXY
    assert TOKEN not in str(handler.response) + str(audits) + str(conn.events)



@pytest.mark.parametrize("value", ["", PROXY, "http://127.0.0.1:3128", "http://[::1]:1",
                                  "http://[2001:db8::1]:65535"])
def test_shared_proxy_validator_accepts_only_explicit_credential_free_endpoints(value):
    assert setup_client.validate_proxy_url(value) == value


INVALID = [None, False, [], 3128, "proxy.example:3128", "https://proxy.example:3128",
           "http://proxy.example", "http://proxy.example:", "http://proxy.example:0", "http://proxy.example:65536",
           "http://proxy.example:-1", "http://proxy.example:+1", "http://proxy.example:1.5",
           "http://user:synthetic-private@proxy.example:3128", "http://@proxy.example:3128",
           "http://proxy.example:3128/", "http://proxy.example:3128/path", "http://proxy.example:3128?",
           "http://proxy.example:3128#", "http://proxy.example:3128\n", " http://proxy.example:3128",
           "http://proxy.example:\t3128", "http://proxy.example:3128\x00", "http://proxy.example:3128\\other",
           "http://proxy..example:3128", "http://-proxy.example:3128", "http://999.0.0.1:3128",
           "http://::1:3128", "http://[::1%eth0]:3128", "http://" + "x" * 1025 + ":1"]


@pytest.mark.parametrize("value", INVALID)
def test_invalid_proxy_has_fixed_error_without_network(value, caplog, capsys):
    with pytest.raises(setup_client.TelegramSetupError) as caught:
        setup_client.validate_proxy_url(value)
    assert caught.value.code is setup_client.TelegramSetupCode.INVALID_PROXY
    assert caught.value.status == 400 and str(caught.value) == "telegram_setup_invalid_proxy"
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("method,result", [("getMe", {"is_bot": True}), ("getUpdates", [])])
@pytest.mark.parametrize("proxy", ["", PROXY])
def test_bot_setup_methods_use_saved_connect_proxy_or_legacy_direct(monkeypatch, method, result, proxy):
    client = Mock()
    client.getresponse.return_value.status = 200
    client.getresponse.return_value.read.return_value = json.dumps({"ok": True, "result": result}).encode()
    constructor = Mock(return_value=client)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", constructor)
    monkeypatch.setenv("HTTPS_PROXY", "http://untrusted.example:9999")
    assert transport.bot_request(TOKEN, method, {}, proxy_url=proxy) == result
    assert constructor.call_args.args == (("proxy.example", 3128) if proxy else ("api.telegram.org",))
    if proxy:
        client.set_tunnel.assert_called_once_with("api.telegram.org", 443)
    else:
        client.set_tunnel.assert_not_called()
    client.close.assert_called_once()


def test_stdlib_tls_wrap_targets_telegram_after_http_tunnel(monkeypatch):
    sock = Mock()
    context = Mock(check_hostname=True, verify_mode=ssl.CERT_REQUIRED)
    monkeypatch.setattr(transport.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", REAL_HTTPS_CONNECTION)

    def connect(client):
        assert (client.host, client.port) == ("proxy.example", 3128)
        assert (client._tunnel_host, client._tunnel_port) == ("api.telegram.org", 443)
        client.sock = sock

    monkeypatch.setattr(transport.http.client.HTTPConnection, "connect", connect)
    client = transport._connection(PROXY)
    client.connect()
    context.wrap_socket.assert_called_once_with(sock, server_hostname="api.telegram.org")
    client.close()


@pytest.mark.parametrize("step,expected", [("set_tunnel", "telegram_unavailable"), ("connect", "telegram_unavailable"),
    ("request", "telegram_outcome_unknown"), ("getresponse", "telegram_outcome_unknown"), ("read", "telegram_outcome_unknown")])
def test_proxy_send_preserves_pre_send_retry_and_post_send_uncertainty(tmp_path, monkeypatch, caplog, capsys, step, expected):
    config(tmp_path, monkeypatch)
    client = Mock()
    target = client.getresponse.return_value if step == "read" else client
    getattr(target, step).side_effect = OSError(TOKEN + " synthetic-private-error")
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", Mock(return_value=client))
    assert transport.send(job(), channel()).code == expected
    client.close.assert_called_once()
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("action", ["verify", "token"])
def test_bad_setup_proxy_never_changes_working_secret_config_or_recipient(tmp_path, monkeypatch, action):
    service = writer.Setup(tmp_path)
    before = {"base_url": "https://example.invalid/app", "recipients": {"1": "123"},
              "names": {"1": "Synthetic chat"}, "proxy_url": PROXY}
    (tmp_path / "telegram.json").write_text(json.dumps(before))
    (tmp_path / "notification_telegram_token").write_text(TOKEN)
    snapshot = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    bot = Mock(side_effect=AssertionError("unexpected Bot API"))
    monkeypatch.setattr(writer, "bot_request", bot)
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_invalid_proxy$"):
        service.handle({"action": action, "user_id": 1, "token": TOKEN,
                        "proxy_url": "http://user:synthetic-private@proxy.example:3128"})
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == snapshot
    bot.assert_not_called()


@pytest.mark.parametrize("specified,expected", [(False, PROXY), (True, "")])
def test_token_rotation_omission_preserves_and_explicit_empty_clears_proxy(tmp_path, monkeypatch, specified, expected):
    service = writer.Setup(tmp_path)
    monkeypatch.setattr(writer, "_publish", lambda path, data, **_: path.write_bytes(data))
    service.write({"base_url": "https://example.invalid/app", "recipients": {"1": "123"}, "proxy_url": PROXY})
    bot = Mock(return_value={"is_bot": True})
    monkeypatch.setattr(writer, "bot_request", bot)
    body = {"action": "token", "user_id": 1, "token": TOKEN}
    if specified:
        body["proxy_url"] = ""
    service.handle(body)
    assert bot.call_args.kwargs == {"proxy_url": expected}
    assert service.read()["proxy_url"] == expected
    assert service.read()["recipients"] == {}  # Existing token rotation rule.


def test_setup_uses_saved_proxy_for_verification_and_keeps_chat_discovery_local(tmp_path, monkeypatch):
    service = writer.Setup(tmp_path)
    monkeypatch.setattr(writer, "_publish", lambda path, data, **_: path.write_bytes(data))
    service.write({"base_url": "https://example.invalid/app", "recipients": {}, "proxy_url": PROXY})
    (tmp_path / "notification_telegram_token").write_text(TOKEN)
    before = (tmp_path / "telegram.json").read_bytes()
    assert service.handle({"action": "status", "user_id": 1})["proxy_url"] == PROXY
    assert (tmp_path / "telegram.json").read_bytes() == before
    bot = Mock(return_value={"is_bot": True, "first_name": "Fixture bot"})
    monkeypatch.setattr(writer, "bot_request", bot)
    generation = service.handle({"action": "chat_generation", "user_id": 1})["generation"]
    assert service.handle({"action": "chats", "user_id": 1, "generation": generation, "observations": []}) == {"chats": []}
    bot.assert_not_called()
    assert service.handle({"action": "verify", "user_id": 1, "token": TOKEN}) == {"bot_name": "Fixture bot"}
    bot.assert_called_once_with(TOKEN, "getMe", {}, proxy_url=PROXY)
    assert (tmp_path / "telegram.json").read_bytes() == before


def test_api_bad_proxy_is_denied_before_audit_socket_or_channel_disable(monkeypatch):
    never = Mock(side_effect=AssertionError("unexpected private access"))
    monkeypatch.setattr(setup_api, "connect", never)
    monkeypatch.setattr(setup_api.telegram_setup, "request", never)
    handler = Handler(payload={"token": TOKEN, "proxy_url": "http://user:synthetic-private@proxy.example:3128"})
    routes.try_handle_post(handler, routes.PREFIX + "/telegram/setup/token")
    assert handler.status == 400 and handler.response == {"error": "telegram_setup_invalid_proxy"}
    never.assert_not_called()


@pytest.mark.parametrize("value", [PROXY, "", "http://user:synthetic-private@proxy.example:3128", None])
def test_private_socket_status_validates_proxy_before_return(monkeypatch, value):
    from tests.unit.test_telegram_setup import fake_setup_socket
    raw = json.dumps({"secret_set": True, "chat_bound": False, "proxy_url": value}).encode()
    fake_setup_socket(monkeypatch, raw)
    if value in (PROXY, ""):
        assert setup_client.request("status", 1)["proxy_url"] == value
    else:
        with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_unavailable$"):
            setup_client.request("status", 1)


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_server_network_messages_explain_proxy_without_private_values(locale):
    from server.sli.core.messages import catalog
    messages = catalog(locale)
    assert messages["notifications.telegram.unavailable"]
    assert messages["notifications.telegram.timeout"]
    assert "http://proxy.example.invalid:3128" in messages["notifications.telegram.invalid_proxy"]


def test_ipvfuture_brackets_are_not_an_ipv6_proxy():
    with pytest.raises(setup_client.TelegramSetupError, match="^telegram_setup_invalid_proxy$"):
        setup_client.validate_proxy_url("http://[v1.example]:3128")


def test_real_connect_response_close_flush_and_capped_bot0_404(monkeypatch):
    import io

    streams, sockets, sent, wrapped = [], [], [], []
    body = b'{"ok":false,"error_code":404,"description":"Not Found"}'

    class Stream(io.BytesIO):
        flushes = 0

        def flush(self):
            self.flushes += 1
            return super().flush()

    class Socket:
        def __init__(self, wire):
            self.wire = wire
            self.closed = False
            sockets.append(self)

        def makefile(self, *_):
            stream = Stream(self.wire)
            streams.append(stream)
            return stream

        def settimeout(self, value):
            assert 0 < value <= 5

        def setsockopt(self, *_):
            pass

        def sendall(self, data):
            sent.append(data)

        def close(self):
            self.closed = True

    connect_wire = b"HTTP/1.1 200 Connection established\r\nProxy-Agent: synthetic\r\n\r\n"
    # Exercise the exact stdlib close->flush lifecycle even on older Python
    # releases which did not yet close the temporary CONNECT response itself.
    check = transport._Response(Socket(connect_wire))
    check.close()
    assert streams[0].closed and streams[0].flushes == 1

    tcp = Socket(connect_wire)
    tls = Socket(b"HTTP/1.1 404 Not Found\r\nContent-Length: " + str(len(body)).encode()
                 + b"\r\nConnection: close\r\n\r\n" + body)

    def wrap(context, sock, *, server_hostname, **_):
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert sock is tcp and server_hostname == "api.telegram.org"
        wrapped.append(server_hostname)
        return tls

    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)

    def connection(address, timeout, source_address):
        nonlocal tcp, tls
        assert address == ("proxy.example", 3128) and timeout == 5 and source_address is None
        tcp = Socket(connect_wire)
        tls = Socket(b"HTTP/1.1 404 Not Found\r\nContent-Length: " + str(len(body)).encode()
                     + b"\r\nConnection: close\r\n\r\n" + body)
        return tcp

    # Keep the actual class global: stdlib uses super(HTTPSConnection,self).
    monkeypatch.setattr(transport.http.client, "HTTPSConnection", REAL_HTTPS_CONNECTION)
    monkeypatch.setattr(transport.http.client.socket, "create_connection", connection)
    # Unmasked low-level path makes fake protocol incompatibilities visible;
    # public bot_request below must still map the actual parsed404 correctly.
    client = transport._connection(PROXY)
    try:
        client.request("POST", "/bot0/getMe", body=b"{}", headers={"Connection": "close"})
        response = client.getresponse()
        assert isinstance(response, transport._Response) and response.status == 404
        assert json.loads(response.read(transport.MAX_RESPONSE + 1))["error_code"] == 404
        response.close()
    finally:
        client.close()
    with pytest.raises(setup_client.TelegramSetupError) as caught:
        transport.bot_request("0", "getMe", {}, proxy_url=PROXY)
    assert caught.value.code is setup_client.TelegramSetupCode.INVALID_TOKEN
    assert wrapped == ["api.telegram.org", "api.telegram.org"] and tls.closed
    assert all(stream.closed for stream in streams)
    assert sent[0].split(b"\r\n", 1)[0].startswith(b"CONNECT api.telegram.org:443 HTTP/")
    assert sent[1].startswith(b"POST /bot0/getMe HTTP/")
    assert not any(b"CONNECT proxy.example" in data for data in sent)


def test_reader_flush_delegates_without_hiding_underlying_errors():
    stream = Mock()
    reader = transport._Reader(stream, Mock(), 10)
    reader.flush()
    stream.flush.assert_called_once_with()
    stream.flush.side_effect = RuntimeError("synthetic flush failure")
    with pytest.raises(RuntimeError, match="synthetic flush failure"):
        reader.flush()
