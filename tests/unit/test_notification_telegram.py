"""N05 transport contracts; only synthetic credentials and fake HTTPS sockets."""

import io
import json
import ssl
from uuid import uuid4

import pytest

from server.sli.core import notification_telegram as telegram

TOKEN = "123456:synthetic_test_token"
PRIVATE = "synthetic-private-value"


def job(**overrides):
    return {"id": str(uuid4()), "object_id": str(uuid4()), "object_kind": "test_problem",
            "channel": "telegram", "recipient_user_id": 2, "created_at": "2026-10-17T00:00:00Z", **overrides}


def channel(**overrides):
    return {"enabled": True, "tls_mode": "tls", "secret_ref": telegram.SECRET_REF, **overrides}


def test_published_problem_template_contains_only_reference_metadata(delivery):
    item = job(object_kind="semantic_finding", finding_id=17, title=PRIVATE, evidence=PRIVATE)
    assert telegram.send(item, channel()) == telegram.Outcome("accepted")
    text = delivery[-1][0]["text"]
    assert "Problem: 17" in text and "/report/security.problems?id=17" in text
    assert "simulated" not in text and PRIVATE not in text and TOKEN not in text


@pytest.mark.parametrize("severity", ["medium", "high"])
def test_nps_problem_severity_snapshot_reaches_telegram_without_source_values(delivery, severity):
    item = job(object_kind="semantic_finding", finding_id=17, object_severity=severity, account=PRIVATE)
    assert telegram.send(item, channel()) == telegram.Outcome("accepted")
    text = delivery[-1][0]["text"]
    assert f"Severity: {severity}" in text and PRIVATE not in text and TOKEN not in text


@pytest.mark.parametrize("key", ["security.problems", "file-audit.mass-operations"])
def test_report_digest_has_saved_period_quality_and_link_without_secrets(delivery, key, caplog):
    from tests.unit.test_report_schedules import sample_run
    run = sample_run(report_key=key)
    assert telegram.send(job(object_kind="report_schedule", object_id=run["id"], report_run=run), channel()).code == "accepted"
    text = delivery[6][0]["text"]
    assert str(run["id"]) in text and "partial" in text and "unavailable" in text
    assert "2026-10-17T09:00:00+00:00" in text and "2026-10-18T09:00:00+00:00" in text
    assert f"/app/report/{key}?" in text
    assert TOKEN not in text + caplog.text and PRIVATE not in text + caplog.text


@pytest.fixture
def delivery(tmp_path, monkeypatch):
    config = {"base_url": "https://sli.example.invalid/app", "recipients": {"2": "-123456"}}
    path, secret = tmp_path / "telegram.json", tmp_path / "secret"
    path.write_text(json.dumps(config), encoding="utf-8")
    secret.write_text(TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE", str(path))
    monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE", str(secret))
    monkeypatch.delenv("SLI_NOTIFICATION_TELEGRAM_TOKEN", raising=False)
    events, requests = [], []

    class Response:
        status = 200
        payload = {"ok": True, "result": {"message_id": 123, "text": PRIVATE, "chat": {"id": -123456}}}
        raw = None
        retry_after = ""

        def getheader(self, name, default):
            assert name == "Retry-After"
            return self.retry_after

        def read(self, size):
            assert size == 65537
            return self.raw if self.raw is not None else json.dumps(self.payload).encode()

    class Client:
        failure = None

        def __init__(self, host, *, context, timeout):
            assert host == "api.telegram.org" and timeout == 5
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            events.append("new")

        def check(self, name):
            events.append(name)
            if self.failure == name:
                raise RuntimeError(f"/bot{TOKEN}/sendMessage {PRIVATE}")

        def set_debuglevel(self, level):
            assert level == 0
            events.append("debug_disabled")

        def connect(self):
            self.check("connect")

        def request(self, method, path, *, body, headers):
            assert method == "POST" and path == f"/bot{TOKEN}/sendMessage"
            assert headers == {"Content-Type": "application/json", "Connection": "close"}
            requests.append(json.loads(body))
            self.check("request")

        def getresponse(self):
            assert self.response_class is telegram._Response
            self.check("response")
            return Response()

        def close(self):
            self.check("close")

    monkeypatch.setattr(telegram.http.client, "HTTPSConnection", Client)
    return path, secret, config, Client, Response, events, requests


def test_verified_tls_fixed_endpoint_post_safe_template_and_stable_id(delivery, caplog, capsys):
    item = job(private=PRIVATE)
    assert telegram.send(item, channel()) == telegram.Outcome("accepted")
    assert delivery[5] == ["new", "debug_disabled", "connect", "request", "response", "close"]
    sent = delivery[6][0]
    assert sent["chat_id"] == "-123456"
    assert sent["link_preview_options"] == {"is_disabled": True} and sent["protect_content"]
    assert set(sent) == {"chat_id", "text", "link_preview_options", "protect_content"}
    assert item["id"] in sent["text"] and item["object_id"] in sent["text"]
    assert "simulated" in sent["text"] and "informational" in sent["text"] and item["created_at"] in sent["text"]
    assert "https://sli.example.invalid/app/report/notifications.deliveries" in sent["text"]
    assert TOKEN not in sent["text"] and PRIVATE not in sent["text"]
    assert telegram.send(item, channel()).code == "accepted"
    assert delivery[6][1]["text"] == sent["text"]
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("override", [{"enabled": False}, {"tls_mode": "plain"}, {"secret_ref": PRIVATE}])
def test_invalid_channel_reads_no_config_or_secret(delivery, monkeypatch, override):
    monkeypatch.setattr(telegram, "_config", lambda *_: pytest.fail("unexpected config read"))
    assert telegram.send(job(), channel(**override)).code == "telegram_not_configured"
    assert not delivery[5]


@pytest.mark.parametrize("override", [
    {"token": TOKEN}, {"api_url": "https://example.invalid"}, {"recipients": []}, {"recipients": {}},
    {"recipients": {"2": "@synthetic"}}, {"recipients": {"2": True}}, {"recipients": {"2": "0"}},
    {"recipients": {"2": "-123\n"}}, {"recipients": {"2": "1" * 17}},
    {"base_url": "http://sli.example.invalid"}, {"base_url": "https://u:p@sli.example.invalid"},
    {"base_url": "https://sli.example.invalid?token=synthetic"}, {"base_url": "https://sli.example.invalid/#fragment"},
    {"base_url": "https://sli.example.invalid/\n"}, {"base_url": []},
])
def test_config_rejects_secrets_endpoints_unapproved_chats_and_bad_links(delivery, override, caplog):
    path, _, config, _, _, events, _ = delivery
    path.write_text(json.dumps({**config, **override}), encoding="utf-8")
    assert telegram.send(job(), channel()).code == "telegram_not_configured"
    assert not events and not caplog.text


@pytest.mark.parametrize("failure", ["missing", "plaintext", "empty", "invalid", "unreadable", "oversized_config", "bad_json"])
def test_credentials_only_from_sli_file_storage_and_invalid_input_never_connects(delivery, monkeypatch, failure):
    path, secret = delivery[:2]
    if failure == "missing":
        monkeypatch.delenv("SLI_NOTIFICATION_TELEGRAM_TOKEN_FILE")
    elif failure == "plaintext":
        monkeypatch.setenv("SLI_NOTIFICATION_TELEGRAM_TOKEN", TOKEN)
    elif failure in {"empty", "invalid"}:
        secret.write_text("" if failure == "empty" else "invalid-token")
    elif failure == "unreadable":
        secret.unlink()
    elif failure == "oversized_config":
        path.write_bytes(b" " * 65537)
    else:
        path.write_bytes(b"\xff")
    assert telegram.send(job(), channel()).code == "telegram_not_configured"
    assert not delivery[5]


@pytest.mark.parametrize("status,code", [
    (400, "telegram_chat_denied"), (401, "telegram_auth_failed"), (403, "telegram_chat_denied"),
    (404, "telegram_auth_failed"), (429, "telegram_rate_limited"), (500, "telegram_unavailable"),
    (503, "telegram_unavailable"), (302, "telegram_rejected"), (418, "telegram_rejected"),
])
def test_fixed_provider_codes_never_expose_descriptions_or_redirect(delivery, status, code, caplog, capsys):
    response = delivery[4]
    response.status = status
    response.payload = {"ok": False, "error_code": status, "description": f"{TOKEN} {PRIVATE}"}
    result = telegram.send(job(), channel())
    assert result.code == code
    assert len(delivery[6]) == 1
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("wait,header,expected", [(120, "600", 600), (900, "bad", 900), (None, "1200", 1200),
    (True, "0", 60), (-1, "-10", 60), ("999", "9" * 100, 60), (2**40, "1", 60)])
def test_retry_after_from_bot_api_and_http_header_is_bounded_typed_and_honored(delivery, wait, header, expected):
    response = delivery[4]
    response.status, response.retry_after = 429, header
    response.payload = {"ok": False, "error_code": 429, "parameters": {"retry_after": wait}}
    assert telegram.send(job(), channel()) == telegram.Outcome("telegram_rate_limited", expected)


@pytest.mark.parametrize("payload", [None, [], {}, {"ok": True}, {"ok": True, "result": {"message_id": True}},
    {"ok": True, "result": {"message_id": 0}}, {"ok": False, "error_code": 503}, {"ok": "true"}])
def test_malformed_or_inconsistent_success_is_unknown_not_an_automatic_retry(delivery, payload):
    delivery[4].payload = payload
    assert telegram.send(job(), channel()).code == "telegram_outcome_unknown"


@pytest.mark.parametrize("raw", [b"not JSON", b"\xff", b" " * 65537])
def test_oversized_and_non_json_replies_are_unknown(delivery, raw):
    delivery[4].raw = raw
    assert telegram.send(job(), channel()).code == "telegram_outcome_unknown"


@pytest.mark.parametrize("step,code", [("connect", "telegram_unavailable"), ("request", "telegram_outcome_unknown"),
    ("response", "telegram_outcome_unknown"), ("close", "accepted")])
def test_exceptions_with_token_url_are_not_logged_or_returned(delivery, step, code, caplog, capsys):
    delivery[3].failure = step
    assert telegram.send(job(), channel()).code == code
    assert delivery[5][-1] == "close"
    assert not caplog.text and not capsys.readouterr().out


def test_http_reader_limits_total_headers_and_body_and_trickle_deadline(monkeypatch):
    class Socket:
        def settimeout(self, value):
            assert 0 < value <= 5
    reader = telegram._Reader(io.BytesIO(b"x" * 65537), Socket(), float("inf"))
    assert len(reader.read(65536)) == 65536
    with pytest.raises(ValueError):
        reader.read(1)
    ticks = iter([0, 10, 20])
    monkeypatch.setattr(telegram.time, "monotonic", lambda: next(ticks))
    reader = telegram._Reader(io.BytesIO(b"trickled\n"), Socket(), 20)
    with pytest.raises(TimeoutError):
        reader.readline()


@pytest.mark.parametrize("wire", [
    b'HTTP/1.1 200 OK\r\nContent-Length: 39\r\n\r\n{"ok":true,"result":{"message_id":123}}',
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n27\r\n{"ok":true,"result":{"message_id":123}}\r\n0\r\n\r\n',
])
def test_bounded_reader_works_with_real_http_response_parser(wire):
    class Socket:
        def makefile(self, *_):
            return io.BytesIO(wire)
        def settimeout(self, value):
            assert 0 < value <= 5
    response = telegram._Response(Socket(), method="POST")
    response.begin()
    assert json.loads(response.read(65537))["result"]["message_id"] == 123
