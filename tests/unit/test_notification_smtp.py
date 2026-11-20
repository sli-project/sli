"""N04 isolated transport contracts; no database, network or real credentials."""

import io
import json
import smtplib
import ssl
from uuid import uuid4

import pytest

from server.sli.core import notification_smtp as smtp
from server.sli.core.smtp_setup import snapshot_marker

PRIVATE = "synthetic-private-value"


def job(**overrides):
    return {"id": str(uuid4()), "object_id": str(uuid4()), "object_kind": "test_problem",
            "channel": "smtp", "recipient_user_id": 2, "created_at": "2026-10-17T00:00:00Z", **overrides}


def channel(**overrides):
    return {"enabled": True, "tls_mode": "starttls", "secret_ref": smtp.SECRET_REF, "revision": 1, **overrides}


@pytest.mark.parametrize("severity", ["medium", "high"])
def test_nps_problem_severity_snapshot_in_safe_email_template(delivery, severity):
    item = job(object_kind="semantic_finding", finding_id=17, object_severity=severity, account=PRIVATE, token=PRIVATE)
    assert smtp.send(item, channel()) == "accepted"
    message = delivery[-1][0]
    body = message.get_content()
    assert message["Subject"] == "SLI: security problem"
    assert f"Severity: {severity}" in body and "Problem: 17" in body
    assert PRIVATE not in body and "/report/security.problems?id=17" in body


@pytest.mark.parametrize("key", ["security.problems", "file-audit.mass-operations"])
def test_report_digest_uses_saved_period_and_quality_without_private_rows(delivery, key, caplog):
    from tests.unit.test_report_schedules import sample_run
    run = sample_run(report_key=key)
    item = job(object_kind="report_schedule", object_id=run["id"], report_run=run, private=PRIVATE)
    assert smtp.send(item, channel()) == "accepted"
    message = delivery[5][0]
    text = message.get_content()
    assert str(run["id"]) in text and "partial" in text and "unavailable" in text
    assert "2026-10-17T09:00:00+00:00" in text and "2026-10-18T09:00:00+00:00" in text
    assert f"/app/report/{key}?" in text and not message.is_multipart()
    assert PRIVATE not in message.as_string() + caplog.text


@pytest.fixture
def delivery(tmp_path, monkeypatch):
    config = {"host": "smtp.example.invalid", "port": 587, "username": "synthetic-login",
              "sender": "sender@example.invalid", "recipients": {"2": "recipient@example.invalid"},
              "base_url": "https://sli.example.invalid/app"}
    config_path, password_path = tmp_path / "smtp.json", tmp_path / "notification_smtp_password"
    config_path.write_text(json.dumps(config), encoding="utf-8")
    password_path.write_text(" " + PRIVATE + " ", encoding="utf-8")
    (tmp_path / "smtp.ready").write_text(snapshot_marker(config, " " + PRIVATE + " ", 1), encoding="utf-8")
    monkeypatch.setenv("SLI_NOTIFICATION_SMTP_CONFIG_FILE", str(config_path))
    monkeypatch.setenv("SLI_NOTIFICATION_SMTP_PASSWORD_FILE", str(password_path))
    monkeypatch.delenv("SLI_NOTIFICATION_SMTP_PASSWORD", raising=False)
    events, messages = [], []

    class Client:
        failure = None
        refused = {}

        def __init__(self, **kwargs):
            events.append(("new", kwargs))

        def check(self, step):
            events.append((step,))
            if self.failure and self.failure[0] == step:
                raise self.failure[1]

        def set_debuglevel(self, level):
            assert level == 0
            events.append(("debug", level))

        def connect(self, host, port):
            assert (host, port) == (config["host"], config["port"])
            self.check("connect")

        def ehlo(self):
            self.check("ehlo")

        def starttls(self, *, context):
            assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
            self.check("starttls")

        def login(self, username, password):
            assert username == config["username"] and password == " " + PRIVATE + " "
            self.check("login")

        def send_message(self, message, *, from_addr, to_addrs):
            assert from_addr == config["sender"] and to_addrs == [config["recipients"]["2"]]
            messages.append(message)
            self.check("send")
            return self.refused

        def close(self):
            self.check("close")

    monkeypatch.setattr(smtp, "_SMTP", Client)
    monkeypatch.setattr(smtp, "_SMTPSSL", Client)
    return config_path, password_path, config, Client, events, messages


@pytest.mark.parametrize("tls_mode", ["starttls", "tls"])
def test_verified_tls_before_auth_and_sanitized_stable_message(delivery, tls_mode, caplog, capsys):
    _, _, _, _, events, messages = delivery
    item = job(private=PRIVATE)
    assert smtp.send(item, channel(tls_mode=tls_mode)) == "accepted"
    names = [event[0] for event in events]
    assert events[0][1]["local_hostname"] == "example.invalid"
    assert names == (["new", "debug", "connect", "ehlo", "starttls", "ehlo", "login", "send", "close"]
                     if tls_mode == "starttls" else ["new", "debug", "connect", "ehlo", "login", "send", "close"])
    if tls_mode == "tls":
        context = events[0][1]["context"]
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert item["id"] in messages[0]["Message-ID"]
    assert messages[0]["Date"]
    body = messages[0].get_content()
    assert "simulated" in body and "informational" in body
    assert item["object_id"] in body and item["created_at"] in body
    assert "https://sli.example.invalid/app/report/notifications.deliveries" in body
    assert PRIVATE not in messages[0].as_string()
    assert smtp.send(item, channel(tls_mode=tls_mode)) == "accepted"
    assert messages[1]["Message-ID"] == messages[0]["Message-ID"]
    assert not caplog.text and not capsys.readouterr().out


@pytest.mark.parametrize("override", [{"enabled": False}, {"secret_ref": PRIVATE}, {"tls_mode": "plain"}])
def test_disabled_or_invalid_channel_never_reads_config_or_secret(delivery, monkeypatch, override):
    monkeypatch.setattr(smtp, "_config", lambda *_: pytest.fail("unexpected config read"))
    assert smtp.send(job(), channel(**override)) == "smtp_not_configured"
    assert not delivery[4]


def test_published_problem_template_contains_only_reference_metadata(delivery):
    item = job(object_kind="semantic_finding", finding_id=17, title=PRIVATE, evidence=PRIVATE)
    assert smtp.send(item, channel()) == "accepted"
    message = delivery[-1][0]
    assert message["Subject"] == "SLI: security problem"
    assert "Problem: 17" in message.get_content()
    assert "/report/security.problems?id=17" in message.get_content()
    assert "simulated" not in message.get_content() and PRIVATE not in message.as_string()


@pytest.mark.parametrize("override", [
    {"password": PRIVATE}, {"host": "smtp\r\n.invalid"}, {"port": True}, {"port": 0},
    {"username": []}, {"sender": "sender@example.invalid\nBcc: recipient@example.invalid"},
    {"recipients": {}}, {"recipients": {"2": "a@example.invalid,b@example.invalid"}},
    {"recipients": {"2": "a@example.invalid\x00"}}, {"recipients": []},
    {"base_url": "http://sli.example.invalid/app"}, {"base_url": "https://user:pass@sli.example.invalid"},
    {"base_url": "https://sli.example.invalid?token=synthetic"},
])
def test_invalid_local_config_never_connects(delivery, override, caplog):
    path, _, config, _, events, _ = delivery
    path.write_text(json.dumps({**config, **override}), encoding="utf-8")
    assert smtp.send(job(), channel()) == "smtp_not_configured"
    assert events == [] and not caplog.text


@pytest.mark.parametrize("failure", ["missing", "oversized", "invalid_json", "plaintext", "unreadable", "empty_secret"])
def test_missing_or_invalid_file_credentials_fail_closed(delivery, monkeypatch, failure, caplog):
    path, password, _, _, events, _ = delivery
    if failure == "missing":
        monkeypatch.delenv("SLI_NOTIFICATION_SMTP_PASSWORD_FILE")
    elif failure == "oversized":
        path.write_bytes(b" " * 65537)
    elif failure == "invalid_json":
        path.write_bytes(b"\xff")
    elif failure == "plaintext":
        monkeypatch.setenv("SLI_NOTIFICATION_SMTP_PASSWORD", PRIVATE)
    elif failure == "unreadable":
        password.unlink()
    else:
        password.write_text("")
    assert smtp.send(job(), channel()) == "smtp_not_configured"
    assert not events and not caplog.text


@pytest.mark.parametrize("step,error,code", [
    ("connect", TimeoutError(PRIVATE), "smtp_unavailable"),
    ("starttls", ssl.SSLCertVerificationError(PRIVATE), "smtp_unavailable"),
    ("starttls", smtplib.SMTPNotSupportedError(PRIVATE), "smtp_unavailable"),
    ("login", smtplib.SMTPAuthenticationError(535, PRIVATE.encode()), "smtp_auth_failed"),
    ("login", smtplib.SMTPAuthenticationError(454, PRIVATE.encode()), "smtp_unavailable"),
    ("send", smtplib.SMTPRecipientsRefused({"synthetic": (550, PRIVATE.encode())}), "smtp_rejected"),
    ("send", smtplib.SMTPRecipientsRefused({"synthetic": (450, PRIVATE.encode())}), "smtp_unavailable"),
    ("send", smtplib.SMTPDataError(451, PRIVATE.encode()), "smtp_unavailable"),
    ("send", smtplib.SMTPDataError(554, PRIVATE.encode()), "smtp_rejected"),
    ("send", smtplib.SMTPServerDisconnected(PRIVATE), "smtp_outcome_unknown"),
    ("send", TimeoutError(PRIVATE), "smtp_outcome_unknown"),
    ("close", RuntimeError(PRIVATE), "accepted"),
])
def test_fixed_provider_results_and_no_auth_reply_or_recipient_logging(delivery, step, error, code, caplog, capsys):
    client, events = delivery[3:5]
    client.failure = (step, error)
    assert smtp.send(job(), channel()) == code
    assert events[-1] == ("close",)
    if step in {"connect", "starttls", "login"}:
        assert "send" not in [event[0] for event in events]
    assert not caplog.text and not capsys.readouterr().out


def test_refused_recipient_is_not_accepted(delivery):
    delivery[3].refused = {"synthetic": (550, PRIVATE.encode())}
    assert smtp.send(job(), channel()) == "smtp_rejected"


def test_deadline_reader_bounds_trickled_reply_and_disables_socket_after_budget(monkeypatch):
    class Socket:
        def settimeout(self, value):
            assert 0 < value <= 5
    client = smtp._SMTP(timeout=5, local_hostname="sli.example.invalid")
    client.sock = Socket()
    client.deadline = 30
    ticks = iter([0, 10, 20, 30])
    monkeypatch.setattr(smtp.time, "monotonic", lambda: next(ticks))
    reader = smtp._DeadlineReader(io.BytesIO(b"250 still trickling\r\n"), client)
    with pytest.raises(TimeoutError):
        reader.readline(8192)


def test_deadline_reader_bounds_total_multiline_response_size():
    class Client:
        sock = type("Socket", (), {"settimeout": lambda *_: None})()
        def remaining(self):
            return 5
    reader = smtp._DeadlineReader(io.BytesIO(b"250-more data\r\n" * 6000), Client())
    with pytest.raises(smtplib.SMTPServerDisconnected, match="^smtp_response_limit$"):
        while reader.readline(8192):
            pass

