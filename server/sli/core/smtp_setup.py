"""Bounded SMTP setup protocol and coherent private-file snapshots."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from urllib.parse import urlsplit

MAX_BYTES = 65536
_MAILBOX = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")
FIELDS = {"host", "port", "username", "sender", "recipients", "base_url"}


class SMTPSetupError(ValueError):
    def __init__(self, code="smtp_setup_unavailable"):
        self.code = code if code in {"smtp_setup_invalid", "smtp_setup_unavailable", "smtp_setup_conflict", "smtp_setup_needs_save"} else "smtp_setup_unavailable"
        self.status = {"smtp_setup_invalid": 400, "smtp_setup_conflict": 409, "smtp_setup_needs_save": 409}.get(self.code, 503)
        super().__init__(self.code)


def text(value):
    return isinstance(value, str) and 0 < len(value) <= 1024 and not any(ord(c) < 32 or ord(c) == 127 for c in value)


def mailbox(value):
    return text(value) and _MAILBOX.fullmatch(value) is not None


def validate_config(config):
    try:
        if not isinstance(config, dict) or set(config) != FIELDS:
            raise ValueError
        if (not all(text(config[key]) for key in ("host", "username", "sender", "base_url"))
                or type(config["port"]) is not int or not 1 <= config["port"] <= 65535
                or not mailbox(config["sender"]) or not isinstance(config["recipients"], dict)
                or len(config["recipients"]) > 1000):
            raise ValueError
        host = config["host"]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                     for part in host.split(".")):
                raise ValueError from None
        if any(not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]{0,18}", key)
               or int(key) >= 2**63 or not mailbox(value) for key, value in config["recipients"].items()):
            raise ValueError
        url = urlsplit(config["base_url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError
        if len(json.dumps(config).encode()) > MAX_BYTES:
            raise ValueError
        return config
    except (ValueError, TypeError):
        raise SMTPSetupError("smtp_setup_invalid") from None


def validate_password(value):
    if (not isinstance(value, str) or not value or len(value.encode()) > MAX_BYTES
            or any(c in value for c in "\r\n\x00")):
        raise SMTPSetupError("smtp_setup_invalid")
    return value


def snapshot_digest(config, password):
    body = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(body + b"\0" + password.encode()).hexdigest()


def bounded_read(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise SMTPSetupError()
    return raw


def snapshot_marker(config, password, revision):
    if type(revision) is not int or not 0 < revision < 2**63:
        raise SMTPSetupError("smtp_setup_invalid")
    return json.dumps({"revision": revision, "digest": snapshot_digest(config, password)}, sort_keys=True)


def read_snapshot(directory, *, revision, prefix=""):
    """Read once, validate once, return captured values, never paths/re-read handles."""
    directory = Path(directory)
    try:
        config = validate_config(json.loads(bounded_read(directory / (prefix + "smtp.json"))))
        password = validate_password(bounded_read(directory / (prefix + "notification_smtp_password")).decode())
        marker = json.loads(bounded_read(directory / (prefix + "smtp.ready")))
        if (type(revision) is not int or not 0 < revision < 2**63 or not isinstance(marker, dict)
                or set(marker) != {"revision", "digest"} or type(marker["revision"]) is not int
                or marker["revision"] != revision or not isinstance(marker["digest"], str)
                or not hmac.compare_digest(marker["digest"], snapshot_digest(config, password))):
            raise ValueError
        return config, password
    except (OSError, ValueError, UnicodeError, TypeError):
        raise SMTPSetupError("smtp_setup_needs_save") from None


def request(action, user_id, **values):
    if type(user_id) is not int or not 0 < user_id < 2**63:
        raise PermissionError("smtp_setup_denied")
    try:
        body = json.dumps({"action": "smtp_" + action, "user_id": user_id, **values}).encode() + b"\n"
        if len(body) > MAX_BYTES:
            raise SMTPSetupError("smtp_setup_invalid")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30)
            client.connect(os.environ.get("SLI_TELEGRAM_SETUP_SOCKET", "/run/notification-setup/control.sock"))
            client.sendall(body)
            with client.makefile("rb") as stream:
                raw = stream.readline(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError
        if "error" in result:
            raise SMTPSetupError(result["error"])
        return result
    except SMTPSetupError:
        raise
    except Exception:
        raise SMTPSetupError() from None
