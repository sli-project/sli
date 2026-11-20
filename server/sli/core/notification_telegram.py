"""N05 Telegram delivery through the fixed Bot API and file-backed SLI secret.

The delivery worker reads SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE: a bounded JSON
object with base_url and recipients (SLI user ID to approved numeric chat ID).
The isolated setup service publishes this file and the SLI file secret; the web
process has only a private control socket. Credentials never belong in JSON.
"""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from server.sli.core.notification_secrets import NotificationSecretError, read_notification_secret
from server.sli.core.notification_message import message_content
from server.sli.core.telegram_setup import TelegramSetupCode, TelegramSetupError, validate_proxy_url

SECRET_REF = "SLI_NOTIFY_TELEGRAM_TOKEN"
STORAGE_REF = "notification_telegram_token"
MAX_RESPONSE = 65536
# Conservatively space all messages, including users sharing one approved group.
MIN_INTERVAL = 3
RESULTS = {
    "accepted": "accepted",
    "telegram_not_configured": "blocked",
    "telegram_auth_failed": "blocked",
    "telegram_chat_denied": "blocked",
    "telegram_rejected": "blocked",
    "telegram_rate_limited": "retry",
    "telegram_unavailable": "retry",
    "telegram_outcome_unknown": "delivery_unknown",
}


@dataclass(frozen=True)
class Outcome:
    code: str
    retry_after: int = 0


def _config(recipient_user_id):
    with Path(os.environ["SLI_NOTIFICATION_TELEGRAM_CONFIG_FILE"]).open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError
    config = json.loads(raw)
    if (not isinstance(config, dict) or not {"base_url", "recipients"} <= set(config)
            or not set(config) <= {"base_url", "recipients", "names", "proxy_url"}):
        raise ValueError
    base_url = config["base_url"]
    if (not isinstance(base_url, str) or not 0 < len(base_url) <= 1024
            or any(ord(c) < 33 or ord(c) == 127 for c in base_url)
            or not isinstance(config["recipients"], dict)):
        raise ValueError
    url = urlsplit(base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError
    chat = config["recipients"].get(str(recipient_user_id))
    # No public usernames, arbitrary endpoints or chat migrations inferred from replies.
    if not isinstance(chat, str) or not re.fullmatch(r"-?[1-9][0-9]{0,15}", chat):
        raise ValueError
    proxy = (os.environ.get("SLI_NOTIFICATION_PROXY", "") if os.environ.get("SLI_DEPLOYMENT_MODE") == "native"
             else config.get("proxy_url", ""))
    return base_url.rstrip("/"), chat, validate_proxy_url(proxy)


class _Reader:
    """Bound headers and body together, including slowly trickled HTTP replies."""

    def __init__(self, stream, sock, deadline):
        self.stream, self.sock, self.deadline = stream, sock, deadline
        self.total = 0

    def read1(self, size):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        self.sock.settimeout(min(5, remaining))
        chunk = self.stream.read1(min(size, MAX_RESPONSE + 1 - self.total))
        self.total += len(chunk)
        if self.total > MAX_RESPONSE:
            raise ValueError
        return chunk

    def read(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.read1(size - len(chunks))
            if not chunk:
                break
            chunks.extend(chunk)
        return bytes(chunks)

    def readline(self, limit=-1):
        line = bytearray()
        while limit < 0 or len(line) < limit:
            chunk = self.read1(1)
            if not chunk:
                break
            line.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(line)

    def flush(self):
        return self.stream.flush()

    def close(self):
        self.stream.close()


class _Response(http.client.HTTPResponse):
    def __init__(self, sock, **kwargs):
        super().__init__(sock, **kwargs)
        self.fp = _Reader(self.fp, sock, time.monotonic() + 20)


def _seconds(value):
    if type(value) is int and 0 < value <= 2**31 - 1:
        return value
    return 0


def _connection(proxy_url):
    proxy_url = validate_proxy_url(proxy_url)
    context = ssl.create_default_context()
    if proxy_url:
        proxy = urlsplit(proxy_url)
        client = http.client.HTTPSConnection(proxy.hostname, proxy.port, timeout=5, context=context)
    else:
        client = http.client.HTTPSConnection("api.telegram.org", timeout=5, context=context)
    try:
        client.set_debuglevel(0)
        client.response_class = _Response
        if proxy_url:
            # HTTPSConnection tunnels HTTP first, then verifies TLS for Telegram.
            client.set_tunnel("api.telegram.org", 443)
        return client
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        raise


def bot_request(token, method, values, *, proxy_url=""):
    """Bounded setup calls; never expose token-bearing exception URLs/replies."""
    if method not in {"getMe", "getUpdates"}:
        raise TelegramSetupError(TelegramSetupCode.FAILED)
    client = None
    try:
        client = _connection(proxy_url)
        client.request("POST", f"/bot{token}/{method}", body=json.dumps(values).encode(),
                       headers={"Content-Type": "application/json", "Connection": "close"})
        response = client.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE or 300 <= response.status < 400:
            raise TelegramSetupError(TelegramSetupCode.PROTOCOL)
        if response.status == 429:
            raise TelegramSetupError(TelegramSetupCode.RATE_LIMITED)
        if 500 <= response.status < 600:
            raise TelegramSetupError(TelegramSetupCode.PROVIDER_UNAVAILABLE)
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            raise TelegramSetupError(TelegramSetupCode.PROTOCOL) from None
        if not isinstance(payload, dict):
            raise TelegramSetupError(TelegramSetupCode.PROTOCOL)
        if response.status != 200:
            if (payload.get("ok") is not False or type(payload.get("error_code")) is not int
                    or payload["error_code"] != response.status):
                raise TelegramSetupError(TelegramSetupCode.PROTOCOL)
            code = {401: TelegramSetupCode.INVALID_TOKEN, 404: TelegramSetupCode.INVALID_TOKEN,
                    409: TelegramSetupCode.CONFLICT}.get(response.status, TelegramSetupCode.FAILED)
            raise TelegramSetupError(code)
        if (payload.get("ok") is not True or "result" not in payload
                or (method == "getMe" and (not isinstance(payload["result"], dict)
                    or payload["result"].get("is_bot") is not True))
                or (method == "getUpdates" and not isinstance(payload["result"], list))):
            raise TelegramSetupError(TelegramSetupCode.PROTOCOL)
        return payload["result"]
    except TelegramSetupError:
        raise
    except ssl.SSLError:
        raise TelegramSetupError(TelegramSetupCode.TLS) from None
    except TimeoutError:
        raise TelegramSetupError(TelegramSetupCode.TIMEOUT) from None
    except OSError:
        raise TelegramSetupError(TelegramSetupCode.NETWORK) from None
    except (ValueError, http.client.HTTPException):
        raise TelegramSetupError(TelegramSetupCode.PROTOCOL) from None
    except Exception:
        raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE) from None
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _outcome(status, payload, retry_after):
    if not isinstance(payload, dict):
        return Outcome("telegram_outcome_unknown")
    if status == 200 and payload.get("ok") is True:
        result = payload.get("result")
        if isinstance(result, dict) and type(result.get("message_id")) is int and result["message_id"] > 0:
            return Outcome("accepted")
        return Outcome("telegram_outcome_unknown")
    if payload.get("ok") is not False:
        return Outcome("telegram_outcome_unknown")
    error = payload.get("error_code")
    if type(error) is not int or error != status:
        return Outcome("telegram_outcome_unknown")
    if status in {401, 404}:
        return Outcome("telegram_auth_failed")
    if status in {400, 403}:
        return Outcome("telegram_chat_denied")
    if status == 429:
        parameters = payload.get("parameters")
        wait = _seconds(parameters.get("retry_after")) if isinstance(parameters, dict) else 0
        return Outcome("telegram_rate_limited", max(60, wait, retry_after))
    if 500 <= status < 600:
        return Outcome("telegram_unavailable")
    return Outcome("telegram_rejected")


def send(job, channel):
    """Fixed results only; no logging, HTTP redirects or debug output.

    A lost/malformed reply after submission is terminal: the provider may have
    accepted the message. Its stable job ID lets an operator inspect duplicates.
    """
    if (not channel or not channel["enabled"] or channel["secret_ref"] != SECRET_REF
            or channel["tls_mode"] != "tls"):
        return Outcome("telegram_not_configured")
    try:
        if job["channel"] != "telegram":
            return Outcome("telegram_not_configured")
        base_url, chat, proxy_url = _config(job["recipient_user_id"])
        token = read_notification_secret(STORAGE_REF)
        _, body_text = message_content(job, base_url)
        # Deliberately excludes identity, paths, addresses and evidence payloads.
        body = json.dumps({
            "chat_id": chat,
            "text": body_text,
            "link_preview_options": {"is_disabled": True},
            "protect_content": True,
        }).encode("utf-8")
    except (KeyError, OSError, ValueError, TypeError, NotificationSecretError):
        return Outcome("telegram_not_configured")

    client, submitting = None, False
    try:
        # http.client does not log URLs; debug is explicitly disabled. Avoid HTTP
        # libraries whose error/debug logs can include the token-bearing path.
        client = _connection(proxy_url)
        client.connect()
        submitting = True
        client.request("POST", f"/bot{token}/sendMessage", body=body,
                       headers={"Content-Type": "application/json", "Connection": "close"})
        response = client.getresponse()
        # Never follow Location or keep a provider description/message/chat in a receipt.
        if 300 <= response.status < 400:
            return Outcome("telegram_rejected")
        retry_header = response.getheader("Retry-After", "")
        retry_after = _seconds(int(retry_header)) if re.fullmatch(r"[0-9]{1,10}", retry_header) else 0
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            return Outcome("telegram_outcome_unknown")
        return _outcome(response.status, json.loads(raw), retry_after)
    except Exception:
        # Do not interpolate exceptions: they can contain the path, token or reply.
        return Outcome("telegram_outcome_unknown" if submitting else "telegram_unavailable")
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
