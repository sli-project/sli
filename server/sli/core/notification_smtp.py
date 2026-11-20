"""SMTP delivery: verified TLS and a single coherent private-file snapshot.

The isolated setup writer publishes smtp.json, its write-only password and a
readiness marker in the existing private notification directory. Unmarked or
partially published configurations fail closed until saved again through setup.
"""

from __future__ import annotations

import os
import http.client
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from server.sli.core.notification_secrets import NotificationSecretError
from server.sli.core.smtp_setup import read_snapshot
from server.sli.core.notification_message import message_content
from server.sli.core.telegram_setup import validate_proxy_url

SECRET_REF = "SLI_NOTIFY_SMTP_PASSWORD"
# Registry metadata predates the N02 secret manifest. Resolve the fixed registry
# reference explicitly; never interpret a reference as a path or environment key.
STORAGE_REF = "notification_smtp_password"
RESULTS = {
    "accepted": "accepted",
    "smtp_not_configured": "blocked",
    "smtp_auth_failed": "blocked",
    "smtp_rejected": "failed",
    "smtp_unavailable": "retry",
    "smtp_outcome_unknown": "delivery_unknown",
}
def _config(recipient_user_id, revision):
    # Fixed sibling files only. Legacy/manual configurations without a matching
    # publication marker require saving through setup before they can send.
    path = Path(os.environ["SLI_NOTIFICATION_SMTP_CONFIG_FILE"])
    prefix = "notifications_" if os.environ.get("SLI_DEPLOYMENT_MODE") == "native" else ""
    if (path.name != prefix + "smtp.json" or os.environ.get("SLI_NOTIFICATION_SMTP_PASSWORD")
            or Path(os.environ["SLI_NOTIFICATION_SMTP_PASSWORD_FILE"]) != path.parent / (prefix + "notification_smtp_password")):
        raise ValueError
    config, password = read_snapshot(path.parent, revision=revision, prefix=prefix)
    recipient = config["recipients"].get(str(recipient_user_id))
    if not recipient:
        raise ValueError
    return config, recipient, password


class _DeadlineReader:
    """Bound even a multiline/trickled SMTP reply to the whole-attempt deadline."""

    def __init__(self, stream, client):
        self.stream, self.client = stream, client
        self.total = 0

    def readline(self, limit):
        line = bytearray()
        while len(line) < limit:
            self.client.sock.settimeout(self.client.remaining())
            chunk = self.stream.read1(1)
            if not chunk:
                break
            self.total += len(chunk)
            if self.total > 65536:
                raise smtplib.SMTPServerDisconnected("smtp_response_limit")
            line.extend(chunk)
            if chunk == b"\n":
                break
        return bytes(line)

    def close(self):
        self.stream.close()


class _Deadline:
    def _get_socket(self, host, port, timeout):
        proxy = (os.environ.get("SLI_NOTIFICATION_PROXY", "")
                 if os.environ.get("SLI_DEPLOYMENT_MODE") == "native" else "")
        if not proxy:
            return super()._get_socket(host, port, timeout)
        parsed = urlsplit(validate_proxy_url(proxy))
        tunnel = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=self.remaining())
        try:
            tunnel.set_debuglevel(0)
            tunnel.set_tunnel(host, port)
            tunnel.connect()
            sock = tunnel.sock
            if isinstance(self, smtplib.SMTP_SSL):
                sock = self.context.wrap_socket(sock, server_hostname=host)
            tunnel.sock = None  # Transfer ownership to smtplib.
            return sock
        except Exception:
            tunnel.close()
            raise

    def connect(self, host="localhost", port=0, source_address=None):
        # smtplib.connect does not refresh _host when constructed without host.
        # TLS and STARTTLS both use it for verified peer identity/SNI. Capture
        # the already-validated configured host before either wrapping path.
        self._host = host
        return super().connect(host, port, source_address)

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        return min(5, remaining)

    def getreply(self):
        if self.file is None:
            self.file = _DeadlineReader(self.sock.makefile("rb"), self)
        return super().getreply()

    def send(self, data):
        if self.sock:
            self.sock.settimeout(self.remaining())
        return super().send(data)


class _SMTP(_Deadline, smtplib.SMTP):
    pass


class _SMTPSSL(_Deadline, smtplib.SMTP_SSL):
    pass


def send(job, channel):
    """Return only an allowlisted code. Never log addresses, AUTH or replies.

    accepted means the SMTP server accepted DATA, not delivery to a person's
    inbox. An uncertain DATA outcome is terminal to avoid automatic duplicates.
    A crash between acceptance and the durable receipt remains an SMTP limit.
    """
    if (not channel or not channel["enabled"] or channel["secret_ref"] != SECRET_REF
            or channel["tls_mode"] not in {"tls", "starttls"}):
        return "smtp_not_configured"
    try:
        config, recipient, password = _config(job["recipient_user_id"], channel["revision"])
        # No object/evidence payload is accepted by this stage's template.
        job_id = str(UUID(str(job["id"])))
        if job["channel"] != "smtp":
            return "smtp_not_configured"
        title, body = message_content(job, config["base_url"])
        message = EmailMessage()
        message["From"], message["To"] = config["sender"], recipient
        message["Subject"] = title
        message["Message-ID"] = f"<{job_id}@notifications.sli.invalid>"
        message["Date"] = formatdate(usegmt=True)
        message.set_content(body)
    except (KeyError, OSError, ValueError, TypeError, NotificationSecretError):
        return "smtp_not_configured"

    client, submitting = None, False
    try:
        context = ssl.create_default_context()
        # Use approved sender metadata for EHLO, never the worker's private name.
        options = {"timeout": 5, "local_hostname": config["sender"].rsplit("@", 1)[1]}
        client = _SMTPSSL(context=context, **options) if channel["tls_mode"] == "tls" else _SMTP(**options)
        client.deadline = time.monotonic() + 30
        client.set_debuglevel(0)
        client.connect(config["host"], config["port"])
        client.ehlo()
        if channel["tls_mode"] == "starttls":
            client.starttls(context=context)
            client.ehlo()
        client.login(config["username"], password)
        submitting = True
        refused = client.send_message(message, from_addr=config["sender"], to_addrs=[recipient])
        if refused:
            return "smtp_rejected"
        return "accepted"
    except smtplib.SMTPAuthenticationError as exc:
        return "smtp_unavailable" if 400 <= exc.smtp_code < 500 else "smtp_auth_failed"
    except smtplib.SMTPRecipientsRefused as exc:
        return "smtp_unavailable" if all(400 <= value[0] < 500 for value in exc.recipients.values()) else "smtp_rejected"
    except smtplib.SMTPResponseException as exc:
        return "smtp_unavailable" if 400 <= exc.smtp_code < 500 else "smtp_rejected"
    except Exception:
        return "smtp_outcome_unknown" if submitting else "smtp_unavailable"
    finally:
        # QUIT failure after DATA acceptance must not turn success into a retry.
        # Closing the socket also avoids an unbounded extra protocol exchange.
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

