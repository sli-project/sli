"""Admin setup client. The API has a socket, never a credential file mount."""
import ipaddress
import json
import re
import os
import socket
from enum import Enum
from urllib.parse import urlsplit


class TelegramSetupCode(str, Enum):
    INVALID_TOKEN = "telegram_setup_invalid_token"
    INVALID_PROXY = "telegram_setup_invalid_proxy"
    NETWORK = "telegram_setup_network"
    TLS = "telegram_setup_tls"
    TIMEOUT = "telegram_setup_timeout"
    UNAVAILABLE = "telegram_setup_unavailable"
    PROVIDER_UNAVAILABLE = "telegram_setup_provider_unavailable"
    RATE_LIMITED = "telegram_setup_rate_limited"
    CONFLICT = "telegram_setup_conflict"
    PROTOCOL = "telegram_setup_protocol"
    FAILED = "telegram_setup_failed"


class TelegramSetupError(ValueError):
    """Only a fixed enum member can supply a public setup error."""

    def __init__(self, code):
        self.code = code if isinstance(code, TelegramSetupCode) else TelegramSetupCode.UNAVAILABLE
        super().__init__(self.code.value)

    @property
    def status(self):
        return {TelegramSetupCode.INVALID_TOKEN: 400, TelegramSetupCode.INVALID_PROXY: 400, TelegramSetupCode.NETWORK: 503,
                TelegramSetupCode.TLS: 503, TelegramSetupCode.TIMEOUT: 504,
                TelegramSetupCode.UNAVAILABLE: 503, TelegramSetupCode.PROVIDER_UNAVAILABLE: 503,
                TelegramSetupCode.RATE_LIMITED: 429, TelegramSetupCode.CONFLICT: 409,
                TelegramSetupCode.PROTOCOL: 502, TelegramSetupCode.FAILED: 400}[self.code]


def validate_proxy_url(value):
    """Credential-free explicit HTTP CONNECT proxy; validation performs no I/O."""
    try:
        if not isinstance(value, str) or len(value) > 1024:
            raise ValueError
        if value == "":
            return value
        if (not value.startswith("http://") or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
                or any(c in value for c in "@?#\\")):
            raise ValueError
        url = urlsplit(value)
        if (url.scheme != "http" or not url.hostname or url.username is not None or url.password is not None
                or url.path or url.query or url.fragment or not 1 <= (url.port or 0) <= 65535
                or not re.fullmatch(r"[0-9]{1,5}", url.netloc.rsplit(":", 1)[-1])):
            raise ValueError
        host = url.hostname
        if url.netloc.startswith("["):
            if not re.fullmatch(r"[0-9a-fA-F:.]+", host):
                raise ValueError
            ipaddress.IPv6Address(host)
        elif re.fullmatch(r"[0-9.]+", host):
            ipaddress.IPv4Address(host)
        elif (len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in host.split("."))):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise TelegramSetupError(TelegramSetupCode.INVALID_PROXY) from None


def error_response(error):
    code = error.code if isinstance(error, TelegramSetupError) else TelegramSetupCode.UNAVAILABLE
    return {"error": (code if isinstance(code, TelegramSetupCode) else TelegramSetupCode.UNAVAILABLE).value}


def request(action, user_id, **values):
    if type(user_id) is not int or user_id <= 0:
        raise PermissionError("telegram_setup_denied")
    if "proxy_url" in values:
        values["proxy_url"] = validate_proxy_url(values["proxy_url"])
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(30)
            client.connect(os.environ.get("SLI_TELEGRAM_SETUP_SOCKET", "/run/notification-setup/control.sock"))
            client.sendall(json.dumps({"action": action, "user_id": user_id, **values}).encode() + b"\n")
            with client.makefile("rb") as stream:
                raw = stream.readline(65537)
            if len(raw) > 65536:
                raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
            if "error" in result:
                if set(result) != {"error"}:
                    raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
                try:
                    code = TelegramSetupCode(result["error"])
                except (ValueError, TypeError):
                    code = TelegramSetupCode.UNAVAILABLE
                raise TelegramSetupError(code)
            if action == "status" and (type(result.get("secret_set")) is not bool
                    or type(result.get("chat_bound")) is not bool
                    or not set(result) <= {"secret_set", "chat_bound", "chat_name", "proxy_url"}
                    or (result.get("chat_name") is not None and (not isinstance(result["chat_name"], str)
                        or len(result["chat_name"]) > 128))):
                raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
            if action == "status":
                try:
                    result["proxy_url"] = validate_proxy_url(result.get("proxy_url", ""))
                except TelegramSetupError:
                    raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE) from None
            return result
    except TelegramSetupError:
        raise
    except TimeoutError:
        raise TelegramSetupError(TelegramSetupCode.TIMEOUT) from None
    except Exception:
        raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE) from None
