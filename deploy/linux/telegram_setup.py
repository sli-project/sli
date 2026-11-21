"""Isolated file-secret writer; fixed Telegram methods, no database credentials.

Only the authenticated API container shares the private Unix socket. Credential
publication uses sli-secrets' atomic, root-owned, group-readable file mechanism.
The delivery container mounts this directory read-only; the API never mounts it.
"""
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import socketserver
import signal
import threading
import time
import subprocess
from urllib.parse import urlsplit

from deploy.linux.sli_secrets import _directory, _publish
from server.sli.core.notification_secrets import NotificationSecretError, validate_notification_secret
from server.sli.core.notification_telegram import bot_request
from server.sli.core.telegram_setup import TelegramSetupCode, TelegramSetupError, error_response, validate_proxy_url


class Setup:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.candidates = {}

    def read(self):
        path = self.directory / "telegram.json"
        if not path.exists():
            url = urlsplit(os.environ["SLI_PUBLIC_URL"])
            if url.scheme != "https" or not url.hostname or url.username or url.password:
                raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
            return {"base_url": f"https://{url.netloc}/app", "recipients": {}, "names": {},
                    **({"proxy_url": os.environ.get("SLI_NOTIFICATION_PROXY", "")}
                       if os.environ.get("SLI_NATIVE_NOTIFICATION_SETUP") == "1" else {})}
        raw = path.read_bytes()
        if len(raw) > 65536:
            raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
        config = json.loads(raw)
        if (not isinstance(config, dict) or (not {"base_url", "recipients"} <= set(config) or not set(config) <= {"base_url", "recipients", "names", "proxy_url"})
                or not isinstance(config.get("base_url"), str) or not isinstance(config.get("recipients"), dict)
                or ("names" in config and (not isinstance(config["names"], dict)
                    or any(not isinstance(value, str) or len(value) > 128 for value in config["names"].values())))):
            raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)
        config.setdefault("names", {})  # Supported legacy delivery config; no file write on status.
        if os.environ.get("SLI_NATIVE_NOTIFICATION_SETUP") == "1":
            config["proxy_url"] = os.environ.get("SLI_NOTIFICATION_PROXY", "")
        try:
            validate_proxy_url(config.get("proxy_url", ""))
        except TelegramSetupError:
            raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE) from None
        return config

    def write(self, config):
        body = json.dumps(config, ensure_ascii=False).encode()
        if len(body) > 65536:
            raise TelegramSetupError(TelegramSetupCode.FAILED)
        _publish(self.directory / "telegram.json", body, replace=True)

    def handle(self, body):
        if isinstance(body, dict) and body.get("action") in {"smtp_status", "smtp_save"}:
            from deploy.linux.smtp_setup import Setup as SMTPSetup
            return SMTPSetup(self.directory).handle(body)
        action, user = body["action"], body["user_id"]
        if type(user) is not int or user <= 0:
            raise TelegramSetupError(TelegramSetupCode.FAILED)
        config = self.read()
        token_path = self.directory / "notification_telegram_token"
        if action == "status" and set(body) == {"action", "user_id"}:
            chat = config["recipients"].get(str(user))
            bound = isinstance(chat, str) and re.fullmatch(r"-?[1-9][0-9]{0,15}", chat) is not None
            return {"secret_set": token_path.exists(), "chat_bound": bound, "chat_name": config["names"].get(str(user)),
                    "proxy_url": config.get("proxy_url", "")}
        if action in {"verify", "token"} and set(body) in ({"action", "user_id", "token"}, {"action", "user_id", "token", "proxy_url"}):
            proxy_url = validate_proxy_url(config.get("proxy_url", "") if os.environ.get("SLI_NATIVE_NOTIFICATION_SETUP") == "1"
                                           else body.get("proxy_url", config.get("proxy_url", "")))
            token = body["token"]
            if not isinstance(token, str):
                raise TelegramSetupError(TelegramSetupCode.INVALID_TOKEN)
            try:
                validate_notification_secret("notification_telegram_token", token)
            except NotificationSecretError:
                raise TelegramSetupError(TelegramSetupCode.INVALID_TOKEN) from None
            bot = bot_request(token, "getMe", {}, proxy_url=proxy_url)
            if not isinstance(bot, dict) or bot.get("is_bot") is not True:
                raise TelegramSetupError(TelegramSetupCode.PROTOCOL)
            name = str(bot.get("first_name") or bot.get("username") or "Telegram")[:128]
            if action == "verify":
                return {"bot_name": name}
            # Replacing a bot invalidates destinations belonging to the previous bot.
            self.write({"base_url": config["base_url"], "recipients": {}, "names": {}, "proxy_url": proxy_url})
            _publish(token_path, token.encode(), replace=True)
            self.candidates.clear()
            return {"secret_set": True, "bot_name": name}
        token = token_path.read_text("utf-8").rstrip("\r\n")
        validate_notification_secret("notification_telegram_token", token)
        generation = hashlib.sha256(token.encode()).hexdigest()
        if action == "chat_generation" and set(body) == {"action", "user_id"}:
            return {"generation": generation}
        if action == "chats" and set(body) == {"action", "user_id", "generation", "observations"}:
            observations = body["observations"]
            if body["generation"] != generation or not isinstance(observations, list) or len(observations) > 100:
                raise TelegramSetupError(TelegramSetupCode.CONFLICT)
            found = {}
            for chat in observations:
                if (not isinstance(chat, dict) or set(chat) != {"id", "name"} or type(chat["id"]) is not int
                        or not 0 < chat["id"] < 10**16 or not isinstance(chat["name"], str)
                        or not 0 < len(chat["name"]) <= 128 or not chat["name"].isprintable()):
                    raise TelegramSetupError(TelegramSetupCode.FAILED)
                found[str(chat["id"])] = chat["name"]
            choices = {secrets.token_urlsafe(24): (chat, name) for chat, name in found.items()}
            self.candidates[user] = (time.monotonic() + 300, generation, choices)
            return {"chats": [{"choice": key, "name": value[1]} for key, value in choices.items()]}
        if action == "bind" and set(body) == {"action", "user_id", "choice"}:
            expires, expected_generation, choices = self.candidates.get(user, (0, "", {}))
            if time.monotonic() >= expires or expected_generation != generation or body["choice"] not in choices:
                raise TelegramSetupError(TelegramSetupCode.FAILED)
            chat, name = choices[body["choice"]]
            config["recipients"][str(user)] = chat
            config["names"][str(user)] = name
            self.write(config)
            self.candidates.pop(user, None)
            return {"chat_name": name, "secret_set": True}
        raise TelegramSetupError(TelegramSetupCode.FAILED)


def refresh_delivery(body):
    """A completed publication needs a fresh systemd credential snapshot."""
    if (os.environ.get("SLI_NATIVE_NOTIFICATION_SETUP") == "1"
            and body.get("action") in {"token", "bind", "smtp_save"}):
        result = subprocess.run(["/usr/bin/systemctl", "restart", "sli-notification-delivery.service"],
                                capture_output=True, timeout=90, check=False,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        if result.returncode:
            raise TelegramSetupError(TelegramSetupCode.UNAVAILABLE)


def prepare_socket(path):
    gid = 10001
    if os.environ.get("SLI_NATIVE_NOTIFICATION_SETUP") == "1":
        import grp
        gid = grp.getgrnam("sli-api").gr_gid
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chown(path.parent, 0, gid)
    path.parent.chmod(0o750)
    path.unlink(missing_ok=True)
    return gid


def main():
    directory = Path(os.environ.get("SLI_TELEGRAM_SECRET_DIR", "/var/lib/notification-secrets"))
    _directory(directory)
    setup = Setup(directory)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(30)
            try:
                raw = self.rfile.readline(65537)
                if not raw:
                    return
                if len(raw) > 65536:
                    raise ValueError
                body = json.loads(raw)
                result = setup.handle(body)
                refresh_delivery(body)
            except Exception as exc:
                from server.sli.core.smtp_setup import SMTPSetupError
                result = {"error": exc.code} if isinstance(exc, SMTPSetupError) else error_response(exc)
            self.wfile.write(json.dumps(result).encode() + b"\n")

    path = Path(os.environ.get("SLI_TELEGRAM_SETUP_SOCKET", "/run/notification-setup/control.sock"))
    gid = prepare_socket(path)
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        os.chown(path, 0, gid)
        path.chmod(0o660)
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        server.timeout = 1
        while not stop.is_set():
            server.handle_request()
    return 0


if __name__ == "__main__":
    main()

