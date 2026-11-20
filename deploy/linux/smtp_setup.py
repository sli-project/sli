"""SMTP operations in the existing isolated notification writer."""
import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from server.sli.core.smtp_setup import (
    SMTPSetupError, bounded_read, read_snapshot, snapshot_marker, validate_config, validate_password,
)


def publish(path, body):
    from deploy.linux.sli_secrets import _publish
    _publish(path, body, replace=True)


class Setup:
    def __init__(self, directory):
        self.directory = Path(directory)

    def handle(self, body):
        try:
            return self._handle(body)
        except SMTPSetupError:
            raise
        except Exception:
            raise SMTPSetupError() from None

    def _handle(self, body):
        user = body.get("user_id")
        if type(user) is not int or not 0 < user < 2**63:
            raise SMTPSetupError("smtp_setup_invalid")
        revision = body.get("revision")
        if type(revision) is not int or not 0 < revision < 2**63:
            raise SMTPSetupError("smtp_setup_invalid")
        action = body.get("action")
        if action == "smtp_status" and set(body) == {"action", "user_id", "revision"}:
            path = self.directory / "smtp.json"
            empty = {"host": "", "port": 587, "username": "", "sender": "", "recipients": {},
                     "secret_set": False, "needs_save": path.exists()}
            if not path.exists():
                return empty
            try:
                config, _ = read_snapshot(self.directory, revision=revision)
                ready = True
            except SMTPSetupError:
                ready = False
                try:
                    config = validate_config(json.loads(bounded_read(path)))
                except (OSError, ValueError, UnicodeError, TypeError):
                    # Keep the repair form usable without exposing malformed
                    # bytes or treating an unverified password as reusable.
                    return empty
            return {key: config[key] for key in ("host", "port", "username", "sender", "recipients")} | {
                "secret_set": ready, "needs_save": not ready}
        expected = {"action", "user_id", "host", "port", "username", "sender", "recipients", "password", "revision", "previous_revision"}
        if action != "smtp_save" or set(body) != expected:
            raise SMTPSetupError("smtp_setup_invalid")
        previous = body["previous_revision"]
        if type(previous) is not int or not 0 < previous < 2**63 - 1 or revision != previous + 1:
            raise SMTPSetupError("smtp_setup_invalid")
        url = urlsplit(os.environ["SLI_PUBLIC_URL"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise SMTPSetupError()
        config = validate_config({key: body[key] for key in ("host", "port", "username", "sender", "recipients")} | {
            "base_url": f"https://{url.netloc}/app"})
        password = body["password"]
        if password == "":
            # A partial/legacy installation needs an explicit password again; do
            # not silently reuse a secret whose matching configuration is unknown.
            _, password = read_snapshot(self.directory, revision=previous)
        password = validate_password(password)
        marker = self.directory / "smtp.ready"
        # Invalidate before either replacement. A crash cannot leave a valid
        # marker for a mixed pair; each _publish fsyncs the parent directory.
        marker.unlink(missing_ok=True)
        fd = os.open(self.directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        publish(self.directory / "notification_smtp_password", password.encode())
        publish(self.directory / "smtp.json", json.dumps(config, ensure_ascii=False).encode())
        publish(marker, snapshot_marker(config, password, revision).encode())
        return {"secret_set": True, "needs_save": False}
