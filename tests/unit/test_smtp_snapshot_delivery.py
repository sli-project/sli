"""Transport cannot reach SMTP for incomplete or mixed publication snapshots."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from uuid import uuid4

from server.sli.core import notification_smtp as smtp
from server.sli.core.smtp_setup import snapshot_marker


class DeliverySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = {"host": "smtp.example.invalid", "port": 587, "username": "fixture",
                       "sender": "sender@example.invalid", "recipients": {"1": "receiver@example.invalid"},
                       "base_url": "https://sli.example.invalid/app"}
        self.password = "synthetic-password"
        (self.directory / "smtp.json").write_text(json.dumps(self.config))
        (self.directory / "notification_smtp_password").write_text(self.password)
        (self.directory / "notification_smtp_password").chmod(0o600)
        (self.directory / "smtp.ready").write_text(snapshot_marker(self.config, self.password, 1))
        self.environment = patch.dict("os.environ", {"SLI_NOTIFICATION_SMTP_CONFIG_FILE": str(self.directory / "smtp.json"),
            "SLI_NOTIFICATION_SMTP_PASSWORD_FILE": str(self.directory / "notification_smtp_password")})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.job = {"id": str(uuid4()), "object_id": str(uuid4()), "object_kind": "test_problem", "channel": "smtp", "recipient_user_id": 1, "created_at": "2026-10-25T00:00:00Z"}
        self.channel = {"enabled": True, "tls_mode": "starttls", "secret_ref": smtp.SECRET_REF, "revision": 1}

    def test_missing_marker_never_constructs_smtp_client(self):
        (self.directory / "smtp.ready").unlink()
        with patch.object(smtp, "_SMTP", side_effect=AssertionError("network reached")):
            self.assertEqual(smtp.send(self.job, self.channel), "smtp_not_configured")

    def test_mixed_secret_never_constructs_smtp_client(self):
        (self.directory / "notification_smtp_password").write_text("synthetic-other")
        with patch.object(smtp, "_SMTP", side_effect=AssertionError("network reached")):
            self.assertEqual(smtp.send(self.job, self.channel), "smtp_not_configured")

    def test_validated_snapshot_is_not_reread_before_login(self):
        client = Mock()
        client.send_message.return_value = {}
        def mutate_after_capture(*args, **kwargs):
            (self.directory / "notification_smtp_password").write_text("synthetic-other")
            (self.directory / "smtp.json").write_text(json.dumps({**self.config, "host": "other.example.invalid"}))
        client.connect.side_effect = mutate_after_capture
        with patch.object(smtp, "_SMTP", return_value=client):
            self.assertEqual(smtp.send(self.job, self.channel), "accepted")
        client.connect.assert_called_once_with("smtp.example.invalid", 587)
        client.login.assert_called_once_with("fixture", self.password)

    def test_timeout_late_publication_cannot_follow_generic_enable(self):
        # A timed-out save reserved/published generation 1; a generic enable
        # advances the DB to generation 2, so the late coherent pair is unusable.
        with patch.object(smtp, "_SMTP", side_effect=AssertionError("network reached")):
            self.assertEqual(smtp.send(self.job, {**self.channel, "revision": 2}), "smtp_not_configured")

    def test_late_old_generation_after_new_save_fails_closed(self):
        newest = {**self.config, "host": "new.example.invalid"}
        (self.directory / "smtp.json").write_text(json.dumps(newest))
        (self.directory / "notification_smtp_password").write_text("synthetic-new")
        (self.directory / "smtp.ready").write_text(snapshot_marker(newest, "synthetic-new", 2))
        # Model a delayed old publication replacing all three files: even a
        # coherent old pair must not be accepted for the current DB generation.
        (self.directory / "smtp.json").write_text(json.dumps(self.config))
        (self.directory / "notification_smtp_password").write_text(self.password)
        (self.directory / "smtp.ready").write_text(snapshot_marker(self.config, self.password, 1))
        with patch.object(smtp, "_SMTP", side_effect=AssertionError("network reached")):
            self.assertEqual(smtp.send(self.job, {**self.channel, "revision": 2}), "smtp_not_configured")


if __name__ == "__main__":
    unittest.main()
