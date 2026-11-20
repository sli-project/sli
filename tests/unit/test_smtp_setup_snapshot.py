"""Synthetic snapshots only: no sockets, real credentials or installation writes."""
import json
import tempfile
import unittest
from pathlib import Path

from server.sli.core.smtp_setup import snapshot_marker, read_snapshot, validate_config


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.config = {"host": "smtp.example.invalid", "port": 587, "username": "fixture",
                       "sender": "sender@example.invalid", "recipients": {"1": "receiver@example.invalid"},
                       "base_url": "https://sli.example.invalid/app"}
        self.password = "synthetic-password"

    def publish(self):
        (self.directory / "smtp.json").write_text(json.dumps(self.config))
        (self.directory / "notification_smtp_password").write_text(self.password)
        (self.directory / "smtp.ready").write_text(snapshot_marker(self.config, self.password, 1))

    def test_matching_snapshot_returns_exact_validated_values(self):
        self.publish()
        self.assertEqual(read_snapshot(self.directory, revision=1), (self.config, self.password))

    def test_missing_marker_fails_closed(self):
        self.publish()
        (self.directory / "smtp.ready").unlink()
        with self.assertRaises(ValueError):
            read_snapshot(self.directory, revision=1)

    def test_each_mixed_generation_fails_closed(self):
        for kind in ("config", "password", "marker"):
            with self.subTest(kind=kind):
                self.publish()
                if kind == "config":
                    changed = {**self.config, "host": "other.example.invalid"}
                    (self.directory / "smtp.json").write_text(json.dumps(changed))
                elif kind == "password":
                    (self.directory / "notification_smtp_password").write_text("other-synthetic-password")
                else:
                    (self.directory / "smtp.ready").write_text("0" * 64)
                with self.assertRaises(ValueError):
                    read_snapshot(self.directory, revision=1)

    def test_strict_config_rejects_injection_and_unknown_keys(self):
        for changes in ({"host": "host\r\nMAIL FROM:x"}, {"port": True}, {"port": 0},
                        {"username": ""}, {"password": "must-not-be-in-config"},
                        {"recipients": {"../1": "x@example.invalid"}}, {"base_url": "http://example.invalid"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_config({**self.config, **changes})


if __name__ == "__main__":
    unittest.main()
