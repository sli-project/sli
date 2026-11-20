"""Publication failures cannot produce a deliverable mixed SMTP snapshot."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.linux.smtp_setup import Setup
from server.sli.core.smtp_setup import read_snapshot


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.service = Setup(self.directory)
        self.body = {"action": "smtp_save", "user_id": 1, "host": "smtp.example.invalid", "port": 587,
                     "username": "fixture", "sender": "from@example.invalid", "password": "synthetic-one",
                     "recipients": {"1": "to@example.invalid"}, "previous_revision": 1, "revision": 2}
        self.env = patch.dict("os.environ", {"SLI_PUBLIC_URL": "https://sli.example.invalid"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def write(self, path, body):
        Path(path).write_bytes(body)

    def test_password_is_write_only_and_blank_preserves(self):
        with patch("deploy.linux.smtp_setup.publish", self.write):
            result = self.service.handle(self.body)
            self.assertNotIn("synthetic-one", json.dumps(result))
            self.service.handle({**self.body, "password": "", "previous_revision": 2, "revision": 3})
        self.assertEqual(read_snapshot(self.directory, revision=3)[1], "synthetic-one")
        status = self.service.handle({"action": "smtp_status", "user_id": 1, "revision": 3})
        self.assertTrue(status["secret_set"])
        self.assertNotIn("password", status)
        self.assertNotIn("synthetic-one", json.dumps(status))

    def test_crash_before_each_publication_leaves_no_usable_pair(self):
        for fail_at in (1, 2, 3):
            with self.subTest(fail_at=fail_at):
                with patch("deploy.linux.smtp_setup.publish", self.write):
                    self.service.handle(self.body)
                calls = []
                def failing(path, body):
                    calls.append(path)
                    if len(calls) == fail_at:
                        raise OSError("synthetic-private-failure")
                    self.write(path, body)
                with patch("deploy.linux.smtp_setup.publish", failing), self.assertRaises(ValueError):
                    self.service.handle({**self.body, "host": "new.example.invalid", "password": "synthetic-two"})
                with self.assertRaises(ValueError):
                    read_snapshot(self.directory, revision=2)

    def test_new_password_required_for_empty_installation(self):
        with self.assertRaises(ValueError):
            self.service.handle({**self.body, "password": ""})

    def test_existing_unmarked_config_requests_resave_without_secret_echo(self):
        with patch("deploy.linux.smtp_setup.publish", self.write):
            self.service.handle(self.body)
        (self.directory / "smtp.ready").unlink()
        status = self.service.handle({"action": "smtp_status", "user_id": 1, "revision": 2})
        self.assertTrue(status["needs_save"])
        self.assertFalse(status["secret_set"])

    def test_malformed_configuration_remains_repairable_without_echo(self):
        (self.directory / "smtp.json").write_text("synthetic-private-corruption")
        status = self.service.handle({"action": "smtp_status", "user_id": 1, "revision": 2})
        self.assertTrue(status["needs_save"])
        self.assertFalse(status["secret_set"])
        self.assertEqual(status["host"], "")
        self.assertNotIn("synthetic-private", json.dumps(status))

    def test_blank_password_requires_exact_previous_generation_before_any_write(self):
        with patch("deploy.linux.smtp_setup.publish", self.write):
            self.service.handle(self.body)
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        with patch("deploy.linux.smtp_setup.publish", side_effect=AssertionError("write before validation")):
            with self.assertRaises(ValueError):
                self.service.handle({**self.body, "password": "", "previous_revision": 1, "revision": 2})
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.directory.iterdir()})

    def test_generic_metadata_revision_invalidates_reusable_password(self):
        with patch("deploy.linux.smtp_setup.publish", self.write):
            self.service.handle(self.body)
        status = self.service.handle({"action": "smtp_status", "user_id": 1, "revision": 3})
        self.assertTrue(status["needs_save"])
        self.assertFalse(status["secret_set"])


if __name__ == "__main__":
    unittest.main()
