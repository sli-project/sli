"""Command environment regressions using synthetic environments and fake children."""
from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts.maintenance import bundle_common as common


class CommandEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.parent = {
            "PATH": "synthetic-path", "SYSTEMROOT": "synthetic-systemroot",
            "ADLOG_ADMIN_PASSWORD": "synthetic-secret", "ADLOG_PG_DSN": "production.invalid",
            "PGHOSTADDR": "192.0.2.1", "PGSERVICE": "synthetic-service",
            "PYTHONPATH": "synthetic-pythonpath", "PYTEST_PLUGINS": "synthetic-plugin",
        }
        self.stack.enter_context(patch.object(common.os, "environ", self.parent))
        self.stack.enter_context(patch.object(common, "TMP_DIR", self.root))
        self.stack.enter_context(patch.object(common, "PYTEST_BASETEMP_ROOT", self.root / "pytest"))
        # Exercise real temporary-file ownership; only the child is simulated.
        self.capture = self.stack.enter_context(patch.object(
            common.tempfile, "mkstemp", wraps=common.tempfile.mkstemp
        ))
        self.popen = self.stack.enter_context(patch.object(
            common.subprocess, "Popen", return_value=Mock(poll=Mock(return_value=0))
        ))

    def invoke(self, **kwargs):
        before = dict(self.parent)
        result = common.run_command(["fake-command"], cwd=self.root, **kwargs)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(self.parent, before)
        return self.popen.call_args.kwargs["env"]

    def test_replacement_reaches_popen_exactly(self):
        supplied = common.sanitized_pytest_env(self.parent)
        before = dict(supplied)
        actual = self.invoke(env=supplied)
        self.assertEqual(actual, supplied)
        self.assertIsNot(actual, supplied)
        self.assertEqual(supplied, before)
        for key in ("ADLOG_ADMIN_PASSWORD", "PGHOSTADDR", "PGSERVICE", "PYTHONPATH", "PYTEST_PLUGINS"):
            self.assertNotIn(key, actual)
        self.assertEqual(actual["ADLOG_PG_DSN"], common.PYTEST_UNREACHABLE_PG_DSN)
        for key in ("PATH", "SYSTEMROOT"):
            self.assertEqual(actual[key], self.parent[key])

    def test_empty_replacement_is_empty(self):
        self.assertEqual(self.invoke(env={}), {})

    def test_legacy_update_merges_parent(self):
        self.assertEqual(self.invoke(env_update={"PATH": "safe-path"}), {**self.parent, "PATH": "safe-path"})

    def test_none_preserves_parent(self):
        self.assertEqual(self.invoke(env=None), self.parent)

    def test_conflicts_fail_before_capture_or_popen(self):
        for env in ({}, {"PATH": "safe-path"}):
            for update in ({}, {"PATH": "other-path"}):
                with self.subTest(env=env, update=update):
                    with patch.object(Path, "mkdir") as mkdir:
                        with self.assertRaisesRegex(ValueError, "env.*env_update"):
                            common.run_command(["fake-command"], env=env, env_update=update)
                        mkdir.assert_not_called()
        self.capture.assert_not_called()
        self.popen.assert_not_called()
