from __future__ import annotations

from pathlib import Path
from contextlib import ExitStack
import tempfile
import unittest
from unittest.mock import Mock, patch

import pytest

from scripts.maintenance import bundle_common as common
from scripts.maintenance import current_baseline_gate as gate
from scripts.maintenance.bundle_common import PYTEST_UNREACHABLE_PG_DSN


@pytest.fixture(autouse=True)
def synthetic_environment(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gate.os, "environ", {})
    monkeypatch.setattr(common, "TMP_DIR", tmp_path)
    monkeypatch.setattr(common, "PYTEST_BASETEMP_ROOT", tmp_path / "pytest")


def test_live_gate_accepts_only_loopback_http() -> None:
    assert gate.validate_loopback_url("http://127.0.0.1:18082") == (
        "http://127.0.0.1:18082/api/health"
    )
    with pytest.raises(ValueError, match="HTTP copy"):
        gate.validate_loopback_url("https://127.0.0.1:8080")
    with pytest.raises(ValueError, match="loopback"):
        gate.validate_loopback_url("http://192.0.2.12:8080")


def test_postgres_gate_requires_distinct_disposable_dsn() -> None:
    with pytest.raises(RuntimeError, match="ADLOG_TEST_PG_DSN"):
        gate.disposable_postgres_env({})
    with pytest.raises(RuntimeError, match="must not equal"):
        gate.disposable_postgres_env(
            {"ADLOG_TEST_PG_DSN": "postgresql://same", "ADLOG_PG_DSN": "postgresql://same"}
        )
    env = gate.disposable_postgres_env(
        {
            "ADLOG_TEST_PG_DSN": "postgresql://127.0.0.1/sli_test_baseline",
            "ADLOG_PG_DSN": "postgresql://127.0.0.1/production",
        }
    )
    assert env["ADLOG_TEST_PG_DSN"] == "postgresql://127.0.0.1/sli_test_baseline"
    # The production DSN never reaches the child; only the unroutable pytest DSN does.
    assert env["ADLOG_PG_DSN"] == PYTEST_UNREACHABLE_PG_DSN


def test_source_fingerprint_changes_with_source(tmp_path: Path) -> None:
    (tmp_path / "server").mkdir()
    source = tmp_path / "server" / "app.py"
    source.write_text("one", encoding="utf-8")
    first = gate.source_fingerprint(tmp_path)
    source.write_text("two", encoding="utf-8")
    assert gate.source_fingerprint(tmp_path) != first


def test_plan_is_read_only_and_names_every_gate(tmp_path: Path) -> None:
    result = gate.run_current_baseline_gate(
        root=tmp_path,
        live_url="http://127.0.0.1:18082",
        plan_only=True,
    )
    assert result["status"] == "planned"
    assert result["production_mutation"] is False
    assert result["collection_started"] is False
    assert set(result["required"]) == {
        "disposable_postgres_env",
        "live_url",
        "source_only",
        "windows_host",
        "ui_acceptance",
    }


def test_missing_disposable_postgres_stops_before_commands(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("ADLOG_TEST_PG_DSN", raising=False)
    monkeypatch.setattr(
        gate,
        "run_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("commands must not run before preflight passes")
        ),
    )

    result = gate.run_current_baseline_gate(
        root=tmp_path,
        live_url="http://127.0.0.1:18082",
    )

    assert result["status"] == "failed"
    assert result["failed_checks"] == ["preflight"]
    assert result["gate_classes"]["postgres_integration"] == "failed"


def test_ui_acceptance_is_not_run_after_earlier_gate_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "ADLOG_TEST_PG_DSN",
        "postgresql://127.0.0.1/sli_test_baseline",
    )
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def fake_run(command, **kwargs):
        commands.append(command)
        environments.append(kwargs["env"])
        is_release = any(str(part).endswith("release_check.py") for part in command)
        return {"exit_code": 1 if is_release else 0}

    monkeypatch.setattr(gate, "run_command", fake_run)
    monkeypatch.setattr(
        gate,
        "probe_loopback_health",
        lambda _url: {"exit_code": 0},
    )

    result = gate.run_current_baseline_gate(
        root=tmp_path,
        live_url="http://127.0.0.1:18082",
    )

    assert result["checks"]["ui_acceptance"]["status"] == "not_run"
    assert result["checks"]["ui_acceptance"]["blocked_by"] == ["release_check"]
    assert result["gate_classes"]["ui"] == "not_run"
    assert not any("beta:menu-walk" in command for command in commands)
    assert environments[0]["ADLOG_DB_BACKEND"] == "postgres"
    assert environments[0]["ADLOG_PG_DSN"].endswith("/sli_test_baseline")
    assert environments[0]["ADLOG_STORAGE_READ_MODE"] == "v2"


def test_ui_acceptance_receives_only_disposable_postgres_runtime(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv(
        "ADLOG_TEST_PG_DSN",
        "postgresql://127.0.0.1/sli_test_baseline",
    )
    monkeypatch.delenv("ADLOG_PG_DSN", raising=False)
    environments: list[dict[str, str]] = []

    def fake_run(_command, **kwargs):
        environments.append(kwargs["env"])
        return {"exit_code": 0}

    monkeypatch.setattr(gate, "run_command", fake_run)
    monkeypatch.setattr(
        gate,
        "probe_loopback_health",
        lambda _url: {"exit_code": 0},
    )

    result = gate.run_current_baseline_gate(
        root=tmp_path,
        live_url="http://127.0.0.1:18082",
    )

    assert result["status"] == "ok"
    ui_env = environments[-1]
    assert ui_env["ADLOG_DB_BACKEND"] == "postgres"
    assert ui_env["ADLOG_PG_DSN"].endswith("/sli_test_baseline")
    assert ui_env["ADLOG_STORAGE_READ_MODE"] == "v2"
    assert ui_env["ADLOG_DISABLE_COLLECTION"] == "1"


class GateChildEnvironmentTests(unittest.TestCase):
    def test_every_child_receives_sanitized_replacement(self):
        parent = {
            "PATH": "synthetic-path", "SYSTEMROOT": "synthetic-systemroot",
            "ADLOG_TEST_PG_DSN": "postgresql://127.0.0.1/sli_test_baseline",
            "ADLOG_PG_DSN": "postgresql://production.invalid/production",
            "ADLOG_ADMIN_PASSWORD": "synthetic-secret", "PGHOSTADDR": "192.0.2.1",
            "PGSERVICE": "synthetic-service", "PYTHONPATH": "synthetic-pythonpath",
            "PYTEST_PLUGINS": "synthetic-plugin",
        }
        before = dict(parent)
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            stack.enter_context(patch.object(common.os, "environ", parent))
            stack.enter_context(patch.object(common, "TMP_DIR", root))
            stack.enter_context(patch.object(common, "PYTEST_BASETEMP_ROOT", root / "pytest"))
            # Keep real capture files/descriptors: run_command owns and closes
            # mkstemp descriptors. Only the child execution is mocked below.
            close = stack.enter_context(patch.object(common.os, "close", wraps=common.os.close))
            popen = stack.enter_context(patch.object(common.subprocess, "Popen",
                return_value=Mock(poll=Mock(return_value=0))))
            stack.enter_context(patch.object(gate, "probe_loopback_health", return_value={"exit_code": 0}))
            stack.enter_context(patch.object(gate.shutil, "which", return_value="fake-npm"))
            result = gate.run_current_baseline_gate(root=root, live_url="http://127.0.0.1:18082")
            self.assertEqual(close.call_count, 10)
            self.assertFalse(list(root.glob("adlog-cmd-*.log")))
        self.assertEqual(result["status"], "ok")
        self.assertEqual(popen.call_count, 5)
        self.assertEqual(parent, before)
        envs = [call.kwargs["env"] for call in popen.call_args_list]
        for env in envs:
            for key in ("ADLOG_ADMIN_PASSWORD", "PGHOSTADDR", "PGSERVICE", "PYTHONPATH", "PYTEST_PLUGINS"):
                self.assertNotIn(key, env)
            for key in ("PATH", "SYSTEMROOT"):
                self.assertEqual(env[key], parent[key])
            self.assertEqual(env["ADLOG_DISABLE_SCHEDULER"], "1")
        for i in (0, 4):
            self.assertEqual(envs[i]["ADLOG_PG_DSN"], parent["ADLOG_TEST_PG_DSN"])
            self.assertEqual(envs[i]["ADLOG_STORAGE_READ_MODE"], "v2")
        for i in (1, 2, 3):
            self.assertEqual(envs[i]["ADLOG_PG_DSN"], common.PYTEST_UNREACHABLE_PG_DSN)
        self.assertEqual(envs[2]["ADLOG_TEST_PG_DSN"], parent["ADLOG_TEST_PG_DSN"])
        self.assertEqual(envs[4]["ADLOG_DISABLE_COLLECTION"], "1")
