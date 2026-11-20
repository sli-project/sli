"""Native CLI host boundary: no shell, credentials, deadline or invented health."""
from types import SimpleNamespace

import pytest

from deploy.linux import native_plugin_runtime as native


def test_adapter_uses_fixed_native_binary_and_streams_progress(monkeypatch, tmp_path):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(native.subprocess, "run", run)
    monkeypatch.setenv("SECRET_FIXTURE", "must-not-reach-child")
    host = native.NativePluginRuntime("test-release")
    manifest = {"plugin_id": "sli.remote-access", "plugin_version": "0.1.0"}
    host.plugin_drain(tmp_path, manifest)
    host.plugin_health(tmp_path, manifest)
    assert calls[0][0] == ["/opt/sli/dotnet/test-release/Sli.Server", "plugin-update-runtime", "drain", "sli.remote-access"]
    assert calls[1][0] == ["/opt/sli/dotnet/test-release/Sli.Server", "plugin-update-runtime", "health", "sli.remote-access", "--version", "0.1.0"]
    for _, kwargs in calls:
        assert set(kwargs) == {"check", "env"}  # No timeout; stdout/stderr stream directly.
        assert "SECRET_FIXTURE" not in kwargs["env"]
        assert kwargs["env"]["SLI_PLUGIN_RUNTIME_DIR"] == str(tmp_path / "plugins")
        assert kwargs["env"]["SLI_PLUGIN_LOCK_DIR"] == "/opt/sli/current/config/plugin_packages/v3"


@pytest.mark.parametrize("code,expected", [(1, 1), (2, 2), (130, 130), (-15, 143)])
def test_cli_preserves_failed_process_or_signal_exit(monkeypatch, capsys, code, expected):
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=code))
    assert native.main(["--release", "test-release", "health", "sli.gpo", "--version", "1.0.0"]) == expected
    assert capsys.readouterr().err == "update_plugin_runtime_failed\n"


def test_missing_binary_is_failure_without_private_diagnostics(monkeypatch, capsys):
    def missing(*args, **kwargs):
        raise FileNotFoundError("private fixture path")

    monkeypatch.setattr(native.subprocess, "run", missing)
    assert native.main(["--release", "test-release", "drain", "sli.ad"]) == 127
    assert capsys.readouterr().err == "update_plugin_runtime_failed\n"


@pytest.mark.parametrize("arguments", [
    ["--release", "../outside", "drain", "sli.ad"],
    ["--release", "test-release", "drain", "../outside"],
    ["--release", "test-release", "health", "sli.ad"],
    ["--release", "test-release", "health", "sli.ad", "--version", "1.0.0;command"],
    ["--release", "test-release", "drain", "sli.ad", "--version", "1.0.0"],
])
def test_invalid_arguments_never_launch_process(monkeypatch, arguments):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid input launched a process")

    monkeypatch.setattr(native.subprocess, "run", forbidden)
    assert native.main(arguments) == 2
