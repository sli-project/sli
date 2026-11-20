"""Retirement clears only owned failures and preserves ClickHouse data."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from deploy.linux import native_diagnostics, native_host as host


@pytest.mark.parametrize("mode", [None, "native", "docker"])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("failed_unit", [None, "sli-clickhouse-history.service", "sli-clickhouse-warm.service"])
def test_retire_clickhouse_clears_failures(tmp_path, monkeypatch, mode, present, failed_unit):
    names = {"sli-clickhouse-history.service", "sli-clickhouse-warm.service"}
    vendor = "clickhouse-server.service"
    if mode:
        receipt = tmp_path / "var/lib/sli/state/host-prepared.json"
        receipt.parent.mkdir(parents=True)
        receipt.write_text(json.dumps({"clickhouse_mode": mode}))
        monkeypatch.setattr(host.clickhouse, "trusted_text", lambda path: path.read_text())
        names.add(vendor)
    units = tmp_path / "etc/systemd/system"
    units.mkdir(parents=True)
    if os.name == "nt":
        # Windows chmod cannot express POSIX group/other permissions.
        original_lstat = Path.lstat

        def metadata(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path.parent == units:
                values = list(info)
                values[0] &= ~0o022
                return os.stat_result(values)
            return info

        monkeypatch.setattr(Path, "lstat", metadata)
    if present:
        for name in names - {vendor}:
            path = units / name
            path.write_text("[Service]\nExecStart=/usr/bin/false\n")
            path.chmod(0o644)
    data = tmp_path / "srv/sli-db/clickhouse/history/data.bin"
    data.parent.mkdir(parents=True)
    data.write_bytes(b"preserved history")
    states = {name: "active" for name in names} if present else {}
    if failed_unit:
        states[failed_unit] = "failed"
    # The vendor belongs to SLI only when the old host receipt says so.
    states[vendor] = "failed"
    states["other.service"] = "failed"
    calls = []
    reloaded = False

    def systemctl(argv, **kwargs):
        nonlocal reloaded
        assert argv[0] == "systemctl"
        calls.append(argv)
        action = argv[1]
        if action == "list-unit-files":
            output = "\n".join(f"{name} enabled" for name in names) if present else ""
            return SimpleNamespace(returncode=int(not output), stdout=output, stderr="")
        if action == "list-units":
            if "--failed" in argv:
                assert reloaded
                assert not list(units.iterdir())
            output = "\n".join(
                f"{name} {'not-found' if reloaded and name != vendor else 'loaded'} {state} {state} Synthetic unit"
                for name, state in states.items()
                if name in argv and ("--failed" not in argv or state == "failed")
            )
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        if action in {"disable", "stop"}:
            name = argv[-1]
            assert name in names
            if states.get(name) == "active":
                states.pop(name)
        elif action == "daemon-reload":
            reloaded = True
        elif action == "reset-failed":
            assert reloaded
            for name in argv[2:]:
                assert name in names
                assert states[name] == "failed"  # Missing units would fail systemctl.
                states.pop(name)
        else:
            pytest.fail(f"Unexpected systemctl action: {action}")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(host.subprocess, "run", systemctl)
    host.retire_clickhouse(tmp_path)
    assert not any(states.get(name) == "failed" for name in names)
    assert states["other.service"] == "failed"
    if mode is None:
        assert states[vendor] == "failed"
    assert data.read_bytes() == b"preserved history"
    if present:
        for name in names:
            assert ["systemctl", "disable", "--now", name] in calls
        assert not list(units.iterdir())
    resets = [call for call in calls if call[1] == "reset-failed"]
    assert bool(resets) == bool(failed_unit or mode)
    calls.clear()
    host.retire_clickhouse(tmp_path)
    assert not any(call[1] == "reset-failed" for call in calls)
    assert data.read_bytes() == b"preserved history"


def test_retire_clickhouse_skips_missing_units(tmp_path, monkeypatch):
    def systemctl(argv, **kwargs):
        assert argv[0] == "systemctl"
        if argv[1] == "list-unit-files":
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        if argv[1] == "list-units" and "--all" in argv:
            output = (
                "sli-clickhouse-history.service not-found inactive dead sli-clickhouse-history.service\n"
                "sli-clickhouse-warm.service not-found inactive dead sli-clickhouse-warm.service\n"
            )
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
        assert argv[1] == "daemon-reload" or (argv[1] == "list-units" and "--failed" in argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(host.subprocess, "run", systemctl)
    host.retire_clickhouse(tmp_path)


@pytest.mark.parametrize("argv, unit_suffix", [
    (["stop", "sli-clickhouse-history.service"], " sli-clickhouse-history.service"),
    (["disable", "--now", "sli-clickhouse-warm.service"], " sli-clickhouse-warm.service"),
    (["reset-failed", "clickhouse-server.service"], " clickhouse-server.service"),
    (["stop", "synthetic-private-unit.service"], ""),
])
def test_retirement_command_failure_names_only_known_units(monkeypatch, capsys, argv, unit_suffix):
    monkeypatch.setattr(host.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(
        returncode=1, stdout="synthetic-private-output", stderr="synthetic-private-error",
    ))
    with pytest.raises(host.HostError) as error:
        host.run(["systemctl", *argv])
    native_diagnostics.failure(error.value)
    assert capsys.readouterr().err == f"native_command_failed: systemctl {argv[0]}{unit_suffix}\n"


@pytest.mark.parametrize("action,returncode,stdout,stderr", [
    ("list-unit-files", 1, "", "synthetic bus failure"),
    ("list-unit-files", 1, "synthetic partial result", ""),
    ("list-unit-files", 2, "", ""),
    ("list-units", 1, "", ""),
])
def test_retire_clickhouse_aborts_on_failed_enumeration(tmp_path, monkeypatch, capsys, action, returncode, stdout, stderr):
    def systemctl(argv, **kwargs):
        if argv[1] == action:
            return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
        assert argv[1] == "list-unit-files"
        return SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(host.subprocess, "run", systemctl)
    with pytest.raises(host.HostError, match="^native_command_failed$") as error:
        host.retire_clickhouse(tmp_path)
    native_diagnostics.failure(error.value)
    assert capsys.readouterr().err == f"native_command_failed: systemctl {action}\n"
