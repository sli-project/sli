from pathlib import Path

from scripts.maintenance import postgres_readiness, release_check


def test_release_check_reports_only_offline_gates_as_executed(tmp_path, monkeypatch) -> None:
    commands = []
    readiness_connections = []

    def run_command(args, **kwargs):
        commands.append(args)
        return {"exit_code": 0, "timed_out": False}

    def run_readiness(*, connect):
        readiness_connections.append(connect)
        return {"status": "ok"}

    monkeypatch.setattr(release_check, "run_command", run_command)
    monkeypatch.setattr(postgres_readiness, "run_readiness", run_readiness)
    monkeypatch.setattr(release_check, "list_reports", list)
    monkeypatch.setattr(release_check, "get_release_metadata", lambda root: {})
    monkeypatch.setattr(release_check, "workstation_release_gate", lambda *args, **kwargs: {"release_eligible": False})
    monkeypatch.setattr(release_check, "audit_pg_runtime_parity", lambda root: {"status": "ok"})

    result = release_check.run_release_check(tmp_path)

    assert any("--offline" in command for command in commands)
    assert readiness_connections == [False]
    gates = result["gate_classes"]
    assert gates["source_only"]["executed"] is True
    assert gates["source_only"]["production_mutation"] is False
    for name in ("postgres_integration", "host_dependent", "live"):
        assert gates[name]["status"] == "not_run"
        assert gates[name]["executed"] is False
    assert gates["live"]["live_ad_contacted"] is False
    assert gates["live"]["runtime_restarted"] is False


def test_release_check_warn_is_nonzero_unless_explicitly_diagnostic(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        release_check,
        "run_release_check",
        lambda: {
            "status": "warn",
            "duration_ms": 1,
            "release_metadata": {},
            "warnings": ["warning"],
            "role_views": [],
        },
    )
    monkeypatch.setattr("sys.argv", ["release_check.py", "--json"])
    assert release_check.main() == 1

    monkeypatch.setattr(
        "sys.argv",
        ["release_check.py", "--json", "--allow-warn"],
    )
    assert release_check.main() == 0


def test_generated_temp_roots_and_python_outputs_are_ignored() -> None:
    ignore = Path(".gitignore").read_text(encoding="utf-8")
    assert "data/**" in ignore
    assert "__pycache__/" in ignore
    assert "*.pyc" in ignore
    assert ".pytest_cache/" in ignore
