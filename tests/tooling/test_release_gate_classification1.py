from pathlib import Path

from scripts.maintenance import release_check


def test_release_check_reports_gate_classes_and_missing_tooling_honestly() -> None:
    source = Path("scripts/maintenance/release_check.py").read_text(encoding="utf-8")
    for name in ("source_only", "postgres_integration", "host_dependent", "live"):
        assert f'"{name}"' in source
    assert '"live_ad_contacted": False' in source
    assert '"runtime_restarted": False' in source
    assert '"ruff": "not_configured"' in source
    assert '"static_type_check": "not_configured"' in source
    assert '"coverage_threshold": "not_configured"' in source


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
