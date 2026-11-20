from __future__ import annotations

import ast
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(("file", "function"), [
    ("core/test_source_inventory_ad_context.py", "test_domain_posture_module_exposes_eight_bounded_fixture_contracts"),
    ("ops/test_sli_web_service.py", "test_sli_web_service_stop_event_and_process_cleanup"),
    ("ops/test_g11a3_v4_decision_packet.py", "test_v4_powershell_boundary_redacts_pre_runner_failure_and_preserves_runner_json"),
    ("sources/test_ad_source_process.py", "test_command_limits_fail_before_native_launch"),
    ("sources/test_ad_source_process.py", "test_existing_v6_hour_budget_is_admitted_but_not_exceeded"),
    ("tooling/test_active_directory_collectors.py", "test_replication_fixture_becomes_a_contract_valid_stable_record"),
    ("tooling/test_ad_context_foundation.py", "test_gpo_report_contract_parses_fixture_facts_under_declared_ceilings"),
    ("tooling/test_local_control_center_ui_contract.py", "test_control_center_validate_only_parses_in_windows_powershell"),
])
def test_native_windows_contracts_are_marked(file: str, function: str) -> None:
    """Keep known native prerequisites out of the Linux no-database gate."""
    path = Path(__file__).resolve().parents[1] / file
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
    module_marks = [
        value.value for value in tree.body
        if isinstance(value, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "pytestmark" for target in value.targets)
    ]
    assert any("pytest.mark.windows_only" in ast.unparse(mark) for mark in [*node.decorator_list, *module_marks])


@pytest.mark.parametrize("platform", ["win32", "linux", "darwin"])
def test_windows_only_skips_native_tests_but_keeps_portable_windows_contracts(
    platform: str, monkeypatch: pytest.MonkeyPatch, pytestconfig,
) -> None:
    namespace = runpy.run_path(str(Path(__file__).resolve().parents[1] / "conftest.py"))
    hook = namespace["pytest_collection_modifyitems"]
    monkeypatch.setitem(hook.__globals__, "sys", SimpleNamespace(platform=platform))
    added = {name: [] for name in ("windows_only", "windows", "unmarked")}
    items = [
        SimpleNamespace(
            get_closest_marker=lambda marker, name=name: (
                pytest.mark.windows_only if name == marker else None
            ),
            add_marker=marks.append,
        )
        for name, marks in added.items()
    ]

    hook(items)

    assert len(added["windows_only"]) == (0 if platform == "win32" else 1)
    if platform != "win32":
        assert added["windows_only"][0].name == "skip"
    assert not added["windows"]
    assert not added["unmarked"]
    assert any(marker.startswith("windows_only:") for marker in pytestconfig.getini("markers"))
