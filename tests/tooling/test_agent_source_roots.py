"""Every existing sli_collect source-root allowlist also delivers the agent."""
import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("relative", [
    "scripts/package_project.py", "scripts/apply_project_zip.py",
    "scripts/maintenance/release_check.py", "scripts/maintenance/current_baseline_gate.py",
    "scripts/maintenance/export_dev_handoff.py", "scripts/maintenance/md_freshness_check.py",
    "scripts/maintenance/documentation_consolidation.py",
    "scripts/maintenance/baseline_snapshot.py", "scripts/maintenance/collect_diagnostics.py",
])
def test_agent_is_in_the_same_source_roots(relative):
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    found = False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
            literals = {item.value for item in node.elts if isinstance(item, ast.Constant) and isinstance(item.value, str)}
            if "sli_collect" in literals:
                assert "sli_agent" in literals, relative
                found = True
    assert found


def test_source_zip_includes_agent_but_not_local_identity(tmp_path):
    from scripts.package_project import is_excluded_file, iter_source_files
    root = tmp_path
    source = root / "sli_agent" / "protection.py"
    source.parent.mkdir()
    source.write_text("# fixture\n")
    assert source in iter_source_files(root)
    assert is_excluded_file(root / "sli_agent" / "private.pem", root)
    assert is_excluded_file(root / "sli_agent" / "credentials.local", root)
    assert is_excluded_file(root / "sli_agent" / "state" / "identity-key.json", root)
    assert is_excluded_file(root / "sli_agent" / "state" / "fixture.packet", root)


def test_apache_license_is_delivered_and_allowed_in_updates():
    from scripts.package_project import INCLUDE_ROOT_FILES
    from scripts.apply_project_zip import ALLOWED_ROOT_FILES
    assert "LICENSE" in INCLUDE_ROOT_FILES and "LICENSE" in ALLOWED_ROOT_FILES
    assert "Apache License" in (ROOT / "sli_agent/LICENSE").read_text(encoding="utf-8")
