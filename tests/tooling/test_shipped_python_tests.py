import sys

import pytest

from scripts.ci import shipped_python_tests


@pytest.mark.parametrize("event", ["pull_request", "workflow_dispatch"])
def test_legacy_report_duplicates_are_available_in_manual_ci(tmp_path, monkeypatch, event):
    legacy_report = "tests/reporting/test_computers_v6_metrics_partition.py"
    mixed_test = "tests/reports/test_computers_v6_comparison_batch.py"
    installer_test = "tests/unit/test_linux_native_install.py"
    migration_test = "tests/migrations/test_install_schema.py"
    other_report = "tests/reporting/test_other_report.py"
    legacy_only = "tests/reporting/test_legacy_runtime.py"
    report_import = "from server.report import render\n"
    installer_import = "from deploy.linux.native_install import install\n"
    for name, source in {
        "server/report.py": "",
        "server/legacy_runtime.py": "",
        "deploy/linux/native_install.py": report_import,
        legacy_report: report_import,
        mixed_test: report_import + installer_import,
        installer_test: installer_import,
        migration_test: report_import,
        other_report: report_import,
        legacy_only: "from server.legacy_runtime import run\n",
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    argfile = tmp_path / "selection.txt"
    monkeypatch.setattr(shipped_python_tests, "INSTALLER_ROOTS", ("native_install",))
    monkeypatch.setenv("GITHUB_EVENT_NAME", event)
    monkeypatch.setattr(sys, "argv", ["shipped_python_tests", "--root", str(tmp_path), "--output", str(argfile)])

    assert shipped_python_tests.main() == 0
    expected = {mixed_test, installer_test, migration_test, other_report}
    if event == "workflow_dispatch":
        expected.add(legacy_report)
    assert set(argfile.read_text(encoding="utf-8").splitlines()) == expected
