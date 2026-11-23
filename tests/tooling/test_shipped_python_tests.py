import sys
from pathlib import Path

import pytest

from scripts.ci import pr_scope, shipped_python_tests


ROOT = Path(__file__).resolve().parents[2]


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


@pytest.mark.parametrize(("paths", "directory_contract"), [
    pytest.param([
        "deploy/linux/native_clickhouse_endpoint.py",
        "deploy/linux/native_diagnostics.py",
        "deploy/linux/native_host.py",
        "tests/unit/test_linux_native_directory.py",
    ], "tests/unit/test_linux_native_directory.py", id="pr-55"),
    pytest.param([
        "deploy/linux/native_remove.py",
        "tests/unit/test_linux_native_remove.py",
    ], "tests/unit/test_linux_native_remove.py", id="pr-56"),
])
def test_installer_pr_runs_affected_tests_and_checks_checkpoint_integrity(paths, directory_contract):
    jobs = pr_scope.plan_jobs(paths)
    assert jobs["unit"] and jobs["checkpoint"]
    assert not (jobs["frontend"] or jobs["postgres"] or jobs["broad"])
    selected = pr_scope.pytest_arguments(ROOT, paths)
    assert directory_contract in selected["unit"]
    assert "tests/unit/test_linux_beta_kit.py" in selected["unit"]
    assert "tests/tooling/test_ui_domain_binding_guard.py" not in selected["source"]
    assert any("test_integrity_receipt_rechecks_current_manifest" in case for case in selected["checkpoint"])


@pytest.mark.parametrize("paths", [
    pytest.param([
        "config/postgres_migrations/391_agent_receipt_summary.rollback.sql",
        "config/postgres_migrations/391_agent_receipt_summary.sql",
        "deploy/linux/native_pg_ledger.json",
        "server-dotnet/tests/Sli.Server.Tests/Storage/InboxPayloadRetentionPostgresTests.cs",
        "server-dotnet/tests/Sli.Server.Tests/Storage/ReceiptRetentionPostgresTests.cs",
    ], id="pr-58"),
    pytest.param(["new-area/example.txt"], id="unknown"),
    pytest.param(["scripts/ci/selector.py"], id="ci-script"),
    pytest.param([".github/workflows/example.yml"], id="workflow"),
    pytest.param(["requirements.lock.txt"], id="shared-dependency"),
])
def test_backend_fallback_runs_full_python_and_postgres(paths):
    jobs = pr_scope.plan_jobs(paths)
    assert jobs["broad"] and jobs["unit"] and jobs["postgres"] and jobs["checkpoint"]
    assert not jobs["frontend"]


@pytest.mark.parametrize(("paths", "enabled", "disabled"), [
    (["docs/install.md"], (), ("unit", "postgres", "frontend")),
    (["frontend/src/report.tsx"], ("unit", "frontend"), ("postgres", "broad")),
    (["server-dotnet/src/Sli.Server/Problems/ProblemEndpoints.cs"], ("unit", "frontend", "postgres", "broad"), ()),
    (["server-dotnet/src/Sli.Server/Reporting/V2/ReportDefinition.cs"], ("unit", "frontend", "broad"), ()),
    (["config/navigation_v3.json"], ("unit", "frontend", "broad"), ()),
    (["server-dotnet/src/Sli.Server/Jobs/Worker.cs"], ("unit",), ("postgres", "frontend", "broad")),
    (["agent-dotnet/src/Sli.Agent.Protocol/Packet.cs"], ("unit", "postgres"), ("frontend", "broad")),
    (["server-dotnet/src/Sli.Server/Agents/AgentPacketEndpoints.cs"], ("unit", "postgres"), ("frontend", "broad")),
    (["frontend/src/report.tsx", "new-area/example.txt"], ("unit", "frontend", "postgres", "broad"), ()),
    ([], ("unit", "postgres", "frontend", "broad"), ()),
])
def test_pr_jobs_follow_change_areas(paths, enabled, disabled):
    jobs = pr_scope.plan_jobs(paths)
    assert all(jobs[key] for key in enabled)
    assert not any(jobs[key] for key in disabled)


def test_installer_selection_follows_imports_including_removed_modules(tmp_path):
    for name, source in {
        "deploy/linux/entry.py": "from deploy.linux import removed",
        "tests/unit/test_affected.py": "from deploy.linux import entry",
        "tests/unit/test_unrelated.py": "from deploy.linux import unrelated",
    }.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    assert pr_scope.scoped_tests(tmp_path, ["deploy/linux/removed.py"]) == {"tests/unit/test_affected.py"}


def test_agent_transport_changes_retain_certificate_and_packet_contracts():
    paths = ["agent-dotnet/src/Sli.Agent.Protocol/Packet.cs"]
    selected = pr_scope.pytest_arguments(ROOT, paths)["unit"]
    assert {"tests/unit/test_agent_tls.py", "tests/unit/test_agent_packets_api.py"} <= set(selected)

def test_shipped_helper_import_and_sql_asset_preserve_mixed_test_files(tmp_path, monkeypatch):
    monkeypatch.setattr(shipped_python_tests, "INSTALLER_ROOTS", ("native_install",))
    cases = {
        "deploy/linux/native_install.py": "",
        "deploy/linux/native_package.py": 'HELPERS = ("native_restore.py", "native-pins.json")',
        "deploy/linux/native_restore.py": "from server import recovery",
        "server/recovery.py": "",
        "server/legacy.py": "",
        "tests/support/first.py": "from tests.support import second",
        "tests/support/second.py": "from tests.support import first\nfrom server import recovery",
        "tests/test_helper.py": "from tests.support import first\nfrom server import legacy",
        "tests/test_sql.py": 'from server import legacy\nfrom pathlib import Path\nMIGRATIONS = Path("config") / "postgres_migrations"',
        "tests/test_uncategorized.py": "import pytest",
        "tests/test_retired.py": "from server import legacy",
    }
    for name, source in cases.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    selected, excluded, closure, _ = shipped_python_tests.select_tests(tmp_path)

    assert {"tests/test_helper.py", "tests/test_sql.py", "tests/test_uncategorized.py"} <= set(selected)
    assert excluded == ["tests/test_retired.py"]
    assert {"deploy/linux/native_restore.py", "server/recovery.py"} <= closure


def test_split_gates_and_security_contracts_remain_selected(tmp_path, monkeypatch):
    monkeypatch.setattr(shipped_python_tests, "INSTALLER_ROOTS", ("native_install",))
    files = {
        "deploy/linux/native_install.py": "",
        "server/legacy.py": "",
        "server/sli/agents/ca.py": "",
        "tests/test_ca.py": "from server.sli.agents import ca",
        "tests/test_backup.py": "from server import legacy",
        "tests/test_retired.py": "from server import legacy",
        "scripts/ci/pr_checkpoint_tests.txt": "tests/test_backup.py::test_checkpoint",
    }
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    selected, excluded, _, _ = shipped_python_tests.select_tests(tmp_path)

    assert {"tests/test_ca.py", "tests/test_backup.py"} <= set(selected)
    assert excluded == ["tests/test_retired.py"]

@pytest.mark.parametrize("path", [
    "deploy/linux/native_backup.py", "deploy/linux/native_restore.py", "deploy/linux/native_upgrade.py",
    "deploy/linux/restore_existing.py", "deploy/linux/restore_sandbox.py",
    "tests/unit/test_linux_native_upgrade_prepare.py",
])
def test_recovery_changes_keep_checkpoint_and_postgres_gates(path):
    jobs = pr_scope.plan_jobs([path])
    assert jobs["unit"] and jobs["checkpoint"] and jobs["postgres"]
    assert not jobs["broad"]
