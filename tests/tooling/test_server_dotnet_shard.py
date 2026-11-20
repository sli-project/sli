from pathlib import Path
import sys

import pytest

from scripts.ci.server_dotnet_shard import main, plan_shard, shard_classes, verify_results


def test_shards_cover_each_class_once_in_a_stable_order():
    classes = ["Auth", "WorkerPostgres", "Http", "StorageDatabase", "BackupPostgres", "Problems", "Ad"]
    shards = [shard_classes(classes, shard, 3) for shard in range(1, 4)]
    assert sorted(name for selected in shards for name in selected) == sorted(classes)
    assert [shard_classes(classes[::-1], shard, 3) for shard in range(1, 4)] == shards
    assert all(any("Postgres" in name or "Database" in name for name in selected) for selected in shards)


@pytest.mark.parametrize("status", ["failed", "errors", "skipped", "not-run"])
def test_one_passing_case_does_not_mask_incomplete_results(tmp_path: Path, status: str):
    result = tmp_path / "results.xml"
    result.write_text(f'<assemblies><assembly {status}="1">'
                      '<collection><test type="Auth" result="Pass"/></collection>'
                      '</assembly></assemblies>', encoding="utf-8")
    with pytest.raises(ValueError, match="failed, were skipped, or did not run"):
        verify_results(result, ["Auth"])


def test_every_selected_class_must_pass(tmp_path: Path):
    result = tmp_path / "results.xml"
    result.write_text('<assemblies><assembly><collection><test type="Auth" result="Pass"/>'
                      '</collection></assembly></assemblies>', encoding="utf-8")
    verify_results(result, ["Auth"])
    with pytest.raises(ValueError, match="Storage"):
        verify_results(result, ["Auth", "Storage"])


def test_plan_discovers_new_required_cases_and_keeps_opt_in_cases_out():
    password = "Sli.Server.Tests.Semantic.PasswordLiveFirstPostgresTests"
    intake = "Sli.Server.Tests.Agents.FileAuditConsumerDatabaseTests"
    owned = "Sli.Server.Tests.Auth.OwnedTests"
    old_method = f"{intake}.BorrowedConnection"
    explicit_method = f"{password}.ManualProfile"
    cases = [
        {"Class": password, "Method": "Upgrade", "Explicit": False},
        {"Class": password, "Method": "ManualProfile", "Explicit": True},
        {"Class": intake, "Method": "MigrationRequiresPreviousVersion", "Explicit": False},
        {"Class": intake, "Method": "BorrowedConnection", "Explicit": False},
        {"Class": owned, "Method": "ExerciseOwnedBinding", "Explicit": False},
    ]
    first, first_exclusions = plan_shard(cases, {owned}, {old_method}, 1, 2)
    second, second_exclusions = plan_shard(cases, {owned}, {old_method}, 2, 2)
    assert set(first + second) == {password, intake}
    assert len(first) == len(second) == 1
    assert first_exclusions | second_exclusions == {old_method, explicit_method}
    with pytest.raises(ValueError, match="invalid shard"):
        plan_shard(cases, {owned}, {old_method}, 3, 3)

def test_shard_discovery_disables_terminal_color(tmp_path, monkeypatch):
    cli = tmp_path / "run"
    cli.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "if '-list' in sys.argv:\n"
        "    print('[{\"Class\":\"Auth\",\"Method\":\"RequiresOwner\",\"Explicit\":false}]')\n"
        "    if '-noColor' not in sys.argv:\n"
        "        sys.stdout.write('\\x1b[0m')\n"
        "else:\n"
        "    Path('server-dotnet-results.xml').write_text("
        "'<assemblies><assembly><collection><test type=\"Auth\" result=\"Pass\"/>"
        "</collection></assembly></assemblies>')\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DOTNET_HOST_PATH", sys.executable)
    monkeypatch.setattr(sys, "argv", ["server_dotnet_shard.py", "1", "1"])

    main()

    assert (tmp_path / "server-dotnet-results.xml").is_file()
