from collections import Counter
from pathlib import Path
import sys

import pytest

from scripts.ci import server_dotnet_shard
from scripts.ci.server_dotnet_shard import plan_profiles, shard_methods, verify_results


def test_shards_cover_methods_once_and_keep_classes_together():
    methods = Counter({
        "Auth.Login": 6, "Auth.Logout": 2, "WorkerPostgres.Process": 3,
        "Topics.Read": 3, "StorageDatabase.Write": 2, "BackupPostgres.Restore": 1,
    })
    shards = [shard_methods(methods, shard, 3) for shard in range(1, 4)]
    assert Counter(name for selected in shards for name in selected) == Counter(methods.keys())
    assert any({"Auth.Login", "Auth.Logout"} <= selected for selected in shards)
    reverse = Counter(dict(reversed(list(methods.items()))))
    assert [shard_methods(reverse, shard, 3) for shard in range(1, 4)] == shards


def test_isolated_runners_can_split_slow_class_without_splitting_theories():
    methods = Counter({"SqlPostgres.Load": 20, "SqlPostgres.Write": 3, "SqlPostgres.Read": 1})
    assert shard_methods(methods, 1, 2, keep_classes=False) == {"SqlPostgres.Load"}
    assert shard_methods(methods, 2, 2, keep_classes=False) == {"SqlPostgres.Read", "SqlPostgres.Write"}


@pytest.mark.parametrize("status", ["failed", "errors", "skipped", "not-run"])
def test_one_passing_case_does_not_mask_incomplete_results(tmp_path: Path, status: str):
    result = tmp_path / "results.xml"
    result.write_text(f'<assemblies><assembly {status}="1">'
                      '<collection><test type="Auth" method="Login" result="Pass"/></collection>'
                      '</assembly></assemblies>', encoding="utf-8")
    with pytest.raises(ValueError, match="failed, were skipped, or did not run"):
        verify_results(result, {"Auth.Login"})


def test_every_selected_method_must_pass_even_in_a_passing_class(tmp_path: Path):
    result = tmp_path / "results.xml"
    result.write_text('<assemblies><assembly>'
                      '<collection><test type="Auth" method="Login" result="Pass"/></collection>'
                      '</assembly></assemblies>', encoding="utf-8")
    verify_results(result, {"Auth.Login"})
    with pytest.raises(ValueError, match="Auth.Logout"):
        verify_results(result, {"Auth.Login", "Auth.Logout"})
    with pytest.raises(ValueError, match="Unexpected.*Auth.Login"):
        verify_results(result, set())


def test_profiles_keep_security_and_new_cases_required_and_move_only_marked_tests():
    auth = "Tests.Auth.LoginTests"
    intake = "Tests.Agents.FileAuditConsumerTests"
    cases = [
        {"Class": auth, "Method": "RequiresOwner", "Explicit": False},
        {"Class": intake, "Method": "RejectsModifiedHash", "Explicit": False},
        {"Class": intake, "Method": "NewCase", "Explicit": False},
        {"Class": intake, "Method": "BorrowedConnection", "Explicit": False},
        {"Class": intake, "Method": "OldUpgrade", "Explicit": False},
        {"Class": intake, "Method": "Volume", "Explicit": True},
        {"Class": intake, "Method": "NeedsExternalHarness", "Explicit": True},
        {"Class": "Tests.OffBeta", "Method": "Presentation", "Explicit": False},
    ]
    exclusions = [["method", f"{intake}.BorrowedConnection"]]
    rules = [
        ["security", "namespace", "Tests.Auth"],
        ["security", "method", f"{intake}.RejectsModifiedHash"],
        ["load", "method", f"{intake}.OldUpgrade"],
        ["load", "method", f"{intake}.Volume"],
        ["outside-beta", "class", "Tests.OffBeta"],
    ]
    profiles = plan_profiles(cases, exclusions, rules)
    assert set(profiles["pr"]) == {f"{auth}.RequiresOwner", f"{intake}.RejectsModifiedHash", f"{intake}.NewCase"}
    assert set(profiles["nightly"]) == {*profiles["pr"], f"{intake}.OldUpgrade", f"{intake}.Volume",
                                        "Tests.OffBeta.Presentation"}
    with pytest.raises(ValueError, match="Security tests missing from PR.*RejectsModifiedHash"):
        plan_profiles(cases, exclusions, [*rules, ["outside-beta", "class", intake]])
    with pytest.raises(ValueError, match="matches no runnable test"):
        plan_profiles(cases, exclusions, [*rules, ["load", "class", "Tests.Missing"]])


def test_shard_passes_selected_methods_and_disables_discovery_colors(tmp_path, monkeypatch):
    cli = tmp_path / "run"
    cli.write_text(
        "from pathlib import Path\n"
        "import sys\n"
        "if '-list' in sys.argv:\n"
        "    print('[{\"Class\":\"Auth\",\"Method\":\"RequiresOwner\",\"Explicit\":false}]')\n"
        "    if '-noColor' not in sys.argv:\n"
        "        sys.stdout.write('\\x1b[0m')\n"
        "else:\n"
        "    assert sys.argv[sys.argv.index('-method')+1] == 'Auth.RequiresOwner'\n"
        "    Path('server-dotnet-results.xml').write_text(\n"
        "        '<assemblies><assembly><collection><test type=\"Auth\" method=\"RequiresOwner\" result=\"Pass\"/>'\n"
        "        '</collection></assembly></assemblies>')\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DOTNET_HOST_PATH", sys.executable)
    monkeypatch.setattr(server_dotnet_shard, "read_rules", lambda path: [])
    monkeypatch.setattr(sys, "argv", ["server_dotnet_shard.py", "1", "1"])

    server_dotnet_shard.main()

    assert (tmp_path / "server-dotnet-results.xml").is_file()
