from collections import Counter
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

from scripts.ci import server_dotnet_shard
from scripts.ci.server_dotnet_shard import plan_profiles, shard_methods, verify_results
from scripts.ci.server_test_durations import build_durations, run_durations


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


def test_measured_shards_cover_every_class_once_and_balance_by_seconds():
    methods = Counter({"A.First": 1, "A.Second": 1, "B.Run": 1, "C.Run": 1, "D.Run": 1, "New.Run": 100})
    durations = {"A": 17.0, "B": 11.0, "C": 8.0, "D": 2.0}
    shards = [shard_methods(methods, shard, 3, durations=durations) for shard in range(1, 4)]

    assert shards == [{"A.First", "A.Second"}, {"B.Run", "D.Run"}, {"C.Run", "New.Run"}]
    classes = [{method.rsplit(".", 1)[0] for method in shard} for shard in shards]
    assert Counter(name for shard in classes for name in shard) == Counter(["A", "B", "C", "D", "New"])
    seconds = [sum({**durations, "New": 9.5}[name] for name in shard) for shard in classes]
    assert max(seconds) - min(seconds) <= max(durations.values())


def test_duration_builder_sums_cases_and_shards_before_taking_run_median(tmp_path):
    runs = []
    for index, seconds in enumerate((3, 10, 100)):
        run = tmp_path / str(index)
        run.mkdir()
        runs.append(run)
        for shard, extra in enumerate((2, 4)):
            (run / f"{shard}.xml").write_text(
                '<assemblies><assembly><collection>'
                f'<test type="A" result="Pass" time="{seconds}"/>'
                f'<test type="A" result="Pass" time="{extra}"/>'
                '</collection></assembly></assemblies>',
                encoding="utf-8",
            )

    assert build_durations(runs, "dotnet") == {"A": 26.0}
    with pytest.raises(ValueError, match="at least three distinct"):
        build_durations(runs[:2] + runs[:1], "dotnet")


def test_pytest_shards_partition_marker_selected_cases_and_report_file_times(tmp_path):
    (tmp_path / "pytest.ini").write_text("[pytest]\nmarkers =\n    postgres_integration\n    e2e\n", encoding="utf-8")
    for name in ("a", "b", "c"):
        (tmp_path / f"test_{name}.py").write_text(
            "import pytest\n"
            "@pytest.mark.postgres_integration\n"
            "@pytest.mark.parametrize('case', [1, 2])\n"
            "def test_kept(case): pass\n"
            "@pytest.mark.postgres_integration\n"
            "@pytest.mark.e2e\n"
            "def test_removed(): assert False\n"
            "def test_unit(): assert False\n",
            encoding="utf-8",
        )
    files = Counter()
    reports = []
    for shard in range(1, 4):
        report = tmp_path / str(shard) / "results.xml"
        reports.append(report)
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "scripts.ci.postgres_test_shard",
             "--postgres-shard", str(shard), "3", "-m", "postgres_integration and not e2e",
             "-o", "junit_family=xunit1", "--junitxml", str(report), str(tmp_path)],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        cases = list(ET.parse(report).iter("testcase"))
        assert {case.get("name") for case in cases} == {"test_kept[1]", "test_kept[2]"}
        assert len({case.get("file") for case in cases}) == 1
        files.update(case.get("file") for case in cases)
    assert files == Counter({"test_a.py": 2, "test_b.py": 2, "test_c.py": 2})
    assert run_durations(reports, "postgres").keys() == files.keys()


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
