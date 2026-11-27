import json
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from tools.lab import drill


def evidence(scenario=1):
    return {
        "scenario": scenario,
        "started_at": "2026-01-01T10:00:00Z",
        "finding": {
            "id": 42,
            "rule_code": "semantic.qw.password-brute-force",
            "title": "Подбирают пароль к учётной записи",
            "title_code": "security.problems.presentation.qw.password-brute-force.title",
            "previous_last_seen_utc": "2026-01-01T09:59:40Z",
            "last_seen_utc": "2026-01-01T10:01:00Z",
            "observed_at": "2026-01-01T10:05:00Z",
        },
        "telegram_attempt": {
            "finding_id": 42,
            "state": "accepted",
            "accepted_at": "2026-01-01T10:06:00Z",
        },
    }


def test_dry_run_prints_rules_and_leaves_cleanup_cases_last():
    result = subprocess.run(
        [sys.executable, "-X", "utf8", str(Path(drill.__file__)), "--dry-run"],
        check=True, capture_output=True, encoding="utf-8",
    )
    steps = result.stdout.splitlines()
    assert [int(line.split(".", 1)[0]) for line in steps] == [1, 2, 3, 4, 5, 6, 8, 10, 7, 9]
    assert "qw.password-success.title" in steps[2]
    assert "Remove the test group membership" in steps[5]
    assert "Restore the saved audit policy" in steps[6]
    assert "Remove the test task and service" in steps[7]
    assert "Restart the SLI agent" in steps[-1]


@pytest.mark.parametrize(
    ("observed_at", "minutes", "within_five"),
    [
        ("2026-01-01T10:05:00Z", 5.0, True),
        ("2026-01-01T10:05:00.001Z", 5.01, False),
        ("2026-01-01T10:10:01Z", None, False),
    ],
)
def test_latency_uses_observation_time(observed_at, minutes, within_five):
    record = evidence()
    record["finding"]["observed_at"] = observed_at
    row = drill.build_report([record])["rows"][0]
    assert row["minutes"] == minutes
    assert (row["found"] and row["minutes"] <= 5) is within_five


@pytest.mark.parametrize("field", ["rule_code", "last_seen_utc", "previous_last_seen_utc"])
def test_findings_must_match_and_advance(field):
    record = evidence()
    record["finding"][field] = {
        "rule_code": "semantic.qw.password-spray",
        "last_seen_utc": "2026-01-01T09:59:50Z",
        "previous_last_seen_utc": "2026-01-01T10:01:00Z",
    }[field]
    assert not drill.build_report([record])["rows"][0]["found"]


def test_success_after_guessing_requires_success_presentation():
    record = evidence(scenario=3)
    assert not drill.build_report([record])["rows"][2]["found"]
    record["finding"]["title_code"] = "security.problems.presentation.qw.password-success.title"
    assert drill.build_report([record])["rows"][2]["found"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("finding_id", 43),
        ("state", "pending"),
        ("accepted_at", "2026-01-01T09:59:00Z"),
        ("accepted_at", "2026-01-01T10:00:30Z"),
        ("accepted_at", "2026-01-01T10:10:01Z"),
    ],
)
def test_telegram_requires_same_finding_and_current_acceptance(field, value):
    record = evidence()
    record["telegram_attempt"][field] = value
    row = drill.build_report([record])["rows"][0]
    assert row["found"]
    assert not row["telegram_accepted"]


@pytest.mark.parametrize(
    "title", [None, "Password guessing", "Подбор semantic.qw.password-brute-force", "Подбор qw.password-brute-force"],
)
def test_russian_title_requires_cyrillic_and_no_rule_code(title):
    record = evidence()
    record["finding"]["title"] = title
    assert not drill.build_report([record])["rows"][0]["russian_title"]


def test_report_writes_the_same_rows_to_json_and_stdout(tmp_path, capsys):
    source = tmp_path / "evidence.json"
    output = tmp_path / "result.json"
    source.write_text(json.dumps([evidence()]), encoding="utf-8")
    assert drill.main(["--evidence", str(source), "--json-output", str(output)]) == 1
    report = json.loads(output.read_text(encoding="utf-8"))
    printed = capsys.readouterr().out
    assert "| Атака | Найдена | Минут до главной | Заголовок на русском | Сообщение в Telegram |" in printed
    assert "| 1. Подбор пароля | да | 5.00 | да | да |" in printed
    assert report["rows"][0]["telegram_accepted"]
    assert not report["rows"][1]["found"]
    assert not report["passed"]


def test_rejects_duplicate_scenarios_without_echoing_invalid_input(tmp_path, capsys):
    source = tmp_path / "evidence.json"
    output = tmp_path / "result.json"
    source.write_text(json.dumps([evidence(), evidence()]), encoding="utf-8")
    assert drill.main(["--evidence", str(source), "--json-output", str(output)]) == 2
    assert "Invalid evidence" in capsys.readouterr().err
    assert not output.exists()


def test_evidence_cannot_be_overwritten_by_the_report(tmp_path, capsys):
    source = tmp_path / "evidence.json"
    original = json.dumps([evidence()])
    source.write_text(original, encoding="utf-8")
    assert drill.main(["--evidence", str(source), "--json-output", str(source)]) == 2
    assert "different file" in capsys.readouterr().err
    assert source.read_text(encoding="utf-8") == original


def test_all_rows_must_meet_the_acceptance_thresholds():
    records = []
    for scenario in drill.SCENARIOS:
        record = evidence(scenario.number)
        record["finding"]["rule_code"] = scenario.rules[0]
        if scenario.title_code:
            record["finding"]["title_code"] = scenario.title_code
        records.append(record)
    assert drill.build_report(records)["passed"]
    records[-1]["telegram_attempt"] = None
    assert not drill.build_report(records)["passed"]


class StandClock:
    def __init__(self, start):
        self.current = drill.timestamp(start)

    def now(self):
        return self.current

    def sleep(self, seconds):
        self.current += timedelta(seconds=seconds)


def test_observe_polls_for_a_finding_then_waits_for_its_telegram_attempt():
    started_at = "2026-01-01T10:00:00Z"
    command = drill.stand_command("observer@stand.example.test", Path("fixture-identity"))
    clock = StandClock(started_at)
    finding = {
        "id": 42, "rule_code": drill.PASSWORD_BRUTE, "title_code": None,
        "signal_at": "2026-01-01T10:00:12Z", "russian_title": True,
    }
    accepted = {"finding_id": 42, "state": "accepted", "accepted_at": "2026-01-01T10:00:35Z"}
    replies = iter([None, finding, None, accepted])
    times = []

    def run(argv, *, input, **options):
        assert argv == command
        assert "begin read only;" in input
        assert options["check"] and options["capture_output"]
        times.append(clock.now() - drill.timestamp(started_at))
        response = next(replies)
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(response) if response else "", stderr="")

    report = drill.observe_stand(
        [{"scenario": 1, "started_at": started_at}], command, now=clock.now, sleep=clock.sleep, run=run,
    )
    row = report["rows"][0]
    assert [elapsed.total_seconds() for elapsed in times] == [0, 20, 20, 40]
    assert row["found"] and row["russian_title"] and row["telegram_accepted"]
    assert row["minutes"] == 0.34


@pytest.mark.parametrize("ssh_times_out", [False, True])
def test_observe_stops_at_the_scenario_deadline(ssh_times_out):
    started_at = "2026-01-01T10:00:00Z"
    command = drill.stand_command("observer@stand.example.test", Path("fixture-identity"))
    clock = StandClock("2026-01-01T10:09:30Z")
    budgets = []

    def run(argv, *, timeout, **options):
        budgets.append(timeout)
        if ssh_times_out:
            clock.sleep(timeout)
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    report = drill.observe_stand(
        [{"scenario": 1, "started_at": started_at}], command, now=clock.now, sleep=clock.sleep, run=run,
    )
    assert clock.now() == drill.timestamp("2026-01-01T10:10:00Z")
    assert budgets == ([30] if ssh_times_out else [30, 10])
    assert not report["rows"][0]["found"]


def test_dry_run_prints_stand_command_with_identity_path_redacted(capsys):
    assert drill.main(["--dry-run", "--stand-ssh", "observer@stand.example.test", "--stand-key", "fixture-key"]) == 0
    output = capsys.readouterr().out
    assert "observer@stand.example.test" in output
    assert "-i '<stand-key>'" in output
    assert "fixture-key" not in output
