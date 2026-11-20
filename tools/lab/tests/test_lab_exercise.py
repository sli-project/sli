"""Recorded synthetic .NET API contracts. No network, AD, or product imports."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("lab_exercise", HERE.parent / "lab-exercise.py")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
START = lab.stamp("2026-11-16T10:00:00Z")
MATCH = ["lab.x00000000000001"]


@pytest.fixture
def responses():
    return json.loads((HERE / "responses.json").read_text("utf-8"))


def test_quiet_state_uses_total_not_top_five(responses):
    home = responses["home"]
    assert lab.quiet_snapshot(home, START.isoformat())["problem_count"] == 7
    home["problems_found"]["count"] = 11
    assert lab.quiet_snapshot(home, START.isoformat())["within_ten"] is False
    home["problems_found"]["count"] = 0
    home["problems_found"]["state"] = "partial"
    assert lab.quiet_snapshot(home, START.isoformat())["within_ten"] is None


@pytest.mark.parametrize("count", [None, True, -1, "7"])
def test_quiet_does_not_invent_zero(responses, count):
    responses["home"]["problems_found"]["count"] = count
    with pytest.raises(lab.ExerciseError):
        lab.quiet_snapshot(responses["home"], START.isoformat())


def test_parses_queue_and_correlates_new_problem(responses):
    rows, cursor = lab.parse_page(responses["queue"])
    assert cursor is None
    assert lab.new_problems(rows, lab.ATTACKS[0], {}, START, MATCH) == rows
    assert not lab.new_problems(rows, lab.ATTACKS[1], {}, START, MATCH)
    assert not lab.new_problems(rows, lab.ATTACKS[0], {}, START, ["another-synthetic-account"])
    assert not lab.new_problems(rows, lab.ATTACKS[0], {41: rows[0]}, START, MATCH)
    assert not lab.new_problems(rows, lab.ATTACKS[0], {}, lab.stamp("2026-11-16T11:00:00Z"), MATCH)
    rows[0]["status"] = "closed"
    assert not lab.new_problems(rows, lab.ATTACKS[0], {}, START, MATCH)


def test_grouped_problem_can_repeat_but_assignment_is_not_an_attack(responses):
    old = copy.deepcopy(responses["queue"]["items"][0])
    old["last_seen_utc"] = "2026-11-16T09:00:00Z"
    assert lab.new_problems(responses["queue"]["items"], lab.ATTACKS[0], {41: old}, START, MATCH)
    old["updated_at"] = "2026-11-16T10:00:30Z"
    old["last_seen_utc"] = responses["queue"]["items"][0]["last_seen_utc"]
    assert not lab.new_problems(responses["queue"]["items"], lab.ATTACKS[0], {41: old}, START, MATCH)


def test_success_requires_success_presentation(responses):
    rows = responses["queue"]["items"]
    assert not lab.new_problems(rows, lab.ATTACKS[2], {}, START, MATCH)
    rows[0]["title_code"] = "security.problems.presentation.qw.password-success.title"
    assert lab.new_problems(rows, lab.ATTACKS[2], {}, START, MATCH)


@pytest.mark.parametrize("change", [{"state": "error"}, {"items": None}, {"has_more": True},
                                    {"items": ["private-response"]}, {"error": "private-response"}])
def test_invalid_page_is_not_empty_success(responses, change):
    responses["queue"].update(change)
    with pytest.raises(lab.ExerciseError, match="^api_contract_invalid$"):
        lab.parse_page(responses["queue"])


def test_paging_continues_and_rejects_repeated_cursor(responses):
    api = lab.Api("http://localhost:8443", "synthetic-token")
    page1 = {**responses["queue"], "has_more": True, "next_cursor": "second"}
    api.get = Mock(side_effect=[page1, {**responses["queue"], "items": []}])
    assert api.pages(lab.QUEUE) == responses["queue"]["items"]
    assert api.get.call_args_list[1].args[1]["cursor"] == "second"
    api.get = Mock(return_value=page1)
    with pytest.raises(lab.ExerciseError, match="api_contract_invalid"):
        api.pages(lab.QUEUE)


@pytest.mark.parametrize("url", ["http://example.test", "https://user:pass@example.test",
                                "https://example.test/?token=private", "https://example.test/#private"])
def test_token_transport_rejects_unsafe_urls(url):
    with pytest.raises(lab.ExerciseError):
        lab.Api(url, "synthetic-token")


def test_redirect_does_not_forward_credentials():
    with pytest.raises(lab.ExerciseError):
        lab.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.test")


def test_delivery_is_for_new_semantic_problem_not_a_test_message(responses):
    rows = responses["workspace"]["items"]
    assert lab.telegram_configured(responses["workspace"])
    assert lab.delivery_accepted(rows, 41, START, set())
    assert not lab.delivery_accepted(rows, 42, START, set())
    assert not lab.delivery_accepted(rows, 41, START, {rows[0]["id"]})
    for field, value in [("object_kind", "test_problem"), ("state", "delivery_unknown"),
                         ("channel", "smtp"), ("created_at", "2026-11-15T10:00:00Z")]:
        changed = [{**rows[0], field: value}]
        assert not lab.delivery_accepted(changed, 41, START, set())


def test_attack_runner_passes_key_path_without_reading_and_strips_token(monkeypatch):
    monkeypatch.setenv("SLI_OPERATOR_TOKEN", "synthetic-private-token")
    process = MagicMock()
    process.__enter__.return_value = process
    process.returncode = 0
    process.communicate.return_value = (b'{"executed":true,"restored":true,"reason":"","match_values":["LAB-DC01"]}', b'')
    popen = Mock(return_value=process)
    monkeypatch.setattr(lab.subprocess, "Popen", popen)
    args = SimpleNamespace(ssh_target="Administrator@192.0.2.10", identity_file=Path("nonexistent-synthetic-identity"), token_env="SLI_OPERATOR_TOKEN")
    assert lab.run_attack(9, args, {"domain": "example.test"})["executed"]
    call = popen.call_args
    assert call.args[0][0] == "ssh" and "nonexistent-synthetic-identity" in call.args[0]
    assert "StrictHostKeyChecking=yes" in call.args[0]
    assert not any(key.casefold() in {"sli_operator_token", "psmodulepath"} for key in call.kwargs["env"])
    assert b"synthetic-private-token" not in process.communicate.call_args.args[0]


def test_process_error_never_exposes_process_diagnostics(monkeypatch):
    monkeypatch.setattr(lab.subprocess, "Popen", Mock(side_effect=OSError("private-process-diagnostic")))
    args = SimpleNamespace(ssh_target=None, identity_file=None, token_env="SLI_OPERATOR_TOKEN")
    with pytest.raises(lab.ExerciseError, match="^attack_failed$"):
        lab.run_attack(9, args, {"domain": "example.test"})


def fake_clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(lab.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(lab.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    monkeypatch.setattr(lab, "utc_now", lambda: START.isoformat())
    return now


def test_exercise_finds_one_problem_and_telegram_without_network(responses, monkeypatch):
    fake_clock(monkeypatch)
    api = SimpleNamespace(token="synthetic-token", get=Mock(return_value=responses["workspace"]),
                          pages=Mock(side_effect=[[], [], responses["queue"]["items"], responses["workspace"]["items"]]))
    monkeypatch.setattr(lab, "run_attack", Mock(return_value={"executed": True, "restored": True, "reason": "", "match_values": MATCH}))
    row, restored = lab.exercise(api, lab.ATTACKS[0], SimpleNamespace(domain_id=7, poll_seconds=10), {})
    assert restored and row["found"] and row["reason"] == ""
    assert row["telegram"] == "accepted" and row["problem_count"] == 1


def test_five_minute_window_and_unavailable_telegram_are_not_success(responses, monkeypatch):
    clock = fake_clock(monkeypatch)
    api = SimpleNamespace(token="synthetic-token", get=Mock(side_effect=lab.ExerciseError("api_unavailable")))
    api.pages = Mock(side_effect=[[], *([responses["queue"]["items"], lab.ExerciseError("api_unavailable")] * 30)])
    monkeypatch.setattr(lab, "run_attack", Mock(return_value={"executed": True, "restored": True, "reason": "", "match_values": MATCH}))
    row, _ = lab.exercise(api, lab.ATTACKS[0], SimpleNamespace(domain_id=7, poll_seconds=10), {})
    assert row["found"] and row["telegram"] == "unverified"
    assert row["reason"] == "telegram_unverified" and clock[0] == 300


def test_cleanup_failure_stops_following_attacks(responses, monkeypatch):
    fake_clock(monkeypatch)
    api = SimpleNamespace(get=Mock(return_value=responses["workspace"]), pages=Mock(return_value=[]))
    monkeypatch.setattr(lab, "run_attack", Mock(return_value={"executed": False, "restored": False, "reason": "cleanup_failed"}))
    row, restored = lab.exercise(api, lab.ATTACKS[0], SimpleNamespace(domain_id=7), {})
    assert not restored and row["reason"] == "cleanup_failed"
    monkeypatch.setattr(lab, "run_attack", Mock(side_effect=lab.ExerciseError("attack_failed")))
    row, restored = lab.exercise(api, lab.ATTACKS[0], SimpleNamespace(domain_id=7), {})
    assert not restored and row["reason"] == "cleanup_unverified"


@pytest.mark.parametrize(("state", "total", "within_ten", "exit_code"), [
    ("empty", 0, True, 0),
    ("ok", 10, True, 0),
    ("ok", 11, False, 1),
    ("partial", 7, None, 1),
    ("stale", 7, None, 1),
    ("denied", None, None, 1),
    ("error", None, None, 1),
])
def test_quiet_only_uses_domain_home_total_without_running_attacks(
        state, total, within_ten, exit_code, monkeypatch, tmp_path, capsys):
    api = Mock()
    api.get.return_value = {"contract_id": "sli.home-summary.v3", "state": state,
                            "total": total, "groups": [], "remaining_problems": total}
    monkeypatch.setattr(lab, "Api", Mock(return_value=api))
    monkeypatch.setenv("SLI_OPERATOR_TOKEN", "synthetic-token")
    attack = Mock(side_effect=AssertionError("attack must not run"))
    monkeypatch.setattr(lab, "run_attack", attack)
    assert lab.main(["--api-url", "https://example.test", "--domain-id", "7",
                     "--results", str(tmp_path), "--quiet-only"]) == exit_code
    api.get.assert_called_once_with("/api/v1/home/summary", {"contract": "v3", "domain_id": 7, "tz": "UTC"})
    attack.assert_not_called()
    report = json.loads((tmp_path / "lab-exercise.json").read_text("utf-8"))
    assert report["quiet"]["problem_count"] == total
    assert report["quiet"]["within_ten"] is within_ten
    assert report["attacks"] == []
    printed_total = "—" if total is None else str(total)
    assert f"проблем на главной — {printed_total}" in capsys.readouterr().out


@pytest.mark.parametrize("payload", [
    {"state": "ok", "total": True},
    {"state": "ok", "total": -1},
    {"state": "ok", "total": None},
    {"state": "empty", "total": 1},
    {"state": "partial"},
])
def test_quiet_only_rejects_malformed_home_total(payload):
    with pytest.raises(lab.ExerciseError, match="^api_contract_invalid$"):
        lab.quiet_home_snapshot({"contract_id": "sli.home-summary.v3", **payload}, START.isoformat())


def test_markdown_json_escape_untrusted_titles_and_exclude_raw_responses(responses, tmp_path):
    title = lab.safe_title("<script>|\n`synthetic-token`", "synthetic-token")
    report = {"quiet": lab.quiet_snapshot(responses["home"], START.isoformat()), "attacks": [
        lab.result_row(lab.ATTACKS[0], found=True, minutes=1.5, title=title, telegram="accepted", count=1)]}
    lab.write_results(tmp_path, report)
    table = (tmp_path / "lab-exercise.md").read_text("utf-8")
    assert "| да | 1.50 |" in table and "&lt;script&gt;&#124;" in table
    assert "synthetic-token" not in table and "&#96;" in table
    saved = (tmp_path / "lab-exercise.json").read_text("utf-8")
    assert "synthetic-token" not in saved and "192.0.2.10" not in saved


def test_powershell_restores_state_with_mocked_ad_and_services():
    shell = shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("Windows PowerShell 5.1 required")
    environment = {key: value for key, value in os.environ.items() if key.casefold() != "psmodulepath"}
    result = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(HERE / "exercise-contract.ps1")],
                            capture_output=True, timeout=30, env=environment)
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")
    assert b"exercise_contracts_passed" in result.stdout
    assert b"private-error" not in result.stdout + result.stderr
