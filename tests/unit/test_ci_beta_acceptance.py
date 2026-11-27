import json

import pytest

from scripts.ci import beta_acceptance


def test_quiet_home_requires_an_observed_count():
    with pytest.raises(beta_acceptance.CheckFailed):
        beta_acceptance.quiet_counts({"problems": {"open_count": None}}, None)


@pytest.mark.parametrize("hygiene, other, status, reason", [
    (0, 0, "pass", None),
    (10, 0, "pass", None),
    (11, 0, "fail", "quiet_limits"),
    (0, 1, "fail", "quiet_limits"),
])
def test_check_six_reports_open_counts_and_applies_limits(hygiene, other, status, reason):
    total = hygiene + other
    home = {"domains": [], "domain_id": None, "problems": {"open_count": total, "items": []}, "weak_spots": {}}
    if total:
        home.update(domains=[{"id": 7}], domain_id=7)

    def read(params):
        assert total > 0
        assert params["domain_id"] == 7 and params["population"] == "open"
        items = [
            {"id": index, "rule_code": "qw.ad-hardening.machine-account-quota" if index <= hygiene else "unclassified"}
            for index in range(1, total + 1)
        ]
        return {"items": items, "has_more": False}

    quiet = beta_acceptance.blank_results("not_reached")["quiet"]
    beta_acceptance.check_quiet_home(home, read, quiet)

    assert quiet == {"status": status, "reason": reason, "open_count": total, "hygiene": hygiene, "other": other}


def test_quiet_home_classifies_the_entire_open_queue():
    home = {"domain_id": 7, "problems": {"open_count": 2, "items": [{"id": 1}]}, "weak_spots": {}}

    def read(params):
        assert params["domain_id"] == 7 and params["population"] == "open"
        if "cursor" not in params:
            return {
                "items": [{"id": 1, "rule_code": "qw.ad-hardening.machine-account-quota"}],
                "has_more": True,
                "next_cursor": "second-page",
            }
        assert params["cursor"] == "second-page"
        return {"items": [{"id": 2, "rule_code": "unclassified"}], "has_more": False}

    assert beta_acceptance.quiet_counts(home, read) == (1, 1)


@pytest.mark.parametrize("ids", [[1], [1, 1], [2, 3]])
def test_quiet_home_rejects_an_inconsistent_report(ids):
    home = {"domain_id": 7, "problems": {"open_count": 2, "items": [{"id": 1}]}, "weak_spots": {}}

    def read(_):
        return {"items": [{"id": row_id, "rule_code": "unclassified"} for row_id in ids], "has_more": False}

    with pytest.raises(beta_acceptance.CheckFailed):
        beta_acceptance.quiet_counts(home, read)


@pytest.mark.parametrize("vm_outcome", ["success", "failure"])
def test_report_preserves_the_three_checks_when_acceptance_fails(tmp_path, monkeypatch, vm_outcome):
    release = "beta-" + "a" * 12
    summary, outputs = tmp_path / "summary.md", tmp_path / "outputs.txt"
    for name, value in {
        "BETA_RESULTS": str(tmp_path),
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(outputs),
        "RELEASE": release,
        "COMMIT": "a" * 40,
        "KIT_SHA256": "b" * 64,
        "RELEASE_OUTCOME": "success",
        "KIT_OUTCOME": "success",
        "VM_OUTCOME": vm_outcome,
    }.items():
        monkeypatch.setenv(name, value)
    checks = beta_acceptance.blank_results("not_reached")
    checks["install"].update(status="pass", reason=None, commands=3, elapsed_ms=98_000, readiness_http=200)
    checks["quiet"].update(reason="quiet_limits", open_count=3, hygiene=2, other=1)
    (tmp_path / "guest.json").write_text(json.dumps(checks), encoding="utf-8")

    beta_acceptance.report()

    result = json.loads((tmp_path / "beta-acceptance.json").read_text(encoding="utf-8"))
    assert result["release"] == release
    assert set(result["checks"]) == {"1", "2", "6"}
    assert outputs.read_text(encoding="utf-8") == "passed=false\n"
    table = summary.read_text(encoding="utf-8")
    assert table.count("| **") == 3
    if vm_outcome == "success":
        assert result["checks"]["6"]["other"] == 1
        assert "| **PASS** | 3 commands" in table
    else:
        assert result["checks"]["1"]["commands"] is None
        assert table.count("**FAIL**") == 3
