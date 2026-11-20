from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

import scripts.maintenance.domain_posture_canary as canary


def _metrics() -> list[dict[str, int | str]]:
    return [
        {
            "check": check,
            "duration_ms": 10 + index,
            "record_count": index,
            "response_bytes": 100 + index,
            "time_limit_seconds": 30,
            "record_limit": 100,
            "response_bytes_limit": 4096,
        }
        for index, check in enumerate(canary.EXPECTED_CHECKS)
    ]


def test_exact_eight_row_powershell_json_shape_is_accepted() -> None:
    rows = _metrics()
    assert canary._validated_metrics(json.dumps(rows)) == rows


def test_powershell_control_add_cannot_leak_a_ninth_pipeline_row() -> None:
    source = canary.MODULE.read_text(encoding="utf-8")
    assert "[void]$request.Controls.Add(" in source
    assert "\n                $request.Controls.Add(" not in source


def test_parser_rejects_missing_row_and_unexpected_shape() -> None:
    rows = _metrics()
    try:
        canary._validated_metrics(json.dumps(rows[:-1]))
    except ValueError as exc:
        assert str(exc) == "incomplete_check_result"
    else:
        raise AssertionError("incomplete result was accepted")

    rows = _metrics()
    rows[0]["raw_value"] = "must not be accepted"
    try:
        canary._validated_metrics(json.dumps(rows))
    except ValueError as exc:
        assert str(exc) == "unexpected_check_result_shape"
    else:
        raise AssertionError("unexpected result field was accepted")


def test_attempt_two_has_separate_evidence_and_confirmation() -> None:
    first = canary._evidence_path(1)
    second = canary._evidence_path(2)
    assert first != second
    assert second.name == "domain-posture-readonly-canary-attempt2.json"
    assert canary.CONFIRMATIONS[2].endswith("-ATTEMPT2")


def test_attempt_three_has_separate_evidence_and_confirmation() -> None:
    paths = [canary._evidence_path(attempt) for attempt in (1, 2, 3)]
    assert len(set(paths)) == 3
    assert paths[2].name == "domain-posture-readonly-canary-attempt3.json"
    assert canary.CONFIRMATIONS[3].endswith("-ATTEMPT3")


def test_attempt_two_token_cannot_start_attempt_three(
    monkeypatch, tmp_path: Path,
) -> None:
    monkeypatch.setitem(canary.EVIDENCE_PATHS, 3, tmp_path / "attempt3.json")
    args = argparse.Namespace(
        directory_server="DC2",
        domain_dn="DC=example,DC=test",
        execute=True,
        confirmation=canary.CONFIRMATIONS[2],
        attempt=3,
    )

    with pytest.raises(PermissionError, match="ATTEMPT3"):
        canary.run(args)


@pytest.mark.parametrize("attempt", [2, 3])
def test_later_attempt_writes_aggregate_only_success_evidence(
    monkeypatch, tmp_path: Path, attempt: int,
) -> None:
    evidence = tmp_path / f"attempt{attempt}.json"
    monkeypatch.setitem(canary.EVIDENCE_PATHS, attempt, evidence)
    monkeypatch.setattr(canary, "_trusted_powershell", lambda: Path("powershell.exe"))

    class Completed:
        returncode = 0
        stdout = json.dumps(_metrics())
        stderr = ""

    monkeypatch.setattr(canary.subprocess, "run", lambda *args, **kwargs: Completed())
    args = argparse.Namespace(
        directory_server="DC2",
        domain_dn="DC=example,DC=test",
        execute=True,
        confirmation=canary.CONFIRMATIONS[attempt],
        attempt=attempt,
    )
    result = canary.run(args)
    persisted = json.loads(evidence.read_text(encoding="utf-8"))
    assert result["status"] == "done"
    assert persisted["checks"] == _metrics()
    assert persisted["raw_attribute_values_persisted"] is False
    assert persisted["security_descriptor_persisted"] is False
    assert "stdout" not in persisted
    assert "stderr" not in persisted
