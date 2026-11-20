from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from scripts.maintenance import gpo_permission_canary as canary


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "directory_server": "DC2",
        "domain": "example.invalid",
        "execute": False,
        "confirmation": "",
        "archive_stopped_access_evidence": False,
        "archive_fixed_job_boundary_evidence": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_retired_canary_refuses_after_permission_contract_entered_exporter():
    with pytest.raises(
        RuntimeError,
        match="running_exporter_references_gpo_permission_contract",
    ):
        canary.run(_args())

    command = canary._command(_args())
    assert "Invoke-SLIBoundedGpoPermissionRead" in command
    assert "Get-GPO -All" in command
    assert "Set-GPPermission" not in command
    assert "Set-GPO" not in command


def test_parse_rows_accepts_only_ordinal_aggregate_metrics():
    header = {
        "kind": "header",
        "policy_count": 1,
        "ceilings": canary.CEILINGS,
    }
    row = {
        "kind": "policy",
        "sequence": 1,
        "duration_ms": 125,
        "response_bytes": 900,
        "permission_count": 5,
        "apply_allow_count": 1,
        "apply_deny_count": 0,
        "denied_count": 0,
        "inherited_count": 2,
        "custom_count": 0,
        "effective_access_evaluated": False,
    }
    count, rows = canary._parse_rows(
        json.dumps(header) + "\n" + json.dumps(row)
    )

    assert count == 1
    assert rows == [{
        key: value for key, value in row.items() if key != "kind"
    }]

    row["trustee_sid"] = "S-1-5-11"
    with pytest.raises(ValueError, match="unexpected_policy_metric_shape"):
        canary._parse_rows(json.dumps(header) + "\n" + json.dumps(row))


def test_parse_rows_rejects_effective_access_claim():
    header = {
        "kind": "header",
        "policy_count": 1,
        "ceilings": canary.CEILINGS,
    }
    row = {
        "kind": "policy",
        "sequence": 1,
        "duration_ms": 125,
        "response_bytes": 900,
        "permission_count": 5,
        "apply_allow_count": 1,
        "apply_deny_count": 0,
        "denied_count": 0,
        "inherited_count": 2,
        "custom_count": 0,
        "effective_access_evaluated": True,
    }

    with pytest.raises(ValueError, match="unexpected_effective_access_claim"):
        canary._parse_rows(json.dumps(header) + "\n" + json.dumps(row))


def test_execute_requires_exact_confirmation(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(canary, "_validate", lambda _args: None)

    with pytest.raises(PermissionError, match=canary.CONFIRMATION):
        canary.run(_args(execute=True, confirmation="wrong"))


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "error_type", "validation_code"),
    [
        (
            1, "", "access denied", "GpoPermissionAccessDenied",
            "missing_inventory_header",
        ),
        (
            0, "not-json", "", "LocalResultValidation",
            "invalid_json_line",
        ),
    ],
)
def test_execute_persists_allowlisted_failure_observability(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: str,
    stderr: str,
    error_type: str,
    validation_code: str,
):
    evidence = tmp_path / "evidence.json"
    monkeypatch.setattr(canary, "EVIDENCE", evidence)
    monkeypatch.setattr(canary, "LOCK", tmp_path / "evidence.lock")
    monkeypatch.setattr(canary, "_validate", lambda _args: None)
    monkeypatch.setattr(
        canary.subprocess,
        "run",
        lambda *_args, **_kwargs: canary.subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=stdout, stderr=stderr,
        ),
    )
    monkeypatch.setattr(canary, "_powershell", lambda: Path("fixture-powershell.exe"))

    result = canary.run(_args(
        execute=True,
        confirmation=canary.CONFIRMATION,
    ))

    assert result["status"] == "stopped"
    assert result["error_type"] == error_type
    assert result["validation_code"] == validation_code
    assert json.loads(evidence.read_text(encoding="utf-8")) == result


def test_only_exact_stopped_access_evidence_can_be_archived_once(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    evidence = tmp_path / "evidence.json"
    attempt2 = tmp_path / "evidence-attempt2.json"
    stopped = {
        "status": "stopped",
        "classification": "bounded_read_only_gpo_permission",
        "error_type": "GpoPermissionAccessDenied",
        "validation_code": "missing_inventory_header",
        "database_changed": False,
        "runtime_changed": False,
        "surveyed_system_changed": False,
        "raw_permission_rows_persisted": False,
        "trustee_sids_persisted": False,
        "account_names_persisted": False,
    }
    evidence.write_text(json.dumps(stopped), encoding="utf-8")
    monkeypatch.setattr(canary, "EVIDENCE", evidence)
    monkeypatch.setattr(canary, "ATTEMPT2_EVIDENCE", attempt2)

    canary._archive_stopped_access_evidence()

    assert not evidence.exists()
    assert json.loads(attempt2.read_text(encoding="utf-8")) == stopped
    evidence.write_text(json.dumps(stopped), encoding="utf-8")
    with pytest.raises(FileExistsError, match="retry_already_used"):
        canary._archive_stopped_access_evidence()


def test_successful_or_unknown_evidence_is_never_archived(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({"status": "done"}), encoding="utf-8")
    monkeypatch.setattr(canary, "EVIDENCE", evidence)
    monkeypatch.setattr(
        canary, "ATTEMPT2_EVIDENCE", tmp_path / "evidence-attempt2.json",
    )

    with pytest.raises(FileExistsError, match="not_retryable"):
        canary._archive_stopped_access_evidence()
    assert json.loads(evidence.read_text(encoding="utf-8")) == {"status": "done"}


def test_exact_fixed_job_boundary_failure_can_be_archived_once(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    evidence = tmp_path / "evidence.json"
    attempt2 = tmp_path / "evidence-attempt2.json"
    attempt3 = tmp_path / "evidence-attempt3.json"
    attempt2.write_text("{}", encoding="utf-8")
    stopped = {
        "status": "stopped",
        "classification": "bounded_read_only_gpo_permission",
        "policy_count": 72,
        "processed_count": 0,
        "stopped_at_policy_index": 1,
        "error_type": "GpoPermissionPowerShellFailed_1",
        "database_changed": False,
        "runtime_changed": False,
        "surveyed_system_changed": False,
        "raw_permission_rows_persisted": False,
        "trustee_sids_persisted": False,
        "account_names_persisted": False,
    }
    evidence.write_text(json.dumps(stopped), encoding="utf-8")
    monkeypatch.setattr(canary, "EVIDENCE", evidence)
    monkeypatch.setattr(canary, "ATTEMPT2_EVIDENCE", attempt2)
    monkeypatch.setattr(canary, "ATTEMPT3_EVIDENCE", attempt3)

    canary._archive_fixed_job_boundary_evidence()

    assert not evidence.exists()
    assert json.loads(attempt3.read_text(encoding="utf-8")) == stopped
    evidence.write_text(json.dumps(stopped), encoding="utf-8")
    with pytest.raises(FileExistsError, match="retry_already_used"):
        canary._archive_fixed_job_boundary_evidence()
