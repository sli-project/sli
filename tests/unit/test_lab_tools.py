"""Lab inventory/JSONL and Windows script contracts; no database or remote host."""
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "tools/lab"
spec = importlib.util.spec_from_file_location("sli_lab_model", LAB / "lab_model.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def expected(**changes):
    return {"schema_version": 1, "run_id": "00000000-0000-4000-8000-000000000001",
            "scenario": "password_spray", "started_at_utc": "2026-10-09T10:00:00Z",
            "ended_at_utc": "2026-10-09T10:00:01+00:00", "actor": "lab-system",
            "target": "lab.u001", "source_address": "127.0.0.1", "event_ids": [4625],
            "executed": True, "object_id": None, "target_sid": None, "related_object_id": None,
            "event_object_id": None, **changes}


def test_inventory_is_deterministic_and_deployed_manifest_matches_generator():
    data = model.inventory()
    assert data == model.inventory()
    assert json.loads((LAB / "lab-data.json").read_text("utf-8-sig")) == data


def test_inventory_size_uniqueness_provenance_and_reserved_namespace():
    data = model.inventory()
    assert data["domain"] == "demo.example" and data["netbios"] == "DEMO"
    assert len(data["departments"]) == 8
    assert len(data["computers"]) == 40
    assert len(data["gpos"]) == 8 and "LAB-VPN" in data["groups"]
    humans = [u for u in data["users"] if not u["service"]]
    services = [u for u in data["users"] if u["service"]]
    assert len(humans) == 150 and len(services) == 2
    assert len({u["display_name"] for u in humans}) == 150
    assert len({u["sam"] for u in data["users"]}) == 152
    assert sum(not u["enabled"] for u in humans) == 3
    assert all(u["marker"] == model.MARKER and u["sam"].startswith("lab.") for u in data["users"])
    assert all(u["department"] in data["departments"] for u in humans)
    assert all(any("А" <= char <= "я" for char in u["display_name"]) for u in humans)
    assert all(c["name"].startswith("LAB-") and c["marker"] == model.MARKER for c in data["computers"])
    assert all(spn.endswith(".demo.example") for u in services for spn in u["spns"])
    assert all(not {"password", "token", "secret", "credentials"}.intersection(u) for u in data["users"])


def test_expected_jsonl_accepts_ps51_bom_and_multiple_rows(tmp_path):
    path = tmp_path / "2026-10-09.jsonl"
    rows = [expected(), expected(executed=False)]
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n\n", encoding="utf-8-sig")
    assert model.read_expected(path) == rows


@pytest.mark.parametrize("scenario", ["wrong_password", "password_spray", "single_account_brute", "disabled_logon"])
def test_expected_accepts_ntlm_failure_alternative(scenario):
    row = expected(scenario=scenario, event_ids=[4625, 4776])
    assert model.validate_expected(row) == row


def test_powershell_authentication_expectations_and_matching():
    shell = shutil.which("pwsh") or (shutil.which("powershell.exe") if os.name == "nt" else None)
    if shell is None:
        pytest.skip("PowerShell required for hermetic lab authentication contracts")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File", str(ROOT / "tests/unit/lab_auth_tools_contract.ps1")],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_auth_contracts_passed" in result.stdout


def test_powershell_verifier_reports_authentication_failures_safely():
    shell = shutil.which("pwsh") or (shutil.which("powershell.exe") if os.name == "nt" else None)
    if shell is None:
        pytest.skip("PowerShell required for hermetic lab report contracts")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File",
         str(ROOT / "tests/unit/lab_auth_tools_contract.ps1"), "-ReportFailures"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_report_failure_contracts_passed" in result.stdout
    assert "synthetic-private-response" not in result.stdout + result.stderr


@pytest.mark.parametrize("shell_name", ["powershell.exe", "pwsh"] if os.name == "nt" else ["pwsh"])
def test_powershell_verifier_keeps_events_inside_scenario_window(shell_name):
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell required for hermetic lab query-window contract")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File",
         str(ROOT / "tests/unit/lab_verify_window_contract.ps1")],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_verify_window_contract_passed" in result.stdout


@pytest.mark.parametrize("shell_name", ["powershell.exe", "pwsh"] if os.name == "nt" else ["pwsh"])
def test_powershell_verifier_reads_named_history_collections(shell_name):
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.skip("PowerShell required for hermetic lab collection contract")
    result = subprocess.run(
        [shell, "-NoProfile", "-NonInteractive", "-File",
         str(ROOT / "tests/unit/lab_verify_collections_contract.ps1")],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_verify_collections_contract_passed" in result.stdout


@pytest.mark.parametrize("changes", [
    {"password": "synthetic-forbidden"}, {"token": "synthetic-forbidden"},
    {"actor": "unapproved-actor"}, {"target": "unapproved-target"},
    {"source_address": "192.0.2.1"}, {"scenario": "unapproved-scenario"},
    {"schema_version": 2}, {"schema_version": True}, {"scenario": []},
    {"executed": "true"}, {"event_ids": [True]},
    {"event_ids": [9999]}, {"event_ids": []}, {"run_id": "invalid"},
    {"started_at_utc": "2026-10-09T10:00:00"},
    {"started_at_utc": "2026-10-09T10:00:00+03:00"},
    {"ended_at_utc": "2026-10-08T10:00:00Z"}, {"object_id": "invalid"},
    {"related_object_id": "invalid"}, {"event_object_id": "invalid"}, {"target_sid": "S-1-5-18"},
])
def test_expected_rejects_private_or_malformed_material(changes):
    with pytest.raises(ValueError, match="^lab_expected_"):
        model.validate_expected(expected(**changes))


def test_all_scenarios_have_a_serializable_expected_contract():
    for scenario in model.SCENARIOS:
        row = expected(scenario=scenario)
        assert model.validate_expected(json.loads(json.dumps(row))) == row


def test_powershell_files_have_bom_and_ps51_requirement():
    paths = list(LAB.glob("*.ps1"))
    assert {path.name for path in paths} == {
        "lab-01-domain.ps1", "lab-02-populate.ps1", "lab-03-simulate.ps1",
        "lab-04-agent.ps1", "lab-05-file-server.ps1", "lab-06-file-simulate.ps1",
        "lab-08-nps-denials.ps1", "lab-common.ps1", "lab-exercise-attack.ps1", "lab-orchestrate.ps1",
        "lab-tunnel.ps1", "lab-verify.ps1",
    }
    for path in paths:
        assert path.read_bytes().startswith(b"\xef\xbb\xbf"), path.name
        assert "#Requires -Version 5.1" in path.read_text("utf-8-sig")


def test_owner_only_issues_tokens_and_keeps_secrets_out_of_process_arguments():
    script = (LAB / "lab-orchestrate.ps1").read_text("utf-8-sig")
    assert "server.sli.agents.issue_token" in script
    assert "--actor', 'sli-lab-orchestrator'" in script
    assert "Write-LabSecret" in script
    assert "finally { Remove-Item -LiteralPath \"$stage\\enrollment.token\" -Force }" in script
    assert "/api/v1/admin/agents/modules" not in script
    assert "python', '-c'" not in script
    agent = (LAB / "lab-04-agent.ps1").read_text("utf-8-sig")
    assert "SERVER_URL=https://localhost:8443" in agent
    assert "TOKEN=" not in agent and "TOKEN_FILE=" not in agent
    assert "lab_agent_registered_waiting_for_server_policy" in agent


@pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell 5.1 parser/fakes required")
def test_native_ps51_parser_msi_arguments_and_fake_reruns():
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(ROOT / "tests/unit/lab_tools_contract.ps1")],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_msi_contracts_passed" in result.stdout
    assert "lab_ps51_contracts_passed" in result.stdout


@pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell 5.1 serializer required")
def test_actual_powershell_expected_serializer_matches_python_contract():
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
         str(ROOT / "tests/unit/lab_tools_contract.ps1"), "-EmitExpected"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0
    assert model.validate_expected(json.loads(result.stdout))["target"] == "lab.u001"
