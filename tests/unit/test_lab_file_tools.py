"""File-server lab contracts: local only; no real AD, SMB or credentials."""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "tools/lab"
spec = importlib.util.spec_from_file_location("file_lab_model", LAB / "lab_model.py")
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


def file_expected(**changes):
    return {"schema_version": 1, "run_id": "00000000-0000-4000-8000-000000000001",
            "scenario": "file_read", "started_at_utc": "2026-10-09T10:00:00Z",
            "ended_at_utc": "2026-10-09T10:00:01Z", "actor": "DEMO\\lab.u003",
            "target": "lab.u003", "source_address": "127.0.0.1", "event_ids": [4663, 5145],
            "executed": True, "object_id": None, "target_sid": "S-1-5-21-1-2-3-1103",
            "related_object_id": None, "event_object_id": None,
            "file_path": "\\\\LAB-DC01.demo.example\\LAB-Finance\\Сводка-01.csv",
            "share": "LAB-Finance", "operation": "read", "destination_path": None,
            "outcome": "success", "audit_required": True, "local_time": "2026-10-09T13:00:01+03:00", **changes}


def test_file_expected_jsonl_roundtrip(tmp_path):
    path = tmp_path / "expected.jsonl"
    rows = [file_expected(scenario=s) for s in model.FILE_SCENARIOS]
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8-sig")
    assert model.read_expected(path) == rows


@pytest.mark.parametrize("changes", [
    {"actor": "DEMO\\administrator"}, {"password": "synthetic"},
    {"file_path": "C:\\OwnerData\\file.txt"},
    {"file_path": "\\\\LAB-DC01.demo.example\\LAB-Finance\\..\\secret.txt"},
    {"share": "SYSVOL"}, {"share": []}, {"audit_required": False}, {"operation": "auditpol"}, {"operation": {}},
    {"local_time": "2026-10-09T13:00:00"}, {"event_ids": [4719]},
])
def test_file_expected_rejects_out_of_scope_material(changes):
    with pytest.raises(ValueError, match="^lab_expected_"):
        model.validate_expected(file_expected(**changes))


@pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell 5.1 required")
def test_file_native_ps51_parser_and_descriptor_contracts():
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(ROOT / "tests/unit/lab_file_tools_contract.ps1")],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "lab_file_ps51_contracts_passed" in result.stdout
