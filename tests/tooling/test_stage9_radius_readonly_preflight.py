from __future__ import annotations

import json
from pathlib import Path




ROOT = Path(__file__).resolve().parents[2]
POWERSHELL = (
    ROOT / "scripts" / "maintenance" / "Invoke-SLI-RadiusReadOnlyPreflight.ps1"
)
RUNNER = (
    ROOT
    / "archive"
    / "runner_one_shot_20260730"
    / "33-radius-readonly-preflight.cmd"
)


def _live_result() -> dict:
    return {
        "schema_version": 1,
        "probe": "stage9-radius-readonly-preflight",
        "read_only": True,
        "contains_event_payload": False,
        "contains_accounting_file_names": False,
        "contains_accounting_file_contents": False,
        "window_hours": 168,
        "event_ids": [6272, 6273],
        "targets": [
            {
                "source_name": "radius01.example.invalid",
                "status": "completed",
                "event_query": {
                    "status": "observed",
                    "selected_count": 2,
                    "truncated": False,
                    "groups": [
                        {"event_id": 6272, "count": 1},
                        {"event_id": 6273, "count": 1},
                    ],
                    "eventdata_field_names": ["UserName"],
                },
                "nps_service": {
                    "status": "observed",
                    "present": True,
                    "runtime_status": "Running",
                },
                "default_accounting_files": {
                    "status": "observed",
                    "observed_count": 1,
                    "truncated": False,
                },
            }
        ],
    }
















def test_powershell_probe_contains_only_read_commands_for_surveyed_systems():
    source = POWERSHELL.read_text(encoding="utf-8-sig").casefold()
    for forbidden in (
        "set-service",
        "start-service",
        "stop-service",
        "restart-service",
        "set-itemproperty",
        "new-itemproperty",
        "remove-item",
        "invoke-command",
        "enter-pssession",
    ):
        assert forbidden not in source
    assert "get-winevent" in source
    assert "get-service" in source
    assert "get-childitem" in source
    assert "6272" in source and "6273" in source




def test_target_inventory_is_exactly_the_current_owner_confirmed_radius():
    target_path = ROOT / "config" / "stage9_radius_targets.json"
    inventory = json.loads(target_path.read_text(encoding="utf-8"))
    assert "current owner-confirmed" in inventory["description"].casefold()
    assert len(inventory["targets"]) == 1
    target = inventory["targets"][0]
    assert set(target) == {"source_name", "connect_address", "owner_confirmed_ip"}
    assert all(isinstance(value, str) and value for value in target.values())
    assert target["source_name"] == target["connect_address"]
    assert target["source_name"] != "radius01.example.invalid"
