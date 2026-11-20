from __future__ import annotations

from server.sli.reports.computers_v5_reporting import compare_computers_v5_snapshots


def _item(entity_id: int, **updates):
    value = {
        "entity_id": entity_id,
        "display_name": f"PC-{entity_id}",
        "enabled": True,
        "computer_type": "workstation",
        "ou_path": "OU-A",
        "operating_system": "Windows 10 Pro",
        "operating_system_version": "10.0 (19045)",
        "ip_addresses": ["10.0.0.1"],
        "quality_issues": [],
        "semantic_findings": [],
    }
    value.update(updates)
    return value


def test_v5_comparison_uses_stable_entity_id_and_keeps_change_types_separate() -> None:
    previous = {
        "contract_id": "sli.computers-report.v5",
        "captured_at_utc": "2026-08-28T12:00:00Z",
        "state": "available",
        "coverage": {"state": "complete"},
        "items": [_item(1), _item(2, display_name="PC-OLD")],
    }
    current = {
        "contract_id": "sli.computers-report.v5",
        "captured_at_utc": "2026-08-29T00:00:00Z",
        "state": "available",
        "coverage": {"state": "complete"},
        "items": [
            _item(
                1,
                enabled=False,
                ou_path="OU-B",
                operating_system="Windows 11 Pro",
                operating_system_version="10.0 (26100)",
                ip_addresses=["10.0.0.2"],
                quality_issues=[{"code": "partial", "label": "Частичный результат"}],
                semantic_findings=[{"finding_id": 77, "status": "open"}],
            ),
            _item(3, display_name="PC-NEW"),
        ],
    }

    result = compare_computers_v5_snapshots(current=current, previous=previous)

    assert result["state"] == "available"
    assert result["current"]["captured_at_utc"] == "2026-08-29T00:00:00Z"
    assert result["previous"]["captured_at_utc"] == "2026-08-28T12:00:00Z"
    assert result["change_count"] == 8
    assert {item["change_type"] for item in result["items"]} == {
        "new_object",
        "missing_current",
        "enabled_changed",
        "ou_changed",
        "os_changed",
        "ip_changed",
        "quality_changed",
        "semantic_changed",
    }
    missing = next(item for item in result["items"] if item["change_type"] == "missing_current")
    assert missing["entity_id"] == 2
    assert "не доказывает удаление" in missing["limitation"]
    semantic = next(item for item in result["items"] if item["change_type"] == "semantic_changed")
    assert semantic["before"] == "нет точных опубликованных связей"
    assert semantic["after"] == "1 точных опубликованных связей"


def test_v5_comparison_does_not_claim_removal_from_partial_current_snapshot() -> None:
    previous = {
        "contract_id": "sli.computers-report.v5",
        "captured_at_utc": "2026-08-28T12:00:00Z",
        "state": "available",
        "coverage": {"state": "complete"},
        "items": [_item(1)],
    }
    current = {
        "contract_id": "sli.computers-report.v5",
        "captured_at_utc": "2026-08-29T00:00:00Z",
        "state": "partial",
        "coverage": {"state": "partial"},
        "items": [],
    }

    result = compare_computers_v5_snapshots(current=current, previous=previous)

    assert result["state"] == "partial"
    assert result["items"][0]["change_type"] == "missing_current"
    assert result["items"][0]["qualification"] == "Объект отсутствует в текущем неполном снимке; причина не установлена."
    assert result["deletion_claim_allowed"] is False
