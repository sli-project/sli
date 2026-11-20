from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import importlib

import pytest


reporting = importlib.import_module("server.sli.reports.computers_v6_reporting")


def _item(*, entity_id: int, guid: str, build: str = "26100") -> dict:
    return {
        "entity_id": entity_id,
        "object_guid": guid,
        "identity": {"object_guid": guid},
        "display_name": f"WS-{entity_id}",
        "enabled": True,
        "computer_type": "workstation",
        "operating_system": "Windows 11 Pro",
        "operating_system_version": "10.0",
        "operating_system_build": build,
        "ou_path": "Workstations",
        "ip_addresses": ["10.0.0.2"],
        "network": {"ad_site": {"state": "observed", "value": "SITE-A"}},
        "managed_by": None,
        "quality_issues": [],
        "semantic_findings": [],
        "evidence": {"attribute_states": {}, "source_states": {}},
        "reasons": [],
        "activity": {},
    }


def test_reference_age_uses_snapshot_completed_at_not_object_collection_time() -> None:
    item = _item(entity_id=1, guid="11111111-1111-4111-8111-111111111111")
    item.update(
        {
            "observed_at_utc": "2026-08-01T00:00:00Z",
            "last_logon_utc": "2026-08-29T12:00:00Z",
            "source_snapshot": {"completed_at_utc": "2026-08-30T12:00:00Z"},
        }
    )

    reporting._requalify_computers_v6_item(item, 60)

    assert item["qualification_observed_at_utc"] == "2026-08-30T12:00:00Z"
    assert item["activity"]["age_days"] == 1


def test_unknown_os_reason_uses_v6_os_source_state() -> None:
    item = _item(entity_id=1, guid="11111111-1111-4111-8111-111111111111")
    item["evidence"]["attribute_states"] = {"operating_system": {"state": "absent_in_source"}}
    item["evidence"]["source_states"] = {"os": {"status": "observed", "value": "Windows 11 Pro"}}

    assert "unknown_os" not in {
        reason["code"] for reason in reporting._attention_reasons(item, 60)
    }

    item["evidence"]["source_states"]["os"] = {
        "status": "missing_in_source",
        "value": None,
        "observed_at": "2026-08-30T12:00:00Z",
    }
    assert "unknown_os" in {
        reason["code"] for reason in reporting._attention_reasons(item, 60)
    }


def test_snapshot_comparison_matches_stable_object_guid_and_compares_os_build() -> None:
    guid = "11111111-1111-4111-8111-111111111111"
    previous_item = _item(entity_id=10, guid=guid, build="26000")
    current_item = _item(entity_id=99, guid=guid, build="26100")

    result = reporting.compare_computers_v6_snapshots(
        current={"contract_id": reporting.CONTRACT_ID, "state": "available", "items": [current_item]},
        previous={"contract_id": reporting.CONTRACT_ID, "state": "available", "items": [previous_item]},
    )

    assert [row["change_type"] for row in result["items"]] == ["os_changed"]
    assert result["items"][0]["entity_id"] == 99
    assert "26000" in result["items"][0]["before"]
    assert "26100" in result["items"][0]["after"]


def test_snapshot_comparison_rejects_missing_or_duplicate_object_guid() -> None:
    missing = _item(entity_id=1, guid="")
    with pytest.raises(ValueError, match="snapshot_missing_object_guid"):
        reporting.compare_computers_v6_snapshots(
            current={"contract_id": reporting.CONTRACT_ID, "items": [missing]},
            previous={"contract_id": reporting.CONTRACT_ID, "items": []},
        )

    duplicate = _item(entity_id=2, guid="11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValueError, match="snapshot_duplicate_object_guid"):
        reporting.compare_computers_v6_snapshots(
            current={"contract_id": reporting.CONTRACT_ID, "items": [duplicate, deepcopy(duplicate)]},
            previous={"contract_id": reporting.CONTRACT_ID, "items": []},
        )


def test_search_covers_description_reason_and_change_explanation() -> None:
    item = _item(entity_id=1, guid="11111111-1111-4111-8111-111111111111")
    item["description"] = "Касса учебного центра"
    item["reasons"] = [
        {
            "label": "Ошибка источника",
            "observed": "DNS отказал",
            "condition": "failed",
            "qualification": "адрес не подтверждён",
            "limitation": "это не доказывает отсутствие ПК",
            "next_action": "проверить DNS",
        }
    ]
    assert "учебного центра" in reporting._item_search_text(item)
    assert "проверить dns" in reporting._item_search_text(item)

    change = {
        "display_name": "WS-1",
        "before": "SITE-A",
        "after": "SITE-B",
        "qualification": "различие снимков",
        "limitation": "причина не установлена",
        "next_action": "сверить объект",
        "object": item,
    }
    assert "причина не установлена" in reporting._change_search_text(change)
    assert "учебного центра" in reporting._change_search_text(change)


def test_all_visible_reference_columns_have_server_sort_values() -> None:
    assert {"ip_addresses", "ad_site", "reason", "quality"} <= reporting.SORT_FIELDS
    item = _item(entity_id=1, guid="11111111-1111-4111-8111-111111111111")
    item["reasons"] = [{"label": "Тип объекта не определён"}]
    item["quality_issues"] = [{"label": "Частичный результат"}]
    assert reporting._sort_value(item, "ip_addresses") == "10.0.0.2"
    assert reporting._sort_value(item, "ad_site") == "site-a"
    assert reporting._sort_value(item, "reason") == "тип объекта не определён"
    assert reporting._sort_value(item, "quality") == "частичный результат"


def test_dynamic_filter_options_support_explicit_missing_values() -> None:
    assert reporting._matches_dynamic_filter(None, "__missing__") is True
    assert reporting._matches_dynamic_filter("", "__missing__") is True
    assert reporting._matches_dynamic_filter("Windows Server", "windows server") is True
    assert reporting._matches_dynamic_filter("Windows client", "windows server") is False


def test_source_unknown_classification_does_not_erase_proven_base_type() -> None:
    item = {
        "object_guid": "11111111-1111-4111-8111-111111111111",
        "computer_type": "server",
        "classification": {"result": "server", "source": "base_inventory"},
        "source_states": {},
        "collection_errors": [],
    }
    overlay = {
        "source_snapshot": {"state": "complete", "completed_at_utc": "2026-08-30T12:00:00Z"},
        "by_guid": {
            item["object_guid"]: {
                "classification": {"result": "unknown", "state": "observed"},
                "sources": {"classification": {"status": "observed"}},
                "roleEvidence": "OperatingSystem contains Server: Windows Server 2022 Datacenter",
            }
        },
    }

    reporting._apply_computers_v6_source_overlay(item, overlay)

    assert item["computer_type"] == "server"
    assert item["classification"]["result"] == "server"
    assert item["classification"]["role_evidence"] == [
        "OperatingSystem contains Server: Windows Server 2022 Datacenter"
    ]


def test_snapshot_history_distinguishes_no_snapshot_from_missing_previous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reporting, "query_rows_bounded", lambda *_args, **_kwargs: [])
    assert reporting._load_snapshot_comparison([1])["reason"] == "snapshot_history_not_collected"

    row = {
        "snapshot_id": 1,
        "domain_id": 1,
        "bucket_start_utc": datetime(2026, 8, 30, tzinfo=timezone.utc),
        "captured_at_utc": datetime(2026, 8, 30, tzinfo=timezone.utc),
        "source_observed_at_utc": datetime(2026, 8, 30, tzinfo=timezone.utc),
        "source_state": "complete",
        "object_count": 1,
        "payload_json": {"contract_id": reporting.CONTRACT_ID, "items": []},
    }
    monkeypatch.setattr(reporting, "query_rows_bounded", lambda *_args, **_kwargs: [row])
    assert (
        reporting._load_snapshot_comparison([1])["reason"]
        == "previous_compatible_snapshot_not_collected"
    )


def test_snapshot_history_exposes_current_count_time_status_and_query_dc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = {
        "snapshot_id": 1,
        "domain_id": 1,
        "bucket_start_utc": datetime(2026, 8, 30, tzinfo=timezone.utc),
        "captured_at_utc": datetime(2026, 8, 30, 12, tzinfo=timezone.utc),
        "source_observed_at_utc": datetime(2026, 8, 30, 11, tzinfo=timezone.utc),
        "source_state": "partial",
        "object_count": 1337,
        "payload_json": {
            "contract_id": reporting.CONTRACT_ID,
            "items": [],
            "source_snapshot": {"state": "partial", "query_dc": "DC2.example.test"},
        },
    }
    monkeypatch.setattr(reporting, "query_rows_bounded", lambda *_args, **_kwargs: [row])

    current = reporting._load_snapshot_comparison([1])["current"]

    assert current["object_count"] == 1337
    assert current["source_observed_at_utc"] == "2026-08-30T11:00:00+00:00"
    assert current["collection_status"] == "partial"
    assert current["query_dc"] == "DC2.example.test"


def test_view_metrics_are_calculated_from_the_filtered_slice() -> None:
    first = _item(entity_id=1, guid="11111111-1111-4111-8111-111111111111")
    first["reasons"] = [{"code": "unknown_os"}]
    first["quality_issues"] = [{"code": "no_record"}]
    second = _item(entity_id=2, guid="22222222-2222-4222-8222-222222222222")
    second["semantic_findings"] = [{"id": 1}, {"id": 2}]

    metrics = reporting._view_metrics([first], snapshot_changes=[])

    assert metrics == {
        "slice_count": 1,
        "attention": 1,
        "changes": 0,
        "data_quality": 1,
        "semantic_links": 0,
        "semantic_findings": 0,
        "metric_counts": {
            "all": 1,
            "unknown_os": 1,
            "no_record": 1,
            "activity_gap": 1,
        },
    }
