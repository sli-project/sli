import json
from pathlib import Path









def test_stage7_evaluation_contract_is_unbiased_and_fail_closed() -> None:
    payload = json.loads(
        Path("config/stage7_storage_evaluation.json").read_text(encoding="utf-8")
    )

    assert [item["id"] for item in payload["candidates"]] == ["D", "A", "B", "C"]
    assert payload["decision_not_preselected"] is True
    assert payload["hard_gates"]["event_hash_mismatches_max"] == 0
    assert payload["selection"]["primary_metric"] == (
        "full_managed_storage_bytes_excluding_capacity_headroom"
    )
    assert (
        "measured_peak_temporary_merge_or_backfill_space"
        not in payload["managed_storage_components"]
    )
    assert payload["execution"]["production_runtime_mutation"] is False
