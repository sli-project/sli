from __future__ import annotations


def test_runtime_baseline_is_read_only_and_does_not_include_event_payload() -> None:
    source = open("scripts/maintenance/runtime_baseline.py", encoding="utf-8").read()

    assert "RUNTIME_BASELINE" in source
    assert "read_only\": True" in source
    assert "scheduler_embedded_status" in source
    assert "record_xml" not in source
    assert "message_text" not in source
