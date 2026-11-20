from datetime import datetime, timedelta, timezone
from pathlib import Path

from server.sli.sources.source_coverage_integrity import classify_channel_integrity


NOW = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def test_channel_integrity_distinguishes_complete_partial_and_unavailable() -> None:
    base = {"server_hostname": "DC1", "channel": "Security", "backfill_completed": True, "last_status": "completed"}
    complete = classify_channel_integrity({**base, "last_successful_collection_utc": NOW - timedelta(minutes=5)}, now=NOW)
    partial = classify_channel_integrity({**base, "last_successful_collection_utc": NOW - timedelta(minutes=35)}, now=NOW)
    unavailable = classify_channel_integrity({**base, "last_successful_collection_utc": None}, now=NOW)
    assert (complete["status"], partial["status"], unavailable["status"]) == ("complete", "partial", "unavailable")


def test_source_reader_is_local_bounded_and_does_not_claim_gap_proof() -> None:
    source = Path("server/sli/sources/source_coverage_integrity.py").read_text(encoding="utf-8")
    assert "limit 100" in source.lower()
    assert "remote_sequence_scan_performed\": False" in source
    assert "surveyed_servers_contacted\": False" in source
    assert "payload_read\": False" in source
    assert "stale_empty_proposals" in source
    assert "actionable_rollbacks" in source
    assert "events_v2_core" not in source
    assert " from events " not in source.lower()
