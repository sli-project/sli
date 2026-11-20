"""Retained DC replay must fail closed before it can import a raw batch."""
from __future__ import annotations

import json
from pathlib import Path

import pytest


def _summary(*, server: str = "DC1", address: str = "DC1.example.test") -> dict:
    channels = [
        "Security", "System", "Directory Service",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational", "DNS Server",
    ]
    return {
        "computer_name": server,
        "connect_address": address,
        "start_time_utc": "2026-09-10T21:34:24.287465+07:00",
        "collector_backend": "python",
        "finished_at": "2026-09-10T21:39:27.703195+07:00",
        "channels": [{"channel": name, "status": "completed"} for name in channels],
    }


def _batch(tmp_path: Path, summary: dict | None = None) -> Path:
    batch = tmp_path / "data" / "raw" / "pilot" / "DC1-20260910-143917"
    batch.mkdir(parents=True)
    payload = summary or _summary()
    for item in payload["channels"]:
        safe = item["channel"].replace("/", "_").replace(" ", "_")
        (batch / f"{safe}.jsonl").write_text("{}\n", encoding="utf-8")
        item["file"] = str(batch / f"{safe}.jsonl")
    (batch / "collection-summary.json").write_text(json.dumps(payload), encoding="utf-8")
    return batch


def test_plan_rejects_lifecycle_that_is_not_a_failed_exact_manifest(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    monkeypatch.setattr(replay, "ROOT", tmp_path)
    monkeypatch.setattr(replay, "raw_batch_manifest", lambda **_: {
        "batch_identity": "b" * 64, "manifest_hash": "m" * 64,
        "raw_path": str(batch.resolve()), "files": [],
    })
    monkeypatch.setattr(replay, "load_lifecycle", lambda **_: {
        "batch_identity": "b" * 64, "manifest_hash": "m" * 64,
        "server": "DC1", "raw_path": str(batch.resolve()), "trace_id": "job-2-DC1",
        "expected_channels": 6, "import_outcome": "succeeded",
        "cursor_outcome": "unknown", "cleanup_outcome": "retained",
    })

    with pytest.raises(RuntimeError, match="lifecycle_not_failed"):
        replay.prepare(batch)


def test_plan_uses_only_catalog_confirmed_identity_and_lifecycle_trace(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    monkeypatch.setattr(replay, "ROOT", tmp_path)
    monkeypatch.setattr(replay, "raw_batch_manifest", lambda **_: {
        "batch_identity": "b" * 64, "manifest_hash": "a" * 64,
        "raw_path": str(batch.resolve()), "files": [{"path": "Security.jsonl"}],
    })
    monkeypatch.setattr(replay, "load_lifecycle", lambda **_: {
        "batch_identity": "b" * 64, "manifest_hash": "a" * 64,
        "server": "DC1", "raw_path": str(batch.resolve()), "trace_id": "job-2-DC1",
        "expected_channels": 6, "import_outcome": "failed",
        "cursor_outcome": "unknown", "cleanup_outcome": "retained",
    })
    monkeypatch.setattr(replay, "catalog_identity", lambda **_: ("example.test", "example.test"))

    prepared = replay.prepare(batch)

    assert prepared.trace_id == "job-2-DC1"
    assert prepared.domain_fqdn == "example.test"
    assert prepared.forest_name == "example.test"
    assert prepared.job_id is None
    assert prepared.confirmation == "replay-retained-dc-batch:" + "a" * 64


def test_apply_requires_exact_manifest_confirmation_before_locks_or_import(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    prepared = replay.PreparedBatch(
        output_dir=batch, server="DC1", trace_id="job-2-DC1", job_id=None,
        domain_fqdn="example.test", forest_name="example.test", collector_backend="python",
        summary=_summary(), batch_identity="b" * 64, manifest_hash="a" * 64,
        confirmation="replay-retained-dc-batch:" + "a" * 64,
    )
    monkeypatch.setattr(replay, "prepare", lambda _: prepared)
    monkeypatch.setattr(replay, "apply_prepared", lambda _: pytest.fail("apply reached"))

    with pytest.raises(RuntimeError, match="confirmation_invalid"):
        replay.run(action="apply", batch=batch, confirmation="replay-retained-dc-batch:" + "0" * 64)


def test_apply_keeps_raw_and_orders_import_then_cursor_then_history(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    prepared = replay.PreparedBatch(
        output_dir=batch, server="DC1", trace_id="job-2-DC1", job_id=None,
        domain_fqdn="example.test", forest_name="example.test", collector_backend="python",
        summary=_summary(), batch_identity="b" * 64, manifest_hash="a" * 64,
        confirmation="replay-retained-dc-batch:" + "a" * 64,
    )
    calls: list[str] = []
    class Completed:
        returncode = 0
        stdout = "Security.jsonl: inserted=1, skipped=0\n"
    monkeypatch.setattr(replay, "held_collection_locks", lambda: __import__("contextlib").nullcontext(None))
    monkeypatch.setattr(replay, "revalidate_prepared", lambda _: calls.append("revalidate"))
    monkeypatch.setattr(replay, "run_import_for_backend", lambda **_: (calls.append("import") or (Completed(), 0, 1, "postgres")))
    monkeypatch.setattr(replay, "record_raw_batch_import_outcome_pg", lambda **_: calls.append("lifecycle_success"))
    monkeypatch.setattr(replay, "update_collection_state_from_summary_pg", lambda **_: calls.append("cursor"))
    monkeypatch.setattr(replay, "record_raw_batch_cursor_outcome_pg", lambda **_: calls.append("cursor_outcome") or {"cursor_outcome": "committed", "committed_channels": 6})
    monkeypatch.setattr(replay, "record_collector_channel_runs_pg", lambda **_: calls.append("history"))
    monkeypatch.setattr(replay, "record_collector_stage_metrics_pg", lambda **_: calls.append("metrics"))
    monkeypatch.setattr(replay, "parse_import_stats", lambda _: {})
    monkeypatch.setattr(replay, "parse_import_profile", lambda _: {})

    replay.apply_prepared(prepared)

    assert calls == ["revalidate", "import", "lifecycle_success", "cursor", "cursor_outcome", "history", "metrics"]
    assert batch.exists()


def test_failed_import_records_failure_but_never_reaches_cursor_or_history(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    prepared = replay.PreparedBatch(batch, "DC1", "job-2-DC1", None, "example.test", "example.test", "python", _summary(), "b" * 64, "a" * 64, "replay-retained-dc-batch:" + "a" * 64)
    calls: list[str] = []
    class Failed:
        returncode = 23
        stdout = ""
        stderr = "bounded importer failure"
    monkeypatch.setattr(replay, "held_collection_locks", lambda: __import__("contextlib").nullcontext(None))
    monkeypatch.setattr(replay, "revalidate_prepared", lambda _: calls.append("revalidate"))
    monkeypatch.setattr(replay, "run_import_for_backend", lambda **_: calls.append("import") or (Failed(), 0, 1, "postgres"))
    monkeypatch.setattr(replay, "record_raw_batch_import_outcome_pg", lambda **kwargs: calls.append(str(kwargs["outcome"])))
    monkeypatch.setattr(replay, "update_collection_state_from_summary_pg", lambda **_: pytest.fail("cursor reached"))
    monkeypatch.setattr(replay, "record_collector_channel_runs_pg", lambda **_: pytest.fail("history reached"))

    with pytest.raises(RuntimeError, match="retained_batch_import_failed:23"):
        replay.apply_prepared(prepared)
    assert calls == ["revalidate", "import", "failed"]
    assert batch.exists()


def test_cursor_not_committed_keeps_raw_and_does_not_claim_history(monkeypatch, tmp_path):
    from scripts.maintenance import replay_retained_dc_batch as replay

    batch = _batch(tmp_path)
    prepared = replay.PreparedBatch(batch, "DC1", "job-2-DC1", None, "example.test", "example.test", "python", _summary(), "b" * 64, "a" * 64, "replay-retained-dc-batch:" + "a" * 64)
    class Completed:
        returncode = 0
        stdout = ""
    monkeypatch.setattr(replay, "held_collection_locks", lambda: __import__("contextlib").nullcontext(None))
    monkeypatch.setattr(replay, "revalidate_prepared", lambda _: None)
    monkeypatch.setattr(replay, "run_import_for_backend", lambda **_: (Completed(), 0, 1, "postgres"))
    monkeypatch.setattr(replay, "record_raw_batch_import_outcome_pg", lambda **_: None)
    monkeypatch.setattr(replay, "update_collection_state_from_summary_pg", lambda **_: None)
    monkeypatch.setattr(replay, "record_raw_batch_cursor_outcome_pg", lambda **_: {"cursor_outcome": "not_committed", "committed_channels": 0})
    monkeypatch.setattr(replay, "record_collector_channel_runs_pg", lambda **_: pytest.fail("history reached"))

    with pytest.raises(RuntimeError, match="retained_batch_cursor_pending"):
        replay.apply_prepared(prepared)
    assert batch.exists()
