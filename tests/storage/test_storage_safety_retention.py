from __future__ import annotations

import json
import os
import time
from pathlib import Path

from server.sli.storage.storage_policy import (
    StoragePolicy,
    _project_scan_warning,
    apply_pytest_run_cleanup_plan,
    apply_storage_cleanup_plan,
    build_pytest_run_cleanup_plan,
    build_storage_cleanup_plan,
    can_start_collection,
    disk_pressure_status,
    get_storage_health,
)


def test_disk_pressure_guard_blocks_low_free(monkeypatch):
    class Usage:
        total = 100
        used = 94
        free = 6

    monkeypatch.setattr("server.sli.storage.storage_policy.shutil.disk_usage", lambda path: Usage())
    result = disk_pressure_status(
        Path("."),
        StoragePolicy(
            min_free_disk_percent=15,
            stop_collection_if_free_disk_percent_below=10,
            stop_collection_if_free_disk_bytes_below=10,
            critical_free_disk_percent=5,
        ),
    )
    assert result["status"] == "blocked"
    assert result["collection_allowed"] is False
    assert result["blocking_threshold"]["mode"] == "free_bytes_or_percent"


def test_incomplete_project_scan_is_never_reported_as_clean() -> None:
    assert _project_scan_warning({
        "scan": {"complete_project_tree": False, "errors": 5},
    }) == "полный обход проекта неполон: ошибок чтения 5"
    assert _project_scan_warning({
        "scan": {"complete_project_tree": True, "errors": 0},
    }) is None


def test_collection_blocks_when_free_percent_is_below_stop_despite_byte_reserve(monkeypatch):
    class Usage:
        total = 500 * 1024**3
        free = int(45.86 * 1024**3)
        used = total - free

    monkeypatch.setattr(
        "server.sli.storage.storage_policy.shutil.disk_usage", lambda path: Usage()
    )

    result = can_start_collection(Path("."), StoragePolicy())

    assert result["status"] == "blocked"
    assert result["collection_allowed"] is False
    assert result["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert result["blocking_threshold"]["condition"] == "free_percent_below_stop"
    assert result["blocking_threshold"]["free_bytes"] == 10 * 1024**3


def test_collection_blocks_below_10_gib_even_when_percentage_is_healthy(monkeypatch):
    class Usage:
        total = 80 * 1024**3
        free = 9 * 1024**3
        used = total - free

    monkeypatch.setattr(
        "server.sli.storage.storage_policy.shutil.disk_usage", lambda path: Usage()
    )

    result = can_start_collection(Path("."), StoragePolicy())

    assert result["status"] == "blocked"
    assert result["collection_allowed"] is False
    assert result["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert result["blocking_threshold"]["condition"] == "free_bytes_below_stop"


def test_collection_warns_only_between_stop_and_warning_thresholds(monkeypatch):
    class Usage:
        total = 100 * 1024**3
        free = 12 * 1024**3
        used = total - free

    monkeypatch.setattr(
        "server.sli.storage.storage_policy.shutil.disk_usage", lambda path: Usage()
    )

    result = can_start_collection(Path("."), StoragePolicy())

    assert result["status"] == "warn"
    assert result["collection_allowed"] is True
    assert result["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert result["blocking_threshold"]["condition"] == "warning_only"


def test_collection_allows_comfortable_byte_and_percentage_reserve(monkeypatch):
    class Usage:
        total = 200 * 1024**3
        free = 50 * 1024**3
        used = total - free

    monkeypatch.setattr(
        "server.sli.storage.storage_policy.shutil.disk_usage", lambda path: Usage()
    )

    result = can_start_collection(Path("."), StoragePolicy())

    assert result["status"] == "ok"
    assert result["collection_allowed"] is True
    assert result["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert result["blocking_threshold"]["condition"] == "none"


def test_storage_cleanup_dry_run_keeps_age_only_raw_without_import_proof(tmp_path, monkeypatch):
    project = tmp_path
    raw = project / "data" / "raw"
    raw.mkdir(parents=True)
    old = raw / "old.jsonl"
    old.write_text("{}\n", encoding="utf-8")
    old_time = time.time() - 5 * 86400
    os.utime(old, (old_time, old_time))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", project / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", project)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", project / "data" / "logs")
    monkeypatch.setattr("server.sli.storage.storage_policy.RAW_ARCHIVE_DIR", project / "data" / "raw_archive")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    monkeypatch.setattr("server.sli.storage.storage_policy.active_backend", lambda: "postgres")
    plan = build_storage_cleanup_plan(limit=10)
    result = apply_storage_cleanup_plan(plan, apply=False)
    assert result["mode"] == "dry-run"
    assert old.exists()
    assert result["total_candidates"] == 0
    excluded = result["scan"]["raw"]["excluded"]
    assert excluded.get("not_confirmed_imported", 0) + excluded.get("import_confirmation_unavailable", 0) == 1
    assert result["safety"]["raw_requires_confirmed_postgres_import"] is True


def test_storage_cleanup_preserves_failed_and_evidence_raw(tmp_path, monkeypatch):
    project = tmp_path
    raw = project / "data" / "raw"
    raw.mkdir(parents=True)
    for name in ("failed_job.jsonl", "evidence_candidate.jsonl"):
        f = raw / name
        f.write_text("{}\n", encoding="utf-8")
        old_time = time.time() - 5 * 86400
        os.utime(f, (old_time, old_time))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", project / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", project)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", project / "data" / "logs")
    monkeypatch.setattr("server.sli.storage.storage_policy.RAW_ARCHIVE_DIR", project / "data" / "raw_archive")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    plan = build_storage_cleanup_plan(limit=10)
    assert plan["total_candidates"] == 0
    assert plan["scan"]["raw"]["excluded"]["protected"] == 2


def test_storage_cleanup_apply_requires_confirm(tmp_path, monkeypatch):
    from server.sli.storage import storage_policy

    production_state = storage_policy.STORAGE_CLEANUP_LAST
    production_before = (
        production_state.read_bytes() if production_state.is_file() else None
    )
    project = tmp_path
    raw = project / "data" / "raw"
    raw.mkdir(parents=True)
    old = raw / "old.jsonl"
    old.write_text("{}\n", encoding="utf-8")
    old_time = time.time() - 5 * 86400
    os.utime(old, (old_time, old_time))
    monkeypatch.setattr("server.sli.storage.storage_policy.DATA_DIR", project / "data")
    monkeypatch.setattr("server.sli.storage.storage_policy.ROOT", project)
    monkeypatch.setattr("server.sli.storage.storage_policy.LOG_DIR", project / "data" / "logs")
    monkeypatch.setattr("server.sli.storage.storage_policy.RAW_ARCHIVE_DIR", project / "data" / "raw_archive")
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    plan = build_storage_cleanup_plan(limit=10)
    result = apply_storage_cleanup_plan(plan, apply=True, confirm_apply=False)
    assert result["status"] == "failed"
    assert old.exists()
    test_state = project / "data" / "maintenance" / "storage_cleanup_last.json"
    assert test_state.is_file()
    production_after = (
        production_state.read_bytes() if production_state.is_file() else None
    )
    assert production_after == production_before


def test_storage_health_contains_capacity_and_policy(monkeypatch):
    monkeypatch.setenv("ADLOG_RAW_RETENTION_DAYS", "2")
    data = get_storage_health()
    assert "policy" in data
    assert data["policy"]["raw_retention_days"] == 2
    assert "capacity_plan" in data
    assert "disk_pressure" in data


def _generated_pytest_run(root: Path, name: str, *, age_hours: float) -> Path:
    run = root / name
    run.mkdir(parents=True)
    payload = run / "events.sqlite"
    payload.write_bytes(b"pytest-only")
    old_time = time.time() - age_hours * 3600
    os.utime(payload, (old_time, old_time))
    os.utime(run, (old_time, old_time))
    return run


def test_pytest_cleanup_plan_is_exact_bounded_and_preserves_recent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from server.sli.storage import storage_policy

    root = tmp_path / "data" / "tmp" / "pytest-runs"
    old = _generated_pytest_run(
        root,
        "full-20260729-120000-1234-abcdef12",
        age_hours=30,
    )
    recent = _generated_pytest_run(
        root,
        "quick-20260730-090000-5678-1234abcd",
        age_hours=2,
    )
    invalid = _generated_pytest_run(root, "manual-folder", age_hours=50)
    monkeypatch.setattr(storage_policy, "PYTEST_RUNS_DIR", root)

    plan = build_pytest_run_cleanup_plan(min_age_hours=24, limit=10)

    assert plan["root"] == str(root.resolve())
    assert plan["total_candidates"] == 1
    assert plan["actions"][0]["path"] == str(old.resolve())
    assert plan["scan"]["excluded"] == {"recent": 1, "invalid_name": 1}
    assert recent.exists()
    assert invalid.exists()


def test_pytest_cleanup_plan_preserves_active_marker(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from server.sli.storage import storage_policy

    root = tmp_path / "data" / "tmp" / "pytest-runs"
    active = _generated_pytest_run(
        root,
        "full-20260729-120000-1234-abcdef12",
        age_hours=30,
    )
    marker = root / f".active-{active.name}.json"
    marker.write_text('{"pid": 1234}\n', encoding="utf-8")
    monkeypatch.setattr(storage_policy, "PYTEST_RUNS_DIR", root)

    plan = build_pytest_run_cleanup_plan(min_age_hours=24, limit=10)

    assert plan["total_candidates"] == 0
    assert plan["scan"]["excluded"] == {"active_marker": 1}
    assert active.exists()
    assert marker.exists()


def test_pytest_cleanup_plan_rejects_top_level_link_like_directory(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from server.sli.storage import storage_policy

    root = tmp_path / "data" / "tmp" / "pytest-runs"
    linked = _generated_pytest_run(
        root,
        "full-20260729-120000-1234-abcdef12",
        age_hours=30,
    )
    monkeypatch.setattr(storage_policy, "PYTEST_RUNS_DIR", root)
    monkeypatch.setattr(
        storage_policy,
        "_path_is_link_like",
        lambda path: path == linked,
    )

    plan = build_pytest_run_cleanup_plan(min_age_hours=24, limit=10)

    assert plan["total_candidates"] == 0
    assert plan["scan"]["excluded"] == {"top_level_link": 1}
    assert linked.exists()


def test_pytest_cleanup_apply_requires_confirmation_and_deletes_only_candidate(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from server.sli.storage import storage_policy

    root = tmp_path / "data" / "tmp" / "pytest-runs"
    old = _generated_pytest_run(
        root,
        "full-20260729-120000-1234-abcdef12",
        age_hours=30,
    )
    sibling = tmp_path / "data" / "tmp" / "keep.txt"
    sibling.parent.mkdir(parents=True, exist_ok=True)
    sibling.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(storage_policy, "PYTEST_RUNS_DIR", root)
    plan = build_pytest_run_cleanup_plan(min_age_hours=24, limit=10)

    refused = apply_pytest_run_cleanup_plan(
        plan,
        apply=True,
        confirm_apply=False,
    )
    assert refused["status"] == "failed"
    assert old.exists()

    applied = apply_pytest_run_cleanup_plan(
        plan,
        apply=True,
        confirm_apply=True,
    )
    assert applied["status"] == "ok"
    assert applied["applied_count"] == 1
    assert not old.exists()
    assert sibling.read_text(encoding="utf-8") == "keep"
