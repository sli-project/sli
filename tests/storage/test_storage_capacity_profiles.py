from __future__ import annotations

from datetime import datetime, timedelta, timezone


GiB = 1024**3


def _snapshot(at: datetime, total_gib: int, *, disk_free_gib: int = 200, disk_total_gib: int = 500) -> dict[str, object]:
    return {
        "captured_at": at,
        "database_bytes": total_gib * GiB,
        "raw_bytes": 0,
        "raw_archive_bytes": 0,
        "backups_bytes": 0,
        "logs_bytes": 0,
        "reports_bytes": 0,
        "artifacts_bytes": 0,
        "disk_free_bytes": disk_free_gib * GiB,
        "disk_total_bytes": disk_total_gib * GiB,
    }


def test_profiles_resolve_deterministically_and_show_explicit_overrides() -> None:
    from server.sli.storage.storage_policy import StoragePolicy, resolve_storage_capacity_profile

    base = StoragePolicy(raw_archive_enabled=True, warm_retention_days=365)
    economy = resolve_storage_capacity_profile("economy", base_policy=base)
    extended = resolve_storage_capacity_profile(
        "extended",
        base_policy=base,
        overrides={"raw_retention_days": 5},
    )

    assert economy["selected_profile"] == "economy"
    assert economy["effective_policy"]["raw_archive_enabled"] is False
    assert economy["effective_policy"]["raw_retention_days"] == 2
    assert extended["selected_profile"] == "extended"
    assert extended["effective_policy"]["raw_retention_days"] == 5
    assert extended["overrides"] == {"raw_retention_days": 5}


def test_relationship_horizon_is_a_distinct_30_day_storage_policy_contract() -> None:
    from server.sli.storage.storage_policy import StoragePolicy

    policy = StoragePolicy(warm_retention_days=365, post_collection_retention_days=14)

    assert policy.relationship_retention_days == 30


def test_load_storage_policy_uses_admin_selected_profile_without_auto_selection() -> None:
    from server.sli.core.app_config import AdLogConfig
    from server.sli.storage.storage_policy import get_storage_capacity_profile_resolution, load_storage_policy

    config = AdLogConfig(
        reports_dir="data/reports",
        log_dir="data/logs",
        storage_capacity_profile="economy",
    )

    assert load_storage_policy(config).raw_archive_enabled is False
    resolution = get_storage_capacity_profile_resolution(config)
    assert resolution["selected_profile"] == "economy"
    assert resolution["overrides"] == {}


def test_realistic_profile_config_keeps_economy_defaults_until_explicit_override(
    tmp_path, monkeypatch
) -> None:
    from server.sli.core.app_config import load_config
    from server.sli.storage.storage_policy import get_storage_capacity_profile_resolution, load_storage_policy

    for name in (
        "ADLOG_STORAGE_CAPACITY_PROFILE",
        "ADLOG_STORAGE_CAPACITY_PROFILE_OVERRIDES",
        "ADLOG_RAW_ARCHIVE_ENABLED",
        "ADLOG_RAW_RETENTION_DAYS",
    ):
        monkeypatch.delenv(name, raising=False)
    config_path = tmp_path / "adlog_config.yaml"
    config_path.write_text(
        """
retention:
  storage_capacity_profile: economy
  raw_retention_days: 14
  raw_archive_enabled: true
  raw_archive_compress: true
  db_retention_days: 7
  warm_retention_days: 365
  min_free_disk_percent: 15
  stop_collection_if_free_disk_percent_below: 10
  stop_collection_if_free_disk_bytes_below: 10737418240
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)

    assert load_storage_policy(config).raw_archive_enabled is False
    assert get_storage_capacity_profile_resolution(config)["overrides"] == {}

    config_path.write_text(
        config_path.read_text(encoding="utf-8")
        + "\n  storage_capacity_profile_overrides: raw_archive_enabled\n",
        encoding="utf-8",
    )
    explicit = get_storage_capacity_profile_resolution(load_config(config_path))
    assert explicit["effective_policy"]["raw_archive_enabled"] is True
    assert explicit["overrides"] == {"raw_archive_enabled": True}


def test_recommendation_requires_consecutive_positive_growth_and_never_changes_selection() -> None:
    from server.sli.storage.storage_policy import StoragePolicy, recommend_storage_capacity_profile

    now = datetime(2026, 8, 10, tzinfo=timezone.utc)
    policy = StoragePolicy(db_retention_days=7, raw_retention_days=2, warm_retention_days=30)
    insufficient = recommend_storage_capacity_profile(
        [_snapshot(now - timedelta(days=2), 100), _snapshot(now - timedelta(days=1), 90)],
        selected_profile="extended",
        effective_policy=policy,
    )
    valid = recommend_storage_capacity_profile(
        [_snapshot(now - timedelta(days=2), 100), _snapshot(now - timedelta(days=1), 101), _snapshot(now, 102)],
        selected_profile="economy",
        effective_policy=policy,
    )

    assert insufficient["recommended_profile"] == "economy"
    assert insufficient["reason"] == "insufficient_growth_evidence"
    assert insufficient["selected_profile"] == "extended"
    assert valid["selected_profile"] == "economy"
    assert valid["recommendation_changes_selection"] is False
    assert valid["growth_bytes_per_day"] == GiB
    assert valid["reason"] == "extended_capacity_sufficient"


def test_disk_guard_blocks_on_either_stop_threshold_and_warns_above_them(monkeypatch, tmp_path) -> None:
    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    policy = StoragePolicy(
        min_free_disk_percent=15,
        stop_collection_if_free_disk_percent_below=10,
        stop_collection_if_free_disk_bytes_below=10 * GiB,
    )
    monkeypatch.setattr(module, "disk_info", lambda _path: {"total_bytes": 500 * GiB, "free_bytes": 50 * GiB, "free_percent": 9.0})
    percent_block = module.disk_pressure_status(tmp_path, policy)
    monkeypatch.setattr(module, "disk_info", lambda _path: {"total_bytes": 500 * GiB, "free_bytes": 5 * GiB, "free_percent": 20.0})
    bytes_block = module.disk_pressure_status(tmp_path, policy)
    monkeypatch.setattr(module, "disk_info", lambda _path: {"total_bytes": 500 * GiB, "free_bytes": 60 * GiB, "free_percent": 12.0})
    warning = module.disk_pressure_status(tmp_path, policy)

    assert percent_block["status"] == "blocked"
    assert percent_block["collection_allowed"] is False
    assert percent_block["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert percent_block["blocking_threshold"]["condition"] == "free_percent_below_stop"
    assert bytes_block["collection_allowed"] is False
    assert bytes_block["blocking_threshold"]["mode"] == "free_bytes_or_percent"
    assert bytes_block["blocking_threshold"]["condition"] == "free_bytes_below_stop"
    assert warning["status"] == "warn"
    assert warning["collection_allowed"] is True


def test_runtime_capacity_evidence_measures_72h_growth_and_forecasts_stop(monkeypatch, tmp_path) -> None:
    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    policy = StoragePolicy(
        stop_collection_if_free_disk_percent_below=10,
        stop_collection_if_free_disk_bytes_below=10 * GiB,
    )
    monkeypatch.setattr(module, "disk_info", lambda _path: {
        "total_bytes": 500 * GiB,
        "used_bytes": 410 * GiB,
        "free_bytes": 90 * GiB,
        "free_percent": 18.0,
    })
    baseline = _snapshot(now - timedelta(hours=72), 100, disk_free_gib=120)
    baseline["disk_used_bytes"] = 380 * GiB
    current = _snapshot(now, 106, disk_free_gib=90)
    current["disk_used_bytes"] = 410 * GiB

    evidence = module.get_storage_runtime_capacity_evidence(
        snapshots=[baseline, current], now_utc=now, path=tmp_path, policy=policy,
    )

    assert evidence["status"] == "ok"
    assert evidence["disk_free_bytes"] == 90 * GiB
    assert evidence["disk_free_percent"] == 18.0
    assert evidence["stop_threshold"]["effective_reserve_bytes"] == 50 * GiB
    assert evidence["measured_growth"]["quality"] == "measured_72h"
    assert evidence["measured_growth"]["database_bytes_per_day"] == 2 * GiB
    assert evidence["measured_growth"]["disk_used_bytes_per_day"] == 10 * GiB
    assert evidence["forecast"]["status"] == "ok"
    assert evidence["forecast"]["estimated_days_to_stop"] == 4.0


def test_runtime_capacity_evidence_is_unknown_without_72h_baseline(monkeypatch, tmp_path) -> None:
    from server.sli.storage import storage_policy as module

    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    monkeypatch.setattr(module, "disk_info", lambda _path: {
        "total_bytes": 500 * GiB,
        "used_bytes": 400 * GiB,
        "free_bytes": 100 * GiB,
        "free_percent": 20.0,
    })

    evidence = module.get_storage_runtime_capacity_evidence(
        snapshots=[_snapshot(now - timedelta(hours=24), 100), _snapshot(now, 101)],
        now_utc=now,
        path=tmp_path,
    )

    assert evidence["status"] == "unknown"
    assert evidence["measured_growth"]["quality"] == "unknown"
    assert evidence["forecast"]["status"] == "unknown"


def test_runtime_capacity_evidence_reports_or_stop_threshold_already_reached(monkeypatch, tmp_path) -> None:
    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    now = datetime(2026, 9, 3, tzinfo=timezone.utc)
    policy = StoragePolicy(
        stop_collection_if_free_disk_percent_below=10,
        stop_collection_if_free_disk_bytes_below=10 * GiB,
    )
    monkeypatch.setattr(module, "disk_info", lambda _path: {
        "total_bytes": 500 * GiB,
        "used_bytes": 450 * GiB,
        "free_bytes": 50 * GiB,
        "free_percent": 9.0,
    })
    baseline = _snapshot(now - timedelta(hours=72), 100)
    baseline["disk_used_bytes"] = 440 * GiB
    current = _snapshot(now, 101)
    current["disk_used_bytes"] = 450 * GiB

    evidence = module.get_storage_runtime_capacity_evidence(
        snapshots=[baseline, current], now_utc=now, path=tmp_path, policy=policy,
    )

    assert evidence["status"] == "already_at_or_below_stop"
    assert evidence["stop_threshold"]["condition"] == "free_percent_below_stop"
    assert evidence["forecast"] == {
        "status": "already_at_or_below_stop",
        "estimated_days_to_stop": 0.0,
    }


def test_economy_raw_lifecycle_deletes_confirmed_imported_raw_without_archive(tmp_path, monkeypatch) -> None:
    import os
    import time

    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    source = raw / "old.jsonl"
    source.write_text("{}\n", encoding="utf-8")
    old = time.time() - 5 * 86400
    os.utime(source, (old, old))
    monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", tmp_path / "data" / "raw_archive")
    monkeypatch.setattr(module, "active_backend", lambda: "postgres")
    monkeypatch.setattr(module, "_confirmed_imported_raw_paths", lambda _paths: ({str(source)}, {"status": "ok"}))

    actions, _scan = module._build_raw_actions(StoragePolicy(raw_retention_days=2, raw_archive_enabled=False), limit=10, deep=False)

    assert [(item["action"], item["path"]) for item in actions] == [("delete_file", str(source))]


def test_economy_raw_cleanup_reuses_existing_plan_and_apply_and_preserves_protected(tmp_path, monkeypatch) -> None:
    import os
    import time

    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    raw = tmp_path / "data" / "raw"
    raw.mkdir(parents=True)
    imported = raw / "imported-old.jsonl"
    protected = raw / "evidence-old.jsonl"
    for path in (imported, protected):
        path.write_text("{}\n", encoding="utf-8")
        old = time.time() - 5 * 86400
        os.utime(path, (old, old))
    monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", tmp_path / "data" / "raw_archive")
    monkeypatch.setattr(module, "LOG_DIR", tmp_path / "data" / "logs")
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "STORAGE_CLEANUP_LAST", tmp_path / "data" / "maintenance" / "last.json")
    monkeypatch.setattr(module, "active_backend", lambda: "postgres")
    monkeypatch.setattr(module, "_confirmed_imported_raw_paths", lambda _paths: ({str(imported)}, {"status": "ok"}))

    plan = module.build_storage_cleanup_plan(
        policy=StoragePolicy(raw_retention_days=2, raw_archive_enabled=False), limit=10,
    )
    applied = module.apply_storage_cleanup_plan(plan, apply=True, confirm_apply=True)

    assert [(item["action"], item["path"]) for item in plan["actions"]] == [("delete_file", str(imported))]
    assert applied["status"] == "ok"
    assert not imported.exists()
    assert protected.exists()


def test_extended_raw_archive_has_a_bounded_cleanup_plan(tmp_path, monkeypatch) -> None:
    import os
    import time

    from server.sli.storage import storage_policy as module
    from server.sli.storage.storage_policy import StoragePolicy

    archive = tmp_path / "data" / "raw_archive"
    archive.mkdir(parents=True)
    archived = archive / "old.zip"
    archived.write_bytes(b"archive")
    old = time.time() - 40 * 86400
    os.utime(archived, (old, old))
    monkeypatch.setattr(module, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(module, "RAW_ARCHIVE_DIR", archive)
    monkeypatch.setattr(module, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(module, "ROOT", tmp_path)

    plan = module.build_storage_cleanup_plan(
        policy=StoragePolicy(raw_archive_enabled=True, warm_retention_days=30),
        limit=10,
    )

    assert any(item["category"] == "raw_archive" and item["path"] == str(archived) for item in plan["actions"])
