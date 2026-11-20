from __future__ import annotations

import importlib

import pytest

from scripts.maintenance.run_semantic_calibration_window import (
    _assert_runtime_safe,
)


def _snapshot(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "runtime_marker": 49,
        "risk_errors": 0,
        "risk_open_jobs": 0,
        "semantic_worker_heartbeats": 1,
        "semantic_worker_live": False,
        "shadow_results": 0,
    }
    result.update(overrides)
    return result


def test_calibration_allows_a_stale_semantic_heartbeat_record() -> None:
    _assert_runtime_safe(_snapshot())


def test_calibration_refuses_a_live_semantic_worker() -> None:
    with pytest.raises(RuntimeError, match="must not be live"):
        _assert_runtime_safe(_snapshot(semantic_worker_live=True))


@pytest.mark.parametrize("module_name", [
    "scripts.runtime.semantic_worker",
    "scripts.runtime.semantic_production_worker",
    "scripts.maintenance.run_semantic_shadow_once",
    "scripts.maintenance.run_semantic_calibration_window",
    "scripts.maintenance.semantic_production_control",
])
def test_semantic_hydration_uses_manifest_without_filesystem_configuration(module_name, monkeypatch, tmp_path):
    from server.sli.storage.storage_v2_archive import ArchivePublisher, InMemoryArchiveManifestStore
    from server.sli.storage.storage_v2_config import StorageV2ConfigurationError

    monkeypatch.setenv("ADLOG_STORAGE_READ_MODE", "v2")
    monkeypatch.setenv("ADLOG_STORAGE_WRITE_MODE", "v2")
    module = importlib.import_module(module_name)
    manifest = InMemoryArchiveManifestStore()
    ArchivePublisher(tmp_path.resolve(), manifest).publish_rows(
        archive_set_id="00000000-0000-4000-8000-000000000001", archive_kind="event", block_index=0,
        rows=[{"id": 1, "event_id": 4624}],
    )
    monkeypatch.setattr(module, "PostgresArchiveManifestStore", lambda _connect: manifest)
    assert module._archive_reader().read_event(archive_kind="event", event_id=1) == {"id": 1, "event_id": 4624}
    monkeypatch.setenv("ADLOG_STORAGE_WRITE_MODE", "invalid")
    with pytest.raises(StorageV2ConfigurationError):
        module._archive_reader()
