from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest


def _config(module, root: Path):
    return module.SnapshotConfig(
        directory_server="DC2",
        domain="host13.example.invalid",
        search_base="DC=example,DC=local",
        privileged_group_sids=(
            "S-1-5-21-100000003-200000003-300000003-512",
            "S-1-5-21-100000003-200000003-300000003-518",
        ),
        vpn_group_references=("S-1-5-21-100000003-200000003-300000003-1701",),
        technical_servers=("DC1", "DC2"),
        output_root=root,
    )


def _bundle(section: str) -> dict:
    return {
        "run_id": f"00000000-0000-4000-8000-{len(section):012d}",
        "sections": [{
            "name": section,
            "status": "complete",
            "record_count": 3,
            "duration_ms": 20,
        }],
    }


@pytest.mark.windows_only
def test_section_requests_cover_one_unified_reconcile_cycle(monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    monkeypatch.setattr(module, "DEFAULT_OUTPUT_ROOT", tmp_path)
    config = module._validate_config(_config(module, tmp_path))
    executable = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")

    requests = {
        section: module._section_request(
            config,
            section=section,
            run_id="00000000-0000-4000-8000-000000000001",
            bundle_path=tmp_path / f"{section}.json",
            powershell=executable,
        )
        for section in module.SECTIONS
    }

    assert tuple(requests) == (
        "privileged_membership",
        "directory_accounts",
        "directory_group_graph",
        "vpn_membership",
        "gpo_governance",
        "domain_posture",
    )
    assert all(request.mode == "reconcile" for request in requests.values())
    assert requests["privileged_membership"].privileged_groups == config.privileged_group_sids
    assert requests["vpn_membership"].vpn_groups == config.vpn_group_references
    assert not requests["directory_accounts"].privileged_groups
    assert requests["directory_accounts"].technical_servers == ("DC1", "DC2")
    assert not requests["vpn_membership"].technical_servers
    assert not requests["gpo_governance"].vpn_groups
    posture_command = module.build_ad_context_command(requests["domain_posture"])
    assert posture_command[posture_command.index("-CollectionProfile") + 1] == "domain_posture_v1"

    deep = module._section_request(
        config,
        section="domain_health",
        run_id="00000000-0000-4000-8000-000000000002",
        bundle_path=tmp_path / "domain_health.json",
        powershell=executable,
    )
    deep_command = module.build_ad_context_command(deep)
    assert deep_command[deep_command.index("-CollectionProfile") + 1] == "domain_health_v1"


def test_collect_section_hides_windows_child_console(monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    no_window = 0x08000000
    calls: list[dict[str, object]] = []
    waits: list[int] = []
    bundle = {"synthetic": True}

    class Process:
        def wait(self, timeout):
            waits.append(timeout)
            return 0

    def launch(*_args, **kwargs):
        calls.append(kwargs)
        return Process()

    config = _config(module, tmp_path)
    monkeypatch.setattr(module, "os", SimpleNamespace(**{**vars(module.os), "name": "nt"}))
    monkeypatch.setattr(module.subprocess, "CREATE_NO_WINDOW", no_window, raising=False)
    monkeypatch.setattr(module.subprocess, "Popen", launch)
    monkeypatch.setattr(module, "build_ad_context_command", lambda _request: ["collector"])
    monkeypatch.setattr(module, "load_bundle", lambda _path: bundle)
    monkeypatch.setattr(module, "_validate_collected_bundle", lambda *_args, **_kwargs: None)

    observed_bundle, _path = module._collect_section(
        config,
        section="directory_accounts",
        cycle_dir=tmp_path,
        powershell=Path("powershell.exe"),
    )

    assert observed_bundle is bundle
    assert waits == [config.timeout_seconds]
    assert calls[0]["creationflags"] & no_window


@pytest.mark.parametrize("field", ["privileged_group_sids", "vpn_group_references"])
def test_group_reference_limit_is_fifty(field, monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    monkeypatch.setattr(module, "DEFAULT_OUTPUT_ROOT", tmp_path)
    values = tuple(f"S-1-5-21-111-222-333-{1000 + index}" for index in range(50))
    config = replace(_config(module, tmp_path), **{field: values})
    assert len(getattr(module._validate_config(config), field)) == 50

    oversized = replace(config, **{field: (*values, "S-1-5-21-100000003-200000003-300000003-2000")})
    with pytest.raises(ValueError, match="one to fifty"):
        module._validate_config(oversized)


def test_cycle_collects_all_sections_then_imports_once(monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    monkeypatch.setattr(module, "DEFAULT_OUTPUT_ROOT", tmp_path)
    config = _config(module, tmp_path)
    collected: list[str] = []
    imported: list[list[dict]] = []
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})

    def collect(_config, *, section, cycle_dir, powershell):
        collected.append(section)
        path = cycle_dir / f"{section}.json"
        path.write_text("{}", encoding="utf-8")
        return _bundle(section), path

    def import_cycle(bundles):
        imported.append(list(bundles))
        return [{"replayed": 0} for _ in bundles]

    monkeypatch.setattr(module, "_collect_section", collect)
    monkeypatch.setattr(module, "_import_cycle", import_cycle)

    result = module.run_cycle(
        config,
        worker_id="worker-test",
        started_at=datetime.now(timezone.utc),
        powershell=Path("powershell.exe"),
    )

    assert collected == list(module.SECTIONS)
    assert len(imported) == 1
    assert [item["sections"][0]["name"] for item in imported[0]] == list(module.SECTIONS)
    assert result["status"] == "idle"
    assert not any(tmp_path.iterdir())


def test_cycle_failure_does_not_import_partial_snapshot(monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    monkeypatch.setattr(module, "DEFAULT_OUTPUT_ROOT", tmp_path)
    config = _config(module, tmp_path)
    imported = False
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})

    def collect(_config, *, section, cycle_dir, powershell):
        if section == "vpn_membership":
            raise RuntimeError("vpn failed")
        return _bundle(section), cycle_dir / f"{section}.json"

    def import_cycle(_bundles):
        nonlocal imported
        imported = True
        return []

    monkeypatch.setattr(module, "_collect_section", collect)
    monkeypatch.setattr(module, "_import_cycle", import_cycle)

    with pytest.raises(RuntimeError, match="vpn failed"):
        module.run_cycle(
            config,
            worker_id="worker-test",
            started_at=datetime.now(timezone.utc),
            powershell=Path("powershell.exe"),
        )

    assert imported is False
    assert len(list(tmp_path.iterdir())) == 1


def test_deep_health_cycle_is_separate_from_light_snapshot(monkeypatch, tmp_path) -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    monkeypatch.setattr(module, "DEFAULT_OUTPUT_ROOT", tmp_path)
    monkeypatch.setattr(module, "record_worker_heartbeat", lambda **_kwargs: {"status": "ok"})
    collected: list[str] = []
    imported: list[list[dict]] = []

    def collect(_config, *, section, cycle_dir, powershell):
        collected.append(section)
        path = cycle_dir / f"{section}.json"
        path.write_text("{}", encoding="utf-8")
        return _bundle(section), path

    monkeypatch.setattr(module, "_collect_section", collect)
    monkeypatch.setattr(module, "_import_cycle", lambda bundles: imported.append(list(bundles)) or [{"replayed": 0}])

    result = module.run_cycle(
        _config(module, tmp_path),
        worker_id="worker-test",
        started_at=datetime.now(timezone.utc),
        powershell=Path("powershell.exe"),
        sections=module.DEEP_SECTIONS,
    )

    assert collected == ["domain_health"]
    assert [item["sections"][0]["name"] for item in imported[0]] == ["domain_health"]
    assert result["status"] == "idle"


def test_deep_health_is_due_initially_and_then_every_six_hours() -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    assert module._deep_cycle_due(None, now_monotonic=100.0, interval_seconds=21600) is True
    assert module._deep_cycle_due(100.0, now_monotonic=21699.9, interval_seconds=21600) is False
    assert module._deep_cycle_due(100.0, now_monotonic=21700.0, interval_seconds=21600) is True


def test_manifest_slot_boundary_is_pure_and_uses_utc_half_days() -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    assert module.MANIFEST_COORDINATOR_INTERVAL_SECONDS == 43200
    assert module.manifest_slot_start_utc(
        datetime(2026, 8, 31, 11, 59, 59, tzinfo=timezone.utc)
    ) == "2026-08-31T00:00:00Z"
    assert module.manifest_slot_start_utc(
        datetime(2026, 8, 31, 12, 0, 0, tzinfo=timezone.utc)
    ) == "2026-08-31T12:00:00Z"
    with pytest.raises(ValueError, match="timezone"):
        module.manifest_slot_start_utc(datetime(2026, 8, 31, 12, 0, 0))


def test_dormant_source_only_coordinator_does_not_publish_hard_failed_base() -> None:
    from scripts.runtime import ad_context_snapshot_worker as module

    published: list[dict] = []
    result = module.coordinate_manifest_source_only(
        slot_start_utc="2026-08-31T12:00:00Z",
        source_members=[
            {"family": "ad_context", "source_state": "complete"},
            {"family": "computers_v6", "source_state": "failed"},
            {"family": "gpo_v2", "source_state": "partial"},
        ],
        publish=lambda candidate: published.append(candidate),
    )

    assert result == {"status": "blocked", "reason": "base_source_failed"}
    assert published == []


def test_supervisor_refuses_unconfigured_coordinator_without_starting(monkeypatch) -> None:
    from scripts.maintenance import worker_supervisor as module

    for name in (
        "ADLOG_AD_CONTEXT_DIRECTORY_SERVER",
        "ADLOG_AD_CONTEXT_DOMAIN",
        "ADLOG_AD_CONTEXT_SEARCH_BASE",
        "ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS",
        "ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES",
        "ADLOG_COLLECTION_PREFLIGHT_SERVER",
    ):
        monkeypatch.delenv(name, raising=False)

    result = module._start("ad_snapshot_manifest_coordinator")

    assert result["started"] is False
    assert result["reason"] == "ad_snapshot_manifest_coordinator_configuration_missing"
    assert result["missing"] == [
        "directory_server",
        "domain",
        "privileged_group_sids",
        "search_base",
        "vpn_group_references",
    ]
