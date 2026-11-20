"""Legacy admission must fail before DB, Windows, process or file side effects."""
import importlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest


FLAG = "SLI_LEGACY_COLLECTION_DISABLED"


@pytest.mark.parametrize("value", [None, "0"])
def test_default_keeps_legacy_admission(value, monkeypatch):
    from server.sli.sources.legacy_collection import require_legacy_collection

    monkeypatch.delenv(FLAG, raising=False)
    if value is not None:
        monkeypatch.setenv(FLAG, value)
    require_legacy_collection()


# Each row executes the real entry point with no usable runtime dependencies.
# Removing its guard would reach argument validation, Windows or DB access.
ENTRY_POINTS = [
    ("scripts.collect.collect_windows_events", "main", (), {}),
    ("scripts.collect.collect_windows_events", "open_remote_session", ("synthetic",), {}),
    ("scripts.run_dc_log_pilot", "main", (), {}),
    ("scripts.runtime.collection_worker", "main", ([],), {}),
    ("scripts.runtime.collection_worker", "run_cycle", (), {"hours": 1, "max_events": 1, "wait_seconds": 1}),
    ("scripts.runtime.ad_context_snapshot_worker", "main", ([],), {}),
    ("scripts.runtime.ad_context_snapshot_worker", "run", (None,), {"once": True}),
    ("scripts.runtime.ad_context_snapshot_worker", "run_cycle", (None,), {"worker_id": "synthetic", "started_at": None}),
    ("scripts.runtime.ad_snapshot_manifest_coordinator_worker", "main", ([],), {}),
    ("scripts.runtime.ad_snapshot_manifest_coordinator_worker", "_default_cycle", (None,), {"domain_dns": ""}),
    ("scripts.runtime.computers_v6_source_worker", "main", ([],), {}),
    ("scripts.runtime.computers_v6_source_worker", "capture_and_persist_once", (), {
        "connection_factory": None, "captured_at": None, "powershell_executable": "",
        "server": None, "search_base": None, "skip_dns": False,
        "collect_ad_site": False, "collect_exact_last_logon": False}),
    ("scripts.runtime.ad_snapshot_projection_worker", "main", ([],), {}),
    ("scripts.runtime.ad_snapshot_projection_worker", "run_once", (), {"manifest_id": ""}),
    ("scripts.runtime.users_report_v2_snapshot_worker", "main", (), {}),
    ("scripts.runtime.users_report_v2_snapshot_worker", "run_once", (), {}),
    ("scripts.runtime.computers_report_v5_snapshot_worker", "main", (), {}),
    ("scripts.runtime.computers_report_v5_snapshot_worker", "run_once", (), {}),
    ("scripts.runtime.computers_report_v6_snapshot_worker", "main", (), {}),
    ("scripts.runtime.computers_report_v6_snapshot_worker", "run_once", (), {}),
    ("scripts.runtime.remote_access_plugin_host", "main", (), {}),
    ("scripts.runtime.remote_access_plugin_host", "run_host", ("radius-session-observation",), {"once": True}),
    ("scripts.runtime.remote_access_plugin_host", "run_cycle_child", ("radius-acquisition", None), {}),
    ("server.jobs.collector", "_run_collect_job", (0,), {}),
    ("server.jobs.collector", "_run_single_server_collection", ("synthetic", 1, 1), {}),
    ("server.jobs.collector_post_collection", "_enqueue_post_collection", (0, [], "synthetic"), {}),
    ("server.jobs.collector_post_collection", "_run_post_collection_job", (0, [], "synthetic"), {}),
    ("server.jobs.collector_post_collection", "run_persisted_post_collection_worker_once", (), {"worker_id": "synthetic"}),
    ("server.jobs.collector_post_collection", "resume_persisted_post_collection_jobs", (), {}),
    ("server.sli.sources.ad_source_process", "run_ad_source_process", ([],), {
        "server": "synthetic", "cwd": None, "timeout_seconds": 1}),
    ("server.sli.sources.radius_plugin_runtime", "run_acquisition_cycle", (), {}),
    ("server.sli.sources.radius_plugin_runtime", "run_consumer_cycle", (), {}),
    ("scripts.maintenance.stage9_radius_manual_worker", "execute", (), {}),
    ("scripts.maintenance.stage9_radius_manual_worker", "main", (), {}),
    ("scripts.maintenance.stage9_radius_session_consumer_manual", "execute", (), {}),
    ("scripts.maintenance.stage9_radius_session_consumer_manual", "main", (), {}),
    ("scripts.maintenance.ad_context_live_canary", "run", (None,), {}),
    ("scripts.maintenance.ad_snapshot_manifest_canary", "main", ([],), {}),
]


@pytest.mark.parametrize("module,function,args,kwargs", ENTRY_POINTS,
                         ids=[f"{module}.{function}" for module, function, _, _ in ENTRY_POINTS])
def test_entry_point_refuses_without_runtime(module, function, args, kwargs, monkeypatch):
    from server.sli.sources.legacy_collection import LegacyCollectionDisabled

    monkeypatch.setenv(FLAG, "1")
    target = getattr(importlib.import_module(module), function)
    with pytest.raises(LegacyCollectionDisabled, match="legacy collection disabled"):
        target(*args, **kwargs)


@pytest.mark.parametrize("value", ["1", "invalid"])
def test_api_admission_refuses_before_disk_or_db(value, monkeypatch):
    from server.jobs import collector

    monkeypatch.setenv(FLAG, value)
    monkeypatch.setattr(collector, "_collection_disk_guard", lambda: pytest.fail("disk guard reached"))
    result = collector.create_collect_job()
    assert result["status"] == "blocked"
    assert result["reason"] == "legacy_collection_disabled"
    assert result["collection_allowed"] is False
    result = collector.start_scheduler()
    assert result["scheduler_enabled"] is False
    assert result["disabled_reason"] == "legacy_collection_disabled"
    assert collector._collection_block_reason() == "legacy_collection_disabled"
    monkeypatch.setenv("ADLOG_ENABLE_INPROCESS_POST_COLLECTION", "1")
    assert collector.inprocess_post_collection_opt_in_enabled() is False
    monkeypatch.setenv("ADLOG_EXTERNAL_POST_COLLECTION_WORKER", "1")
    assert collector.post_collection_worker_mode() == "disabled"


def test_windows_supervisor_does_not_spawn_legacy_worker(monkeypatch):
    from scripts.maintenance import worker_supervisor

    monkeypatch.setenv(FLAG, "1")
    monkeypatch.setattr(worker_supervisor.subprocess, "Popen", lambda *a, **k: pytest.fail("child started"))
    for worker in ("collection", "ad_snapshot_manifest_coordinator"):
        assert worker_supervisor._start(worker) == {
            "started": False, "reason": "legacy_collection_disabled"}


@pytest.mark.parametrize("script,args", [
    ("scripts/collect/Collect-DcEventsLastHour.ps1", ["-ComputerName", "synthetic"]),
    ("scripts/ad_context/Export-AdContextBundle.ps1", [
        "-OutputPath", "unused", "-RunId", "00000000-0000-4000-8000-000000000001",
        "-DirectoryServer", "synthetic", "-SearchBase", "synthetic", "-Domain", "synthetic",
        "-Sections", "synthetic", "-CollectionProfile", "privileged_membership_v1",
        "-Mode", "full", "-PrivilegedGroups", "synthetic", "-MaxRecords", "1", "-MaxBundleBytes", "1024"]),
    ("scripts/ad_context/Export-AdAuditContextBundle.ps1", [
        "-OutputPath", "unused", "-RunId", "00000000-0000-4000-8000-000000000001",
        "-DirectoryServer", "synthetic", "-SearchBase", "synthetic", "-Domain", "synthetic",
        "-Sections", "synthetic", "-CollectionProfile", "ad_snapshot_base_v1", "-Mode", "full",
        "-MaxRecords", "1", "-MaxBundleBytes", "1024", "-MaxDirectoryAccounts", "1",
        "-MaxVpnMembers", "1", "-MaxGpos", "1"]),
    ("scripts/ad_context/Export-AdGpoV2Snapshot.ps1", ["-OutputPath", "unused"]),
    ("scripts/ad_context/Export-ComputersV6ReferenceSnapshot.ps1", []),
    ("scripts/dc_client/Invoke-AdLogDcClient.ps1", []),
    ("scripts/dc_client/Register-AdLogDcClientTask.ps1", []),
])
def test_powershell_entry_refuses_before_source_access(script, args, monkeypatch):
    executable = shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell is not installed in the dev container")
    monkeypatch.setenv(FLAG, "1")
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-File", str(root / script), *args],
                            env=os.environ.copy(), capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert "legacy collection disabled" in result.stderr


def test_agent_collection_remains_available(monkeypatch):
    from sli_agent.modules import EventLogModule

    monkeypatch.setenv(FLAG, "1")
    module = EventLogModule(source_instance_id="synthetic", source_name="synthetic",
                            channel="Security", generation="synthetic", reader=lambda _: [])
    sample = module.collect()
    assert sample.module_id == "sli.windows-eventlog"
    assert sample.payload["records"] == []
