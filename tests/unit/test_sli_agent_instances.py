"""Independent service instances with synthetic identities and OS/transport fakes."""
import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent.config import AgentConfig, machine_config_path, service_name
from sli_agent.enrollment import IdentityStore
from sli_agent.modules import EventLogModule
from sli_agent.protection import directory_lock
from sli_agent.spool import Spool

HOST = "00000000-0000-4000-8000-000000000001"
NOW = datetime(2026, 10, 7, 12, tzinfo=timezone.utc)


def config(root, name, **kwargs):
    return AgentConfig("https://core.invalid", root / "ca.pem", root / "state",
                       instance_name=name, **{"host_id": HOST, **kwargs})


@pytest.mark.parametrize("name", ["", "DC", "../dc", "a/b", "a\\b", "a" * 49, "dc ", "é", True, 1])
def test_instance_names_reject_case_aliases_and_path_escape(tmp_path, name):
    with pytest.raises(ValueError, match="agent_config_invalid"):
        config(tmp_path, name)


def test_named_config_requires_host_uuid_and_keeps_legacy_paths(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="agent_config_invalid"):
        AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path, instance_name="dc")
    with pytest.raises(ValueError, match="agent_config_invalid"):
        config(tmp_path, "dc", host_id=None)
    legacy = AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path)
    assert legacy.storage_dir == tmp_path and service_name() == "SLIAgent"
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    assert machine_config_path() == tmp_path / "SLI/Agent/agent.json"
    assert machine_config_path("dc") == tmp_path / "SLI/Agent/instances/SLI-Agent-dc/agent.json"
    assert config(tmp_path, "dc").storage_dir == tmp_path / "state/instances/SLI-Agent-dc"
    # A prefix also makes Windows reserved device names safe directory names.
    assert config(tmp_path, "con").storage_dir.name == "SLI-Agent-con"


def test_two_instances_have_separate_keys_host_state_and_locks(tmp_path):
    first, second = config(tmp_path, "dc"), config(tmp_path, "workstation")
    a, b = IdentityStore(first), IdentityStore(second)
    pa, pb = a.prepare(), b.prepare()
    assert pa["host_id"] == pb["host_id"] == HOST
    assert pa["key_fingerprint"] != pb["key_fingerprint"]
    assert pa["instance_name"] == "dc" and pb["instance_name"] == "workstation"
    assert IdentityStore(first).prepare() == pa
    assert IdentityStore(second).prepare() == pb
    for part in (Path(), Path("running"), Path("spool"), Path("transport-lock")):
        with directory_lock(first.storage_dir / part), directory_lock(second.storage_dir / part):
            with pytest.raises(OSError):
                with directory_lock(first.storage_dir / part):
                    pytest.fail("same-instance lock was not exclusive")
    assert stat.S_IMODE(first.storage_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE((first.storage_dir / "identity-key.json").stat().st_mode) == 0o600


def test_changing_config_host_cannot_rebind_existing_state(tmp_path):
    first = config(tmp_path, "dc")
    IdentityStore(first).prepare()
    changed = AgentConfig(first.server_url, first.ca_bundle, first.state_dir,
                          instance_name="dc", host_id=str(uuid4()))
    with pytest.raises(ValueError, match="agent_identity_invalid"):
        IdentityStore(changed).prepare()
    assert IdentityStore(first).prepare()["host_id"] == HOST


def test_two_spools_capture_and_commit_independent_channel_cursors(tmp_path):
    first, second = config(tmp_path, "dc"), config(tmp_path, "workstation")
    spools = [Spool(c.storage_dir / "spool", max_bytes=50000, max_age_seconds=3600) for c in (first, second)]
    values = []
    for spool, record in zip(spools, (7, 23)):
        xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
               f'<System><EventID>4624</EventID><EventRecordID>{record}</EventRecordID></System></Event>')
        module = EventLogModule(source_instance_id=str(uuid4()), source_name="fixture-host", channel="Security",
                                generation="fixture-generation", reader=lambda after, value=xml: [value])
        values.append(spool.capture(ec.generate_private_key(ec.SECP256R1()), agent_id=str(uuid4()),
                                    sample=module.collect(None, now=NOW), now=NOW))
    assert spools[0].captured("sli.windows-eventlog")["cursor_after"]["token"] == "7"
    assert spools[1].captured("sli.windows-eventlog")["cursor_after"]["token"] == "23"
    envelope = values[0]["envelope"]
    receipt = {"contract_id": "sli.agent-receipt.v1", "packet_id": envelope["packet_id"],
               "payload_sha256": envelope["payload_sha256"], "status": "committed",
               "committed_cursor": envelope["cursor_after"], "evidence_ref": "fixture-evidence",
               "committed_at_utc": NOW.isoformat(), "error_code": None}
    assert not spools[1].acknowledge(values[0], receipt)
    assert spools[0].acknowledge(values[0], receipt)
    restarted = Spool(second.storage_dir / "spool", max_bytes=50000, max_age_seconds=3600)
    assert restarted.pending(now=NOW) == [values[1]]
    assert restarted.state["sli.windows-eventlog"]["committed"] == 0
    assert restarted.captured("sli.windows-eventlog")["cursor_after"]["token"] == "23"
    assert spools[0].state["sli.windows-eventlog"]["committed"] == 1


def test_runtime_instances_keep_status_modules_and_running_locks_separate(tmp_path, monkeypatch):
    from sli_agent import policies, runtime
    from sli_agent.modules import configured_modules

    configurations = [config(tmp_path, "dc", collection_enabled=True, event_channels=({
        "source_instance_id": HOST, "source_name": "fixture-host", "channel": "Security",
        "generation": "fixture-generation", "reader": lambda after: []},)), config(tmp_path, "workstation")]
    identities = {c.instance_name: SimpleNamespace(agent_id=str(uuid4()), key=ec.generate_private_key(ec.SECP256R1()))
                  for c in configurations}
    monkeypatch.setattr(runtime, "IdentityStore", lambda c: SimpleNamespace(
        prepare=lambda: {"host_id": HOST}, load=lambda: identities[c.instance_name], renew_if_due=lambda *a, **kw: False))
    calls = []
    def modules(c, host_id, assigned=()):
        calls.append((c.instance_name, assigned))
        return configured_modules(c, host_id, assigned)
    monkeypatch.setattr(runtime, "configured_modules", modules)
    monkeypatch.setattr(policies, "configured_modules", modules)
    def transport(c):
        return SimpleNamespace(
            get=lambda *a, **kw: {"agent_id": identities[c.instance_name].agent_id, "assigned_modules": []},
            post=lambda *a, **kw: {})
    monkeypatch.setattr(runtime, "Transport", transport)
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, delay):
            self.done = True
    first, second = configurations
    with directory_lock(first.storage_dir / "running"):
        runtime.run(second, Stop())
        with pytest.raises(OSError):
            runtime.run(first, Stop())
    assert not (first.storage_dir / "status.json").exists()
    runtime.run(first, Stop())
    assert {name for name, assigned in calls if assigned == []} == {"dc", "workstation"}
    for c in configurations:
        status = json.loads((c.storage_dir / "status.json").read_bytes())
        expected = ["sli.heartbeat", "sli.windows-eventlog"] if c.instance_name == "dc" else ["sli.heartbeat"]
        assert status["enabled_modules"] == expected
        assert status["collection_enabled"] == (c.instance_name == "dc")
        spool = Spool(c.storage_dir / "spool", max_bytes=10000, max_age_seconds=3600)
        assert spool.pending()[0]["envelope"]["agent_id"] == identities[c.instance_name].agent_id
        assert spool.captured("sli.heartbeat")["sequence"] == 1
        assert (spool.captured("sli.windows-eventlog") is not None) == (c.instance_name == "dc")


def fake_windows_service(monkeypatch):
    from sli_agent import service
    class Framework:
        def __init__(self, args):
            self.registered_name = self._svc_name_
        def ReportServiceStatus(self, value):
            self.reported = value
    manager = SimpleNamespace(LogErrorMsg=lambda value: None)
    utilities = SimpleNamespace(ServiceFramework=Framework)
    monkeypatch.setitem(sys.modules, "win32serviceutil", utilities)
    monkeypatch.setitem(sys.modules, "win32service", SimpleNamespace(SERVICE_STOP_PENDING=3))
    monkeypatch.setitem(sys.modules, "servicemanager", manager)
    monkeypatch.setattr(service, "os", SimpleNamespace(name="nt"))
    return service, utilities


def test_scm_imported_class_selects_config_from_actual_service_name(tmp_path, monkeypatch):
    service, _ = fake_windows_service(monkeypatch)
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    for name in ("dc", "workstation"):
        path = machine_config_path(name)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps({"server_url": "https://core.invalid", "ca_bundle": str(tmp_path / "ca.pem"),
                                   "state_dir": str(tmp_path / "state"), "host_id": HOST, "instance_name": name}))
    calls = []
    monkeypatch.setattr(service, "run", lambda c, stop: calls.append((c, stop)))
    cls = service.service_class()
    assert cls.__module__ == "sli_agent.service" and cls.__qualname__ == "SliAgentService"
    a, b = cls(["SLI-Agent-dc"]), cls(["SLI-Agent-workstation"])
    a.SvcDoRun()
    b.SvcDoRun()
    assert [c.instance_name for c, _ in calls] == ["dc", "workstation"]
    assert a.registered_name == "SLI-Agent-dc" and b.registered_name == "SLI-Agent-workstation"
    a.SvcStop()
    assert a.stop.is_set() and not b.stop.is_set()
    assert cls(["SLIAgent"]).instance_name is None
    with pytest.raises(ValueError):
        cls(["SLI-Agent-../dc"])
    bad_path = machine_config_path("dc")
    body = json.loads(bad_path.read_text())
    body["instance_name"] = "workstation"
    bad_path.write_text(json.dumps(body))
    with pytest.raises(RuntimeError, match="agent_service_failed"):
        a.SvcDoRun()
    assert len(calls) == 2


def test_service_registration_uses_instance_name_and_stable_import(monkeypatch):
    service, utilities = fake_windows_service(monkeypatch)
    seen = []
    utilities.HandleCommandLine = lambda cls, serviceClassString, argv: seen.append((cls._svc_name_, serviceClassString, argv))
    monkeypatch.setattr(sys, "argv", ["service.py", "--instance", "dc", "--startup", "manual", "install"])
    service.main()
    assert seen == [("SLI-Agent-dc", "sli_agent.service.SliAgentService",
                     ["service.py", "--startup", "manual", "install"])]


def test_msi_service_uses_managed_enrollment_loop(tmp_path, monkeypatch):
    from sli_agent import msi
    service, _ = fake_windows_service(monkeypatch)
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    path = machine_config_path()
    path.parent.mkdir(parents=True)
    (path.parent / ".msi-owned").write_text(msi.OWNER)
    cfg = AgentConfig(server_url="https://example.invalid", ca_bundle=tmp_path / "ca.pem", state_dir=tmp_path / "state")
    monkeypatch.setattr(service.AgentConfig, "load", lambda p: cfg)
    monkeypatch.setattr(service, "run", lambda *a: pytest.fail("MSI enrollment must run first"))
    calls = []
    monkeypatch.setattr(msi, "run_managed", lambda c, stop: calls.append(c))
    service.service_class()(["SLIAgent"]).SvcDoRun()
    assert calls == [cfg]


def test_embedded_python_enters_scm_dispatcher_directly(monkeypatch):
    service, _ = fake_windows_service(monkeypatch)
    calls = []
    manager = SimpleNamespace(Initialize=lambda: calls.append("initialize"),
        PrepareToHostSingle=lambda cls: calls.append(cls._svc_name_),
        StartServiceCtrlDispatcher=lambda: calls.append("dispatch"))
    monkeypatch.setitem(sys.modules, "servicemanager", manager)
    monkeypatch.setattr(sys, "argv", ["service.py"])
    service.main()
    assert calls == ["initialize", "SLIAgent", "dispatch"]


def test_scm_supervisor_and_restart_helper_follow_actual_instance(tmp_path, monkeypatch):
    from sli_agent import launcher
    service, _ = fake_windows_service(monkeypatch)
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    cfg = config(tmp_path, "dc", update_root=tmp_path / "releases",
                 update_trust_store=tmp_path / "trust.json", service_python=tmp_path / "python.exe")
    monkeypatch.setattr(service.AgentConfig, "load", lambda path: cfg)
    monkeypatch.setattr(service, "run", lambda *a: pytest.fail("update-enabled service must use supervisor"))
    calls = []
    monkeypatch.setattr(launcher, "request_service_restart", lambda python, instance: calls.append((python, instance)))
    def supervise(c, path, stop, *, restart_service):
        assert c is cfg and path == machine_config_path("dc")
        assert c.release_root == tmp_path / "releases/instances/SLI-Agent-dc"
        assert not stop.is_set()
        restart_service()
    monkeypatch.setattr(launcher, "supervise", supervise)
    cls = service.service_class()
    cls(["SLI-Agent-dc"]).SvcDoRun()
    assert calls == [(cfg.service_python, "dc")]
    with pytest.raises(RuntimeError, match="agent_service_failed"):
        cls(["SLI-Agent-workstation"]).SvcDoRun()
    assert len(calls) == 1


def test_service_registration_propagates_failure_status(monkeypatch):
    service, utilities = fake_windows_service(monkeypatch)
    utilities.HandleCommandLine = lambda *a, **kw: 5
    monkeypatch.setattr(sys, "argv", ["service.py", "--instance", "dc", "install"])
    assert service.main() == 5


def test_installer_names_paths_and_acls_are_instance_specific():
    source = (Path(__file__).resolve().parents[2] / "tools/install-sli-agent.ps1").read_text(encoding="utf-8")
    assert "[string]$Instance" in source and "$Instance -cnotmatch" in source
    assert "$config.instance_name -cne $Instance" in source
    assert "$serviceName = 'SLI-Agent-' + $Instance" in source
    assert "Join-Path (Join-Path $config.state_dir 'instances') $serviceName" in source
    assert "Get-Acl -LiteralPath $statePath" in source
    assert "agent_install_state_acl_unexpected_principal" in source
    assert "agent_install_instance_state_path_invalid" in source
    assert "@('--instance', $Instance)" in source
    assert "Get-Service -Name $serviceName" in source
    assert "$PSCmdlet.ShouldProcess($serviceName" in source
    assert "--startup disabled install" in source and "--startup manual install" in source
    assert "Start-Service" not in source and "--password" not in source


def test_named_config_load_preserves_rights_probe_settings(tmp_path):
    path = tmp_path / "agent.json"
    planned = {"module_id": "sli.workstations", "enabled": True, "config": {}}
    path.write_text(json.dumps({"server_url": "https://core.invalid", "ca_bundle": "ca.pem",
                               "state_dir": str(tmp_path / "state"), "instance_name": "dc", "host_id": HOST,
                               "service_identity_sid": "S-1-5-18", "allow_missing_rights": True,
                               "probe_modules": [planned]}))
    cfg = AgentConfig.load(path)
    assert cfg.storage_dir == tmp_path / "state/instances/SLI-Agent-dc"
    assert cfg.service_identity_sid == "S-1-5-18" and cfg.allow_missing_rights is True
    assert cfg.probe_modules == (planned,)


@pytest.mark.parametrize("verified", [False, True])
def test_rights_probe_reports_stay_in_each_instance_state(tmp_path, verified):
    from sli_agent.probe import save_report

    configurations = [config(tmp_path, name) for name in ("dc", "workstation")]
    target = "rights-probe.json" if verified else "rights-probe-unverified.json"
    for cfg, ready in zip(configurations, (True, False)):
        cfg.storage_dir.mkdir(parents=True)
        report = {"identity_verified": verified, "ready": ready, "checks": []}
        save_report(cfg, report)
        assert json.loads((cfg.storage_dir / target).read_bytes()) == report
    assert json.loads((configurations[0].storage_dir / target).read_bytes())["ready"] is True
    assert not (tmp_path / "state" / target).exists()
    assert not list((tmp_path / "state").rglob(".rights-probe-*"))
