"""Rights diagnostics with synthetic identities, Windows APIs and transports."""
import base64
import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from sli_agent.config import AgentConfig
from sli_agent.probe import WindowsRightsReader, format_table, probe, save_report

SID = "S-1-5-18"


def config(tmp_path, **kwargs):
    return AgentConfig("https://core.invalid", tmp_path / "ca.pem", tmp_path,
                       service_identity_sid=SID, **kwargs)


def assignment(module="sli.ad-dc", **settings):
    return {"module_id": module, "enabled": True, "config": settings}


class Reader:
    def __init__(self, sid=SID, outcomes=None):
        self.sid = sid
        self.outcomes = outcomes or {}
        self.calls = []

    def current_sid(self):
        return self.sid

    def __getattr__(self, kind):
        def read(*args):
            self.calls.append((kind, args))
            value = self.outcomes.get(kind)
            if isinstance(value, Exception):
                raise value
            return value
        return read


@pytest.mark.parametrize("settings", [{"paused": True}, {"families": {"nps": False}}])
def test_nps_paused_family_performs_no_source_rights_reads(tmp_path, settings):
    reader = Reader()
    result = probe(config(tmp_path), reader=reader,
                   assigned_modules=[assignment("sli.vpn-nps", **settings)], planned=False)
    assert result["ready"] and reader.calls == []


def test_accounting_module_requires_file_rights_without_event_channel_rights(tmp_path):
    reader = Reader(outcomes={"event_channel": PermissionError("fixture")})
    result = probe(config(tmp_path), reader=reader, planned=False,
        assigned_modules=[assignment("sli.radius-accounting", accounting_directory="fixture-path")])
    assert result["ready"]
    assert reader.calls == [("accounting", ("fixture-path",))]


@pytest.mark.parametrize("value,status", [
    (None, "available"), (PermissionError("fixture-private-diagnostic"), "denied"),
    (FileNotFoundError("fixture-private-diagnostic"), "not_present"),
    (RuntimeError("fixture-private-diagnostic"), "denied"),
    ("available", "available"), ("denied", "denied"), ("not_present", "not_present"),
    ("not_applicable", "not_applicable"), ("fixture-private-diagnostic", "denied"),
])
def test_statuses_and_remedies_do_not_expose_diagnostics(tmp_path, value, status):
    report = probe(config(tmp_path), reader=Reader(outcomes={"ad": value}),
                   assigned_modules=[assignment()])
    check = next(c for c in report["checks"] if c["kind"] == "ad")
    assert check["status"] == status
    assert bool(check["remedy_ru"]) == (status != "available")
    assert report["ready"] == (status == "available")
    assert "fixture-private-diagnostic" not in json.dumps(report)
    assert "fixture-private-diagnostic" not in format_table(report)


@pytest.mark.parametrize("sid,expected", [(SID, None), (None, SID), ("S-1-5-19", SID)])
def test_identity_mismatch_or_unspecified_identity_never_reads_sources(tmp_path, sid, expected):
    reader = Reader(sid)
    report = probe(replace(config(tmp_path), service_identity_sid=expected), reader=reader,
                   assigned_modules=[assignment()])
    assert not report["identity_verified"] and not report["ready"]
    assert not reader.calls
    assert all(c["status"] == "not_applicable" for c in report["checks"])
    assert all(c["reason"] == "run_as_service_identity" for c in report["checks"])
    assert "от имени службы" in format_table(report)


def test_dc_source_pack_and_directory_requirements_are_registered(tmp_path):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment()])
    root = Path(__file__).resolve().parents[2]
    channels = json.loads((root / "config/source_packs/dc.json").read_text())["channels"]
    assert [args[0] for kind, args in reader.calls if kind == "event_channel"] == channels
    assert ("ad", ()) in reader.calls and ("sysvol", ()) in reader.calls
    assert report["identity_verified"] and report["ready"]


@pytest.mark.parametrize("module,sysvol", [("sli.ad-snapshot", False), ("sli.gpo-snapshot", True)])
def test_snapshot_reads_do_not_require_event_channels(tmp_path, module, sysvol):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment(module)])
    assert report["ready"]
    assert ("ad", ()) in reader.calls
    assert (("sysvol", ()) in reader.calls) == sysvol
    assert not any(kind == "event_channel" for kind, _ in reader.calls)


def test_workstation_requirements_match_all_collected_channels(tmp_path):
    from sli_agent.workstations import CHANNELS
    reader = Reader()
    probe(config(tmp_path), reader=reader, assigned_modules=[assignment("sli.workstations")])
    assert {args[0] for kind, args in reader.calls if kind == "event_channel"} == set(CHANNELS)
    assert all(kind == "event_channel" for kind, args in reader.calls)


def test_live_dc_module_only_probes_enabled_event_channels(tmp_path):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment("sli.windows.ad-dc",
        source_name="fixture-source", connect_address="fixture-endpoint",
        channels={"System": False, "Directory Service": False})])
    assert reader.calls == [("event_channel", ("Security",))]
    assert report["ready"]


def test_dc_history_probes_only_its_enabled_channels(tmp_path):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment("sli.windows.ad-dc-history",
        source_name="fixture-source", connect_address="fixture-endpoint", history_before_utc="2026-10-10T00:00:00Z",
        channels={"System": False, "Directory Service": False})])
    assert reader.calls == [("event_channel", ("Security",))]
    assert report["ready"]


def test_workstation_probe_skips_disabled_family_channels(tmp_path):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment("sli.workstations",
        families={"usb": False, "protection": False})])
    assert reader.calls == [("event_channel", ("Security",))]
    assert report["ready"]


@pytest.mark.parametrize("module", ["sli.vpn-nps", "sli.remote-access"])
@pytest.mark.parametrize("directory", [None, "fixture-private-accounting-path"])
def test_accounting_is_required_only_when_configured_and_path_is_private(tmp_path, module, directory):
    reader = Reader()
    settings = {} if directory is None else {"accounting_directory": directory}
    report = probe(config(tmp_path), reader=reader, assigned_modules=[assignment(module, **settings)])
    check = next(c for c in report["checks"] if c["kind"] == "accounting")
    assert check["required"] == (directory is not None)
    assert check["status"] == ("available" if directory else "not_applicable")
    assert (("accounting", (directory,)) in reader.calls) == (directory is not None)
    assert report["ready"]
    assert "fixture-private-accounting-path" not in json.dumps(report)


def test_disabled_and_legacy_assignments_do_not_probe(tmp_path):
    reader = Reader()
    report = probe(config(tmp_path), reader=reader, assigned_modules=[
        "sli.workstations", {**assignment(), "enabled": False}])
    assert report["ready"] and not reader.calls


def test_unknown_enabled_module_is_not_silently_treated_as_available(tmp_path):
    report = probe(config(tmp_path), reader=Reader(), assigned_modules=[assignment("fixture-private-module")])
    assert not report["ready"]
    assert report["checks"][-1]["reason"] == "module_unregistered"
    assert "fixture-private-module" not in json.dumps(report)


@pytest.mark.parametrize("assignments", [
    [assignment(), assignment()], [{**assignment(), "enabled": "yes"}],
    [{**assignment(), "config": []}], [None], {},
])
def test_invalid_assignments_fail_closed(tmp_path, assignments):
    with pytest.raises(ValueError, match="agent_probe_config_invalid"):
        probe(config(tmp_path), reader=Reader(), assigned_modules=assignments)


def test_preview_checks_planned_channels_without_enabling_collection(tmp_path):
    cfg = config(tmp_path, event_channels=({"channel": "fixture-private-channel"},),
                 probe_modules=(assignment("sli.workstations"),))
    reader = Reader()
    report = probe(cfg, reader=reader)
    assert report["ready"] and cfg.collection_enabled is False
    assert ("event_channel", ("fixture-private-channel",)) in reader.calls
    assert "fixture-private-channel" not in json.dumps(report)
    reader = Reader()
    probe(cfg, reader=reader, assigned_modules=(), planned=False)
    assert not reader.calls  # Runtime uses only actual local opt-in and assignments.


@pytest.mark.parametrize("field,value", [("service_identity_sid", "fixture-private-account"),
                                        ("allow_missing_rights", "yes"), ("probe_modules", [])])
def test_invalid_probe_configuration(tmp_path, field, value):
    with pytest.raises(ValueError, match="agent_config_invalid"):
        replace(config(tmp_path), **{field: value})


def test_config_loads_preview_modules_and_override(tmp_path):
    path = tmp_path / "agent.json"
    path.write_text(json.dumps({"server_url": "https://core.invalid", "ca_bundle": "ca.pem",
        "state_dir": str(tmp_path), "service_identity_sid": SID, "allow_missing_rights": True,
        "probe_modules": [assignment()]}))
    cfg = AgentConfig.load(path)
    assert cfg.probe_modules == (assignment(),) and cfg.allow_missing_rights is True


def test_saved_json_preserves_parent_acl_and_contains_only_safe_report(tmp_path, monkeypatch):
    secured = []
    monkeypatch.setattr("sli_agent.probe.restrict_path", lambda path: secured.append(path))
    cfg = config(tmp_path)
    report = probe(cfg, reader=Reader(), assigned_modules=[assignment()])
    save_report(cfg, report)
    assert json.loads((tmp_path / "rights-probe.json").read_bytes()) == report
    assert all(path != tmp_path for path in secured)
    assert not list(tmp_path.glob(".rights-probe-*"))
    assert not (tmp_path / "identity-key.json").exists()


@pytest.mark.parametrize("error_code,status", [(None, "available"), (259, "available"),
                                               (5, "denied"), (15007, "not_present"), (87, "denied")])
def test_native_event_probe_queries_reads_and_closes_handles(tmp_path, monkeypatch, error_code, status):
    closed, calls = [], []
    query = SimpleNamespace(Close=lambda: closed.append("query"))
    event = SimpleNamespace(Close=lambda: closed.append("event"))

    class WindowsError(Exception):
        winerror = error_code

    def next_events(*args):
        calls.append(("next", args))
        if error_code is not None:
            raise WindowsError("fixture-private-diagnostic")
        return [event]

    def query_events(*args):
        calls.append(("query", args))
        if error_code == 15007:
            raise WindowsError("fixture-private-diagnostic")
        return query

    def render(*args):
        calls.append(("render", args))
        return "fixture-private-event-xml"

    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtQuery=query_events, EvtNext=next_events, EvtRender=render, error=WindowsError,
        EvtQueryChannelPath=1, EvtQueryForwardDirection=2, EvtRenderEventXml=1))
    reader = WindowsRightsReader()
    monkeypatch.setattr(reader, "current_sid", lambda: SID)
    report = probe(config(tmp_path, event_channels=({"channel": "Security"},)), reader=reader)
    assert report["checks"][-1]["status"] == status
    assert calls[0] == ("query", ("Security", 3, "*", None))
    assert closed == (["event", "query"] if error_code is None else [] if error_code == 15007 else ["query"])
    assert any(c[0] == "render" for c in calls) == (error_code is None)
    assert "fixture-private" not in json.dumps(report)


@pytest.mark.parametrize("kind", ["ad", "sysvol"])
@pytest.mark.parametrize("returncode,output", [(0, "available"), (0, "denied"), (0, "not_present"),
                                               (0, "fixture-private-diagnostic"), (1, "available")])
def test_native_directory_probes_validate_safe_output_and_use_no_credentials(monkeypatch, kind, returncode, output):
    def execute(args, **kwargs):
        script = base64.b64decode(args[-1]).decode("utf-16-le")
        assert args[1:4] == ["-NoProfile", "-NonInteractive", "-EncodedCommand"]
        assert kwargs["capture_output"] and kwargs["timeout"] == 20
        if kind == "ad":
            assert "::Secure" in script and "::Signing" in script and "::Sealing" in script
            assert "RefreshCache(@('distinguishedName'))" in script
            assert ", $null, $null, $auth)" not in script
            assert "$root.AuthenticationType = $auth" in script
            assert "$object.AuthenticationType = $auth" in script
        else:
            assert "\\SYSVOL\\" in script and "EnumerateDirectories" in script and "'gpt.ini'" in script
        return SimpleNamespace(returncode=returncode, stdout=output, stderr="fixture-private-diagnostic")
    monkeypatch.setattr("sli_agent.probe.subprocess.run", execute)
    if returncode or output.startswith("fixture"):
        with pytest.raises(RuntimeError, match="^agent_probe_read_failed$"):
            getattr(WindowsRightsReader(), kind)()
    else:
        assert getattr(WindowsRightsReader(), kind)() == output


def test_native_event_render_failure_is_denied_and_closes_all_handles(tmp_path, monkeypatch):
    closed = []
    query = SimpleNamespace(Close=lambda: closed.append("query"))
    event = SimpleNamespace(Close=lambda: closed.append("event"))
    def render(*args):
        raise PermissionError("fixture-private-diagnostic")
    monkeypatch.setitem(sys.modules, "win32evtlog", SimpleNamespace(
        EvtQuery=lambda *args: query, EvtNext=lambda *args: [event], EvtRender=render,
        error=OSError, EvtQueryChannelPath=1, EvtQueryForwardDirection=2, EvtRenderEventXml=1))
    reader = WindowsRightsReader()
    monkeypatch.setattr(reader, "current_sid", lambda: SID)
    report = probe(config(tmp_path, event_channels=({"channel": "Security"},)), reader=reader)
    assert report["checks"][-1]["status"] == "denied"
    assert closed == ["event", "query"]
    assert "fixture-private-diagnostic" not in json.dumps(report)


def test_cli_returns_blocked_exit_json_without_enrollment_or_secrets(tmp_path, monkeypatch, capsys):
    from sli_agent import __main__ as cli
    cfg = config(tmp_path)
    monkeypatch.setattr(cli.AgentConfig, "load", lambda path: cfg)
    monkeypatch.setattr(cli, "probe", lambda cfg: probe(cfg, reader=Reader("S-1-5-19")))
    monkeypatch.setattr(cli, "IdentityStore", lambda cfg: pytest.fail("probe must not create enrollment state"))
    monkeypatch.setattr(sys, "argv", ["sli_agent", "probe", "--config", "unused", "--json"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    assert json.loads(capsys.readouterr().out) == json.loads((tmp_path / "rights-probe-unverified.json").read_bytes())


@pytest.mark.parametrize("kind", ["sysvol", "accounting"])
@pytest.mark.parametrize("error,status", [(PermissionError("fixture-private-path"), "denied"),
                                         (FileNotFoundError("fixture-private-path"), "not_present")])
def test_directory_and_accounting_errors_block_readiness_without_disclosing_paths(tmp_path, kind, error, status):
    module = assignment() if kind == "sysvol" else assignment("sli.vpn-nps", accounting_directory="fixture-private-path")
    report = probe(config(tmp_path), reader=Reader(outcomes={kind: error}), assigned_modules=[module])
    check = next(c for c in report["checks"] if c["kind"] == kind)
    assert check["status"] == status and check["required"] and check["remedy_ru"]
    assert not report["ready"] and "fixture-private-path" not in json.dumps(report)


def test_accounting_reader_lists_empty_directory_and_reads_only_one_byte(tmp_path, monkeypatch):
    reader = WindowsRightsReader()
    assert reader.accounting(tmp_path) is None
    (tmp_path / "fixture.log").write_bytes(b"fixture-private-log-contents")
    read_sizes = []
    class Stream:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def read(self, size):
            read_sizes.append(size)
            return b"x"
    def open_log(path, mode):
        assert mode == "rb"
        return Stream()
    monkeypatch.setattr("sli_agent.probe.open", open_log, raising=False)
    assert reader.accounting(tmp_path) is None
    assert read_sizes == [1]


def test_windows_identity_probe_closes_token_and_does_not_resolve_account_names(monkeypatch):
    import sli_agent.probe as probe_module
    closed = []
    token = SimpleNamespace(Close=lambda: closed.append(True))
    monkeypatch.setattr(probe_module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "win32api", SimpleNamespace(GetCurrentProcess=lambda: "process"))
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(TOKEN_QUERY=8))
    monkeypatch.setitem(sys.modules, "win32security", SimpleNamespace(TokenUser=1,
        OpenProcessToken=lambda process, flags: token,
        GetTokenInformation=lambda handle, kind: ("sid", 0), ConvertSidToStringSid=lambda value: SID))
    assert WindowsRightsReader().current_sid() == SID
    assert closed == [True]


def test_cli_still_prints_safe_json_if_installer_cannot_write_service_state(tmp_path, monkeypatch, capsys):
    from sli_agent import __main__ as cli
    cfg = config(tmp_path)
    monkeypatch.setattr(cli.AgentConfig, "load", lambda path: cfg)
    monkeypatch.setattr(cli, "probe", lambda cfg: probe(cfg, reader=Reader("S-1-5-19")))
    def fail_save(*args):
        raise PermissionError("fixture-private-path")
    monkeypatch.setattr(cli, "save_report", fail_save)
    monkeypatch.setattr(sys, "argv", ["sli_agent", "probe", "--config", "unused", "--json"])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 2
    output = capsys.readouterr().out
    assert "fixture-private-path" not in output
    report = json.loads(output)
    assert not report["ready"] and report["checks"][-1]["reason"] == "report_write_failed"


@pytest.mark.parametrize("verified,ready,override,collects", [
    (True, True, False, True), (True, False, False, False),
    (True, False, True, True), (False, False, True, False),
])
@pytest.mark.parametrize("revision", [None, 2])
def test_runtime_rechecks_actual_assignments_and_gates_collection(
        tmp_path, monkeypatch, verified, ready, override, collects, revision):
    from sli_agent import policies, runtime
    from sli_agent.modules import HeartbeatModule
    from sli_agent.spool import Spool
    monkeypatch.setattr(runtime, "service_identity_verified", lambda cfg: True)
    host, agent = str(uuid4()), str(uuid4())
    identity = SimpleNamespace(agent_id=agent, key=ec.generate_private_key(ec.SECP256R1()))
    monkeypatch.setattr(runtime, "IdentityStore", lambda cfg: SimpleNamespace(
        prepare=lambda: {"host_id": host}, load=lambda: identity, renew_if_due=lambda *a, **kw: False))
    assignments = [assignment("sli.workstations")]
    calls = []
    policy = {"agent_id": agent, "assigned_modules": assignments}
    if revision is not None:
        policy["policy_revision"] = revision

    def post(path, body, **kwargs):
        assert path == "/api/v1/agent/policy-report"
        assert body == {"applied_policy_revision": revision}
        assert kwargs["identity"] is identity
        calls.append("policy_ack")
        return {"applied_policy_revision": revision}

    monkeypatch.setattr(runtime, "Transport", lambda cfg: SimpleNamespace(
        get=lambda *a, **kw: policy, post=post))

    class Collector:
        module_id = "sli.workstations"
        def collect(self, captured, *, now):
            calls.append("collect")
            return replace(HeartbeatModule(host).collect(captured, now=now), module_id=self.module_id)

    monkeypatch.setattr(policies, "configured_modules", lambda *args: [HeartbeatModule(host), Collector()])

    def rights(cfg, **kwargs):
        assert kwargs["assigned_modules"] == assignments and kwargs["planned"] is False
        calls.append("probe")
        return {"identity_verified": verified, "ready": ready, "checks": []}

    monkeypatch.setattr(runtime, "probe", rights)
    class Stop:
        done = False
        def is_set(self):
            return self.done
        def wait(self, delay):
            self.done = True
    runtime.run(config(tmp_path, allow_missing_rights=override), Stop())
    assert calls == (["policy_ack"] if revision is not None else []) + (["probe", "collect"] if collects else ["probe"])
    spool = Spool(tmp_path / "spool", max_bytes=100000, max_age_seconds=3600)
    assert spool.captured("sli.heartbeat") is not None
    assert (spool.captured("sli.workstations") is not None) == collects
    status = json.loads((tmp_path / "status.json").read_bytes())
    assert status["rights_probe_ready"] is ready
    assert (status["error_code"] == "agent_required_rights_missing") == (not collects)
    path = tmp_path / ("rights-probe.json" if verified else "rights-probe-unverified.json")
    assert json.loads(path.read_bytes())["identity_verified"] is verified


def test_runtime_identity_mismatch_stops_before_locks_keys_and_collectors(tmp_path, monkeypatch):
    from sli_agent import runtime
    monkeypatch.setattr(WindowsRightsReader, "current_sid", lambda self: "S-1-5-19")
    monkeypatch.setattr(runtime, "directory_lock", lambda path: pytest.fail("state ACL must remain unchanged"))
    monkeypatch.setattr(runtime, "IdentityStore", lambda cfg: pytest.fail("must not load private identity"))
    with pytest.raises(RuntimeError, match="^agent_service_identity_unverified$"):
        runtime.run(config(tmp_path, allow_missing_rights=True), None)
    report = json.loads((tmp_path / "rights-probe-unverified.json").read_bytes())
    assert not report["identity_verified"] and not report["ready"]


def test_installer_prints_manual_start_command_only_after_required_rights_gate():
    source = (Path(__file__).resolve().parents[2] / "tools/install-sli-agent.ps1").read_text(encoding="utf-8")
    assert "[switch]$Start" not in source
    registration, probe_source = source.split("--startup manual install", 1)
    assert "sc.exe start" not in registration
    table, gate = probe_source.split("Format-Table -Wrap -AutoSize", 1)
    assert "ConvertFrom-Json" in table
    blocked, allowed = gate.split("if (-not $probe.ready -and -not $AllowMissingRights) {", 1)[1].split("return", 1)
    assert "sc.exe start" not in blocked
    assert 'Write-Output "sc.exe start $serviceName"' in allowed
    assert "remedy_ru" in table
