"""Offline AD/DC credential wiring; never use the real store, source or DB."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.core
MODE_KEY = "ADLOG_AD_SOURCE_CREDENTIAL_MODE"
DPAPI = "dpapi_current_user"


def forbidden(*args, **kwargs):
    raise AssertionError("unexpected external operation")


@pytest.fixture(autouse=True)
def offline_boundary(monkeypatch, tmp_path):
    from server.sli.sources import ad_source_credentials as store
    from server.sli.sources import dc_discovery
    from scripts.collect import collect_windows_events as events

    monkeypatch.delenv(MODE_KEY, raising=False)
    monkeypatch.delenv("ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE", raising=False)
    monkeypatch.setattr(store, "load_credentials", forbidden)
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(events, "win32evtlog", SimpleNamespace(
        EvtRpcLogin=1, EvtRpcLoginAuthDefault=0, EvtOpenSession=forbidden,
    ))
    for name in ("log_event", "log_internal_error", "log_performance_stage"):
        monkeypatch.setattr(events, name, lambda *a, **k: None)
    (tmp_path / "domain_controllers.json").write_text(json.dumps({
        "domain_controllers": [{"hostname": "DC1", "connect_address": "dc1.example.test"}],
    }), encoding="utf-8")


@pytest.mark.parametrize(("username", "user", "domain"), [
    ("MiXeD\\Collector", "Collector", "MiXeD"),
    ("Collector@MiXeD.example.test", "Collector@MiXeD.example.test", None),
])
def test_explicit_dpapi_uses_exact_native_login_tuple(monkeypatch, username, user, domain):
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store

    password = "synthetic-only-password!"
    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials(username, password))
    calls = []
    sentinel = object()
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: calls.append(a) or sentinel)

    assert events.open_remote_session("DC1", ad_source_credential_mode=DPAPI) is sentinel
    assert calls == [(("dc1.example.test", user, domain, password, 0), 1, 0, 0)]


def test_default_helper_does_not_inherit_ad_mode(monkeypatch):
    from scripts.collect import collect_windows_events as events

    monkeypatch.setenv(MODE_KEY, DPAPI)
    calls = []
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: calls.append(a))
    events.open_remote_session("radius01.example.test")
    assert calls == [(("radius01.example.test", None, None, None, 0), 1, 0, 0)]


def test_dc_eventlog_can_use_explicit_vpn_store_without_changing_ad_store(monkeypatch):
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store

    monkeypatch.setenv("ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE", "vpn")
    def load(*, profile="ad"):
        assert profile == "vpn"
        return store.AdSourceCredentials("EventReader@example.test", "synthetic-password")
    monkeypatch.setattr(store, "load_credentials", load)
    calls = []
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: calls.append(a))
    events.open_remote_session("DC1", ad_source_credential_mode=DPAPI)
    assert calls == [(("dc1.example.test", "EventReader@example.test", None, "synthetic-password", 0), 1, 0, 0)]


def test_unknown_eventlog_profile_fails_before_secret_or_rpc(monkeypatch):
    from scripts.collect import collect_windows_events as events

    monkeypatch.setenv("ADLOG_AD_EVENTLOG_CREDENTIAL_PROFILE", "unexpected")
    with pytest.raises(RuntimeError, match="^ad_source_credential_profile_invalid$") as caught:
        events.open_remote_session("DC1", ad_source_credential_mode=DPAPI)
    from server.sli.sources.collection_failure_policy import classify_collection_failure
    assert classify_collection_failure([caught.value]).blocked


@pytest.mark.parametrize("target", ["radius01.example.test", "dc1.attacker.test", "127.0.0.1", "localhost", ""])
def test_dpapi_endpoint_must_be_exactly_configured_before_store_or_rpc(target):
    from scripts.collect import collect_windows_events as events

    with pytest.raises(RuntimeError, match="ad_source_endpoint_invalid"):
        events.open_remote_session(target, ad_source_credential_mode=DPAPI)


def test_unreadable_store_is_sanitized_before_rpc(monkeypatch):
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store

    def failed_load():
        raise OSError("synthetic-private-store-path synthetic-only-password!")

    monkeypatch.setattr(store, "load_credentials", failed_load)
    with pytest.raises(RuntimeError, match="^ad_source_credentials_unavailable$") as caught:
        events.open_remote_session("DC1", ad_source_credential_mode=DPAPI)
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("code", [1317, 1326, 1327, 1328, 1329, 1330, 1331, 1385, 1793, 1907, 1909])
def test_terminal_auth_codes_and_wire_marker_require_operator(code):
    from server.sli.sources.collection_failure_policy import classify_collection_failure, collection_failure_fields

    for error in (OSError(code, "synthetic localized error"), f"winerror {code}",
                  f"({code}, 'EvtOpenSession', 'synthetic localized error')"):
        decision = classify_collection_failure([error])
        assert decision.blocked
        assert decision.code == "windows_event_log_authentication_failed"
        assert collection_failure_fields(decision)["retryable"] is False
    assert classify_collection_failure(["windows_event_log_authentication_failed"]).blocked


def test_native_auth_error_is_sanitized(monkeypatch):
    import traceback
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store
    from server.sli.sources.collection_failure_policy import classify_collection_failure

    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!"))
    def rejected(*args):
        raise OSError(1326, "TEST\\Collector synthetic-only-password!")
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", rejected)
    with pytest.raises(RuntimeError) as caught:
        events.open_remote_session("DC1", ad_source_credential_mode=DPAPI)
    rendered = "".join(traceback.format_exception(caught.value))
    assert "synthetic-only-password!" not in rendered
    assert "TEST\\Collector" not in rendered
    assert classify_collection_failure([caught.value]).blocked


def test_terminal_auth_stops_remaining_channels_and_quarantines_batch(monkeypatch, tmp_path):
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store
    from scripts.run_dc_log_pilot import summarize_channel_status, write_collection_block_marker

    monkeypatch.setattr(events, "os", SimpleNamespace(name="nt", environ=events.os.environ))
    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!"))
    calls = []
    def rejected(*args):
        calls.append(True)
        raise OSError(1326, "synthetic-only-password!")
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", rejected)
    monkeypatch.setattr(events.sys, "argv", ["collect_windows_events.py", "--computer-name", "dc1.example.test",
        "--source-name", "DC1", "--channels", "Security,System", "--output-root", str(tmp_path / "output"),
        "--ad-source-credential-mode", DPAPI])
    assert events.main() == 74
    assert calls == [True]
    summary_file, = (tmp_path / "output").glob("*/collection-summary.json")
    summary = json.loads(summary_file.read_text(encoding="utf-8"))
    assert summary["channels"][1]["status"] == "not_attempted"
    assert summary["cursor_advanced"] is False
    status = summarize_channel_status(summary)
    assert status["terminal_block"] and not status["import_allowed"]
    marker = write_collection_block_marker(summary_file.parent, summary, status, server="DC1")
    assert json.loads(marker.read_text(encoding="utf-8"))["import_attempted"] is False
    assert "synthetic-only-password!" not in summary_file.read_text(encoding="utf-8")


def request_fixture(tmp_path, **overrides):
    from server.source_packs.adapters import WindowsEventLogRequest
    values = dict(backend="python", python_executable="python", python_script=tmp_path / "collector.py",
        powershell_script=tmp_path / "collector.ps1", computer_name="dc1.example.test", source_name="DC1",
        hours=1, max_events_per_channel=5, channel_timeout_seconds=5, output_root=tmp_path,
        channels=("Security",), collection_mode="current", collect_message=False, channel_limits={},
        channel_timeouts={}, start_time_utc=None, channel_start_times={}, channel_after_record_ids={})
    values.update(overrides)
    return WindowsEventLogRequest(**values)


def test_adapter_propagates_only_closed_mode_and_default_ignores_env(monkeypatch, tmp_path):
    from server.source_packs.adapters import build_windows_eventlog_command
    monkeypatch.setenv(MODE_KEY, DPAPI)
    assert "--ad-source-credential-mode" not in build_windows_eventlog_command(request_fixture(tmp_path))
    command = build_windows_eventlog_command(request_fixture(tmp_path, ad_source_credential_mode=DPAPI))
    assert command[command.index("--ad-source-credential-mode") + 1] == DPAPI
    assert "synthetic-only-password!" not in repr(command)
    for backend, mode in [("powershell", DPAPI), ("python", "invalid-private-value")]:
        with pytest.raises(RuntimeError, match="ad_source_(backend_unsupported|credential_mode_invalid)") as caught:
            build_windows_eventlog_command(request_fixture(tmp_path, backend=backend, ad_source_credential_mode=mode))
        assert "invalid-private-value" not in str(caught.value)


def test_supervisor_payload_carries_only_nonsecret_mode():
    from server.sli.ops.worker_supervisor_secrets import supervisor_environment_payload
    source = {"ADLOG_PG_DSN": "synthetic-not-used", "ADLOG_COLLECTION_PRINCIPAL": "TEST\\Owner",
              "ADLOG_COLLECTION_PRINCIPAL_SID": "S-1-5-21-1-2-3-1000", MODE_KEY: DPAPI}
    assert supervisor_environment_payload(source)[MODE_KEY] == DPAPI


@pytest.mark.parametrize("mode", ["process", DPAPI])
def test_worker_preflight_uses_canonical_fqdn_and_local_identity(monkeypatch, mode):
    from scripts.runtime import collection_worker as worker
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import windows_runtime_identity as identity
    from server.sli.sources import ad_source_credentials as store

    monkeypatch.setenv(MODE_KEY, mode)
    monkeypatch.setattr(identity, "verify_collection_identity", lambda: {"status": "ok", "local_owner": True})
    monkeypatch.setattr(worker, "get_active_collection_block", lambda: None)
    monkeypatch.setattr(worker, "activate_collection_block", forbidden)
    monkeypatch.setattr(worker, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!"))
    sessions = []
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: sessions.append(a) or object())
    probes = []
    monkeypatch.setattr(events, "probe_latest_record_id", lambda session, channel, timeout_ms: probes.append((channel, timeout_ms)) or 1)
    result = worker.preflight_windows_collection_context(server="DC1", worker_id="offline-worker")
    assert result["status"] == "ok"
    assert sessions[0][0][0] == "dc1.example.test"
    assert sessions[0][0][1] == ("Collector" if mode == DPAPI else None)
    assert probes == [("Security", 5000)]


@pytest.mark.parametrize("failure", ["store", "1326", "mode", "powershell"])
def test_preflight_failure_blocks_before_jobs_and_automatic_reauthentication(monkeypatch, failure):
    from scripts.runtime import collection_worker as worker
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import windows_runtime_identity as identity
    from server.sli.sources import ad_source_credentials as store

    monkeypatch.setenv(MODE_KEY, "invalid-private-value" if failure == "mode" else DPAPI)
    monkeypatch.setenv("ADLOG_COLLECTOR_BACKEND", "powershell" if failure == "powershell" else "python")
    monkeypatch.setattr(identity, "verify_collection_identity", lambda: {"status": "ok"})
    monkeypatch.setattr(worker, "log_event", lambda *a, **k: None)
    monkeypatch.setattr(worker, "create_collect_job", forbidden)
    monkeypatch.setattr(worker, "collection_worker_lock", forbidden)
    monkeypatch.setattr(worker, "load_config", lambda: SimpleNamespace(db_backend="postgres"))
    blocks = []
    monkeypatch.setattr(worker, "get_active_collection_block", lambda: blocks[-1] if blocks else None)
    monkeypatch.setattr(worker, "activate_collection_block", lambda **kw: blocks.append(kw) or kw)
    attempts = []
    def load():
        attempts.append("store")
        if failure == "store":
            raise OSError("synthetic-only-password!")
        return store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!")
    def rejected(*args):
        attempts.append("rpc")
        raise OSError(1326, "synthetic-only-password!")
    monkeypatch.setattr(store, "load_credentials", load)
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", rejected)
    result = worker.preflight_windows_collection_context(server="DC1", worker_id="offline-worker")
    assert result["status"] == "failed"
    assert len(blocks) == 1
    assert "synthetic-only-password!" not in repr(result)
    prior = list(attempts)
    # Even a directly restarted worker cannot use its old auto-recovery path
    # to repeat authentication after a terminal credential failure.
    repeated = worker.preflight_windows_collection_context(server="DC1", worker_id="offline-worker")
    assert repeated["status"] == "failed"
    assert attempts == prior
    assert worker.run_cycle(hours=1, max_events=5, wait_seconds=1)["status"] == "blocked"
    if failure in {"mode", "powershell"}:
        assert attempts == []


def test_collection_composition_passes_mode_to_pilot_and_stops_other_dcs(monkeypatch):
    import subprocess
    from server.jobs import collector
    monkeypatch.setenv(MODE_KEY, DPAPI)
    monkeypatch.setattr(collector, "_scheduler_canary_config", lambda: {"enabled": False, "archive_enabled": False})
    monkeypatch.setattr(collector, "get_adaptive_plan_for_server", lambda server: SimpleNamespace(
        channels=["Security"], channel_limits={"Security": 5}, channel_timeouts={"Security": 5},
        recovery_mode=False, reason="offline"))
    monkeypatch.setattr(collector, "log_event", lambda *a, **k: None)
    commands = []
    monkeypatch.setattr(collector, "_run_subprocess_live", lambda command, *a, **k: commands.append(command) or subprocess.CompletedProcess(command, 0))
    collector._run_single_server_collection("DC1", 1, 5)
    assert commands[0][commands[0].index("--ad-source-credential-mode") + 1] == DPAPI
    seen = []
    monkeypatch.setattr(collector, "PARALLEL_DC_WORKERS", 4)
    monkeypatch.setattr(collector, "_collect_server_once", lambda job, server, *a: seen.append(server) or (
        server, subprocess.CompletedProcess([], 74), 0, "", "windows_event_log_authentication_failed"))
    results = collector._collect_servers_parallel(7, ["DC1", "DC2"], 1, 5)
    assert seen == ["DC1"]
    assert len(results) == 1


@pytest.mark.parametrize(("mode", "backend", "expected"), [(DPAPI, "python", 74), (DPAPI, "powershell", 74), ("invalid-private-value", "python", 74)])
def test_pilot_mode_composition_fails_closed_without_secret_transport(monkeypatch, tmp_path, capsys, mode, backend, expected):
    import subprocess
    from scripts import run_dc_log_pilot as pilot
    monkeypatch.setattr(pilot.sys, "argv", ["run_dc_log_pilot.py", "--server", "DC1", "--connect-address", "dc1.example.test",
        "--collector-backend", backend, "--ad-source-credential-mode", mode, "--raw-root", str(tmp_path), "--no-technical-report"])
    for name in ("log_event", "log_internal_error", "log_performance_stage"):
        monkeypatch.setattr(pilot, name, lambda *a, **k: None)
    monkeypatch.setattr(pilot, "runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(pilot, "python_collector_available", lambda: (True, "offline"))
    monkeypatch.setattr(pilot, "validate_adapter_for_channels", lambda *a: [])
    commands = []
    monkeypatch.setattr(pilot, "run_command", lambda cmd, **kw: commands.append(cmd) or subprocess.CompletedProcess(cmd, 74, "", ""))
    assert pilot.main() == expected
    if backend == "python" and mode == DPAPI:
        assert commands[0][commands[0].index("--ad-source-credential-mode") + 1] == DPAPI
    else:
        assert commands == []
    assert "invalid-private-value" not in capsys.readouterr().err


def test_explicit_recovery_probe_uses_same_dpapi_identity_and_reverse_query(monkeypatch, capsys):
    from scripts.maintenance import collection_block_control as control
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store
    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!"))
    calls, reads = [], []
    handle = SimpleNamespace(Close=lambda: calls.append("closed"))
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: calls.append(a) or handle)
    monkeypatch.setattr(events, "probe_latest_record_id", lambda *a, **k: reads.append(k) or 1)
    assert control._internal_probe("DC1", ad_source_credential_mode=DPAPI) == 0
    assert calls[0][0][:3] == ("dc1.example.test", "Collector", "TEST")
    assert calls[-1] == "closed"
    assert reads == [{"timeout_ms": 5000}]
    assert "synthetic-only-password!" not in capsys.readouterr().out


@pytest.mark.parametrize("mode", [None, "invalid-private-value", DPAPI])
def test_recovery_requires_explicit_valid_mode_for_credential_blocks(monkeypatch, capsys, mode):
    import subprocess
    from scripts.maintenance import collection_block_control as control
    from server.sli.sources import collection_runtime_block as block
    argv = ["collection_block_control.py", "--probe-server", "DC1", "--confirm", control.CONFIRMATION]
    if mode is not None:
        argv += ["--ad-source-credential-mode", mode]
    monkeypatch.setattr(control.sys, "argv", argv)
    monkeypatch.setattr(block, "get_active_collection_block", lambda: {"reason_code": "ad_source_credentials_unavailable"})
    commands, clears = [], []
    monkeypatch.setattr(control.subprocess, "run", lambda command, **kw: commands.append(command) or subprocess.CompletedProcess(command, 0, '{"status":"ok"}', ''))
    monkeypatch.setattr(block, "record_probe_and_clear", lambda **kw: clears.append(kw) or {"clear_outcome": "cleared"})
    assert control.main() == (0 if mode == DPAPI else 2)
    if mode == DPAPI:
        assert commands[0][commands[0].index("--ad-source-credential-mode") + 1] == DPAPI
        assert len(clears) == 1
    else:
        assert commands == [] and clears == []
    output = capsys.readouterr()
    assert "invalid-private-value" not in output.out + output.err


@pytest.mark.parametrize("session_id", [0, 7])
def test_local_identity_decodes_oem_cyrillic_without_weakening_session_guard(monkeypatch, session_id):
    import ctypes
    from server.sli.sources import windows_runtime_identity as identity
    principal = "ТЕСТ-ПК\\оператор"
    monkeypatch.setenv("USERDOMAIN", "SYNTHETIC")
    monkeypatch.setattr(identity.getpass, "getuser", lambda: "fallback-not-authority")
    sid = "S-1-5-21-1-2-3-1000"
    raw = f'"{principal}","{sid}"\r\n'.encode("cp866")
    observed = []
    def whoami(command, **kwargs):
        observed.append(kwargs)
        # Model a Cyrillic Windows OEM pipe while Python defaults to UTF-8.
        encoding = "cp866" if kwargs.get("encoding") == "oem" else "utf-8"
        return SimpleNamespace(returncode=0, stdout=raw.decode(encoding))
    def process_session(pid, pointer):
        pointer._obj.value = session_id
        return 1
    monkeypatch.setattr(identity.subprocess, "run", whoami)
    monkeypatch.setattr(identity.os, "name", "nt")
    monkeypatch.setattr(ctypes, "windll", SimpleNamespace(
        kernel32=SimpleNamespace(WTSGetActiveConsoleSessionId=lambda: 7, ProcessIdToSessionId=process_session),
        shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0)), raising=False)
    result = identity.verify_collection_identity(expected_principal=principal, expected_sid=sid)
    assert result["current_principal"] == principal
    assert result["current_sid"] == sid
    assert result["status"] == ("ok" if session_id else "failed")
    assert result["interactive"] is bool(session_id)
    assert observed[0]["errors"] == "strict"


@pytest.mark.parametrize("stage", ["cursor_probe", "query", "post_probe"])
@pytest.mark.parametrize("code", [5, 1326])
def test_dpapi_query_auth_failure_never_falls_back_or_probes_again(monkeypatch, tmp_path, stage, code):
    from scripts.collect import collect_windows_events as events
    from server.sli.sources import ad_source_credentials as store
    monkeypatch.setattr(store, "load_credentials", lambda: store.AdSourceCredentials("TEST\\Collector", "synthetic-only-password!"))
    monkeypatch.setattr(events.win32evtlog, "EvtOpenSession", lambda *a: object())
    probes, queries = [], []
    def probe(*args):
        probes.append(True)
        if stage == "cursor_probe" or (stage == "post_probe" and len(probes) == 2):
            raise OSError(code, "synthetic-only-password!")
        return {"latest_record_id": 2, "oldest_record_id": 1, "generation_identity": "synthetic-generation"}
    def query(*args):
        queries.append(True)
        if stage == "query":
            raise OSError(code, "synthetic-only-password!")
        return object()
    monkeypatch.setattr(events, "probe_channel_state", probe)
    monkeypatch.setattr(events, "query_events", query)
    monkeypatch.setattr(events, "next_event_batch", lambda *a: [])
    result = events.collect_channel(computer_name="dc1.example.test", source_name="DC1", channel="Security",
        out_file=tmp_path / "Security.jsonl", start_time_utc="2026-01-01T00:00:00+00:00",
        after_record_id=1, saved_channel_generation_identity="synthetic-generation", max_events=5,
        timeout_seconds=5, collect_message=False, progress_every=5, ad_source_credential_mode=DPAPI)
    assert result["retryable"] is False
    assert result["cursor_commit_allowed"] is False
    assert "synthetic-only-password!" not in repr(result)
    assert len(probes) == (2 if stage == "post_probe" else 1)
    assert len(queries) == (0 if stage == "cursor_probe" else 1)


def test_pilot_terminal_result_activates_durable_block_before_import(monkeypatch, tmp_path):
    import subprocess
    from scripts import run_dc_log_pilot as pilot
    from server.sli.sources import collection_runtime_block as block
    output = tmp_path / "synthetic-batch"
    output.mkdir()
    (output / "collection-summary.json").write_text(json.dumps({"channels": [{
        "channel": "Security", "count": 0, "status": "failed",
        "failure_code": "windows_event_log_authentication_failed",
    }]}), encoding="utf-8")
    monkeypatch.setattr(pilot.sys, "argv", ["run_dc_log_pilot.py", "--server", "DC1", "--connect-address", "dc1.example.test",
        "--collector-backend", "python", "--ad-source-credential-mode", DPAPI, "--no-technical-report"])
    for name in ("log_event", "log_internal_error", "log_performance_stage", "record_collector_runs", "update_adaptive_state_from_summary"):
        if hasattr(pilot, name):
            monkeypatch.setattr(pilot, name, lambda *a, **k: None)
    monkeypatch.setattr(pilot, "runtime_db_backend", lambda: "postgres")
    monkeypatch.setattr(pilot, "python_collector_available", lambda: (True, "offline"))
    monkeypatch.setattr(pilot, "validate_adapter_for_channels", lambda *a: [])
    monkeypatch.setattr(pilot, "run_command", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 74, f"Collection output: {output}\n", ""))
    monkeypatch.setattr(pilot, "run_import_for_backend", forbidden)
    blocks = []
    monkeypatch.setattr(block, "activate_collection_block", lambda **kw: blocks.append(kw) or kw)
    assert pilot.main() == 74
    assert blocks[0]["reason_code"] == "windows_event_log_authentication_failed"
    assert (output / "collection-blocked.json").exists()
