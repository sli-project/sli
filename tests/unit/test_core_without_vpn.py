"""Hermetic registration and API smoke coverage for an omitted VPN package."""
from __future__ import annotations

from dataclasses import replace
import importlib.abc
import os
from pathlib import Path
import subprocess
import sys

import pytest

from server.sli.plugins import registry as plugins

ROOT = Path(__file__).resolve().parents[2]


def _hide_vpn(monkeypatch):
    discovered = tuple(
        entry for entry in plugins.discover_plugins() if entry[0] != "sli.remote-access"
    )
    monkeypatch.setattr(plugins, "discover_plugins", lambda: discovered)
    plugins.registered_plugins.cache_clear()


@pytest.fixture
def without_vpn(monkeypatch):
    _hide_vpn(monkeypatch)
    yield
    plugins.registered_plugins.cache_clear()


def test_absent_vpn_preserves_ad_normalizer(without_vpn):
    from server.source_packs.normalizers import get_source_normalizer

    assert plugins.plugin_installed("sli.ad")
    assert not plugins.plugin_installed("sli.remote-access")
    normalizer = get_source_normalizer("windows-ad-dc-v1")
    assert normalizer is not None
    assert normalizer.event_ids_for_analysis_family("successful_logon") == (4624,)
    assert get_source_normalizer("windows-nps-radius-v1") is None


def test_missing_registration_has_no_executable_contributions(without_vpn):
    assert not plugins.plugin_installed("sli.remote-access")
    assert plugins.plugin_hook("sli.remote-access", "configured") is None
    for hook in ("nps_agent_policy", "nps_agent_rows", "import_nps_agent_packet", "run_accounting_import_once"):
        assert plugins.plugin_hook("sli.remote-access", hook) is None
    assert plugins.call_plugin("sli.remote-access", "get_vpn_session_report")["state"] == "not_installed"
    with pytest.raises(RuntimeError, match="plugin_not_installed"):
        plugins.require_plugin("sli.remote-access", "load_radius_collection_routes")
    with pytest.raises(ValueError, match="handler_version_unavailable"):
        plugins.plugin_job_handlers("sli.remote-access", "radius-session-observation")


@pytest.mark.parametrize("module", ["sli.vpn-nps", "sli.radius-accounting"])
def test_absent_vpn_rejects_agent_assignment_before_database_access(without_vpn, module):
    from server.sli.agents import assignments, policies
    from server.sli.agents.ca import AgentError

    body = {"module_id": module, "enabled": True, "config": {}}
    with pytest.raises(AgentError, match="^invalid_agent_module_assignment$"):
        assignments.validate_assignment(body, "fixture-host")
    with pytest.raises(AgentError, match="^invalid_agent_module_assignment$"):
        policies.assign_module(None, body, actor="fixture-actor")


@pytest.mark.parametrize("module", ["sli.vpn-nps", "sli.radius-accounting"])
def test_absent_vpn_rejects_agent_ingress_without_receipt_or_publication(without_vpn, module):
    from cryptography.hazmat.primitives.asymmetric import ec
    from server.sli.agent_ingest import receive_packet
    from sli_agent.envelope import make_packet
    from sli_agent.modules import HeartbeatModule
    from tests.unit.test_agent_ingest import AGENT, HOST, NOW, Ledger

    key = ec.generate_private_key(ec.SECP256R1())
    sample = replace(HeartbeatModule(HOST).collect(now=NOW), module_id=module)
    value = make_packet(key, agent_id=AGENT, sequence=1, sample=sample, now=NOW)
    ledger = Ledger()
    identity = {"id": AGENT, "host_id": HOST, "assigned_modules": [
        {"module_id": module, "enabled": True, "config": {}}]}
    receipt = receive_packet(ledger, identity=identity, public_key=key.public_key(), value=value, now=NOW)
    assert receipt["error_code"] == "agent_nps_packet_invalid"
    assert receipt["committed_cursor"] is None
    assert not ledger.rows and not ledger.imports


def test_absent_vpn_keeps_agent_projection_pending_without_database_access(without_vpn):
    from server.sli.agents.consumer import PacketPending, dispatch_packet

    with pytest.raises(PacketPending, match="^agent_plugin_not_installed$"):
        dispatch_packet(None, [], packet={}, envelope={"module_id": "sli.vpn-nps"})


def test_discovery_requires_manifest_and_package_file(monkeypatch):
    actual = Path.is_file
    entry = ROOT / "server/sli/plugins/remote_access/registration.py"
    manifest = ROOT / "config/plugin_packages/v3/sli.remote-access.json"
    vpn_entry = ("sli.remote-access", plugins.BUNDLED["sli.remote-access"])
    discovered = set(plugins.discover_plugins())
    assert vpn_entry in discovered
    for hidden in (entry, manifest):
        monkeypatch.setattr(Path, "is_file", lambda path, hidden=hidden: path != hidden and actual(path))
        # Omitting VPN must preserve independently installed packages such as AD.
        assert set(plugins.discover_plugins()) == discovered - {vpn_entry}


def test_present_plugin_registers_reports_jobs_and_preserves_calls(monkeypatch):
    from server.sli.plugins.remote_access import registration
    from server.sli.reports import vpn_session_reporting
    from server.sli.reporting.v2.reports import vpn_audit, vpn_connections

    contribution = plugins.Contributions()
    registration.register(contribution)
    assert contribution.hooks["reports"]() == (vpn_audit.REPORT, vpn_connections.REPORT)
    assert set(contribution.jobs) == {"radius-acquisition", "radius-session-observation"}
    expected = {"state": "partial", "items": [{"source": "synthetic-source"}]}
    calls = []

    def report(*args, **kwargs):
        calls.append((args, kwargs))
        return expected

    monkeypatch.setattr(vpn_session_reporting, "get_vpn_session_report", report)
    assert contribution.hooks["get_vpn_session_report"]({}, source_domain_id=7) is expected
    assert calls == [(({},), {"source_domain_id": 7})]
    stage, _ = contribution.jobs["radius-acquisition"]
    assert stage(None, {"handler_id": "radius-acquisition", "result_contract": "synthetic.v1"})["coverage_state"] == "not_collected"


def test_plugin_normalizer_identity_and_reserved_id_are_preserved():
    from server.source_packs.normalizers import get_source_normalizer, register_source_normalizer

    normalizer = get_source_normalizer("windows-nps-radius-v1")
    assert normalizer is not None
    assert get_source_normalizer("windows-nps-radius-v1") is normalizer
    with pytest.raises(ValueError, match="reserved"):
        register_source_normalizer(replace(normalizer, event_label=lambda *args: "synthetic"))


def test_absent_vpn_does_not_observe_configuration_or_read_its_tables(without_vpn, monkeypatch):
    from server.sli.core import setup_status
    from server.sli.sources import plugin_state
    from server.sli.reports import account_revocation_reporting
    from server.sli.semantic import investigation_cases
    from server.api.routes import investigations

    def unexpected(*args, **kwargs):
        raise AssertionError("absent plugin must not read a source or database")

    monkeypatch.setattr(setup_status.database, "query_rows", unexpected)
    monkeypatch.setattr(plugin_state, "list_plugin_states", unexpected)
    assert plugin_state.remote_access_configured() is False
    assert plugin_state.report_plugin_state("vpn.audit")["state"] == "not_installed"
    pack = {"pack_id": "sli.windows.vpn-radius", "source_kind": "event"}
    assert setup_status._source_configuration(pack, None, None, None) is None
    assert setup_status._source_data(pack, [{"source_instance_id": "synthetic-source"}]) == {}
    assert account_revocation_reporting._read_sessions(
        None, domain_id=7, start=None, end=None, sids=["synthetic-sid"],
    ) == ([], "not_installed", False)
    assert not investigation_cases._vpn_session_exists(None, source_domain_id=7, session_row_id="synthetic-session")
    assert not investigations.plugin_evidence_allowed({}, source_domain_id=7)
    from server.sli.reporting import ui_operations
    from server.sli.sources import plugin_management

    assert ui_operations._radius_vpn_operations_view()["status"] == "not_installed"
    assert plugin_management._default_radius_loader()["status"] == "not_installed"


def test_absent_vpn_does_not_register_or_enable_pilot_jobs(without_vpn, monkeypatch):
    from server.sli.core import job_executor, job_registry

    monkeypatch.setenv(job_executor.FLAG, "1")
    monkeypatch.setenv("SLI_CORE_JOB_AD_GPO_PILOT", "0")
    assert not job_executor.pilot_enabled()
    assert not any(manifest["plugin_id"] == "sli.remote-access" for manifest in job_registry.pilot_registry().manifests)
    from scripts.runtime import collection_worker

    monkeypatch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
    assert collection_worker.run_nps_stage(dc_servers=[], max_events=1, heartbeat_callback=None)["status"] == "not_installed"


def test_absent_vpn_rejects_nps_session_before_credentials_or_rpc(without_vpn, monkeypatch):
    from types import SimpleNamespace
    from scripts.collect import collect_windows_events as collector
    from server.sli.sources import ad_source_auth

    def unexpected(*args, **kwargs):
        raise AssertionError("absent plugin must not load credentials or contact a source")

    monkeypatch.setattr(ad_source_auth, "load_ad_source_login", unexpected)
    monkeypatch.setattr(collector, "win32evtlog", SimpleNamespace(EvtOpenSession=unexpected))
    with pytest.raises(RuntimeError, match="^plugin_not_installed$"):
        collector.open_remote_session(
            "synthetic-source", ad_source_credential_mode="dpapi_current_user", nps_continuous=True,
        )


def test_absent_vpn_rejects_nps_cli_before_collection(without_vpn, monkeypatch, tmp_path, capsys):
    from scripts.collect import collect_windows_events as collector

    monkeypatch.setattr(collector, "collect_channel", lambda **_: pytest.fail("source collection must not start"))
    monkeypatch.setattr(sys, "argv", [
        "collect_windows_events.py", "--nps-continuous", "--computer-name", "synthetic-source",
        "--source-name", "synthetic-source", "--ad-source-credential-mode", "dpapi_current_user",
        "--channels", "Security", "--start-time-utc", "2026-09-09T00:00:00Z",
        "--end-time-utc", "2026-09-09T01:00:00Z", "--event-ids-json", "[6272,6273]",
        "--max-events-per-channel", "50000", "--channel-timeout-seconds", "60",
        "--output-root", str(tmp_path),
    ])

    assert collector.main() == 12
    assert "continuous_nps_admission_failed: plugin_not_installed" in capsys.readouterr().err
    assert not list(tmp_path.iterdir())


def core_without_vpn_smoke():
    """Run in a fresh interpreter: cached plugin modules cannot hide coupling."""
    from tests.tooling.test_core_does_not_import_vpn import vpn_module

    class HideVpn(importlib.abc.MetaPathFinder):
        def find_spec(self, fullname, path=None, target=None):
            if vpn_module(fullname):
                raise AssertionError(f"core imported excluded VPN implementation: {fullname}")
            return None

    class Handler:
        def __init__(self, access):
            self.access = access
            self.sent = None

        def _access_decision(self):
            return self.access

        def _send_json(self, payload, status=200):
            self.sent = (payload, int(status))

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("ADLOG_REPORT_DOMAIN_FQDN", "example.test")
        patch.setenv("ADLOG_DB_BACKEND", "postgres")
        _hide_vpn(patch)
        sys.meta_path.insert(0, HideVpn())
        import psycopg

        def no_database(*args, **kwargs):
            raise AssertionError("smoke test must not use a real database")

        patch.setattr(psycopg, "connect", no_database)
        from server.api import http_server
        from server.api.routes import reports_v2
        from server.sli.agents import collection_health
        from server.sli.core import job_registry
        from server.sli.reporting import navigation_registry
        from server.sli.reporting.v2 import registry
        from server.sli.reporting.v2.definition import result
        from server.source_packs import registry as sources
        from server.source_packs.normalizers import get_source_normalizer
        from scripts.runtime import collection_worker
        from scripts import run_dc_log_pilot
        from sli_agent.modules import configured_modules
        from types import SimpleNamespace

        patch.setattr(collection_health, "query_rows_bounded", lambda *args, **kwargs: [])
        health = collection_health.get_agent_collection_health()
        assert health["state"] == "unknown"
        assert health["items"] == []
        assert health["active_agents"] == health["current_agents"] == 0

        assert [module.module_id for module in configured_modules(
            SimpleNamespace(collection_enabled=False), "fixture-host")] == ["sli.heartbeat"]

        patch.setenv("ADLOG_NPS_EVENTLOG_ENABLED", "1")
        assert collection_worker.run_nps_stage(dc_servers=[], max_events=1, heartbeat_callback=None)["status"] == "not_installed"
        assert callable(run_dc_log_pilot.load_radius_collection_routes)

        app = http_server.create_app()
        definitions = registry.registered_reports()
        assert definitions and not any(item.key.startswith("vpn.") for item in definitions)
        assert all(manifest["plugin_id"] != "sli.remote-access" for manifest in job_registry.pilot_registry().manifests)
        assert sources.get_source_pack("sli.windows.vpn-radius") is None
        assert sources.get_source_pack("sli.windows.ad-dc") is not None
        assert get_source_normalizer("windows-nps-radius-v1") is None
        assert get_source_normalizer("windows-ad-dc-v1") is not None
        patch.setattr(navigation_registry, "list_plugin_states", lambda: [])
        decision = {"reports": [{"report_key": "vpn.audit", "allowed": True, "allowed_actions": ["view"]}]}
        assert "sli.remote-access" not in navigation_registry.navigation(decision)["enabled_plugins"]
        assert registry.get_report("vpn.connections") is None

        # Keep the real core declaration, API parsing and projection. Only its
        # data/options producers are faked so the smoke needs no PostgreSQL.
        report = registry.get_report("security.events.chains")
        assert report is not None
        fake = replace(report, options=None, query=lambda context: result(report, state="not_collected"))
        original = reports_v2.get_report
        patch.setattr(reports_v2, "get_report", lambda key: fake if key == report.key else original(key))
        patch.setattr(reports_v2, "validate_storage_route_authorization", lambda *args: None)
        decision["reports"].append({
            "report_key": report.access.report_key, "allowed": True, "allowed_actions": ["view"],
            "grants": [{"allowed_actions": ["view"], "field_categories": sorted(report.access.required_fields),
                        "scope": {"kind": "domain", "ids": [7]}}],
        })
        decision["capabilities"] = ["events.view", *getattr(report.access, "required_capabilities", ())]
        handler = Handler(decision)
        assert app.dispatch_get(handler, "/api/v2/reports", {})
        assert any(item["key"] == report.key for item in handler.sent[0]["items"])
        assert app.dispatch_get(handler, f"/api/v2/reports/{report.key}", {})
        assert handler.sent[1] == 200 and handler.sent[0]["key"] == report.key
        assert app.dispatch_get(handler, f"/api/v2/reports/{report.key}/data", {"domain": ["7"]})
        assert handler.sent[1] == 200 and handler.sent[0]["state"] == "not_collected"
        for path in (
            "/api/v2/reports/vpn.connections/data", "/api/v2/reports/vpn.accounts",
            "/api/v1/reports/vpn.audit/sessions", "/api/v1/reports/vpn.audit/windows-authentication",
            "/api/v1/reports/vpn.audit/data",
        ):
            assert app.dispatch_get(handler, path, {})
            assert handler.sent[1] == 200 and handler.sent[0]["state"] == "not_installed"
        handler = Handler({})
        assert app.dispatch_get(handler, "/api/v2/reports/vpn.connections/data", {})
        assert handler.sent[1] == 403
        assert not any(vpn_module(name) for name in sys.modules)


def test_core_application_starts_and_serves_reports_with_vpn_hidden():
    executable = os.environ.get("SLI_TEST_PYTHON", sys.executable)
    completed = subprocess.run(
        [executable, "-c", "from tests.unit.test_core_without_vpn import core_without_vpn_smoke; core_without_vpn_smoke()"],
        cwd=ROOT, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
