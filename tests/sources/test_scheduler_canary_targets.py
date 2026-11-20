from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def test_dc_connect_map_env_rejects_endpoint_override(monkeypatch) -> None:
    monkeypatch.setenv("ADLOG_DC_CONNECT_MAP", "DC1=192.0.2.19;DC2=192.0.2.20")
    import server.sli.sources.dc_discovery as dc_discovery

    dc_discovery = importlib.reload(dc_discovery)
    with pytest.raises(dc_discovery.DomainControllerConfigurationError, match="Environment DC endpoint override"):
        dc_discovery.resolve_domain_controller_connect_address("DC1")


def test_domain_controller_example_config_file_uses_fqdn_targets() -> None:
    text = Path("config/domain_controllers.example.json").read_text(encoding="utf-8")
    assert '"hostname": "DC1"' in text
    assert '"connect_address": "dc1.example.test"' in text
    assert '"owner_confirmed_ip": "198.51.100.23"' in text
    assert '"hostname": "DC2"' in text
    assert '"connect_address": "dc2.example.test"' in text
    assert '"owner_confirmed_ip": "198.51.100.24"' in text


def test_collector_exposes_scheduler_canary_and_targets() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    assert "def _scheduler_canary_config" in text
    assert "scheduler_canary_enabled" in text
    assert "domain_controller_targets" in text
    assert "ADLOG_CANARY_ARCHIVE" in text
    assert "command.append(\"--archive\")" in text


def test_scheduler_command_has_single_collection_mode_argument() -> None:
    text = Path("server/jobs/collector.py").read_text(encoding="utf-8")
    function = text.split("def _run_single_server_collection", 1)[1].split("def _run_subprocess_live", 1)[0]
    assert function.count('"--collection-mode"') == 1


def test_toolkit_does_not_offer_canary_actions_while_collection_is_stopped() -> None:
    text = Path("tools/adlog-tool.ps1").read_text(encoding="utf-8")
    assert "pg-canary-scheduler-start" not in text
    assert "pg-canary-scheduler-stop" not in text
    assert "ADLOG_SCHEDULER_CANARY" not in text
    assert "ADLOG_CANARY_MAX_EVENTS" not in text
