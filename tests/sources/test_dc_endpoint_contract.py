from __future__ import annotations

import json
import subprocess


CHANNELS = [
    "Security",
    "System",
    "Directory Service",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "DNS Server",
]


def test_configured_dc_endpoints_use_fqdn_and_confirmed_dns_readback(
    monkeypatch, tmp_path
) -> None:
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {
                        "hostname": "DC1",
                        "connect_address": "dc1.example.test",
                        "owner_confirmed_ip": "198.51.100.23",
                    },
                    {
                        "hostname": "DC2",
                        "connect_address": "dc2.example.test",
                        "owner_confirmed_ip": "198.51.100.24",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    targets = dc_discovery.get_configured_domain_controller_targets()

    assert targets == [
        {
            "hostname": "DC1",
            "connect_address": "dc1.example.test",
            "owner_confirmed_ip": "198.51.100.23",
        },
        {
            "hostname": "DC2",
            "connect_address": "dc2.example.test",
            "owner_confirmed_ip": "198.51.100.24",
        },
    ]
    assert dc_discovery.verify_configured_domain_controller_dns_readback(
        resolver=lambda hostname: (
            hostname,
            [],
            ["198.51.100.23"] if hostname.startswith("dc1") else ["198.51.100.24"],
        )
    ) == targets


def test_stale_ip_literal_endpoint_is_rejected_before_collection(monkeypatch, tmp_path) -> None:
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {"hostname": "DC1", "connect_address": "192.0.2.19"},
                    {"hostname": "DC2", "connect_address": "192.0.2.20"},
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    try:
        dc_discovery.get_configured_domain_controller_targets()
    except dc_discovery.DomainControllerConfigurationError as exc:
        assert "IP literal" in str(exc)
    else:
        raise AssertionError("literal stale DC endpoints must fail closed")


def test_bare_hostname_endpoint_is_rejected_before_collection(monkeypatch, tmp_path) -> None:
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {"domain_controllers": [{"hostname": "DC1", "connect_address": "DC1"}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    try:
        dc_discovery.get_configured_domain_controller_targets()
    except dc_discovery.DomainControllerConfigurationError as exc:
        assert "FQDN" in str(exc)
    else:
        raise AssertionError("bare DC endpoint must fail closed")


def test_environment_endpoint_override_is_rejected(monkeypatch, tmp_path) -> None:
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {
                        "hostname": "DC1",
                        "connect_address": "dc1.example.test",
                        "owner_confirmed_ip": "198.51.100.23",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)
    monkeypatch.setenv("ADLOG_DC_CONNECT_MAP", "DC1=override.example.test")

    try:
        dc_discovery.get_configured_domain_controller_targets()
    except dc_discovery.DomainControllerConfigurationError as exc:
        assert "Environment DC endpoint override" in str(exc)
    else:
        raise AssertionError("environment endpoint override must fail closed")


def test_unconfigured_server_is_rejected_when_endpoint_contract_exists(monkeypatch, tmp_path) -> None:
    from server.sli.sources import dc_discovery

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {"hostname": "DC1", "connect_address": "dc1.example.test"}
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(dc_discovery, "CONFIG_DIR", tmp_path)

    try:
        dc_discovery.resolve_domain_controller_connect_address("DC2")
    except dc_discovery.DomainControllerConfigurationError as exc:
        assert "not configured" in str(exc)
    else:
        raise AssertionError("unconfigured server must not become a connection endpoint")


def test_source_inventory_uses_only_confirmed_dns_readback_ips(monkeypatch, tmp_path) -> None:
    from server.sli.core import database

    (tmp_path / "domain_controllers.json").write_text(
        json.dumps(
            {
                "domain_controllers": [
                    {
                        "hostname": "DC1",
                        "connect_address": "dc1.example.test",
                        "owner_confirmed_ip": "198.51.100.23",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(database, "CONFIG_DIR", tmp_path)

    assert database._configured_source_addresses() == {"dc1": ["198.51.100.23"]}


def test_all_six_channels_receive_one_resolved_endpoint(monkeypatch) -> None:
    from server.jobs import collector

    calls: list[str] = []
    captured: dict[str, object] = {}
    monkeypatch.setattr(
        collector,
        "resolve_domain_controller_connect_address",
        lambda server: calls.append(server) or "dc1.example.test",
    )
    monkeypatch.setattr(
        collector,
        "_scheduler_canary_config",
        lambda: {
            "enabled": True,
            "profile": "endpoint-contract",
            "channels": CHANNELS,
            "max_events_per_channel": 100,
            "requested_max_events_per_channel": 100,
            "hours": 1,
            "channel_timeout_seconds": 30,
            "command_timeout_seconds": 300,
            "collection_mode": "current",
            "archive_enabled": True,
            "max_events_cap": 100,
            "max_events_capped": False,
        },
    )
    monkeypatch.setattr(collector, "_scheduler_skip_report_enabled", lambda: True)
    monkeypatch.setattr(collector, "log_event", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        collector,
        "_run_subprocess_live",
        lambda command, timeout_seconds, **kwargs: captured.update(
            command=command, timeout_seconds=timeout_seconds
        )
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    result = collector._run_single_server_collection("DC1", 1, 100, job_id=7)

    command = list(captured["command"])
    assert result.returncode == 0
    assert calls == ["DC1"]
    assert command[command.index("--connect-address") + 1] == "dc1.example.test"
    assert command[command.index("--channels") + 1].split(",") == CHANNELS


def test_archive_worker_defaults_to_the_shared_fqdn_target_contract(monkeypatch) -> None:
    from scripts.maintenance import pg_archive_worker

    monkeypatch.setattr(
        pg_archive_worker,
        "verify_configured_domain_controller_dns_readback",
        lambda: [
            {"hostname": "DC1", "connect_address": "dc1.example.test"},
            {"hostname": "DC2", "connect_address": "dc2.example.test"},
        ],
    )
    assert pg_archive_worker.parse_targets(None) == {
        "DC1": "dc1.example.test",
        "DC2": "dc2.example.test",
    }


def test_archive_worker_rejects_target_override_outside_shared_contract(monkeypatch) -> None:
    from scripts.maintenance import pg_archive_worker

    monkeypatch.setattr(
        pg_archive_worker,
        "verify_configured_domain_controller_dns_readback",
        lambda: [{"hostname": "DC1", "connect_address": "dc1.example.test"}],
    )
    try:
        pg_archive_worker.parse_targets(["DC1=192.0.2.19"])
    except SystemExit as exc:
        assert "configured FQDN" in str(exc)
    else:
        raise AssertionError("archive worker override must not introduce an IP endpoint")


def test_archive_worker_verifies_dns_before_resolving_targets(monkeypatch) -> None:
    from scripts.maintenance import pg_archive_worker

    calls: list[bool] = []
    monkeypatch.setattr(
        pg_archive_worker,
        "verify_configured_domain_controller_dns_readback",
        lambda: calls.append(True)
        or [{"hostname": "DC1", "connect_address": "dc1.example.test"}],
    )

    assert pg_archive_worker.parse_targets(None) == {"DC1": "dc1.example.test"}
    assert calls == [True]
