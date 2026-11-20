from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_registered_sources_reuse_current_ad_computer_inventory(monkeypatch) -> None:
    from server.sli.core import database

    monkeypatch.setattr(database, "query_rows", lambda *args, **kwargs: [
        {
            "hostname": "DC1",
            "fqdn": None,
            "role": "domain_controller",
            "is_active": True,
            "os_name": None,
            "os_version": None,
            "domain_fqdn": "example.test",
            "netbios_name": "EXAMPLE",
            "site_name": "Site-1",
        },
        {
            "hostname": "DC2",
            "fqdn": None,
            "role": "domain_controller",
            "is_active": True,
            "os_name": None,
            "os_version": None,
            "domain_fqdn": "example.test",
            "netbios_name": "EXAMPLE",
            "site_name": "Site-1",
        },
    ])
    monkeypatch.setattr(database, "_configured_source_addresses", lambda: {
        "dc1": ["192.0.2.10"],
        "dc2": ["192.0.2.11"],
    })
    monkeypatch.setattr(database, "query_rows_bounded", lambda *args, **kwargs: [
        {
            "display_key": "dc1",
            "sam_key": "dc1",
            "dns_key": "dc1",
            "fqdn": "dc1.example.test",
            "os_name": "Windows Server",
            "os_version": "10.0",
            "last_observed_at_utc": "2026-07-26T03:00:00Z",
        },
        {
            "display_key": "dc2",
            "sam_key": "dc2",
            "dns_key": "dc2",
            "fqdn": "dc2.example.test",
            "os_name": "Windows Server",
            "os_version": "10.0",
            "last_observed_at_utc": "2026-07-26T03:00:00Z",
        },
    ])

    sources = database.get_sources()

    assert [(item["hostname"], item["fqdn"]) for item in sources] == [
        ("DC1", "dc1.example.test"),
        ("DC2", "dc2.example.test"),
    ]
    assert all(item["os_name"] == "Windows Server" for item in sources)
    assert all(item["inventory_source"] == "ad_context" for item in sources)
    assert sources[0]["ip_addresses"] == ["192.0.2.10"]


def test_source_inventory_parses_bounded_disk_rows_and_rejects_invalid_values() -> None:
    from server.sli.core.database import _finalize_source_inventory

    result = _finalize_source_inventory(
        {
            "hostname": "DC1",
            "ip_addresses": ["192.0.2.10", "not-an-ip"],
            "logical_disks": [
                "C:|107374182400|53687091200",
                "D:|1000|100",
                "bad|100|50",
                "E:|10|20",
            ],
            "technical_inventory_status": "complete",
        },
        ["192.0.2.10", "2001:db8::10"],
    )

    assert result["ip_addresses"] == ["192.0.2.10", "2001:db8::10"]
    assert result["disks"] == [
        {
            "name": "C:",
            "total_bytes": 107374182400,
            "free_bytes": 53687091200,
            "free_percent": 50.0,
        },
        {
            "name": "D:",
            "total_bytes": 1000,
            "free_bytes": 100,
            "free_percent": 10.0,
        },
    ]
    assert result["disk_state"] == "warning"


@pytest.mark.windows_only
def test_domain_posture_module_exposes_eight_bounded_fixture_contracts() -> None:
    powershell = (
        Path(os.environ.get("WINDIR") or r"C:\Windows")
        / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    )
    module = ROOT / "scripts" / "ad_context" / "DomainPosture.psm1"
    command = (
        f"Import-Module '{module}' -Force; "
        "@(Get-SLIDomainPostureContract -DomainDn 'DC=example,DC=local') "
        "| ConvertTo-Json -Depth 8 -Compress"
    )

    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=ROOT, capture_output=True, text=True, timeout=60, check=True,
    )
    checks = json.loads(completed.stdout)

    assert [item["key"] for item in checks] == [
        "domain_password_policy",
        "dcsync_domain_dacl",
        "delegation",
        "user_service_principal_names",
        "kerberos_preauth_disabled",
        "sid_history",
        "domain_trusts",
        "domain_controllers",
    ]
    assert all(item["ldap_base"] == "DC=example,DC=local" for item in checks)
    assert all(item["time_limit_seconds"] > 0 for item in checks)
    assert all(item["record_limit"] > 0 for item in checks)
    assert all(item["response_bytes_limit"] > 0 for item in checks)
    dcsync = next(item for item in checks if item["key"] == "dcsync_domain_dacl")
    assert dcsync["search_scope"] == "Base"
    assert dcsync["attributes"] == [
        "objectGUID", "objectSid", "distinguishedName", "nTSecurityDescriptor",
    ]
    assert dcsync["security_descriptor_dacl"] is True


def test_running_exporter_has_no_path_to_domain_posture_module() -> None:
    exporter = (
        ROOT / "scripts" / "ad_context" / "Export-AdAuditContextBundle.ps1"
    ).read_text(encoding="utf-8")
    module = (
        ROOT / "scripts" / "ad_context" / "DomainPosture.psm1"
    ).read_text(encoding="utf-8")

    assert "DomainPosture.psm1" not in exporter
    assert "Invoke-SLIDomainPostureRead" not in exporter
    for prohibited in ("Set-AD", "New-AD", "Remove-AD", "Enable-AD", "Disable-AD"):
        assert prohibited not in module
