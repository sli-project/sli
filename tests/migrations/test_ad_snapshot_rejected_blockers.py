from __future__ import annotations

from datetime import datetime, timezone
from inspect import getsource
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SLOT = "2026-08-31T12:00:00Z"
AD_FAMILIES = (
    "ad_context_base",
    "ad_privileged_membership",
    "ad_vpn_membership",
    "ad_domain_posture",
    "ad_domain_health",
    "ad_gpo_governance",
)
ALL_FAMILIES = set(AD_FAMILIES) | {"users_v2", "computers_v6", "gpo_v2"}


def _descriptor(family: str, source_id: str, marker: str, state: str = "complete") -> dict[str, object]:
    contract = "sli.windows.ad-context" if family.startswith("ad_") else {
        "users_v2": "sli.users-report.v2",
        "computers_v6": "sli.ad-computers.snapshot/2.0",
        "gpo_v2": "sli.ad-gpo.snapshot/1.0",
    }[family]
    return {
        "family": family,
        "contract_id": contract,
        "source_id": source_id,
        "observed_at_utc": "2026-08-31T12:05:00Z",
        "source_state": state,
        "payload_sha256": marker * 64,
        "reason_code": None if state == "complete" else f"{family}_{state}",
    }


@pytest.mark.windows_only  # Requests use an absolute Windows PowerShell executable path.
def test_real_adapter_accepts_all_exact_coordinator_requests(monkeypatch, tmp_path: Path) -> None:
    from scripts.runtime import ad_snapshot_manifest_coordinator_worker as worker
    from server.source_packs.adapters import build_ad_context_command

    monkeypatch.setenv("ADLOG_AD_CONTEXT_POWERSHELL", "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DIRECTORY_SERVER", "dc.example.test")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_DOMAIN", "example.test")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_SEARCH_BASE", "DC=example,DC=test")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_PRIVILEGED_GROUP_SIDS", "S-1-5-21-100-200-300-512,S-1-5-21-100-200-300-519")
    monkeypatch.setenv("ADLOG_AD_CONTEXT_VPN_GROUP_REFERENCES", "VPN-Users,S-1-5-21-100-200-300-1701")
    monkeypatch.setenv("ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_USERS", "40000")
    monkeypatch.setenv("ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_COMPUTERS", "10000")

    commands = {}
    for family in AD_FAMILIES:
        request = worker._collector_request(output=tmp_path / f"{family}.json", run_id="00000000-0000-4000-8000-000000000001", family=family)
        commands[family] = build_ad_context_command(request)

    base = commands["ad_context_base"]
    assert base[base.index("-MaxDirectoryUsers") + 1] == "40000"
    assert base[base.index("-MaxDirectoryComputers") + 1] == "10000"
    assert base[base.index("-PrivilegedGroups") + 1] == ""
    assert base[base.index("-VpnGroups") + 1] == ""
    assert commands["ad_privileged_membership"][commands["ad_privileged_membership"].index("-PrivilegedGroups") + 1] == "S-1-5-21-100-200-300-512,S-1-5-21-100-200-300-519"
    assert commands["ad_vpn_membership"][commands["ad_vpn_membership"].index("-VpnGroups") + 1] == "VPN-Users,S-1-5-21-100-200-300-1701"
    with pytest.raises(ValueError, match="sum"):
        monkeypatch.setenv("ADLOG_AD_SNAPSHOT_MAX_DIRECTORY_USERS", "45000")
        worker._collector_request(output=tmp_path / "bad.json", run_id="00000000-0000-4000-8000-000000000002", family="ad_context_base")


def test_coordinator_reuses_canonical_context_worker_import_connection() -> None:
    source = (ROOT / "scripts/runtime/ad_snapshot_manifest_coordinator_worker.py").read_text(encoding="utf-8")

    assert "_import_connect as ad_context_import_connect" in source
    assert "with ad_context_import_connect() as connection:" in source


def test_coordinator_computers_capture_timestamp_follows_enrichment() -> None:
    source = (ROOT / "scripts/runtime/ad_snapshot_manifest_coordinator_worker.py").read_text(encoding="utf-8")
    persist_computers = source.split("    def persist_computers(", 1)[1].split("    def publish(", 1)[0]

    assert "connection_factory=connect, captured_at=None," in persist_computers
    assert "captured_at=now" not in persist_computers
    assert 'persisted.get("base_inventory_status") != "observed"' in persist_computers


def test_base_computer_rows_supply_every_reference_property_and_filetime() -> None:
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import _computer_rows

    attributes = {
        "display_name": "APP-01",
        "operating_system": "Windows Server 2022 Datacenter",
        "service_principal_names": ["HOST/APP-01", "WSMAN/APP-01"],
        "dns_host_name": "app-01.example.test",
        "last_logon_utc": "2026-08-31T12:34:56.123456Z",
        "operating_system_version": "10.0 (20348)",
        "operating_system_service_pack": "Service Pack 1",
        "enabled": True,
        "canonical_name": "example.test/Servers/APP-01",
        "distinguished_name": "CN=APP-01,OU=Servers,DC=example,DC=test",
        "password_last_set_utc": "2026-08-01T00:00:00Z",
        "created_utc": "2020-01-01T00:00:00Z",
        "when_changed_utc": "2026-08-30T10:00:00Z",
        "description": "Application server",
        "location": "DC-1",
        "managed_by": "CN=Ops,OU=Groups,DC=example,DC=test",
        "user_account_control": 4096,
        "trusted_for_delegation": False,
        "trusted_to_auth_for_delegation": True,
    }
    bundle = {"records": [{
        "section": "directory_accounts",
        "identity": {
            "kind": "ad_computer",
            "object_guid": "00000000-0000-4000-8000-000000000321",
            "object_sid": "S-1-5-21-100-200-300-1101",
        },
        "attributes": attributes,
    }]}

    assert _computer_rows(bundle) == [{
        "Name": "APP-01",
        "OperatingSystem": "Windows Server 2022 Datacenter",
        "ServicePrincipalName": ["HOST/APP-01", "WSMAN/APP-01"],
        "DNSHostName": "app-01.example.test",
        "ObjectGUID": "00000000-0000-4000-8000-000000000321",
        "lastLogonTimestamp": 134326532961234560,
        "OperatingSystemVersion": "10.0 (20348)",
        "OperatingSystemServicePack": "Service Pack 1",
        "Enabled": True,
        "CanonicalName": "example.test/Servers/APP-01",
        "DistinguishedName": "CN=APP-01,OU=Servers,DC=example,DC=test",
        "PasswordLastSet": "2026-08-01T00:00:00Z",
        "whenCreated": "2020-01-01T00:00:00Z",
        "whenChanged": "2026-08-30T10:00:00Z",
        "Description": "Application server",
        "Location": "DC-1",
        "ManagedBy": "CN=Ops,OU=Groups,DC=example,DC=test",
        "SID": "S-1-5-21-100-200-300-1101",
        "userAccountControl": 4096,
        "TrustedForDelegation": False,
        "TrustedToAuthForDelegation": True,
    }]


def test_base_computer_rows_preserve_every_missing_property_as_none() -> None:
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import _computer_rows

    source_states = {"operating_system_service_pack": {
        "state": "absent_in_source", "source_attribute": "OperatingSystemServicePack",
    }}
    bundle = {"records": [{
        "section": "directory_accounts",
        "identity": {"kind": "ad_computer"},
        "attributes": {"computer_reference_attribute_states": source_states},
    }]}

    row = _computer_rows(bundle)[0]

    assert len(row) == 21
    assert all(value is None for value in row.values())
    assert bundle["records"][0]["attributes"]["computer_reference_attribute_states"] == source_states


def test_base_bundle_qualification_allows_only_explicit_nonblocking_partial_reasons() -> None:
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import _qualify_base_bundle

    bundle = {
        "sections": [
            {"name": "directory_accounts", "status": "partial", "error_code": "collection_incomplete"},
            {"name": "directory_group_graph", "status": "complete", "error_code": None},
            {"name": "directory_exact_logon", "status": "complete", "error_code": None},
        ],
        "records": [
            {"record_type": "data_quality", "section": "directory_accounts", "code": "password_expiry_partial"},
        ],
    }

    accepted = _qualify_base_bundle(bundle)

    assert accepted["usable"] is True
    assert accepted["coverage_state"] == "partial"
    for section, blocking_code in (
        ("directory_accounts", "directory_accounts_truncated"),
        ("directory_accounts", "directory_accounts_failed"),
        ("directory_group_graph", "directory_group_graph_truncated"),
        ("directory_group_graph", "directory_group_memberships_truncated"),
        ("directory_group_graph", "directory_group_links_unresolved"),
        ("directory_group_graph", "directory_group_graph_failed"),
        ("directory_exact_logon", "exact_last_logon_users_truncated"),
        ("directory_exact_logon", "exact_last_logon_dc_coverage_partial"),
        ("directory_exact_logon", "directory_exact_logon_failed"),
    ):
        rejected = {
            **bundle,
            "records": [*bundle["records"], {"record_type": "data_quality", "section": section, "code": blocking_code}],
        }
        assert _qualify_base_bundle(rejected)["usable"] is False

    missing_reason = {**bundle, "records": []}
    assert _qualify_base_bundle(missing_reason)["usable"] is False
    spoofed_technical_code = {
        **bundle,
        "records": [*bundle["records"], {"record_type": "data_quality", "section": "directory_accounts", "code": "technical_inventory_fake_unknown"}],
    }
    assert _qualify_base_bundle(spoofed_technical_code)["usable"] is False
    failed_section = {**bundle, "sections": [{**item, "status": "failed"} if item["name"] == "directory_accounts" else item for item in bundle["sections"]]}
    assert _qualify_base_bundle(failed_section)["usable"] is False
    inconsistent_error = {**bundle, "sections": [{**item, "error_code": None} if item["name"] == "directory_accounts" else item for item in bundle["sections"]]}
    assert _qualify_base_bundle(inconsistent_error)["usable"] is False
    falsely_complete = {**bundle, "sections": [{**item, "status": "complete", "error_code": None} if item["name"] == "directory_accounts" else item for item in bundle["sections"]]}
    assert _qualify_base_bundle(falsely_complete)["usable"] is False


def test_one_shot_acquires_every_family_once_and_publishes_truthful_manifest() -> None:
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import run_one_shot

    calls: list[str] = []
    bundles = {family: {"run_id": f"00000000-0000-4000-8000-{index:012d}"} for index, family in enumerate(AD_FAMILIES, 1)}
    published: list[dict[str, object]] = []

    def acquire(family: str) -> dict[str, object]:
        calls.append(family)
        return {
            "bundle": bundles[family],
            "computer_rows": [{"ObjectGUID": "c"}] if family == "ad_context_base" else [],
            "base_complete": family != "ad_context_base" or True,
            "acquisition": {"profile": "ad_snapshot_base_v1", "user_full_queries": 1, "computer_full_queries": 1} if family == "ad_context_base" else {},
        }

    result = run_one_shot(
        slot_start_utc=SLOT,
        domain={"id": 7, "sid": "S-1-5-21-1-2-3", "dns": "example.test"},
        execute=True,
        acquire_ad_family=acquire,
        import_ad_family=lambda bundle, family: _descriptor(
            family, str(bundle["run_id"]), format(AD_FAMILIES.index(family) + 1, "x"),
            "failed" if family == "ad_domain_posture" else "partial" if family == "ad_domain_health" else "complete",
        ),
        persist_users=lambda _: _descriptor("users_v2", "121", "7"),
        persist_computers=lambda rows: calls.append(f"computers:{len(rows)}") or _descriptor("computers_v6", "00000000-0000-4000-8000-000000000101", "8"),
        import_gpo=lambda bundle: _descriptor("gpo_v2", str(bundle["run_id"]), "9"),
        publish=lambda manifest: published.append(manifest) or {"manifest_id": manifest["manifest_id"], "replayed": 0, "readback_verified": True},
        assembled_at_utc="2026-08-31T12:10:00Z",
    )

    assert calls == [*AD_FAMILIES[:1], "computers:1", *AD_FAMILIES[1:]]
    assert {member["family"] for member in published[0]["members"]} == ALL_FAMILIES
    assert set(result["source_hashes"]) == ALL_FAMILIES
    assert set(result["source_ids"]) == ALL_FAMILIES
    assert result["partial_families"] == ["ad_domain_health", "ad_domain_posture"]
    assert result["source_states"]["ad_domain_posture"] == "failed"
    assert result["acquisition"] == {"base_invocations": 1, "privileged_invocations": 1, "vpn_invocations": 1, "posture_invocations": 1, "health_invocations": 1, "gpo_invocations": 1, "user_full_queries": 1, "computer_full_queries": 1, "gpo_v2_queries": 1}


def test_same_slot_replays_verified_existing_manifest_without_collection_or_persistence() -> None:
    canonical_slot = "2026-08-31T11:00:00Z"
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import run_one_shot
    from scripts.maintenance import ad_snapshot_manifest_canary as canary

    stored: dict[str, object] = {}
    calls: list[str] = []
    base_verifications: list[list[dict[str, object]]] = []
    bundles = {family: {"run_id": f"00000000-0000-4000-8000-{index:012d}"} for index, family in enumerate(AD_FAMILIES, 1)}
    domain = {"id": 7, "sid": "S-1-5-21-1-2-3", "dns": "example.test"}

    def acquire(family: str) -> dict[str, object]:
        calls.append(f"acquire:{family}")
        return {"bundle": bundles[family], "computer_rows": [], "base_complete": True,
                "acquisition": {"profile": "ad_snapshot_base_v1", "user_full_queries": 1, "computer_full_queries": 1}}

    def publish(manifest):
        stored["manifest"] = manifest
        return {"manifest_id": manifest["manifest_id"], "replayed": 0, "readback_verified": True}

    kwargs = dict(
        slot_start_utc=canonical_slot, domain=domain, execute=True, acquire_ad_family=acquire,
        import_ad_family=lambda bundle, family: calls.append(f"import:{family}") or _descriptor(family, str(bundle["run_id"]), format(AD_FAMILIES.index(family) + 1, "x")),
        persist_users=lambda _bundle: calls.append("persist:users") or _descriptor("users_v2", "121", "7"),
        persist_computers=lambda _rows: calls.append("persist:computers") or _descriptor("computers_v6", "00000000-0000-4000-8000-000000000101", "8"),
        import_gpo=lambda bundle: calls.append("import:gpo") or _descriptor("gpo_v2", str(bundle["run_id"]), "9"),
        publish=publish, assembled_at_utc="2026-08-31T12:10:00Z",
        lookup_existing=lambda **_query: stored.get("manifest"),
        resolve_existing_source=lambda member: {**member, "domain_id": 7, "domain_sid": domain["sid"],
                                                   "domain_dns": domain["dns"], "import_state": "completed"},
        verify_existing_base=lambda members: base_verifications.append(members) or {"usable": True},
    )
    request = {"account": "EXAMPLE\\operator", "slot_start_utc": canonical_slot,
               "window_start_utc": "2026-08-31T19:05:00Z", "window_end_utc": "2026-08-31T19:25:00Z",
               "domain_dns": domain["dns"]}
    fresh = canary.run(
        request=request, request_hash=canary.request_sha256(request), execute=True,
        confirmation=canary.EXECUTE_TOKEN, current_account="EXAMPLE\\operator",
        now=lambda: datetime(2026, 8, 31, 19, 10, tzinfo=timezone.utc),
        coordinator=lambda **_requested: run_one_shot(**kwargs),
    )
    assert fresh["status"] == "published"
    assert fresh["single_query_proof"] is True
    calls.clear()

    replay = run_one_shot(**kwargs)

    assert calls == []
    assert replay["status"] == "replayed_existing"
    assert replay["source_contacted"] is False
    assert replay["database_contacted"] is True
    assert replay["database_modified"] is False
    assert replay["source_ids"] == {item["family"]: item["source_id"] for item in stored["manifest"]["members"]}
    assert len(base_verifications) == 1


def test_same_slot_incomplete_existing_manifest_fails_closed_before_callbacks() -> None:
    from scripts.runtime.ad_snapshot_manifest_coordinator_worker import run_one_shot
    from server.ad_context.snapshot_manifest import canonical_manifest_sha256

    domain = {"id": 7, "sid": "S-1-5-21-1-2-3", "dns": "example.test"}
    existing = {
        "contract_version": "sli.ad-snapshot-manifest/1.0", "manifest_id": "00000000-0000-4000-8000-000000000124",
        "domain_id": 7, "domain_sid": domain["sid"], "domain_dns": domain["dns"], "slot_start_utc": SLOT,
        "assembled_at_utc": "2026-08-31T12:10:00Z", "coverage_state": "complete",
        "members": [_descriptor("ad_context_base", "00000000-0000-4000-8000-000000000001", "a")],
    }
    existing["manifest_sha256"] = canonical_manifest_sha256(existing)
    calls: list[str] = []
    callback = lambda *_args: calls.append("called")

    with pytest.raises(RuntimeError, match="existing_manifest_family_set_mismatch"):
        run_one_shot(
            slot_start_utc=SLOT, domain=domain, execute=True, acquire_ad_family=callback,
            import_ad_family=callback, persist_users=callback, persist_computers=callback,
            publish=callback, import_gpo=callback, lookup_existing=lambda **_query: existing,
            resolve_existing_source=lambda member: {**member, "domain_id": 7, "domain_sid": domain["sid"],
                                                       "domain_dns": domain["dns"], "import_state": "completed"},
        )
    assert calls == []


def test_manifest_contract_resolves_static_ad_families_by_exact_sections() -> None:
    from server.ad_context.snapshot_manifest import ALLOWED_FAMILY_CONTRACTS, BASE_FAMILIES
    from server.ad_context import repository

    for family in AD_FAMILIES:
        assert ALLOWED_FAMILY_CONTRACTS[family] == "sli.windows.ad-context"
    assert BASE_FAMILIES == frozenset({"ad_context_base", "computers_v6"})
    source = getsource(repository._resolve_manifest_source)
    for section in ("directory_accounts", "directory_group_graph", "directory_exact_logon", "privileged_membership", "vpn_membership", "domain_posture", "domain_health", "gpo_governance"):
        assert section in source
    migration = (ROOT / "config/postgres_migrations/121_ad_snapshot_manifest_foundation.sql").read_text(encoding="utf-8")
    for family in ALL_FAMILIES:
        assert f"'{family}'" in migration

    class Cursor:
        def __init__(self) -> None:
            self.params = None

        def execute(self, _query, params) -> None:
            self.params = params

        def fetchone(self):
            return {"contract_id": "sli.windows.ad-context", "source_id": "00000000-0000-4000-8000-000000000001", "source_state": "complete"}

    cursor = Cursor()
    resolved = repository._resolve_manifest_source(cursor, {"family": "ad_context_base", "source_id": "00000000-0000-4000-8000-000000000001"})
    assert cursor.params == ("00000000-0000-4000-8000-000000000001", ["directory_accounts", "directory_group_graph", "directory_exact_logon"], 3)
    assert resolved["family"] == "ad_context_base"


def _e4_command(control, name: str) -> str:
    spec = control.ROOT_SPECS[name]
    marker = f" --component {spec.component_marker}" if spec.component_marker else ""
    return f'"C:\\sli\\.venv\\Scripts\\python.exe" "{spec.script}"{marker}'


def _e4_rows(control, names: tuple[str, ...], *, parent: int, first_pid: int) -> list[dict[str, object]]:
    return [
        {"pid": first_pid + index, "parent_pid": parent, "command_line": _e4_command(control, name), "creation_time": f"created:{first_pid + index}"}
        for index, name in enumerate(names)
    ]


def _e4_static_ok(control, *, refused: tuple[str, ...] = ()) -> dict[str, object]:
    return {
        "status": "ok",
        "identity_status": "ok",
        "canonical_admission_keys": list(control.CANONICAL_ADMISSION_KEYS),
        "unrelated_admission_refused_roots": list(refused),
    }


def _e4_heartbeat(pid: int, *, at: str = "2026-09-01T00:00:01Z") -> dict[str, object]:
    return {
        "worker_name": "ad_snapshot_manifest_coordinator",
        "worker_id": f"fresh-worker:{pid}",
        "process_pid": pid,
        "status": "initial_delay",
        "phase": "initial_delay",
        "expected_interval_seconds": 43200,
        "heartbeat_at": at,
    }


def _e4_before(
    control,
    *,
    include_legacy: bool = True,
    unrelated_names: tuple[str, ...] | None = None,
) -> list[dict[str, object]]:
    names = control.UNRELATED_SUPERVISED_ROOTS if unrelated_names is None else unrelated_names
    rows = [
        {"pid": 1, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        {"pid": 9, "parent_pid": 1, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)},
        *_e4_rows(control, names, parent=1, first_pid=40),
    ]
    if include_legacy:
        rows += _e4_rows(control, control.LEGACY_AD_ROOTS, parent=1, first_pid=10)
    return rows


def _e4_after(
    control,
    *,
    unrelated_names: tuple[str, ...] | None = None,
    canonical_pid: int = 120,
) -> list[dict[str, object]]:
    names = control.UNRELATED_SUPERVISED_ROOTS if unrelated_names is None else unrelated_names
    return [
        {"pid": 2, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        {"pid": canonical_pid, "parent_pid": 2, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)},
        *_e4_rows(control, names, parent=2, first_pid=140),
    ]


def test_runtime_control_drops_only_cim_idle_pid_zero_before_topology() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    rows = [
        {"pid": 0, "parent_pid": 0, "command_line": "System Idle Process"},
        *_e4_before(control),
    ]
    plan = control.run(
        action="plan",
        confirmation=None,
        inventory=lambda: {"complete": True, "source": "powershell_cim", "processes": rows},
        stop_tree=lambda _pid: pytest.fail("plan must not stop a process"),
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: pytest.fail("plan must not restart the supervisor"),
        heartbeat=lambda: pytest.fail("plan must not query heartbeat"),
    )

    assert plan["status"] == "planned"
    assert plan["before"]["supervisor_root_pids"] == [1]
    assert plan["before"]["ad_snapshot_manifest_coordinator_root_pids"] == [9]
    assert plan["before"]["legacy_target_root_pids"] == [10, 11, 12, 13, 14, 15]

    with pytest.raises(RuntimeError, match="process_inventory_ambiguous_pid"):
        control._snapshot(
            [
                {"pid": 0, "parent_pid": 1, "command_line": "not-the-idle-process"},
                {"pid": 1, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
            ]
        )


def test_runtime_control_handles_empty_quoted_nonmanaged_command_tokens() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    command_lines = (
        r'"C:\Program Files\Example\helper.exe" "" --mode audit',
        r'cmd.exe /c ""',
        r'python.exe "C:\temp\unmanaged.py" ""',
    )
    rows = [
        *_e4_before(control),
        *[
            {"pid": 900 + index, "parent_pid": 0, "command_line": command_line}
            for index, command_line in enumerate(command_lines)
        ],
    ]

    assert all("" in control._command_tokens(command_line) for command_line in command_lines)
    plan = control.run(
        action="plan",
        confirmation=None,
        inventory=lambda: rows,
        stop_tree=lambda _pid: pytest.fail("plan must not stop a process"),
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: pytest.fail("plan must not restart the supervisor"),
        heartbeat=lambda: pytest.fail("plan must not query heartbeat"),
    )

    assert plan["status"] == "planned"
    assert plan["before"]["ad_snapshot_manifest_coordinator_root_pids"] == [9]
    assert plan["before"]["legacy_target_root_pids"] == [10, 11, 12, 13, 14, 15]


def test_runtime_control_loads_sealed_environment_before_default_admission(monkeypatch) -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control
    from server.sli.sources import windows_runtime_identity
    from server.sli.ops import worker_supervisor_secrets

    sealed = {
        key: f"sealed-value-{index}"
        for index, key in enumerate(control.CANONICAL_ADMISSION_KEYS, start=1)
    }
    for key in sealed:
        monkeypatch.delenv(key, raising=False)
    calls: list[str] = []
    identity_inputs: list[dict[str, str | None]] = []
    static_results: list[dict[str, object]] = []

    def load_environment(*, override_existing: bool = False) -> dict[str, object]:
        calls.append("load")
        assert override_existing is True
        for key, value in sealed.items():
            monkeypatch.setenv(key, value)
        return {
            "status": "ok",
            "keys": sorted(sealed),
            "credential_values_exposed": False,
        }

    def verify_identity() -> dict[str, object]:
        calls.append("identity")
        identity_inputs.append({key: os.environ.get(key) for key in sealed})
        return {"status": "ok"}

    original_static_check = control._static_ownership_check

    def capture_static_check(**kwargs) -> dict[str, object]:
        result = original_static_check(**kwargs)
        static_results.append(result)
        return result

    monkeypatch.setattr(worker_supervisor_secrets, "load_supervisor_environment", load_environment)
    monkeypatch.setattr(windows_runtime_identity, "verify_collection_identity", verify_identity)
    monkeypatch.setattr(control, "_static_ownership_check", capture_static_check)

    mutations: list[str] = []
    with pytest.raises(RuntimeError, match="process_inventory_incomplete"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: {"complete": False, "processes": []},
            stop_tree=lambda _pid: mutations.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: mutations.append("restart"),
            heartbeat=lambda: mutations.append("heartbeat"),
            supervisor_allows=lambda: False,
        )

    assert calls == ["load", "identity"]
    assert identity_inputs == [sealed]
    assert mutations == []
    assert static_results[0]["status"] == "ok"
    assert static_results[0]["canonical_admission_keys"] == list(control.CANONICAL_ADMISSION_KEYS)
    assert not any(value in repr(static_results) for value in sealed.values())


def test_runtime_control_is_supervisor_owned_and_preserves_active_writers() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    before = [
        {"pid": 1, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        {"pid": 20, "parent_pid": 1, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)},
        *_e4_rows(control, control.LEGACY_AD_ROOTS, parent=1, first_pid=10),
        *_e4_rows(control, control.UNRELATED_SUPERVISED_ROOTS, parent=1, first_pid=40),
    ]
    plan_calls: list[str] = []
    plan = control.run(
        action="plan",
        confirmation=None,
        inventory=lambda: plan_calls.append("inventory") or before,
        stop_tree=lambda _pid: pytest.fail("plan must not stop a process"),
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: pytest.fail("plan must not restart the supervisor"),
        heartbeat=lambda: pytest.fail("plan must not query heartbeat"),
    )
    assert plan_calls == ["inventory"]
    assert plan["status"] == plan["state"] == "planned"
    assert plan["before"]["legacy_target_root_pids"] == [10, 11, 12, 13, 14, 15]
    assert "command_line" not in repr(plan)

    after_stop = [row for row in before if int(row["pid"]) not in {10, 11, 12, 13, 14, 15}]
    after = [
        {"pid": 2, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        {"pid": 120, "parent_pid": 2, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)},
        *_e4_rows(control, control.UNRELATED_SUPERVISED_ROOTS, parent=2, first_pid=140),
    ]
    inventories = iter([before, after_stop, after])
    stopped_pids: list[int] = []
    restart_tokens: list[str] = []
    result = control.run(
        action="apply",
        confirmation=control.APPLY_TOKEN,
        inventory=lambda: next(inventories),
        stop_tree=stopped_pids.append,
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=restart_tokens.append,
        heartbeat=lambda: _e4_heartbeat(120),
        static_check=lambda: _e4_static_ok(control),
        utc_now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert stopped_pids == [10, 11, 12, 13, 14, 15]
    assert restart_tokens == [control.SUPERVISOR_RESTART_TOKEN]
    assert result["state"] == result["status"] == "accepted"
    assert result["coordinator_supervisor_owned"] is True
    assert result["all_legacy_roots_absent"] is True
    assert result["unrelated_roots_preserved"] is True
    assert result["rollback_plan"]["automatic_legacy_relaunch"] is False
    source = Path(control.__file__).read_text(encoding="utf-8")
    assert "subprocess.Popen" not in source
    assert "worker_supervisor._start" not in source


def test_runtime_control_cli_adds_repository_root_for_lazy_server_imports() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    source = Path(control.__file__).read_text(encoding="utf-8")
    assert "import sys" in source
    assert 'if str(ROOT) not in sys.path:' in source
    assert 'sys.path.insert(0, str(ROOT))' in source


def test_runtime_control_normalizes_windows_venv_wrapper_trees() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    def worker_tree(
        root: int,
        parent: int,
        name: str | Path,
        child: int,
        helper: int,
    ) -> list[dict[str, object]]:
        command = (
            f'"C:\\sli\\.venv\\Scripts\\python.exe" "{control.ROOT_SPECS[name].script}"'
            if isinstance(name, str)
            else f'"C:\\sli\\.venv\\Scripts\\python.exe" "{name}"'
        )
        if isinstance(name, str) and control.ROOT_SPECS[name].component_marker:
            command += f" --component {control.ROOT_SPECS[name].component_marker}"
        return [
            {"pid": root, "parent_pid": parent, "command_line": command, "creation_time": f"created:{root}"},
            {"pid": child, "parent_pid": root, "command_line": command},
            {"pid": helper, "parent_pid": child, "command_line": "conhost.exe --worker-helper"},
        ]

    supervisor_before = worker_tree(100, 0, control.SUPERVISOR, 101, 102)
    canonical_before = worker_tree(150, 101, control.CANONICAL_AD_ROOT, 151, 152)
    legacy_before: list[dict[str, object]] = []
    legacy_pids: list[int] = []
    for index, name in enumerate(control.LEGACY_AD_ROOTS):
        root = 200 + index * 10
        legacy_pids.append(root)
        legacy_before += worker_tree(root, 101, name, root + 1, root + 2)
    unrelated_before: list[dict[str, object]] = []
    for index, name in enumerate(control.UNRELATED_SUPERVISED_ROOTS):
        root = 400 + index * 10
        unrelated_before += worker_tree(root, 101, name, root + 1, root + 2)
    before = supervisor_before + canonical_before + legacy_before + unrelated_before
    after_stop = supervisor_before + canonical_before + unrelated_before

    supervisor_after = worker_tree(110, 0, control.SUPERVISOR, 111, 112)
    canonical_after = worker_tree(600, 111, control.CANONICAL_AD_ROOT, 601, 602)
    unrelated_after: list[dict[str, object]] = []
    for index, name in enumerate(control.UNRELATED_SUPERVISED_ROOTS):
        root = 700 + index * 10
        unrelated_after += worker_tree(root, 111, name, root + 1, root + 2)
    after = supervisor_after + canonical_after + unrelated_after
    inventories = iter([before, after_stop, after])
    stopped_pids: list[int] = []

    result = control.run(
        action="apply",
        confirmation=control.APPLY_TOKEN,
        inventory=lambda: next(inventories),
        stop_tree=stopped_pids.append,
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: None,
        heartbeat=lambda: _e4_heartbeat(601),
        static_check=lambda: _e4_static_ok(control),
        utc_now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert stopped_pids == legacy_pids
    assert result["heartbeat"]["process_pid"] == 601
    assert result["after_stop"]["legacy_target_root_pids"] == []
    assert result["after_stop"]["legacy_target_tree_pids"] == []
    assert result["after"]["ad_snapshot_manifest_coordinator_root_pids"] == [600]
    assert result["after"]["ad_snapshot_manifest_coordinator_tree_pids"] == [600, 601, 602]
    for name in control.LEGACY_AD_ROOTS:
        assert result["after"][f"{name}_root_pids"] == []
        assert result["after"][f"{name}_tree_pids"] == []
    for name in control.UNRELATED_SUPERVISED_ROOTS:
        assert len(result["after"][f"{name}_root_pids"]) == 1

    # The coordinator interpreter child is valid; a child of a different
    # supervisor-owned root is not a valid coordinator heartbeat.
    assert 601 in result["after"]["supervisor_tree_pids"]
    assert 701 in result["after"]["supervisor_tree_pids"]
    assert 701 not in result["after"]["ad_snapshot_manifest_coordinator_tree_pids"]
    child_ready, child_heartbeat = control._heartbeat_ready(
        _e4_heartbeat(601),
        after=result["after"],
        handoff_marker=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    unrelated_ready, unrelated_heartbeat = control._heartbeat_ready(
        _e4_heartbeat(701),
        after=result["after"],
        handoff_marker=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    assert child_ready is True
    assert child_heartbeat is not None
    assert unrelated_ready is False
    assert unrelated_heartbeat is None

    lookalikes = [
        {"pid": 900, "parent_pid": 0, "command_line": f"python {control.V5}.bak"},
        {"pid": 901, "parent_pid": 0, "command_line": f"python x{control.V5.name}"},
        {"pid": 902, "parent_pid": 0, "command_line": f"python {control.V5}.pyc"},
    ]
    assert control._tree(lookalikes, control.V5) == ([], [])


def test_runtime_control_polls_until_supervisor_owned_coordinator_and_heartbeat_are_ready() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    before = [
        {"pid": 1, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        {"pid": 9, "parent_pid": 1, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)},
        *_e4_rows(control, control.LEGACY_AD_ROOTS, parent=1, first_pid=10),
        *_e4_rows(control, control.UNRELATED_SUPERVISED_ROOTS, parent=1, first_pid=40),
    ]
    after_stop = [row for row in before if int(row["pid"]) not in {10, 11, 12, 13, 14, 15}]
    pending = [
        {"pid": 2, "parent_pid": 0, "command_line": f"python {control.SUPERVISOR}"},
        *_e4_rows(control, control.UNRELATED_SUPERVISED_ROOTS, parent=2, first_pid=140),
    ]
    ready = pending + [
        {"pid": 40, "parent_pid": 2, "command_line": _e4_command(control, control.CANONICAL_AD_ROOT)}
    ]
    inventories = iter([before, after_stop, pending, ready])
    clock = [0.0]
    sleeps: list[float] = []
    heartbeat_calls: list[str] = []

    result = control.run(
        action="apply",
        confirmation=control.APPLY_TOKEN,
        inventory=lambda: next(inventories),
        stop_tree=lambda _pid: None,
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: None,
        heartbeat=lambda: heartbeat_calls.append("read") or _e4_heartbeat(40),
        static_check=lambda: _e4_static_ok(control),
        readiness_timeout_seconds=5,
        monotonic=lambda: clock[0],
        sleep=lambda seconds: (sleeps.append(seconds), clock.__setitem__(0, clock[0] + seconds)),
        utc_now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert sleeps == [1]
    assert heartbeat_calls == ["read"]
    assert result["coordinator_pid"] == 40
    assert result["heartbeat"]["phase"] == "initial_delay"
    assert result["heartbeat"]["heartbeat_at"] == "2026-09-01T00:00:01Z"
    assert result["after"]["legacy_target_root_pids"] == []
    assert result["after"]["legacy_target_tree_pids"] == []


def test_runtime_control_readiness_timeout_fails_closed() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    def failed_read() -> object:
        raise RuntimeError("read-only heartbeat unavailable")

    valid = _e4_heartbeat(120)
    invalid_heartbeats = [
        lambda: None,
        failed_read,
        lambda: [valid, valid],
        lambda: {**valid, "worker_name": "other_worker"},
        lambda: {**valid, "expected_interval_seconds": 60},
        lambda: {**valid, "process_pid": 140},
        lambda: {**valid, "worker_id": ""},
        lambda: {**valid, "status": "failed"},
        lambda: {**valid, "heartbeat_at": "2026-09-01T00:00:00Z"},
        lambda: {**valid, "heartbeat_at": "2026-09-01T00:00:01"},
    ]

    for heartbeat in invalid_heartbeats:
        before = _e4_before(control)
        after_stop = [row for row in before if int(row["pid"]) not in {10, 11, 12, 13, 14, 15}]
        ready = _e4_after(control)
        calls = [before, after_stop]
        stopped_pids: list[int] = []
        restart_tokens: list[str] = []
        clock = [0.0]

        def inventory() -> list[dict[str, object]]:
            return calls.pop(0) if calls else ready

        with pytest.raises(RuntimeError, match="coordinator_readiness_timeout"):
            control.run(
                action="apply",
                confirmation=control.APPLY_TOKEN,
                inventory=inventory,
                stop_tree=stopped_pids.append,
                validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
                restart_supervisor=restart_tokens.append,
                heartbeat=heartbeat,
                static_check=lambda: _e4_static_ok(control),
                readiness_timeout_seconds=2,
                monotonic=lambda: clock[0],
                sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
                utc_now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
            )

        assert stopped_pids == [10, 11, 12, 13, 14, 15]
        assert restart_tokens == [control.SUPERVISOR_RESTART_TOKEN]
        assert clock[0] >= 2


def test_runtime_control_static_and_preflight_gates_have_no_mutation(monkeypatch) -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    static = control._static_ownership_check(
        identity_check=lambda: {"status": "ok"},
        admission_check=lambda: {
            "status": "ok",
            "canonical_admission_keys": list(control.CANONICAL_ADMISSION_KEYS),
        },
    )
    assert static["status"] == "ok"
    assert static["canonical_admission_keys"] == list(control.CANONICAL_ADMISSION_KEYS)

    calls: list[str] = []
    with pytest.raises(RuntimeError, match="apply_requires_exact_confirmation"):
        control.run(
            action="apply",
            confirmation=None,
            inventory=lambda: calls.append("inventory") or _e4_before(control),
            stop_tree=lambda _pid: calls.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: calls.append("restart"),
            heartbeat=lambda: calls.append("heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert calls == []

    with pytest.raises(RuntimeError, match="static_runtime_ownership_invalid"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: calls.append("inventory") or _e4_before(control),
            stop_tree=lambda _pid: calls.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: calls.append("restart"),
            heartbeat=lambda: calls.append("heartbeat"),
            static_check=lambda: {"status": "blocked"},
        )
    assert calls == []

    with pytest.raises(RuntimeError, match="supervisor_configuration_can_relaunch_legacy_worker"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: calls.append("inventory") or _e4_before(control),
            stop_tree=lambda _pid: calls.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: calls.append("restart"),
            heartbeat=lambda: calls.append("heartbeat"),
            static_check=lambda: _e4_static_ok(control),
            supervisor_allows=lambda: True,
        )
    assert calls == []

    with pytest.raises(RuntimeError, match="process_inventory_incomplete"):
        control.run(
            action="plan",
            confirmation=None,
            inventory=lambda: {"complete": False, "processes": []},
            stop_tree=lambda _pid: calls.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: calls.append("restart"),
            heartbeat=lambda: calls.append("heartbeat"),
        )
    assert calls == []

    # A shared host without its exact component marker is not a preservable
    # RADIUS logical root and therefore fails before a legacy stop.
    malformed = _e4_before(control)
    for row in malformed:
        if int(row["pid"]) == 42:
            row["command_line"] = f"python {control.ROOT_SPECS['plugin_radius_acquisition'].script}"
    with pytest.raises(RuntimeError, match="unrelated_root_missing_without_admission_refusal"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: malformed,
            stop_tree=lambda _pid: calls.append("stop"),
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: calls.append("restart"),
            heartbeat=lambda: calls.append("heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert calls == []


def test_runtime_control_fails_closed_for_independent_duplicate_roots() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    processes = [
        {"pid": 10, "parent_pid": 1, "command_line": f"python {control.COORDINATOR}"},
        {"pid": 20, "parent_pid": 1, "command_line": f"python {control.COORDINATOR}"},
    ]
    assert control._tree(processes, control.COORDINATOR) == ([10, 20], [10, 20])

    stopped: list[int] = []
    duplicate = _e4_before(control) + [
        {"pid": 99, "parent_pid": 1, "command_line": _e4_command(control, "computers_v5_snapshot")}
    ]
    with pytest.raises(RuntimeError, match="exact_worker_inventory_has_multiple_roots"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: duplicate,
            stop_tree=stopped.append,
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: pytest.fail("must not restart"),
            heartbeat=lambda: pytest.fail("must not read heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert stopped == []

    cross_component = _e4_before(control)
    for row in cross_component:
        if int(row["pid"]) == 15:
            row["parent_pid"] = 12
    with pytest.raises(RuntimeError, match="legacy_descendant_closure_cross_component"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: cross_component,
            stop_tree=stopped.append,
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: pytest.fail("must not restart"),
            heartbeat=lambda: pytest.fail("must not read heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert stopped == []

    protected = _e4_before(control)
    for row in protected:
        if int(row["pid"]) == 9:
            row["parent_pid"] = 12
    with pytest.raises(RuntimeError, match="legacy_target_intersects_protected_tree"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=lambda: protected,
            stop_tree=stopped.append,
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=lambda _token: pytest.fail("must not restart"),
            heartbeat=lambda: pytest.fail("must not read heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert stopped == []

    with pytest.raises(RuntimeError, match="process_inventory_ambiguous_tree"):
        control._snapshot(
            [
                {"pid": 1, "parent_pid": 2, "command_line": "python one.py"},
                {"pid": 2, "parent_pid": 1, "command_line": "python two.py"},
            ]
        )


def test_runtime_control_handles_zero_legacy_roots_and_admission_gated_absence() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    refused = ("semantic", "storage_lifecycle")
    admitted_names = tuple(name for name in control.UNRELATED_SUPERVISED_ROOTS if name not in refused)
    before = _e4_before(control, include_legacy=False, unrelated_names=admitted_names)
    after = _e4_after(control, unrelated_names=admitted_names)
    inventories = iter([before, before, after])
    stopped: list[int] = []

    result = control.run(
        action="apply",
        confirmation=control.APPLY_TOKEN,
        inventory=lambda: next(inventories),
        stop_tree=stopped.append,
        validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
        restart_supervisor=lambda _token: None,
        heartbeat=lambda: _e4_heartbeat(120),
        static_check=lambda: _e4_static_ok(control, refused=refused),
        utc_now=lambda: datetime(2026, 9, 1, tzinfo=timezone.utc),
    )
    assert stopped == []
    assert result["before"]["legacy_target_root_pids"] == []
    assert result["after"]["legacy_target_tree_pids"] == []
    assert result["static"]["unrelated_admission_refused_roots"] == list(refused)


def test_runtime_control_stops_after_post_stop_or_restart_failure() -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    before = _e4_before(control)
    stale_after_stop = list(before)
    stopped: list[int] = []
    restart_tokens: list[str] = []
    with pytest.raises(RuntimeError, match="legacy_target_tree_present_after_stop"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=iter([before, stale_after_stop]).__next__,
            stop_tree=stopped.append,
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=restart_tokens.append,
            heartbeat=lambda: pytest.fail("must not read heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert stopped == [10, 11, 12, 13, 14, 15]
    assert restart_tokens == []

    before = _e4_before(control)
    after_stop = [row for row in before if int(row["pid"]) not in {10, 11, 12, 13, 14, 15}]
    stopped = []
    restart_tokens = []

    def restart_once(token: str) -> None:
        restart_tokens.append(token)
        raise RuntimeError("restart transport failed")

    with pytest.raises(RuntimeError, match="restart transport failed"):
        control.run(
            action="apply",
            confirmation=control.APPLY_TOKEN,
            inventory=iter([before, after_stop]).__next__,
            stop_tree=stopped.append,
            validate_target=lambda _pid, _identity: None,  # Synthetic OS boundary.
            restart_supervisor=restart_once,
            heartbeat=lambda: pytest.fail("must not read heartbeat"),
            static_check=lambda: _e4_static_ok(control),
        )
    assert stopped == [10, 11, 12, 13, 14, 15]
    assert restart_tokens == [control.SUPERVISOR_RESTART_TOKEN]


def test_canary_window_uses_injected_now_not_slot_start() -> None:
    canonical_slot = "2026-08-31T11:00:00Z"
    from scripts.maintenance import ad_snapshot_manifest_canary as canary

    request = {"account": "EXAMPLE\\operator", "slot_start_utc": canonical_slot, "window_start_utc": "2026-08-31T19:05:00Z", "window_end_utc": "2026-08-31T19:25:00Z", "domain_dns": "example.test"}
    digest = canary.request_sha256(request)
    now = datetime(2026, 8, 31, 19, 10, tzinfo=timezone.utc)
    result = canary.run(
        request=request, request_hash=digest, execute=True, confirmation=canary.EXECUTE_TOKEN,
        current_account="EXAMPLE\\operator", now=lambda: now,
        coordinator=lambda **_: {"status": "published", "base_complete": True, "slot_start_utc": canonical_slot, "domain_dns": "example.test", "acquisition": {"base_invocations": 1, "privileged_invocations": 1, "vpn_invocations": 1, "posture_invocations": 1, "health_invocations": 1, "gpo_invocations": 1, "user_full_queries": 1, "computer_full_queries": 1, "gpo_v2_queries": 1}, "source_hashes": {family: "a" * 64 for family in ALL_FAMILIES}, "source_ids": {family: ("121" if family == "users_v2" else "00000000-0000-4000-8000-000000000001") for family in ALL_FAMILIES}, "source_states": {family: ("partial" if family == "ad_domain_health" else "complete") for family in ALL_FAMILIES}, "partial_families": ["ad_domain_health"], "manifest_sha256": "b" * 64},
    )
    assert result["status"] == "published"
    assert result["partial_families"] == ["ad_domain_health"]
    with pytest.raises(RuntimeError, match="current_time_outside"):
        canary.run(request=request, request_hash=digest, execute=True, confirmation=canary.EXECUTE_TOKEN, current_account="EXAMPLE\\operator", now=lambda: datetime(2026, 8, 31, 19, 30, tzinfo=timezone.utc), coordinator=lambda **_: {})


def test_canary_accepts_verified_existing_slot_without_claiming_single_query_proof() -> None:
    canonical_slot = "2026-08-31T11:00:00Z"
    from scripts.maintenance import ad_snapshot_manifest_canary as canary

    request = {"account": "EXAMPLE\\operator", "slot_start_utc": canonical_slot, "window_start_utc": "2026-08-31T19:05:00Z", "window_end_utc": "2026-08-31T19:25:00Z", "domain_dns": "example.test"}
    result = canary.run(
        request=request, request_hash=canary.request_sha256(request), execute=True,
        confirmation=canary.EXECUTE_TOKEN, current_account="EXAMPLE\\operator",
        now=lambda: datetime(2026, 8, 31, 19, 10, tzinfo=timezone.utc),
        coordinator=lambda **_: {
            "status": "replayed_existing", "base_complete": True, "slot_start_utc": canonical_slot,
            "domain_dns": "example.test", "source_contacted": False, "database_contacted": True,
            "database_modified": False, "single_query_proof": False,
            "source_hashes": {family: "a" * 64 for family in ALL_FAMILIES},
            "source_ids": {family: str(index) for index, family in enumerate(sorted(ALL_FAMILIES), 1)},
            "source_states": {family: ("partial" if family in {"ad_context_base", "computers_v6"} else "complete") for family in ALL_FAMILIES},
            "partial_families": ["ad_context_base", "computers_v6"], "manifest_sha256": "b" * 64,
        },
    )
    assert result["status"] == "replayed_existing"
    assert result["source_contacted"] is False
    assert result["database_modified"] is False
    assert result["single_query_proof"] is False
    assert "acquisition" not in result


def test_canary_cli_treats_verified_existing_slot_as_success(monkeypatch, capsys) -> None:
    canonical_slot = "2026-08-31T11:00:00Z"
    from scripts.maintenance import ad_snapshot_manifest_canary as canary

    request = {"account": "EXAMPLE\\operator", "slot_start_utc": canonical_slot, "window_start_utc": "2026-08-31T19:05:00Z", "window_end_utc": "2026-08-31T19:25:00Z", "domain_dns": "example.test"}
    monkeypatch.setattr(canary, "_account", lambda: "EXAMPLE\\operator")
    monkeypatch.setattr(canary, "run", lambda **_kwargs: {"status": "replayed_existing"})
    exit_code = canary.main([
        "--request-json", __import__("json").dumps(request),
        "--request-sha256", canary.request_sha256(request), "--execute",
        "--confirm", canary.EXECUTE_TOKEN,
    ])
    assert exit_code == 0
    assert "replayed_existing" in capsys.readouterr().out


def test_e3_rejects_destructive_retention_and_direct_projection_worker_claims() -> None:
    migration_root = ROOT / "config" / "postgres_migrations"
    forward = (migration_root / "129_ad_snapshot_projection_retention.sql").read_text(encoding="utf-8").casefold()
    rollback = (migration_root / "129_ad_snapshot_projection_retention.rollback.sql").read_text(encoding="utf-8").casefold()
    projection_shim = (ROOT / "scripts" / "runtime" / "ad_snapshot_projection_worker.py").read_text(encoding="utf-8").casefold()
    retention = (ROOT / "server" / "sli" / "sources" / "ad_snapshot_retention.py").read_text(encoding="utf-8").casefold()

    for text in (forward, rollback, retention):
        assert "delete from ad_snapshot_projection_outputs" not in text
        assert "truncate ad_snapshot_projection_outputs" not in text
        assert "delete from ad_snapshot_projection_receipts" not in text
        assert "truncate ad_snapshot_projection_receipts" not in text
    assert "delete from public.schema_migrations" in rollback
    assert "where version = 129" in rollback
    assert "claim_projection_receipts" not in projection_shim
    assert "record_projection_result" not in projection_shim
    assert "run_exact_manifest_projection_cycle" in projection_shim
    assert "storage_lifecycle" not in retention


@pytest.mark.parametrize("missing_identity", [False, True])
def test_runtime_control_checks_captured_identity_before_stop(missing_identity) -> None:
    from scripts.maintenance import ad_snapshot_runtime_control as control

    before = _e4_before(control)
    if missing_identity:
        for row in before:
            row.pop("creation_time", None)
    calls = []

    def refuse(pid, identity):
        calls.append(("validate", pid, identity))
        raise RuntimeError("target_identity_changed_or_unavailable")

    with pytest.raises(RuntimeError, match="target_identity"):
        control.run(
            action="apply", confirmation=control.APPLY_TOKEN,
            inventory=lambda: before, validate_target=refuse,
            stop_tree=lambda pid: calls.append(("stop", pid)),
            restart_supervisor=lambda token: calls.append(("restart", token)),
            static_check=lambda: _e4_static_ok(control),
        )
    assert all(call[0] == "validate" for call in calls)
    if not missing_identity:
        assert calls == [("validate", 10, {"creation_time": "created:10", "root_name": "ad_context_snapshot"})]
    else:
        assert calls == []
