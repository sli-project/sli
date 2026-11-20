"""Audit management with a fake Windows API; no native calls and no database."""
import ctypes
import json
import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock
from uuid import UUID

import pytest

from sli_agent.control import collection_policy
from sli_agent.policies import apply_policy
from sli_agent.windows_audit import AuditManager, SUBCATEGORIES, gpo_override, parse_backup_csv, required_families
from sli_agent import windows_audit_native as native

LOGON = SUBCATEGORIES["logon"][0]
LOGOFF = SUBCATEGORIES["logoff"][0]
PROCESS = SUBCATEGORIES["process_creation"][0]


def assignments(*families):
    return [{"module_id": "sli.workstations", "enabled": True, "config": {
        "families": {family: family in families for family in ("logons", "processes", "local_admins", "protection", "usb")}}}]


class API:
    def __init__(self, root):
        self.root = root
        self.actual = dict.fromkeys((spec[0] for spec in SUBCATEGORIES.values()), 0)
        self.writes = []
        self.owner = "ok"
        self.system = True
        self.command = None
        self.command_writes = []
        self.fail = False
        self.ignore_write = False
        self.command_owner = "ok"

    def query(self, guids):
        return {guid: self.actual[guid] for guid in guids}

    def ownership(self):
        return self.owner

    def is_system(self):
        return self.system

    def set(self, changes):
        snapshot = json.loads((self.root / "state.json").read_bytes())
        assert set(changes) <= set(snapshot["subcategories"])
        self.writes.append(dict(changes))
        if self.fail:
            raise OSError("private-fixture-diagnostic")
        if not self.ignore_write:
            self.actual.update(changes)

    def command_line(self):
        return self.command

    def command_line_ownership(self):
        return self.command_owner

    def set_command_line(self, value):
        assert json.loads((self.root / "state.json").read_bytes())["command_line"] is not None
        self.command_writes.append(value)
        self.command = value


def setup(tmp_path):
    api = API(tmp_path / "audit")
    return AuditManager(api.root, api=api), api


@pytest.mark.parametrize("enabled", [True, False, None])
def test_powershell_logging_readback_is_independent_and_never_enables_policy(tmp_path, enabled):
    manager, api = setup(tmp_path)
    def read():
        if enabled is None:
            raise OSError("fixture-private-diagnostic")
        return {"channel_enabled": enabled, "script_block_logging_enabled": enabled}
    api.powershell_logging = read
    result = manager.reconcile(assignments("protection"), collection_policy({}), 1)
    assert result["powershell_logging"] == {"channel_enabled": enabled, "script_block_logging_enabled": enabled}
    assert api.writes == [] and api.command_writes == []
    assert "private" not in str(result)


def test_native_powershell_check_reads_channel_and_policy_and_closes_handle(monkeypatch):
    handle = SimpleNamespace(Close=Mock())
    backend = SimpleNamespace(EvtOpenChannelConfig=Mock(return_value=handle),
        EvtGetChannelConfigProperty=Mock(return_value=False), EvtChannelConfigEnabled=0)
    monkeypatch.setitem(sys.modules, "win32evtlog", backend)
    read = Mock(return_value=0)
    monkeypatch.setattr(native, "read_dword", read)
    result = native.WindowsAuditAPI.__new__(native.WindowsAuditAPI).powershell_logging()
    assert result == {"channel_enabled": False, "script_block_logging_enabled": False}
    backend.EvtOpenChannelConfig.assert_called_once_with("Microsoft-Windows-PowerShell/Operational", 0)
    handle.Close.assert_called_once()
    assert read.call_args.args[1] == "EnableScriptBlockLogging"


def test_mapping_includes_required_masks_and_only_enabled_families():
    required = required_families(assignments("logons", "processes", "local_admins", "protection", "usb"))
    assert [(row["guid"], row["success"], row["failure"]) for row in required["logons"]] == [
        (LOGON, True, True), (LOGOFF, True, False)]
    assert required["processes"][0]["guid"] == PROCESS
    assert required["local_admins"][0]["guid"] == "0cce9237-69ae-11d9-bed3-505054503030"
    assert [row["subcategory"] for row in required["protection"]] == [
        "security_system_extension", "other_object_access", "audit_policy_change"]
    assert required["usb"][0]["guid"] == "0cce9248-69ae-11d9-bed3-505054503030"
    assert set(required_families(assignments("logons"))) == {"logons"}
    assert required_families(["sli.workstations", {"module_id": "sli.workstations", "enabled": False}]) == {}
    assert required_families([{"module_id": "sli.ad-snapshot", "enabled": True}]) == {}


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_backup_csv_guid_and_numeric_masks_ignore_localized_strings_and_user_policy(locale):
    text = (Path(__file__).parents[1] / "fixtures/windows_audit" / f"{locale}.csv").read_text("utf-8")
    assert parse_backup_csv("\ufeff" + text) == {LOGON: 3, LOGOFF: 0, PROCESS: 1}


@pytest.mark.parametrize("text", ["no csv", f"a,System,unused,{{{LOGON}}},Success,,invalid\n",
    f"a,System,unused,{{{LOGON}}},Failure,,2\na,System,unused,{{{LOGON}}},Success,,1\n"])
def test_invalid_or_ambiguous_backup_fails_closed(text):
    with pytest.raises(ValueError, match="agent_audit_csv_invalid"):
        parse_backup_csv(text)


@pytest.mark.parametrize("force,domain,legacy,known,expected", [
    (1, False, True, True, "ok"), (0, False, True, True, "managed_by_gpo"),
    (None, False, True, True, "managed_by_gpo"), (1, True, False, True, "managed_by_gpo"),
    (1, False, False, False, "unknown"), (None, False, False, True, "ok"),
])
def test_gpo_override_detection(force, domain, legacy, known, expected):
    assert gpo_override(force_subcategories=force, domain_audit_policy=domain,
                        legacy_policy=legacy, evidence_known=known) == expected


def test_observation_is_default_and_reports_actual_vs_required_without_writes(tmp_path):
    manager, api = setup(tmp_path)
    api.actual[LOGON] = 1
    report = manager.reconcile(assignments("logons", "protection"), collection_policy({}), 2)
    assert report["management_state"] == "disabled"
    assert report["families"]["logons"]["state"] == "missing"
    assert report["families"]["logons"]["required"][0]["actual_failure"] is False
    assert "System" in report["families"]["protection"]["non_security_channels"]
    assert not api.writes and not api.command_writes


def test_apply_missing_bits_saves_original_then_restarts_and_restores_exact_values(tmp_path):
    manager, api = setup(tmp_path)
    api.actual[LOGON] = 1
    api.actual[LOGOFF] = 3
    original = dict(api.actual)
    control = collection_policy({"manage_windows_audit": True})
    report = manager.reconcile(assignments("logons"), control, 2)
    assert report["management_state"] == "applied" and report["families"]["logons"]["state"] == "ok"
    assert api.writes == [{LOGON: 3}]
    saved = json.loads((api.root / "state.json").read_bytes())
    assert saved["subcategories"] == {LOGON: {"previous": 1, "applied": 3, "phase": "confirmed"}}
    manager = AuditManager(api.root, api=api)
    manager.reconcile(assignments("logons"), control, 2)
    assert len(api.writes) == 1
    result = manager.reconcile(assignments("logons"), collection_policy({}), 3)
    assert result["management_state"] == "restored" and api.actual == original
    assert json.loads((api.root / "state.json").read_bytes())["subcategories"] == {}


def test_removed_family_restores_only_subcategories_the_agent_owned(tmp_path):
    manager, api = setup(tmp_path)
    api.actual[PROCESS] = 1
    control = collection_policy({"manage_windows_audit": True})
    manager.reconcile(assignments("logons", "processes"), control, 1)
    manager.reconcile(assignments("processes"), control, 2)
    assert api.writes == [{LOGON: 3, LOGOFF: 1}, {LOGON: 0, LOGOFF: 0}]
    assert api.actual[PROCESS] == 1


@pytest.mark.parametrize("owner,system", [("managed_by_gpo", True), ("unknown", True), ("ok", False)])
def test_gpo_unproven_ownership_and_non_system_never_change_audit(tmp_path, owner, system):
    manager, api = setup(tmp_path)
    api.owner, api.system = owner, system
    report = manager.reconcile(assignments("logons"), collection_policy({"manage_windows_audit": True}), 1)
    assert report["management_state"] == "blocked" and not api.writes
    assert report["families"]["logons"]["state"] == (owner if owner != "ok" else "missing")


def test_gpo_refresh_never_reapplies_even_if_it_restores_the_original_value(tmp_path):
    manager, api = setup(tmp_path)
    control = collection_policy({"manage_windows_audit": True})
    manager.reconcile(assignments("logons"), control, 1)
    api.actual[LOGON] = 0
    result = manager.reconcile(assignments("logons"), control, 1)
    assert result["families"]["logons"]["state"] == "managed_by_gpo"
    assert result["management_state"] == "blocked" and len(api.writes) == 1
    manager.reconcile(assignments("logons"), collection_policy({}), 2)
    assert len(api.writes) == 1 and json.loads((api.root / "state.json").read_bytes())["subcategories"]


def test_failed_write_preserves_snapshot_and_restart_can_finish_pending_intent(tmp_path):
    manager, api = setup(tmp_path)
    control = collection_policy({"manage_windows_audit": True})
    api.fail = True
    result = manager.reconcile(assignments("logons"), control, 1)
    assert result["management_state"] == "unknown"
    assert "private-fixture" not in json.dumps(result)
    assert json.loads((api.root / "state.json").read_bytes())["subcategories"][LOGON]["previous"] == 0
    api.fail = False
    result = AuditManager(api.root, api=api).reconcile(assignments("logons"), control, 1)
    assert result["management_state"] == "applied"
    manager.reconcile(assignments("logons"), collection_policy({}), 2)
    assert api.actual[LOGON] == api.actual[LOGOFF] == 0


def test_immediate_readback_conflict_is_durable_and_not_retried(tmp_path):
    manager, api = setup(tmp_path)
    api.ignore_write = True
    control = collection_policy({"manage_windows_audit": True})
    result = manager.reconcile(assignments("logons"), control, 1)
    assert result["management_state"] == "blocked"
    assert result["families"]["logons"]["state"] == "managed_by_gpo"
    manager.reconcile(assignments("logons"), control, 1)
    assert len(api.writes) == 1


def test_command_line_requires_explicit_consent_and_enabled_process_family_and_restores_absence(tmp_path):
    manager, api = setup(tmp_path)
    control = collection_policy({"manage_windows_audit": True})
    manager.reconcile(assignments("processes"), control, 1)
    assert not api.command_writes
    consent = collection_policy({"manage_windows_audit": True, "audit_process_command_line": True})
    manager.reconcile(assignments("logons"), consent, 2)
    assert not api.command_writes
    report = manager.reconcile(assignments("processes"), consent, 3)
    assert report["command_line_enabled"] is True and api.command_writes == [1]
    manager.reconcile(assignments("processes"), collection_policy({}), 4)
    assert api.command_writes == [1, None] and api.command is None


def test_registry_gpo_and_later_registry_drift_block_changes(tmp_path):
    manager, api = setup(tmp_path)
    control = collection_policy({"manage_windows_audit": True, "audit_process_command_line": True})
    api.command_owner = "managed_by_gpo"
    assert manager.reconcile(assignments("processes"), control, 1)["management_state"] == "blocked"
    assert not api.writes and not api.command_writes
    api.command_owner = "ok"
    manager.reconcile(assignments("processes"), control, 1)
    api.command = None
    assert manager.reconcile(assignments("processes"), control, 1)["management_state"] == "blocked"
    assert api.command_writes == [1]


def test_corrupted_state_never_changes_windows(tmp_path):
    manager, api = setup(tmp_path)
    api.root.mkdir()
    (api.root / "state.json").write_text('{"subcategories":{"arbitrary":{}},"command_line":null}')
    result = manager.reconcile(assignments("logons"), collection_policy({"manage_windows_audit": True}), 1)
    assert result["management_state"] == "unknown" and not api.writes


def test_native_guid_layout_query_free_and_none_mask_set_with_fake_dll(monkeypatch):
    monkeypatch.setattr(native, "security_privilege", nullcontext)
    api = native.WindowsAuditAPI.__new__(native.WindowsAuditAPI)
    captured = []
    memory = (native.AuditPolicyInformation * 1)(native.AuditPolicyInformation(native.GUID.parse(LOGON), 4, native.GUID()))
    def query(values, count, out):
        assert bytes(values[0]) == UUID(LOGON).bytes_le and count == 1
        ctypes.cast(out, ctypes.POINTER(ctypes.POINTER(native.AuditPolicyInformation)))[0] = ctypes.cast(
            memory, ctypes.POINTER(native.AuditPolicyInformation))
        return True
    def write(values, count):
        captured.append((bytes(values[0].subcategory), values[0].mask, count))
        return True
    api.advapi = SimpleNamespace(AuditQuerySystemPolicy=query, AuditFree=Mock(), AuditSetSystemPolicy=write)
    api.is_system = lambda: True
    assert ctypes.sizeof(native.GUID) == 16 and ctypes.sizeof(native.AuditPolicyInformation) == 36
    assert api.query({LOGON}) == {LOGON: 0}
    api.advapi.AuditFree.assert_called_once()
    api.set({LOGON: 0})
    assert captured == [(UUID(LOGON).bytes_le, 4, 1)]


def test_audit_readback_is_separate_from_policy_acknowledgement(tmp_path):
    manager, api = setup(tmp_path)
    transport = Mock()
    agent = "00000000-0000-4000-8000-000000000001"
    applied = apply_policy(SimpleNamespace(collection_enabled=False), "00000000-0000-4000-8000-000000000002",
        {"agent_id": agent, "policy_revision": 2, "assigned_modules": assignments("logons"),
         "collection_policy": {"manage_windows_audit": True}}, transport, SimpleNamespace(agent_id=agent), audit_manager=manager)
    transport.post.assert_called_once_with("/api/v1/agent/policy-report",
        {"applied_policy_revision": 2, "collection_state": "active"}, identity=SimpleNamespace(agent_id=agent))
    report = applied.windows_audit
    assert report["policy_revision"] == 2 and report["management_state"] == "applied"
    assert api.actual[LOGON] == 3


@pytest.mark.parametrize("policy", [{"manage_windows_audit": 1}, {"audit_process_command_line": "true"}])
def test_management_flags_are_strict_booleans(policy):
    with pytest.raises(ValueError, match="agent_collection_policy_invalid"):
        collection_policy(policy)


def install_rsop(monkeypatch, *, domain=True, gpos=(), legacy=(), registry=(), fail=False):
    query = Mock(side_effect=lambda sql: list(gpos) if "RSOP_GPO" in sql else list(legacy)
                 if "RSOP_AuditPolicy" in sql else list(registry))
    package = ModuleType("win32com")
    client = ModuleType("win32com.client")
    client.GetObject = Mock(side_effect=OSError("private-fixture-diagnostic") if fail else None,
                            return_value=SimpleNamespace(ExecQuery=query))
    package.client = client
    monkeypatch.setitem(sys.modules, "win32com", package)
    monkeypatch.setitem(sys.modules, "win32com.client", client)
    monkeypatch.setitem(sys.modules, "pythoncom", SimpleNamespace(CoInitialize=Mock(), CoUninitialize=Mock()))
    monkeypatch.setitem(sys.modules, "win32net", SimpleNamespace(NetGetJoinInformation=lambda _: ("fixture.invalid", 3 if domain else 2)))
    return query


def test_native_ownership_uses_applied_audit_cse_not_domain_membership_alone(monkeypatch):
    monkeypatch.setattr(native, "read_dword", lambda *a: 1)
    monkeypatch.setattr(native, "domain_audit_history", lambda: False)
    query = install_rsop(monkeypatch, gpos=[SimpleNamespace(enabled=True, accessDenied=False, filterAllowed=True,
        fileSystemPath=r"\\fixture.invalid\SYSVOL\fixture", extensionIds=[native.AUDIT_CSE.upper()])])
    assert native.ownership() == "managed_by_gpo"
    assert "RSOP_GPO" in query.call_args_list[0].args[0]
    install_rsop(monkeypatch)
    assert native.ownership() == "ok"


def test_native_ownership_legacy_override_and_missing_domain_evidence(monkeypatch):
    monkeypatch.setattr(native, "domain_audit_history", lambda: False)
    monkeypatch.setattr(native, "read_dword", lambda *a: 0)
    install_rsop(monkeypatch, legacy=[SimpleNamespace(auditSetting=0)])
    assert native.ownership() == "managed_by_gpo"
    monkeypatch.setattr(native, "read_dword", lambda *a: 1)
    assert native.ownership() == "ok"
    install_rsop(monkeypatch, fail=True)
    assert native.ownership() == "unknown"
    install_rsop(monkeypatch, domain=False, fail=True)
    assert native.ownership() == "ok"


def test_native_registry_policy_blocks_optional_command_line_management(monkeypatch):
    api = native.WindowsAuditAPI.__new__(native.WindowsAuditAPI)
    install_rsop(monkeypatch, registry=[SimpleNamespace(keyName=native.COMMAND_KEY)])
    assert api.command_line_ownership() == "managed_by_gpo"
    install_rsop(monkeypatch, fail=True)
    assert api.command_line_ownership() == "unknown"


def test_partial_write_failure_preserves_all_original_values(tmp_path):
    manager, api = setup(tmp_path)
    original_write = api.set
    def partial(changes):
        api.actual[LOGON] = changes[LOGON]
        raise OSError("private-fixture-diagnostic")
    api.set = partial
    control = collection_policy({"manage_windows_audit": True})
    assert manager.reconcile(assignments("logons"), control, 1)["management_state"] == "unknown"
    api.set = original_write
    assert manager.reconcile(assignments("logons"), control, 1)["management_state"] == "applied"
    manager.reconcile(assignments("logons"), collection_policy({}), 2)
    assert api.actual[LOGON] == api.actual[LOGOFF] == 0


def test_crash_after_restore_write_before_readback_finishes_without_reapplying(tmp_path):
    manager, api = setup(tmp_path)
    manager.reconcile(assignments("logons"), collection_policy({"manage_windows_audit": True}), 1)
    query = api.query
    calls = 0
    def interrupted(guids):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("private-fixture-diagnostic")
        return query(guids)
    api.query = interrupted
    assert manager.reconcile(assignments("logons"), collection_policy({}), 2)["management_state"] == "unknown"
    api.query = query
    result = AuditManager(api.root, api=api).reconcile(assignments("logons"), collection_policy({}), 2)
    assert result["management_state"] == "restored"
    assert api.writes == [{LOGON: 3, LOGOFF: 1}, {LOGON: 0, LOGOFF: 0}]


def test_shared_file_bits_union_downgrade_and_restart_keep_original_masks(tmp_path):
    manager, api = setup(tmp_path)
    guid = "0cce9244-69ae-11d9-bed3-505054503030"
    api.actual[guid] = 0
    control = collection_policy({"manage_windows_audit": True})
    manager.reconcile([], control, 1, file_masks={guid: 2}, file_manage=True)
    assert api.actual[guid] == 2
    # Widening a requirement must save the actual pre-write state, so a
    # failed API call can be retried after restart without inventing drift.
    api.fail = True
    manager.reconcile([], control, 2, file_masks={guid: 3}, file_manage=True)
    saved = json.loads((api.root / "state.json").read_bytes())["subcategories"][guid]
    assert saved == {"previous": 0, "applied": 2, "phase": "restoring"}
    api.fail = False
    manager = AuditManager(api.root, api=api)
    assert manager.reconcile([], control, 2, file_masks={guid: 3}, file_manage=True)["management_state"] == "applied"
    assert api.actual[guid] == 3
    manager.reconcile([], control, 3, file_masks={guid: 2}, file_manage=True)
    assert api.actual[guid] == 2
    assert manager.reconcile([], collection_policy({}), 4, file_masks={guid: 2})["management_state"] == "disabled"
    assert api.actual[guid] == 2
    manager.reconcile([], collection_policy({}), 5)
    assert api.actual[guid] == 0
