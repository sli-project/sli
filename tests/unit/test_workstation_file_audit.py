"""Workstation file-audit opt-in contracts; no Windows or database access."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from sli_agent.file_audit_policy import audit_requirements, policy
from sli_agent.modules import configured_modules
from tests.unit.test_file_audit_collection import NOW, collector, xml
from tests.unit.test_file_audit_contracts import AGENT, settings
from tests.unit.test_sli_agent_file_audit import command, execute, setup


def workstation_policy():
    value = {**settings(), "source_kind": "workstation"}
    value["roots"][0]["share_name"] = ""
    return value


def test_workstation_policy_supports_local_roots_and_defaults_to_server():
    assert policy(workstation_policy())["source_kind"] == "workstation"
    assert policy(settings()).get("source_kind", "server") == "server"
    with pytest.raises(ValueError):
        policy({**settings(), "source_kind": "unknown"})


def test_workstation_audit_plan_does_not_enable_smb_auditing():
    masks = audit_requirements(workstation_policy())
    assert "0cce921d-69ae-11d9-bed3-505054503030" in masks
    assert "0cce9224-69ae-11d9-bed3-505054503030" not in masks
    assert "0cce9244-69ae-11d9-bed3-505054503030" not in masks


def test_workstation_file_audit_is_explicit_and_can_coexist_with_security_families():
    config = SimpleNamespace(collection_enabled=False)
    workstation = {"module_id": "sli.workstations", "enabled": True, "config": {}}
    assert [m.module_id for m in configured_modules(config, AGENT, [workstation])] == ["sli.heartbeat", "sli.workstations"]
    audit = {"module_id": "sli.file-audit", "enabled": True, "config": workstation_policy()}
    assert {m.module_id for m in configured_modules(config, AGENT, [workstation, audit])} == {
        "sli.heartbeat", "sli.workstations", "sli.file-audit"}
    with pytest.raises(ValueError, match="workstation_required"):
        configured_modules(config, AGENT, [audit])


@pytest.mark.parametrize("sid,name", [
    ("S-1-5-18", "SYSTEM"), ("S-1-5-19", "LOCAL SERVICE"), ("S-1-5-20", "NETWORK SERVICE"),
    ("S-1-5-80-123", "synthetic-service"), ("S-1-5-21-1-2-3-1001", "synthetic-device$"),
    ("S-1-5-21-1-2-3-1002", "synthetic-managed$"), ("S-1-5-21-1-2-3-1003", "synthetic-excluded"),
])
def test_only_user_file_events_are_collected(sid, name):
    config = workstation_policy()
    config["service_account_exclusions"] = ["S-1-5-21-1-2-3-1003"]
    rows = [(xml(1, SubjectUserSid=sid, SubjectUserName=name), "b1"),
            (xml(2, SubjectUserSid="S-1-5-21-1-2-3-1004", SubjectUserName="synthetic-user"), "b2")]
    sample = collector(config, reader=lambda *_: rows, path_check=lambda *_: "file", account_check=lambda _: True).collect(now=NOW)
    assert [r["record_id"] for r in sample.payload["records"]] == [2]
    assert sample.filtered_count == 1
    assert sample.payload["header"]["cursor"]["last_record_id"] == 2


def test_local_apply_and_restore_do_not_require_or_change_smb_permissions(tmp_path):
    manager, api, audit = setup(tmp_path)
    api.share = lambda *_: pytest.fail("local roots must not query SMB")
    original = deepcopy(api.objects[next(iter(api.objects))].describe())
    config = workstation_policy()
    _, applied = execute(manager, command("apply", config=config))
    assert applied["scopes"][0]["state"] == "verified"
    assert applied["snapshots"][0]["share"] == {
        "name": "", "path": config["roots"][0]["path"], "dacl": "", "complete": True}
    manager.acknowledge(applied)
    _, restored = execute(manager, command("restore", config=config))
    assert restored["ownership_remaining"] is False
    assert api.objects[next(iter(api.objects))].describe() == original
    assert all(value == 0 for value in audit.actual.values())


def test_local_service_account_is_filtered_and_failed_classification_is_a_gap():
    config = workstation_policy()
    raw = xml(1, SubjectUserSid="S-1-5-21-1-2-3-1004")
    sample = collector(config, reader=lambda *_: [(raw, "b1")], account_check=lambda _: False).collect(now=NOW)
    assert not sample.payload["records"] and sample.filtered_count == 1
    def unavailable(_):
        raise RuntimeError("synthetic-private-diagnostic")
    sample = collector(config, reader=lambda *_: [(raw, "b1")], account_check=unavailable).collect(now=NOW)
    assert not sample.payload["records"] and sample.lost_count == 1 and sample.continuity_state == "gap"


def test_native_account_filter_excludes_configured_services_and_computer_accounts(monkeypatch):
    import sys
    from sli_agent.file_audit_accounts import UserAccountFilter
    service_api = SimpleNamespace(SC_MANAGER_ENUMERATE_SERVICE=1, SERVICE_WIN32=2, SERVICE_STATE_ALL=3,
        SERVICE_QUERY_CONFIG=4, OpenSCManager=lambda *_: "scm", CloseServiceHandle=lambda _: None,
        EnumServicesStatus=lambda *_: [("synthetic-service", "Synthetic", {})],
        OpenService=lambda *_: "service", QueryServiceConfig=lambda *_: [None] * 7 + ["synthetic-service-user"])
    account_api = SimpleNamespace(ConvertStringSidToSid=lambda sid: sid, ConvertSidToStringSid=lambda sid: sid,
        LookupAccountName=lambda *_: ("S-1-5-21-1-2-3-1001", "synthetic", 1),
        LookupAccountSid=lambda _, sid: ("synthetic-device$" if sid.endswith("1002") else "synthetic-user", "synthetic", 1), SidTypeUser=1)
    monkeypatch.setitem(sys.modules, "win32service", service_api)
    monkeypatch.setitem(sys.modules, "win32security", account_api)
    check = UserAccountFilter()
    assert not check("S-1-5-21-1-2-3-1001")
    assert not check("S-1-5-21-1-2-3-1002")
    assert check("S-1-5-21-1-2-3-1003")


def test_local_permission_rules_do_not_invent_an_unknown_smb_descriptor(tmp_path):
    from server.sli.plugins.file_audit.rules import permission_findings
    manager, api, _ = setup(tmp_path)
    config = workstation_policy()
    api.objects[r"C:\synthetic"].row["dacl"] = "D:(A;;FW;;;WD)"
    _, applied = execute(manager, command("check", config=config))
    snapshot = {**applied["snapshots"][0], "agent_id": AGENT, "source_instance_id": AGENT}
    findings = permission_findings(snapshot, config=policy(config))
    assert [row["rule_code"] for row in findings] == ["file-audit.broad-write"]
    assert findings[0]["details"]["layer"] == "ntfs"
