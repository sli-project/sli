"""Security rules consume attested actions and inventory, never live Windows/DB."""
from copy import deepcopy
import json

import pytest

from server.sli.plugins.file_audit import rules
from sli_agent.file_audit_policy import policy
from tests.unit.test_file_audit_contracts import AGENT, settings

SID = "S-1-5-21-1-2-3-1001"
GROUP = "S-1-5-21-1-2-3-513"
START = "2026-01-05T05:00:00+00:00"


def config():
    value = settings()
    value["roots"][0]["important"] = True
    return policy(value)


def action(index=1, **changes):
    return {"action_id": f"{index:064x}", "agent_id": AGENT, "source_instance_id": AGENT,
            "collection_scope_id": "scope:one", "subject_sid": SID, "operation": "read",
            "outcome": "success", "correlation_state": "complete", "object_type": "file",
            "observed_at": START, "path": rf"C:\synthetic\file{index}",
            "evidence": [{"evidence_key": f"{index:064x}", "core_evidence_ref": f"synthetic:{index}",
                          "role": "primary"}], **changes}


def snapshot(**changes):
    return {"snapshot_id": "00000000-0000-4000-8000-000000000003", "snapshot_sha256": "a" * 64,
            "agent_id": AGENT, "source_instance_id": AGENT, "collection_scope_id": "scope:one",
            "observed_at_utc": "2026-01-05T04:00:00+00:00", "completeness": "complete",
            "unread_objects": 0, "share": {"path": r"C:\synthetic", "complete": True,
                                         "dacl": "D:(A;;FR;;;WD)"},
            "local_groups": {"complete": True, "groups": []},
            "objects": [{"path": r"C:\synthetic\file1", "object_type": "file",
                         "dacl": "D:(A;;FR;;;WD)"}], **changes}


def activity(rows, **kwargs):
    return rules.activity_findings(rows, agent_id=AGENT, source_instance_id=AGENT, **kwargs)


def test_mass_counts_distinct_files_in_sliding_window_and_keeps_evidence():
    cfg = config()
    cfg["mass_operation_files"] = 20
    rows = [action(i) for i in range(1, 21)]
    rows += [action(21, path=rows[0]["path"].upper())]
    found = activity(rows, config=cfg)
    assert len(found) == 1
    assert found[0]["rule_code"] == "file-audit.mass-read"
    assert found[0]["details"]["distinct_files"] == 20
    assert len(found[0]["action_ids"]) == 21
    assert found == activity(list(reversed(rows)), config=cfg)
    assert not activity(rows[:19], config=cfg)
    assert not activity(rows, config=config())  # owner default 100
    old = [action(i, observed_at="2026-01-05T04:54:59+00:00") for i in range(1, 20)]
    assert not activity(old + [action(20)], config=cfg)


@pytest.mark.parametrize("changes", [
    {"operation": "access_check"}, {"operation": "delete_right"}, {"object_type": "directory"},
    {"outcome": "failure"}, {"subject_sid": None}, {"correlation_state": "ambiguous"},
    {"source_instance_id": "synthetic-other"}, {"collection_scope_id": "scope:other"},
])
def test_unconfirmed_or_unscoped_activity_does_not_count(changes):
    cfg = config()
    cfg["mass_operation_files"] = 1
    assert not activity([action(**changes)], config=cfg)


def test_mass_isolated_by_actor_scope_operation_and_administrator_exclusions():
    cfg = config()
    cfg["mass_operation_files"] = 2
    assert not activity([action(), action(2, subject_sid=GROUP)], config=cfg)
    assert not activity([action(), action(2, operation="delete")], config=cfg)
    cfg["service_account_exclusions"] = [SID]
    assert not activity([action(), action(2)], config=cfg)


def test_confirmed_delete_and_inventory_file_resolution():
    cfg = config()
    cfg["mass_operation_files"] = 1
    assert activity([action(operation="delete")], config=cfg)[0]["rule_code"] == "file-audit.mass-delete"
    row = action(object_type="unknown", correlation_state="partial")
    assert not activity([row], config=cfg)
    found = activity([row], config=cfg, snapshots=[snapshot()])
    assert found[0]["snapshot_ids"] == [snapshot()["snapshot_id"]]
    future = snapshot(observed_at_utc="2026-01-05T06:00:00+00:00")
    assert not activity([row], config=cfg, snapshots=[future])


def test_separate_mass_bursts_and_exact_window_boundary():
    cfg = config()
    cfg["mass_operation_files"] = 2
    rows = [action(), action(2, observed_at="2026-01-05T05:05:00Z"),
            action(3, observed_at="2026-01-05T06:00:00Z"), action(4, observed_at="2026-01-05T06:01:00Z")]
    assert len(activity(rows, config=cfg)) == 2
    rows[1]["observed_at"] = "2026-01-05T05:05:00.000001Z"
    assert len(activity(rows, config=cfg)) == 1


def test_partial_snapshot_cannot_replace_full_inventory():
    cfg = config()
    cfg["mass_operation_files"] = 1
    full = snapshot()
    partial = snapshot(snapshot_id="00000000-0000-4000-8000-000000000006", completeness="partial",
                       unread_objects=1, observed_at_utc="2026-01-05T04:30:00Z")
    partial["objects"][0]["object_type"] = "directory"
    row = action(object_type="unknown", correlation_state="partial")
    assert activity([row], config=cfg, snapshots=[full, partial])[0]["snapshot_ids"] == [full["snapshot_id"]]


def calendar():
    return {"timezone": "Etc/GMT-3", "weekdays": [0, 1, 2, 3, 4], "start": "09:00", "end": "18:00",
            "excluded_dates": [], "exceptions": []}


def test_out_of_hours_uses_platform_timezone_boundaries_and_exceptions():
    cfg = config()
    schedule = calendar()
    found = activity([action()], config=cfg, working_time=schedule)
    assert found[0]["rule_code"] == "file-audit.out-of-hours"
    assert found[0]["details"]["local_time"].startswith("2026-01-05T08:00")
    for instant in ("2026-01-05T06:00:00Z", "2026-01-05T14:59:59Z"):
        assert not activity([action(observed_at=instant)], config=cfg, working_time=schedule)
    assert activity([action(observed_at="2026-01-05T15:00:00Z")], config=cfg, working_time=schedule)
    schedule["exceptions"] = [{"subject_sid": SID, "start_utc": "2026-01-05T04:00:00Z",
                              "end_utc": "2026-01-05T06:00:00Z", "reason": "synthetic"}]
    assert not activity([action()], config=cfg, working_time=schedule)
    assert not activity([action()], config=cfg)  # missing schedule is unknown


def test_permission_rules_distinguish_ntfs_grant_from_smb_effective_access():
    snap = snapshot()
    snap["objects"][0]["dacl"] = f"D:(A;;FR;;;{SID})"
    snap["share"]["dacl"] = f"D:(A;;FR;;;{GROUP})"
    principals = {SID: {"kind": "user", "enabled": True, "group_sids": [], "complete": True},
                  GROUP: {"kind": "group", "domain_users": False}}
    found = rules.permission_findings(snap, config=config(), principals=principals)
    assert len(found) == 1 and found[0]["rule_code"] == "file-audit.direct-user-rights"
    assert found[0]["details"]["effective_smb_mask"] == 0
    assert found[0]["details"]["ntfs_mask"] != 0
    assert found[0]["snapshot_ids"] == [snap["snapshot_id"]]


def test_broad_disabled_and_direct_grants_preserve_deny_and_unknown_aces():
    snap = snapshot()
    snap["share"]["dacl"] = "D:(A;;0x1301bf;;;WD)"
    snap["objects"][0]["dacl"] = f"D:(A;;0x1301bf;;;WD)(A;;FR;;;{SID})"
    principals = {SID: {"kind": "user", "enabled": False, "group_sids": [], "complete": True}}
    found = rules.permission_findings(snap, config=config(), principals=principals)
    assert {item["rule_code"] for item in found} == {
        "file-audit.broad-write", "file-audit.direct-user-rights", "file-audit.disabled-account-rights"}
    denied = deepcopy(snap)
    denied["share"]["dacl"] = "D:(A;;FR;;;WD)"
    denied["objects"][0]["dacl"] = "D:(D;;FA;;;WD)(A;;FA;;;WD)"
    assert not rules.permission_findings(denied, config=config())
    opaque = deepcopy(snap)
    opaque["objects"][0]["dacl"] = 'D:(XA;;FA;;;WD;(synthetic-condition))'
    result = rules.permission_findings(opaque, config=config())
    assert any(row["conclusion_state"] == "requires_review" for row in result)


def test_partial_snapshot_and_missing_membership_do_not_claim_effective_access():
    snap = snapshot(completeness="partial", unread_objects=1)
    snap["objects"][0]["dacl"] = f"D:(A;;FR;;;{SID})"
    principals = {SID: {"kind": "user", "enabled": True, "group_sids": [], "complete": False}}
    found = rules.permission_findings(snap, config=config(), principals=principals)
    assert found[0]["details"]["effective_smb_mask"] is None
    assert found[0]["details"]["coverage_state"] == "partial"
    cfg = config()
    cfg["service_account_exclusions"] = [SID]
    assert not rules.permission_findings(snap, config=cfg, principals=principals)


def test_domain_users_and_nested_local_groups_with_inherited_grants():
    snap = snapshot()
    snap["objects"][0]["dacl"] = f"D:(A;ID;FW;;;{GROUP})(A;ID;FR;;;{SID})"
    snap["share"]["dacl"] = "D:(A;;FR;;;S-1-5-32-545)"
    snap["local_groups"]["groups"] = [{"group_sid": "S-1-5-32-546", "member_sids": [GROUP]},
        {"group_sid": "S-1-5-32-545", "member_sids": ["S-1-5-32-546"]}]
    principals = {GROUP: {"kind": "group", "domain_users": True},
                  SID: {"kind": "user", "enabled": False, "group_sids": [GROUP], "complete": True}}
    found = rules.permission_findings(snap, config=config(), principals=principals)
    assert {row["rule_code"] for row in found} == {"file-audit.broad-write", "file-audit.disabled-account-rights"}
    disabled = next(row for row in found if row["rule_code"] == "file-audit.disabled-account-rights")
    assert disabled["details"]["effective_smb_mask"] & 1


def test_unresolved_sid_is_preserved_for_review_and_no_name_is_guessed():
    snap = snapshot()
    snap["objects"][0]["dacl"] = f"D:(A;;FR;;;{SID})"
    found = rules.permission_findings(snap, config=config())
    assert found[0]["subject_sid"] == SID
    assert found[0]["conclusion_state"] == "requires_review"
    assert found[0]["details"]["reason"] == "principal_not_observed"


def test_calendar_overnight_holiday_and_dst_use_local_date():
    schedule = {**calendar(), "start": "22:00", "end": "06:00", "weekdays": [0]}
    assert not activity([action(observed_at="2026-01-05T23:00:00Z")], config=config(), working_time=schedule)
    schedule["excluded_dates"] = ["2026-01-05"]
    assert activity([action(observed_at="2026-01-05T23:00:00Z")], config=config(), working_time=schedule)
    schedule = {**calendar(), "timezone": "Europe/Berlin", "weekdays": [6], "start": "02:00", "end": "03:00"}
    for instant in ("2026-10-25T00:30:00Z", "2026-10-25T01:30:00Z"):
        assert not activity([action(observed_at=instant)], config=config(), working_time=schedule)


def test_working_time_setting_validation_is_strict_and_has_no_silent_default():
    from server.sli.core import platform_settings
    spec = platform_settings.SETTINGS["security.working_time"]
    assert spec.default is None and not spec.environment
    assert json.loads(spec.validate(json.dumps(calendar()))) == calendar()
    for field, value in (("timezone", "invalid-zone"), ("start", "25:00"), ("weekdays", [True]), ("unexpected", 1)):
        invalid = {**calendar(), field: value}
        with pytest.raises(ValueError, match="working_time_invalid"):
            spec.validate(json.dumps(invalid))


def test_missing_working_time_setting_is_unknown(monkeypatch):
    from server.sli.core import platform_settings
    platform_settings.clear_cache()
    monkeypatch.setattr(platform_settings.database, "query_rows", lambda *_a, **_k: [])
    with pytest.raises(ValueError, match="setting_not_configured"):
        platform_settings.get_setting("security.working_time")
    platform_settings.clear_cache()
