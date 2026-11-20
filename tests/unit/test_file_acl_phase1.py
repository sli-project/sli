"""Phase-one ACL evidence identity and conservative classification."""
from copy import deepcopy
from dataclasses import replace
from uuid import NAMESPACE_URL, uuid5

import pytest

from server.sli.plugins.file_audit.rules import permission_findings
from server.sli.semantic.file_acl import classify_acl_result, resource_key
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceRefError, EvidenceScope
from sli_agent.envelope import digest
from tests.unit.test_file_audit_rules import AGENT, SID, config, snapshot

INSTALLATION = "00000000-0000-4000-8000-000000000099"
COMMAND = "synthetic-acl-command"


def retained_snapshot(rights="FW", *, source_kind="server", important=True):
    cfg = config()
    cfg["roots"][0]["important"] = important
    cfg["source_kind"] = source_kind
    snap = snapshot()
    snap["objects"][0]["dacl"] = f"D:(A;;{rights};;;{SID})"
    snap["share"]["dacl"] = f"D:(A;;FA;;;{SID})"
    snap["snapshot_sha256"] = digest({key: value for key, value in snap.items()
                                      if key not in ("snapshot_sha256", "snapshot_id")})
    snap["snapshot_id"] = str(uuid5(NAMESPACE_URL, COMMAND + snap["snapshot_sha256"]))
    principal = {"kind": "user", "enabled": True, "complete": True, "group_sids": []}
    rows = permission_findings(snap, config=cfg, principals={SID: principal})
    row = next(row for row in rows if row["rule_code"] == "file-audit.direct-user-rights"
               and row["details"]["layer"] == "ntfs")
    return cfg, snap, row


def test_snapshot_ref_has_real_uuid_command_namespace_and_exact_hash():
    cfg, snap, _ = retained_snapshot()
    scope = EvidenceScope(INSTALLATION, "sli.file-audit", AGENT,
                          "audit-command:" + COMMAND, cfg["roots"][0]["collection_scope_id"])
    ref = EvidenceRef("file_audit_snapshot", snap["snapshot_id"], snap["snapshot_sha256"], scope)
    assert ref.native_id == snap["snapshot_id"]
    for changes in ({"native_id": "a" * 64}, {"native_id": "00000000-0000-4000-8000-00000000000A"},
                    {"scope": replace(scope, collection_scope_id="")},
                    {"scope": replace(scope, source_generation="event-generation")},
                    {"scope": replace(scope, source_generation="audit-command:")}):
        with pytest.raises(EvidenceRefError):
            replace(ref, **changes)


@pytest.mark.parametrize("important,rights,severity", [(True, "FW", "high"), (False, "FW", "medium"),
                                                       (True, "FR", "medium")])
def test_direct_risk_requires_sensitive_root_and_proven_dangerous_effective_rights(important, rights, severity):
    cfg, snap, row = retained_snapshot(rights, important=important)
    verdict = classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)
    assert verdict["severity"] == severity
    assert verdict["coverage_state"] == "complete"


@pytest.mark.parametrize("change", ["share-deny", "membership", "local-groups", "unsupported", "inherited"])
def test_unknown_or_denied_rights_never_become_high(change):
    cfg, snap, row = retained_snapshot()
    principal = deepcopy(row["details"]["principal"])
    if change == "share-deny":
        snap["share"]["dacl"] = f"D:(D;;FA;;;{SID})(A;;FA;;;{SID})"
    elif change == "membership":
        principal["complete"] = False
    elif change == "local-groups":
        snap["local_groups"]["complete"] = False
    elif change == "unsupported":
        snap["objects"][0]["dacl"] = f"D:(XA;;FW;;;{SID};(synthetic))"
    else:
        snap["objects"][0]["dacl"] = f"D:(A;ID;FW;;;{SID})"
    rows = permission_findings(snap, config=cfg, principals={SID: principal})
    direct = [item for item in rows if item["rule_code"] == "file-audit.direct-user-rights"
              and item["details"]["layer"] == "ntfs"]
    assert not direct or classify_acl_result(direct[0], snapshot=snap, config=cfg,
                                            installation_id=INSTALLATION)["severity"] == "medium"


def test_broad_write_is_medium_and_resource_identity_ignores_path_subject_and_command():
    cfg, snap, _ = retained_snapshot()
    snap["objects"][0]["dacl"] = "D:(A;;FW;;;WD)"
    row = next(item for item in permission_findings(snap, config=cfg)
               if item["rule_code"] == "file-audit.broad-write")
    verdict = classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)
    assert verdict["severity"] == "medium"
    assert verdict["effective_access_state"] == "requires_review"
    changed = {**row, "subject_sid": "S-1-1-0", "result_id": "f" * 64,
               "details": {**row["details"], "path": r"C:\synthetic\another"}}
    assert resource_key(row, installation_id=INSTALLATION) == resource_key(changed, installation_id=INSTALLATION)
    for key in ("agent_id", "source_instance_id", "collection_scope_id"):
        assert resource_key({**row, key: "synthetic-other"}, installation_id=INSTALLATION) != verdict["resource_key"]


def test_forged_masks_or_snapshot_binding_are_rejected():
    cfg, snap, row = retained_snapshot("FR")
    row["details"]["effective_smb_mask"] = 0x1f01ff
    with pytest.raises(ValueError, match="file_acl_result_invalid"):
        classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)


def test_workstation_requires_complete_local_membership_without_smb():
    cfg, snap, row = retained_snapshot(source_kind="workstation")
    assert classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)["severity"] == "high"
    snap["local_groups"]["complete"] = False
    principal = row["details"]["principal"]
    row = next(item for item in permission_findings(snap, config=cfg, principals={SID: principal})
               if item["rule_code"] == "file-audit.direct-user-rights")
    assert classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)["severity"] == "medium"


@pytest.mark.parametrize("inherited", [False, True])
def test_direct_read_does_not_inherit_high_from_some_other_write_grant(inherited):
    cfg, snap, old = retained_snapshot("FR")
    if inherited:
        snap["objects"][0]["dacl"] = f"D:(A;;FR;;;{SID})(A;ID;FW;;;{SID})"
    else:
        snap["objects"][0]["dacl"] = f"D:(A;;FR;;;{SID})(A;;FW;;;WD)"
    row = next(item for item in permission_findings(snap, config=cfg,
               principals={SID: old["details"]["principal"]})
               if item["rule_code"] == "file-audit.direct-user-rights" and item["details"]["layer"] == "ntfs")
    assert row["details"]["effective_smb_mask"] & 0x6
    assert classify_acl_result(row, snapshot=snap, config=cfg, installation_id=INSTALLATION)["severity"] == "medium"
