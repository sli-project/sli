"""Pure ACL classification over retained, externally verified rule/snapshot facts.

This module grants no source authority and publishes nothing. A caller must first
verify snapshot provenance and the retained result hash with the database. User
kind and membership remain retained AD enrichment, never inferred from a SID.
"""
from uuid import UUID

from server.sli.plugins.file_audit.acl import (
    WRITE_MASK,
    access_mask,
    parse_dacl,
    token_for,
)
from server.sli.plugins.file_audit.rules import permission_findings
from sli_agent.envelope import digest


def resource_key(result, *, installation_id):
    """Command/path/principal-independent identity; evidence authorization stays exact."""
    if str(UUID(installation_id)) != installation_id:
        raise ValueError("file_acl_result_invalid")
    return digest(["file-acl-resource.v1", installation_id,
                   *[result[key] for key in ("agent_id", "source_instance_id", "collection_scope_id")]])


def classify_acl_result(result, *, snapshot, config, installation_id):
    """Recompute supported grants; unknown or read-only direct ACLs stay medium.

    Partial inventory limits coverage, not a positively observed object's ACL.
    This verdict never asserts that a retained grant is still present today.
    """
    try:
        code, details = result["rule_code"], result["details"]
        if code not in {"file-audit.broad-write", "file-audit.direct-user-rights"}:
            raise ValueError
        sid = result["subject_sid"]
        principal = details["principal"]
        # A mutable caller mask must not become an authoritative permission.
        candidates = permission_findings(snapshot, config=config, principals={sid: principal})
        if result not in candidates or result["conclusion_state"] != "observed":
            raise ValueError
        root = next(root for root in config["roots"]
                    if root["collection_scope_id"] == result["collection_scope_id"])
        severity = "medium"
        effective = details["effective_smb_mask"]
        effective_state = details["effective_smb_state"]
        direct_mask = 0
        if details["layer"] == "ntfs":
            obj = next(obj for obj in snapshot["objects"] if obj["path"] == details["path"])
            aces, known = parse_dacl(obj["dacl"])
            explicit = tuple(ace for ace in aces if ace.sid == sid and not ace.inherited)
            direct_mask = access_mask(explicit, {sid}) if known else 0
        if config.get("source_kind") == "workstation" and details["layer"] == "ntfs":
            obj = next(obj for obj in snapshot["objects"] if obj["path"] == details["path"])
            aces, known = parse_dacl(obj["dacl"])
            token, complete = token_for(sid, principal, snapshot["local_groups"])
            effective = access_mask(aces, token) if known and complete else None
            effective_state = "dacl_model" if effective is not None else "requires_review"
        if (code == "file-audit.direct-user-rights" and root["important"] is True
                and principal.get("kind") == "user" and principal.get("enabled") is True
                and details["layer"] == "ntfs" and details["membership_complete"] is True
                and effective_state == "dacl_model" and effective is not None
                and effective & direct_mask & WRITE_MASK):
            severity = "high"
        return {"rule_code": code, "severity": severity,
                "resource_key": resource_key(result, installation_id=installation_id),
                "observed_at": result["observed_at"], "path": details["path"],
                "coverage_state": snapshot["completeness"],
                "effective_access_state": effective_state,
                "limitations": list(details["limitations"])}
    except (KeyError, TypeError, ValueError, StopIteration):
        raise ValueError("file_acl_result_invalid") from None
