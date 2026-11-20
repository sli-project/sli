#!/usr/bin/env python3
"""Plan/apply a domain-scoped VPN evidence assignment for an explicit subject.

Assignments use the ordinary access model. The command verifies existing
report/session access, rejects matching denies and rechecks its approved plan.
Existing assignments require no migration and retain their subject and scope.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from psycopg.conninfo import conninfo_to_dict, make_conninfo

from server.sli.access import access_control_v4
from server.sli.access.access_control_v4 import capability_decision_for_resource_groups
from server.sli.reports.vpn_report_composition import vpn_report_composition_decision
from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment


CAPABILITY_KEY = access_control_v4.VPN_SESSION_EVIDENCE_CAPABILITY
PLAN_CONFIRM_PREFIX = "APPLY-VPN-SESSION-EVIDENCE:"
OWNER_REASON = "Owner-approved exact VPN session evidence access"
OWNER_APPROVED_BY = "owner"
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

# CLI output is consumed by operational tooling.  Never print a driver error,
# connection string, or arbitrary exception text; these are the only stable
# application failure states the bounded controller intentionally exposes.
SAFE_ERROR_CODES = frozenset({
    "protected_postgres_credentials_required",
    "local_vpn_grant_target_mismatch",
    "connected_vpn_grant_target_mismatch",
    "vpn_report_scope_required",
    "vpn_evidence_matching_deny",
    "vpn_evidence_result_not_allowed",
    "vpn_evidence_foreign_scope_widened",
    "vpn_evidence_target_not_active",
    "vpn_evidence_domain_not_registered",
    "vpn_evidence_capability_not_registered",
    "vpn_evidence_target_access_mismatch",
    "vpn_evidence_action_invalid",
    "vpn_evidence_plan_arguments_invalid",
    "vpn_evidence_confirmation_invalid",
    "vpn_evidence_not_ready",
    "vpn_evidence_plan_changed",
    "vpn_evidence_target_invalid",
    "vpn_evidence_audit_actor_invalid",
    "vpn_evidence_grant_metadata_invalid",
    "vpn_evidence_scope_invalid",
    "vpn_evidence_target_changed",
    "vpn_evidence_assignment_write_failed",
})


class VpnEvidenceGrantError(RuntimeError):
    pass


def safe_error_code(exc: BaseException) -> str:
    """Return only audited controller codes, never arbitrary exception text."""
    candidate = str(exc)
    if candidate in SAFE_ERROR_CODES:
        return candidate
    return "vpn_evidence_operation_failed"


def _load_environment() -> None:
    if not (
        os.getenv("ADLOG_PG_DSN", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
        and os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    ):
        load_supervisor_environment()


def _admin_dsn() -> str:
    source = os.getenv("ADLOG_PG_DSN", "").strip()
    username = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    password = os.getenv("ADLOG_PG_ADMIN_PASSWORD", "")
    if not source or not username or not password:
        raise VpnEvidenceGrantError("protected_postgres_credentials_required")
    values = conninfo_to_dict(source)
    values.update(user=username, password=password)
    return make_conninfo(**values)


def validate_target(dsn: str) -> None:
    parts = conninfo_to_dict(dsn)
    host = str(parts.get("host") or "")
    hostaddr = str(parts.get("hostaddr") or host)
    if (
        host not in LOOPBACK_HOSTS
        or hostaddr not in LOOPBACK_HOSTS
        or parts.get("dbname") != "sli_local"
        or parts.get("service")
    ):
        raise VpnEvidenceGrantError("local_vpn_grant_target_mismatch")


def _connect(dsn: str):
    import psycopg
    from psycopg.rows import dict_row

    return psycopg.connect(
        dsn,
        row_factory=dict_row,
        connect_timeout=5,
        application_name="sli_vpn_evidence_grant_control",
        options="-c statement_timeout=3000 -c lock_timeout=1000",
    )


def _decision(access: Mapping[str, Any], *, domain_id: int) -> dict[str, Any]:
    composition = vpn_report_composition_decision(
        access, source_domain_id=domain_id, action="view"
    )
    evidence = composition.session_evidence
    if not composition.report_allowed:
        return {"status": "not_ready", "reason": "vpn_report_scope_required"}
    if not composition.sessions.allowed:
        return {"status": "not_ready", "reason": str(composition.sessions.reason)}
    if evidence.reason in {"explicit_deny", "invalid_scope_policy"}:
        return {"status": "not_ready", "reason": "vpn_evidence_matching_deny"}
    return {"status": "ready"}


def evaluate_target_access(access: Mapping[str, Any], *, domain_id: int) -> dict[str, Any]:
    """Check the existing report/session path and the prospective exact scope."""
    scope = {"kind": "domain", "ids": [domain_id]}
    baseline = _decision(access, domain_id=domain_id)
    if baseline["status"] != "ready":
        return baseline
    prospective = deepcopy(dict(access))
    policies = [dict(item) for item in prospective.get("capability_policies", [])]
    policies.append({
        "capability_key": CAPABILITY_KEY,
        "effect": "allow",
        "scope": scope,
        "valid": True,
        "source_type": "direct",
        "source": "user:target",
    })
    prospective["capability_policies"] = policies
    domain = _decision(prospective, domain_id=domain_id)
    domain_capability = capability_decision_for_resource_groups(
        prospective, CAPABILITY_KEY,
        resource_groups=[[{"kind": "domain", "id": domain_id}]],
    )
    foreign_capability = capability_decision_for_resource_groups(
        prospective, CAPABILITY_KEY,
        resource_groups=[[{"kind": "domain", "id": domain_id + 1}]],
    )
    if domain["status"] != "ready" or not domain_capability["allowed"]:
        return {"status": "not_ready", "reason": "vpn_evidence_result_not_allowed"}
    if foreign_capability["allowed"]:
        return {"status": "not_ready", "reason": "vpn_evidence_foreign_scope_widened"}
    return {"status": "ready", "domain_allowed": True, "foreign_domain_allowed": False}


def _access_fingerprint_projection(access: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only policy inputs; exclude evaluation time, preferences and secrets."""
    report = next(
        (dict(item) for item in access.get("reports", []) if item.get("report_key") == "vpn.audit"),
        {},
    )
    report_keys = (
        "report_key", "version", "dataset_version", "status", "allowed",
        "assignment_version_state", "missing_capabilities", "grants",
    )
    policies = [
        dict(item) for item in access.get("capability_policies", [])
        if str(item.get("capability_key") or "") in {"vpn.sessions.view", CAPABILITY_KEY}
    ]
    return {
        "packages": [dict(item) for item in access.get("package_explain", [])],
        "capability_policies": policies,
        "explicit_denies": dict(access.get("explicit_denies") or {}),
        "vpn_report": {key: report.get(key) for key in report_keys},
    }


def _fingerprint(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return sha256(encoded).hexdigest()


def _capture_state(cursor: Any, *, subject_id: int, domain_id: int) -> dict[str, Any]:
    cursor.execute(
        "select id,username,role,is_active from auth_users where id=%s order by id limit 2",
        (subject_id,),
    )
    targets = [dict(row) for row in cursor.fetchall()]
    if len(targets) != 1 or not targets[0].get("is_active"):
        raise VpnEvidenceGrantError("vpn_evidence_target_not_active")
    target = targets[0]
    cursor.execute(
        "select id,fqdn,netbios_name,domain_sid from domains where id=%s",
        (domain_id,),
    )
    domain = dict(cursor.fetchone() or {})
    if int(domain.get("id") or 0) != domain_id:
        raise VpnEvidenceGrantError("vpn_evidence_domain_not_registered")
    cursor.execute(
        "select id,capability_key,label from access_capabilities where capability_key=%s",
        (CAPABILITY_KEY,),
    )
    capability = dict(cursor.fetchone() or {})
    if int(capability.get("id") or 0) <= 0 or capability.get("capability_key") != CAPABILITY_KEY:
        raise VpnEvidenceGrantError("vpn_evidence_capability_not_registered")
    # preview_user_id is the existing read-only access-owner path; the derived
    # session type models the target's grants, not an authenticated login.
    access = access_control_v4.effective_access(None, preview_user_id=int(target["id"]))
    if dict(access.get("subject") or {}).get("id") != int(target["id"]):
        raise VpnEvidenceGrantError("vpn_evidence_target_access_mismatch")
    decision = evaluate_target_access(access, domain_id=domain_id)
    material = {
        "target": {key: target.get(key) for key in ("id", "username", "role", "is_active")},
        "domain": {key: domain.get(key) for key in ("id", "fqdn", "netbios_name", "domain_sid")},
        "capability": {key: capability.get(key) for key in ("id", "capability_key", "label")},
        "access": _access_fingerprint_projection(access),
    }
    return {"target": target, "decision": decision, "fingerprint": _fingerprint(material)}


def _check_connection_identity(cursor: Any, *, expected_user: str) -> None:
    cursor.execute(
        "select host(inet_server_addr()) as host, current_database() as database, current_user as role"
    )
    identity = dict(cursor.fetchone() or {})
    if (
        str(identity.get("host") or "") not in {"127.0.0.1", "::1"}
        or identity.get("database") != "sli_local"
        or identity.get("role") != expected_user
    ):
        raise VpnEvidenceGrantError("connected_vpn_grant_target_mismatch")


def _lock_access_inputs(cursor: Any) -> None:
    cursor.execute(
        """
        lock table auth_users,domains,access_groups,access_group_members,
                   access_platform_owners,access_role_packages,
                   access_subject_packages,access_packages,access_package_capabilities,
                   access_package_reports,access_report_assignments,
                   access_capability_assignments,access_capabilities,
                   report_registry_v4,report_datasets_v4 in share row exclusive mode
        """
    )


def plan_confirmation(plan_digest: str) -> str:
    return PLAN_CONFIRM_PREFIX + plan_digest


def run(*, subject_id: int, domain_id: int, action: str = "plan", confirmation: str | None = None, plan_digest: str | None = None) -> dict[str, Any]:
    if action not in {"plan", "apply"}:
        raise VpnEvidenceGrantError("vpn_evidence_action_invalid")
    if action == "plan" and (confirmation is not None or plan_digest is not None):
        raise VpnEvidenceGrantError("vpn_evidence_plan_arguments_invalid")
    if action == "apply" and (not plan_digest or confirmation != plan_confirmation(plan_digest)):
        raise VpnEvidenceGrantError("vpn_evidence_confirmation_invalid")
    if isinstance(subject_id, bool) or not isinstance(subject_id, int) or subject_id <= 0:
        raise VpnEvidenceGrantError("vpn_evidence_target_invalid")
    if isinstance(domain_id, bool) or not isinstance(domain_id, int) or domain_id <= 0:
        raise VpnEvidenceGrantError("vpn_evidence_scope_invalid")
    scope = {"kind": "domain", "ids": [domain_id]}
    _load_environment()
    dsn = _admin_dsn()
    validate_target(dsn)
    expected_user = os.getenv("ADLOG_PG_ADMIN_USER", "").strip()
    with _connect(dsn) as connection, connection.cursor() as cursor:
        cursor.execute(
            "begin read only" if action == "plan" else "begin isolation level serializable"
        )
        cursor.execute("set local statement_timeout='3s'")
        cursor.execute("set local lock_timeout='1s'")
        cursor.execute("set local search_path=public,pg_catalog")
        _check_connection_identity(cursor, expected_user=expected_user)
        if action == "plan":
            state = _capture_state(cursor, subject_id=subject_id, domain_id=domain_id)
            return {
                "status": str(state["decision"]["status"]),
                "action": "plan",
                "subject_id": subject_id,
                "scope": scope,
                "plan_digest": state["fingerprint"],
                "confirmation": plan_confirmation(str(state["fingerprint"])),
                "reason": state["decision"].get("reason"),
                "source_contacted": False,
                "runtime_changed": False,
            }

        _lock_access_inputs(cursor)
        state = _capture_state(cursor, subject_id=subject_id, domain_id=domain_id)
        if state["decision"]["status"] != "ready":
            raise VpnEvidenceGrantError(str(state["decision"].get("reason") or "vpn_evidence_not_ready"))
        if state["fingerprint"] != plan_digest:
            raise VpnEvidenceGrantError("vpn_evidence_plan_changed")
        result = access_control_v4.grant_vpn_session_evidence_allow_with_cursor(
            cursor=cursor,
            subject=state["target"],
            scope=scope,
            actor={"type": "local", "id": None, "username": "local-maintenance"},
            reason=OWNER_REASON,
            approved_by=OWNER_APPROVED_BY,
            plan_digest=str(plan_digest),
        )
        return {
            "status": "ok",
            "action": "apply",
            "grant": result,
            "subject_id": subject_id,
            "scope": scope,
            "source_contacted": False,
            "runtime_changed": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("plan", "apply"), default="plan")
    parser.add_argument("--subject-id", type=int, required=True)
    parser.add_argument("--domain-id", type=int, required=True)
    parser.add_argument("--confirmation")
    parser.add_argument("--plan-digest")
    args = parser.parse_args()
    try:
        result = run(subject_id=args.subject_id, domain_id=args.domain_id, action=args.action, confirmation=args.confirmation, plan_digest=args.plan_digest)
    except Exception as exc:
        code = safe_error_code(exc)
        print(json.dumps({"status": "error", "action": args.action, "code": code}))
        return 1
    print(json.dumps(result, ensure_ascii=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
