"""Fail-closed Stage 9 acquisition evidence-root ACL validation.

V1 remains a historical source artifact.  V2 is the only default/current
contract and binds the third exact ACL principal to the configured collection
identity at live-readback time.  Summaries deliberately omit identities and
filesystem paths.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]


def _ensure_project_root_on_import_path() -> None:
    root = str(ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


_ensure_project_root_on_import_path()


V1_CONTRACT_PATH = ROOT / "config" / "stage9_radius_evidence_root_v1.json"
CONTRACT_PATH = ROOT / "config" / "stage9_radius_evidence_root_v2.json"
V1_CONTRACT_ID = "sli.radius-acquisition-evidence-root.v1"
CONTRACT_ID = "sli.radius-acquisition-evidence-root.v2"
_SID = re.compile(r"^S-\d(?:-\d+)+$", re.IGNORECASE)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIXED_ACL_SIDS = ("S-1-5-18", "S-1-5-32-544")
_FORBIDDEN_SIDS = ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546")


class EvidenceRootPolicyError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _read_contract(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceRootPolicyError("evidence_root_contract_invalid") from exc
    if not isinstance(value, dict):
        raise EvidenceRootPolicyError("evidence_root_contract_invalid")
    return value


def load_evidence_root_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    return validate_evidence_root_contract(_read_contract(path))


def _validate_common(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != 1:
        raise EvidenceRootPolicyError("evidence_root_schema_unsupported")
    if value.get("status") != "prepared_source_only":
        raise EvidenceRootPolicyError("evidence_root_source_only_required")
    if value.get("platform") != "windows_ntfs":
        raise EvidenceRootPolicyError("evidence_root_platform_invalid")
    if value.get("activation_enabled") is not False:
        raise EvidenceRootPolicyError("evidence_root_activation_forbidden")
    if value.get("required_relative_directories") != [
        "staging", "published", "quarantine"
    ]:
        raise EvidenceRootPolicyError("evidence_root_directories_invalid")
    if value.get("forbidden_sids") != list(_FORBIDDEN_SIDS):
        raise EvidenceRootPolicyError("evidence_root_forbidden_sids_changed")
    if dict(value.get("root_policy") or {}) != {
        "explicit_absolute_path_required": True,
        "outside_project_root_required": True,
        "same_volume_required": True,
        "reparse_points_allowed": False,
        "raw_path_persisted": False,
    }:
        raise EvidenceRootPolicyError("evidence_root_path_policy_changed")
    if set(value.get("prohibited_actions") or []) != {
        "acl_apply", "directory_create", "source_contact",
        "production_registration", "cursor_bootstrap", "worker_activation",
        "autostart",
    }:
        raise EvidenceRootPolicyError("evidence_root_prohibitions_changed")


def validate_evidence_root_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    value = dict(contract)
    _validate_common(value)
    contract_id = value.get("contract_id")
    identity = dict(value.get("manual_worker_identity") or {})
    acl = dict(value.get("required_acl") or {})
    if contract_id == CONTRACT_ID:
        if identity != {"source": "configured_collection_identity"}:
            raise EvidenceRootPolicyError("evidence_root_worker_identity_changed")
        expected_acl = {
            "owner_sid": "S-1-5-32-544",
            "fixed_full_control_sids": list(_FIXED_ACL_SIDS),
            "configured_worker_sid_required": True,
            "full_control_rights": 2032127,
            "inheritance_flags": 3,
            "propagation_flags": 0,
            "root_inheritance_protected": True,
            "children_inherit_only": True,
        }
        if acl != expected_acl:
            raise EvidenceRootPolicyError("evidence_root_acl_contract_changed")
    elif contract_id == V1_CONTRACT_ID:
        if identity != {
            "principal": r"EXAMPLE\operator",
            "sid": "S-1-5-21-100000004-200000004-300000004-6995",
        }:
            raise EvidenceRootPolicyError("evidence_root_worker_identity_changed")
        expected_acl = {
            "owner_sid": "S-1-5-32-544",
            "full_control_sids": [
                "S-1-5-18",
                "S-1-5-32-544",
                "S-1-5-21-100000004-200000004-300000004-6995",
            ],
            "full_control_rights": 2032127,
            "inheritance_flags": 3,
            "propagation_flags": 0,
            "root_inheritance_protected": True,
            "children_inherit_only": True,
        }
        if acl != expected_acl:
            raise EvidenceRootPolicyError("evidence_root_acl_contract_changed")
    else:
        raise EvidenceRootPolicyError("evidence_root_contract_id_unexpected")
    return value


def _legacy_placeholder_sid() -> str:
    historical = _read_contract(V1_CONTRACT_PATH)
    return str(dict(historical.get("manual_worker_identity") or {}).get("sid") or "")


def _expected_sids(policy: Mapping[str, Any], expected_worker_sid: str | None) -> set[str]:
    if policy["contract_id"] == V1_CONTRACT_ID:
        return {
            str(sid).upper()
            for sid in dict(policy["required_acl"])["full_control_sids"]
        }
    if not expected_worker_sid:
        raise EvidenceRootPolicyError("configured_worker_sid_required")
    if _SID.fullmatch(expected_worker_sid) is None:
        raise EvidenceRootPolicyError("configured_worker_sid_invalid")
    if expected_worker_sid.casefold() == _legacy_placeholder_sid().casefold():
        raise EvidenceRootPolicyError("configured_worker_sid_placeholder_forbidden")
    fixed = dict(policy["required_acl"])["fixed_full_control_sids"]
    return {*(str(sid).upper() for sid in fixed), expected_worker_sid.upper()}


def validate_evidence_root_readback(
    snapshot: Mapping[str, Any], *, contract: Mapping[str, Any] | None = None,
    expected_worker_sid: str | None = None,
) -> dict[str, Any]:
    policy = validate_evidence_root_contract(contract or load_evidence_root_contract())
    value = dict(snapshot)
    if value.get("schema_version") != 1:
        raise EvidenceRootPolicyError("acl_snapshot_schema_unsupported")
    if value.get("platform") != "windows":
        raise EvidenceRootPolicyError("acl_snapshot_windows_required")
    target = dict(value.get("target") or {})
    fingerprint = str(target.get("root_fingerprint_sha256") or "").casefold()
    if _SHA256.fullmatch(fingerprint) is None:
        raise EvidenceRootPolicyError("acl_snapshot_fingerprint_invalid")
    for key, expected in {
        "is_absolute": True, "outside_project_root": True, "exists": True,
        "is_directory": True, "is_reparse_point": False, "same_volume": True,
    }.items():
        if target.get(key) is not expected:
            raise EvidenceRootPolicyError(f"evidence_root_{key}_required")
    expected_names = [".", *policy["required_relative_directories"]]
    nodes = value.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != len(expected_names):
        raise EvidenceRootPolicyError("evidence_root_nodes_incomplete")
    by_name: dict[str, Mapping[str, Any]] = {}
    for node in nodes:
        if not isinstance(node, Mapping):
            raise EvidenceRootPolicyError("evidence_root_node_invalid")
        name = str(node.get("relative_path") or "")
        if name in by_name:
            raise EvidenceRootPolicyError("evidence_root_node_duplicate")
        by_name[name] = node
    if set(by_name) != set(expected_names):
        raise EvidenceRootPolicyError("evidence_root_nodes_unexpected")
    expected_sids = _expected_sids(policy, expected_worker_sid)
    for name in expected_names:
        _validate_node(by_name[name], is_root=name == ".", acl_policy=policy["required_acl"], expected_sids=expected_sids, forbidden_sids=set(policy["forbidden_sids"]))
    entry_count = sum(len(list(by_name[name].get("entries") or [])) for name in expected_names)
    canonical = json.dumps({"contract_id": policy["contract_id"], "root_fingerprint_sha256": fingerprint, "nodes": expected_names, "acl_entry_count": entry_count}, sort_keys=True, separators=(",", ":"))
    return {"status": "accepted", "classification": "protected_acl_exact", "contract_id": policy["contract_id"], "root_fingerprint_sha256": fingerprint, "node_count": len(expected_names), "acl_entry_count": entry_count, "readback_sha256": sha256(canonical.encode("utf-8")).hexdigest(), "activation_enabled": False, "source_contacted": False, "raw_path_persisted": False}


def _validate_node(node: Mapping[str, Any], *, is_root: bool, acl_policy: Mapping[str, Any], expected_sids: set[str], forbidden_sids: set[str]) -> None:
    if node.get("exists") is not True or node.get("is_directory") is not True:
        raise EvidenceRootPolicyError("evidence_root_node_missing")
    if node.get("is_reparse_point") is not False:
        raise EvidenceRootPolicyError("evidence_root_reparse_forbidden")
    if str(node.get("owner_sid") or "").upper() != str(acl_policy["owner_sid"]).upper():
        raise EvidenceRootPolicyError("evidence_root_owner_invalid")
    if is_root and bool(node.get("inheritance_protected")) is not True:
        raise EvidenceRootPolicyError("evidence_root_inheritance_not_protected")
    if not is_root and bool(node.get("inheritance_protected")) is not False:
        raise EvidenceRootPolicyError("evidence_root_child_inheritance_invalid")
    entries = node.get("entries")
    if not isinstance(entries, list):
        raise EvidenceRootPolicyError("evidence_root_acl_entries_invalid")
    actual: dict[str, Mapping[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise EvidenceRootPolicyError("evidence_root_acl_entry_invalid")
        sid = str(entry.get("sid") or "").upper()
        if _SID.fullmatch(sid) is None:
            raise EvidenceRootPolicyError("evidence_root_acl_sid_invalid")
        if sid in forbidden_sids:
            raise EvidenceRootPolicyError("evidence_root_broad_principal_forbidden")
        if sid in actual:
            raise EvidenceRootPolicyError("evidence_root_acl_sid_duplicate")
        actual[sid] = entry
    if set(actual) != expected_sids:
        raise EvidenceRootPolicyError("evidence_root_acl_principals_not_exact")
    for entry in actual.values():
        if str(entry.get("access_type") or "").casefold() != "allow":
            raise EvidenceRootPolicyError("evidence_root_deny_or_unknown_ace")
        if int(entry.get("rights", -1)) != int(acl_policy["full_control_rights"]):
            raise EvidenceRootPolicyError("evidence_root_acl_rights_invalid")
        if int(entry.get("inheritance_flags", -1)) != int(acl_policy["inheritance_flags"]):
            raise EvidenceRootPolicyError("evidence_root_acl_inheritance_flags_invalid")
        if int(entry.get("propagation_flags", -1)) != int(acl_policy["propagation_flags"]):
            raise EvidenceRootPolicyError("evidence_root_acl_propagation_flags_invalid")
        if bool(entry.get("is_inherited")) is is_root:
            raise EvidenceRootPolicyError("evidence_root_acl_inherited_state_invalid")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", help="Snapshot JSON path, or '-' for stdin.")
    parser.add_argument("--validate-contract", action="store_true")
    parser.add_argument("--load-supervisor-environment", action="store_true")
    return parser.parse_args(argv)


def _configured_worker_sid() -> str:
    from server.sli.ops.worker_supervisor_secrets import load_supervisor_environment
    from server.sli.sources.windows_runtime_identity import expected_collection_identity, verify_collection_identity

    try:
        load_supervisor_environment()
    except RuntimeError as exc:
        raise EvidenceRootPolicyError(
            "configured_worker_environment_unavailable"
        ) from exc
    _principal, sid = expected_collection_identity()
    if not sid:
        raise EvidenceRootPolicyError("configured_worker_sid_required")
    if verify_collection_identity().get("status") != "ok":
        raise EvidenceRootPolicyError("configured_collection_identity_mismatch")
    return str(sid)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        contract = load_evidence_root_contract()
        if args.validate_contract:
            result = {"status": "validated", "classification": "source_only_contract", "contract_id": contract["contract_id"], "activation_enabled": False, "source_contacted": False}
        else:
            if not args.snapshot:
                raise EvidenceRootPolicyError("acl_snapshot_required")
            if not args.load_supervisor_environment:
                raise EvidenceRootPolicyError("configured_worker_sid_required")
            raw = sys.stdin.read() if args.snapshot == "-" else Path(args.snapshot).read_text(encoding="utf-8")
            snapshot = json.loads(raw)
            if not isinstance(snapshot, Mapping):
                raise EvidenceRootPolicyError("acl_snapshot_object_required")
            result = validate_evidence_root_readback(snapshot, contract=contract, expected_worker_sid=_configured_worker_sid())
    except (EvidenceRootPolicyError, OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        code = exc.code if isinstance(exc, EvidenceRootPolicyError) else "evidence_root_readback_invalid"
        print(json.dumps({"status": "blocked", "classification": code, "activation_enabled": False, "source_contacted": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
