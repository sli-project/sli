from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest

from server.sli.storage import acquisition_evidence_root as evidence_root
from server.sli.storage.acquisition_evidence_root import (
    EvidenceRootPolicyError,
    load_evidence_root_contract,
    validate_evidence_root_contract,
    validate_evidence_root_readback,
)


ROOT = Path(__file__).resolve().parents[2]
V1_CONTRACT = ROOT / "config" / "stage9_radius_evidence_root_v1.json"
V2_CONTRACT = ROOT / "config" / "stage9_radius_evidence_root_v2.json"
SYSTEM = "S-1-5-18"
ADMINS = "S-1-5-32-544"
WORKER = "S-1-5-21-100000004-200000004-300000004-7995"
PLACEHOLDER_WORKER = "S-1-5-21-100000004-200000004-300000004-6995"


def _entry(sid: str, *, inherited: bool) -> dict[str, object]:
    return {
        "sid": sid,
        "access_type": "allow",
        "rights": 2032127,
        "inheritance_flags": 3,
        "propagation_flags": 0,
        "is_inherited": inherited,
    }


def _node(name: str, *, root: bool) -> dict[str, object]:
    return {
        "relative_path": name,
        "exists": True,
        "is_directory": True,
        "is_reparse_point": False,
        "owner_sid": ADMINS,
        "inheritance_protected": root,
        "entries": [
            _entry(SYSTEM, inherited=not root),
            _entry(ADMINS, inherited=not root),
            _entry(WORKER, inherited=not root),
        ],
    }


def _snapshot() -> dict[str, object]:
    return {
        "schema_version": 1,
        "platform": "windows",
        "target": {
            "root_fingerprint_sha256": "a" * 64,
            "is_absolute": True,
            "outside_project_root": True,
            "exists": True,
            "is_directory": True,
            "is_reparse_point": False,
            "same_volume": True,
        },
        "nodes": [
            _node(".", root=True),
            _node("staging", root=False),
            _node("published", root=False),
            _node("quarantine", root=False),
        ],
    }


def test_current_contract_is_source_only_and_configured_identity_bound() -> None:
    contract = load_evidence_root_contract()
    assert contract["status"] == "prepared_source_only"
    assert contract["activation_enabled"] is False
    assert contract["manual_worker_identity"] == {
        "source": "configured_collection_identity"
    }
    assert "acl_apply" in contract["prohibited_actions"]


def test_direct_validator_entrypoint_restores_project_import_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        evidence_root.sys,
        "path",
        [entry for entry in evidence_root.sys.path if entry != str(ROOT)],
    )

    evidence_root._ensure_project_root_on_import_path()

    assert evidence_root.sys.path[0] == str(ROOT)


def test_configured_worker_sid_fails_closed_when_supervisor_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> None:
        raise RuntimeError("worker supervisor environment is not provisioned")

    monkeypatch.setattr(
        "server.sli.ops.worker_supervisor_secrets.load_supervisor_environment",
        unavailable,
    )

    with pytest.raises(
        EvidenceRootPolicyError,
        match="configured_worker_environment_unavailable",
    ):
        evidence_root._configured_worker_sid()


def test_historical_v1_contract_remains_separately_validatable() -> None:
    contract = load_evidence_root_contract(V1_CONTRACT)
    validate_evidence_root_contract(contract)
    snapshot = _snapshot()
    for node in snapshot["nodes"]:
        node["entries"][2]["sid"] = PLACEHOLDER_WORKER
    summary = validate_evidence_root_readback(
        snapshot, contract=load_evidence_root_contract(V1_CONTRACT)
    )
    assert summary["contract_id"] == "sli.radius-acquisition-evidence-root.v1"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("principal", "EXAMPLE\\different"),
        ("sid", WORKER),
    ],
)
def test_historical_v1_contract_rejects_identity_drift(
    field: str, value: str,
) -> None:
    contract = load_evidence_root_contract(V1_CONTRACT)
    contract["manual_worker_identity"][field] = value
    with pytest.raises(
        EvidenceRootPolicyError,
        match="evidence_root_worker_identity_changed",
    ):
        validate_evidence_root_contract(contract)


def test_historical_v1_contract_rejects_acl_sid_drift() -> None:
    contract = load_evidence_root_contract(V1_CONTRACT)
    contract["required_acl"]["full_control_sids"][2] = WORKER
    with pytest.raises(
        EvidenceRootPolicyError,
        match="evidence_root_acl_contract_changed",
    ):
        validate_evidence_root_contract(contract)


def test_exact_protected_acl_readback_is_accepted_without_identity_leak() -> None:
    summary = validate_evidence_root_readback(
        _snapshot(), expected_worker_sid=WORKER
    )
    assert summary["status"] == "accepted"
    assert summary["classification"] == "protected_acl_exact"
    assert summary["node_count"] == 4
    assert summary["acl_entry_count"] == 12
    assert summary["activation_enabled"] is False
    assert summary["source_contacted"] is False
    assert summary["raw_path_persisted"] is False
    assert "root_path" not in summary
    assert "principal" not in summary
    assert WORKER not in str(summary)


def test_current_v2_contract_is_configured_identity_only() -> None:
    assert V2_CONTRACT.is_file()
    value = json.loads(V2_CONTRACT.read_text(encoding="utf-8"))
    serialized = json.dumps(value, sort_keys=True)
    assert value["contract_id"] == "sli.radius-acquisition-evidence-root.v2"
    assert value["manual_worker_identity"] == {
        "source": "configured_collection_identity"
    }
    assert value["required_acl"]["configured_worker_sid_required"] is True
    assert r"EXAMPLE\operator" not in serialized
    assert PLACEHOLDER_WORKER not in serialized


def test_current_v2_requires_non_placeholder_configured_sid() -> None:
    with pytest.raises(EvidenceRootPolicyError, match="configured_worker_sid_required"):
        validate_evidence_root_readback(_snapshot())
    with pytest.raises(
        EvidenceRootPolicyError,
        match="configured_worker_sid_placeholder_forbidden",
    ):
        validate_evidence_root_readback(
            _snapshot(), expected_worker_sid=PLACEHOLDER_WORKER
        )


@pytest.mark.parametrize("sid", ["S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-32-546"])
def test_broad_or_guest_principal_is_rejected(sid: str) -> None:
    snapshot = _snapshot()
    snapshot["nodes"][0]["entries"].append(_entry(sid, inherited=False))
    with pytest.raises(EvidenceRootPolicyError, match="evidence_root_broad_principal_forbidden"):
        validate_evidence_root_readback(snapshot, expected_worker_sid=WORKER)


def test_extra_principal_is_rejected() -> None:
    snapshot = _snapshot()
    snapshot["nodes"][0]["entries"].append(
        _entry("S-1-5-21-100000001-200000001-300000001-4", inherited=False)
    )
    with pytest.raises(EvidenceRootPolicyError, match="evidence_root_acl_principals_not_exact"):
        validate_evidence_root_readback(snapshot, expected_worker_sid=WORKER)


def test_inherited_root_acl_is_rejected() -> None:
    snapshot = _snapshot()
    snapshot["nodes"][0]["inheritance_protected"] = False
    with pytest.raises(EvidenceRootPolicyError, match="evidence_root_inheritance_not_protected"):
        validate_evidence_root_readback(snapshot, expected_worker_sid=WORKER)


def test_reparse_child_is_rejected() -> None:
    snapshot = _snapshot()
    snapshot["nodes"][2]["is_reparse_point"] = True
    with pytest.raises(EvidenceRootPolicyError, match="evidence_root_reparse_forbidden"):
        validate_evidence_root_readback(snapshot, expected_worker_sid=WORKER)


def test_non_exact_rights_are_rejected() -> None:
    snapshot = deepcopy(_snapshot())
    snapshot["nodes"][1]["entries"][2]["rights"] = 131241
    with pytest.raises(EvidenceRootPolicyError, match="evidence_root_acl_rights_invalid"):
        validate_evidence_root_readback(snapshot, expected_worker_sid=WORKER)
