# ruff: noqa: F401 -- re-export hub (plan 7.2b): split-out modules read these
# names through ``plugin_compatibility_registration`` at call time.
from __future__ import annotations

"""Fail-closed source-only compatibility registrations for Stage 9.

Loading a registration reads repository metadata only. It never contacts a
source, opens PostgreSQL, changes a cursor, or starts a worker.
"""

import ast
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from server.sli.core.paths import ROOT
from server.source_packs.adapters import (
    adapter_id_for_backend,
    get_source_adapter,
)
from server.source_packs.registry import (
    get_source_pack,
    resolve_source_normalizer,
    resolve_source_pack,
    validate_adapter_for_pack,
)

REGISTRATION_PATH = (
    ROOT / "config" / "stage9_ad_dc_compatibility_registration_v1.json"
)
DATASET_REPORT_PARITY_PATH = (
    ROOT / "config" / "stage9_ad_dc_dataset_report_parity_v1.json"
)
EXPECTED_STATE_KEYS = {
    "package_lifecycle",
    "desired_activation",
    "observed_health",
    "component_runtime",
    "migration_state",
    "source_state",
    "queue_state",
    "dataset_state",
}
FORBIDDEN_CHANGES = {
    "source_contact",
    "source_instance",
    "cursor",
    "database",
    "migration",
    "runtime_activation",
    "autostart",
    "access",
    "dataset_contract",
    "product_runtime_ownership",
}
DATASET_REPORT_FORBIDDEN_CHANGES = {
    "source_contact",
    "database",
    "migration",
    "cursor",
    "runtime_activation",
    "autostart",
    "access_assignment",
    "dataset_contract",
    "report_publication",
    "frontend",
    "read_path_cutover",
    "product_runtime_ownership",
}
EXPECTED_DATASET_REPORT_CONTRACTS = (
    {
        "primary_source_sections": ("directory_accounts",),
        "enrichment_source_sections": (
            "directory_group_graph",
            "directory_exact_logon",
            "domain_posture",
            "domain_health",
        ),
        "dataset_key": "ad.audit.snapshot",
        "report_key": "ad.state",
        "target_path": "/ad-report",
    },
    {
        "primary_source_sections": ("privileged_membership",),
        "enrichment_source_sections": ("directory_accounts",),
        "dataset_key": "ad.accounts.privileged",
        "report_key": "ad.privileged",
        "target_path": "/privileged-report",
    },
    {
        "primary_source_sections": ("vpn_membership",),
        "enrichment_source_sections": (
            "directory_accounts",
            "privileged_membership",
        ),
        "dataset_key": "ad.accounts.vpn",
        "report_key": "vpn.audit",
        "target_path": "/vpn-report",
    },
    {
        "primary_source_sections": ("gpo_governance",),
        "enrichment_source_sections": (),
        "dataset_key": "ad.gpo.governance",
        "report_key": "ad.gpo.review",
        "target_path": "/gpo-report",
    },
)


class CompatibilityRegistrationError(ValueError):
    pass


@dataclass(frozen=True)
class CompatibilityRegistration:
    registration_id: str
    plugin_id: str
    mode: str
    source_pack_ids: tuple[str, ...]
    entrypoints: tuple[str, ...]
    state: Mapping[str, str]
    ownership: Mapping[str, str]
    acquisition_policy: str
    registration_sha256: str

    def public_dict(self) -> dict[str, Any]:
        return {
            "registration_id": self.registration_id,
            "plugin_id": self.plugin_id,
            "mode": self.mode,
            "source_pack_ids": list(self.source_pack_ids),
            "entrypoints": list(self.entrypoints),
            "state": dict(self.state),
            "ownership": dict(self.ownership),
            "acquisition_policy": self.acquisition_policy,
            "registration_sha256": self.registration_sha256,
            "execution_changed": False,
        }


@dataclass(frozen=True)
class DatasetReportParityContract:
    primary_source_sections: tuple[str, ...]
    enrichment_source_sections: tuple[str, ...]
    dataset_key: str
    dataset_version: int
    report_key: str
    report_version: int
    target_path: str
    scope_kinds: tuple[str, ...]


@dataclass(frozen=True)
class DatasetReportParityRegistration:
    parity_id: str
    registration_id: str
    contracts: tuple[DatasetReportParityContract, ...]
    parity_sha256: str


def load_ad_dc_compatibility_registration(
    path: Path = REGISTRATION_PATH,
) -> CompatibilityRegistration:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityRegistrationError(
            "compatibility_registration_json_invalid"
        ) from exc
    if not isinstance(value, dict):
        raise CompatibilityRegistrationError(
            "compatibility_registration_object_required"
        )
    return validate_ad_dc_compatibility_registration(
        value,
        registration_sha256=hashlib.sha256(raw).hexdigest(),
    )


def validate_ad_dc_compatibility_registration(
    value: Mapping[str, Any],
    *,
    registration_sha256: str = "",
) -> CompatibilityRegistration:
    _require_equal(value, "schema_version", 2)
    _require_equal(
        value,
        "registration_id",
        "sli.stage9.ad-dc.compatibility.v1",
    )
    _require_equal(value, "plugin_id", "sli.windows.ad-dc")
    _require_equal(value, "mode", "compatibility_only")
    package = _mapping(value, "package")
    _require_equal(package, "delivery", "bundled_reviewed")
    _require_equal(package, "lifecycle", "compatibility_registered")
    _require_equal(
        package,
        "handler_loading",
        "existing_allowlisted_code_only",
    )

    source_packs = value.get("source_packs")
    if not isinstance(source_packs, list) or len(source_packs) != 2:
        raise CompatibilityRegistrationError(
            "compatibility_source_packs_exactly_two_required"
        )
    source_pack_ids: list[str] = []
    for raw_item in source_packs:
        if not isinstance(raw_item, Mapping):
            raise CompatibilityRegistrationError(
                "compatibility_source_pack_object_required"
            )
        item = dict(raw_item)
        pack_id = str(item.get("pack_id") or "")
        pack = get_source_pack(pack_id)
        if pack is None:
            raise CompatibilityRegistrationError(
                f"compatibility_source_pack_unknown:{pack_id}"
            )
        if item.get("version") != pack.version:
            raise CompatibilityRegistrationError(
                f"compatibility_source_pack_version_drift:{pack_id}"
            )
        if item.get("manifest_sha256") != pack.manifest_sha256:
            raise CompatibilityRegistrationError(
                f"compatibility_source_pack_hash_drift:{pack_id}"
            )
        source_pack_ids.append(pack_id)
    if source_pack_ids != [
        "sli.windows.ad-dc",
        "sli.windows.ad-context",
    ]:
        raise CompatibilityRegistrationError(
            "compatibility_source_pack_order_or_identity_invalid"
        )

    entrypoints_raw = value.get("existing_execution_entrypoints")
    if not isinstance(entrypoints_raw, list) or not entrypoints_raw:
        raise CompatibilityRegistrationError(
            "compatibility_entrypoints_required"
        )
    entrypoints: list[str] = []
    for raw_entrypoint in entrypoints_raw:
        relative = str(raw_entrypoint or "").replace("\\", "/").strip("/")
        candidate = (ROOT / relative).resolve()
        if (
            not relative
            or ROOT.resolve() not in candidate.parents
            or not candidate.is_file()
        ):
            raise CompatibilityRegistrationError(
                f"compatibility_entrypoint_invalid:{relative}"
            )
        entrypoints.append(relative)
    if len(entrypoints) != len(set(entrypoints)):
        raise CompatibilityRegistrationError(
            "compatibility_entrypoints_duplicate"
        )

    state = _mapping(value, "state")
    if set(state) != EXPECTED_STATE_KEYS:
        raise CompatibilityRegistrationError(
            "compatibility_state_axes_invalid"
        )
    _require_equal(state, "component_runtime", "core_owned_final")
    _require_equal(state, "migration_state", "not_required")

    ownership = _mapping(value, "ownership")
    _require_equal(
        ownership,
        "descriptor_and_semantic_contract",
        "sli.windows.ad-dc",
    )
    _require_equal(
        ownership,
        "directory_context_contract",
        "sli.windows.ad-context",
    )
    _require_equal(ownership, "canonical_evidence", "core")
    _require_equal(
        ownership,
        "warm_authentication_session",
        "core_hosted_compatibility",
    )
    _require_equal(
        value,
        "acquisition_policy",
        "full_channel_then_core_evidence_then_subscription_routing",
    )

    changes = _mapping(value, "changes")
    if set(changes) != FORBIDDEN_CHANGES:
        raise CompatibilityRegistrationError(
            "compatibility_change_contract_incomplete"
        )
    enabled = sorted(key for key, changed in changes.items() if changed is not False)
    if enabled:
        raise CompatibilityRegistrationError(
            "compatibility_registration_changes_execution:"
            + ",".join(enabled)
        )

    next_steps = value.get("potential_strangler_steps")
    if not isinstance(next_steps, list) or next_steps != [
        "source_pack_parity",
        "dataset_and_report_parity",
        "adapter_parity",
        "worker_parity",
        "separate_read_path_cutover_decision",
    ]:
        raise CompatibilityRegistrationError(
            "compatibility_strangler_sequence_invalid"
        )
    _require_equal(value, "strangler_steps_authorized", False)

    ownership_decision = _mapping(value, "ownership_decision")
    _require_equal(ownership_decision, "model", "core_owned_final")
    for decision_key in ("decision_basis", "decision_date", "rationale"):
        if (
            not isinstance(ownership_decision.get(decision_key), str)
            or not ownership_decision[decision_key]
        ):
            raise CompatibilityRegistrationError(
                f"compatibility_ownership_decision_{decision_key}_invalid"
            )

    digest = registration_sha256 or hashlib.sha256(
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return CompatibilityRegistration(
        registration_id=str(value["registration_id"]),
        plugin_id=str(value["plugin_id"]),
        mode=str(value["mode"]),
        source_pack_ids=tuple(source_pack_ids),
        entrypoints=tuple(entrypoints),
        state={str(key): str(item) for key, item in state.items()},
        ownership={str(key): str(item) for key, item in ownership.items()},
        acquisition_policy=str(value["acquisition_policy"]),
        registration_sha256=digest,
    )






def load_ad_dc_dataset_report_parity(
    path: Path = DATASET_REPORT_PARITY_PATH,
) -> DatasetReportParityRegistration:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompatibilityRegistrationError(
            "dataset_report_parity_json_invalid"
        ) from exc
    if not isinstance(value, dict):
        raise CompatibilityRegistrationError(
            "dataset_report_parity_object_required"
        )
    return validate_ad_dc_dataset_report_parity(
        value,
        parity_sha256=hashlib.sha256(raw).hexdigest(),
    )


def validate_ad_dc_dataset_report_parity(
    value: Mapping[str, Any],
    *,
    parity_sha256: str = "",
) -> DatasetReportParityRegistration:
    _require_equal(value, "schema_version", 1)
    _require_equal(
        value,
        "parity_id",
        "sli.stage9.ad-dc.dataset-report-parity.v1",
    )
    _require_equal(value, "mode", "source_contract_only")
    _require_equal(
        value,
        "registration_id",
        "sli.stage9.ad-dc.compatibility.v1",
    )
    raw_contracts = value.get("contracts")
    if not isinstance(raw_contracts, list) or len(raw_contracts) != 4:
        raise CompatibilityRegistrationError(
            "dataset_report_parity_exactly_four_contracts_required"
        )
    contracts: list[DatasetReportParityContract] = []
    normalized: list[dict[str, Any]] = []
    expected_keys = {
        "primary_source_sections",
        "enrichment_source_sections",
        "dataset_key",
        "dataset_version",
        "report_key",
        "report_version",
        "target_path",
        "scope_kinds",
    }
    for item in raw_contracts:
        if not isinstance(item, Mapping) or set(item) != expected_keys:
            raise CompatibilityRegistrationError(
                "dataset_report_parity_contract_shape_invalid"
            )
        primary = _string_list(
            item.get("primary_source_sections"),
            "dataset_report_parity_primary_source_sections",
            allow_empty=False,
        )
        enrichment = _string_list(
            item.get("enrichment_source_sections"),
            "dataset_report_parity_enrichment_source_sections",
            allow_empty=True,
        )
        scopes = _string_list(
            item.get("scope_kinds"),
            "dataset_report_parity_scope_kinds",
            allow_empty=False,
        )
        if scopes != ("all", "server", "domain"):
            raise CompatibilityRegistrationError(
                "dataset_report_parity_scope_kinds_invalid"
            )
        if item.get("dataset_version") != 1 or item.get("report_version") != 1:
            raise CompatibilityRegistrationError(
                "dataset_report_parity_version_invalid"
            )
        contract = DatasetReportParityContract(
            primary_source_sections=primary,
            enrichment_source_sections=enrichment,
            dataset_key=str(item.get("dataset_key") or ""),
            dataset_version=1,
            report_key=str(item.get("report_key") or ""),
            report_version=1,
            target_path=str(item.get("target_path") or ""),
            scope_kinds=scopes,
        )
        contracts.append(contract)
        normalized.append(
            {
                "primary_source_sections": primary,
                "enrichment_source_sections": enrichment,
                "dataset_key": contract.dataset_key,
                "report_key": contract.report_key,
                "target_path": contract.target_path,
            }
        )
    if tuple(normalized) != EXPECTED_DATASET_REPORT_CONTRACTS:
        raise CompatibilityRegistrationError(
            "dataset_report_parity_contract_identity_or_order_invalid"
        )
    changes = _mapping(value, "changes")
    if set(changes) != DATASET_REPORT_FORBIDDEN_CHANGES:
        raise CompatibilityRegistrationError(
            "dataset_report_parity_change_contract_incomplete"
        )
    enabled = sorted(key for key, changed in changes.items() if changed is not False)
    if enabled:
        raise CompatibilityRegistrationError(
            "dataset_report_parity_changes_execution:" + ",".join(enabled)
        )
    _require_equal(
        value,
        "next_gate",
        "adapter_and_worker_parity_without_read_path_cutover",
    )
    digest = parity_sha256 or hashlib.sha256(
        json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return DatasetReportParityRegistration(
        parity_id=str(value["parity_id"]),
        registration_id=str(value["registration_id"]),
        contracts=tuple(contracts),
        parity_sha256=digest,
    )


















def _string_list(
    value: Any,
    error_code: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or not item for item in value)
        or len(value) != len(set(value))
    ):
        raise CompatibilityRegistrationError(error_code)
    return tuple(value)


def _require_equal(
    value: Mapping[str, Any],
    key: str,
    expected: Any,
) -> None:
    if value.get(key) != expected:
        raise CompatibilityRegistrationError(
            f"compatibility_{key}_must_equal_{expected}"
        )


from server.sli.sources.plugin_compatibility_registration_evidence import (
    _dataset_query_branch,
    _domain_scope_membership_counts,
    _literal_assignment_value,
    _literal_expression_value,
    _literal_string_sequence,
    _mapping,
    build_ad_dc_adapter_worker_parity_evidence,
    build_ad_dc_compatibility_evidence,
    build_ad_dc_dataset_report_parity_evidence,
    build_ad_dc_source_pack_parity_evidence,
)
