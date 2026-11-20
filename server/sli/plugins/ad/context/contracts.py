from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from server.sli.plugins.gpo.context_contracts import (
    GPO_SETTING_KEYS, GPO_SETTING_SCOPES, _gpo_settings, validate_context_snapshot,
    GpoV2SourceContractError, is_gpo_sensitive_field, validate_gpo_v2_snapshot,
)

SCHEMA_VERSION = "ad-context-bundle/v1"
PACK_ID = "sli.windows.ad-context"
AD_SNAPSHOT_MANIFEST_V1_CONTRACT_VERSION = "sli.ad-snapshot-manifest/1.0"
AD_SNAPSHOT_MANIFEST_V2_CONTRACT_VERSION = "sli.ad-snapshot-manifest/2.0"
AD_SNAPSHOT_MANIFEST_V3_CONTRACT_VERSION = "sli.ad-snapshot-manifest/3.0"
AD_SNAPSHOT_MANIFEST_CONTRACT_VERSION = AD_SNAPSHOT_MANIFEST_V2_CONTRACT_VERSION
SUPPORTED_SECTIONS = frozenset({
    "privileged_membership", "directory_accounts", "vpn_membership",
    "directory_group_graph", "directory_exact_logon",
    "gpo_governance", "domain_posture", "domain_health",
})
SUPPORTED_MODES = frozenset({"full", "targeted", "reconcile"})
SUPPORTED_SECTION_STATUSES = frozenset({"complete", "partial", "failed", "skipped"})
ENTITY_KINDS = frozenset({
    "ad_user", "ad_group", "ad_computer", "security_principal", "gpo",
    "domain", "domain_trust", "domain_controller", "password_policy",
    "replication_link",
})
ENTITY_ATTRIBUTE_KEYS = frozenset(
    {
        "display_name", "sam_account_name", "distinguished_name", "enabled", "object_class", "object_classes",
        "user_principal_name", "given_name", "surname", "canonical_name",
        "last_logon_utc", "last_logon_timestamp_utc", "password_last_set_utc",
        "password_never_expires", "password_expired", "password_not_required",
        "cannot_change_password", "smartcard_logon_required", "does_not_require_preauth",
        "allow_reversible_password_encryption", "trusted_for_delegation",
        "trusted_to_auth_for_delegation", "account_not_delegated", "use_des_key_only",
        "user_account_control", "msds_supported_encryption_types",
        "password_expiry_utc", "password_expiry_status",
        "effective_password_policy_dn", "effective_password_policy_name",
        "effective_password_policy_source",
        "is_inactive", "inactivity_basis", "inactive_threshold_days",
        "department", "title", "company", "manager", "employee_id", "employee_number", "location",
        "email", "mail", "office", "telephone_number", "mobile", "ip_phone", "fax",
        "other_telephones", "street_address", "city", "state", "postal_code", "country",
        "proxy_addresses", "script_path", "home_directory", "home_drive", "profile_path",
        "admin_count", "account_expiration_utc", "locked_out",
        "when_created_utc", "when_changed_utc", "last_bad_password_attempt_utc",
        "bad_password_count_at_query_dc",
        "primary_group_id", "unresolved_group_dns", "unresolved_primary_group_sid",
        "group_category", "group_scope", "managed_by", "unresolved_parent_dns",
        "exact_last_logon_utc", "exact_last_logon_status",
        "exact_last_logon_discovered_dc_count", "exact_last_logon_successful_dc_count",
        "exact_last_logon_failed_dcs",
        "dns_host_name", "operating_system", "operating_system_version",
        "operating_system_service_pack",
        "ip_addresses", "logical_disks", "technical_inventory_status",
        "technical_inventory_observed_at_utc",
        "created_utc", "modified_utc", "owner", "description", "link_count", "links",
        "gpo_computer_enabled", "gpo_user_enabled",
        "gpo_link_enabled_count", "gpo_link_enforced_count",
        "application_state",
        "gpo_security_filtering_sids", "gpo_security_filtering_deny_sids",
        "gpo_security_filtering_collected",
        "gpo_security_filtering_effective_evaluated",
        "gpo_permission_count", "gpo_permission_custom_count",
        "gpo_wmi_filter_present", "gpo_wmi_filter_id",
        "gpo_startup_script_count", "gpo_logon_script_count",
        "gpo_scheduled_task_count", "gpo_service_count", "gpo_local_group_count",
        "gpo_settings",
        "password_min_length", "password_max_age", "password_min_age",
        "password_history_length", "password_properties", "lockout_threshold",
        "lockout_duration", "lockout_observation_window",
        "security_descriptor_sha256", "directory_rights", "delegation_mode",
        "allowed_to_delegate_to", "resource_based_delegation_descriptor_sha256",
        "resource_based_delegation_present", "laps_password_expiration_utc", "legacy_laps_password_expiration_utc",
        "resource_based_delegation_sids", "resource_based_delegation_status",
        "password_last_set_status", "laps_password_expiration_status", "legacy_laps_password_expiration_status",
        "service_principal_names", "kerberos_preauth_required", "sid_history",
        "trust_partner", "trust_flat_name", "trust_direction", "trust_type",
        "trust_attributes",
        "forest_name", "netbios_name", "domain_mode", "forest_mode",
        "pdc_emulator", "rid_master", "infrastructure_master", "schema_master",
        "domain_naming_master", "recycle_bin_enabled", "machine_account_quota",
        "ldap_signing_requirement", "ldap_channel_binding_requirement",
        "site_name", "is_global_catalog", "is_read_only", "operation_master_roles",
        "advertising_state", "connectivity_state", "services_state", "sysvol_state",
        "netlogon_state", "dns_state", "health_error_codes",
        "infrastructure_role",
        "source_dc", "destination_dc", "naming_context",
        "last_replication_attempt_utc", "last_replication_success_utc",
        "consecutive_failure_count", "last_replication_result", "replication_state",
    }
)
RELATION_ATTRIBUTE_KEYS = frozenset({"membership_type", "source_section"})
MAX_RECORDS = 200_000
MAX_TEXT_LENGTH = 4096
TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "source_pack_id", "source_pack_version", "run_id", "mode", "domain", "scope", "observed_at_utc", "sections", "records", "gpo_v2_snapshot", "bundle_sha256"}
)
DOMAIN_KEYS = frozenset({"sid", "dns_name"})
SCOPE_KEYS = frozenset({"search_base", "privileged_group_sids", "vpn_group_sids", "collection_profile", "computer_membership_collected"})
SECTION_PROFILES = {
    "privileged_membership": "privileged_membership_v1",
    "directory_accounts": "directory_security_v1",
    "directory_group_graph": "directory_group_graph_v1",
    "directory_exact_logon": "directory_exact_logon_v1",
    "vpn_membership": "vpn_security_v1",
    "gpo_governance": "gpo_governance_v2",
    "domain_posture": "domain_posture_v1",
    "domain_health": "domain_health_v1",
}
SNAPSHOT_BASE_PROFILE_SECTIONS = (
    "directory_accounts",
    "directory_group_graph",
    "directory_exact_logon",
)
SECTION_KEYS = frozenset({"name", "status", "record_count", "duration_ms", "error_code"})
COMMON_RECORD_KEYS = frozenset({"record_type", "record_key", "section", "observed_at_utc"})
IDENTITY_KEYS = frozenset({"kind", "domain_sid", "object_guid", "object_sid"})
COMPUTER_ATTRIBUTE_SOURCES = {
    "enabled": "Enabled",
    "last_logon_utc": "LastLogonDate",
    "dns_host_name": "DNSHostName",
    "operating_system": "OperatingSystem",
    "operating_system_version": "OperatingSystemVersion",
}
COMPUTER_REFERENCE_ATTRIBUTE_SOURCES = {
    **COMPUTER_ATTRIBUTE_SOURCES,
    "operating_system_service_pack": "OperatingSystemServicePack",
    "canonical_name": "CanonicalName",
    "description": "Description",
    "location": "Location",
    "managed_by": "ManagedBy",
    "password_last_set_utc": "PasswordLastSet",
    "created_utc": "whenCreated",
    "when_changed_utc": "whenChanged",
    "service_principal_names": "servicePrincipalName",
    "trusted_for_delegation": "TrustedForDelegation",
    "trusted_to_auth_for_delegation": "TrustedToAuthForDelegation",
    "user_account_control": "userAccountControl",
}
COMPUTER_ATTRIBUTE_STATES = frozenset({"present", "absent_in_source"})
SOURCE_STATE_VALUES = frozenset({
    "observed", "not_collected", "not_evaluated", "missing_in_source", "no_record",
    "partial", "failed", "access_denied", "parse_error", "not_applicable",
})


class AdContextContractError(ValueError):
    pass


def load_bundle(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 25 * 1024 * 1024:
        raise AdContextContractError("AD Context bundle exceeds the 25 MiB first-slice limit")
    try:
        raw = path.read_bytes()
        sidecar = path.with_name(path.name + ".sha256")
        if not sidecar.is_file():
            raise AdContextContractError("AD Context bundle SHA-256 sidecar is required")
        sidecar_parts = sidecar.read_text(encoding="ascii").strip().split()
        if not sidecar_parts:
            raise AdContextContractError("AD Context bundle SHA-256 sidecar is empty")
        expected = sidecar_parts[0].lower()
        if len(expected) != 64 or expected != hashlib.sha256(raw).hexdigest():
            raise AdContextContractError("AD Context bundle file SHA-256 mismatch")
        data = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdContextContractError(f"invalid AD Context JSON bundle: {type(exc).__name__}") from exc
    return validate_bundle(data)


def validate_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(bundle, dict):
        raise AdContextContractError("bundle must be an object")
    _reject_unknown(bundle, TOP_LEVEL_KEYS, "bundle")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise AdContextContractError("unsupported AD Context schema_version")
    if bundle.get("source_pack_id") != PACK_ID:
        raise AdContextContractError("unexpected AD Context source_pack_id")
    source_pack_version = _required_text(
        bundle.get("source_pack_version"), "source_pack_version"
    )
    version_match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", source_pack_version)
    require_computer_reference_provenance = bool(
        version_match
        and tuple(int(value) for value in version_match.groups()) >= (0, 9, 0)
    )
    try:
        run_id = str(UUID(str(bundle.get("run_id") or "")))
    except ValueError as exc:
        raise AdContextContractError("run_id must be a UUID") from exc
    mode = _enum(bundle.get("mode"), SUPPORTED_MODES, "mode")
    domain = _object(bundle.get("domain"), "domain")
    _reject_unknown(domain, DOMAIN_KEYS, "domain")
    domain_sid = _required_text(domain.get("sid"), "domain.sid")
    domain_dns = _required_text(domain.get("dns_name"), "domain.dns_name").lower()
    scope = _object(bundle.get("scope"), "scope")
    _reject_unknown(scope, SCOPE_KEYS, "scope")
    search_base = _required_text(scope.get("search_base"), "scope.search_base")
    collection_profile = _optional_text(scope.get("collection_profile"), "scope.collection_profile", 128)
    if "computer_membership_collected" in scope and not isinstance(scope["computer_membership_collected"], bool):
        raise AdContextContractError("scope.computer_membership_collected must be boolean")
    raw_group_sids = scope.get("privileged_group_sids", [])
    raw_vpn_group_sids = scope.get("vpn_group_sids", [])
    if not isinstance(raw_group_sids, list) or not isinstance(raw_vpn_group_sids, list):
        raise AdContextContractError("scope group SID fields must be arrays")
    group_sids = [_required_text(value, "scope.privileged_group_sids") for value in raw_group_sids]
    vpn_group_sids = [_required_text(value, "scope.vpn_group_sids") for value in raw_vpn_group_sids]
    if len(group_sids) != len({value.casefold() for value in group_sids}):
        raise AdContextContractError("scope.privileged_group_sids must be unique")
    if len(vpn_group_sids) != len({value.casefold() for value in vpn_group_sids}):
        raise AdContextContractError("scope.vpn_group_sids must be unique")
    observed_at = _utc(bundle.get("observed_at_utc"), "observed_at_utc")
    sections = bundle.get("sections")
    records = bundle.get("records")
    if not isinstance(sections, list) or not sections:
        raise AdContextContractError("sections must be a non-empty array")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise AdContextContractError("records must be a bounded array")
    normalized_sections = [_section(item) for item in sections]
    if scope.get("computer_membership_collected") is True and not any(
        item["name"] == "directory_group_graph" and item["status"] == "complete" for item in normalized_sections
    ):
        raise AdContextContractError("computer membership requires a complete directory_group_graph section")
    names = [item["name"] for item in normalized_sections]
    if len(names) != len(set(names)):
        raise AdContextContractError("section names must be unique")
    if collection_profile is not None:
        profile_matches = len(names) == 1 and collection_profile == SECTION_PROFILES[names[0]]
        if len(names) == 1 and names[0] == "gpo_governance" and collection_profile in {"gpo_governance_v3", "gpo_governance_v4"}:
            profile_matches = True
        if collection_profile == "ad_snapshot_base_v1" and tuple(names) == SNAPSHOT_BASE_PROFILE_SECTIONS:
            profile_matches = True
        if not profile_matches:
            raise AdContextContractError("scope.collection_profile does not match the collected section")
    declared_statuses = {item["name"]: item["status"] for item in normalized_sections}
    for section_name, group_scope, scope_key in (
        ("privileged_membership", group_sids, "privileged_group_sids"),
        ("vpn_membership", vpn_group_sids, "vpn_group_sids"),
    ):
        if section_name in names and not group_scope and declared_statuses[section_name] not in {"skipped", "failed"}:
            raise AdContextContractError(f"{section_name} requires scope.{scope_key}")
    normalized_records = [
        _record(
            item,
            domain_sid,
            require_computer_reference_provenance=require_computer_reference_provenance,
        )
        for item in records
    ]
    if any(item["observed_at_utc"] != observed_at for item in normalized_records):
        raise AdContextContractError("record observation time must match bundle observed_at_utc")
    keys = [item["record_key"] for item in normalized_records]
    if len(keys) != len(set(keys)):
        raise AdContextContractError("record_key values must be unique inside one bundle")
    declared = {item["name"]: item for item in normalized_sections}
    for item in normalized_records:
        if item["section"] not in declared:
            raise AdContextContractError("record references an undeclared section")
    for section in normalized_sections:
        actual = sum(1 for item in normalized_records if item["section"] == section["name"])
        if section["record_count"] != actual:
            raise AdContextContractError(f"section {section['name']} record_count mismatch")
    if (
        collection_profile == "ad_snapshot_base_v1"
        and declared["directory_exact_logon"]["status"] == "complete"
    ):
        required_exact_logon_attributes = {
            "exact_last_logon_status",
            "exact_last_logon_discovered_dc_count",
            "exact_last_logon_successful_dc_count",
            "exact_last_logon_failed_dcs",
        }
        missing_exact_logon_coverage = [
            item["record_key"]
            for item in normalized_records
            if item["record_type"] == "entity"
            and item["section"] == "directory_accounts"
            and item["identity"]["kind"] == "ad_user"
            and not required_exact_logon_attributes.issubset(item["attributes"])
        ]
        if missing_exact_logon_coverage:
            raise AdContextContractError(
                "complete ad_snapshot_base_v1 exact lastLogon coverage is missing "
                "from one or more directory_accounts ad_user records"
            )
    entities = {item["record_key"]: item for item in normalized_records if item["record_type"] == "entity"}
    relations = [item for item in normalized_records if item["record_type"] == "relation"]
    if any(
        relation["source_record_key"] not in entities
        or relation["target_record_key"] not in entities
        for relation in relations
    ):
        raise AdContextContractError("membership relation endpoints must be entity records")
    scoped_groups = {
        str(item["identity"].get("object_sid") or "").casefold(): item["record_key"]
        for item in entities.values()
        if item["identity"]["kind"] == "ad_group"
    }
    missing_groups = [sid for sid in group_sids + vpn_group_sids if sid.casefold() not in scoped_groups]
    if missing_groups:
        raise AdContextContractError("scope group SID must have an ad_group entity record")
    for section_name, root_sids in (
        ("privileged_membership", group_sids), ("vpn_membership", vpn_group_sids),
    ):
        section_relations = [
            item for item in normalized_records
            if item["record_type"] == "relation" and item["section"] == section_name
        ]
        if not section_relations:
            continue
        reachable_groups = {scoped_groups[sid.casefold()] for sid in root_sids}
        changed = True
        while changed:
            changed = False
            for relation in section_relations:
                source = entities.get(relation["source_record_key"])
                if (
                    relation["target_record_key"] in reachable_groups
                    and source is not None and source["identity"]["kind"] == "ad_group"
                    and relation["source_record_key"] not in reachable_groups
                ):
                    reachable_groups.add(relation["source_record_key"])
                    changed = True
        if any(relation["target_record_key"] not in reachable_groups for relation in section_relations):
            raise AdContextContractError("membership relation target is outside the declared section scope")
        if any(
            relation["source_record_key"] not in entities or relation["target_record_key"] not in entities
            for relation in section_relations
        ):
            raise AdContextContractError("membership relation endpoints must be entity records")
    gpo_v2_snapshot = validate_context_snapshot(
        bundle, names=names, collection_profile=collection_profile,
    )

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "source_pack_id": PACK_ID,
        "source_pack_version": source_pack_version,
        "run_id": run_id,
        "mode": mode,
        "domain": {"sid": domain_sid, "dns_name": domain_dns},
        "scope": {
            "search_base": search_base,
            "privileged_group_sids": sorted(group_sids, key=str.casefold),
            "vpn_group_sids": sorted(vpn_group_sids, key=str.casefold),
            **({"collection_profile": collection_profile} if collection_profile is not None else {}),
        },
        "observed_at_utc": observed_at,
        "sections": normalized_sections,
        "records": sorted(normalized_records, key=lambda item: item["record_key"]),
        **({"gpo_v2_snapshot": gpo_v2_snapshot} if gpo_v2_snapshot is not None else {}),
    }
    if "computer_membership_collected" in scope:
        normalized["scope"]["computer_membership_collected"] = scope["computer_membership_collected"]
    calculated_hash = canonical_sha256(normalized)
    supplied_hash = str(bundle.get("bundle_sha256") or "").strip().lower()
    if supplied_hash and supplied_hash != calculated_hash:
        raise AdContextContractError("bundle_sha256 does not match normalized bundle content")
    normalized["bundle_sha256"] = calculated_hash
    return normalized


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_content_sha256(record: dict[str, Any]) -> str:
    """Hash semantic content, not observation metadata."""
    return canonical_sha256({key: value for key, value in record.items() if key != "observed_at_utc"})


def _section(value: Any) -> dict[str, Any]:
    section = _object(value, "section")
    _reject_unknown(section, SECTION_KEYS, "section")
    name = _enum(section.get("name"), SUPPORTED_SECTIONS, "section.name")
    status = _enum(section.get("status"), SUPPORTED_SECTION_STATUSES, "section.status")
    try:
        record_count = int(section.get("record_count"))
    except (TypeError, ValueError) as exc:
        raise AdContextContractError("section.record_count must be an integer") from exc
    if record_count < 0 or record_count > MAX_RECORDS:
        raise AdContextContractError("section.record_count is out of bounds")
    return {
        "name": name,
        "status": status,
        "record_count": record_count,
        "duration_ms": max(0, int(section.get("duration_ms") or 0)),
        "error_code": _optional_text(section.get("error_code"), "section.error_code", 128),
    }


def _record(
    value: Any,
    expected_domain_sid: str,
    *,
    require_computer_reference_provenance: bool = False,
) -> dict[str, Any]:
    record = _object(value, "record")
    record_type = _enum(record.get("record_type"), frozenset({"entity", "relation", "data_quality"}), "record_type")
    common = {
        "record_type": record_type,
        "record_key": _required_text(record.get("record_key"), "record_key"),
        "section": _enum(record.get("section"), SUPPORTED_SECTIONS, "section"),
        "observed_at_utc": _utc(record.get("observed_at_utc"), "record.observed_at_utc"),
    }
    if record_type == "entity":
        _reject_unknown(record, COMMON_RECORD_KEYS | {"identity", "attributes"}, "entity record")
        identity = _object(record.get("identity"), "identity")
        _reject_unknown(identity, IDENTITY_KEYS, "identity")
        domain_sid = _required_text(identity.get("domain_sid"), "identity.domain_sid")
        if domain_sid.casefold() != expected_domain_sid.casefold():
            raise AdContextContractError("entity domain_sid differs from bundle domain")
        kind = _enum(identity.get("kind"), ENTITY_KINDS, "identity.kind")
        object_guid = _required_text(identity.get("object_guid"), "identity.object_guid").lower()
        try:
            object_guid = str(UUID(object_guid))
        except ValueError as exc:
            raise AdContextContractError("identity.object_guid must be a UUID") from exc
        raw_attributes = _object(record.get("attributes") or {}, "entity.attributes")
        raw_gpo_settings = raw_attributes.pop("gpo_settings", None)
        raw_attribute_states = raw_attributes.pop("attribute_states", None)
        raw_reference_attribute_states = raw_attributes.pop(
            "computer_reference_attribute_states", None
        )
        attributes = _allowlisted_object(raw_attributes, ENTITY_ATTRIBUTE_KEYS, "entity.attributes")
        for key in ("password_last_set_status", "laps_password_expiration_status", "legacy_laps_password_expiration_status"):
            if key in attributes:
                _enum(attributes[key], frozenset({"observed", "not_set", "not_returned", "schema_absent", "parse_error"}), key)
        if "resource_based_delegation_status" in attributes:
            _enum(attributes["resource_based_delegation_status"], frozenset({
                "observed", "partial", "not_returned", "schema_absent", "parse_error", "not_collected",
            }), "resource_based_delegation_status")
        if attributes.get("resource_based_delegation_sids") is not None:
            sids = attributes["resource_based_delegation_sids"]
            if not isinstance(sids, list) or any(not re.fullmatch(r"S-1-(?:\d+-)+\d+", sid) for sid in sids):
                raise AdContextContractError("resource_based_delegation_sids must contain SIDs")
        if raw_gpo_settings is not None:
            if kind != "gpo" or common["section"] != "gpo_governance":
                raise AdContextContractError("gpo_settings is only valid for GPO governance entities")
            attributes["gpo_settings"] = _gpo_settings(raw_gpo_settings)
        if raw_attribute_states is not None:
            if kind != "ad_computer" or common["section"] != "directory_accounts":
                raise AdContextContractError(
                    "entity.attributes.attribute_states is only valid for directory computer entities"
                )
            attributes["attribute_states"] = _computer_attribute_states(raw_attribute_states)
        if raw_reference_attribute_states is not None:
            if kind != "ad_computer" or common["section"] != "directory_accounts":
                raise AdContextContractError(
                    "entity.attributes.computer_reference_attribute_states is only valid "
                    "for directory computer entities"
                )
            attributes["computer_reference_attribute_states"] = (
                _computer_reference_attribute_states(raw_reference_attribute_states)
            )
        elif (
            require_computer_reference_provenance
            and kind == "ad_computer"
            and common["section"] == "directory_accounts"
        ):
            raise AdContextContractError(
                "entity.attributes.computer_reference_attribute_states must describe "
                "every supported computer attribute"
            )
        inactivity_basis = attributes.get("inactivity_basis")
        if inactivity_basis not in {
            None,
            "not_applicable",
            "last_logon",
            "creation_time_without_logon",
            "insufficient_time_evidence",
        }:
            raise AdContextContractError(
                "entity.attributes.inactivity_basis is unsupported"
            )
        for state_key in ("password_expiry_status", "exact_last_logon_status"):
            if state_key in attributes:
                _enum(attributes[state_key], SOURCE_STATE_VALUES, f"entity.attributes.{state_key}")
        common.update(
            {
                "identity": {
                    "kind": kind,
                    "domain_sid": domain_sid,
                    "object_guid": object_guid,
                    "object_sid": _optional_text(identity.get("object_sid"), "identity.object_sid", 256),
                },
                "attributes": attributes,
            }
        )
        return common
    if record_type == "relation":
        _reject_unknown(
            record,
            COMMON_RECORD_KEYS | {"relation_kind", "source_record_key", "target_record_key", "attributes"},
            "relation record",
        )
        relation_kind = _enum(record.get("relation_kind"), frozenset({"member_of"}), "relation_kind")
        attributes = _allowlisted_object(record.get("attributes"), RELATION_ATTRIBUTE_KEYS, "relation.attributes")
        if "membership_type" in attributes:
            _enum(
                attributes["membership_type"],
                frozenset({"direct", "primary"}),
                "relation.attributes.membership_type",
            )
        common.update(
            {
                "relation_kind": relation_kind,
                "source_record_key": _required_text(record.get("source_record_key"), "source_record_key"),
                "target_record_key": _required_text(record.get("target_record_key"), "target_record_key"),
                "attributes": attributes,
            }
        )
        return common
    _reject_unknown(record, COMMON_RECORD_KEYS | {"classification", "code", "message"}, "data-quality record")
    if record.get("classification") not in (None, "DataQuality"):
        raise AdContextContractError("data-quality classification must be DataQuality")
    common.update(
        {
            "classification": "DataQuality",
            "code": _required_text(record.get("code"), "data_quality.code"),
            "message": _required_text(record.get("message"), "data_quality.message"),
        }
    )
    return common


def _allowlisted_object(value: Any, allowed: frozenset[str], label: str) -> dict[str, Any]:
    data = _object(value or {}, label)
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise AdContextContractError(f"{label} has unsupported fields: {', '.join(unknown)}")
    for key, item in data.items():
        if isinstance(item, str) and len(item) > MAX_TEXT_LENGTH:
            raise AdContextContractError(f"{label}.{key} is too long")
        if isinstance(item, list):
            if len(item) > 256:
                raise AdContextContractError(f"{label}.{key} has too many values")
            if any(not isinstance(entry, str) or len(entry) > MAX_TEXT_LENGTH for entry in item):
                raise AdContextContractError(f"{label}.{key} must contain bounded strings")
    return data


def _normalized_computer_attribute_states(
    value: Any,
    *,
    sources: dict[str, str],
    label: str,
) -> dict[str, dict[str, str]]:
    data = _object(value, label)
    if set(data) != set(sources):
        raise AdContextContractError(f"{label} must describe every supported computer attribute")
    normalized: dict[str, dict[str, str]] = {}
    for key, expected_source in sources.items():
        item_label = f"{label}.{key}"
        item = _object(data.get(key), item_label)
        _reject_unknown(item, frozenset({"state", "source_attribute"}), item_label)
        state = _enum(
            item.get("state"), COMPUTER_ATTRIBUTE_STATES,
            f"{item_label} attribute state",
        )
        source = _required_text(item.get("source_attribute"), f"{item_label}.source_attribute")
        if source != expected_source:
            raise AdContextContractError(f"{item_label}.source_attribute is inconsistent")
        normalized[key] = {"state": state, "source_attribute": source}
    return normalized


def _computer_attribute_states(value: Any) -> dict[str, dict[str, str]]:
    return _normalized_computer_attribute_states(
        value,
        sources=COMPUTER_ATTRIBUTE_SOURCES,
        label="entity.attributes.attribute_states",
    )


def _computer_reference_attribute_states(value: Any) -> dict[str, dict[str, str]]:
    return _normalized_computer_attribute_states(
        value,
        sources=COMPUTER_REFERENCE_ATTRIBUTE_SOURCES,
        label="entity.attributes.computer_reference_attribute_states",
    )


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdContextContractError(f"{label} must be an object")
    return dict(value)


def _reject_unknown(value: dict[str, Any], allowed: frozenset[str] | set[str], label: str) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise AdContextContractError(f"{label} has unsupported fields: {', '.join(unknown)}")


def _enum(value: Any, allowed: frozenset[str], label: str) -> str:
    text = _required_text(value, label)
    if text not in allowed:
        raise AdContextContractError(f"unsupported {label}: {text}")
    return text


def _required_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > MAX_TEXT_LENGTH:
        raise AdContextContractError(f"{label} is required and bounded")
    return text


def _optional_text(value: Any, label: str, limit: int) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if len(text) > limit:
        raise AdContextContractError(f"{label} is too long")
    return text or None


def _utc(value: Any, label: str) -> str:
    text = _required_text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AdContextContractError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AdContextContractError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
