"""Field-policy projection for entity directory context."""
from __future__ import annotations

from typing import Any, Mapping


ATTRIBUTE_CATEGORIES: dict[str, str] = {
    "display_name": "identity_basic", "record_key": "identity_basic",
    "kind": "identity_basic", "object_class": "identity_basic",
    "enabled": "security", "locked": "security", "locked_out": "security",
    "lockout_time": "security", "last_logon_utc": "security",
    "is_inactive": "security", "password_never_expires": "security",
    "password_last_set_utc": "security", "account_expiration_utc": "security",
    "inactive_threshold_days": "security", "operating_system": "security",
    "operating_system_version": "security", "admin_count": "privilege",
    "privileged": "privilege", "member_of": "privilege",
    "membership_type": "privilege", "department": "hr", "title": "hr",
    "employee_id": "hr", "email": "contact", "mail": "contact",
    "telephone_number": "contact", "object_guid": "technical",
    "object_sid": "technical", "domain_sid": "technical",
    "distinguished_name": "technical", "dns_host_name": "technical",
    "source_section": "technical", "relation_type": "technical",
}

RELATION_CLASS_BY_SECTION = {"privileged_membership": "privileged", "vpn_membership": "vpn"}


def project_attributes(
    attributes: Mapping[str, Any], capabilities: set[str],
) -> dict[str, Any]:
    projected: dict[str, Any] = {}
    for key, value in attributes.items():
        category = ATTRIBUTE_CATEGORIES.get(str(key))
        if category and f"field.{category}" in capabilities:
            projected[str(key)] = value
    return projected


def project_context_record(
    record: Mapping[str, Any], capabilities: set[str],
) -> dict[str, Any]:
    """Flatten a context envelope while applying the field allowlist."""
    projected: dict[str, Any] = {}
    for key in ("attributes", "identity"):
        nested = record.get(key)
        if isinstance(nested, Mapping):
            projected.update(project_attributes(nested, capabilities))
    projected.update(project_attributes(record, capabilities))
    return projected


def project_ad_context(
    context: Mapping[str, Any], *, capabilities: set[str], include_relations: bool,
) -> dict[str, Any]:
    """Return response-safe AD context without protected fields or counters."""
    result = dict(context)
    projected_items: list[dict[str, Any]] = []
    for source in context.get("items") or []:
        item = dict(source)
        if item.get("context_kind") == "relation" and not include_relations:
            continue
        item["attributes"] = project_context_record(
            dict(item.get("attributes") or {}), capabilities,
        )
        if item.get("context_kind") == "relation":
            # The collection section is technical, but the UI must still tell a
            # privileged membership from a VPN or plain group one.
            item["relation_class"] = RELATION_CLASS_BY_SECTION.get(str(item.get("source_section") or ""), "group")
        item.pop("integrity_sha256", None)
        if "field.technical" not in capabilities:
            for key in (
                "source_run_id", "context_evidence_id",
                "subject_entity_id", "related_entity_id", "source_section",
            ):
                item.pop(key, None)
        if "field.identity_basic" not in capabilities:
            item.pop("subject_display_name", None)
            item.pop("related_display_name", None)
        projected_items.append(item)
    result["items"] = projected_items
    result["returned_count"] = len(projected_items)
    if "field.technical" not in capabilities:
        result.pop("ad_context_entity_id", None)
    return result
