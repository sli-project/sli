"""Disabled-by-default bridges from existing audit rows to journal v1."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from server.sli.reports.administrative_activity import (
    AdministrativeActivity,
    append_administrative_activity_with_cursor,
    load_administrative_activity_contract,
    validate_administrative_activity,
)

AUTH_ACTIONS: dict[str, tuple[str, str, str | None]] = {
    "login": ("authentication", "auth.login", None),
    "logout": ("authentication", "auth.logout", None),
    "initial_owner_claimed": ("access_management", "auth.initial_owner.claimed", "platform_owner"),
    "user_created": ("access_management", "auth.user.created", "user"),
    "user_updated": ("access_management", "auth.user.updated", "user"),
    "user_password_reset": (
        "access_management",
        "auth.user.password_reset",
        "user",
    ),
    "api_key_issued": ("access_management", "auth.api_key.issued", "api_key"),
    "api_key_revoked": ("access_management", "auth.api_key.revoked", "api_key"),
}
ACCESS_ACTIONS: dict[str, tuple[str, str, str]] = {
    "report_key_capabilities_created": (
        "access_management", "access.report_key.capabilities_created", "ad_domain"
    ),
    "report_api_key_issued": (
        "access_management", "access.report_key.issued", "api_key"
    ),
    "report_assignment_created": (
        "access_management", "access.report.assignment_created", "report"
    ),
    "package_assignment_created": (
        "access_management", "access.package.assignment_created", "package"
    ),
    "vpn_session_evidence_grant_created": (
        "access_management", "access.vpn.session_evidence_grant_created", "capability"
    ),
    "report_access_requested": (
        "access_management", "access.report.requested", "report"
    ),
    "report_access_request_rejected": (
        "access_management", "access.report.request_rejected", "report"
    ),
    "report_access_request_approved": (
        "access_management", "access.report.request_approved", "report"
    ),
    "report_published": (
        "report_publication", "report.published", "report"
    ),
    "report_draft_created": (
        "report_publication", "report.draft_created", "report"
    ),
    "report_version_promoted": (
        "report_publication", "report.version_promoted", "report"
    ),
    "report_retired": (
        "report_publication", "report.retired", "report"
    ),
    "report_visibility_changed": (
        "report_publication", "report.visibility_changed", "report"
    ),
    # «Настройки платформы» (owner decision 2026-10-01): installation-wide
    # configuration such as the report domain.
    "platform_setting_update": (
        "source_configuration", "platform.setting.updated", "platform_setting"
    ),
    # «Первичная настройка»: AD domains registered or changed by an administrator.
    "setup_domain_add": (
        "source_configuration", "setup.domain.added", "ad_domain"
    ),
    "setup_domain_update": (
        "source_configuration", "setup.domain.updated", "ad_domain"
    ),
    # «Первичная настройка»: domain controller collection targets.
    "setup_dc_add": (
        "source_configuration", "setup.domain_controller.added", "domain_controller"
    ),
    "setup_dc_update": (
        "source_configuration", "setup.domain_controller.updated", "domain_controller"
    ),
}
OUTCOMES = {
    "ok": "succeeded",
    "failed": "failed",
    "throttled": "denied",
    "denied": "denied",
}
ACTOR_KINDS = {
    "session": "session",
    "api_key": "api_key",
    "windows": "windows",
    "system": "system",
    "local": "local_operator",
    "local_operator": "local_operator",
    "plugin": "plugin",
    "anonymous": "system",
}


def mirror_auth_audit_if_enabled(
    *,
    cursor: Any,
    audit_id: int,
    created_at: datetime,
    actor_type: str,
    actor_id: int | None,
    action: str,
    outcome: str,
    remote_address: str | None,
) -> dict[str, Any]:
    """Validate every bridge but write only after explicit contract activation."""
    clean_id = int(audit_id)
    if clean_id < 1:
        raise ValueError("administrative_activity_auth_audit_id_invalid")
    action_parts = str(action or "").split(":")
    action_prefix = action_parts[0]
    mapping = AUTH_ACTIONS.get(action_prefix)
    if mapping is None:
        raise ValueError("administrative_activity_auth_action_not_allowlisted")
    category, action_key, target_kind = mapping
    actor_kind = ACTOR_KINDS.get(str(actor_type or "").strip().lower())
    if actor_kind is None:
        raise ValueError("administrative_activity_auth_actor_not_allowlisted")
    mapped_outcome = OUTCOMES.get(str(outcome or "").strip().lower())
    if mapped_outcome is None:
        raise ValueError("administrative_activity_auth_outcome_not_allowlisted")
    target_key = None
    if target_kind == "platform_owner":
        # Activation targets the singleton owner slot, including anonymous failures.
        if len(action_parts) != 1:
            raise ValueError("administrative_activity_auth_target_invalid")
        target_key = "platform_owner:primary"
    elif target_kind is not None:
        if len(action_parts) < 2 or not action_parts[1].isdigit():
            raise ValueError("administrative_activity_auth_target_invalid")
        target_key = f"{target_kind}:{int(action_parts[1])}"
    activity = AdministrativeActivity(
        event_uid=uuid5(NAMESPACE_URL, f"sli:auth_audit:{clean_id}"),
        occurred_at_utc=created_at,
        actor_kind=actor_kind,
        actor_key=(
            f"{actor_kind}:{int(actor_id)}"
            if actor_id is not None else f"{actor_kind}:anonymous"
        ),
        category=category,
        action_key=action_key,
        target_kind=target_kind,
        target_key=target_key,
        outcome=mapped_outcome,
        reason_code=(
            "authentication_throttled" if outcome == "throttled" else None
        ),
        details={"legacy_auth_audit_id": clean_id},
        remote_address=remote_address,
    )
    validate_administrative_activity(activity)
    contract = load_administrative_activity_contract()
    if contract["runtime_write_enabled"] is not True:
        return {
            "status": "disabled",
            "source": "auth_audit",
            "source_row_id": clean_id,
            "journal_written": False,
        }
    written = append_administrative_activity_with_cursor(activity, cursor=cursor)
    return {
        "status": "written",
        "source": "auth_audit",
        "source_row_id": clean_id,
        "journal_written": True,
        "activity_id": written["activity_id"],
    }


def mirror_access_audit_if_enabled(
    *,
    cursor: Any,
    audit_id: int,
    created_at: datetime,
    actor_type: str,
    actor_id: int | None,
    action: str,
    subject_type: str | None,
    subject_id: int | None,
    target_type: str | None,
    target_key: str | None,
    outcome: str,
    remote_address: str | None,
) -> dict[str, Any]:
    """Project one allowlisted access audit row without reason or raw details."""
    clean_id = int(audit_id)
    if clean_id < 1:
        raise ValueError("administrative_activity_access_audit_id_invalid")
    clean_action = str(action or "").strip()
    mapping = ACCESS_ACTIONS.get(clean_action)
    if mapping is None:
        raise ValueError("administrative_activity_access_action_not_allowlisted")
    actor_kind = ACTOR_KINDS.get(str(actor_type or "").strip().lower())
    if actor_kind is None:
        raise ValueError("administrative_activity_access_actor_not_allowlisted")
    mapped_outcome = OUTCOMES.get(str(outcome or "").strip().lower())
    if mapped_outcome is None:
        raise ValueError("administrative_activity_access_outcome_not_allowlisted")
    category, action_key, expected_target_kind = mapping
    clean_target_type = str(target_type or "").strip().lower()
    clean_target_key = str(target_key or "").strip()
    if clean_target_type != expected_target_kind or not clean_target_key:
        raise ValueError("administrative_activity_access_target_invalid")
    details: dict[str, str | int] = {"legacy_access_audit_id": clean_id}
    if subject_type is not None:
        clean_subject_type = str(subject_type).strip().lower()
        if clean_subject_type not in {"user", "group"}:
            raise ValueError("administrative_activity_access_subject_invalid")
        if subject_id is None or int(subject_id) < 1:
            raise ValueError("administrative_activity_access_subject_invalid")
        details["subject_type"] = clean_subject_type
        details["subject_id"] = int(subject_id)
    activity = AdministrativeActivity(
        event_uid=uuid5(NAMESPACE_URL, f"sli:access_audit_v4:{clean_id}"),
        occurred_at_utc=created_at,
        actor_kind=actor_kind,
        actor_key=(
            f"{actor_kind}:{int(actor_id)}"
            if actor_id is not None else f"{actor_kind}:anonymous"
        ),
        category=category,
        action_key=action_key,
        target_kind=expected_target_kind,
        target_key=f"{expected_target_kind}:{clean_target_key}",
        outcome=mapped_outcome,
        details=details,
        remote_address=remote_address,
    )
    validate_administrative_activity(activity)
    contract = load_administrative_activity_contract()
    if contract["runtime_write_enabled"] is not True:
        return {
            "status": "disabled",
            "source": "access_audit_v4",
            "source_row_id": clean_id,
            "journal_written": False,
        }
    written = append_administrative_activity_with_cursor(activity, cursor=cursor)
    return {
        "status": "written",
        "source": "access_audit_v4",
        "source_row_id": clean_id,
        "journal_written": True,
        "activity_id": written["activity_id"],
    }
