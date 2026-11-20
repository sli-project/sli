from __future__ import annotations

"""Windows AD/DC event catalogue: constants, event-ID sets and pure lookups."""

from collections.abc import Mapping
from typing import Any

# Source-pack-owned context for the bounded PowerShell origin read model.
# These events are not a general process-reporting surface.
DC_POWERSHELL_ORIGIN_EVENT_IDS = {
    "boot_start": 4608,
    "process_start": 4688,
    "process_stop": 4689,
    "session_start": 4624,
    "session_stop": 4634,
}


# Exact source-owned scope for short-lived routine session source records.
SECURITY_ROUTINE_SESSION_EVENT_KEYS = frozenset({"4624", "4634"})


# Source-pack-owned scope for the bounded AD account-change history.  These
# are event observations, not a state-machine or a current-account assertion.
AD_ACCOUNT_CHANGE_EVENT_IDS = frozenset({
    4720,
    4722,
    4723,
    4724,
    4725,
    4726,
    4738,
    4740,
    4767,
    4781,
})


_AD_ACCOUNT_CHANGE_KIND_BY_EVENT_ID = {
    4720: "created",
    4722: "enabled",
    4723: "password_change_attempt",
    4724: "password_reset_attempt",
    4725: "disabled",
    4726: "deleted",
    4738: "attributes_changed",
    4740: "locked",
    4767: "unlocked",
    4781: "renamed",
}


_GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID = {
    4728: ("added", "global"),
    4729: ("removed", "global"),
    4732: ("added", "local"),
    4733: ("removed", "local"),
    4756: ("added", "universal"),
    4757: ("removed", "universal"),
}


_SECURITY_EVENT_CHANGE_KIND_BY_EVENT_ID = {
    4738: "attributes_changed",
    4728: "member_added", 4732: "member_added", 4756: "member_added",
    4729: "member_removed", 4733: "member_removed", 4757: "member_removed",
    4727: "group_created", 4731: "group_created", 4754: "group_created",
    4730: "group_deleted", 4734: "group_deleted", 4755: "group_deleted",
    4737: "group_changed", 4735: "group_changed", 4758: "group_changed",
    4764: "group_type_changed",
    4719: "audit_policy_changed", 1102: "security_log_cleared",
}


_SECURITY_EVENT_CHANGE_TEXT_LIMIT = 512


_SECURITY_EVENT_ACCOUNT_ATTRIBUTE_FIELDS = (
    (("DisplayName", "changed_display_name"), "display_name"),
    (("SamAccountName", "changed_sam_account_name"), "sam_account_name"),
    (("UserPrincipalName", "changed_user_principal_name"), "user_principal_name"),
    (("HomeDirectory", "changed_home_directory"), "home_directory"),
    (("HomePath", "changed_home_path"), "home_path"),
    (("ScriptPath", "changed_script_path"), "script_path"),
    (("ProfilePath", "changed_profile_path"), "profile_path"),
    (("UserWorkstations", "changed_user_workstations"), "user_workstations"),
    (("PasswordLastSet", "changed_password_last_set"), "password_last_set"),
    (("AccountExpires", "changed_account_expires"), "account_expires"),
    (("PrimaryGroupId", "changed_primary_group_id"), "primary_group_id"),
    (("AllowedToDelegateTo", "changed_allowed_to_delegate_to"), "allowed_to_delegate_to"),
    (("UserAccountControl", "changed_user_account_control"), "user_account_control"),
    (("OldUacValue", "old_user_account_control"), "old_user_account_control"),
    (("NewUacValue", "new_user_account_control"), "new_user_account_control"),
)


_SECURITY_EVENT_GROUP_ATTRIBUTE_FIELDS = (
    (("Description", "changed_description"), "description"),
    (("DisplayName", "changed_display_name"), "display_name"),
    (("SamAccountName", "changed_sam_account_name"), "sam_account_name"),
    (("GroupType", "changed_group_type"), "group_type"),
)


# The atomic security-events report deliberately has a smaller, source-owned
# vocabulary than the generic event explorer.  Each family is an observation
# class, not a finding or a reconstruction of AD state.
SECURITY_EVENTS_CONTEXT_EVENT_IDS = frozenset({4624, 4625, 4771, 4776})


SECURITY_RELATION_ANCHOR_EVENT_IDS = (
    4625, 4720, 4724, 4728, 4729, 4732, 4733, 4740, 4756, 4757, 4767,
)


SECURITY_RELATION_CONTEXT_EVENT_IDS = (4624,)


SECURITY_RELATION_EVENT_IDS_BY_SEMANTIC_TYPE = {
    "authentication.session.created": (4624,),
    "authentication.session.failed": (4625,),
    "directory.account.created": (4720,),
    "account.password.reset.succeeded": (4724,),
    "group.member.added": (4728, 4732, 4756),
    "group.member.removed": (4729, 4733, 4757),
    "authentication.account.locked": (4740,),
    "authentication.account.unlocked": (4767,),
}


SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS = frozenset({
    1102, 4719,
    4720, 4722, 4723, 4724, 4725, 4726,
    4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4738,
    4740, 4754, 4755, 4756, 4757, 4758, 4764, 4767, 4781,
})


# The report reads the complete query vocabulary, including authentication.
# Keep the smaller legacy action vocabulary above for existing consumers.
SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS = (
    SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS | SECURITY_EVENTS_CONTEXT_EVENT_IDS
)


# Kept for existing consumers whose unfiltered selection must remain bounded to
# the default report vocabulary.
SECURITY_EVENTS_REPORT_EVENT_IDS = SECURITY_EVENTS_REPORT_DEFAULT_EVENT_IDS


SECURITY_EVENTS_EVENTLOG_EVENT_ID = 1102


SECURITY_EVENTS_REPORT_AUDITING_PROVIDER = "Microsoft-Windows-Security-Auditing"


SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"


SECURITY_EVENTS_MIXED_OUTCOME_EVENT_IDS = frozenset({4723, 4724, 4776})


SECURITY_AUDIT_SUCCESS_KEYWORDS = frozenset({
    "auditsuccess",
    "audit success",
    "9007199254740992",
    "0x20000000000000",
    "0x8020000000000000",
    "-9214364837600034816",
})


SECURITY_AUDIT_FAILURE_KEYWORDS = frozenset({
    "auditfailure",
    "audit failure",
    "4503599627370496",
    "0x10000000000000",
    "0x8010000000000000",
    "-9218868437227405312",
})


_SECURITY_EVENT_FAMILY_BY_EVENT_ID = {
    4740: "account_lock", 4767: "account_lock",
    4723: "password_operation", 4724: "password_operation",
    4720: "account_lifecycle", 4722: "account_lifecycle",
    4725: "account_lifecycle", 4726: "account_lifecycle",
    4738: "account_change", 4781: "account_change",
    4728: "group_membership", 4729: "group_membership",
    4732: "group_membership", 4733: "group_membership",
    4756: "group_membership", 4757: "group_membership",
    4727: "group_lifecycle", 4730: "group_lifecycle",
    4731: "group_lifecycle", 4734: "group_lifecycle",
    4735: "group_lifecycle", 4737: "group_lifecycle",
    4754: "group_lifecycle", 4755: "group_lifecycle",
    4758: "group_lifecycle", 4764: "group_lifecycle",
    4624: "authentication", 4625: "authentication",
    4771: "authentication", 4776: "authentication",
    4719: "audit_configuration", 1102: "audit_configuration",
}


_SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID = {
    4624: "success",
    4625: "failure",
    4771: "failure",
}


SECURITY_EVENTS_SUCCESS_EVENT_IDS = frozenset(
    event_id for event_id, outcome in _SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID.items()
    if outcome == "success"
)


SECURITY_EVENTS_FAILURE_EVENT_IDS = frozenset(
    event_id for event_id, outcome in _SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID.items()
    if outcome == "failure"
)


SECURITY_EVENTS_GROUP_EVENT_IDS = frozenset(
    event_id for event_id, family in _SECURITY_EVENT_FAMILY_BY_EVENT_ID.items()
    if family in {"group_membership", "group_lifecycle"}
)


WINDOWS_AUTHENTICATION_REPORT_EVENT_IDS = frozenset({
    4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4770, 4771, 4773,
    4776,
})


WINDOWS_AUTHENTICATION_REPORT_FAILURE_EVENT_IDS = frozenset({
    4625, 4771, 4773,
})


WINDOWS_AUTHENTICATION_REPORT_MIXED_RESULT_EVENT_IDS = frozenset({
    4768, 4769, 4776,
})


WINDOWS_AUTHENTICATION_REPORT_SUBJECT_PRINCIPAL_EVENT_IDS = frozenset({4672})


# Microsoft documents 4772 but Windows does not generate it.  Keep that
# source fact out of both the bounded report and its manual-review policy;
# failures that a domain controller actually emits are represented by their
# own collected Event IDs (including result-code-qualified mixed events).
WINDOWS_AUTHENTICATION_REPORT_DEFINED_NOT_EMITTED_EVENT_IDS = frozenset({4772})


WINDOWS_AUTHENTICATION_REPORT_SUCCESS_EVENT_ID = 4624


WINDOWS_AUTH_SESSION_SUPPLEMENTAL_LOGOUT_EVENT_ID = 4647


WINDOWS_AUTH_SESSION_EXPLICIT_CREDENTIALS_EVENT_ID = 4648


_AD_ACCOUNT_OBSERVED_STATE_BY_EVENT_ID = {
    4720: "present",
    4722: "enabled",
    4725: "disabled",
    4726: "deleted",
    4740: "locked",
    4767: "unlocked",
}


def account_change_kind(event_id: Any) -> str | None:
    try:
        return _AD_ACCOUNT_CHANGE_KIND_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def is_account_rename_event(event_id: Any) -> bool:
    return account_change_kind(event_id) == "renamed"


def observed_account_state_after_change(event_id: Any) -> str | None:
    try:
        return _AD_ACCOUNT_OBSERVED_STATE_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def group_membership_change(event_id: Any) -> tuple[str, str] | None:
    """Return source-native membership operation and group scope only."""

    try:
        return _GROUP_MEMBERSHIP_CHANGE_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def security_event_change_kind(event_id: Any) -> str | None:
    """Return an exact observed report-change kind, never inferred state."""
    try:
        return _SECURITY_EVENT_CHANGE_KIND_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def _security_event_change_text(event_data: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = event_data.get(name)
        if value is not None and (clean := str(value).strip()) and clean != "-":
            return clean[:_SECURITY_EVENT_CHANGE_TEXT_LIMIT]
    return None


def _security_event_partial_change(kind: str, reason: str) -> dict[str, Any]:
    return {
        "state": "partial", "kind": kind,
        "detail": {"state": "unknown", "reason": reason},
    }


def _security_event_observed_attributes(
    event_data: Mapping[str, Any],
    fields: tuple[tuple[tuple[str, str], str], ...],
) -> dict[str, str]:
    return {
        public: value
        for names, public in fields
        if (value := _security_event_change_text(event_data, *names)) is not None
    }


def security_event_observed_change(
    event_id: Any, event_data: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the bounded public change contract for source-native details only."""
    kind = security_event_change_kind(event_id)
    if kind == "attributes_changed":
        attributes = _security_event_observed_attributes(
            event_data, _SECURITY_EVENT_ACCOUNT_ATTRIBUTE_FIELDS,
        )
        return (
            {"state": "observed", "kind": kind, "attributes": attributes}
            if attributes else _security_event_partial_change(
                kind, "account_attributes_not_present",
            )
        )
    if kind == "group_changed":
        attributes = _security_event_observed_attributes(
            event_data, _SECURITY_EVENT_GROUP_ATTRIBUTE_FIELDS,
        )
        return (
            {"state": "observed", "kind": kind, "attributes": attributes}
            if attributes else _security_event_partial_change(
                kind, "group_change_attributes_not_present",
            )
        )
    if kind == "group_type_changed":
        values = {
            public: value
            for names, public in (
                (("OldGroupType", "old_group_type"), "old_group_type"),
                (("NewGroupType", "new_group_type"), "new_group_type"),
            )
            if (value := _security_event_change_text(event_data, *names)) is not None
        }
        return (
            {"state": "observed", "kind": kind, **values}
            if values else _security_event_partial_change(
                kind, "group_type_values_not_present",
            )
        )
    if kind == "audit_policy_changed":
        values = {
            public: value
            for names, public in (
                (("CategoryId", "audit_category_id"), "category_id"),
                (("SubcategoryId", "audit_subcategory_id"), "subcategory_id"),
                (("SubcategoryGuid", "audit_subcategory_guid"), "subcategory_guid"),
                (("AuditPolicyChanges", "audit_policy_changes"), "observed_value"),
            )
            if (value := _security_event_change_text(event_data, *names)) is not None
        }
        return (
            {"state": "observed", "kind": kind, **values}
            if values else _security_event_partial_change(
                kind, "audit_policy_fields_not_present",
            )
        )
    if kind == "security_log_cleared":
        cleared = _security_event_change_text(
            event_data, "Channel", "LogName", "cleared_log",
        )
        return {
            "state": "observed", "kind": kind,
            **({"observed_value": cleared} if cleared is not None else {}),
        }
    return None


def security_event_has_caller_computer(event_id: Any) -> bool:
    try:
        return int(event_id) == 4740
    except (TypeError, ValueError):
        return False


def security_event_family(event_id: Any) -> str | None:
    """Return the approved atomic-report family for one Windows Event ID."""

    try:
        return _SECURITY_EVENT_FAMILY_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def security_event_report_provider(event_id: Any) -> str | None:
    """Return the exact source provider accepted by the security report."""
    try:
        clean_event_id = int(event_id)
    except (TypeError, ValueError):
        return None
    if clean_event_id not in SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS:
        return None
    if clean_event_id == SECURITY_EVENTS_EVENTLOG_EVENT_ID:
        return SECURITY_EVENTS_REPORT_EVENTLOG_PROVIDER
    return SECURITY_EVENTS_REPORT_AUDITING_PROVIDER


def security_event_static_outcome(event_id: Any) -> str | None:
    """Return only an outcome proven by the event's documented identity."""

    try:
        return _SECURITY_EVENT_STATIC_OUTCOME_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None


def security_audit_outcome(keywords: Any) -> str | None:
    """Interpret only Windows' source-native audit success/failure keyword bits."""

    if keywords is None:
        return None
    if isinstance(keywords, (list, tuple, set, frozenset)):
        observed = {security_audit_outcome(value) for value in keywords}
        observed.discard(None)
        return next(iter(observed)) if len(observed) == 1 else None
    clean = str(keywords).strip().casefold()
    if not clean:
        return None
    if clean in SECURITY_AUDIT_SUCCESS_KEYWORDS or "auditsuccess" in clean.replace(" ", ""):
        return "success"
    if clean in SECURITY_AUDIT_FAILURE_KEYWORDS or "auditfailure" in clean.replace(" ", ""):
        return "failure"
    try:
        numeric = int(clean, 0)
    except ValueError:
        return None
    unsigned = numeric & ((1 << 64) - 1)
    success = bool(unsigned & 0x0020000000000000)
    failure = bool(unsigned & 0x0010000000000000)
    if success == failure:
        return None
    return "success" if success else "failure"


def security_event_ids_for_family(family: Any) -> frozenset[int]:
    """Return the exact approved atomic-report IDs for a source-owned family."""

    clean = str(family or "").strip().casefold()
    return frozenset(
        event_id for event_id, event_family in _SECURITY_EVENT_FAMILY_BY_EVENT_ID.items()
        if event_id in SECURITY_EVENTS_REPORT_EXPLICIT_QUERY_EVENT_IDS and event_family == clean
    )
