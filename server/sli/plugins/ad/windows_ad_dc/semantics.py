from __future__ import annotations

"""Windows AD/DC semantic projection, event identities and core role filters."""

import re
from collections.abc import Mapping
from typing import Any

from server.sli.entities.identity_resolution import (
    СОСТОЯНИЕ_ВНЕШНИЙ,
    СОСТОЯНИЕ_РАЗРЕШЕНО,
    Опознание,
    разрешить_субъект,
)
from server.sli.sources.process_identity_contract import (
    bounded_process_text,
    bounded_process_text_state,
    windows_process_id,
)
from server.sli.plugins.ad.windows_ad_dc.catalog import (
    security_audit_outcome,
    security_event_observed_change,
    security_event_report_provider,
)
from server.sli.plugins.ad.windows_ad_dc.facts import logon_failure_result_code

_SEMANTIC_DOMAIN_SID = re.compile(r"^S-1-5-21-\d+-\d+-\d+-\d+$", re.IGNORECASE)


def semantic_event_identities(
    semantic_types: tuple[str, ...],
) -> tuple["SemanticEventIdentity", ...]:
    """Compile exact Windows descriptors for source-neutral semantic types.

    The semantic projection remains the single mapping authority.  This
    resolver probes accepted catalogue identities rather than maintaining a
    second Event ID taxonomy for dispatch hydration.
    """

    from server.sli.events.event_catalog import (
        all_event_catalog_entries,
        event_noise_classification,
    )
    from server.source_packs.contracts import SemanticEventIdentity

    wanted = {str(value).strip() for value in semantic_types if str(value).strip()}
    if not wanted:
        return ()
    identities: list[SemanticEventIdentity] = []
    for entry in all_event_catalog_entries():
        if str(entry.get("source") or "").strip() != "sli.windows.ad-dc":
            continue
        try:
            event_id = int(entry["event_key"])
        except (KeyError, TypeError, ValueError):
            continue
        stream = str(entry.get("stream") or "").strip()
        provider = str(entry.get("provider_name") or "").strip()
        projection = semantic_projection_for_event(
            event_id=event_id,
            channel=stream,
            provider=provider,
            event_data={},
            correlation_id=None,
            source_host="catalog-probe",
        )
        semantic_type = str(projection.get("semantic_type") or "")
        if semantic_type not in wanted:
            continue
        noise_class, catalog_version = event_noise_classification(
            event_id,
            stream,
            provider,
        )
        identities.append(
            SemanticEventIdentity(
                source="sli.windows.ad-dc",
                stream=stream,
                event_key=str(entry["event_key"]),
                provider_name=provider,
                semantic_type=semantic_type,
                noise_class=noise_class,
                noise_catalog_version=catalog_version,
            )
        )
    return tuple(
        sorted(
            identities,
            key=lambda item: (
                item.semantic_type,
                item.stream.casefold(),
                item.provider_name.casefold(),
                item.event_key,
            ),
        )
    )


def semantic_core_role_filters(
    semantic_type: str,
    join_roles: tuple[str, ...],
    trigger_roles: Mapping[str, str],
) -> tuple["SemanticCoreRoleFilter", ...] | None:
    """Map semantic join roles to exact compact fields for Windows context."""

    from server.source_packs.contracts import SemanticCoreRoleFilter

    fields_by_type: dict[str, dict[str, tuple[str, str | None]]] = {
        "authentication.session.created": {
            "affected_entity": ("target_user_sid", "target_user_name"),
            "session_principal": ("logon_id", None),
            "source_ip": ("ip_address", None),
        },
        "authentication.explicit_credentials.used": {
            "actor": ("subject_user_sid", "subject_user_name"),
            "affected_entity": ("target_user_sid", "target_user_name"),
            "session_principal": ("logon_id", None),
            "source_ip": ("ip_address", None),
        },
        "authentication.privileged_session.created": {
            "actor": ("subject_user_sid", "subject_user_name"),
            "session_principal": ("logon_id", None),
            "source_ip": ("ip_address", None),
        },
    }
    declared = fields_by_type.get(str(semantic_type))
    if declared is None:
        return None
    filters: list[SemanticCoreRoleFilter] = []
    for role in join_roles:
        if role == "source_host":
            continue
        raw_value = str(trigger_roles.get(role) or "").strip()
        field_pair = declared.get(role)
        if not raw_value or field_pair is None:
            return None
        value = _semantic_core_identity_value(raw_value)
        if role == "session_principal":
            _source_host, separator, suffix = raw_value.partition(":")
            if not separator or not suffix:
                return None
            value = suffix
        filters.append(
            SemanticCoreRoleFilter(
                role=role,
                primary_field=field_pair[0],
                fallback_field=field_pair[1],
                value=value,
            )
        )
    return tuple(filters)


def _semantic_core_identity_value(value: str) -> str:
    """Translate a canonical ladder key back to its bounded source field."""

    prefix, separator, remainder = str(value).strip().partition(":")
    if not separator or prefix not in {"sid", "guid", "upn", "sam", "name"}:
        return str(value).strip()
    if prefix in {"sam", "sid"}:
        return remainder.rpartition(":")[2]
    return remainder


def semantic_projection_for_event(
    *,
    event_id: Any,
    channel: str | None,
    provider: str | None,
    event_data: Mapping[str, Any],
    correlation_id: str | None,
    source_host: str,
    identity_host: str | None = None,
    keywords: Any = None,
) -> dict[str, Any]:
    """Translate named Windows EventData into the source-neutral semantic shape."""
    try:
        windows_event_id = int(event_id)
    except (TypeError, ValueError):
        windows_event_id = 0
    if not _semantic_descriptor_matches(
        event_id=windows_event_id,
        channel=channel,
        provider=provider,
    ):
        return _unknown_semantic_projection(
            event_id=windows_event_id,
            channel=channel,
            provider=provider,
            correlation_id=correlation_id,
            source_host=source_host,
            reason="descriptor_identity_missing_or_mismatched",
        )
    data = event_data
    roles: dict[str, str] = {"source_host": source_host}
    actor_sid = _semantic_text(data, "SubjectUserSid")
    actor_identity = _semantic_account_identity(
        data,
        prefix="Subject",
        source_host=identity_host or source_host,
        name_fallbacks=("SubjectUser",),
    )
    actor = actor_identity.ключ or None
    target_sid = _semantic_text(data, "TargetUserSid")
    target_identity = _semantic_account_identity(
        data,
        prefix="Target",
        source_host=identity_host or source_host,
        name_fallbacks=("TargetUser",),
    )
    target = target_identity.ключ or None
    if windows_event_id == 4624:
        session_logon = _semantic_text(data, "TargetLogonId", "LogonId")
    elif windows_event_id == 4672:
        session_logon = _semantic_text(data, "SubjectLogonId", "LogonId")
    else:
        session_logon = _semantic_text(
            data,
            "SubjectLogonId",
            "TargetLogonId",
            "LogonId",
        )
    if actor:
        roles["actor"] = actor
    if target:
        roles["affected_entity"] = target
    if session_logon:
        roles["session_principal"] = (
            f"{source_host}:{str(session_logon).strip().casefold()}"
        )
    identity_roles: dict[str, dict[str, Any]] = {}
    if actor:
        identity_roles["actor"] = _semantic_identity_quality(actor_identity)
    if target:
        identity_roles["affected_entity"] = _semantic_identity_quality(
            target_identity
        )
    if session_logon:
        identity_roles["session_principal"] = {
            "key": roles["session_principal"],
            "state": "resolved",
            "step": "source_scoped_session",
            "provisional": False,
            "confidence": 1.0,
            "reason": None,
            "aliases": [],
            "rule": "source-host-plus-logon-id/v1",
        }
    source_ip = _semantic_text(
        data,
        "IpAddress",
        "ClientAddress",
        "SourceNetworkAddress",
    )
    if source_ip and source_ip not in {"-", "::1", "127.0.0.1"}:
        roles["source_ip"] = source_ip

    semantic_type = "event.unknown"
    facts: dict[str, Any] = {
        "windows_event_id": windows_event_id,
        "channel": channel,
        "provider": provider,
        "correlation_id": correlation_id,
    }
    process_quality: dict[str, str] = {}
    if windows_event_id in {4103, 4104}:
        semantic_type = (
            "powershell.module.fragment" if windows_event_id == 4103
            else "powershell.script_block.fragment"
        )
        facts.update({
            "native_process_id": _semantic_process_identity(data, "SystemExecutionProcessId"),
            "powershell_user_name": _semantic_bounded_text(data, "User", "ConnectedUser", limit=512),
            "powershell_command_name": _semantic_bounded_text(data, "CommandName", limit=512) if windows_event_id == 4103 else None,
            "powershell_script_block_text": _semantic_bounded_text(data, "ScriptBlockText", limit=2048) if windows_event_id == 4104 else None,
        })
    elif windows_event_id == 4608:
        semantic_type = "system.boot.boundary"
    elif windows_event_id in {4688, 4689}:
        semantic_type = "process.started.fragment" if windows_event_id == 4688 else "process.ended.fragment"
        process_id_name = "NewProcessId" if windows_event_id == 4688 else "ProcessId"
        process_quality["process_id_state"] = _semantic_process_state(data, process_id_name)
        if windows_event_id == 4688:
            process_quality["process_parent_id_state"] = _semantic_process_state(data, "CreatorProcessId")
            process_quality["process_command_line_state"] = bounded_process_text_state(
                data.get("CommandLine"), "process_command_line"
            )
        facts.update({
            "process_id": _semantic_process_identity(data, process_id_name),
            "process_name": bounded_process_text(
                data.get("NewProcessName" if windows_event_id == 4688 else "ProcessName"),
                "process_name",
            ),
            "process_parent_id": _semantic_process_identity(data, "CreatorProcessId") if windows_event_id == 4688 else None,
            "process_command_line": bounded_process_text(data.get("CommandLine"), "process_command_line") if windows_event_id == 4688 else None,
            "process_user_sid": bounded_process_text(data.get("SubjectUserSid"), "process_user_sid"),
            "process_user_name": bounded_process_text(data.get("SubjectUserName"), "process_user_name"),
            "process_user_domain": bounded_process_text(data.get("SubjectDomainName"), "process_user_domain"),
            "process_logon_id": bounded_process_text(data.get("SubjectLogonId"), "process_logon_id"),
        })
    elif windows_event_id == 4624:
        semantic_type = "authentication.session.created"
        facts["logon_type"] = _semantic_text(data, "LogonType")
    elif windows_event_id == 4634:
        semantic_type = "authentication.session.ended"
        facts["logon_type"] = _semantic_text(data, "LogonType")
    elif windows_event_id == 4647:
        semantic_type = "authentication.logout.requested"
        facts["lifecycle_role"] = "supplemental_logout_only"
    elif windows_event_id == 4625:
        semantic_type = "authentication.session.failed"
        failure_status = logon_failure_result_code(data)
        facts["failure_status"] = failure_status
        facts.update(_semantic_result_facts(failure_status))
    elif windows_event_id == 4720:
        semantic_type = "directory.account.created"
    elif windows_event_id == 4722:
        semantic_type = "directory.account.enabled"
    elif windows_event_id == 4723:
        audit_outcome = security_audit_outcome(keywords)
        result_code = _semantic_text(data, "Status", "ResultCode")
        facts.update({
            "result": audit_outcome or "unknown",
            "audit_outcome_state": "observed" if audit_outcome else "unknown",
            "audit_outcome": audit_outcome,
            "result_code": result_code,
            "result_code_state": "observed" if result_code else "unknown",
        })
        semantic_type = (
            "account.password.changed.succeeded"
            if audit_outcome == "success"
            else "account.password.change.attempted"
        )
    elif windows_event_id == 4724:
        audit_outcome = security_audit_outcome(keywords)
        result_code = _semantic_text(data, "Status", "ResultCode")
        facts.update({
            "result": audit_outcome or "unknown",
            "audit_outcome_state": "observed" if audit_outcome else "unknown",
            "audit_outcome": audit_outcome,
            "result_code": result_code,
            "result_code_state": "observed" if result_code else "unknown",
        })
        semantic_type = (
            "account.password.reset.succeeded"
            if audit_outcome == "success"
            else "account.password.reset.attempted"
        )
    elif windows_event_id == 4725:
        semantic_type = "directory.account.disabled"
    elif windows_event_id == 4726:
        semantic_type = "directory.account.deleted"
    elif windows_event_id == 4738:
        semantic_type = "directory.account.changed"
    elif windows_event_id == 4781:
        semantic_type = "directory.account.renamed"
        facts.update({
            "account_name_before": _semantic_text(data, "OldTargetUserName", "OldAccountName"),
            "account_name_after": _semantic_text(data, "NewTargetUserName", "NewAccountName"),
        })
    elif windows_event_id == 4740:
        semantic_type = "authentication.account.locked"
        facts["caller_computer"] = _semantic_text(
            data, "CallerComputerName", "CallerComputer",
        )
    elif windows_event_id == 4767:
        semantic_type = "authentication.account.unlocked"
    elif windows_event_id == 4672:
        semantic_type = "authentication.privileged_session.created"
        facts["privileges"] = _semantic_text(data, "PrivilegeList")
        facts["security_assertion"] = (
            "privileged_session_observed_not_privilege_escalation"
        )
    elif windows_event_id == 4648:
        semantic_type = "authentication.explicit_credentials.used"
        facts["security_assertion"] = (
            "explicit_credentials_observed_no_high_risk_by_default"
        )
    elif windows_event_id == 4768:
        semantic_type = "authentication.kerberos.tgt.requested"
        facts.update(_semantic_result_facts(_semantic_text(
            data, "Status", "ResultCode", "FailureCode", "ErrorCode"
        )))
    elif windows_event_id == 4769:
        semantic_type = "authentication.kerberos.service_ticket.requested"
        facts["service_name"] = _semantic_text(data, "ServiceName")
        facts.update(_semantic_result_facts(_semantic_text(
            data, "Status", "ResultCode", "FailureCode", "ErrorCode"
        )))
    elif windows_event_id == 4770:
        semantic_type = "authentication.kerberos.service_ticket.renewed"
        facts["service_name"] = _semantic_text(data, "ServiceName")
        facts.update(_semantic_result_facts(_semantic_text(
            data, "Status", "ResultCode", "FailureCode", "ErrorCode"
        )))
    elif windows_event_id == 4771:
        semantic_type = "authentication.kerberos.preauthentication.failed"
        facts.update(_semantic_result_facts(_semantic_text(
            data, "FailureCode", "Status", "ResultCode", "ErrorCode"
        )))
    elif windows_event_id == 4773:
        semantic_type = "authentication.kerberos.service_ticket.failed"
        facts["service_name"] = _semantic_text(data, "ServiceName")
        facts.update(_semantic_result_facts(_semantic_text(
            data, "FailureCode", "Status", "ResultCode", "ErrorCode"
        )))
    elif windows_event_id == 4776:
        semantic_type = "authentication.credentials.validated"
        facts["workstation"] = _semantic_text(data, "Workstation", "WorkstationName")
        facts.update(_semantic_result_facts(_semantic_text(
            data, "Status", "ResultCode", "FailureCode", "ErrorCode"
        )))
    elif windows_event_id == 4719:
        semantic_type = "audit.policy.changed"
        facts.update(
            {
                "audit_category_id": _semantic_text(data, "CategoryId"),
                "audit_subcategory_id": _semantic_text(data, "SubcategoryId"),
                "audit_subcategory_guid": _semantic_text(
                    data,
                    "SubcategoryGuid",
                ),
                "audit_policy_changes": _semantic_text(
                    data,
                    "AuditPolicyChanges",
                ),
                "subject_logon_id": _semantic_text(data, "SubjectLogonId"),
            }
        )
    elif windows_event_id in {4728, 4732, 4756, 4729, 4733, 4757}:
        added = windows_event_id in {4728, 4732, 4756}
        semantic_type = "group.member.added" if added else "group.member.removed"
        facts.update(
            {
                "change": "added" if added else "removed",
                "group_scope": {
                    4728: "global",
                    4729: "global",
                    4732: "local",
                    4733: "local",
                    4756: "universal",
                    4757: "universal",
                }[windows_event_id],
                "group": _semantic_text(
                    data,
                    "TargetSid",
                    "TargetUserName",
                    "GroupName",
                ),
                "member": _semantic_text(data, "MemberSid", "MemberName"),
            }
        )
        if facts["group"]:
            roles["container_entity"] = str(facts["group"])
        if facts["member"]:
            roles["target_entity"] = str(facts["member"])
    elif windows_event_id in {4727, 4730, 4737, 4731, 4734, 4735, 4754, 4755, 4758, 4764}:
        change = {
            4727: "created", 4730: "deleted", 4737: "changed",
            4731: "created", 4734: "deleted", 4735: "changed",
            4754: "created", 4755: "deleted", 4758: "changed",
            4764: "type_changed",
        }[windows_event_id]
        semantic_type = f"directory.group.{change}"
        facts.update({
            "change": change,
            "group_scope": {
                4727: "global", 4730: "global", 4737: "global",
                4731: "local", 4734: "local", 4735: "local",
                4754: "universal", 4755: "universal", 4758: "universal",
                4764: "universal",
            }[windows_event_id],
            "group": _semantic_text(data, "TargetSid", "TargetUserName", "GroupName"),
        })
        if facts["group"]:
            roles["container_entity"] = str(facts["group"])
    elif windows_event_id == 5136:
        semantic_type = "directory.attribute.changed.fragment"
        value = _semantic_text(data, "AttributeValue")
        operation = (
            _semantic_text(data, "OperationType", "Operation") or ""
        ).lower()
        object_identity = _semantic_text(data, "ObjectGUID", "ObjectDN")
        operation_correlation_id = (
            _semantic_text(
                data,
                "OpCorrelationID",
                "CorrelationId",
                "CorrelationID",
            )
            or correlation_id
        )
        facts.update(
            {
                "object": object_identity,
                "attribute": _semantic_text(data, "AttributeLDAPDisplayName"),
                "operation": operation,
                "operation_correlation_id": operation_correlation_id,
            }
        )
        if object_identity:
            roles["target_entity"] = object_identity
        if value and "delete" in operation:
            facts["removed_values"] = [value]
        elif value and "add" in operation:
            facts["added_values"] = [value]
        elif value:
            facts["observed_values"] = [value]
    elif windows_event_id == 4697:
        semantic_type = "service.installed.fragment"
        facts.update(
            {
                "service_name": _semantic_text(data, "ServiceName"),
                "service_file": _semantic_text(
                    data,
                    "ServiceFileName",
                    "ImagePath",
                ),
                "service_account": _semantic_text(
                    data,
                    "ServiceAccount",
                    "AccountName",
                ),
                "service_start_type": _semantic_text(data, "ServiceStartType"),
                "native_process_id": _semantic_process_identity(data, "ClientProcessId"),
                "process_user_sid": bounded_process_text(data.get("SubjectUserSid"), "process_user_sid"),
                "process_user_name": bounded_process_text(data.get("SubjectUserName"), "process_user_name"),
                "process_user_domain": bounded_process_text(data.get("SubjectDomainName"), "process_user_domain"),
                "process_logon_id": bounded_process_text(data.get("SubjectLogonId"), "process_logon_id"),
            }
        )
        if facts["service_name"]:
            roles["target_entity"] = str(facts["service_name"])
    elif windows_event_id == 7045:
        semantic_type = "service.installed.fragment"
        facts.update(
            {
                "service_name": _semantic_text(data, "ServiceName"),
                "service_file": _semantic_text(data, "ServiceFileName", "ImagePath"),
                "service_account": _semantic_text(data, "ServiceAccount", "AccountName"),
                "service_start_type": _semantic_text(data, "ServiceStartType"),
            }
        )
        if facts["service_name"]:
            roles["target_entity"] = str(facts["service_name"])
    elif windows_event_id in {4698, 4699, 4700, 4701, 4702}:
        change = {4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}[windows_event_id]
        semantic_type = f"scheduled_task.{change}.fragment"
        facts.update({
            "task_name": _semantic_text(data, "TaskName", "TaskNamePath"),
            "task_content": _semantic_bounded_text(data, "TaskContentNew", "TaskContent", limit=8192),
            "task_change": change,
            "native_process_id": _semantic_process_identity(data, "ClientProcessId"),
            "process_user_sid": bounded_process_text(data.get("SubjectUserSid"), "process_user_sid"),
            "process_user_name": bounded_process_text(data.get("SubjectUserName"), "process_user_name"),
            "process_user_domain": bounded_process_text(data.get("SubjectDomainName"), "process_user_domain"),
            "process_logon_id": bounded_process_text(data.get("SubjectLogonId"), "process_logon_id"),
        })
        if facts["task_name"]:
            roles["target_entity"] = str(facts["task_name"])
    elif (
        windows_event_id == 106
        and str(channel or "").strip().casefold()
        == "microsoft-windows-taskscheduler/operational"
    ):
        semantic_type = "scheduled_task.created.fragment"
        facts.update(
            {
                "task_name": _semantic_text(data, "TaskName"),
                "task_instance_id": _semantic_text(
                    data, "TaskInstanceId", "InstanceId"
                ),
                "task_user_context": _semantic_text(
                    data, "UserContext", "UserName"
                ),
            }
        )
        if facts["task_name"]:
            roles["target_entity"] = str(facts["task_name"])
    elif (
        windows_event_id == 1102
        and str(provider or "").strip().casefold()
        == "microsoft-windows-eventlog"
        and str(channel or "").strip().casefold() == "security"
    ) or (
        windows_event_id == 104
        and str(provider or "").strip().casefold()
        == "microsoft-windows-eventlog"
        and str(channel or "").strip().casefold() == "system"
    ):
        semantic_type = "eventlog.cleared.fragment"
        cleared_log = _semantic_text(data, "Channel", "LogName", "ChannelName")
        if windows_event_id == 1102 and not cleared_log:
            cleared_log = "Security"
        facts["cleared_log"] = cleared_log

    observed_change = security_event_observed_change(windows_event_id, data)
    if observed_change is not None:
        facts["observed_change"] = observed_change

    relation_quality: dict[str, dict[str, str]] = {}
    if windows_event_id in {4624, 4720, 4724, 4740, 4767}:
        account_sid_field = (
            "TargetUserSid" if windows_event_id == 4624 else "TargetSid"
        )
        account_sid = _semantic_exact_domain_sid(data, account_sid_field)
        relation_quality["relation_account_identity"] = {
            "state": "exact" if account_sid is not None else "not_exact",
            "sid_field": account_sid_field,
        }
        if account_sid is not None:
            facts["relation_account_sid"] = account_sid
    if windows_event_id in {4728, 4732, 4756, 4729, 4733, 4757}:
        member_sid = _semantic_exact_domain_sid(data, "MemberSid")
        group_sid = _semantic_exact_domain_sid(data, "TargetSid")
        relation_quality["relation_membership_identity"] = {
            "state": (
                "exact" if member_sid is not None and group_sid is not None
                else "not_exact"
            ),
            "member_sid_field": "MemberSid",
            "group_sid_field": "TargetSid",
        }
        if member_sid is not None and group_sid is not None:
            facts["relation_member_sid"] = member_sid
            facts["relation_group_sid"] = group_sid

    return {
        "semantic_type": semantic_type,
        "roles": roles,
        "facts": {key: value for key, value in facts.items() if value is not None},
        "quality": {
            "event_data_encoding": "named",
            "catalog_independent": True,
            "raw_event_mutated": False,
            "missing_actor_sid": actor_sid is None,
            "unresolved_actor": (
                actor is not None
                and actor_identity.состояние
                not in {СОСТОЯНИЕ_РАЗРЕШЕНО, СОСТОЯНИЕ_ВНЕШНИЙ}
            ),
            "unresolved_target": (
                target is not None
                and target_identity.состояние
                not in {СОСТОЯНИЕ_РАЗРЕШЕНО, СОСТОЯНИЕ_ВНЕШНИЙ}
            ),
            "missing_source_ip": "source_ip" not in roles,
            "unknown_event_mapping": semantic_type == "event.unknown",
            "semantic_mapping_status": (
                "defined_but_not_emitted"
                if windows_event_id == 4772
                else "mapped"
                if semantic_type != "event.unknown"
                else "accepted_descriptor_without_semantic_projection"
            ),
            "defined_but_not_emitted": windows_event_id == 4772,
            **relation_quality,
            **process_quality,
            "identity_roles": identity_roles,
            "provisional_identity_roles": sorted(
                role
                for role, identity in identity_roles.items()
                if bool(identity.get("provisional"))
            ),
            "unresolved_identity_roles": sorted(
                role
                for role, identity in identity_roles.items()
                if identity.get("state") == "unresolved"
            ),
        },
    }


def _semantic_descriptor_matches(
    *,
    event_id: int,
    channel: str | None,
    provider: str | None,
) -> bool:
    """Require the canonical descriptor identity before applying a mapping.

    The local import avoids a module-import cycle: the catalogue resolves its
    path through the source-pack registry, while this pack owns the projection.
    Runtime meaning remains fail-closed if a donor mapping exists in code but
    its descriptor has not been accepted.
    """

    from server.sli.events.event_catalog import lookup_semantic_event_descriptor

    descriptor = lookup_semantic_event_descriptor(
        "sli.windows.ad-dc",
        str(channel or ""),
        str(event_id),
        provider,
    )
    if descriptor is not None:
        return True
    return (
        str(channel or "").strip().casefold() == "security"
        and security_event_report_provider(event_id) == str(provider or "").strip()
    )


def _unknown_semantic_projection(
    *,
    event_id: int,
    channel: str | None,
    provider: str | None,
    correlation_id: str | None,
    source_host: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "semantic_type": "event.unknown",
        "roles": {"source_host": source_host},
        "facts": {
            "windows_event_id": event_id,
            "channel": channel,
            "provider": provider,
            "correlation_id": correlation_id,
        },
        "quality": {
            "event_data_encoding": "named",
            "catalog_independent": False,
            "raw_event_mutated": False,
            "missing_actor_sid": True,
            "unresolved_actor": False,
            "unresolved_target": False,
            "missing_source_ip": True,
            "unknown_event_mapping": True,
            "semantic_mapping_status": reason,
            "identity_roles": {},
            "provisional_identity_roles": [],
            "unresolved_identity_roles": [],
        },
    }


def _semantic_account_identity(
    data: Mapping[str, Any],
    *,
    prefix: str,
    source_host: str,
    name_fallbacks: tuple[str, ...] = (),
) -> Опознание:
    """Resolve an account role only through the canonical identity ladder."""

    return разрешить_субъект(
        sid=_semantic_text(data, f"{prefix}UserSid", f"{prefix}Sid"),
        guid=_semantic_text(data, f"{prefix}UserGuid", f"{prefix}Guid"),
        upn=_semantic_text(
            data,
            f"{prefix}UserPrincipalName",
            f"{prefix}UPN",
        ),
        почта=_semantic_text(data, f"{prefix}Email", f"{prefix}Mail"),
        sam=_semantic_text(
            data,
            f"{prefix}UserName",
            *name_fallbacks,
        ),
        домен=_semantic_text(
            data,
            f"{prefix}DomainName",
            f"{prefix}UserDomain",
        ),
        узел=source_host,
    )


def _semantic_identity_quality(identity: Опознание) -> dict[str, Any]:
    return {
        "key": identity.ключ or None,
        "state": identity.состояние,
        "step": identity.ступень,
        "provisional": identity.временный,
        "confidence": identity.уверенность,
        "reason": identity.причина,
        "aliases": list(identity.псевдонимы),
        "rule": "identity-ladder/v1",
    }


def _semantic_text(data: Mapping[str, Any], *names: str) -> str | None:
    for name in names:
        value = data.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _semantic_exact_domain_sid(data: Mapping[str, Any], field: str) -> str | None:
    value = _semantic_text(data, field)
    if value is None or _SEMANTIC_DOMAIN_SID.fullmatch(value) is None:
        return None
    return value.upper()


def _semantic_result_facts(result_code: str | None) -> dict[str, str]:
    if result_code is None:
        return {"result_code_state": "unknown", "result": "unknown"}
    normalized = result_code.strip().casefold()
    return {
        "result_code": result_code,
        "result_code_state": "observed",
        "result": "success" if normalized in {"0", "0x0", "0x00000000", "00000000"} else "failure",
    }


def _semantic_bounded_text(
    data: Mapping[str, Any], *names: str, limit: int
) -> str | None:
    value = _semantic_text(data, *names)
    return value if value is not None and len(value.encode("utf-8")) <= limit else None


def _semantic_bounded_state(
    data: Mapping[str, Any], *names: str, limit: int
) -> str:
    value = _semantic_text(data, *names)
    if value is None:
        return "unknown_missing"
    return "exact" if len(value.encode("utf-8")) <= limit else "unknown_over_limit"


def _semantic_process_state(data: Mapping[str, Any], *names: str) -> str:
    value = _semantic_text(data, *names)
    if value is None or value == "-":
        return "unknown_missing"
    return "exact" if _semantic_process_identity(data, *names) is not None else "unknown_invalid"


def _semantic_process_identity(data: Mapping[str, Any], *names: str) -> str | None:
    raw = _semantic_text(data, *names)
    return windows_process_id(raw)
