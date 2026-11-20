from __future__ import annotations

"""Windows AD/DC event facts extraction and correlation."""

import json
from collections.abc import Mapping
from typing import Any
from uuid import UUID

from server.sli.sources.process_identity_contract import (
    bounded_process_text,
    windows_process_id,
)

TASK_SCHEDULER_CHANNEL = "Microsoft-Windows-TaskScheduler/Operational"


_TASK_CORRELATION_FIELD_BY_EVENT_ID = {
    100: "InstanceId",
    102: "InstanceId",
    200: "TaskInstanceId",
    201: "TaskInstanceId",
}


_MESSAGE_SAMPLE_EVENT_KEYS = frozenset(
    {
        ("dns server", 5504),
        ("system", 101),
        ("system", 103),
        ("system", 108),
        ("system", 1112),
        ("microsoft-windows-taskscheduler/operational", 101),
        ("microsoft-windows-taskscheduler/operational", 108),
    }
)


_PRIVILEGED_GROUP_NAMES = frozenset(
    {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "администраторы домена",
        "администраторы предприятия",
        "администраторы схемы",
    }
)


AD_GROUP_MEMBERSHIP_EVENT_IDS = frozenset({4728, 4729, 4732, 4733, 4756, 4757})


def correlation_id_for_event(
    *,
    channel: str | None,
    event_id: Any,
    event_data: Mapping[str, Any],
) -> str | None:
    """Return a canonical correlation ID only for proven Windows event shapes.

    Task Scheduler emits UUIDs under two different field names.  Unknown
    channels, Event IDs, missing values and malformed UUIDs fail closed instead
    of copying arbitrary source data into the shared correlation column.
    """

    if str(channel or "").strip().casefold() != TASK_SCHEDULER_CHANNEL.casefold():
        return None
    try:
        field = _TASK_CORRELATION_FIELD_BY_EVENT_ID.get(int(event_id))
    except (TypeError, ValueError):
        return None
    if field is None:
        return None
    value = event_data.get(field)
    if value in (None, ""):
        return None
    try:
        return str(UUID(str(value).strip()))
    except (AttributeError, ValueError):
        return None


def retain_message_sample_for_event(
    *,
    channel: str | None,
    event_id: Any,
    provider_name: str | None,
) -> bool:
    """Decide whether a bounded message sample belongs in warm event facts.

    This preserves the accepted Windows behavior without teaching the generic
    Storage V2 mapper about Windows Event IDs.  The provider fallback is
    intentionally limited to the System stream owned by this source pack.
    """

    stream = str(channel or "").strip().casefold()
    try:
        numeric_event_id = int(event_id)
    except (TypeError, ValueError):
        return False
    if (stream, numeric_event_id) in _MESSAGE_SAMPLE_EVENT_KEYS:
        return True
    provider = str(provider_name or "").strip().casefold()
    return stream == "system" and (
        "group policy" in provider or "grouppolicy" in provider
    )


def logon_failure_result_code(event_data: Mapping[str, Any]) -> str | None:
    """Prefer a nonzero NTSTATUS substatus that refines a failed logon."""
    status = str(event_data.get("Status") or "").strip() or None
    substatus = str(event_data.get("SubStatus") or "").strip() or None
    if substatus:
        try:
            if 0 < int(substatus, 16) <= 0xFFFFFFFF:
                return substatus
        except ValueError:
            pass
    return status or substatus


def event_facts_for_event(
    *,
    row: Mapping[str, Any],
    event_data: Mapping[str, Any],
) -> dict[str, Any]:
    """Map Windows payload fields into the shared bounded warm-facts schema."""

    def pick(*keys: str, limit: int = 512) -> str | None:
        for key in keys:
            value = event_data.get(key)
            if value not in (None, ""):
                return str(value).strip()[:limit] or None
        return None

    def pick_exact(*keys: str, limit: int) -> str | None:
        for key in keys:
            value = event_data.get(key)
            if value not in (None, ""):
                text = str(value).strip()
                return text if text and len(text) <= limit else None
        return None

    def process_identity(*keys: str) -> str | None:
        """Canonicalize a source-native Windows PID without broad coercion."""
        for key in keys:
            if event_data.get(key) not in (None, ""):
                return windows_process_id(event_data[key])
        return None

    message_needed = retain_message_sample_for_event(
        channel=row.get("channel"),
        event_id=row.get("event_id"),
        provider_name=row.get("provider_name"),
    )
    message = str(row.get("message_text") or "").strip() if message_needed else ""
    stream = str(row.get("channel") or "").strip().casefold()
    provider = str(row.get("provider_name") or "").strip().casefold()
    try:
        numeric_event_id = int(row.get("event_id") or 0)
    except (TypeError, ValueError):
        numeric_event_id = 0
    is_powershell_operational = (
        stream == "microsoft-windows-powershell/operational"
        and provider == "microsoft-windows-powershell"
    )
    is_security_auditing = (
        stream == "security"
        and provider == "microsoft-windows-security-auditing"
    )
    powershell_command_name = (
        pick("CommandName", limit=512)
        if is_powershell_operational and numeric_event_id == 4103
        else None
    )
    powershell_user_name = (
        pick("User", "ConnectedUser", limit=512)
        if is_powershell_operational and numeric_event_id in {4103, 4104}
        else None
    )
    powershell_script_block_text = (
        pick("ScriptBlockText", limit=2048)
        if is_powershell_operational and numeric_event_id == 4104
        else None
    )
    powershell_process_id = (
        process_identity("SystemExecutionProcessId")
        if is_powershell_operational and numeric_event_id in {4103, 4104}
        else None
    )
    account_name_before = (
        pick("OldTargetUserName", limit=512)
        if is_security_auditing and numeric_event_id == 4781
        else None
    )
    account_name_after = (
        pick("NewTargetUserName", limit=512)
        if is_security_auditing and numeric_event_id == 4781
        else None
    )
    membership_member_name = (
        pick("MemberName", limit=512)
        if is_security_auditing and numeric_event_id in AD_GROUP_MEMBERSHIP_EVENT_IDS
        else None
    )
    membership_member_sid = (
        pick("MemberSid", limit=512)
        if is_security_auditing and numeric_event_id in AD_GROUP_MEMBERSHIP_EVENT_IDS
        else None
    )
    if membership_member_name == "-":
        membership_member_name = None
    if membership_member_sid == "-":
        membership_member_sid = None
    if is_security_auditing and numeric_event_id == 4688:
        process_name = bounded_process_text(
            event_data.get("NewProcessName"), "process_name"
        )
        process_id = process_identity("NewProcessId")
    elif is_security_auditing and numeric_event_id == 4689:
        process_name = bounded_process_text(
            event_data.get("ProcessName"), "process_name"
        )
        process_id = process_identity("ProcessId")
    else:
        process_name = bounded_process_text(
            event_data.get("ProcessName")
            or event_data.get("NewProcessName")
            or event_data.get("Application"),
            "process_name",
        )
        process_id = process_identity("ProcessId", "NewProcessId")
    process_scoped = is_security_auditing and numeric_event_id in {
        4688, 4689, 4697, 4698, 4699, 4700, 4701, 4702
    }
    result_code = pick("ResultCode", "Status", "SubStatus", limit=128)
    if numeric_event_id == 4625:
        result_code = pick("ResultCode", limit=128) or logon_failure_result_code(
            event_data
        )
        result_code = result_code[:128] if result_code else None
    facts = {
        "process_name": process_name,
        "process_id": process_id,
        "target_server_name": pick("TargetServerName", "TargetServer", limit=512),
        "service_name": pick_exact("ServiceName", limit=512) if numeric_event_id in {4697, 7045} else pick("ServiceName", limit=512),
        "task_name": pick_exact("TaskName", "TaskNamePath", limit=512) if numeric_event_id in {4698, 4699, 4700, 4701, 4702} else pick("TaskName", "TaskNamePath", limit=512),
        "task_action": pick(
            "Action",
            "ActionName",
            "TaskAction",
            "TaskContentNew",
            "TaskContent",
            limit=1024,
        ),
        "task_author": pick("Author", "TaskAuthor", limit=512),
        "run_as": pick("RunAs", "UserContext", "TaskUserName", limit=512),
        "logon_type": pick("LogonType", limit=64),
        "result_code": result_code,
        "object_name": pick("ObjectName", limit=512),
        "share_name": pick("ShareName", limit=512),
        "message_sample": message[:220] or None,
        "powershell_user_name": powershell_user_name,
        "powershell_command_name": powershell_command_name,
        "powershell_script_block_text": powershell_script_block_text,
        "powershell_process_id": powershell_process_id,
        "process_parent_id": process_identity("CreatorProcessId") if numeric_event_id == 4688 else None,
        "process_command_line": bounded_process_text(event_data.get("CommandLine"), "process_command_line") if numeric_event_id == 4688 else None,
        "process_user_sid": bounded_process_text(event_data.get("SubjectUserSid"), "process_user_sid") if process_scoped else None,
        "process_user_name": bounded_process_text(event_data.get("SubjectUserName"), "process_user_name") if process_scoped else None,
        "process_user_domain": bounded_process_text(event_data.get("SubjectDomainName"), "process_user_domain") if process_scoped else None,
        "process_logon_id": bounded_process_text(event_data.get("SubjectLogonId"), "process_logon_id") if process_scoped else None,
        "service_file": pick_exact("ServiceFileName", "ImagePath", limit=2048) if numeric_event_id in {4697, 7045} else None,
        "service_account": pick_exact("ServiceAccount", "AccountName", limit=512) if numeric_event_id in {4697, 7045} else None,
        "service_start_type": pick_exact("ServiceStartType", limit=128) if numeric_event_id in {4697, 7045} else None,
        "task_content": pick_exact("TaskContentNew", "TaskContent", limit=8192) if numeric_event_id in {4698, 4699, 4700, 4701, 4702} else None,
        "task_change": {4698: "created", 4699: "deleted", 4700: "enabled", 4701: "disabled", 4702: "updated"}.get(numeric_event_id),
        "native_process_id": process_identity("ClientProcessId") if numeric_event_id in {4697, 4698, 4699, 4700, 4701, 4702} else None,
    }
    # Storage V2 writes a fixed set of warm-fact columns.  Preserve the exact
    # pre-Stage-9 payload for every prior event and add source-native account
    # facts only to the newly catalogued rename observation.
    if is_security_auditing and numeric_event_id == 4781:
        facts.update(
            {
                "account_target_sid": pick("TargetSid", "TargetUserSid", limit=512),
                "account_target_name": pick(
                    "NewTargetUserName", "TargetUserName", limit=512
                ),
                "account_name_before": account_name_before,
                "account_name_after": account_name_after,
            }
        )
    if is_security_auditing and numeric_event_id in AD_GROUP_MEMBERSHIP_EVENT_IDS:
        facts.update(
            {
                "membership_member_sid": membership_member_sid,
                "membership_member_name": membership_member_name,
            }
        )
    return facts


def _parse_event_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(str(value))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _is_service_account(name: Any) -> bool:
    text = str(name or "").strip().casefold()
    if not text or text in {"-", "anonymous logon"}:
        return False
    account = text.rsplit("\\", 1)[-1]
    return (
        account.startswith("svc")
        or account.startswith("service")
        or account.endswith("$")
        or "service" in account
    )


def _is_privileged_group(name: Any) -> bool:
    text = str(name or "").strip().casefold()
    return bool(text) and any(group in text for group in _PRIVILEGED_GROUP_NAMES)
