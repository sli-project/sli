"""Versioned 4688 projection; no process joins, enrichment or text truncation."""
from __future__ import annotations

import re
from types import MappingProxyType

# Part of windows-fields.v2. Never infer integrity from TokenElevationType.
INTEGRITY_LEVELS = MappingProxyType({
    "S-1-16-0": "Untrusted", "S-1-16-4096": "Low", "S-1-16-8192": "Medium",
    "S-1-16-8448": "MediumPlus", "S-1-16-12288": "High",
    "S-1-16-16384": "System", "S-1-16-20480": "ProtectedProcess",
})
_UNSUPPORTED = ("OriginalFileName", "Description", "Product", "Company", "FileVersion",
                "Hashes", "CurrentDirectory", "ParentCommandLine", "ParentUser", "ProcessGuid", "ParentProcessGuid")
_DERIVED = ("Image", "ParentImage", "User", "UserSid", "LogonId", "LogonIdNumeric",
            "IntegrityLevel", "ParentProcessId", "CreatorProcessId", "NativeProcessId")


def _hex(value, bits):
    if not isinstance(value, str) or not re.fullmatch(r"0[xX][0-9a-fA-F]{1,16}", value):
        return None
    number = int(value, 16)
    return number if number < 2**bits else None


def _present(value):
    return isinstance(value, str) and bool(value.strip()) and value != "-"


def _sid(value):
    if not isinstance(value, str) or not re.fullmatch(r"S-1-[0-9]{1,15}(?:-[0-9]{1,10}){1,15}", value):
        return False
    parts = value.split("-")
    return int(parts[2]) < 2**48 and all(int(part) < 2**32 for part in parts[3:]) and value != "S-1-0-0"


def project_process_creation(values: dict, provenance: dict, version: int) -> dict[str, str]:
    """Project only native versioned fields, marking unknowns for the matcher.

    ProcessId in EventData is the creator PID; System/Execution is the emitter.
    Empty CommandLine remains distinguishable from absence, but cannot prove
    an argument-free launch. Consumers MUST honor unavailable before matching.
    """
    unavailable = {}
    for name in (*_DERIVED, *_UNSUPPORTED):
        values.pop(name, None)
        provenance.pop(name, None)
    unavailable.update(dict.fromkeys(_UNSUPPORTED, "not_in_4688"))

    def alias(destination, native):
        if _present(values.get(native)):
            values[destination] = values[native]
            provenance[destination] = provenance[native]
        else:
            unavailable[destination] = "native_field_missing"

    alias("Image", "NewProcessName")
    creator_pid = values.pop("ProcessId", None)
    creator_origin = provenance.pop("ProcessId", None)
    if creator_pid is not None:
        values["CreatorProcessId"] = creator_pid
        provenance["CreatorProcessId"] = creator_origin
    for destination, native, value, origin in (
        ("ProcessId", "NewProcessId", values.get("NewProcessId"), provenance.get("NewProcessId")),
        ("ParentProcessId", "CreatorProcessId", creator_pid, creator_origin),
    ):
        number = _hex(value, 32)
        if number is None:
            unavailable[destination] = "native_pid_invalid_or_missing"
        else:
            values[destination] = number
            provenance[destination] = f"{origin} ({native}: hex -> uint32)"

    if version < 1:
        values.pop("CommandLine", None)
        provenance.pop("CommandLine", None)
        unavailable["CommandLine"] = "not_in_event_version"
    elif not _present(values.get("CommandLine")):
        unavailable["CommandLine"] = "command_line_audit_not_proven"

    if version < 2:
        unavailable.update(ParentImage="not_in_event_version", IntegrityLevel="not_in_event_version")
    else:
        alias("ParentImage", "ParentProcessName")
        label = values.get("MandatoryLabel")
        if label in INTEGRITY_LEVELS:
            values["IntegrityLevel"] = INTEGRITY_LEVELS[label]
            provenance["IntegrityLevel"] = provenance["MandatoryLabel"] + " (MandatoryLabel SID table v1)"
        else:
            unavailable["IntegrityLevel"] = "mandatory_label_unknown"

    # A null target denotes the creator's context. A partially populated or
    # malformed target must never borrow the creator's name or logon ID.
    target_names = ("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId")
    null_target = (values.get("TargetUserSid") in (None, "", "-", "S-1-0-0")
                   and all(values.get(name) in (None, "", "-", "0x0") for name in target_names[1:]))
    prefix = "Target" if version == 2 and not null_target else "Subject"
    if not _sid(values.get(prefix + "UserSid")):
        unavailable.update(User="subject_context_invalid", UserSid="subject_context_invalid",
                           LogonId="subject_context_invalid", LogonIdNumeric="subject_context_invalid")
        return unavailable
    alias("UserSid", prefix + "UserSid")
    name, domain = prefix + "UserName", prefix + "DomainName"
    if _present(values.get(name)) and _present(values.get(domain)):
        values["User"] = values[domain] + "\\" + values[name]
        provenance["User"] = f"{provenance[domain]} + {provenance[name]} ({prefix} context)"
    else:
        unavailable["User"] = "subject_name_missing"
    logon = prefix + "LogonId"
    number = _hex(values.get(logon), 64)
    if number is None:
        unavailable.update(LogonId="native_logon_invalid_or_missing", LogonIdNumeric="native_logon_invalid_or_missing")
    else:
        alias("LogonId", logon)
        values["LogonIdNumeric"] = number
        provenance["LogonIdNumeric"] = provenance[logon] + " (hex -> uint64)"
    return unavailable
