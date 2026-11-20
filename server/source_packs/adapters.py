from __future__ import annotations

"""Reusable, non-plugin Source Adapter command contracts.

Adapters own only acquisition.  They return the same normalized JSONL contract
consumed by the core importer; they do not own storage, cursors, search or
authorization.  The first implementation deliberately wraps the two already
accepted Windows Event Log collectors instead of introducing a new runtime.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


WINDOWS_EVENTLOG_PYTHON = "windows-eventlog-pywin32"
WINDOWS_EVENTLOG_POWERSHELL = "windows-eventlog-powershell"
AD_CONTEXT_POWERSHELL = "ad-context-powershell"
_AD_CONTEXT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ad_context" / "Export-AdContextBundle.ps1"
_AD_AUDIT_CONTEXT_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "ad_context" / "Export-AdAuditContextBundle.ps1"
_POWERSHELL_EXECUTABLE_NAMES = frozenset({"powershell.exe", "pwsh", "pwsh.exe"})
_AD_SID_PATTERN = re.compile(r"^S-1-(?:\d+-){1,14}\d+$", re.IGNORECASE)
_AD_GROUP_REFERENCE_PATTERN = re.compile(r"^[^,\x00-\x1f]{1,128}$")
_AD_CONTEXT_SECTIONS = frozenset({
    "privileged_membership", "directory_accounts", "vpn_membership",
    "directory_group_graph", "directory_exact_logon",
    "gpo_governance", "domain_posture", "domain_health",
})
_AD_CONTEXT_PROFILES = {
    "privileged_membership": "privileged_membership_v1",
    "directory_accounts": "directory_security_v1",
    "directory_group_graph": "directory_group_graph_v1",
    "directory_exact_logon": "directory_exact_logon_v1",
    "vpn_membership": "vpn_security_v1",
    "gpo_governance": "gpo_governance_v4",
    "domain_posture": "domain_posture_v1",
    "domain_health": "domain_health_v1",
}


@dataclass(frozen=True)
class SourceAdapterDescriptor:
    """Declarative identity of one bundled acquisition adapter.

    It is deliberately not a plugin. A pack may reference only one of these
    built-in IDs; arbitrary code is never loaded from configuration.
    """

    adapter_id: str
    display_name: str
    transport: str
    output_contract: str

    def public_dict(self) -> dict[str, str]:
        return {
            "adapter_id": self.adapter_id,
            "display_name": self.display_name,
            "transport": self.transport,
            "output_contract": self.output_contract,
        }


_ADAPTERS: tuple[SourceAdapterDescriptor, ...] = (
    SourceAdapterDescriptor(
        adapter_id=WINDOWS_EVENTLOG_PYTHON,
        display_name="Windows Event Log via pywin32",
        transport="Windows Event Log RPC",
        output_contract="normalized-event-jsonl-v1",
    ),
    SourceAdapterDescriptor(
        adapter_id=WINDOWS_EVENTLOG_POWERSHELL,
        display_name="Windows Event Log via PowerShell",
        transport="Windows Event Log RPC",
        output_contract="normalized-event-jsonl-v1",
    ),
    SourceAdapterDescriptor(
        adapter_id=AD_CONTEXT_POWERSHELL,
        display_name="AD Context via repository-owned PowerShell",
        transport="Active Directory read-only cmdlets",
        output_contract="ad-context-bundle-v1",
    ),
)


def get_source_adapter(adapter_id: str) -> SourceAdapterDescriptor | None:
    """Resolve only a bundled adapter; unknown IDs are not executable."""
    wanted = str(adapter_id or "").strip()
    return next((adapter for adapter in _ADAPTERS if adapter.adapter_id == wanted), None)


def list_source_adapters() -> list[dict[str, str]]:
    return [adapter.public_dict() for adapter in _ADAPTERS]


@dataclass(frozen=True)
class BoundedWindowsEventLogSelection:
    event_ids: tuple[int, ...]
    start_time_utc: str
    end_time_utc: str


def parse_bounded_eventlog_selection(
    *,
    event_ids_json: str | None,
    start_time_utc: str | None,
    end_time_utc: str | None,
) -> BoundedWindowsEventLogSelection | None:
    values = (event_ids_json, start_time_utc, end_time_utc)
    if event_ids_json is None and end_time_utc is None:
        return None
    if any(value is None or not str(value).strip() for value in values):
        raise ValueError("bounded Event Log selection requires event IDs and explicit start/end UTC")
    try:
        loaded = json.loads(str(event_ids_json))
    except json.JSONDecodeError as exc:
        raise ValueError("bounded Event Log event ID allowlist must be valid JSON") from exc
    if not isinstance(loaded, list) or not 1 <= len(loaded) <= 64:
        raise ValueError("bounded Event Log event ID allowlist must contain 1..64 integers")
    if any(type(value) is not int or not 1 <= value <= 65535 for value in loaded):
        raise ValueError("bounded Event Log event IDs must be integers in range 1..65535")
    event_ids = tuple(loaded)
    if len(set(event_ids)) != len(event_ids):
        raise ValueError("bounded Event Log event IDs must be unique")

    def utc_value(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("bounded Event Log timestamps must be explicit UTC") from exc
        if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
            raise ValueError("bounded Event Log timestamps must be explicit UTC")
        return parsed.astimezone(timezone.utc)

    start = utc_value(str(start_time_utc))
    end = utc_value(str(end_time_utc))
    if start >= end:
        raise ValueError("bounded Event Log start/end UTC range must be increasing")

    return BoundedWindowsEventLogSelection(
        event_ids=event_ids,
        start_time_utc=start.isoformat(),
        end_time_utc=end.isoformat(),
    )


@dataclass(frozen=True)
class WindowsEventLogRequest:
    backend: str
    python_executable: str
    python_script: Path
    powershell_script: Path
    computer_name: str
    source_name: str
    hours: int
    max_events_per_channel: int
    channel_timeout_seconds: int
    output_root: Path
    channels: tuple[str, ...]
    collection_mode: str
    collect_message: bool
    channel_limits: dict[str, int]
    channel_timeouts: dict[str, int]
    start_time_utc: str | None
    channel_start_times: dict[str, str]
    channel_after_record_ids: dict[str, int]
    event_ids: tuple[int, ...] = ()
    end_time_utc: str | None = None
    channel_cursor_generations: dict[str, str] | None = None
    source_continuity_canary: bool = False
    nps_continuous: bool = False
    ad_source_credential_mode: str = "process"


@dataclass(frozen=True)
class AdContextRequest:
    powershell_executable: str
    output_path: Path
    run_id: str
    directory_server: str
    search_base: str
    domain: str
    sections: tuple[str, ...]
    collection_profile: str | None = None
    privileged_groups: tuple[str, ...] = ()
    vpn_groups: tuple[str, ...] = ()
    inactive_days: int = 180
    mode: str = "full"
    max_records: int = 2000
    max_bundle_bytes: int = 2 * 1024 * 1024
    max_directory_accounts: int = 2000
    max_directory_users: int | None = None
    max_directory_computers: int | None = None
    max_directory_groups: int = 10000
    max_directory_memberships: int = 35000
    max_vpn_members: int = 500
    max_gpos: int = 72
    technical_servers: tuple[str, ...] = ()
    technical_inventory_timeout_seconds: int = 20


def adapter_id_for_backend(backend: str) -> str:
    if backend == "python":
        return WINDOWS_EVENTLOG_PYTHON
    if backend == "powershell":
        return WINDOWS_EVENTLOG_POWERSHELL
    raise ValueError(f"unsupported Windows Event Log backend: {backend}")


def build_windows_eventlog_command(request: WindowsEventLogRequest) -> list[str]:
    """Build the established collector command without executing it."""
    from server.sli.sources.ad_source_auth import validate_ad_source_credential_mode

    mode = validate_ad_source_credential_mode(request.ad_source_credential_mode, backend=request.backend)
    if request.backend == "python":
        command = [
            request.python_executable,
            str(request.python_script),
            "--computer-name", request.computer_name,
            "--source-name", request.source_name,
            "--hours", str(request.hours),
            "--max-events-per-channel", str(request.max_events_per_channel),
            "--channel-timeout-seconds", str(request.channel_timeout_seconds),
            "--output-root", str(request.output_root),
            "--channels", ",".join(request.channels),
            "--collection-mode", request.collection_mode,
            "--collect-message", "true" if request.collect_message else "false",
        ]
        if mode != "process":
            command.extend(["--ad-source-credential-mode", mode])
        if request.channel_limits:
            command.extend(["--channel-limits-json", json.dumps(request.channel_limits, ensure_ascii=False)])
        if request.channel_timeouts:
            command.extend(["--channel-timeouts-json", json.dumps(request.channel_timeouts, ensure_ascii=False)])
        if request.start_time_utc:
            command.extend(["--start-time-utc", request.start_time_utc])
        if request.event_ids:
            command.extend(["--event-ids-json", json.dumps(request.event_ids, separators=(",", ":"))])
        if request.end_time_utc:
            command.extend(["--end-time-utc", request.end_time_utc])
        if request.source_continuity_canary:
            command.append("--source-continuity-canary")
        if request.nps_continuous:
            command.append("--nps-continuous")
        if request.channel_start_times:
            command.extend(["--channel-start-times-json", json.dumps(request.channel_start_times, ensure_ascii=False)])
        if request.channel_after_record_ids:
            command.extend(["--channel-after-record-ids-json", json.dumps(request.channel_after_record_ids, ensure_ascii=False)])
        if request.channel_cursor_generations:
            command.extend([
                "--channel-cursor-generations-json",
                json.dumps(request.channel_cursor_generations, ensure_ascii=False),
            ])
        return command

    if request.event_ids or request.end_time_utc or request.source_continuity_canary or request.nps_continuous:
        raise ValueError("bounded Windows Event Log selection requires the python backend")
    if request.backend != "powershell":
        raise ValueError(f"unsupported Windows Event Log backend: {request.backend}")
    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(request.powershell_script),
        "-ComputerName", request.computer_name,
        "-SourceName", request.source_name,
        "-Hours", str(request.hours),
        "-MaxEventsPerChannel", str(request.max_events_per_channel),
        "-ChannelTimeoutSeconds", str(request.channel_timeout_seconds),
        "-OutputRoot", str(request.output_root),
        f"-CollectMessage:${str(bool(request.collect_message)).lower()}",
        "-RequestedCollectionMode", request.collection_mode,
    ]
    if request.channels:
        # powershell.exe -File does not bind multiple native argv values to a
        # [string[]] parameter.  Only the first value belongs to -Channels and
        # the next one is treated as an unexpected positional argument.  Pass
        # one value and let the collector normalize its CSV channel contract.
        command.extend(["-Channels", ",".join(request.channels)])
    if request.channel_limits:
        command.extend(["-ChannelMaxEventsJson", json.dumps(request.channel_limits, ensure_ascii=False)])
    if request.channel_timeouts:
        command.extend(["-ChannelTimeoutSecondsJson", json.dumps(request.channel_timeouts, ensure_ascii=False)])
    if request.start_time_utc:
        command.extend(["-StartTimeUtc", request.start_time_utc])
    if request.channel_start_times:
        command.extend(["-ChannelStartTimesJson", json.dumps(request.channel_start_times, ensure_ascii=False)])
    if request.channel_after_record_ids:
        command.extend(["-ChannelAfterRecordIdsJson", json.dumps(request.channel_after_record_ids, ensure_ascii=False)])
    return command


def build_ad_context_command(request: AdContextRequest) -> list[str]:
    """Build the single allowlisted AD Context collector command.

    The script path is repository-owned and cannot be supplied by a manifest,
    configuration file or API request.  This function only builds argv; the
    caller remains responsible for a bounded subprocess deadline and process-
    tree termination.
    """
    executable = Path(str(request.powershell_executable or "").strip())
    if not executable.is_absolute() or executable.name.casefold() not in _POWERSHELL_EXECUTABLE_NAMES:
        raise ValueError("AD Context requires an absolute allowlisted PowerShell executable path")
    if not request.run_id.strip() or not request.directory_server.strip() or not request.search_base.strip() or not request.domain.strip():
        raise ValueError("AD Context run_id, directory_server, search_base and domain are required")
    if not 1 <= int(request.max_records) <= 50000:
        raise ValueError("AD Context max_records is out of bounds")
    if not 1024 <= int(request.max_bundle_bytes) <= 25 * 1024 * 1024:
        raise ValueError("AD Context max_bundle_bytes is out of bounds")
    if request.mode not in {"full", "targeted", "reconcile"}:
        raise ValueError("unsupported AD Context collection mode")
    sections = tuple(dict.fromkeys(str(value).strip() for value in request.sections if str(value).strip()))
    if not sections or any(value not in _AD_CONTEXT_SECTIONS for value in sections):
        raise ValueError("AD Context contains an unsupported collection section")
    unified_sections = (
        "directory_accounts",
        "directory_group_graph",
        "directory_exact_logon",
    )
    unified_profile = request.collection_profile == "ad_snapshot_base_v1"
    if unified_profile:
        if sections != unified_sections:
            raise ValueError("ad_snapshot_base_v1 requires the exact bounded section set")
    elif request.collection_profile is not None:
        raise ValueError("unsupported explicit AD Context collection profile")
    elif len(sections) != 1:
        raise ValueError("AD Context execution requires exactly one bounded section")
    groups = tuple(value.strip() for value in request.privileged_groups if value.strip())
    if "privileged_membership" in sections and (not groups or len(groups) > 10 or any(_AD_SID_PATTERN.fullmatch(value) is None for value in groups)):
        raise ValueError("AD Context requires one to ten exact privileged group SIDs")
    if "privileged_membership" not in sections and groups:
        raise ValueError("privileged groups require the privileged_membership section")
    vpn_groups = tuple(value.strip() for value in request.vpn_groups if value.strip())
    if "vpn_membership" in sections and (
        not vpn_groups or len(vpn_groups) > 10
        or any(_AD_GROUP_REFERENCE_PATTERN.fullmatch(value) is None for value in vpn_groups)
    ):
        raise ValueError("AD Context requires one to ten exact bounded VPN group references")
    if "vpn_membership" not in sections and vpn_groups:
        raise ValueError("VPN groups require the vpn_membership section")
    if not 1 <= int(request.inactive_days) <= 3650:
        raise ValueError("AD Context inactive_days is out of bounds")
    section_limits = {
        "max_directory_accounts": int(request.max_directory_accounts),
        "max_directory_groups": int(request.max_directory_groups),
        "max_directory_memberships": int(request.max_directory_memberships),
        "max_vpn_members": int(request.max_vpn_members),
        "max_gpos": int(request.max_gpos),
    }
    directory_user_limit = (
        int(request.max_directory_users)
        if request.max_directory_users is not None
        else int(request.max_directory_accounts) // 2
    )
    directory_computer_limit = (
        int(request.max_directory_computers)
        if request.max_directory_computers is not None
        else int(request.max_directory_accounts) - directory_user_limit
    )
    if "directory_accounts" in sections and (
        directory_user_limit < 1
        or directory_computer_limit < 1
        or directory_user_limit + directory_computer_limit > int(request.max_records)
    ):
        raise ValueError("AD Context independent directory limits exceed max_records")
    technical_servers = tuple(
        dict.fromkeys(value.strip() for value in request.technical_servers if value.strip())
    )
    if (
        len(technical_servers) > 50
        or any(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value) is None for value in technical_servers)
    ):
        raise ValueError("AD Context technical server inventory is out of bounds")
    if technical_servers and sections != ("directory_accounts",):
        raise ValueError("technical server inventory requires the directory_accounts section")
    if not 5 <= int(request.technical_inventory_timeout_seconds) <= 60:
        raise ValueError("technical inventory timeout must be between 5 and 60 seconds")
    relevant_limits = []
    if "directory_accounts" in sections:
        relevant_limits.append(section_limits["max_directory_accounts"])
    if "directory_group_graph" in sections:
        relevant_limits.extend((
            section_limits["max_directory_groups"],
            section_limits["max_directory_memberships"],
        ))
    if "directory_exact_logon" in sections:
        relevant_limits.append(directory_user_limit)
    if "vpn_membership" in sections:
        relevant_limits.append(section_limits["max_vpn_members"])
    if "gpo_governance" in sections:
        relevant_limits.append(section_limits["max_gpos"])
    if any(value < 1 or value > int(request.max_records) for value in relevant_limits):
        raise ValueError("AD Context section limit is out of bounds or exceeds max_records")
    if "gpo_governance" in sections and section_limits["max_gpos"] > 72:
        raise ValueError("GPO governance exceeds the proven 72-policy contract")
    script = (_AD_CONTEXT_SCRIPT if sections == ("privileged_membership",) else _AD_AUDIT_CONTEXT_SCRIPT).resolve()
    repository_root = Path(__file__).resolve().parents[2]
    if repository_root not in script.parents:
        raise ValueError("AD Context collector path escapes the repository")
    command = [
        str(executable),
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
        "-OutputPath",
        str(request.output_path),
        "-RunId",
        request.run_id,
        "-DirectoryServer",
        request.directory_server,
        "-SearchBase",
        request.search_base,
        "-Domain",
        request.domain,
        "-Sections",
        ",".join(sections),
        "-CollectionProfile",
        "ad_snapshot_base_v1" if unified_profile else _AD_CONTEXT_PROFILES[sections[0]],
        "-Mode",
        request.mode,
        "-PrivilegedGroups",
        ",".join(groups),
        "-MaxRecords",
        str(request.max_records),
        "-MaxBundleBytes",
        str(request.max_bundle_bytes),
    ]
    if sections != ("privileged_membership",):
        command.extend([
            "-VpnGroups", ",".join(vpn_groups),
            "-InactiveDays", str(int(request.inactive_days)),
            "-MaxDirectoryAccounts", str(section_limits["max_directory_accounts"]),
            "-MaxDirectoryUsers", str(directory_user_limit),
            "-MaxDirectoryComputers", str(directory_computer_limit),
            "-MaxDirectoryGroups", str(section_limits["max_directory_groups"]),
            "-MaxDirectoryMemberships", str(section_limits["max_directory_memberships"]),
            "-MaxVpnMembers", str(section_limits["max_vpn_members"]),
            "-MaxGpos", str(section_limits["max_gpos"]),
            "-TechnicalServers", ",".join(technical_servers),
            "-TechnicalInventoryTimeoutSeconds", str(int(request.technical_inventory_timeout_seconds)),
        ])
    return command
