from __future__ import annotations

"""Read-only preflight for adding a Windows AD/DC source.

This module deliberately validates a proposed configuration only.  It does not
resolve DNS, contact a controller, write a configuration file, schedule a job,
or change the database.  Those actions remain an explicit operator step after
the plan is reviewed.
"""

from dataclasses import dataclass
import ipaddress
import re
from typing import Any, Mapping, Sequence

from server.source_packs.adapters import get_source_adapter
from server.source_packs.registry import get_source_pack


DC_SOURCE_PACK_ID = "sli.windows.ad-dc"
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")


@dataclass(frozen=True)
class OnboardingIssue:
    code: str
    message: str

    def public_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}


@dataclass(frozen=True)
class DcOnboardingPlan:
    hostname: str
    connect_address: str
    source_pack_id: str
    channels: tuple[str, ...]
    adapter_id: str
    valid: bool
    issues: tuple[OnboardingIssue, ...]

    def public_dict(self) -> dict[str, Any]:
        return {
            "api_version": "v1",
            "kind": "dc_onboarding_preflight",
            "valid": self.valid,
            "hostname": self.hostname,
            "connect_address": self.connect_address,
            "source_pack_id": self.source_pack_id,
            "channels": list(self.channels),
            "adapter_id": self.adapter_id,
            "network_actions": [],
            "database_actions": [],
            "collection_actions": [],
            "issues": [issue.public_dict() for issue in self.issues],
            "next_operator_action": (
                "Review the plan, then explicitly add the controller to the managed configuration."
                if self.valid
                else "Correct the configuration errors before any connectivity or collection check."
            ),
        }


def plan_dc_onboarding(
    candidate: Mapping[str, object],
    *,
    existing_hostnames: Sequence[str] = (),
) -> DcOnboardingPlan:
    """Validate one prospective AD/DC source without touching external state."""
    hostname = _clean(str(candidate.get("hostname") or candidate.get("name") or ""))
    connect_address = _clean(str(candidate.get("connect_address") or candidate.get("address") or candidate.get("ip") or hostname))
    source_pack_id = _clean(str(candidate.get("source_pack_id") or DC_SOURCE_PACK_ID))
    adapter_id = _clean(str(candidate.get("adapter_id") or "windows-eventlog-pywin32"))
    channels = _clean_channels(candidate.get("channels"))
    issues: list[OnboardingIssue] = []

    if not _is_valid_hostname(hostname):
        issues.append(OnboardingIssue("invalid_hostname", "hostname must be a DNS-safe logical controller name"))
    if not _is_valid_connect_address(connect_address):
        issues.append(OnboardingIssue("invalid_connect_address", "connect_address must be a hostname or IP address"))
    if hostname and hostname.casefold() in {str(value).strip().casefold() for value in existing_hostnames}:
        issues.append(OnboardingIssue("duplicate_hostname", "hostname is already configured"))

    pack = get_source_pack(source_pack_id)
    if pack is None:
        issues.append(OnboardingIssue("unknown_source_pack", "source_pack_id is not a bundled source pack"))
    else:
        allowed_channels = {value.casefold() for value in pack.channels}
        invalid_channels = [value for value in channels if value.casefold() not in allowed_channels]
        if invalid_channels:
            issues.append(OnboardingIssue("unsupported_channel", f"channels are not owned by {pack.pack_id}: {', '.join(invalid_channels)}"))
        if adapter_id not in pack.adapters:
            issues.append(OnboardingIssue("unsupported_adapter", f"adapter_id is not declared by {pack.pack_id}"))
    if get_source_adapter(adapter_id) is None:
        issues.append(OnboardingIssue("unknown_adapter", "adapter_id is not a bundled source adapter"))

    if not channels:
        issues.append(OnboardingIssue("missing_channels", "at least one explicitly selected channel is required"))

    return DcOnboardingPlan(
        hostname=hostname,
        connect_address=connect_address,
        source_pack_id=source_pack_id,
        channels=channels,
        adapter_id=adapter_id,
        valid=not issues,
        issues=tuple(issues),
    )


def _clean(value: str) -> str:
    return value.strip().lstrip("\\").rstrip(".")


def _clean_channels(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    result: list[str] = []
    seen: set[str] = set()
    for item in value:
        channel = _clean(str(item))
        if channel and channel.casefold() not in seen:
            result.append(channel)
            seen.add(channel.casefold())
    return tuple(result)


def _is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.fullmatch(value)) and not value.replace(".", "").isdigit()


def _is_valid_connect_address(value: str) -> bool:
    if not value or any(char in value for char in "\\/@:\\"):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(_HOSTNAME_RE.fullmatch(value))
