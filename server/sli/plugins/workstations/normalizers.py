"""Bounded Windows workstation projections using the single source owner."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from server.sli.plugins.workstations.contracts import Workstation
from server.sli.plugins.workstations.script_secrets import MASK_FAILED, mask_script_secrets
from server.source_packs.registry import resolve_source_normalizer

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_PROVIDER = "Microsoft-Windows-Windows Defender"
PNP_CHANNEL = "Microsoft-Windows-Kernel-PnP/Configuration"
PNP_PROVIDER = "Microsoft-Windows-Kernel-PnP"
DRIVER_CHANNEL = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
DRIVER_PROVIDER = "Microsoft-Windows-DriverFrameworks-UserMode"

SHARED_EVENTS = {
    4624: "logons", 4625: "logons", 4634: "logons", 4647: "logons",
    4688: "processes", 4697: "processes", 7045: "processes",
    **dict.fromkeys(range(4698, 4703), "processes"),
    4732: "protection", 4733: "protection", 4719: "protection",
}
TAMPER_IDENTITIES = {
    ("Security", "Microsoft-Windows-Eventlog", 1102): ("protection", "security.audit.cleared"),
    ("System", "Service Control Manager", 7036): ("protection", "service.state.changed"),
    ("System", "Service Control Manager", 7040): ("protection", "service.start_type.changed"),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104):
        ("protection", "powershell.script_block.observed"),
}
NEW_IDENTITIES = {
    ("Security", SECURITY_PROVIDER, 6416): ("usb", "device.external.observed"),
    **{(DEFENDER_CHANNEL, DEFENDER_PROVIDER, event_id):
       ("protection", "security.protection.disabled") for event_id in (5001, 5010, 5012)},
    **{(PNP_CHANNEL, PNP_PROVIDER, event_id):
       ("usb", "device.external.observed") for event_id in (400, 410, 420)},
    **{(DRIVER_CHANNEL, DRIVER_PROVIDER, event_id):
       ("usb", "device.external.observed") for event_id in (2003, 2100, 2101)},
}


def text(data: Mapping[str, Any], *keys: str, limit: int = 512) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip() and value.strip() != "-":
            return value.strip()[:limit]
    return None


def new_projection(*, event_id: Any, channel: str | None, provider: str | None,
                   event_data: Mapping[str, Any], source_host: str | None = None,
                   **_kwargs: Any) -> dict[str, Any]:
    try:
        identity = (str(channel or "").casefold(), str(provider or "").casefold(), int(event_id))
    except (TypeError, ValueError):
        return {}
    spec = next((value for key, value in {**NEW_IDENTITIES, **TAMPER_IDENTITIES}.items()
                 if (key[0].casefold(), key[1].casefold(), key[2]) == identity), None)
    if spec is None:
        return {}
    family, semantic_type = spec
    if family == "usb":
        device_id = text(event_data, "DeviceId", "DeviceInstanceId", "InstanceId", "DeviceInstanceID")
        device_class = text(event_data, "ClassId", "ClassGuid", "ClassName")
        # Enumeration alone is not proof of storage access. Restrict the
        # removable-storage report to source-native storage identifiers/classes.
        storage = bool(device_id and device_id.upper().startswith(("USBSTOR\\", "UASPSTOR\\"))) or bool(
            text(event_data, "Removable", "IsRemovable") in {"true", "1"}
            and
            device_class and device_class.casefold() in {
                "diskdrive", "volume", "{4d36e967-e325-11ce-bfc1-08002be10318}",
                "{71a27cdd-812a-11d0-bec7-08002be2092f}",
            }
        )
        if identity[0] != "security" and not storage:
            return {}
        facts = {"device_id": device_id, "device_class": device_class,
                 "device_location": text(event_data, "LocationInformation", "Location"),
                 "device_description": text(event_data, "DeviceDescription", "DeviceName"),
                 "storage_evidence": storage}
    elif identity[2] in (7036, 7040):
        facts = {"service_name": text(event_data, "ServiceName", "param4", "param1"),
                 "service_display_name": text(event_data, "param1", "ServiceName"),
                 "service_state": text(event_data, "State", "param2") if identity[2] == 7036 else None,
                 "start_type": text(event_data, "StartType", "param3") if identity[2] == 7040 else None,
                 "previous_start_type": text(event_data, "OldStartType", "param2") if identity[2] == 7040 else None}
    elif identity[2] == 4104:
        script = event_data.get("ScriptBlockText")
        masked, count, truncated = mask_script_secrets(script) if isinstance(script, str) else (None, 0, False)
        # Informational agent count; never use it to bypass server masking.
        agent_count = event_data.get("SecretsMasked")
        if (isinstance(agent_count, str) and agent_count.isascii() and agent_count.isdecimal()
                and len(agent_count) <= 4 and int(agent_count) <= 8192):
            count += int(agent_count)
        facts = {"script_block_text": masked, "secrets_masked": count,
                 "script_block_id": text(event_data, "ScriptBlockId"),
                 "script_block_text_truncated": event_data.get("ScriptBlockTextTruncated") == "true"
                     or truncated}
        if isinstance(masked, str) and masked.startswith(MASK_FAILED):
            facts["script_masking_failed"] = True
    elif identity[2] == 1102:
        facts = {"log_cleared": True}
    else:
        facts = {"protection_component": {5001: "real_time", 5010: "malware_scanning",
                                          5012: "virus_scanning"}[identity[2]]}
    return {"semantic_type": semantic_type, "roles": {"source_host": source_host} if source_host else {},
            "facts": {key: value for key, value in facts.items() if value is not None},
            "quality": {"raw_event_mutated": any(event_data.get(k) == "true" for k in
                        ("ScriptBlockTextTruncated", "CollectionFieldsTruncated"))
                        or identity[2] == 4104 and count > 0,
                        "observation_only": family == "usb"}}


def normalize(row: Mapping[str, Any], event_data: Mapping[str, Any], station: Workstation) -> dict[str, Any] | None:
    event_id = int(row["event_id"])
    channel, provider = row.get("channel"), row.get("provider_name")
    if event_id in SHARED_EVENTS:
        expected = ("System", "Service Control Manager") if event_id == 7045 else ("Security", SECURITY_PROVIDER)
        if (str(channel).casefold(), str(provider).casefold()) != tuple(value.casefold() for value in expected):
            return None
        # Only the built-in Administrators SID proves this particular group.
        # A workstation agent attestation establishes that this is a local SAM.
        if event_id in (4732, 4733) and text(event_data, "TargetSid") != "S-1-5-32-544":
            return None
        owner = resolve_source_normalizer(channel, provider, str(event_id))
        if owner is None:
            raise ValueError("workstation_shared_normalizer_unavailable")
        projection = owner.semantic_projection(
            event_id=event_id, channel=channel, provider=provider, event_data=event_data,
            correlation_id=None, source_host=station.agent_key, keywords=row.get("keywords"),
        )
        family = SHARED_EVENTS[event_id]
    else:
        projection = new_projection(event_id=event_id, channel=channel, provider=provider,
                                    event_data=event_data, source_host=station.agent_key)
        if not projection:
            return None
        family = next(spec[0] for key, spec in {**NEW_IDENTITIES, **TAMPER_IDENTITIES}.items()
                      if key[2] == event_id and key[0].casefold() == str(channel).casefold()
                      and key[1].casefold() == str(provider).casefold())
    if projection.get("semantic_type") in (None, "event.unknown"):
        raise ValueError("workstation_semantic_mapping_unavailable")
    facts = dict(projection.get("facts") or {})
    if event_id in (4624, 4625, 4634, 4647):
        facts["logon_type"] = text(event_data, "LogonType", limit=16)
    if event_id == 4624:
        # Target is the signed-in account; Subject is the actor, not its name.
        facts.update({key: text(event_data, native, limit=256) for key, native in (
            ("logon_user_name", "TargetUserName"), ("logon_user_domain", "TargetDomainName"),
            ("logon_user_sid", "TargetUserSid"),
        )})
    if event_id in (4732, 4733):
        # The member is the object of the change, never its initiator. Keep
        # native SIDs and display labels separate; a local SID is not an AD ref.
        facts.update({key: text(event_data, native) for key, native in (
            ("group_sid", "TargetSid"), ("member_sid", "MemberSid"),
            ("member_name", "MemberName"), ("actor_sid", "SubjectUserSid"),
            ("actor_name", "SubjectUserName"), ("actor_domain", "SubjectDomainName"),
        )})
    return {"agent_key": station.agent_key, "entity_id": station.entity_id,
            "ad_computer_id": station.ad_computer_id, "family": family,
            "semantic_type": projection["semantic_type"], "roles": dict(projection.get("roles") or {}),
            "facts": facts, "quality": {**(projection.get("quality") or {}),
                "ad_enrichment": "available" if station.ad_computer_id else "not_collected",
                "coverage": "not_proven"}}
