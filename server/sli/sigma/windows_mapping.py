"""Map retained native XML, never rendered messages or bounded fact projections.

Named payload values remain native strings (including hex and %% resource IDs).
Missing fields stay absent; empty XML elements remain empty strings. Type-aware
Sigma comparisons and source quality gates belong to subsequent stages.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Mapping
from uuid import UUID
from xml.etree import ElementTree as ET

from server.sli.sigma.process_mapping import project_process_creation
from server.sli.storage.xml_safety import UnsafeXmlError, parse_bounded_xml

MAPPING_VERSION = "sli.sigma.windows-fields.v2"
IDENTITY_VERSION = "sli.sigma.windows-event.v1"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
AUDIT_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"
SCM_PROVIDER = "Service Control Manager"
_PROVIDER_GUIDS = {
    AUDIT_PROVIDER: "54849625-5478-4994-a5ba-3e3b0328c30d",
    EVENTLOG_PROVIDER: "fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148",
    SCM_PROVIDER: "555908d1-a6d7-4695-8e1e-26931d2012f4",
    "Microsoft-Windows-PowerShell": "a0c1853b-5c40-4b15-8766-3cf1c58f985a",
}
# Exact native versions for the Security/System and process_creation slice.
# New Kerberos v2: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
SUPPORTED_EVENT_VERSIONS = MappingProxyType({
    ("Security", EVENTLOG_PROVIDER, 1102): (0,),
    **{("Security", AUDIT_PROVIDER, event_id): versions for event_id, versions in (
        (4624, (0, 1, 2)), (4625, (0,)), (4688, (0, 1, 2)), (4697, (0,)), (4698, (0, 1)),
        (4702, (0, 1)), (4719, (0,)), (4720, (0,)), (4732, (0,)),
        (4768, (0, 2)), (4769, (0, 2)), (4776, (0,)), (4781, (0,)),
    )},
    ("System", SCM_PROVIDER, 7045): (0,),
    ("System", SCM_PROVIDER, 7036): (0,),
    ("System", SCM_PROVIDER, 7040): (0,),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", 4104): (1,),
})
_SCM_INSTALL_FIELDS = ("ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName")
_RESERVED = frozenset({
    "eventid", "provider_name", "provider_guid", "channel", "computer", "version",
    "eventrecordid", "timecreated", "processid", "threadid", "data",
    "message", "message_text", "renderedmessage", "rendered_message",
})
FieldValue = str | int | tuple[str, ...]


class SigmaMappingError(ValueError):
    """Fixed diagnostic codes only; never include event payloads."""


@dataclass(frozen=True, repr=False)
class EventScope:
    """Trusted reader scope; never derive these identifiers from host names."""

    installation_id: str
    source_instance_id: str
    source_generation: str

    def __post_init__(self) -> None:
        if any(not isinstance(value, str) or not value.strip() for value in (
            self.installation_id, self.source_instance_id, self.source_generation,
        )):
            raise SigmaMappingError("sigma_event_scope_invalid")


@dataclass(frozen=True, repr=False)
class EventIdentity:
    scope: EventScope
    channel: str
    provider_name: str
    provider_guid: str | None
    event_id: int
    event_version: int
    record_id: int
    computer: str
    occurred_at: str
    source_xml_sha256: str

    @property
    def key(self) -> str:
        """Content-bound identity, independent of packet/ingestion/mapping version.

        Record IDs alone collide after log resets and between sources/channels.
        Keep native timestamp precision; datetime would truncate 100 ns ticks.
        This is an adapter identity, not a fabricated core/WS EvidenceRef.
        """
        raw = json.dumps([IDENTITY_VERSION, asdict(self)], sort_keys=True,
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class MappedWindowsEvent:
    mapping_version: str
    identity: EventIdentity = field(repr=False)
    fields: Mapping[str, FieldValue] = field(repr=False)
    provenance: Mapping[str, str] = field(repr=False)
    unavailable: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}), repr=False)


def _one(parent: ET.Element, name: str, *, required: bool = True) -> ET.Element | None:
    nodes = parent.findall(f"{{{NS}}}{name}")
    if len(nodes) > 1 or required and not nodes:
        raise SigmaMappingError("sigma_event_structure_invalid")
    return nodes[0] if nodes else None


def _text(node: ET.Element | None) -> str:
    if node is None or len(node) or node.attrib.get("{http://www.w3.org/2001/XMLSchema-instance}nil"):
        raise SigmaMappingError("sigma_event_structure_invalid")
    return node.text or ""


def _integer(value: str | None, *, maximum: int) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,20}", value):
        raise SigmaMappingError("sigma_event_header_invalid")
    number = int(value)
    if number > maximum:
        raise SigmaMappingError("sigma_event_header_invalid")
    return number


def _payload(root: ET.Element, identity: EventIdentity) -> tuple[dict, dict]:
    data = _one(root, "EventData", required=False)
    user_data = _one(root, "UserData", required=False)
    values: dict[str, FieldValue] = {}
    provenance: dict[str, str] = {}
    if data is not None and user_data is not None:
        raise SigmaMappingError("sigma_event_payload_ambiguous")
    if user_data is not None:
        # Native 1102 does not use EventData. Do not flatten arbitrary UserData.
        log_ns = "http://manifests.microsoft.com/win/2004/08/windows/eventlog"
        if (identity.event_id != 1102 or len(user_data) != 1
                or user_data[0].tag != f"{{{log_ns}}}LogFileCleared"):
            raise SigmaMappingError("sigma_event_userdata_unsupported")
        nodes = list(user_data[0])
        if any(not node.tag.startswith(f"{{{log_ns}}}") for node in nodes):
            raise SigmaMappingError("sigma_event_userdata_unsupported")
        entries = [(node.tag.split("}", 1)[1], _text(node),
                    f"UserData/LogFileCleared/{node.tag.split('}', 1)[1]}") for node in nodes]
    elif data is not None:
        nodes = data.findall(f"{{{NS}}}Data")
        if any(node.tag not in {f"{{{NS}}}Data", f"{{{NS}}}Binary"} for node in data):
            raise SigmaMappingError("sigma_event_structure_invalid")
        named = [node.attrib.get("Name") for node in nodes]
        if any(named) and not all(named):
            raise SigmaMappingError("sigma_event_payload_ambiguous")
        if nodes and not any(named):
            # Positional aliases require this exact channel/provider/ID/version
            # and complete arity. Never infer Security fields from an index.
            if (identity.channel, identity.provider_name, identity.event_id, identity.event_version) != (
                "System", SCM_PROVIDER, 7045, 0,
            ) or len(nodes) != len(_SCM_INSTALL_FIELDS):
                raise SigmaMappingError("sigma_event_positional_unsupported")
            values["Data"] = tuple(_text(node) for node in nodes)
            provenance["Data"] = "EventData/Data[]"
            named = list(_SCM_INSTALL_FIELDS)
        entries = [(name, _text(node), f"EventData/Data[{index}]")
                   for index, (name, node) in enumerate(zip(named, nodes), 1)]
    else:
        entries = []
    seen = set()
    for name, value, origin in entries:
        if not name or name != name.strip() or name in seen:
            raise SigmaMappingError("sigma_event_payload_ambiguous")
        seen.add(name)
        if name.casefold() not in _RESERVED or identity.event_id == 4688 and name == "ProcessId":
            values[name] = value
            provenance[name] = origin
    return values, provenance


def map_windows_event(xml: str, *, scope: EventScope) -> MappedWindowsEvent:
    """Pure adapter over authorized retained XML; performs no IO or DB access.

    The reader must verify evidence integrity and authorization before calling.
    No row/property/message fallback is accepted if source XML is unavailable.
    """
    if not isinstance(xml, str) or not xml or not isinstance(scope, EventScope):
        raise SigmaMappingError("sigma_event_input_invalid")
    try:
        root = parse_bounded_xml(xml)
    except (ET.ParseError, UnsafeXmlError, UnicodeError):
        raise SigmaMappingError("sigma_event_xml_invalid") from None
    if root.tag != f"{{{NS}}}Event":
        raise SigmaMappingError("sigma_event_structure_invalid")
    system = _one(root, "System")
    channel = _text(_one(system, "Channel"))
    provider = _one(system, "Provider")
    provider_name = provider.attrib.get("Name")
    event_id = _integer(_text(_one(system, "EventID")), maximum=65535)
    version = _integer(_text(_one(system, "Version")), maximum=255)
    if version not in SUPPORTED_EVENT_VERSIONS.get((channel, provider_name, event_id), ()):
        raise SigmaMappingError("sigma_event_schema_unsupported")
    guid = provider.attrib.get("Guid")
    if guid is not None:
        try:
            guid = str(UUID(guid))
        except ValueError:
            raise SigmaMappingError("sigma_event_provider_invalid") from None
        if guid != _PROVIDER_GUIDS[provider_name]:
            raise SigmaMappingError("sigma_event_provider_invalid")
    record_id = _integer(_text(_one(system, "EventRecordID")), maximum=2**64 - 1)
    computer = _text(_one(system, "Computer"))
    occurred_at = _one(system, "TimeCreated").attrib.get("SystemTime")
    if (not record_id or not computer.strip() or not isinstance(occurred_at, str)
            or not re.fullmatch(r"[0-9]{4}(-[0-9]{2}){2}T[0-9]{2}(:[0-9]{2}){2}(\.[0-9]{1,9})?Z", occurred_at)):
        raise SigmaMappingError("sigma_event_header_invalid")
    try:
        # Python 3.10 accepts microseconds, Windows emits 100 ns precision.
        # Validate the date without changing the retained native identity.
        datetime.fromisoformat(re.sub(r"(\.\d{6})\d+(?=Z$)", r"\1", occurred_at).replace("Z", "+00:00"))
    except ValueError:
        raise SigmaMappingError("sigma_event_header_invalid") from None
    identity = EventIdentity(scope, channel, provider_name, guid, event_id, version,
                             record_id, computer, occurred_at, hashlib.sha256(xml.encode("utf-8")).hexdigest())
    values, provenance = _payload(root, identity)
    unavailable = project_process_creation(values, provenance, version) if event_id == 4688 else {}
    headers = {
        "EventID": event_id, "Version": version, "Provider_Name": provider_name,
        "Channel": channel, "Computer": computer, "EventRecordID": record_id,
        "TimeCreated": occurred_at,
    }
    values.update(headers)
    provenance.update({name: f"System/{name}" for name in headers})
    provenance["Provider_Name"] = "System/Provider/@Name"
    provenance["TimeCreated"] = "System/TimeCreated/@SystemTime"
    if guid is not None:
        values["Provider_Guid"] = guid
        provenance["Provider_Guid"] = "System/Provider/@Guid"
    execution = _one(system, "Execution", required=False)
    if execution is not None:
        for native, sigma in (("ProcessID", "ProcessId"), ("ThreadID", "ThreadId")):
            if event_id == 4688 and native == "ProcessID":
                sigma = "NativeProcessId"
            if native in execution.attrib:
                values[sigma] = _integer(execution.attrib[native], maximum=2**32 - 1)
                provenance[sigma] = f"System/Execution/@{native}"
    return MappedWindowsEvent(MAPPING_VERSION, identity, MappingProxyType(values), MappingProxyType(provenance),
                              MappingProxyType(unavailable))
