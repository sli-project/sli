"""Turn source-native Event Log rows into packets without server imports."""
from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from server.sli.storage.xml_safety import parse_bounded_xml
from sli_collect.packets import make_packet

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def query_event_source(backend: Any, session: Any, channel: str, xpath: str) -> Any:
    flags = backend.EvtQueryChannelPath | backend.EvtQueryForwardDirection
    return backend.EvtQuery(channel, flags, xpath, session)


def render_event_source(backend: Any, event: Any) -> str:
    return backend.EvtRender(event, backend.EvtRenderEventXml)


def xml_text(root: ET.Element, path: str) -> str | None:
    item = root.find(path, NS)
    return item.text if item is not None else None


def xml_attr(root: ET.Element, path: str, attr: str) -> str | None:
    item = root.find(path, NS)
    return item.attrib.get(attr) if item is not None else None


def xml_int(root: ET.Element, path: str) -> int | None:
    value = xml_text(root, path)
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


MESSAGE_RENDERING_UNSUPPORTED = "message_rendering_not_supported"


def parse_event_xml(xml: str, *, source_name: str, connect_address: str, channel: str, collect_message: bool = False) -> dict[str, Any]:
    if collect_message:
        # Defence in depth: main() already refuses the run.  If a future caller
        # bypasses that guard we fail closed instead of returning empty messages.
        raise RuntimeError(
            f"{MESSAGE_RENDERING_UNSUPPORTED}: the Python backend cannot render provider messages"
        )
    root = parse_bounded_xml(xml)
    properties: list[Any] = []
    for item in root.findall(".//e:EventData/e:Data", NS):
        properties.append(item.text)
    provider = root.find(".//e:System/e:Provider", NS)
    time_created = root.find(".//e:System/e:TimeCreated", NS)
    security = root.find(".//e:System/e:Security", NS)
    return {
        "computer_name": source_name,
        "connect_address": connect_address,
        "channel": channel,
        "provider_name": provider.attrib.get("Name") if provider is not None else None,
        "event_id": xml_int(root, ".//e:System/e:EventID"),
        "version": xml_int(root, ".//e:System/e:Version"),
        "level": xml_int(root, ".//e:System/e:Level"),
        "task": xml_int(root, ".//e:System/e:Task"),
        "opcode": xml_int(root, ".//e:System/e:Opcode"),
        "keywords": xml_text(root, ".//e:System/e:Keywords"),
        "record_id": xml_int(root, ".//e:System/e:EventRecordID"),
        "time_created": time_created.attrib.get("SystemTime") if time_created is not None else None,
        "machine_name": xml_text(root, ".//e:System/e:Computer"),
        "user_id": security.attrib.get("UserID") if security is not None else None,
        # Provider message rendering is NOT implemented in the Python backend.
        # This value is always None by contract.  The previous expression
        # `None if not collect_message else None` looked conditional but returned
        # None on both branches, so a caller that requested rendered messages
        # silently received empty `events.message_text`.
        # main() now fails closed on collect_message=true, so a requested
        # message can never be dropped without an explicit error.
        "message": None,
        "properties": properties,
        "xml": xml,
    }




def event_packet(row: dict[str, Any], *, generation: str | None,
                 after_record_id: int | None) -> dict[str, Any]:
    return make_packet(
        source=row["computer_name"], channel=row["channel"], generation=generation,
        cursor={"after_record_id": after_record_id, "last_record_id": row.get("record_id")},
        records=[{"format": "event_xml", "record_id": row.get("record_id"), "payload": row}],
        # A single row cannot prove exhaustion of the frozen selector. The
        # channel's final declaration is published in its summary packet.
        continuity={"status": "not_proven"},
    )


def channel_summary_packet(*, source: str, summary: dict[str, Any]) -> dict[str, Any]:
    return make_packet(
        source=source, channel=summary["channel"],
        generation=summary["channel_generation_identity"],
        cursor={"after_record_id": summary["after_record_id"],
                "last_record_id": summary["batch_max_record_id"]},
        records=[], continuity=summary["continuity"],
    )
