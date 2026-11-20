"""Dependency-free bounds for externally sourced Windows Event XML."""
from __future__ import annotations

from xml.etree import ElementTree as ET

MAX_EVENT_XML_BYTES = 4 * 1024 * 1024
MAX_EVENT_XML_DEPTH = 64
MAX_EVENT_XML_NODES = 100_000


class UnsafeXmlError(ValueError):
    pass


def parse_bounded_xml(
    xml_text: str, *, max_bytes: int = MAX_EVENT_XML_BYTES,
    max_depth: int = MAX_EVENT_XML_DEPTH, max_nodes: int = MAX_EVENT_XML_NODES,
) -> ET.Element:
    encoded = str(xml_text).encode("utf-8", errors="strict")
    if len(encoded) > int(max_bytes):
        raise UnsafeXmlError("xml_size_limit_exceeded")
    upper_xml = encoded.upper()
    if b"<!DOCTYPE" in upper_xml or b"<!ENTITY" in upper_xml:
        raise UnsafeXmlError("xml_dtd_or_entity_forbidden")
    root = ET.fromstring(encoded)
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > int(max_nodes):
            raise UnsafeXmlError("xml_node_limit_exceeded")
        if depth > int(max_depth):
            raise UnsafeXmlError("xml_depth_limit_exceeded")
        stack.extend((child, depth + 1) for child in node)
    return root
