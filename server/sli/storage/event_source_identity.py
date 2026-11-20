"""Versioned native identity and conservative representation comparison.

RU: транспорт не является событием; XML и свойства сверяются отдельно.
EN: transport is not event identity; XML and properties are checked separately.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping
from typing import Any

from server.sli.storage.storage_v2_models import parse_utc_timestamp
from server.sli.storage.xml_safety import parse_bounded_xml

IDENTITY_VERSION = 2
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
REASONS = {
    "event_identity_differs": ("Различаются данные идентичности события", "Event identity data differs"),
    "event_xml_differs": ("Различаются общие поля XML", "Shared XML fields differ"),
    "event_properties_differs": ("Различаются свойства события", "Event properties differ"),
    "event_representation_incomparable": ("Представления не вложены друг в друга", "Neither representation contains the other"),
    "event_representation_invalid": ("Некорректное представление события", "Invalid event representation"),
    "event_retained_source_unavailable": ("Нет проверенного исходного представления", "Verified retained source unavailable"),
    "event_retained_hash_differs": ("Нарушена связь с сохранённым хешем", "Retained hash binding differs"),
    "agent_projection_failed": ("Импорт не завершён; проверьте доступность и допуск", "Import incomplete; check availability and admission"),
    "agent_source_not_configured": ("Источник не настроен однозначно", "Source is not uniquely configured"),
}


class RepresentationConflict(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def legacy_event_hash(row: Mapping[str, Any]) -> str:
    """The exact v1 digest remains readable; never rewrite a retained digest."""
    return digest(dict(row))


def _xml(row):
    try:
        return parse_bounded_xml(row["xml"]) if row.get("xml") else None
    except (ValueError, TypeError, SyntaxError):
        raise RepresentationConflict("event_representation_invalid") from None


def canonical_identity(row: Mapping[str, Any]) -> dict:
    root = _xml(row)
    system = root.find(NS + "System") if root is not None else None

    def native(tag, attr=None):
        element = system.find(NS + tag) if system is not None else None
        return (element.get(attr) if attr else element.text) if element is not None else None

    values = {}
    for field, tag, attr in (
        ("record_id", "EventRecordID", None), ("event_id", "EventID", None),
        ("version", "Version", None), ("level", "Level", None), ("task", "Task", None),
        ("opcode", "Opcode", None), ("keywords", "Keywords", None),
        ("provider_name", "Provider", "Name"), ("provider_guid", "Provider", "Guid"),
        ("time_created", "TimeCreated", "SystemTime"), ("channel", "Channel", None),
        ("user_id", "Security", "UserID"), ("machine_name", "Computer", None),
    ):
        xml_value = native(tag, attr)
        value = row.get(field)
        if field == "machine_name":
            value = value or xml_value or row.get("computer_name")

        def normalize(item, field=field):
            if item is None:
                return None
            if field in {"record_id", "event_id", "version", "level", "task", "opcode"}:
                return int(item)
            if field == "keywords":
                return int(str(item), 16) if str(item).lower().startswith("0x") else int(item)
            if field == "time_created":
                return parse_utc_timestamp(item).isoformat()
            if field in {"machine_name", "provider_guid"}:
                return str(item).casefold()
            return str(item)

        try:
            if value is not None and xml_value is not None and normalize(value) != normalize(xml_value):
                raise RepresentationConflict("event_identity_differs")
            values[field] = normalize(value if value is not None else xml_value)
        except (TypeError, ValueError) as exc:
            if isinstance(exc, RepresentationConflict):
                raise
            raise RepresentationConflict("event_representation_invalid") from None
    excluded = set(values) | {
        "xml", "properties", "message", "time_created_local", "computer_name",
        "connect_address", "transport_address", "collector_host", "collector_version",
        "collected_at", "collection_timestamp", "collection_id",
    }
    # Unknown fields fail conservatively instead of silently becoming transport.
    return {"version": IDENTITY_VERSION, "system": values,
            "extra": {key: value for key, value in row.items() if key not in excluded}}


def event_identity_hash(row: Mapping[str, Any]) -> str:
    return digest(canonical_identity(row))


def _xml_fields(root):
    """Flatten attributes/text by named path; keep duplicate multiplicity."""
    result = {}

    def visit(node, path):
        counts = Counter()
        for child in node:
            name = (child.tag, child.get("Name"))
            index = counts[name]
            counts[name] += 1
            visit(child, path + ((name, index),))
        for key, value in node.attrib.items():
            result[(path, "@" + key)] = value
        if node.text is not None and (not len(node) or node.text.strip()):
            result[(path, "text")] = node.text
        if node.tail and node.tail.strip():
            result[(path, "tail")] = node.tail

    if root is not None:
        visit(root, (((root.tag, root.get("Name")), 0),))
    return result


def _properties(row, root):
    properties = row.get("properties")
    if properties is None:
        return [], False
    if not isinstance(properties, list):
        raise RepresentationConflict("event_representation_invalid")
    # Named XML proves alignment even when a shortened collector selected a
    # non-prefix subset. Otherwise use a strict positional prefix comparison.
    data = list(root.findall(".//" + NS + "EventData/" + NS + "Data")) if root is not None else []

    def text(value):
        return "" if value is None else str(value)

    aligned = len(data) == len(properties) and all(
        text(item.text) == text(value) for item, value in zip(data, properties))
    return properties, aligned


def preferred_representation(retained: Mapping[str, Any], incoming: Mapping[str, Any]) -> dict:
    """Only a proven superset wins. Conflicting or complementary bodies fail."""
    if canonical_identity(retained) != canonical_identity(incoming):
        raise RepresentationConflict("event_identity_differs")
    old_root, new_root = _xml(retained), _xml(incoming)
    old, new = _xml_fields(old_root), _xml_fields(new_root)
    if any(old[key] != new[key] for key in old.keys() & new.keys()):
        raise RepresentationConflict("event_xml_differs")
    (old_props, old_aligned), (new_props, new_aligned) = _properties(retained, old_root), _properties(incoming, new_root)
    if not (old_aligned and new_aligned):
        common = min(len(old_props), len(new_props))
        if old_props[:common] != new_props[:common]:
            raise RepresentationConflict("event_properties_differs")
    old_size, new_size = len(old_props), len(new_props)
    old_contains = new.keys() <= old.keys() and old_size >= new_size
    new_contains = old.keys() <= new.keys() and new_size >= old_size
    if old_contains:
        return dict(retained)
    if new_contains:
        return dict(incoming)
    raise RepresentationConflict("event_representation_incomparable")
