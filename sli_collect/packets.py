"""Versioned, JSON-compatible acquisition boundary shared with server import."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

CONTRACT = "sli.collection-packet.v1"
FORMATS = frozenset({"event_xml", "accounting_line", "snapshot_json"})
# Keep the Security canary selector independent of server persistence helpers.
AUTHENTICATION_EVENT_KEYS = frozenset({4608, 4624, 4634, 4672})


def make_packet(*, source: str, channel: str, generation: str | None,
                cursor: dict[str, Any], records: list[dict[str, Any]],
                continuity: dict[str, Any], context: dict[str, Any] | None = None,
                observed_at: datetime | None = None) -> dict[str, Any]:
    ids = [item["record_id"] for item in records if item.get("record_id") is not None]
    packet = {
        "contract": CONTRACT,
        "header": {"source": source, "channel": channel, "generation": generation,
                   "record_id_range": {"first": min(ids) if ids else None,
                                       "last": max(ids) if ids else None},
                   "cursor": cursor,
                   "observed_at_utc": (observed_at or datetime.now(timezone.utc)).isoformat()},
        "records": records, "continuity": continuity, "context": context or {},
    }
    validate_packet(packet)
    return deepcopy(packet)


def validate_packet(packet: Any) -> dict[str, Any]:
    """Validate the envelope without installing a schema/DB library on the agent.

    Source-specific cursor and payload checks remain with the server importer.
    Errors contain only a fixed code, never source records.
    """
    def require(condition: bool) -> None:
        if not condition:
            raise ValueError("collection_packet_invalid")

    require(isinstance(packet, dict))
    require(set(packet) == {"contract", "header", "records", "continuity", "context"})
    require(packet["contract"] == CONTRACT)
    header = packet["header"]
    require(isinstance(header, dict))
    require(set(header) == {"source", "channel", "generation", "record_id_range", "cursor", "observed_at_utc"})
    for name in ("source", "channel", "observed_at_utc"):
        require(isinstance(header[name], str) and bool(header[name].strip()))
    require(header["generation"] is None or
            isinstance(header["generation"], str) and bool(header["generation"].strip()))
    try:
        observed = datetime.fromisoformat(header["observed_at_utc"].replace("Z", "+00:00"))
        require(observed.utcoffset() is not None and observed.utcoffset().total_seconds() == 0)
    except (ValueError, TypeError):
        raise ValueError("collection_packet_invalid") from None
    require(isinstance(header["cursor"], dict))
    require(isinstance(packet["context"], dict))
    continuity = packet["continuity"]
    require(isinstance(continuity, dict))
    require(isinstance(continuity.get("status"), str) and
            continuity["status"] in {"complete", "not_proven"})
    records = packet["records"]
    require(isinstance(records, list))
    ids = []
    for record in records:
        require(isinstance(record, dict))
        require(set(record) == {"format", "record_id", "payload"})
        require(isinstance(record["format"], str) and record["format"] in FORMATS)
        record_id = record["record_id"]
        require(record_id is None or type(record_id) is int and record_id >= 0)
        require(isinstance(record["payload"], str if record["format"] == "accounting_line" else dict))
        if record["format"] != "event_xml":
            require(record_id is None)
        else:
            require(isinstance(record["payload"].get("xml"), str))
            require(all(name in record["payload"] for name in ("computer_name", "channel")))
        if record_id is not None:
            ids.append(record_id)
    bounds = header["record_id_range"]
    require(isinstance(bounds, dict) and set(bounds) == {"first", "last"})
    require(all(value is None or type(value) is int and value >= 0 for value in bounds.values()))
    require(bounds == {"first": min(ids) if ids else None,
                                          "last": max(ids) if ids else None})
    return packet
