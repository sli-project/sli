"""Exact event hydration from the retained, imported agent packet; no source writes."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from server.sli.storage.event_source_representation import (
    packet_source_row,
    source_payload,
)


def verified_agent_event_payload(
    summary: Mapping[str, Any], packet: Mapping[str, Any],
) -> Mapping[str, Any]:
    return source_payload(summary, packet_source_row(summary, packet))
