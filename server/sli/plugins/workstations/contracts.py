"""Core adapters. All identity and access values are issued by the server."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True)
class Workstation:
    agent_key: str
    entity_id: int
    ad_computer_id: int | None = None

    def __post_init__(self):
        if (not isinstance(self.agent_key, str) or not self.agent_key.strip()
                or self.agent_key.strip() != self.agent_key or len(self.agent_key) > 256
                or type(self.entity_id) is not int or self.entity_id <= 0
                or (self.ad_computer_id is not None
                    and (type(self.ad_computer_id) is not int or self.ad_computer_id <= 0))):
            raise ValueError("workstation_identity_invalid")


class IdentityAdapter(Protocol):
    # TODO(stage 4): wrap core_identity.observe_entity with a stable agent-key
    # identifier, and its immutable optional AD association. Never join by name.
    def workstation(self, conn: Any, agent_key: str) -> Workstation: ...


class ReportScopeAdapter(Protocol):
    # Resolve the complete atomic grant (action + categories + scope), including
    # devices without AD enrichment; the reader rejects more than 500 keys.
    # Request parameters must never supply this adapter or its output.
    def agent_keys(self, access: Mapping[str, Any], report_key: str,
                   action: str, required_fields: frozenset[str]) -> Sequence[str]: ...


class QueueAdapter(Protocol):
    # TODO(stage 3): register these pinned declarations with the core queue's
    # allowlist/executor and wrap the bounded counts/continuation in the fenced
    # sli.core-job-result.v1 envelope. Registration never executes the handler.
    def register(self, *, manifest: Mapping[str, Any], handlers: Mapping[str, Any]) -> None: ...


class HistoryAdapter(Protocol):
    # Bound by storage.workstation_history to immutable CH write/readback.
    # Absence blocks expiration and preserves PostgreSQL evidence.
    # A returned hash is an acknowledged, durable, exact copy of the ENTIRE
    # observation (identity, full source XML and bounded facts), not an enqueue.
    def preserve(self, observation: Mapping[str, Any]) -> str: ...

    def read(self, *, keys: Sequence[str], family: str, start: datetime,
             end: datetime, cursor: str, limit: int,
             observation_id: str | None = None) -> Sequence[Mapping[str, Any]]: ...
