from __future__ import annotations

"""Source-neutral normalization contracts shared by core and bundled packs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SemanticEventIdentity:
    """Exact source-owned identity for one normalized semantic type."""

    source: str
    stream: str
    event_key: str
    provider_name: str
    semantic_type: str
    noise_class: str
    noise_catalog_version: str


@dataclass(frozen=True)
class SemanticCoreRoleFilter:
    """Source-owned projection of one semantic join role onto compact core."""

    role: str
    primary_field: str
    fallback_field: str | None
    value: str


@dataclass(frozen=True)
class EventEntitySemantics:
    target_is_group: bool = False
    service_name_is_entity: bool = False
    target_server_is_entity: bool = False


@dataclass(frozen=True)
class EventStateSemantics:
    rule_id: str
    state_type: str
    status: str


@dataclass(frozen=True)
class AccountEventSemantics:
    label: str
    timeline_category: str
    severity: str


@dataclass(frozen=True)
class FindingRule:
    rule_code: str
    title: str
    severity: str
    why_it_matters: str
    recommendation: str


@dataclass(frozen=True)
class SecurityMonitorGroup:
    key: str
    label: str
    event_ids: tuple[int, ...]
    severity: str
    hint: str
    card_hint: str = ""
    check: str = ""
