"""FOUNDATION-1 semantic contracts, deliberately detached from runtime.

The module defines deterministic, replayable interpretations of persisted
Storage V2 events.  It does not enqueue work, mutate a database, create a
finding, or enable a worker.  Those operations require later gated phases.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from hashlib import sha256
import json
import os
from typing import Any, Mapping, Sequence

from server.sli.entities.identity_resolution import IDENTITY_RESOLUTION_VERSION
from server.sli.sources.process_identity_contract import process_episode_fields_valid
from server.source_packs.registry import resolve_source_normalizer
from server.sli.storage.storage_v2_models import parse_utc_timestamp


SEMANTIC_CONTRACT_VERSION = 1
NORMALIZER_ID = "windows.named-eventdata"
NORMALIZER_BASE_VERSION = "1.4"
NORMALIZER_VERSION = (
    f"{NORMALIZER_BASE_VERSION}+identity-{IDENTITY_RESOLUTION_VERSION}"
)
ASSEMBLER_ID = "semantic-action-assembler"
ASSEMBLER_VERSION = "1.1"
_INDEPENDENT_AUTHENTICATION_TYPES = frozenset({
    "authentication.session.created",
    "authentication.session.ended",
    "authentication.logout.requested",
    "authentication.session.failed",
    "authentication.explicit_credentials.used",
    "authentication.privileged_session.created",
    "authentication.kerberos.tgt.requested",
    "authentication.kerberos.service_ticket.requested",
    "authentication.kerberos.service_ticket.renewed",
    "authentication.kerberos.preauthentication.failed",
    "authentication.kerberos.service_ticket.failed",
    "authentication.credentials.validated",
    "remote_access.authentication.allowed",
    "remote_access.authentication.denied",
})
PROCESS_EPISODE_ASSEMBLER_ID = "process-episode-assembler"
PROCESS_EPISODE_ASSEMBLER_VERSION = "1.0"
CANONICAL_ACTION_STATUSES = frozenset({
    "observed",
    "partially_confirmed",
    "state_confirmed",
    "multi_source_confirmed",
    "contradicted",
})
CANONICAL_ENTITY_ROLES = frozenset({
    "actor",
    "session_principal",
    "affected_entity",
    "target_entity",
    "container_entity",
    "source_host",
    "source_ip",
})


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(value: Mapping[str, Any]) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _five_minute_bucket(value: datetime) -> str:
    value = value.astimezone(timezone.utc).replace(second=0, microsecond=0)
    return (value - timedelta(minutes=value.minute % 5)).isoformat()


def _identity_text(value: Any) -> str | None:
    text = str(value or "").strip()
    return text.casefold() if text else None


def _material_json(value: Mapping[str, Any]) -> str:
    return _canonical_json(value).decode("utf-8")


@dataclass(frozen=True)
class SemanticFeatureSettings:
    normalization_enabled: bool = False
    assembly_enabled: bool = False
    directory_state_enabled: bool = False
    correlation_enabled: bool = False
    risk_engine_enabled: bool = False
    finding_creation_enabled: bool = False

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "SemanticFeatureSettings":
        source = environ if environ is not None else os.environ

        def enabled(name: str) -> bool:
            return str(source.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}

        normalization = enabled("ADLOG_SEMANTIC_NORMALIZATION_ENABLED")
        assembly = normalization and enabled("ADLOG_SEMANTIC_ASSEMBLY_ENABLED")
        directory_state = assembly and enabled("ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED")
        correlation = assembly and enabled("ADLOG_SEMANTIC_CORRELATION_ENABLED")
        risk = correlation and enabled("ADLOG_SEMANTIC_RISK_ENGINE_ENABLED")
        findings = risk and enabled("ADLOG_SEMANTIC_FINDING_CREATION_ENABLED")
        return cls(normalization, assembly, directory_state, correlation, risk, findings)


@dataclass(frozen=True)
class StoredEvent:
    event_id: int
    windows_event_id: int
    channel: str
    server: str
    occurred_at_utc: datetime
    event_data: Mapping[str, Any]
    provider: str | None = None
    correlation_id: str | None = None
    source_host_id: int | str | None = None
    domain_id: int | str | None = None
    event_record_id: int | None = None
    source_event_sha256: str | None = None
    source_facts_sha256: str | None = None
    keywords: Any = None

    def __post_init__(self) -> None:
        if self.occurred_at_utc.tzinfo is None:
            raise ValueError("occurred_at_utc must be timezone-aware")
        if not isinstance(self.event_data, Mapping):
            raise ValueError("event_data must be named EventData mapping")


@dataclass(frozen=True)
class NormalizedEvent:
    source_event_id: int
    semantic_type: str
    occurred_at_utc: datetime
    roles: Mapping[str, str]
    facts: Mapping[str, Any]
    quality: Mapping[str, Any]
    semantic_sha256: str


def apply_identity_role_overrides(
    event: NormalizedEvent,
    overrides: Mapping[str, Mapping[str, str]],
) -> NormalizedEvent:
    """Apply only persisted R7 provisional→canonical identity mappings.

    The caller obtains ``overrides`` from the immutable merge registry.  A
    role is changed only when its quality metadata proves that the same key
    was provisional.  Missing or contradictory metadata fails closed instead
    of silently rewriting semantic evidence.
    """

    if not overrides:
        return event
    roles = dict(event.roles)
    quality = dict(event.quality)
    raw_identity_roles = quality.get("identity_roles")
    if not isinstance(raw_identity_roles, Mapping):
        raise ValueError("identity merge requires identity_roles metadata")
    identity_roles = {
        str(role): dict(value)
        for role, value in raw_identity_roles.items()
        if isinstance(value, Mapping)
    }
    applied: list[dict[str, str]] = []
    for role, source_key in sorted(roles.items()):
        override = overrides.get(str(source_key))
        if override is None:
            continue
        target_key = str(override.get("target_key") or "").strip()
        merge_id = str(override.get("merge_id") or "").strip()
        if not target_key or not merge_id or target_key == source_key:
            raise ValueError("identity merge override is incomplete or circular")
        metadata = identity_roles.get(role)
        if metadata is None:
            raise ValueError("identity merge role has no quality metadata")
        if str(metadata.get("key") or "") != source_key:
            raise ValueError("identity merge role key contradicts quality metadata")
        if metadata.get("state") != "provisional" or not bool(metadata.get("provisional")):
            raise ValueError("identity merge may replace only a provisional role")
        aliases = sorted({
            str(value) for value in metadata.get("aliases", []) if str(value).strip()
        } | {source_key})
        roles[role] = target_key
        identity_roles[role] = {
            **metadata,
            "key": target_key,
            "state": "resolved",
            "provisional": False,
            "confidence": 1.0,
            "reason": None,
            "aliases": aliases,
            "resolution_evidence": "identity_merge_r7",
            "identity_merge_id": merge_id,
        }
        applied.append({
            "role": role,
            "source_key": source_key,
            "target_key": target_key,
            "merge_id": merge_id,
        })
    if not applied:
        return event
    quality["identity_roles"] = identity_roles
    quality["provisional_identity_roles"] = sorted(
        role for role, value in identity_roles.items()
        if bool(value.get("provisional"))
    )
    quality["unresolved_identity_roles"] = sorted(
        role for role, value in identity_roles.items()
        if value.get("state") == "unresolved"
    )
    quality["identity_merge_replays"] = applied
    identity = {
        "source_event_id": event.source_event_id,
        "semantic_type": event.semantic_type,
        "roles": roles,
        "facts": dict(event.facts),
        "identity_resolution_version": IDENTITY_RESOLUTION_VERSION,
    }
    return NormalizedEvent(
        source_event_id=event.source_event_id,
        semantic_type=event.semantic_type,
        occurred_at_utc=event.occurred_at_utc,
        roles=roles,
        facts=dict(event.facts),
        quality=quality,
        semantic_sha256=_digest(identity),
    )


@dataclass(frozen=True)
class CanonicalAction:
    action_kind: str
    status: str
    occurred_at_utc: datetime
    contribution_key: str
    source_event_ids: tuple[int, ...]
    attributes: Mapping[str, Any]
    action_sha256: str = ""

    @property
    def canonical_deduplication_key(self) -> str:
        """Stable action identity; retained ``contribution_key`` is a schema alias.

        Risk contributions are deliberately not created by this foundation.
        A later risk engine must derive its own contribution key from the
        canonical action identity instead of from the evidence set.
        """
        return self.contribution_key


@dataclass(frozen=True)
class SemanticShadowResult:
    """A no-write result suitable for a future outbox worker's shadow audit."""

    normalized: NormalizedEvent | None
    actions: tuple[CanonicalAction, ...]
    skipped_reason: str | None = None


@dataclass(frozen=True)
class ProcessEpisode:
    episode_id: str
    process_id: int
    domain_id: str
    source_host_id: str
    display_host: str
    boot_event_id: int
    start_event_id: int
    started_at_utc: datetime
    end_event_id: int | None
    confirmed_end_at_utc: datetime | None
    process_name: str | None
    command_line: str | None
    user_sid: str | None
    user_name: str | None
    user_domain: str | None
    logon_id: str | None
    parent_process_id: int | None
    parent_episode_id: str | None
    completeness_state: str
    confirmation_state: str
    ordering_state: str
    evidence_event_ids: tuple[int, ...]
    assembler_id: str = PROCESS_EPISODE_ASSEMBLER_ID
    assembler_version: str = PROCESS_EPISODE_ASSEMBLER_VERSION


@dataclass(frozen=True)
class ProcessAssemblyResult:
    episodes: tuple[ProcessEpisode, ...]
    standalone_evidence_ids: tuple[int, ...]


def stored_event_from_source_payload(source: Mapping[str, Any]) -> StoredEvent:
    """Build the deterministic semantic input from one verified archive row."""

    raw_event_data = source.get("event_data_json")
    if isinstance(raw_event_data, Mapping):
        event_data = dict(raw_event_data)
    else:
        event_data = json.loads(str(raw_event_data or "{}"))
        if not isinstance(event_data, Mapping):
            raise ValueError("event_data_json must contain a named object")
        event_data = dict(event_data)
    return StoredEvent(
        event_id=int(source["id"]),
        windows_event_id=int(source["event_id"]),
        channel=str(source["channel"]),
        server=str(source.get("computer") or source["source_host_id"]),
        occurred_at_utc=parse_utc_timestamp(source["time_created_utc"]),
        event_data=event_data,
        provider=str(source.get("provider_name") or "") or None,
        correlation_id=str(source.get("correlation_id") or "") or None,
        source_host_id=source["source_host_id"],
        domain_id=source.get("domain_id"),
        event_record_id=(int(source["event_record_id"]) if source.get("event_record_id") is not None else None),
        source_event_sha256=(
            bytes(source["source_event_sha256"]).hex()
            if isinstance(source.get("source_event_sha256"), (bytes, bytearray, memoryview))
            else str(source.get("source_event_sha256") or source.get("normalized_hash") or "") or None
        ),
        source_facts_sha256=(
            bytes(source["source_facts_sha256"]).hex()
            if isinstance(source.get("source_facts_sha256"), (bytes, bytearray, memoryview))
            else str(source.get("source_facts_sha256") or "") or None
        ),
        keywords=source.get("keywords"),
    )


def normalize_semantic_source_payload(
    source: Mapping[str, Any],
) -> NormalizedEvent:
    """Normalize one already verified Storage V2 archive payload."""

    return normalize_windows_event(stored_event_from_source_payload(source))


def normalize_windows_event(event: StoredEvent) -> NormalizedEvent:
    """Interpret a Windows event only from named EventData values.

    An unknown event stays a durable ``event.unknown`` fact.  It is never
    promoted to a security finding by this foundation layer.
    """
    source_host = str(event.source_host_id if event.source_host_id is not None else event.server)
    normalizer = resolve_source_normalizer(
        event.channel,
        event.provider,
        str(event.windows_event_id),
    )
    if normalizer is None:
        projection = {
            "semantic_type": "event.unknown",
            "roles": {"source_host": source_host},
            "facts": {
                "windows_event_id": event.windows_event_id,
                "channel": event.channel,
                "provider": event.provider,
                "correlation_id": event.correlation_id,
            },
            "quality": {
                "event_data_encoding": "named",
                "catalog_independent": False,
                "raw_event_mutated": False,
                "missing_actor_sid": True,
                "unresolved_actor": False,
                "unresolved_target": False,
                "missing_source_ip": True,
                "unknown_event_mapping": True,
                "semantic_mapping_status": "source_pack_or_provider_unresolved",
            },
        }
    else:
        projection = normalizer.semantic_projection(
            event_id=event.windows_event_id,
            channel=event.channel,
            provider=event.provider,
            event_data=event.event_data,
            correlation_id=event.correlation_id,
            source_host=source_host,
            identity_host=event.server,
            keywords=event.keywords,
        )
    semantic_type = str(projection["semantic_type"])
    roles = dict(projection["roles"])
    facts = dict(projection["facts"])
    facts.update({
        "domain_id": event.domain_id,
        "source_host_id": event.source_host_id,
        "host": event.server,
        "event_record_id": event.event_record_id,
        "source_event_sha256": event.source_event_sha256,
        "source_facts_sha256": event.source_facts_sha256,
    })
    facts = {key: value for key, value in facts.items() if value is not None}
    quality = dict(projection["quality"])
    quality["identity_resolution_version"] = IDENTITY_RESOLUTION_VERSION
    identity = {
        "source_event_id": event.event_id,
        "semantic_type": semantic_type,
        "roles": roles,
        "facts": facts,
        "identity_resolution_version": IDENTITY_RESOLUTION_VERSION,
    }
    return NormalizedEvent(event.event_id, semantic_type, event.occurred_at_utc.astimezone(timezone.utc), roles, facts, quality, _digest(identity))


def assemble_process_episodes(events: Sequence[NormalizedEvent]) -> ProcessAssemblyResult:
    """Assemble boot-scoped process episodes without heuristic end inference."""

    unique: dict[int, NormalizedEvent] = {}
    quarantined: set[int] = set()
    standalone: set[int] = set()
    for event in events:
        try:
            native_record_id = int(event.facts["event_record_id"])
        except (KeyError, TypeError, ValueError):
            standalone.add(event.source_event_id)
            continue
        if native_record_id <= 0:
            standalone.add(event.source_event_id)
            continue
        if event.source_event_id in quarantined:
            continue
        prior = unique.get(event.source_event_id)
        if prior is None:
            unique[event.source_event_id] = event
        elif prior.semantic_sha256 != event.semantic_sha256:
            quarantined.add(event.source_event_id)
            standalone.add(event.source_event_id)
            unique.pop(event.source_event_id, None)
    def channel(item: NormalizedEvent) -> str:
        return str(item.facts.get("channel") or "").casefold()

    def record_id(item: NormalizedEvent) -> int:
        return int(item.facts["event_record_id"])

    def native_scope(item: NormalizedEvent) -> tuple[str, str, str]:
        return (
            str(item.facts.get("domain_id") or ""),
            str(item.facts.get("source_host_id") or ""),
            channel(item),
        )

    native_ids: dict[tuple[str, str, str, int], list[int]] = {}
    for item in unique.values():
        native_ids.setdefault((*native_scope(item), record_id(item)), []).append(
            item.source_event_id
        )
    for source_ids in native_ids.values():
        if len(source_ids) > 1:
            standalone.update(source_ids)
            for source_event_id in source_ids:
                unique.pop(source_event_id, None)

    def definitely_before(left: NormalizedEvent, right: NormalizedEvent) -> bool:
        if native_scope(left) == native_scope(right):
            left_record, right_record = record_id(left), record_id(right)
            return left_record < right_record
        return left.occurred_at_utc < right.occurred_at_utc

    # Build one authoritative EventRecordID stream per native source channel,
    # then merge the stream heads by timestamp.  This preserves every native
    # channel edge without pretending the deterministic cross-channel merge is
    # a certain causal order.
    streams: dict[tuple[str, str, str], list[NormalizedEvent]] = {}
    for item in unique.values():
        streams.setdefault(native_scope(item), []).append(item)
    for stream in streams.values():
        stream.sort(key=lambda item: (
            record_id(item), item.occurred_at_utc, item.source_event_id,
        ))
    offsets = {key: 0 for key in streams}
    ordered: list[NormalizedEvent] = []
    while len(ordered) < len(unique):
        available = [
            stream[offsets[key]] for key, stream in streams.items()
            if offsets[key] < len(stream)
        ]
        item = min(available, key=lambda value: (
            value.occurred_at_utc, native_scope(value), record_id(value),
            value.source_event_id,
        ))
        ordered.append(item)
        offsets[native_scope(item)] += 1
    evidence_position = {
        value.source_event_id: index for index, value in enumerate(ordered)
    }

    def scope(item: NormalizedEvent) -> tuple[str, str]:
        return (
            str(item.facts.get("domain_id") or ""),
            str(item.facts.get("source_host_id") or ""),
        )

    boots: dict[tuple[str, str], list[NormalizedEvent]] = {}
    for item in ordered:
        if item.semantic_type == "system.boot.boundary":
            boots.setdefault(scope(item), []).append(item)

    def boot_for(item: NormalizedEvent) -> NormalizedEvent | None:
        candidates = [
            value for value in boots.get(scope(item), [])
            if value.source_event_id == item.source_event_id
            or definitely_before(value, item)
        ]
        return candidates[-1] if candidates else None

    starts_by_key: dict[tuple[str, str, int, int], list[NormalizedEvent]] = {}
    closes: list[NormalizedEvent] = []
    for item in ordered:
        if item.semantic_type not in {"process.started.fragment", "process.ended.fragment"}:
            continue
        if not process_episode_fields_valid(item.facts):
            standalone.add(item.source_event_id)
            continue
        boot_event = boot_for(item)
        try:
            pid = int(item.facts.get("process_id") or 0)
        except (TypeError, ValueError):
            pid = 0
        if boot_event is None or pid <= 0 or not all(scope(item)):
            standalone.add(item.source_event_id)
            continue
        key = (*scope(item), boot_event.source_event_id, pid)
        if item.semantic_type == "process.started.fragment":
            starts_by_key.setdefault(key, []).append(item)
        else:
            closes.append(item)

    mutable: list[dict[str, Any]] = []
    by_key: dict[tuple[str, str, int, int], list[dict[str, Any]]] = {}
    for key, starts in sorted(starts_by_key.items()):
        for start in sorted(starts, key=lambda item: evidence_position[item.source_event_id]):
            identity = {
                "domain_id": key[0], "source_host_id": key[1],
                "boot_event_id": key[2],
                "process_id": key[3], "start_event_id": start.source_event_id,
                "started_at_utc": start.occurred_at_utc.isoformat(),
            }
            item = {
                "episode_id": _digest(identity), "process_id": key[3],
                "domain_id": key[0], "source_host_id": key[1],
                "display_host": str(start.facts.get("host") or ""),
                "boot_event_id": key[2],
                "start_event_id": start.source_event_id, "started_at_utc": start.occurred_at_utc,
                "end_event_id": None, "confirmed_end_at_utc": None,
                "process_name": start.facts.get("process_name"),
                "command_line": start.facts.get("process_command_line"),
                "user_sid": start.facts.get("process_user_sid"),
                "user_name": start.facts.get("process_user_name"),
                "user_domain": start.facts.get("process_user_domain"),
                "logon_id": start.facts.get("process_logon_id"),
                "parent_process_id": int(start.facts["process_parent_id"]) if start.facts.get("process_parent_id") else None,
                "parent_episode_id": None, "completeness_state": "incomplete_open",
                "confirmation_state": "open_incomplete", "ordering_state": "source_native",
                "evidence_event_ids": [start.source_event_id],
                "_start": start, "_channels": {channel(start)},
            }
            mutable.append(item)
            by_key.setdefault(key, []).append(item)
    for generations in by_key.values():
        starts_at: dict[tuple[datetime, str, int], list[dict[str, Any]]] = {}
        for generation in generations:
            start = generation["_start"]
            starts_at.setdefault(
                (start.occurred_at_utc, channel(start), record_id(start)), []
            ).append(generation)
        for same_time in starts_at.values():
            if len(same_time) > 1:
                for generation in same_time:
                    generation["confirmation_state"] = "ambiguous_conflict"
                    generation["completeness_state"] = "conflict_ambiguous_close"

    def compatible(episode: Mapping[str, Any], close: NormalizedEvent) -> bool:
        pairs = (
            ("process_name", "process_name"), ("user_sid", "process_user_sid"),
            ("user_name", "process_user_name"), ("user_domain", "process_user_domain"),
            ("logon_id", "process_logon_id"),
        )
        return all(
            not episode.get(left) or not close.facts.get(right)
            or str(episode[left]).casefold() == str(close.facts[right]).casefold()
            for left, right in pairs
        )

    closes_by_episode: dict[str, list[NormalizedEvent]] = {}
    for close in closes:
        boot_event = boot_for(close)
        pid = int(close.facts.get("process_id") or 0)
        key = (*scope(close), boot_event.source_event_id if boot_event else -1, pid)
        candidates = [
            item for item in by_key.get(key, [])
            if definitely_before(item["_start"], close)
        ]
        if candidates:
            candidates = [
                item for item in candidates
                if not any(
                    definitely_before(item["_start"], other["_start"])
                    for other in candidates if other is not item
                )
                and compatible(item, close)
            ]
        if len(candidates) != 1:
            standalone.add(close.source_event_id)
            continue
        closes_by_episode.setdefault(candidates[0]["episode_id"], []).append(close)
    for item in mutable:
        matching = closes_by_episode.get(item["episode_id"], [])
        if len(matching) == 1:
            close = matching[0]
            item.update(end_event_id=close.source_event_id, confirmed_end_at_utc=close.occurred_at_utc,
                        completeness_state="complete", confirmation_state="confirmed_end")
            item["evidence_event_ids"].append(close.source_event_id)
            item["_channels"].add(channel(close))
        elif len(matching) > 1:
            item["confirmation_state"] = "ambiguous_conflict"
            item["completeness_state"] = "conflict_ambiguous_close"
            item["evidence_event_ids"].extend(value.source_event_id for value in matching)
            item["_channels"].update(channel(value) for value in matching)

    attachable_types = {
        "powershell.module.fragment", "powershell.script_block.fragment",
        "service.installed.fragment", "scheduled_task.created.fragment",
        "scheduled_task.deleted.fragment", "scheduled_task.enabled.fragment",
        "scheduled_task.disabled.fragment", "scheduled_task.updated.fragment",
    }
    for evidence in ordered:
        if evidence.semantic_type not in attachable_types:
            continue
        if not process_episode_fields_valid(evidence.facts):
            standalone.add(evidence.source_event_id)
            continue
        boot_event = boot_for(evidence)
        try:
            pid = int(evidence.facts.get("native_process_id") or 0)
        except (TypeError, ValueError):
            pid = 0
        if boot_event is None or pid <= 0:
            standalone.add(evidence.source_event_id)
            continue
        key = (*scope(evidence), boot_event.source_event_id, pid)
        candidates = [
            episode for episode in by_key.get(key, [])
            if definitely_before(episode["_start"], evidence)
            and (
                episode["confirmed_end_at_utc"] is None
                or definitely_before(evidence, unique[episode["end_event_id"]])
            )
            and compatible(episode, evidence)
        ]
        if len(candidates) != 1:
            standalone.add(evidence.source_event_id)
            continue
        candidates[0]["evidence_event_ids"].append(evidence.source_event_id)
        candidates[0]["_channels"].add(channel(evidence))

    for child in mutable:
        parent_pid = child["parent_process_id"]
        if parent_pid is None:
            continue
        key = (
            child["domain_id"], child["source_host_id"],
            child["boot_event_id"], parent_pid,
        )
        candidates = [
            parent for parent in by_key.get(key, [])
            if definitely_before(parent["_start"], child["_start"])
            and (
                parent["confirmed_end_at_utc"] is None
                or definitely_before(
                    child["_start"], unique[parent["end_event_id"]]
                )
            )
        ]
        # An older open generation is not active past a later start of the same PID.
        if candidates:
            candidates = [
                parent for parent in candidates
                if not any(
                    definitely_before(parent["_start"], other["_start"])
                    for other in candidates if other is not parent
                )
            ]
        if len(candidates) == 1:
            child["parent_episode_id"] = candidates[0]["episode_id"]
        else:
            child["completeness_state"] = "incomplete_parent_unproven"

    episodes = tuple(ProcessEpisode(**{
                         **{key: value for key, value in item.items() if not key.startswith("_")},
                         "ordering_state": (
                             "cross_channel_uncertain"
                             if len(item["_channels"]) > 1 else "source_native"
                         ),
                         "evidence_event_ids": tuple(sorted(
                             set(item["evidence_event_ids"]),
                             key=lambda event_id: evidence_position[event_id],
                         )),
                     })
                     for item in sorted(
                         mutable,
                         key=lambda value: evidence_position[value["start_event_id"]],
                     ))
    return ProcessAssemblyResult(episodes, tuple(sorted(standalone)))


def assemble_canonical_actions(events: Sequence[NormalizedEvent]) -> list[CanonicalAction]:
    """Create deterministic actions for defined semantic fragments only.

    No broad "near in time" joins are performed: a single action is emitted
    only for fragments with the same explicit material identity.
    """
    groups: dict[tuple[str, str], tuple[Mapping[str, Any], list[NormalizedEvent]]] = {}
    for event in events:
        if event.semantic_type == "directory.attribute.changed.fragment":
            kind = "directory.attribute.changed"
            correlation_id = _identity_text(event.facts.get("operation_correlation_id"))
            material: dict[str, Any] = {
                "source_host": event.roles.get("source_host"),
                "object": _identity_text(event.facts.get("object")),
                "attribute": _identity_text(event.facts.get("attribute")),
                "actor": _identity_text(event.roles.get("actor")),
            }
            if correlation_id:
                material["operation_correlation_id"] = correlation_id
            else:
                material["time_bucket"] = _five_minute_bucket(event.occurred_at_utc)
                material["uncorrelated_fragment_event_id"] = event.source_event_id
            if not material["object"] or not material["attribute"] or not material["actor"]:
                material["incomplete_fragment_event_id"] = event.source_event_id
        elif event.semantic_type == "service.installed.fragment":
            kind = "service.installed"
            material = {
                "source_host": event.roles.get("source_host"),
                "service_name": _identity_text(event.facts.get("service_name")),
                "service_file": _identity_text(event.facts.get("service_file")),
                "service_account": _identity_text(event.facts.get("service_account")),
                "time_bucket": _five_minute_bucket(event.occurred_at_utc),
                "source_event_id": event.source_event_id,
            }
            if not material["service_name"] or not material["service_file"]:
                material["incomplete_fragment_event_id"] = event.source_event_id
        elif event.semantic_type == "eventlog.cleared.fragment":
            kind = "eventlog.cleared"
            material = {
                "source_host": event.roles.get("source_host"),
                "cleared_log": _identity_text(event.facts.get("cleared_log")),
                "time_bucket": _five_minute_bucket(event.occurred_at_utc),
                "source_event_id": event.source_event_id,
            }
            if not material["cleared_log"]:
                material["incomplete_fragment_event_id"] = event.source_event_id
        elif event.semantic_type == "audit.policy.changed":
            kind = "audit.policy.changed"
            material = {
                "source_host": event.roles.get("source_host"),
                "actor": _identity_text(event.roles.get("actor")),
                "audit_subcategory_guid": _identity_text(
                    event.facts.get("audit_subcategory_guid")
                ),
                "audit_policy_changes": _identity_text(
                    event.facts.get("audit_policy_changes")
                ),
                # A complete policy-mutation record is its own action. Distinct
                # records must never coalesce merely because their fields are
                # equal.
                "source_event_id": event.source_event_id,
            }
            if (
                not material["actor"]
                or not material["audit_subcategory_guid"]
                or not material["audit_policy_changes"]
            ):
                material["incomplete_event_id"] = event.source_event_id
        elif event.semantic_type == "group.member.added":
            kind = "group.member.added"
            material = {
                "source_host": event.roles.get("source_host"),
                "actor": _identity_text(event.roles.get("actor")),
                "group": _identity_text(event.facts.get("group")),
                "member": _identity_text(event.facts.get("member")),
                "group_scope": _identity_text(event.facts.get("group_scope")),
                # Each audited membership mutation remains independent even
                # when the same actor repeats the same operation.
                "source_event_id": event.source_event_id,
            }
            if (
                not material["source_host"]
                or not material["group"]
                or not material["member"]
            ):
                material["incomplete_event_id"] = event.source_event_id
        elif event.semantic_type == "scheduled_task.created.fragment":
            kind = "scheduled_task.created"
            material = {
                "source_host": event.roles.get("source_host"),
                "task_name": _identity_text(event.facts.get("task_name")),
                "task_instance_id": _identity_text(
                    event.facts.get("task_instance_id")
                ),
                "task_user_context": _identity_text(
                    event.facts.get("task_user_context")
                ),
                # Event 106 is the creation record; it is not merged merely
                # because the same task name is observed again.
                "source_event_id": event.source_event_id,
            }
            if not material["source_host"] or not material["task_name"]:
                material["incomplete_event_id"] = event.source_event_id
        elif event.semantic_type in _INDEPENDENT_AUTHENTICATION_TYPES:
            kind = event.semantic_type
            material = {
                "source_host": event.roles.get("source_host"),
                "session_principal": event.roles.get("session_principal"),
                "source_event_id": event.source_event_id,
            }
        else:
            continue
        key = (kind, _material_json(material))
        if key not in groups:
            groups[key] = (material, [])
        groups[key][1].append(event)

    actions: list[CanonicalAction] = []
    for (kind, _), (material, members) in sorted(groups.items()):
        ordered = sorted(members, key=lambda item: (item.occurred_at_utc, item.source_event_id))
        attributes: dict[str, Any] = {
            "material_identity": material,
            "semantic_contract_version": SEMANTIC_CONTRACT_VERSION,
        }
        if kind in _INDEPENDENT_AUTHENTICATION_TYPES:
            attributes["source_evidence"] = [
                {
                    "source_event_id": item.source_event_id,
                    "semantic_sha256": item.semantic_sha256,
                }
                for item in ordered
            ]
            attributes["observed_facts"] = [dict(item.facts) for item in ordered]
            attributes["observed_roles"] = [dict(item.roles) for item in ordered]
            attributes["session_independent"] = kind.startswith("remote_access.")
        if kind == "directory.attribute.changed":
            attributes["added_values"] = sorted({value for item in ordered for value in item.facts.get("added_values", [])})
            attributes["removed_values"] = sorted({value for item in ordered for value in item.facts.get("removed_values", [])})
            attributes["quality"] = "complete" if attributes["added_values"] and attributes["removed_values"] else "partial"
            attributes["identity_quality"] = (
                "exact_correlation_id"
                if material.get("operation_correlation_id")
                else "correlation_id_missing"
            )
        key = _digest({"action_kind": kind, "material_identity": material})
        action_sha256 = _digest({"action_kind": kind, "deduplication_key": key, "attributes": attributes})
        actions.append(CanonicalAction(
            action_kind=kind,
            status="observed",
            occurred_at_utc=ordered[0].occurred_at_utc,
            contribution_key=key,
            source_event_ids=tuple(item.source_event_id for item in ordered),
            attributes=attributes,
            action_sha256=action_sha256,
        ))
    return actions


def process_shadow_event(event: StoredEvent, *, settings: SemanticFeatureSettings) -> SemanticShadowResult:
    """Process exactly one event without persistence or side effects.

    A future worker may persist this result only after migration 022 is applied
    and a dedicated runtime gate is accepted.  This function is safe to call in
    current production code because every semantic flag defaults to false.
    """
    if not settings.normalization_enabled:
        return SemanticShadowResult(None, (), "semantic_normalization_disabled")
    normalized = normalize_windows_event(event)
    actions = tuple(assemble_canonical_actions((normalized,))) if settings.assembly_enabled else ()
    return SemanticShadowResult(normalized, actions)
