"""Strict, replayable correlation rules detached from collection and findings."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from server.sli.semantic.semantic_processing import NormalizedEvent


@dataclass(frozen=True)
class SemanticRelation:
    relation_kind: str
    source_event_ids: tuple[int, ...]
    contribution_key: str
    confidence: str
    explanation: str
    partition_key: str | None = None


def correlate_session_privilege_observation(
    events: Iterable[NormalizedEvent],
    *,
    window: timedelta = timedelta(minutes=15),
) -> list[SemanticRelation]:
    """Link a created session and its privilege observation by scoped Logon ID."""
    if window <= timedelta(0) or window > timedelta(hours=24):
        raise ValueError("session privilege correlation window must be within 24 hours")
    sessions: dict[str, list[NormalizedEvent]] = defaultdict(list)
    privileges: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        identity = event.roles.get("session_principal")
        if not identity:
            continue
        if event.semantic_type == "authentication.session.created":
            sessions[identity].append(event)
        elif event.semantic_type == "authentication.privileged_session.created":
            privileges[identity].append(event)
    result: list[SemanticRelation] = []
    for identity in sorted(set(sessions).intersection(privileges)):
        for session in sorted(sessions[identity], key=lambda item: item.source_event_id):
            for privilege in sorted(privileges[identity], key=lambda item: item.source_event_id):
                if abs(privilege.occurred_at_utc - session.occurred_at_utc) > window:
                    continue
                ids = tuple(sorted((session.source_event_id, privilege.source_event_id)))
                result.append(SemanticRelation(
                    "authentication.session.has_special_privileges",
                    ids,
                    f"session-special-privileges:{identity}:{ids[0]}:{ids[1]}",
                    "high",
                    "Связь подтверждена совпадением source_host и LogonId; она описывает сессию, не повышение прав.",
                ))
    return result


def aggregate_bruteforce_attempts(events: Iterable[NormalizedEvent], *, minimum_failures: int = 5, window: timedelta = timedelta(minutes=10)) -> list[SemanticRelation]:
    """Allowed aggregate correlation: same target and source IP in a bounded window."""
    grouped: dict[tuple[str, str], list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.semantic_type != "authentication.session.failed":
            continue
        target, source_ip = event.roles.get("affected_entity"), event.roles.get("source_ip")
        if target and source_ip:
            grouped[(target, source_ip)].append(event)
    result: list[SemanticRelation] = []
    for (target, source_ip), members in sorted(grouped.items()):
        ordered = sorted(members, key=lambda item: (item.occurred_at_utc, item.source_event_id))
        for start, first in enumerate(ordered):
            windowed = [item for item in ordered[start:] if item.occurred_at_utc - first.occurred_at_utc <= window]
            if len(windowed) < minimum_failures:
                continue
            ids = tuple(item.source_event_id for item in windowed)
            result.append(SemanticRelation(
                "authentication.bruteforce.suspected",
                ids,
                f"bruteforce:{target}:{source_ip}:{first.occurred_at_utc.isoformat()}:{ids[0]}",
                "medium",
                f"{len(ids)} неуспешных входов для одной учётной записи с одного IP за {int(window.total_seconds() // 60)} мин.",
            ))
            break
    return result
