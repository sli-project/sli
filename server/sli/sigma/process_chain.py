"""One bounded worker chain: atomic 4688 detection -> native confirmed process end.

The worker supplies a complete, overlapping source context (including boot and
PID reuse), not just matched events. Exact source readers and the existing
process assembler own interpretation. Results are immutable values; the caller
owns checkpoints/persistence. This adapter never enables rules or publishes risk.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import re

from server.sli.semantic.finding_evidence import validate_finding_evidence
from server.sli.semantic.semantic_processing import (
    NORMALIZER_ID, NORMALIZER_VERSION, PROCESS_EPISODE_ASSEMBLER_ID,
    PROCESS_EPISODE_ASSEMBLER_VERSION, SEMANTIC_CONTRACT_VERSION,
    assemble_process_episodes, normalize_semantic_source_payload,
)
from server.sli.semantic.semantic_processing_repository import load_semantic_source_event
from server.sli.sigma.detection_input import load_detection_match
from server.sli.sigma.plugin_dependencies import REQUIREMENTS, ChainDependencyBlocker, process_chain_admission
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

CHAIN_ID = "sli.sigma.process.confirmed_end"
CHAIN_VERSION = 1
MAX_CONTEXT = 128
MAX_MATCHES = 128


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, repr=False, kw_only=True)
class ProcessChainRule:
    """Pin one Sigma execution and native interpretation, with bounded time."""

    execution_sha256: str
    scope: EvidenceScope
    evaluation_mode: str
    window_seconds: int = 3600
    allowed_lateness_seconds: int = 3600

    def __post_init__(self):
        if (not isinstance(self.execution_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", self.execution_sha256)
                or not isinstance(self.scope, EvidenceScope)
                or self.scope.plugin_id != "sli.windows.ad-dc"
                or self.scope.collection_scope_id
                or self.evaluation_mode not in ("test", "shadow", "enabled")
                or type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 86400
                or type(self.allowed_lateness_seconds) is not int
                or not 0 <= self.allowed_lateness_seconds <= 86400):
            raise ValueError("sigma_process_chain_rule_invalid")

    @property
    def definition_sha256(self):
        return _digest({
            **asdict(self), "chain_id": CHAIN_ID, "chain_version": CHAIN_VERSION,
            "plugin_contracts": REQUIREMENTS,
            "native": [SEMANTIC_CONTRACT_VERSION, NORMALIZER_ID, NORMALIZER_VERSION,
                       PROCESS_EPISODE_ASSEMBLER_ID, PROCESS_EPISODE_ASSEMBLER_VERSION],
        })


@dataclass(frozen=True, repr=False, kw_only=True)
class ProcessChainResult:
    definition_sha256: str
    match_ids: tuple[str, ...]
    execution_json: str
    evaluation_mode: str
    episode_id: str
    source_host_id: str
    domain_id: str
    process_id: int
    boot_event_id: int
    started_at_utc: datetime
    ended_at_utc: datetime
    evidence_refs: tuple[EvidenceRef, ...]

    @property
    def result_id(self):
        value = asdict(self)
        value["started_at_utc"] = self.started_at_utc.isoformat()
        value["ended_at_utc"] = self.ended_at_utc.isoformat()
        return _digest(value)

    @property
    def evidence_count(self):
        # Sigma's anchor and the native process start are the same event.
        return len(self.evidence_refs)


@dataclass(frozen=True, repr=False, kw_only=True)
class ProcessChainEvaluation:
    results: tuple[ProcessChainResult, ...]
    unmatched_match_ids: tuple[str, ...]
    late_match_ids: tuple[str, ...]
    blocked_match_ids: tuple[str, ...] = ()
    blockers: tuple[ChainDependencyBlocker, ...] = ()

    @property
    def state(self):
        return "blocked" if self.blockers else "completed"


def evaluate_process_chain(cur, *, rule: ProcessChainRule, match_ids: tuple[str, ...],
                           source_refs: tuple[EvidenceRef, ...], archive,
                           watermark: datetime) -> ProcessChainEvaluation:
    """Evaluate exact durable inputs in a caller-owned worker transaction.

    ``watermark`` is the worker's previous event-time watermark, not wall time.
    Replay within lateness uses the same complete overlap and result ID. Older
    evidence is reported separately, never silently treated as a clean result.
    Overflow rejects the entire slice, so fan-out cannot publish a partial chain.
    Only core process evidence is supported by this first native bridge.
    """
    if (not isinstance(rule, ProcessChainRule)
            or type(match_ids) is not tuple or not 1 <= len(match_ids) <= MAX_MATCHES
            or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                   for value in match_ids)
            or type(source_refs) is not tuple or not 1 <= len(source_refs) <= MAX_CONTEXT
            or any(not isinstance(ref, EvidenceRef) or ref.storage_kind != "core_event"
                   or ref.scope != rule.scope for ref in source_refs)
            or not isinstance(watermark, datetime) or watermark.utcoffset() is None):
        raise ValueError("sigma_process_chain_request_invalid")
    with process_chain_admission(cur) as blockers:
        if blockers:
            return ProcessChainEvaluation(
                results=(), unmatched_match_ids=(), late_match_ids=(),
                blocked_match_ids=tuple(sorted(set(match_ids))), blockers=blockers,
            )
        return _evaluate_process_chain(cur, rule=rule, match_ids=match_ids,
                                       source_refs=source_refs, archive=archive,
                                       watermark=watermark.astimezone(timezone.utc))


def _evaluate_process_chain(cur, *, rule, match_ids, source_refs, archive, watermark):
    refs = validate_finding_evidence(cur, source_refs)
    by_id = {int(ref.native_id): ref for ref in refs}
    matches = tuple(load_detection_match(cur, match_id=value) for value in sorted(set(match_ids)))
    for match in matches:
        if (match.execution_sha256 != rule.execution_sha256
                or match.evaluation_mode != rule.evaluation_mode
                or match.evidence.storage_kind != "core_event"
                or match.evidence.scope != rule.scope):
            raise RuntimeError("sigma_process_chain_execution_mismatch")
        if match.evidence not in refs:
            raise RuntimeError("sigma_process_chain_anchor_unavailable")

    events = []
    for source_id, ref in sorted(by_id.items()):
        try:
            payload = load_semantic_source_event(cur, source_event_id=source_id, archive=archive)
            if payload is None:
                raise ValueError
            event = normalize_semantic_source_payload(payload)
            if (event.source_event_id != source_id
                    or event.facts.get("source_event_sha256") != ref.sha256
                    or event.semantic_type not in {"system.boot.boundary", "process.started.fragment",
                                                   "process.ended.fragment"}
                    or not event.roles.get("source_host")
                    or str(event.facts.get("source_host_id") or "") != event.roles["source_host"]):
                raise ValueError
        except Exception:
            # Native readers may carry source identities or raw parser errors.
            raise RuntimeError("sigma_process_chain_source_unavailable") from None
        events.append(event)
    events_by_id = {event.source_event_id: event for event in events}
    by_start = {}
    for match in matches:
        start_id = int(match.evidence.native_id)
        start = events_by_id[start_id]
        if (start.semantic_type != "process.started.fragment"
                or start.occurred_at_utc != match.occurred_at_utc):
            raise RuntimeError("sigma_process_chain_anchor_mismatch")
        by_start.setdefault(start_id, []).append(match)
    # Two different entity claims about the same physical start are ambiguous.
    if any(len({item.entity_key for item in items}) != 1 for items in by_start.values()):
        raise RuntimeError("sigma_process_chain_identity_conflict")

    results, matched, late = [], set(), set()
    for episode in assemble_process_episodes(events).episodes:
        anchors = by_start.get(episode.start_event_id, ())
        if (not anchors or episode.confirmation_state != "confirmed_end"
                or episode.ordering_state != "source_native"
                or episode.end_event_id is None or episode.confirmed_end_at_utc is None):
            continue
        start, end = events_by_id[episode.start_event_id], events_by_id[episode.end_event_id]
        boot = events_by_id[episode.boot_event_id]
        # Native ordering alone cannot justify a negative/excessive time window.
        if not timedelta(0) <= end.occurred_at_utc - start.occurred_at_utc <= timedelta(seconds=rule.window_seconds):
            continue
        if not boot.occurred_at_utc <= start.occurred_at_utc:
            continue
        ids = tuple(item.match_id for item in anchors)
        if end.occurred_at_utc < watermark - timedelta(seconds=rule.allowed_lateness_seconds):
            late.update(ids)
            continue
        evidence = tuple(by_id[source_id] for source_id in (
            episode.boot_event_id, episode.start_event_id, episode.end_event_id,
        ))
        results.append(ProcessChainResult(
            definition_sha256=rule.definition_sha256, match_ids=ids,
            execution_json=json.dumps(anchors[0].execution, sort_keys=True, separators=(",", ":")),
            evaluation_mode=rule.evaluation_mode, episode_id=episode.episode_id,
            source_host_id=episode.source_host_id, domain_id=episode.domain_id,
            process_id=episode.process_id, boot_event_id=episode.boot_event_id,
            started_at_utc=start.occurred_at_utc, ended_at_utc=end.occurred_at_utc,
            evidence_refs=evidence,
        ))
        matched.update(ids)
    return ProcessChainEvaluation(
        results=tuple(sorted(results, key=lambda item: item.result_id)),
        unmatched_match_ids=tuple(sorted(set(match_ids) - matched - late)),
        late_match_ids=tuple(sorted(late)),
    )
