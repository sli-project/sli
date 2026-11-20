"""N08: bounded source-time NPS threshold evaluation, without I/O or delivery.

Coverage is supplied by the acquisition reader, never inferred from event counts.
Checkpoints and QW inputs must be persisted in the same caller transaction.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from server.sli.semantic.qw_input import QWSignal
from server.sli.semantic.qw_threshold_contract import (
    DIMENSIONS,
    MAX_EVENTS,
    QUALITIES,
    RULE_ID,
    ThresholdRule,
    digest,
    utc,
    validate_context,
)
from server.sli.storage.evidence_ref import EvidenceRef

MAX_GROUPS = 500

# Preserve the adapter's public contract while core imports only its schema.
__all__ = (
    "DIMENSIONS", "MAX_EVENTS", "MAX_GROUPS", "QUALITIES", "RULE_ID", "Denial",
    "ThresholdRule", "digest", "evaluate", "risk_policy", "utc", "validate_context",
)


@dataclass(frozen=True, repr=False)
class Denial:
    occurred_at_utc: datetime
    evidence: EvidenceRef
    group_value: str | None

    def __post_init__(self):
        object.__setattr__(self, "occurred_at_utc", utc(self.occurred_at_utc))
        if (not isinstance(self.evidence, EvidenceRef) or self.evidence.storage_kind != "core_event"
                or self.group_value is not None and (
                    not isinstance(self.group_value, str) or not 1 <= len(self.group_value) <= 512)):
            raise ValueError("nps_threshold_denial_invalid")


def evaluate(rule, events, *, end, now, checkpoint=None, current_quality="partial", previous_quality="partial"):
    """Two adjacent half-open windows, with a bounded overlap on every read.

    A full quiet window closes an episode only with confirmed current coverage.
    Unknown groups are scoped hashes; NAS is never substituted for client IP.
    No event value is copied to the checkpoint, QW explanation or message.
    """
    end, now = utc(end), utc(now)
    if (end > now or len(events) > MAX_EVENTS or current_quality not in QUALITIES
            or previous_quality not in QUALITIES):
        raise ValueError("nps_threshold_input_invalid")
    window = timedelta(seconds=rule.window_seconds)
    start, previous_start = end - window, end - 2 * window
    checkpoint = checkpoint or {}
    if checkpoint.get("watermark") and utc(checkpoint["watermark"]) > end:
        raise ValueError("nps_threshold_watermark_regression")
    if now - end > window:
        current_quality = previous_quality = "stale"
    groups = defaultdict(lambda: [[], []])
    seen = {}
    for event in events:
        if not isinstance(event, Denial) or event.evidence.scope != rule.scope:
            raise ValueError("nps_threshold_scope_mismatch")
        identity = event.evidence.native_id
        if identity in seen:
            if seen[identity] != event:
                raise ValueError("nps_threshold_event_conflict")
            continue
        seen[identity] = event
        if not previous_start <= event.occurred_at_utc < end:
            continue
        # Missing explicitly observed client IP is not a synthetic endpoint.
        if rule.dimension == "client_ip" and event.group_value is None:
            continue
        key = digest([rule.checkpoint_key, rule.dimension, event.group_value])
        groups[key][int(event.occurred_at_utc < start)].append(event)
    old_episodes = checkpoint.get("episodes", {})
    if len(set(groups) | set(old_episodes)) > MAX_GROUPS:
        raise ValueError("nps_threshold_group_limit")
    episodes, rows, signals = {}, [], []
    for key in sorted(set(groups) | set(old_episodes)):
        current, previous = groups[key]
        current.sort(key=lambda item: (item.occurred_at_utc, item.evidence.native_id))
        previous.sort(key=lambda item: (item.occurred_at_utc, item.evidence.native_id))
        count, before = len(current), len(previous)
        episode = dict(old_episodes.get(key, {}))
        crossed = count >= rule.threshold
        comparison = "threshold"
        severity = "medium"
        if crossed and current_quality == previous_quality == "good":
            if before == 0:
                comparison = "new_activity"
            elif count >= rule.surge_factor * before:
                severity, comparison = "high", "surge"
        if crossed:
            if not episode:
                episode = {"key": digest([key, current[rule.threshold - 1].evidence.params]), "severity": "medium"}
            episode["last_above"] = end.isoformat()
            if severity == "high":
                episode["severity"] = "high"
            refs = tuple(event.evidence for event in current)
            context = {"count": count, "previous_count": before, "threshold": rule.threshold,
                       "window_seconds": rule.window_seconds, "surge_factor": rule.surge_factor,
                       "dimension": rule.dimension, "comparison": comparison,
                       "current_quality": current_quality, "previous_quality": previous_quality,
                       "from_utc": start.isoformat(), "to_utc": end.isoformat(),
                       "identity_state": "unknown" if current[0].group_value is None else "observed"}
            # A replay/new polling time with the same evidence and severity is
            # not a new input. A later escalation does produce an episode update.
            signature = digest([[ref.params for ref in refs], before, comparison, severity, current_quality, previous_quality])
            if episode.get("signature") != signature:
                for offset in range(0, len(refs), 256):
                    signals.append(QWSignal(
                        kind="threshold", rule_id=RULE_ID, rule_version=1, rule_sha256=rule.rule_sha256,
                        policy_revision=rule.policy_revision, evaluation_mode=rule.evaluation_mode,
                        entity_key=key, episode_key=episode["key"],
                        occurred_at_utc=current[-1].occurred_at_utc, received_at_utc=now,
                        evidence_refs=refs[offset:offset + 256], evidence_total=len(refs),
                        base_severity=severity, effective_severity=severity,
                        severity_reasons=("nps_surge",) if severity == "high" else ("nps_threshold",),
                        quality="good" if current_quality == previous_quality == "good" else "degraded",
                        threshold_context=context,
                    ))
                episode["signature"] = signature
        elif episode and current_quality == "good" and end - utc(episode["last_above"]) >= window:
            episode = {}
        if episode:
            episodes[key] = episode
        if current or previous or episode:
            rows.append({"entity_key": key, "episode_key": episode.get("key"), "count": count,
                         "previous_count": before, "threshold": rule.threshold,
                         "policy_revision": rule.policy_revision, "rule_sha256": rule.rule_sha256,
                         "severity": episode.get("severity") if crossed else None,
                         "comparison": comparison if crossed else None,
                         "current_quality": current_quality, "previous_quality": previous_quality,
                         "state": "observed" if crossed else "below_threshold" if current_quality == "good" else "not_proven"})
    return {"watermark": end.isoformat(), "episodes": episodes, "rows": rows,
            "state": "not_proven" if current_quality == "not_collected" else current_quality}, tuple(signals)


def risk_policy(rule, *, policy_id):
    """Draft only: normal lifecycle and source admission remain mandatory."""
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    execution = {"version": "sli.qw.execution.v1", "kind": "threshold", "rule_id": RULE_ID,
                 "rule_version": 1, "rule_sha256": rule.rule_sha256, "scope": asdict(rule.scope)}
    return RiskPolicyDefinition(policy_id=policy_id, policy_version=rule.policy_revision,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": RULE_ID, "execution": execution},
            "scenario_kind": "qw.nps-denials", "result_class": "security_incident",
            "merge_window_seconds": rule.window_seconds, "expected_evidence_count": rule.threshold,
            "title": "NPS denial threshold", "explanation": "Unique source NPS decisions crossed the configured threshold.",
            "risk": {"class": "high", "raw_score": "60", "display_points": 60,
                     "rationale": "Confirmed comparison of equal NPS windows; observed threshold is medium."},
        })
