"""Content-bound detection input for versioned semantic risk policies.

The admitted detector calls enqueue_detection_match_risk_jobs in its transaction.
This adapter neither enables a policy nor registers a consumer or a source.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import re
from typing import Any
from uuid import UUID

from server.sli.semantic.finding_evidence import validate_finding_evidence
from server.sli.semantic.semantic_risk import (
    ConfidenceFactors, EvidenceQuality, IdentityResolution, ScenarioSourceKind,
)
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True, repr=False, kw_only=True)
class DetectionMatch:
    """One atomic match; no raw fields, display identities or Sigma risk verdict."""

    rule_id: str
    rule_sha256: str
    manifest_sha256: str
    compiler_version: str
    mapping_version: str
    overlay_sha256: str
    evidence: EvidenceRef
    entity_key: str
    occurred_at_utc: datetime
    evaluation_mode: str
    conclusion_state: str = "observed"
    quality: str = "good"
    suppressed: bool = False

    def __post_init__(self):
        try:
            valid_rule = str(UUID(self.rule_id)) == self.rule_id
        except (ValueError, TypeError, AttributeError):
            valid_rule = False
        if (not valid_rule or any(not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value)
                                 for value in (self.rule_sha256, self.manifest_sha256,
                                               self.overlay_sha256, self.entity_key))
                or any(not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", value)
                       for value in (self.compiler_version, self.mapping_version))
                or not isinstance(self.evidence, EvidenceRef)
                or not isinstance(self.occurred_at_utc, datetime)
                or self.occurred_at_utc.tzinfo is None
                or self.evaluation_mode not in ("test", "shadow", "enabled")
                or self.conclusion_state not in ("observed", "not_evaluable", "unknown")
                or self.quality not in ("good", "degraded", "unknown")
                or type(self.suppressed) is not bool):
            raise ValueError("sigma_detection_input_invalid")
        object.__setattr__(self, "occurred_at_utc", self.occurred_at_utc.astimezone(timezone.utc))

    @property
    def document(self):
        value = asdict(self)
        value["occurred_at_utc"] = self.occurred_at_utc.isoformat()
        return value

    @property
    def execution(self):
        """Pin the complete execution and scope, independently of event/mode."""
        return {
            "version": "sli.sigma.execution.v1", "rule_id": self.rule_id,
            "rule_sha256": self.rule_sha256, "manifest_sha256": self.manifest_sha256,
            "compiler_version": self.compiler_version, "mapping_version": self.mapping_version,
            "overlay_sha256": self.overlay_sha256, "scope": asdict(self.evidence.scope),
        }

    @property
    def execution_sha256(self):
        return _digest(self.execution)

    @property
    def match_id(self):
        return _digest(self.document)

    @property
    def evidence_key(self):
        return _digest(self.evidence.params)

    @property
    def partition_key(self):
        return _digest(asdict(self.evidence.scope))

    @property
    def eligible(self):
        return self.conclusion_state == "observed" and self.quality == "good" and not self.suppressed


def load_detection_match(cur: Any, *, match_id: str) -> DetectionMatch:
    cur.execute(
        "select rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json "
        "from semantic_detection_matches where match_id=%s", (match_id,),
    )
    row = dict(cur.fetchone() or {})
    if not row:
        raise LookupError("sigma_detection_input_unavailable")
    try:
        document = row["document_json"]
        if isinstance(document, str):
            document = json.loads(document)
        document = dict(document)
        evidence = dict(document.pop("evidence"))
        evidence["scope"] = EvidenceScope(**evidence["scope"])
        match = DetectionMatch(**(document | {
            "evidence": EvidenceRef(**evidence),
            "occurred_at_utc": datetime.fromisoformat(document["occurred_at_utc"]),
        }))
    except (ValueError, TypeError, KeyError, RuntimeError):
        raise RuntimeError("sigma_detection_input_conflict") from None
    if (match.match_id != match_id or not match.eligible
            or row["rule_id"] != match.rule_id or row["evaluation_mode"] != match.evaluation_mode
            or row["occurred_at_utc"] != match.occurred_at_utc or row["evidence_key"] != match.evidence_key):
        raise RuntimeError("sigma_detection_input_conflict")
    return match


def enqueue_detection_match_risk_jobs(cur: Any, *, match: DetectionMatch) -> tuple[str, ...]:
    """Persist a verified input and enqueue only policies with the same mode."""
    from server.sli.semantic.semantic_risk_runtime_repository import _enqueue_source

    if not isinstance(match, DetectionMatch):
        raise ValueError("sigma_detection_input_invalid")
    if not match.eligible:
        return ()
    validate_finding_evidence(cur, (match.evidence,))
    cur.execute(
        """
        insert into semantic_detection_matches(
            match_id,rule_id,evaluation_mode,occurred_at_utc,evidence_key,document_json
        ) values(%s,%s,%s,%s,%s,%s::jsonb)
        on conflict(match_id) do nothing
        """,
        (match.match_id, match.rule_id, match.evaluation_mode, match.occurred_at_utc,
         match.evidence_key, json.dumps(match.document, sort_keys=True)),
    )
    if load_detection_match(cur, match_id=match.match_id) != match:
        raise RuntimeError("sigma_detection_input_conflict")
    return _enqueue_source(cur, source_kind=ScenarioSourceKind.DETECTION_MATCH, source_id=match.match_id)


def detection_match_proposal(cur: Any, *, policy: Any, source_id: str):
    from server.sli.semantic.semantic_risk_runtime_repository import _coverage_for_policy, _proposal

    match = load_detection_match(cur, match_id=source_id)
    if policy.selector_value != match.rule_id:
        raise RuntimeError("sigma_detection_policy_selector_mismatch")
    if policy.detection_execution_sha256 != match.execution_sha256:
        raise RuntimeError("sigma_detection_execution_mismatch")
    validate_finding_evidence(cur, (match.evidence,))
    # Episode and problem identity do not include a detector or policy revision.
    # The exact installation/source/generation and entity remain mandatory.
    seconds = int(policy.merge_window.total_seconds())
    episode = int(match.occurred_at_utc.timestamp()) // seconds
    proposal = _proposal(
        policy=policy, source_id=source_id, partition_key=match.partition_key,
        strict_keys={"policy": policy.policy_id, "entity": match.entity_key, "episode": str(episode)},
        occurred_at=match.occurred_at_utc, normalized_ids=(),
        factors=ConfidenceFactors(identity_resolution=IdentityResolution.EXACT,
                                  sequence_completeness=100, time_quality=EvidenceQuality.GOOD,
                                  parser_quality=EvidenceQuality.GOOD),
        coverage=_coverage_for_policy(cur, policy=policy, partition_key=match.partition_key,
                                      observed_at=match.occurred_at_utc),
        evidence_refs=(match.evidence,), evidence_key=match.evidence_key,
    )
    return proposal


def verify_detection_proposal(cur: Any, *, proposal: Any) -> None:
    match = load_detection_match(cur, match_id=proposal.step.source_id)
    if (proposal.partition_key != match.partition_key
            or proposal.step.occurred_at_utc != match.occurred_at_utc
            or proposal.step.evidence_refs != (match.evidence,)
            or proposal.contribution.evidence_key != match.evidence_key):
        raise RuntimeError("sigma_detection_source_mismatch")
    validate_finding_evidence(cur, (match.evidence,))


def scenario_detection_evidence(cur: Any, *, scenario_id: str) -> tuple[EvidenceRef, ...]:
    cur.execute(
        "select detection_match_id from semantic_scenario_steps "
        "where scenario_id=%s and source_kind='detection_match' order by step_id limit 257", (scenario_id,),
    )
    ids = [str(row["detection_match_id"]) for row in (cur.fetchall() or [])]
    if not ids or len(ids) > 256:
        raise RuntimeError("sigma_detection_evidence_unavailable")
    matches = [load_detection_match(cur, match_id=identity) for identity in ids]
    if any(match.evaluation_mode != "enabled" for match in matches):
        raise RuntimeError("sigma_detection_mode_mismatch")
    return tuple(dict.fromkeys(match.evidence for match in matches))
