"""Deterministic Risk, Confidence, Coverage and scenario contracts.

The module is deliberately pure: it does not create findings, register a
worker or mutate storage. Risk never depends on Confidence or Coverage.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from hashlib import sha256
import json

from server.sli.semantic.event_semantic_contract import Confidence, MachineRisk
from server.sli.storage.evidence_ref import EvidenceRef


MAX_SCENARIO_WINDOW = timedelta(hours=24)
MAX_RAW_SCORE = Decimal("100000")
_RISK_ORDER = {
    MachineRisk.UNKNOWN: 0,
    MachineRisk.INFO: 1,
    MachineRisk.LOW: 2,
    MachineRisk.MEDIUM: 3,
    MachineRisk.HIGH: 4,
    MachineRisk.CRITICAL: 5,
}


class CoverageStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class ConclusionState(str, Enum):
    """What the evaluator can honestly conclude from the captured evidence."""

    OBSERVED = "observed"
    NOT_FOUND = "not_found"
    NOT_CHECKED = "not_checked"


class ScenarioResultClass(str, Enum):
    SECURITY_INCIDENT = "security_incident"
    SECURITY_EXPOSURE = "security_exposure"
    CONTROL_GAP = "control_gap"


class ScenarioSourceKind(str, Enum):
    CANONICAL_ACTION = "canonical_action"
    CORRELATION_CANDIDATE = "correlation_candidate"
    CONTROL_HEALTH = "control_health"
    DETECTION_MATCH = "detection_match"
    QW_SIGNAL = "qw_signal"


class IdentityResolution(str, Enum):
    EXACT = "exact"
    PARTIAL = "partial"
    UNRESOLVED = "unresolved"
    UNKNOWN = "unknown"


class EvidenceQuality(str, Enum):
    GOOD = "good"
    DEGRADED = "degraded"
    POOR = "poor"
    UNKNOWN = "unknown"


@dataclass(frozen=True, kw_only=True)
class CompletenessSnapshot:
    """Immutable values that make a conclusion auditable.

    A missing measurement is stored as ``None`` rather than inferred.  This is
    deliberately stricter than Coverage: a negative conclusion is allowed only
    when the catalogue, collection freshness, required channels and close
    window are all proved complete in this exact snapshot.
    """

    captured_at_utc: datetime
    catalog_entry_count: int
    catalog_fully_classified: int
    catalog_schema_v2_ready: int
    freshness_max_age_seconds: int | None
    freshness_budget_seconds: int
    required_channels: tuple[str, ...]
    available_channels: tuple[str, ...]
    window_end_utc: datetime
    descriptor_close_timeout_seconds: int | None
    allowed_lateness_seconds: int | None
    close_deadline_utc: datetime | None
    window_closed: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "captured_at_utc",
            _aware_utc(self.captured_at_utc, field="snapshot captured_at_utc"),
        )
        object.__setattr__(
            self,
            "window_end_utc",
            _aware_utc(self.window_end_utc, field="snapshot window_end_utc"),
        )
        if self.close_deadline_utc is not None:
            object.__setattr__(
                self,
                "close_deadline_utc",
                _aware_utc(
                    self.close_deadline_utc,
                    field="snapshot close_deadline_utc",
                ),
            )
        total = int(self.catalog_entry_count)
        classified = int(self.catalog_fully_classified)
        schema_ready = int(self.catalog_schema_v2_ready)
        if total < 0 or not 0 <= classified <= total or not 0 <= schema_ready <= total:
            raise ValueError("catalogue completeness counts are inconsistent")
        if self.freshness_max_age_seconds is not None and int(
            self.freshness_max_age_seconds
        ) < 0:
            raise ValueError("freshness_max_age_seconds must not be negative")
        if int(self.freshness_budget_seconds) <= 0:
            raise ValueError("freshness_budget_seconds must be positive")
        if (
            self.descriptor_close_timeout_seconds is not None
            and int(self.descriptor_close_timeout_seconds) <= 0
        ):
            raise ValueError("descriptor_close_timeout_seconds must be positive")
        if (
            self.allowed_lateness_seconds is not None
            and int(self.allowed_lateness_seconds) < 0
        ):
            raise ValueError("allowed_lateness_seconds must not be negative")
        required = tuple(
            dict.fromkeys(
                _bounded_text(item, field="required channel", maximum=320)
                for item in self.required_channels
            )
        )
        available = tuple(
            dict.fromkeys(
                _bounded_text(item, field="available channel", maximum=320)
                for item in self.available_channels
            )
        )
        if len(required) > 64 or len(available) > 64:
            raise ValueError("completeness snapshot is limited to 64 channels")
        if not set(available).issubset(set(required)):
            raise ValueError("available channels must be a subset of required channels")
        object.__setattr__(self, "required_channels", required)
        object.__setattr__(self, "available_channels", available)

    @property
    def catalog_classification_ratio(self) -> float:
        return (
            self.catalog_fully_classified / self.catalog_entry_count
            if self.catalog_entry_count
            else 1.0
        )

    @property
    def supports_negative_conclusion(self) -> bool:
        return bool(
            self.catalog_fully_classified == self.catalog_entry_count
            and self.catalog_schema_v2_ready == self.catalog_entry_count
            and self.freshness_max_age_seconds is not None
            and self.freshness_max_age_seconds <= self.freshness_budget_seconds
            and self.required_channels
            and set(self.available_channels) == set(self.required_channels)
            and self.descriptor_close_timeout_seconds is not None
            and self.allowed_lateness_seconds is not None
            and self.close_deadline_utc is not None
            and self.window_closed
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "captured_at_utc": self.captured_at_utc.isoformat(),
            "catalog_completeness": {
                "entry_count": self.catalog_entry_count,
                "fully_classified": self.catalog_fully_classified,
                "classification_ratio": self.catalog_classification_ratio,
                "schema_v2_ready": self.catalog_schema_v2_ready,
            },
            "collection_freshness": {
                "max_age_seconds": self.freshness_max_age_seconds,
                "budget_seconds": self.freshness_budget_seconds,
                "complete": (
                    self.freshness_max_age_seconds is not None
                    and self.freshness_max_age_seconds
                    <= self.freshness_budget_seconds
                ),
            },
            "channel_availability": {
                "required": list(self.required_channels),
                "available": list(self.available_channels),
                "available_count": len(self.available_channels),
                "required_count": len(self.required_channels),
                "complete": bool(
                    self.required_channels
                    and set(self.available_channels) == set(self.required_channels)
                ),
            },
            "window_closure": {
                "window_end_utc": self.window_end_utc.isoformat(),
                "descriptor_close_timeout_seconds": (
                    self.descriptor_close_timeout_seconds
                ),
                "allowed_lateness_seconds": self.allowed_lateness_seconds,
                "close_deadline_utc": (
                    self.close_deadline_utc.isoformat()
                    if self.close_deadline_utc is not None
                    else None
                ),
                "closed": self.window_closed,
            },
            "supports_negative_conclusion": self.supports_negative_conclusion,
        }


def resolve_conclusion_state(
    requested: ConclusionState,
    *,
    snapshot: CompletenessSnapshot,
) -> ConclusionState:
    """Fail closed when an absence was not fully observable."""

    if requested is ConclusionState.NOT_FOUND:
        return (
            ConclusionState.NOT_FOUND
            if snapshot.supports_negative_conclusion
            else ConclusionState.NOT_CHECKED
        )
    return requested


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _bounded_text(value: str, *, field: str, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{field} must contain 1..{maximum} characters")
    return result


def _canonical_json(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=str,
    ).encode("utf-8")


@dataclass(frozen=True, kw_only=True)
class ControlCoverage:
    control_id: str
    status: CoverageStatus
    reason: str
    observed_at_utc: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "control_id", _bounded_text(self.control_id, field="control_id", maximum=160))
        object.__setattr__(self, "reason", _bounded_text(self.reason, field="coverage reason", maximum=2000))
        object.__setattr__(
            self,
            "observed_at_utc",
            _aware_utc(self.observed_at_utc, field="coverage observed_at_utc"),
        )

    @property
    def assessment_sha256(self) -> bytes:
        return sha256(
            _canonical_json(
                {
                    "control_id": self.control_id,
                    "status": self.status.value,
                    "reason": self.reason,
                    "observed_at_utc": self.observed_at_utc.isoformat(),
                }
            )
        ).digest()


@dataclass(frozen=True, kw_only=True)
class ConfidenceFactors:
    identity_resolution: IdentityResolution = IdentityResolution.UNKNOWN
    state_confirmed: bool = False
    multi_source_confirmed: bool = False
    sequence_completeness: int = 0
    time_quality: EvidenceQuality = EvidenceQuality.UNKNOWN
    parser_quality: EvidenceQuality = EvidenceQuality.UNKNOWN

    def __post_init__(self) -> None:
        if not 0 <= int(self.sequence_completeness) <= 100:
            raise ValueError("sequence_completeness must be within 0..100")

    def as_dict(self) -> dict[str, object]:
        return {
            "identity_resolution": self.identity_resolution.value,
            "state_confirmed": self.state_confirmed,
            "multi_source_confirmed": self.multi_source_confirmed,
            "sequence_completeness": int(self.sequence_completeness),
            "time_quality": self.time_quality.value,
            "parser_quality": self.parser_quality.value,
        }


@dataclass(frozen=True, kw_only=True)
class ConfidenceAssessment:
    level: Confidence
    score: int
    factors: ConfidenceFactors
    coverage_status: CoverageStatus


@dataclass(frozen=True, kw_only=True)
class RiskContribution:
    contribution_key: str
    source_kind: ScenarioSourceKind
    source_id: str
    policy_id: str
    policy_version: int
    policy_sha256: bytes
    risk_class: MachineRisk
    raw_score: Decimal
    display_points: int
    hard_critical: bool
    rationale: str
    evidence_key: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contribution_key",
            _bounded_text(self.contribution_key, field="contribution_key", maximum=320),
        )
        object.__setattr__(self, "source_id", _bounded_text(self.source_id, field="source_id", maximum=160))
        object.__setattr__(self, "policy_id", _bounded_text(self.policy_id, field="policy_id", maximum=160))
        object.__setattr__(self, "rationale", _bounded_text(self.rationale, field="risk rationale", maximum=2000))
        if int(self.policy_version) <= 0:
            raise ValueError("policy_version must be positive")
        if len(bytes(self.policy_sha256)) != 32:
            raise ValueError("policy_sha256 must contain 32 bytes")
        if self.source_kind in {ScenarioSourceKind.DETECTION_MATCH, ScenarioSourceKind.QW_SIGNAL} and (
            len(self.evidence_key) != 64 or any(char not in "0123456789abcdef" for char in self.evidence_key)
        ):
            raise ValueError("detection risk contribution requires an exact evidence key")
        raw = Decimal(str(self.raw_score))
        if raw < 0 or raw > MAX_RAW_SCORE:
            raise ValueError("raw_score must be within 0..100000")
        object.__setattr__(self, "raw_score", raw)
        if not 0 <= int(self.display_points) <= 100:
            raise ValueError("display_points must be within 0..100")
        if self.risk_class is MachineRisk.UNKNOWN:
            raise ValueError("risk contribution requires a concrete risk_class")
        if self.hard_critical and self.risk_class is not MachineRisk.CRITICAL:
            raise ValueError("hard_critical contribution must be critical")

    @property
    def contribution_sha256(self) -> bytes:
        return sha256(self.contribution_key.encode("utf-8")).digest()


@dataclass(frozen=True, kw_only=True)
class ScenarioStep:
    step_key: str
    source_kind: ScenarioSourceKind
    source_id: str
    occurred_at_utc: datetime
    title: str
    explanation: str
    normalized_event_ids: tuple[str, ...]
    confidence_factors: ConfidenceFactors
    evidence_refs: tuple[EvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "step_key", _bounded_text(self.step_key, field="step_key", maximum=320))
        object.__setattr__(self, "source_id", _bounded_text(self.source_id, field="source_id", maximum=160))
        object.__setattr__(self, "title", _bounded_text(self.title, field="step title", maximum=300))
        object.__setattr__(self, "explanation", _bounded_text(self.explanation, field="step explanation", maximum=2000))
        object.__setattr__(
            self,
            "occurred_at_utc",
            _aware_utc(self.occurred_at_utc, field="step occurred_at_utc"),
        )
        evidence = tuple(dict.fromkeys(str(item).strip() for item in self.normalized_event_ids))
        if any(not item for item in evidence) or len(evidence) > 32768:
            raise ValueError("scenario step requires bounded normalized evidence")
        if self.source_kind is ScenarioSourceKind.DETECTION_MATCH:
            if evidence or len(self.evidence_refs) != 1 or not isinstance(self.evidence_refs[0], EvidenceRef):
                raise ValueError("detection scenario step requires exact native evidence")
        elif self.source_kind is ScenarioSourceKind.QW_SIGNAL:
            if (evidence or type(self.evidence_refs) is not tuple or not 1 <= len(self.evidence_refs) <= 256
                    or any(not isinstance(ref, EvidenceRef) for ref in self.evidence_refs)):
                raise ValueError("qw_signal_invalid")
        elif self.source_kind is not ScenarioSourceKind.CONTROL_HEALTH and not evidence:
            raise ValueError("action/correlation scenario step requires normalized evidence")
        object.__setattr__(self, "normalized_event_ids", evidence)

    @property
    def step_sha256(self) -> bytes:
        return sha256(self.step_key.encode("utf-8")).digest()


@dataclass(frozen=True, kw_only=True)
class ScenarioProposal:
    scenario_kind: str
    result_class: ScenarioResultClass
    partition_key: str
    strict_keys: Mapping[str, str]
    merge_window: timedelta
    title: str
    explanation: str
    step: ScenarioStep
    contribution: RiskContribution
    coverage: tuple[ControlCoverage, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "scenario_kind", _bounded_text(self.scenario_kind, field="scenario_kind", maximum=200))
        object.__setattr__(self, "partition_key", _bounded_text(self.partition_key, field="partition_key", maximum=160))
        object.__setattr__(self, "title", _bounded_text(self.title, field="scenario title", maximum=300))
        object.__setattr__(self, "explanation", _bounded_text(self.explanation, field="scenario explanation", maximum=2000))
        if self.merge_window <= timedelta(0) or self.merge_window > MAX_SCENARIO_WINDOW:
            raise ValueError("scenario merge_window must be within 24 hours")
        strict = {
            _bounded_text(str(key), field="strict key name", maximum=80):
            _bounded_text(str(value), field="strict key value", maximum=320)
            for key, value in self.strict_keys.items()
        }
        if not strict or len(strict) > 8:
            raise ValueError("scenario merge requires 1..8 strict keys")
        object.__setattr__(self, "strict_keys", strict)
        if self.step.source_kind is not self.contribution.source_kind:
            raise ValueError("scenario step and risk contribution source_kind must match")
        if self.step.source_id != self.contribution.source_id:
            raise ValueError("scenario step and risk contribution source_id must match")
        controls = tuple(self.coverage)
        if len(controls) > 64:
            raise ValueError("scenario coverage is limited to 64 controls")
        object.__setattr__(self, "coverage", controls)

    @property
    def identity_sha256(self) -> bytes:
        return sha256(
            _canonical_json(
                {
                    "scenario_kind": self.scenario_kind,
                    "result_class": self.result_class.value,
                    "partition_key": self.partition_key,
                    "strict_keys": dict(self.strict_keys),
                    "merge_window_seconds": int(self.merge_window.total_seconds()),
                }
            )
        ).digest()


@dataclass(frozen=True, kw_only=True)
class RiskAssessment:
    raw_score: Decimal
    display_score: int
    risk_class: MachineRisk
    hard_critical: bool


@dataclass(frozen=True, kw_only=True)
class ScenarioAssessment:
    identity_sha256: bytes
    first_seen_utc: datetime
    last_seen_utc: datetime
    risk: RiskAssessment
    confidence: ConfidenceAssessment
    coverage_status: CoverageStatus
    proposals: tuple[ScenarioProposal, ...]


def summarize_coverage(observations: Sequence[ControlCoverage]) -> CoverageStatus:
    if not observations:
        return CoverageStatus.UNKNOWN
    latest: dict[str, ControlCoverage] = {}
    for item in observations:
        current = latest.get(item.control_id)
        if current is None or item.observed_at_utc > current.observed_at_utc:
            latest[item.control_id] = item
    statuses = {item.status for item in latest.values()}
    if statuses == {CoverageStatus.COMPLETE}:
        return CoverageStatus.COMPLETE
    if statuses == {CoverageStatus.UNKNOWN}:
        return CoverageStatus.UNKNOWN
    if statuses.issubset({CoverageStatus.UNAVAILABLE, CoverageStatus.UNKNOWN}):
        return CoverageStatus.UNAVAILABLE
    return CoverageStatus.PARTIAL


def assess_confidence(
    factors: ConfidenceFactors, *, coverage_status: CoverageStatus
) -> ConfidenceAssessment:
    identity_points = {
        IdentityResolution.EXACT: 25,
        IdentityResolution.PARTIAL: 12,
        IdentityResolution.UNRESOLVED: 0,
        IdentityResolution.UNKNOWN: 5,
    }[factors.identity_resolution]
    quality_points = {
        EvidenceQuality.GOOD: 10,
        EvidenceQuality.DEGRADED: 5,
        EvidenceQuality.POOR: 0,
        EvidenceQuality.UNKNOWN: 2,
    }
    coverage_points = {
        CoverageStatus.COMPLETE: 5,
        CoverageStatus.PARTIAL: 2,
        CoverageStatus.UNAVAILABLE: 0,
        CoverageStatus.UNKNOWN: 0,
    }[coverage_status]
    score = min(
        100,
        identity_points
        + (15 if factors.state_confirmed else 0)
        + (15 if factors.multi_source_confirmed else 0)
        + int(factors.sequence_completeness) // 5
        + quality_points[factors.time_quality]
        + quality_points[factors.parser_quality]
        + coverage_points,
    )
    has_signal = any(
        (
            factors.identity_resolution is not IdentityResolution.UNKNOWN,
            factors.state_confirmed,
            factors.multi_source_confirmed,
            factors.sequence_completeness > 0,
            factors.time_quality is not EvidenceQuality.UNKNOWN,
            factors.parser_quality is not EvidenceQuality.UNKNOWN,
            coverage_status is not CoverageStatus.UNKNOWN,
        )
    )
    if not has_signal:
        level = Confidence.UNKNOWN
    elif score >= 80:
        level = Confidence.HIGH
    elif score >= 50:
        level = Confidence.MEDIUM
    else:
        level = Confidence.LOW
    return ConfidenceAssessment(
        level=level,
        score=score,
        factors=factors,
        coverage_status=coverage_status,
    )


def aggregate_risk(contributions: Sequence[RiskContribution]) -> RiskAssessment:
    if not contributions:
        raise ValueError("risk assessment requires at least one contribution")
    unique: dict[str, RiskContribution] = {}
    for item in contributions:
        existing = unique.get(item.contribution_key)
        if existing is not None and existing != item:
            raise ValueError("risk contribution key replay conflict")
        unique[item.contribution_key] = item
    values = tuple(unique.values())
    hard_critical = any(item.hard_critical for item in values)
    risk_class = max((item.risk_class for item in values), key=_RISK_ORDER.__getitem__)
    evidence_groups: dict[
        tuple[ScenarioSourceKind, str], list[RiskContribution]
    ] = {}
    for item in values:
        key = (item.evidence_key if item.source_kind in {ScenarioSourceKind.DETECTION_MATCH, ScenarioSourceKind.QW_SIGNAL}
               else item.source_id)
        evidence_groups.setdefault((item.source_kind, key), []).append(
            item
        )
    if hard_critical:
        risk_class = MachineRisk.CRITICAL
    return RiskAssessment(
        raw_score=min(
            MAX_RAW_SCORE,
            sum(
                (
                    max(item.raw_score for item in group)
                    for group in evidence_groups.values()
                ),
                start=Decimal("0"),
            ),
        ),
        display_score=min(
            100,
            sum(
                max(item.display_points for item in group)
                for group in evidence_groups.values()
            ),
        ),
        risk_class=risk_class,
        hard_critical=hard_critical,
    )


def merge_scenario_proposals(
    proposals: Sequence[ScenarioProposal],
) -> ScenarioAssessment:
    if not proposals:
        raise ValueError("scenario assessment requires at least one proposal")
    ordered = tuple(sorted(proposals, key=lambda item: (item.step.occurred_at_utc, item.step.step_key)))
    identity = ordered[0].identity_sha256
    if any(item.identity_sha256 != identity for item in ordered[1:]):
        raise ValueError("scenario proposals do not share strict identity")
    first_seen = ordered[0].step.occurred_at_utc
    last_seen = ordered[-1].step.occurred_at_utc
    window = min(item.merge_window for item in ordered)
    if last_seen - first_seen > window:
        raise ValueError("scenario proposals exceed their merge window")
    steps: dict[str, ScenarioStep] = {}
    contributions: dict[str, RiskContribution] = {}
    for item in ordered:
        existing_step = steps.get(item.step.step_key)
        if existing_step is not None and existing_step != item.step:
            raise ValueError("scenario step key replay conflict")
        steps[item.step.step_key] = item.step
        existing_contribution = contributions.get(item.contribution.contribution_key)
        if existing_contribution is not None and existing_contribution != item.contribution:
            raise ValueError("risk contribution key replay conflict")
        contributions[item.contribution.contribution_key] = item.contribution
    coverage_items = tuple(item for proposal in ordered for item in proposal.coverage)
    coverage_status = summarize_coverage(coverage_items)
    confidence_values = [
        assess_confidence(item.step.confidence_factors, coverage_status=coverage_status)
        for item in ordered
    ]
    confidence = min(confidence_values, key=lambda item: item.score)
    return ScenarioAssessment(
        identity_sha256=identity,
        first_seen_utc=first_seen,
        last_seen_utc=last_seen,
        risk=aggregate_risk(tuple(contributions.values())),
        confidence=confidence,
        coverage_status=coverage_status,
        proposals=ordered,
    )
