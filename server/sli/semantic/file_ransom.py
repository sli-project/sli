"""R01: source-policy-bound mass-write/delete inputs for the shared QW bridge."""
from dataclasses import asdict, dataclass
from datetime import timedelta
import re
from uuid import UUID

from server.sli.semantic.qw_input import QWSignal, _digest
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope
from sli_agent.envelope import timestamp

RULE_ID = "qw.file-ransom"
MAX_EVIDENCE = 32768


@dataclass(frozen=True, repr=False, kw_only=True)
class RansomExclusion:
    """Local administrator approval, limited to one SID/root and event interval."""
    subject_sid: str
    collection_scope_id: str
    reason: str
    approved_by: str
    active_from: str
    active_to: str

    def __post_init__(self):
        try:
            start, end = timestamp(self.active_from), timestamp(self.active_to)
            valid = timedelta(0) < end - start <= timedelta(days=31)
        except (ValueError, TypeError):
            valid = False
        if (not valid or not isinstance(self.subject_sid, str) or len(self.subject_sid) > 184
                or not re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", self.subject_sid)
                or any(not isinstance(value, str) or not 1 <= len(value) <= limit
                       or value.strip() != value or any(ord(c) < 32 or ord(c) == 127 for c in value)
                       for value, limit in ((self.collection_scope_id, 256), (self.reason, 500), (self.approved_by, 128)))):
            raise ValueError("file_ransom_exclusion_invalid")


@dataclass(frozen=True, repr=False, kw_only=True)
class RansomRule:
    scope: EvidenceScope
    agent_id: str
    source_policy_revision: str
    policy_revision: int = 1
    evaluation_mode: str = "shadow"
    # Must match the retained source policy's mass-operation results.
    threshold: int = 100
    window_seconds: int = 300
    exclusions: tuple[RansomExclusion, ...] = ()

    def __post_init__(self):
        try:
            valid_agent = str(UUID(self.agent_id)) == self.agent_id
        except (ValueError, TypeError, AttributeError):
            valid_agent = False
        if (not isinstance(self.scope, EvidenceScope) or self.scope.plugin_id != "sli.file-audit"
                or not self.scope.collection_scope_id or not valid_agent
                or not isinstance(self.source_policy_revision, str)
                or not 1 <= len(self.source_policy_revision) <= 16
                or not self.source_policy_revision.isascii() or not self.source_policy_revision.isdecimal()
                or not 0 < int(self.source_policy_revision) <= 9007199254740991
                or str(int(self.source_policy_revision)) != self.source_policy_revision
                or type(self.policy_revision) is not int or not 0 < self.policy_revision < 2**31
                or not isinstance(self.evaluation_mode, str) or self.evaluation_mode not in {"test", "shadow", "enabled"}
                or type(self.threshold) is not int or not 1 <= self.threshold <= 1000000
                or type(self.window_seconds) is not int or not 1 <= self.window_seconds <= 86400):
            raise ValueError("file_ransom_rule_invalid")
        if (not isinstance(self.exclusions, tuple) or len(self.exclusions) > 100
                or any(not isinstance(item, RansomExclusion)
                       or item.collection_scope_id != self.scope.collection_scope_id for item in self.exclusions)):
            raise ValueError("file_ransom_exclusion_invalid")

    @property
    def rule_sha256(self):
        return _digest({"version": 1, "agent_id": self.agent_id,
                        "source_policy_revision": self.source_policy_revision,
                        "threshold": self.threshold, "window_seconds": self.window_seconds})

    @property
    def checkpoint_key(self):
        # An approval/expiry must not reset R01's durable replay checkpoint.
        document = asdict(self)
        document.pop("exclusions")
        return _digest(document)

    @property
    def execution(self):
        return {"version": "sli.qw.execution.v1", "kind": "ransom", "rule_id": RULE_ID,
                "rule_version": 1, "rule_sha256": self.rule_sha256, "scope": asdict(self.scope)}


def exclusion_for(rule, result):
    start, end, _ = mass_window(rule, result)
    # Partial overlaps fail closed: do not suppress unapproved file activity.
    return next((item for item in rule.exclusions if item.subject_sid == result["subject_sid"]
                 and timestamp(item.active_from) <= start and end < timestamp(item.active_to)), None)


def mass_window(rule, result):
    """Consume confirmed file-rule output; never reinterpret access rights as delete."""
    details = result["details"]
    if (result["rule_code"] not in {"file-audit.mass-write", "file-audit.mass-delete"}
            or result["conclusion_state"] != "observed" or result["rule_version"] != 1
            or result["agent_id"] != rule.agent_id
            or result["source_instance_id"] != rule.scope.source_instance_id
            or result["collection_scope_id"] != rule.scope.collection_scope_id
            or not result.get("subject_sid")
            or details["threshold"] != rule.threshold or details["window_seconds"] != rule.window_seconds
            or not rule.threshold <= details["distinct_files"] <= len(result["action_ids"])):
        raise ValueError("file_ransom_result_invalid")
    start, end = timestamp(details["window_start"]), timestamp(details["window_end"])
    if not timedelta(0) <= end - start <= timedelta(seconds=rule.window_seconds):
        raise ValueError("file_ransom_result_invalid")
    return start, end, _digest([rule.checkpoint_key, result["subject_sid"]])


def signals(rule, result, refs, *, episode_key, now, complete):
    """Keep every native witness, in verified portions of at most 256 references."""
    _, end, entity_key = mass_window(rule, result)
    refs = tuple(sorted(set(refs), key=lambda ref: ref.params))
    if (not 1 <= len(refs) <= MAX_EVIDENCE
            or any(not isinstance(ref, EvidenceRef) or ref.scope != rule.scope
                   or ref.storage_kind != "file_audit_observation" for ref in refs)):
        raise ValueError("file_ransom_evidence_invalid")
    return tuple(QWSignal(kind="ransom", rule_id=RULE_ID, rule_version=1,
        rule_sha256=rule.rule_sha256, policy_revision=rule.policy_revision,
        evaluation_mode=rule.evaluation_mode, entity_key=entity_key, episode_key=episode_key,
        occurred_at_utc=end, received_at_utc=now, evidence_refs=refs[offset:offset + 256],
        evidence_total=len(refs), base_severity="high", effective_severity="high",
        severity_reasons=("mass_file_changes",), quality="good" if complete else "degraded")
        for offset in range(0, len(refs), 256))


def risk_policy(rule, *, policy_id):
    """Draft definition only; normal source binding and ENABLED admission still apply."""
    from server.sli.semantic.semantic_risk import ScenarioSourceKind
    from server.sli.semantic.semantic_risk_policy import RiskPolicyDefinition

    return RiskPolicyDefinition(policy_id=policy_id, policy_version=rule.policy_revision,
        source_kind=ScenarioSourceKind.QW_SIGNAL, definition={
            "type": "scenario_policy", "source_selector": {"rule_id": RULE_ID, "execution": rule.execution},
            "scenario_kind": RULE_ID, "result_class": "security_incident",
            "merge_window_seconds": rule.window_seconds, "expected_evidence_count": rule.threshold,
            "title": "Suspected ransomware: mass file changes",
            "explanation": "Confirmed mass writes or deletions crossed the source file policy threshold. "
                           "Review the retained native evidence; encryption is not proven.",
            "risk": {"class": "high", "raw_score": "60", "display_points": 60,
                     "rationale": "Confirmed mass file changes require investigation."},
        })
