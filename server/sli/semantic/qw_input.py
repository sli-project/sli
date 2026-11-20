"""N06: content-bound QW inputs; callers own transactions and source admission.

No detector, policy, source, finding or delivery is enabled by importing this
module. Publication and delivery remain explicit worker actions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
from hashlib import sha256
import json
import re

from server.sli.semantic.finding_evidence import validate_finding_evidence
from server.sli.semantic.semantic_risk import (
    ConclusionState, ConfidenceFactors, EvidenceQuality, IdentityResolution, ScenarioSourceKind,
)
from server.sli.storage.evidence_ref import EvidenceRef, EvidenceScope

KINDS = frozenset({"threshold", "ransom", "decoy", "watch", "acl"})
MODES = frozenset({"test", "shadow", "enabled"})
SEVERITIES = ("info", "low", "medium", "high", "critical")


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _hash(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def execution_pin_sha256(execution, *, rule_id):
    """Pin QW rule/version and native source scope, without Sigma metadata."""
    if (isinstance(execution, dict) and rule_id in {"qw.password-brute-force", "qw.password-spray"}
            and execution.get("rule_version") == 2):
        from server.sli.semantic.password_attack_v2 import Rule

        try:
            if type(execution["rule_version"]) is not int:
                raise ValueError
            scope = EvidenceScope(**execution["scope"])
            rule = Rule(scope, "brute" if rule_id == "qw.password-brute-force" else "spray")
            if execution != rule.execution:
                raise ValueError
        except (KeyError, TypeError, ValueError, RuntimeError):
            raise ValueError("qw_execution_pin_invalid") from None
        return _digest(execution)
    if isinstance(execution, dict) and execution.get("version") == "sli.qw.file-acl-execution.v1":
        from server.sli.semantic.file_acl_input import validate_execution

        validate_execution(execution)
        if execution["rule_id"] != rule_id:
            raise ValueError("qw_execution_pin_invalid")
        return _digest(execution)
    try:
        if (not isinstance(execution, dict)
                or set(execution) != {"version", "kind", "rule_id", "rule_version", "rule_sha256", "scope"}
                or execution["version"] != "sli.qw.execution.v1"
                or execution["kind"] not in KINDS or execution["kind"] == "acl"
                or not isinstance(rule_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,159}", rule_id)
                or execution["rule_id"] != rule_id
                or type(execution["rule_version"]) is not int or not 0 < execution["rule_version"] < 2**31
                or not _hash(execution["rule_sha256"])):
            raise ValueError
        EvidenceScope(**execution["scope"])
    except (KeyError, TypeError, ValueError, RuntimeError):
        raise ValueError("qw_execution_pin_invalid") from None
    return _digest(execution)


@dataclass(frozen=True, repr=False, kw_only=True)
class QWSignal:
    kind: str
    rule_id: str
    rule_version: int
    rule_sha256: str
    policy_revision: int
    evaluation_mode: str
    entity_key: str
    episode_key: str
    occurred_at_utc: datetime
    received_at_utc: datetime
    evidence_refs: tuple[EvidenceRef, ...]
    base_severity: str = "medium"
    effective_severity: str = "medium"
    severity_reasons: tuple[str, ...] = ()
    quality: str = "good"
    conclusion_state: str = "observed"
    evidence_total: int = 0
    threshold_context: dict | None = None
    decoy_context: dict | None = None
    file_decoy_context: dict | None = None
    watch_context: dict | None = None
    acl_context: dict | None = None
    password_context: dict | None = None
    processing_mode: str = "live"

    def __post_init__(self):
        if self.processing_mode not in ("live", "historical_replay", "history_import"):
            raise ValueError("qw_processing_mode_invalid")
        if (type(self.evidence_refs) is not tuple or not 1 <= len(self.evidence_refs) <= 256
                or any(not isinstance(ref, EvidenceRef) for ref in self.evidence_refs)
                or len(set(self.evidence_refs)) != len(self.evidence_refs)
                or len({ref.scope for ref in self.evidence_refs}) != 1
                or type(self.evidence_total) is not int
                or not (self.evidence_total == 0 or len(self.evidence_refs) <= self.evidence_total <= 32768)
                or type(self.policy_revision) is not int or not 0 < self.policy_revision < 2**31
                or not isinstance(self.evaluation_mode, str) or self.evaluation_mode not in MODES
                or not _hash(self.entity_key) or not _hash(self.episode_key)
                or not isinstance(self.quality, str) or self.quality not in {"good", "degraded", "unknown"}
                or not isinstance(self.conclusion_state, str)
                or self.conclusion_state not in {state.value for state in ConclusionState}
                or self.base_severity not in SEVERITIES or self.effective_severity not in SEVERITIES
                or SEVERITIES.index(self.effective_severity) < SEVERITIES.index(self.base_severity)
                or type(self.severity_reasons) is not tuple or len(self.severity_reasons) > 16
                or any(not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,79}", code)
                       for code in self.severity_reasons)):
            raise ValueError("qw_signal_invalid")
        for field in ("occurred_at_utc", "received_at_utc"):
            stamp = getattr(self, field)
            if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp.utcoffset() is None:
                raise ValueError("qw_signal_invalid")
            object.__setattr__(self, field, stamp.astimezone(timezone.utc))
        # Canonical order makes evidence permutations an exact replay.
        object.__setattr__(self, "evidence_refs", tuple(sorted(self.evidence_refs, key=lambda ref: ref.params)))
        if (self.password_context is not None
                or (self.rule_id in {"qw.password-brute-force", "qw.password-spray"} and self.rule_version == 2)):
            from server.sli.semantic.password_attack_runtime import validate_signal

            validate_signal(self)
        if (self.kind == "acl" or self.acl_context is not None
                or self.rule_id.startswith("qw.file-acl-")
                or any(ref.storage_kind == "file_audit_snapshot" for ref in self.evidence_refs)):
            from server.sli.semantic.file_acl_input import validate_signal

            validate_signal(self)
        execution_pin_sha256(self.execution, rule_id=self.rule_id)
        if self.rule_id == "qw.account-watch" or self.watch_context is not None:
            from server.sli.semantic.account_watch import WatchRule, effective_severity, validate_context

            validate_context(self.watch_context)
            rule = WatchRule(scope=self.evidence_refs[0].scope, policy_revision=self.policy_revision,
                             evaluation_mode=self.evaluation_mode)
            if (self.rule_id != "qw.account-watch" or self.kind != "watch" or self.rule_version != 1
                    or self.rule_sha256 != rule.rule_sha256 or len(self.evidence_refs) != 1
                    or self.evidence_refs[0].storage_kind != "core_event"
                    or self.evidence_refs[0].native_id != str(self.watch_context["source_event_id"])
                    or self.effective_severity != effective_severity(self.base_severity)
                    or self.severity_reasons != ("watch",) or self.conclusion_state != "observed"
                    or any(value is not None for value in (
                        self.threshold_context, self.decoy_context, self.file_decoy_context))):
                raise ValueError("account_watch_signal_invalid")
        if self.rule_id == "qw.account-decoy" or self.decoy_context is not None:
            from server.sli.semantic.account_decoy import DecoyRule, validate_context

            validate_context(self.decoy_context)
            rule = DecoyRule(scope=self.evidence_refs[0].scope, policy_revision=self.policy_revision,
                             evaluation_mode=self.evaluation_mode)
            if (self.rule_id != "qw.account-decoy" or self.kind != "decoy" or self.rule_version != 1
                    or self.rule_sha256 != rule.rule_sha256 or len(self.evidence_refs) != 1
                    or self.base_severity != "high" or self.effective_severity != "high"
                    or self.conclusion_state != "observed" or self.threshold_context is not None
                    or self.file_decoy_context is not None):
                raise ValueError("account_decoy_signal_invalid")
        if self.rule_id == "qw.file-decoy" or self.file_decoy_context is not None:
            from server.sli.semantic.file_decoy import FileDecoyRule, validate_context

            validate_context(self.file_decoy_context)
            rule = FileDecoyRule(scope=self.evidence_refs[0].scope, agent_id=self.file_decoy_context["agent_id"],
                                 policy_revision=self.policy_revision, evaluation_mode=self.evaluation_mode)
            if (self.rule_id != "qw.file-decoy" or self.kind != "decoy" or self.rule_version != 1
                    or self.rule_sha256 != rule.rule_sha256 or len(self.evidence_refs) > 2
                    or self.base_severity != "high" or self.effective_severity != "high"
                    or self.conclusion_state != "observed" or self.threshold_context is not None):
                raise ValueError("file_decoy_signal_invalid")
        if self.rule_id == "qw.file-ransom" and (
                self.kind != "ransom" or self.base_severity != "high" or self.effective_severity != "high"):
            raise ValueError("file_ransom_signal_invalid")
        if self.rule_id == "qw.nps-denials" and self.threshold_context is None:
            raise ValueError("nps_threshold_context_invalid")
        if self.threshold_context is not None:
            from server.sli.semantic.qw_threshold_contract import (
                RULE_ID,
                ThresholdRule,
                validate_context,
            )

            validate_context(self.threshold_context)
            rule = ThresholdRule(scope=self.evidence_refs[0].scope,
                dimension=self.threshold_context["dimension"], threshold=self.threshold_context["threshold"],
                window_seconds=self.threshold_context["window_seconds"], surge_factor=self.threshold_context["surge_factor"])
            expected = "high" if self.threshold_context["comparison"] == "surge" else "medium"
            if (self.rule_id != RULE_ID or self.rule_version != 1 or self.kind != "threshold"
                    or self.rule_sha256 != rule.rule_sha256
                    or self.base_severity != expected or self.effective_severity != expected
                    or self.quality != ("good" if self.threshold_context["current_quality"] ==
                        self.threshold_context["previous_quality"] == "good" else "degraded")):
                raise ValueError("nps_threshold_context_invalid")

    @property
    def execution(self):
        if self.acl_context is not None:
            from server.sli.semantic.file_acl_input import execution

            return execution(self.acl_context["resource"])
        return {"version": "sli.qw.execution.v1", "kind": self.kind, "rule_id": self.rule_id,
                "rule_version": self.rule_version, "rule_sha256": self.rule_sha256,
                "scope": asdict(self.evidence_refs[0].scope)}

    @property
    def document(self):
        result = asdict(self)
        # Preserve the IDs of N06's already-admitted atomic inputs.
        if self.evidence_total == 0:
            result.pop("evidence_total")
        if self.threshold_context is None:
            result.pop("threshold_context")
        if self.decoy_context is None:
            result.pop("decoy_context")
        if self.file_decoy_context is None:
            result.pop("file_decoy_context")
        if self.watch_context is None:
            result.pop("watch_context")
        if self.acl_context is None:
            result.pop("acl_context")
        if self.password_context is None:
            result.pop("password_context")
        if self.processing_mode == "live":
            result.pop("processing_mode")
        for field in ("occurred_at_utc", "received_at_utc"):
            result[field] = getattr(self, field).isoformat()
        return result

    @property
    def signal_id(self):
        # Retry/collection arrival time does not change source identity.
        return _digest({key: value for key, value in self.document.items() if key != "received_at_utc"})

    @property
    def partition_key(self):
        if self.acl_context is not None:
            return self.acl_context["resource_key"]
        return _digest(self.execution["scope"])

    @property
    def evidence_key(self):
        return _digest([ref.params for ref in self.evidence_refs])


def load_qw_signal(cur, *, signal_id):
    cur.execute("select signal_id,evaluation_mode,document_json from semantic_qw_signals where signal_id=%s", (signal_id,))
    row = dict(cur.fetchone() or {})
    if not row:
        raise LookupError("qw_signal_unavailable")
    try:
        document = row["document_json"]
        document = dict(json.loads(document) if isinstance(document, str) else document)
        refs = tuple(EvidenceRef(**(ref | {"scope": EvidenceScope(**ref["scope"])}))
                     for ref in document.pop("evidence_refs"))
        document["severity_reasons"] = tuple(document["severity_reasons"])
        for field in ("occurred_at_utc", "received_at_utc"):
            document[field] = datetime.fromisoformat(document[field])
        signal = QWSignal(**document, evidence_refs=refs)
    except (KeyError, TypeError, ValueError, RuntimeError):
        raise RuntimeError("qw_signal_conflict") from None
    if signal.signal_id != signal_id or signal.evaluation_mode != row["evaluation_mode"]:
        raise RuntimeError("qw_signal_conflict")
    return signal


def enqueue_qw_signal_risk_jobs(cur, *, signal):
    """Verify native evidence before durable admission; never commit or send."""
    from server.sli.semantic.semantic_risk_runtime_repository import _enqueue_source

    if not isinstance(signal, QWSignal):
        raise ValueError("qw_signal_invalid")
    if signal.password_context is not None:
        from server.sli.semantic.password_attack_runtime import verify_signal

        verify_signal(cur, signal)
    else:
        validate_finding_evidence(cur, signal.evidence_refs)
    if signal.acl_context is not None:
        from server.sli.semantic.file_acl_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.watch_context is not None:
        from server.sli.semantic.account_watch_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.decoy_context is not None:
        from server.sli.semantic.account_decoy_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.file_decoy_context is not None:
        from server.sli.semantic.file_decoy_runtime import verify_signal

        verify_signal(cur, signal)
    cur.execute("""insert into semantic_qw_signals(signal_id,evaluation_mode,document_json)
        values(%s,%s,%s::jsonb) on conflict(signal_id) do nothing""",
                (signal.signal_id, signal.evaluation_mode, json.dumps(signal.document, sort_keys=True)))
    persisted = load_qw_signal(cur, signal_id=signal.signal_id)
    if persisted.signal_id != signal.signal_id:
        raise RuntimeError("qw_signal_conflict")
    return _enqueue_source(cur, source_kind=ScenarioSourceKind.QW_SIGNAL, source_id=signal.signal_id)


def qw_signal_proposal(cur, *, policy, source_id):
    from server.sli.semantic.semantic_risk_runtime_repository import _coverage_for_policy, _proposal

    signal = load_qw_signal(cur, signal_id=source_id)
    if (policy.selector_value != signal.rule_id or policy.policy_version != signal.policy_revision
            or policy.qw_execution_sha256 != _digest(signal.execution)):
        raise RuntimeError("qw_signal_policy_mismatch")
    if signal.password_context is not None and policy.scenario_kind != signal.rule_id:
        raise RuntimeError("password_v2_policy_invalid")
    # Password transport/policy may be loaded before the publication lock.
    # Native checks occur after the scenario -> ledger lock/frozen gate.
    if signal.password_context is None:
        validate_finding_evidence(cur, signal.evidence_refs)
    if signal.acl_context is not None:
        from server.sli.semantic.file_acl_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.watch_context is not None:
        from server.sli.semantic.account_watch_runtime import verify_signal
        from server.sli.semantic.event_semantic_contract import MachineRisk

        verify_signal(cur, signal)
        if (policy.risk_class is not MachineRisk.CRITICAL or policy.scenario_kind != signal.rule_id
                or policy.hard_critical or policy.merge_window.total_seconds() != 300
                or policy.expected_evidence_count != 1):
            raise RuntimeError("account_watch_policy_invalid")
        points = {"low": 10, "medium": 25, "high": 60, "critical": 80}[signal.effective_severity]
        policy = replace(policy, risk_class=MachineRisk(signal.effective_severity),
                         raw_score=min(policy.raw_score, Decimal(points)),
                         display_points=min(policy.display_points, points))
    if signal.decoy_context is not None:
        from server.sli.semantic.account_decoy_runtime import verify_signal
        from server.sli.semantic.event_semantic_contract import MachineRisk

        verify_signal(cur, signal)
        if policy.risk_class is not MachineRisk.HIGH or policy.scenario_kind != signal.rule_id:
            raise RuntimeError("account_decoy_policy_invalid")
    if signal.file_decoy_context is not None:
        from server.sli.semantic.file_decoy_runtime import verify_signal
        from server.sli.semantic.event_semantic_contract import MachineRisk

        verify_signal(cur, signal)
        if policy.risk_class is not MachineRisk.HIGH or policy.scenario_kind != signal.rule_id:
            raise RuntimeError("file_decoy_policy_invalid")
    if signal.acl_context is not None:
        from server.sli.semantic.event_semantic_contract import MachineRisk

        if (policy.risk_class is not MachineRisk.MEDIUM or policy.scenario_kind != signal.rule_id
                or policy.hard_critical or policy.raw_score > Decimal(25) or policy.display_points > 25):
            raise RuntimeError("file_acl_medium_policy_required")
    quality = EvidenceQuality.GOOD if signal.quality == "good" else EvidenceQuality.DEGRADED
    # The admitted policy caps risk at high. An observed threshold remains
    # medium; only a confirmed comparison can use that high contribution.
    context = signal.threshold_context
    if signal.rule_id == "qw.file-ransom":
        from server.sli.semantic.event_semantic_contract import MachineRisk

        if policy.risk_class is not MachineRisk.HIGH or policy.scenario_kind != "qw.file-ransom":
            raise RuntimeError("file_ransom_policy_invalid")
    if context is not None:
        from server.sli.semantic.event_semantic_contract import MachineRisk

        if (policy.risk_class is not MachineRisk.HIGH or policy.scenario_kind != "qw.nps-denials"
                or policy.merge_window.total_seconds() != context["window_seconds"]
                or policy.expected_evidence_count != context["threshold"]):
            raise RuntimeError("nps_threshold_policy_invalid")
        if signal.effective_severity == "medium":
            policy = replace(policy, risk_class=MachineRisk.MEDIUM,
                             raw_score=min(policy.raw_score, Decimal(25)), display_points=min(policy.display_points, 25))
        policy = replace(policy, explanation=(
            f"NPS 6273: {context['count']} unique denials in {context['window_seconds']} seconds; "
            f"threshold {context['threshold']}; previous {context['previous_count']}; "
            f"comparison {context['comparison']}; coverage {context['current_quality']}/{context['previous_quality']}; "
            f"period [{context['from_utc']}, {context['to_utc']}); policy revision {signal.policy_revision}."))
    return _proposal(
        policy=policy, source_id=source_id, partition_key=signal.partition_key,
        strict_keys={"kind": signal.kind, "entity": signal.entity_key, "episode": signal.episode_key},
        occurred_at=signal.occurred_at_utc, normalized_ids=(),
        factors=ConfidenceFactors(identity_resolution=(IdentityResolution.UNKNOWN if context is not None
                                      and context["identity_state"] == "unknown" else IdentityResolution.EXACT),
                                  sequence_completeness=min(100, 100 * len(signal.evidence_refs) // policy.expected_evidence_count),
                                  time_quality=quality, parser_quality=quality),
        coverage=_coverage_for_policy(cur, policy=policy, partition_key=signal.partition_key,
                                      observed_at=signal.occurred_at_utc),
        evidence_refs=signal.evidence_refs, evidence_key=signal.evidence_key,
    )


def verify_qw_proposal(cur, *, proposal):
    """Bind a step to the complete immutable, observed ENABLED input."""
    signal = load_qw_signal(cur, signal_id=proposal.step.source_id)
    if (signal.evaluation_mode != "enabled" or signal.conclusion_state != "observed"
            or proposal.partition_key != signal.partition_key
            or dict(proposal.strict_keys) != {"kind": signal.kind, "entity": signal.entity_key,
                                             "episode": signal.episode_key}
            or proposal.step.occurred_at_utc != signal.occurred_at_utc
            or proposal.step.evidence_refs != signal.evidence_refs
            or proposal.contribution.evidence_key != signal.evidence_key
            or proposal.contribution.policy_version != signal.policy_revision):
        raise RuntimeError("qw_signal_source_mismatch")
    if signal.acl_context is not None:
        from server.sli.semantic.event_semantic_contract import MachineRisk

        if proposal.contribution.risk_class is not MachineRisk.MEDIUM or proposal.contribution.hard_critical:
            raise RuntimeError("file_acl_medium_proposal_required")
    if signal.password_context is not None:
        from server.sli.semantic.password_attack_runtime import lock_publication, verify_signal

        cur.execute("select pg_advisory_xact_lock(hashtextextended(%s,0))", (proposal.identity_sha256.hex(),))
        lock_publication(cur, signal)
        verify_signal(cur, signal)
    else:
        validate_finding_evidence(cur, signal.evidence_refs)
    if signal.acl_context is not None:
        from server.sli.semantic.file_acl_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.watch_context is not None:
        from server.sli.semantic.account_watch_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.decoy_context is not None:
        from server.sli.semantic.account_decoy_runtime import verify_signal

        verify_signal(cur, signal)
    if signal.file_decoy_context is not None:
        from server.sli.semantic.file_decoy_runtime import verify_signal

        verify_signal(cur, signal)


def scenario_qw_evidence_batches(cur, *, scenario_id):
    """Keyset pages of immutable members; each native verification is <=256 refs.

    The caller holds the episode's transaction lock through validation, linking
    and outbox admission. No partial publication or delivery escapes a rollback.
    """
    after = "00000000-0000-0000-0000-000000000000"
    found = False
    while True:
        cur.execute("""select step_id,qw_signal_id from semantic_scenario_steps
            where scenario_id=%s and step_id>%s and source_kind='qw_signal'
            order by step_id limit 32""", (scenario_id, after))
        rows = list(cur.fetchall() or [])
        if not rows:
            break
        for row in rows:
            signal = load_qw_signal(cur, signal_id=row["qw_signal_id"])
            if signal.evaluation_mode != "enabled" or signal.conclusion_state != "observed":
                raise RuntimeError("qw_signal_source_mismatch")
            if signal.acl_context is not None:
                from server.sli.semantic.file_acl_runtime import verify_signal

                verify_signal(cur, signal)
            found = True
            yield validate_finding_evidence(cur, signal.evidence_refs)
        after = str(rows[-1]["step_id"])
    if not found:
        raise RuntimeError("qw_evidence_unavailable")
