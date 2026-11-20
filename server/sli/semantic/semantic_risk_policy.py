"""Declarative, bounded policies that turn semantic sources into scenarios."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from hashlib import sha256
import json
from typing import Any

from server.sli.semantic.event_semantic_contract import MachineRisk
from server.sli.semantic.semantic_processing import CANONICAL_ENTITY_ROLES
from server.sli.semantic.semantic_risk import ScenarioResultClass, ScenarioSourceKind


POLICY_LIFECYCLE = frozenset(
    {"draft", "validated", "test", "shadow", "enabled", "disabled", "deprecated"}
)
POLICY_TRANSITIONS = {
    "draft": frozenset({"validated", "disabled"}),
    "validated": frozenset({"draft", "test", "disabled"}),
    "test": frozenset({"draft", "shadow", "disabled"}),
    "shadow": frozenset({"enabled", "disabled", "deprecated"}),
    "enabled": frozenset({"disabled", "deprecated"}),
    "disabled": frozenset({"draft", "deprecated"}),
    "deprecated": frozenset(),
}
EXECUTABLE_POLICY_STATES = frozenset({"test", "shadow", "enabled"})
_FORBIDDEN_KEYS = frozenset(
    {
        "sql",
        "shell",
        "powershell",
        "python",
        "csharp",
        "command",
        "script",
        "network_call",
        "http",
        "url",
    }
)


def _canonical_json(value: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _validate_value(value: Any, *, path: str = "definition") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key).strip().casefold()
            if name in _FORBIDDEN_KEYS:
                raise ValueError(f"forbidden risk policy field: {path}.{key}")
            _validate_value(item, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _validate_value(item, path=f"{path}[{index}]")
        return
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise ValueError(f"unsupported risk policy value at {path}")


def _text(value: object, *, field: str, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{field} must contain 1..{maximum} characters")
    return result


def _string_list(value: object, *, field: str, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{field} must be a list")
    result = tuple(_text(item, field=field, maximum=160) for item in value)
    if len(result) > maximum or len(set(result)) != len(result):
        raise ValueError(f"{field} must contain unique bounded values")
    return result


@dataclass(frozen=True, kw_only=True)
class RiskPolicyDefinition:
    policy_id: str
    policy_version: int
    source_kind: ScenarioSourceKind
    definition: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "policy_id", _text(self.policy_id, field="policy_id", maximum=160)
        )
        if int(self.policy_version) <= 0:
            raise ValueError("policy_version must be positive")
        if self.definition.get("type") != "scenario_policy":
            raise ValueError("risk policy definition type must be scenario_policy")
        _validate_value(self.definition)
        encoded = _canonical_json(self.definition).encode("utf-8")
        if len(encoded) > 65536:
            raise ValueError("risk policy definition exceeds 64 KiB")

    @property
    def definition_json(self) -> str:
        return _canonical_json(self.definition)

    @property
    def definition_sha256(self) -> bytes:
        return sha256(self.definition_json.encode("utf-8")).digest()


@dataclass(frozen=True, kw_only=True)
class CompiledRiskPolicy:
    policy_id: str
    policy_version: int
    source_kind: ScenarioSourceKind
    selector_value: str
    scenario_kind: str
    result_class: ScenarioResultClass
    strict_roles: tuple[str, ...]
    merge_window: timedelta
    title: str
    explanation: str
    risk_class: MachineRisk
    raw_score: Decimal
    display_points: int
    hard_critical: bool
    rationale: str
    expected_evidence_count: int
    required_controls: tuple[str, ...]
    allowed_lateness_seconds: int | None
    definition_sha256: bytes
    detection_execution_sha256: str | None = None
    qw_execution_sha256: str | None = None


def compile_risk_policy(policy: RiskPolicyDefinition) -> CompiledRiskPolicy:
    definition = dict(policy.definition)
    detection_execution_sha256 = None
    qw_execution_sha256 = None
    selector = definition.get("source_selector")
    if not isinstance(selector, Mapping):
        raise ValueError("source_selector must be an object")
    if policy.source_kind is ScenarioSourceKind.CANONICAL_ACTION:
        selector_value = _text(
            selector.get("action_kind"), field="action_kind", maximum=200
        )
        strict_roles = _string_list(
            definition.get("strict_roles", ()), field="strict_roles", maximum=4
        )
        if any(role not in CANONICAL_ENTITY_ROLES for role in strict_roles):
            raise ValueError("strict_roles must use canonical entity roles")
    elif policy.source_kind is ScenarioSourceKind.CORRELATION_CANDIDATE:
        selector_value = _text(
            selector.get("relation_kind"), field="relation_kind", maximum=200
        )
        strict_roles = _string_list(
            definition.get("strict_roles"), field="strict_roles", maximum=4
        )
        if not strict_roles:
            raise ValueError("correlation risk policy requires strict_roles")
        if any(role not in CANONICAL_ENTITY_ROLES for role in strict_roles):
            raise ValueError("strict_roles must use canonical entity roles")
    elif policy.source_kind is ScenarioSourceKind.CONTROL_HEALTH:
        selector_value = _text(
            selector.get("control_id"), field="control_id", maximum=160
        )
        strict_roles = ()
    elif policy.source_kind is ScenarioSourceKind.DETECTION_MATCH:
        from uuid import UUID

        selector_value = _text(selector.get("rule_id"), field="rule_id", maximum=36)
        if str(UUID(selector_value)) != selector_value:
            raise ValueError("rule_id must be a canonical UUID")
        from server.sli.sigma.lifecycle import execution_pin_sha256

        if set(selector) != {"rule_id", "execution"}:
            raise ValueError("sigma_detection_execution_pin_required")
        detection_execution_sha256 = execution_pin_sha256(selector["execution"], rule_id=selector_value)
        strict_roles = ()
    elif policy.source_kind is ScenarioSourceKind.QW_SIGNAL:
        from server.sli.semantic.qw_input import execution_pin_sha256

        if set(selector) != {"rule_id", "execution"}:
            raise ValueError("qw_execution_pin_invalid")
        selector_value = selector["rule_id"]
        qw_execution_sha256 = execution_pin_sha256(selector["execution"], rule_id=selector_value)
        strict_roles = ()
    else:
        raise ValueError("risk policy source kind is not supported")
    try:
        merge_seconds = int(definition.get("merge_window_seconds"))
    except (TypeError, ValueError) as exc:
        raise ValueError("merge_window_seconds must be an integer") from exc
    if not 1 <= merge_seconds <= 86400:
        raise ValueError("merge_window_seconds must be within 24 hours")
    risk = definition.get("risk")
    if not isinstance(risk, Mapping):
        raise ValueError("risk must be an object")
    risk_class = MachineRisk(str(risk.get("class") or "unknown"))
    if risk_class is MachineRisk.UNKNOWN:
        raise ValueError("risk policy requires a concrete risk class")
    raw_score = Decimal(str(risk.get("raw_score")))
    display_points = int(risk.get("display_points"))
    hard_critical = bool(risk.get("hard_critical", False))
    if raw_score < 0 or raw_score > Decimal("100000"):
        raise ValueError("raw_score must be within 0..100000")
    if not 0 <= display_points <= 100:
        raise ValueError("display_points must be within 0..100")
    if hard_critical and risk_class is not MachineRisk.CRITICAL:
        raise ValueError("hard_critical policy must use critical risk")
    try:
        expected = int(definition.get("expected_evidence_count", 1))
    except (TypeError, ValueError) as exc:
        raise ValueError("expected_evidence_count must be an integer") from exc
    if not 1 <= expected <= 32768:
        raise ValueError("expected_evidence_count must be within 1..32768")
    controls = _string_list(
        definition.get("required_controls", ()),
        field="required_controls",
        maximum=64,
    )
    raw_allowed_lateness = definition.get("allowed_lateness_seconds")
    if raw_allowed_lateness is None:
        allowed_lateness = None
    else:
        try:
            allowed_lateness = int(raw_allowed_lateness)
        except (TypeError, ValueError) as exc:
            raise ValueError("allowed_lateness_seconds must be an integer") from exc
        if not 0 <= allowed_lateness <= 86400:
            raise ValueError("allowed_lateness_seconds must be within 0..86400")
    return CompiledRiskPolicy(
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        source_kind=policy.source_kind,
        selector_value=selector_value,
        scenario_kind=_text(
            definition.get("scenario_kind"), field="scenario_kind", maximum=200
        ),
        result_class=ScenarioResultClass(str(definition.get("result_class"))),
        strict_roles=strict_roles,
        merge_window=timedelta(seconds=merge_seconds),
        title=_text(definition.get("title"), field="title", maximum=300),
        explanation=_text(
            definition.get("explanation"), field="explanation", maximum=2000
        ),
        risk_class=risk_class,
        raw_score=raw_score,
        display_points=display_points,
        hard_critical=hard_critical,
        rationale=_text(risk.get("rationale"), field="rationale", maximum=2000),
        expected_evidence_count=expected,
        required_controls=controls,
        allowed_lateness_seconds=allowed_lateness,
        definition_sha256=policy.definition_sha256,
        detection_execution_sha256=detection_execution_sha256,
        qw_execution_sha256=qw_execution_sha256,
    )
