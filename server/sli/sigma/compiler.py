"""Offline, fail-closed compilation of the history-25 Sigma dialect.

pySigma owns condition parsing, list linking and modifier application. This
module only lowers its typed tree to immutable data; it never matches events,
executes regexes or admits rules to a runtime subscription. Compilation support
does not imply that mapped fields or suitable source evidence are available.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from importlib.metadata import version
from typing import Literal

import yaml

from server.sli.sigma.windows_mapping import MAPPING_VERSION

COMPILER_VERSION = "sli.sigma.compiler.v1"
IR_VERSION = "sli.sigma.ir.v1"
PARSER_VERSION = "1.3.3"
MAX_YAML_BYTES = 1024 * 1024
MAX_EXPANDED_BYTES = 4 * MAX_YAML_BYTES
MAX_NODES = 4096
MAX_DEPTH = 48
MAX_VALUE_LENGTH = 4096
MAX_CONDITION_LENGTH = 4096
SUPPORTED_MODIFIERS = frozenset({"contains", "endswith", "startswith", "all", "re", "windash"})
_FIELDS = {
    "security": frozenset({
        "EventID", "Provider_Name", "AuditPolicyChanges", "SubcategoryGuid",
        "AuthenticationPackageName", "IpAddress", "IpPort", "KeyLength",
        "LogonProcessName", "LogonType", "NewTargetUserName", "PreAuthType",
        "SamAccountName", "ServiceFileName", "ServiceName", "ServiceStartType",
        "ServiceType", "Status", "SubStatus", "SubjectUserName", "SubjectUserSid",
        "TargetSid", "TargetUserName", "TargetUserSid", "TaskContent", "TaskContentNew",
        "TicketEncryptionType", "TicketOptions",
    }),
    "system": frozenset({"EventID", "Provider_Name", "ServiceName", "ImagePath"}),
    "process_creation": frozenset({"Image", "ParentImage", "CommandLine"}),
}


class UnsupportedRule(ValueError):
    """Fixed reason codes only; parser errors may contain original rule values."""


class _BoundedLoader(yaml.SafeLoader):
    """Reject aliases, duplicate keys, unsafe tags and excessive nesting."""

    def __init__(self, stream):
        super().__init__(stream)
        self._depth = 0
        self._nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise UnsupportedRule("yaml_alias_unsupported")
        self._depth += 1
        self._nodes += 1
        try:
            if self._depth > MAX_DEPTH or self._nodes > MAX_NODES:
                raise UnsupportedRule("complexity_limit")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise UnsupportedRule("yaml_mapping_invalid")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


@dataclass(frozen=True, repr=False)
class PatternPart:
    kind: Literal["literal", "any", "one"]
    text: str = ""


@dataclass(frozen=True, repr=False)
class IRValue:
    """Patterns match the full field, ignoring case; regexes search, case-sensitive.

    Wildcards are tokens, never interpolated regex text. Null, an empty pattern
    and an absent source field remain distinct; evaluability is a later stage.
    Regex text is retained for a future bounded matcher, never executed here.
    """

    kind: Literal["pattern", "number", "null", "regex"]
    scalar: str | int | None = None
    parts: tuple[PatternPart, ...] = ()


@dataclass(frozen=True, repr=False)
class IRExpression:
    op: Literal["and", "or", "not", "compare"]
    args: tuple[IRExpression, ...] = ()
    field: str | None = None
    value: IRValue | None = None


@dataclass(frozen=True, repr=False)
class CompiledRule:
    rule_id: str
    source_sha256: str
    logsource: str
    expression: IRExpression
    required_fields: tuple[str, ...]
    author: str
    license: str | None
    source_uri: str
    upstream_commit: str
    compiler_version: str = COMPILER_VERSION
    ir_version: str = IR_VERSION
    parser_version: str = PARSER_VERSION
    mapping_version: str = MAPPING_VERSION

    @property
    def plan_sha256(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


def _logsource(document: dict) -> str:
    source = document.get("logsource")
    if not isinstance(source, dict) or source.get("product") != "windows":
        raise UnsupportedRule("logsource_unsupported")
    if set(source) - {"product", "service", "category", "definition"}:
        raise UnsupportedRule("logsource_unsupported")
    if source.get("category") == "process_creation" and "service" not in source:
        return "process_creation"
    if "category" not in source and source.get("service") in ("security", "system"):
        return source["service"]
    raise UnsupportedRule("logsource_unsupported")


@dataclass
class _InputBudget:
    expanded_values: int = 0
    expanded_bytes: int = 0


def _validate_detection(definition, allowed_fields: frozenset[str], budget: _InputBudget,
                        depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise UnsupportedRule("complexity_limit")
    if isinstance(definition, list):
        if not definition or not all(isinstance(item, dict) for item in definition):
            raise UnsupportedRule("keyword_unsupported")
        for item in definition:
            _validate_detection(item, allowed_fields, budget, depth + 1)
        return
    if not isinstance(definition, dict) or not definition:
        raise UnsupportedRule("keyword_unsupported")
    for key, value in definition.items():
        name, *modifiers = key.split("|")
        if not name:
            raise UnsupportedRule("keyword_unsupported")
        if name not in allowed_fields:
            raise UnsupportedRule("field_unsupported")
        if any(modifier not in SUPPORTED_MODIFIERS for modifier in modifiers):
            raise UnsupportedRule("modifier_unsupported")
        values = value if isinstance(value, list) else [value]
        if not values:
            raise UnsupportedRule("empty_list_unsupported")
        if len(set(modifiers)) != len(modifiers):
            raise UnsupportedRule("modifier_chain_unsupported")
        # Only the modifier sequences needed by history-25 are admitted.
        chain = tuple(modifier for modifier in modifiers if modifier != "all")
        if chain not in ((), ("contains",), ("endswith",), ("startswith",),
                         ("re",), ("contains", "windash"), ("windash", "contains")):
            raise UnsupportedRule("modifier_chain_unsupported")
        for item in values:
            if type(item) not in (str, int, type(None)):
                raise UnsupportedRule("value_unsupported")
            expansions = 1
            size = 16
            if isinstance(item, str):
                if len(item) > MAX_VALUE_LENGTH:
                    raise UnsupportedRule("complexity_limit")
                # windash expands combinatorially inside pySigma. Bound it first.
                if "windash" in modifiers:
                    dashes = item.count("-") + item.count("/")
                    if dashes > 4:
                        raise UnsupportedRule("complexity_limit")
                    expansions = 5 ** dashes
                size = len(item.encode("utf-8")) + 2
            budget.expanded_values += expansions
            budget.expanded_bytes += size * expansions
            if budget.expanded_values > MAX_NODES or budget.expanded_bytes > MAX_EXPANDED_BYTES:
                raise UnsupportedRule("complexity_limit")


@dataclass
class _Lowerer:
    fields: set[str] = field(default_factory=set)
    nodes: int = 0

    def tick(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise UnsupportedRule("complexity_limit")

    def lower(self, node, depth: int = 0) -> IRExpression:
        from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR

        self.tick(depth)
        if type(node) in (ConditionAND, ConditionOR, ConditionNOT):
            op = {ConditionAND: "and", ConditionOR: "or", ConditionNOT: "not"}[type(node)]
            if not node.args or op == "not" and len(node.args) != 1:
                raise UnsupportedRule("condition_unsupported")
            return IRExpression(op, tuple(self.lower(arg, depth + 1) for arg in node.args))
        if type(node) is ConditionFieldEqualsValueExpression:
            self.fields.add(node.field)
            return self.value(node.field, node.value, depth + 1)
        raise UnsupportedRule("condition_unsupported")

    def value(self, name: str, value, depth: int) -> IRExpression:
        from sigma.types import SigmaExpansion, SigmaNull, SigmaNumber, SigmaRegularExpression, SigmaString, SpecialChars

        self.tick(depth)
        if type(value) is SigmaExpansion:
            if not value.values:
                raise UnsupportedRule("value_unsupported")
            return IRExpression("or", tuple(self.value(name, item, depth + 1) for item in value.values))
        if type(value) is SigmaString:
            parts = []
            for part in value.iter_parts():
                if isinstance(part, str):
                    parts.append(PatternPart("literal", part))
                elif part == SpecialChars.WILDCARD_MULTI:
                    parts.append(PatternPart("any"))
                elif part == SpecialChars.WILDCARD_SINGLE:
                    parts.append(PatternPart("one"))
                else:
                    raise UnsupportedRule("value_unsupported")
            result = IRValue("pattern", parts=tuple(parts))
        elif type(value) is SigmaNumber and type(value.number) is int:
            result = IRValue("number", value.number)
        elif type(value) is SigmaNull:
            result = IRValue("null")
        elif type(value) is SigmaRegularExpression and not value.flags and not value.contains_placeholder():
            result = IRValue("regex", value.regexp.to_plain_regex())
        else:
            raise UnsupportedRule("value_unsupported")
        return IRExpression("compare", field=name, value=result)


def _validate_condition(node, detections, depth=0) -> None:
    """Prevent pySigma pruning an empty selector out of an otherwise valid tree."""
    from sigma.conditions import ConditionAND, ConditionIdentifier, ConditionNOT, ConditionOR, ConditionSelector

    if depth > MAX_DEPTH:
        raise UnsupportedRule("complexity_limit")
    if type(node) is ConditionSelector:
        if not node.resolve_referenced_detections(detections):
            raise UnsupportedRule("condition_selector_empty")
    elif type(node) is ConditionIdentifier:
        if node.identifier not in detections.detections:
            raise UnsupportedRule("condition_identifier_missing")
    elif type(node) in (ConditionAND, ConditionOR, ConditionNOT):
        for arg in node.args:
            _validate_condition(arg, detections, depth + 1)
    else:
        raise UnsupportedRule("condition_unsupported")


def compile_rule(raw_yaml: bytes, *, source_uri: str = "", upstream_commit: str = "",
                 license_id: str | None = None) -> CompiledRule:
    """Compile one atomic YAML rule, or refuse the entire rule with a reason code.

    Callers compiling the reviewed profile must first verify its stage-01 lock.
    Parser installation is optional and isolated from the server environment.
    """
    try:
        if version("pySigma") != PARSER_VERSION or version("pyparsing") != "3.2.5":
            raise UnsupportedRule("parser_version_mismatch")
        if not isinstance(raw_yaml, bytes) or len(raw_yaml) > MAX_YAML_BYTES:
            raise UnsupportedRule("yaml_size_limit")
        document = yaml.load(raw_yaml, Loader=_BoundedLoader)
        if not isinstance(document, dict):
            raise UnsupportedRule("yaml_mapping_invalid")
        if any(key in document for key in ("correlation", "action", "scope")):
            raise UnsupportedRule("rule_type_unsupported")
        if document.get("taxonomy", "sigma") != "sigma":
            raise UnsupportedRule("taxonomy_unsupported")
        logsource = _logsource(document)
        detection = document.get("detection")
        if not isinstance(detection, dict) or "condition" not in detection:
            raise UnsupportedRule("condition_unsupported")
        conditions = detection["condition"]
        if not isinstance(conditions, list):
            conditions = [conditions]
        if not conditions or any(not isinstance(item, str) or not item or
                                 len(item) > MAX_CONDITION_LENGTH for item in conditions):
            raise UnsupportedRule("condition_unsupported")
        budget = _InputBudget()
        for key, definition in detection.items():
            if key != "condition":
                _validate_detection(definition, _FIELDS[logsource], budget)

        from server.sli.sigma.cache_policy import prepare_sigma_caches

        prepare_sigma_caches()
        from sigma.rule import SigmaRule

        rule = SigmaRule.from_dict(document)
        if rule.id is None or not isinstance(rule.author, str) or not rule.author.strip():
            raise UnsupportedRule("metadata_missing")
        if license_id is not None and rule.license not in (None, license_id):
            raise UnsupportedRule("license_mismatch")
        lowerer = _Lowerer()
        expressions = []
        for condition in rule.detection.parsed_condition:
            _validate_condition(condition.parse(postprocess=False), rule.detection)
            expressions.append(lowerer.lower(condition.parsed))
        # Sigma condition lists represent alternative queries, hence OR.
        expression = expressions[0] if len(expressions) == 1 else IRExpression("or", tuple(expressions))
        return CompiledRule(
            rule_id=str(rule.id), source_sha256=hashlib.sha256(raw_yaml).hexdigest(),
            logsource=logsource, expression=expression, required_fields=tuple(sorted(lowerer.fields)),
            author=rule.author, license=rule.license or license_id, source_uri=source_uri,
            upstream_commit=upstream_commit,
        )
    except UnsupportedRule:
        raise
    except Exception:
        # Never expose pySigma/PyYAML diagnostics or values from imported YAML.
        raise UnsupportedRule("invalid_rule") from None
