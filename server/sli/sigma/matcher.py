"""Bounded, side-effect-free evaluation of the stage-04 Sigma IR.

This is a field matcher, not a source quality/admission gate or a history job.
Callers must supply authorized, complete mapped fields and honor unavailable.
Regex compilation/search runs in a disposable process, never in the worker.
"""
from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

if TYPE_CHECKING:
    from server.sli.sigma.compiler import CompiledRule, IRExpression, IRValue

MATCHER_VERSION = "sli.sigma.matcher.v1"
_REGEX_WORKER = Path(__file__).with_name("_regex_worker.py")


@dataclass(frozen=True)
class MatchLimits:
    max_nodes: int = 4096
    max_depth: int = 48
    max_pattern_chars: int = 4096
    max_field_chars: int = 262144
    max_values: int = 64
    max_steps: int = 2_000_000
    max_regex_calls: int = 32
    regex_timeout_seconds: float = 0.25
    timeout_seconds: float = 2.0

    def __post_init__(self):
        for key, value in asdict(self).items():
            if key.endswith("seconds"):
                if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 10:
                    raise ValueError("sigma_match_limits_invalid")
            elif type(value) is not int or not 0 < value <= 2_000_000:
                raise ValueError("sigma_match_limits_invalid")
        if self.max_depth > 48:
            raise ValueError("sigma_match_limits_invalid")


@dataclass(frozen=True)
class MatchResult:
    status: str
    reasons: tuple[str, ...]
    replay_sha256: str


class _Stopped(Exception):
    """Fixed diagnostic codes; never include pattern or event content."""


@dataclass
class _Budget:
    limits: MatchLimits
    deadline: float
    steps: int = 0
    regex_calls: int = 0

    def tick(self, count=1):
        self.steps += count
        if self.steps > self.limits.max_steps:
            raise _Stopped("work_limit")
        if time.monotonic() >= self.deadline:
            raise _Stopped("time_limit")


def _validate(node: IRExpression, budget: _Budget, fields: set[str], depth=0, nodes=None):
    from server.sli.sigma.compiler import IRExpression, IRValue, PatternPart

    nodes = [0] if nodes is None else nodes
    nodes[0] += 1
    budget.tick()
    if nodes[0] > budget.limits.max_nodes or depth > budget.limits.max_depth:
        raise _Stopped("ir_complexity_limit")
    if type(node) is not IRExpression or type(node.args) is not tuple:
        raise _Stopped("invalid_ir")
    if node.op in ("and", "or", "not"):
        if (not node.args or node.op == "not" and len(node.args) != 1
                or node.field is not None or node.value is not None
                or len(node.args) > budget.limits.max_nodes):
            raise _Stopped("invalid_ir")
        for arg in node.args:
            _validate(arg, budget, fields, depth + 1, nodes)
        return
    if (node.op != "compare" or node.args or type(node.field) is not str
            or not 0 < len(node.field) <= 128 or type(node.value) is not IRValue):
        raise _Stopped("invalid_ir")
    fields.add(node.field)
    value = node.value
    if type(value.parts) is not tuple or len(value.parts) > budget.limits.max_pattern_chars:
        raise _Stopped("invalid_ir")
    if value.kind == "pattern":
        size = 0
        if value.scalar is not None:
            raise _Stopped("invalid_ir")
        for part in value.parts:
            budget.tick()
            if (type(part) is not PatternPart or part.kind not in ("literal", "any", "one")
                    or type(part.text) is not str or part.kind != "literal" and part.text):
                raise _Stopped("invalid_ir")
            size += max(1, len(part.text))
        if size > budget.limits.max_pattern_chars:
            raise _Stopped("pattern_size_limit")
    elif value.parts:
        raise _Stopped("invalid_ir")
    elif value.kind == "regex":
        if type(value.scalar) is not str or len(value.scalar) > budget.limits.max_pattern_chars:
            raise _Stopped("invalid_ir")
    elif value.kind == "number":
        if type(value.scalar) is not int or value.scalar.bit_length() > 64:
            raise _Stopped("invalid_ir")
    elif value.kind != "null" or value.scalar is not None:
        raise _Stopped("invalid_ir")


def _glob(value: str, pattern: IRValue, budget: _Budget) -> bool:
    # Interpret only compiler tokens. Literal backslashes/metacharacters are
    # never re-parsed as escapes or interpolated into a regular expression.
    tokens = []
    for part in pattern.parts:
        if part.kind == "literal":
            tokens.extend(("literal", char) for char in part.text.casefold())
        else:
            tokens.append((part.kind, ""))
    text = value.casefold()
    pos = source = 0
    star = -1
    retry = 0
    while source < len(text):
        budget.tick()
        if pos < len(tokens) and (tokens[pos][0] == "one" or tokens[pos] == ("literal", text[source])):
            source += 1
            pos += 1
        elif pos < len(tokens) and tokens[pos][0] == "any":
            star, retry = pos, source
            pos += 1
        elif star >= 0:
            retry += 1
            source, pos = retry, star + 1
        else:
            return False
    while pos < len(tokens) and tokens[pos][0] == "any":
        budget.tick()
        pos += 1
    return pos == len(tokens)


def _regex(pattern: str, text: str, budget: _Budget) -> bool:
    budget.tick()
    budget.regex_calls += 1
    if budget.regex_calls > budget.limits.max_regex_calls:
        raise _Stopped("regex_call_limit")
    timeout = min(budget.limits.regex_timeout_seconds, budget.deadline - time.monotonic())
    if timeout <= 0:
        raise _Stopped("time_limit")
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(_REGEX_WORKER)],
            input=json.dumps([pattern, text]), text=True, capture_output=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        # subprocess.run kills and reaps the child before propagating timeout.
        raise _Stopped("regex_timeout") from None
    except OSError:
        raise _Stopped("regex_worker_failed") from None
    budget.tick()
    if result.returncode or result.stdout not in ("0", "1"):
        raise _Stopped("regex_invalid_or_resource_limit")
    return result.stdout == "1"


def _compare(value: IRValue, native, budget: _Budget) -> bool:
    budget.tick()
    if value.kind == "null":
        return native is None
    if native is None:
        raise _Stopped("field_null")
    if value.kind == "number":
        # Native XML payloads are strings; never coerce bool, floats or hex
        # strings to a decimal comparison or round large integer values.
        if type(native) is int:
            return native == value.scalar
        if not native or len(native) > 21:
            return False
        signless = native[1:] if native[:1] in ("+", "-") else native
        return bool(signless) and signless.isascii() and signless.isdecimal() and int(native) == value.scalar
    text = str(native)
    if value.kind == "regex":
        return _regex(value.scalar, text, budget)
    return _glob(text, value, budget)


def _evaluate(node: IRExpression, values: dict, unavailable: set[str], budget: _Budget):
    """Three-valued logic; an unavailable negated filter cannot become true."""
    budget.tick()
    if node.op == "compare":
        if node.field in unavailable:
            return None, {"field_unavailable"}
        if node.field not in values:
            return None, {"field_missing"}
        native = values[node.field]
        items = native if type(native) is tuple else (native,)
        if not items:
            return None, {"field_empty_collection"}
        unknown = set()
        for item in items:
            if item is None and node.value.kind != "null":
                unknown.add("field_null")
            elif _compare(node.value, item, budget):
                return True, set()
        return (None, unknown) if unknown else (False, set())
    if node.op == "not":
        result, reasons = _evaluate(node.args[0], values, unavailable, budget)
        return (None if result is None else not result), reasons
    unknown = set()
    for arg in node.args:
        result, reasons = _evaluate(arg, values, unavailable, budget)
        if node.op == "and" and result is False or node.op == "or" and result is True:
            return result, set()
        unknown.update(reasons)
    return (None, unknown) if unknown else (node.op == "and", set())


def match_rule(rule: CompiledRule, fields: Mapping[str, object], *,
               unavailable: Mapping[str, str] | None = None,
               limits: MatchLimits = MatchLimits()) -> MatchResult:
    """Match one compiled plan against bounded native fields, with no IO to SLI.

    Missing, explicit null and empty text are distinct. No truncation, rendered
    message fallback, source admission or finding/risk publication occurs here.
    Replay hashes bind plan, matcher, limits and required field values; they are
    not event identities or EvidenceRefs. Elapsed time/PIDs never enter a hash.
    """
    from server.sli.sigma.compiler import COMPILER_VERSION, IR_VERSION, MAPPING_VERSION, PARSER_VERSION, CompiledRule

    budget = _Budget(limits, time.monotonic() + limits.timeout_seconds)
    fingerprint = {"matcher": MATCHER_VERSION, "limits": asdict(limits)}
    try:
        if (type(rule) is not CompiledRule or rule.ir_version != IR_VERSION
                or rule.compiler_version != COMPILER_VERSION or rule.mapping_version != MAPPING_VERSION
                or rule.parser_version != PARSER_VERSION):
            raise _Stopped("ir_version_unsupported")
        required = set()
        _validate(rule.expression, budget, required)
        if rule.required_fields != tuple(sorted(required)):
            raise _Stopped("invalid_ir")
        fingerprint["plan"] = rule.plan_sha256
        values, snapshot = {}, {}
        unavailable_fields = set()
        for name in sorted(required):
            budget.tick()
            if unavailable is not None and name in unavailable:
                unavailable_fields.add(name)
                snapshot[name] = ["unavailable"]
            elif name not in fields:
                snapshot[name] = ["missing"]
            else:
                native = fields[name]
                items = native if type(native) is tuple else (native,)
                if len(items) > limits.max_values:
                    raise _Stopped("field_value_limit")
                for item in items:
                    if type(item) not in (str, int, type(None)):
                        raise _Stopped("field_type_unsupported")
                    if type(item) is str and len(item) > limits.max_field_chars:
                        raise _Stopped("field_size_limit")
                    if type(item) is int and item.bit_length() > 64:
                        raise _Stopped("field_size_limit")
                    budget.tick(len(item) if type(item) is str else 1)
                values[name] = native
                snapshot[name] = ["present", native]
        fingerprint["fields"] = snapshot
        result, reasons = _evaluate(rule.expression, values, unavailable_fields, budget)
        status = "not_evaluable" if result is None else "matched" if result else "not_matched"
    except _Stopped as error:
        status, reasons = "not_evaluable", {str(error)}
    fingerprint.update(status=status, reasons=sorted(reasons))
    raw = json.dumps(fingerprint, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    digest = hashlib.sha256(raw.encode("ascii")).hexdigest()
    return MatchResult(status, tuple(sorted(reasons)), digest)
