"""Load the versioned semantic chain training pack without activating rules."""
from __future__ import annotations

import json
from pathlib import Path

from server.sli.semantic.semantic_correlation_repository import (
    CorrelationRuleDefinition,
    register_correlation_rule,
)
from server.sli.semantic.semantic_dispatch import compile_correlation_rule
from server.sli.semantic.semantic_dispatch_repository import replace_rule_subscriptions


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PACK_PATH = REPOSITORY_ROOT / "config" / "semantic_chain_pack_v1.json"


def load_dispatch_rule_pack(path: Path = DEFAULT_PACK_PATH) -> tuple[CorrelationRuleDefinition, ...]:
    """Return only DRAFT dispatcher definitions from a validated training pack.

    Loading is side-effect free: it neither registers database rules nor enables
    the worker.  The explicit maintenance command owns that later transition.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("owner") != "semantic_worker":
        raise ValueError("semantic chain pack owner must be semantic_worker")
    if raw.get("default_lifecycle") != "draft":
        raise ValueError("semantic chain pack must default to draft")
    items = raw.get("rules")
    if not isinstance(items, list) or not items:
        raise ValueError("semantic chain pack requires rules")
    rules: list[CorrelationRuleDefinition] = []
    seen: set[tuple[str, int]] = set()
    for item in items:
        if not isinstance(item, dict) or item.get("rule_kind") == "worker_assembler":
            continue
        if item.get("lifecycle_status") != "draft":
            raise ValueError("training pack dispatcher rules must remain draft")
        rule = CorrelationRuleDefinition(
            rule_id=str(item.get("rule_id") or ""),
            rule_version=int(item.get("rule_version") or 0),
            rule_kind=str(item.get("rule_kind") or ""),
            definition=dict(item.get("definition") or {}),
        )
        identity = (rule.rule_id, rule.rule_version)
        if identity in seen:
            raise ValueError("semantic chain pack has duplicate rule version")
        seen.add(identity)
        compile_correlation_rule(rule)
        rules.append(rule)
    if not rules:
        raise ValueError("semantic chain pack has no dispatcher rules")
    return tuple(rules)


def register_draft_dispatch_rule_pack(cur, path: Path = DEFAULT_PACK_PATH) -> tuple[str, ...]:
    """Persist immutable DRAFT rules and subscriptions; never activates them."""
    registered: list[str] = []
    for rule in load_dispatch_rule_pack(path):
        register_correlation_rule(cur, rule=rule)
        replace_rule_subscriptions(cur, rule=compile_correlation_rule(rule))
        registered.append(f"{rule.rule_id}@{rule.rule_version}")
    return tuple(registered)
