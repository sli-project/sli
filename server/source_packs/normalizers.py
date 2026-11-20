from __future__ import annotations

"""Allowlisted source normalizers referenced by declarative pack manifests."""

from collections.abc import Callable, Mapping
from typing import Any

from server.source_packs.normalizer_types import (  # noqa: F401 - re-exported contract
    AccountEventResolver,
    ContextualClassifier,
    CorrelationNormalizer,
    EntitySemanticsNormalizer,
    EventFactsNormalizer,
    EventIdFamilyResolver,
    EventLabelResolver,
    FindingRulesResolver,
    ImportantEventIdsResolver,
    InvestigationCategoryResolver,
    InvestigationCheckResolver,
    InvestigationEventIdsResolver,
    SecurityMonitorGroupsResolver,
    SemanticCoreRoleFiltersResolver,
    SemanticEventIdentitiesResolver,
    SemanticProjectionNormalizer,
    SourceNormalizer,
    StateSemanticsNormalizer,
)
from server.sli.plugins.registry import NORMALIZER_OWNERS
_NORMALIZERS: Mapping[str, SourceNormalizer] = {}


def get_source_normalizer(normalizer_id: str | None) -> SourceNormalizer | None:
    """Manifest v2 entry points first, then the bundled v1 table (ADR 0012)."""
    key = str(normalizer_id or "").strip()
    owner = NORMALIZER_OWNERS.get(key)
    if owner is not None:
        from server.sli.plugins.registry import plugin_hook

        hook = plugin_hook(owner, f"normalizer:{key}")
        return hook() if hook is not None else None
    local = _ENTRY_NORMALIZERS.get(key) or _NORMALIZERS.get(key)
    if local is not None:
        return local
    from server.sli.plugins.registry import registered_plugins

    for plugin in registered_plugins().values():
        hook = plugin.hooks.get(f"normalizer:{key}")
        if hook is not None:
            return hook()
    return None


# --- Manifest v2 entry points (ADR 0012) -------------------------------------

#: Only these module namespaces may be named by a manifest ``normalizer_entry``:
#: bundled packs and installed external packs. A manifest never imports
#: arbitrary code.
ALLOWED_ENTRY_PREFIXES: tuple[str, ...] = ("server.source_packs.", "sli_source_packs.")
REQUIRED_HANDLERS: tuple[str, ...] = ("event_facts", "entity_semantics", "event_label")

# Handlers a simple source may omit, with safe defaults: no correlation, no
# state, no families, no finding rules, no investigation hints, no semantics.
_OPTIONAL_DEFAULTS: Mapping[str, Callable[..., Any]] = {
    "correlation_id": lambda **_kwargs: None,
    "state_semantics": lambda **_kwargs: None,
    "contextual_classification": lambda _row: {},
    "account_event": lambda _event_id: None,
    "event_ids_for_search_family": lambda _family: (),
    "event_ids_for_analysis_family": lambda _family: (),
    "important_account_event_ids": lambda: (),
    "finding_rules": dict,
    "investigation_event_ids": lambda _family: (),
    "investigation_category": lambda _event_id: "other",
    "investigation_check": lambda _category: None,
    "security_monitor_groups": lambda: (),
    "monitor_privileged_event_ids": lambda: (),
    "semantic_projection": lambda **_kwargs: {},
    "semantic_event_identities": lambda _types: (),
    "semantic_core_role_filters": lambda _type, _roles, _triggers: None,
}

_ENTRY_NORMALIZERS: dict[str, SourceNormalizer] = {}


def load_normalizer_entry(normalizer_id: str, entry: str) -> SourceNormalizer:
    """Builds a normalizer from ``"module:object"``.

    ``object`` is a ``SourceNormalizer`` or any namespace (module, class,
    instance) exposing the handlers by their ``SourceNormalizer`` field names.
    The three core handlers are required; the rest get safe defaults.
    """
    import importlib

    module_name, _, attribute = str(entry or "").partition(":")
    if not module_name or not attribute or not module_name.startswith(ALLOWED_ENTRY_PREFIXES):
        raise ValueError(f"normalizer entry is not allowed: {entry}")
    target = getattr(importlib.import_module(module_name), attribute)
    if isinstance(target, SourceNormalizer):
        return target
    handlers: dict[str, Any] = {}
    for name in REQUIRED_HANDLERS:
        handler = getattr(target, name, None)
        if not callable(handler):
            raise ValueError(f"normalizer {normalizer_id} lacks required handler: {name}")  # noqa: TRY004 - a manifest error, reported like the others
        handlers[name] = handler
    for name, default in _OPTIONAL_DEFAULTS.items():
        handler = getattr(target, name, None)
        handlers[name] = handler if callable(handler) else default
    return SourceNormalizer(normalizer_id=normalizer_id, **handlers)


def register_source_normalizer(normalizer: SourceNormalizer) -> None:
    """Makes an entry-point normalizer resolvable by id; bundled ids cannot be replaced."""
    reserved = normalizer.normalizer_id in _NORMALIZERS or normalizer.normalizer_id in NORMALIZER_OWNERS
    if reserved and get_source_normalizer(normalizer.normalizer_id) is not normalizer:
        raise ValueError(f"normalizer id is reserved by a bundled pack: {normalizer.normalizer_id}")
    _ENTRY_NORMALIZERS[normalizer.normalizer_id] = normalizer
