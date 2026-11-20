"""Report registry (ADR 0010 §3): declarations are discovered from ``reports/``."""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Mapping
from dataclasses import replace
from functools import lru_cache
from typing import Any

from server.sli.plugins.registry import PLUGIN_REPORT_MODULES, registered_plugins
from server.sli.plugins.update_runtime import (
    admission,
    fenced,
    generation,
    optional_admission,
)
from server.sli.reporting.navigation_registry import load_registry, navigation
from server.sli.reporting.report_intent_contract import validate_report_intent
from server.sli.reporting.v2.access import ReportAccess, report_grant
from server.sli.reporting.v2.definition import ReportDefinition

SECTION_TITLES = {
    "investigation": "Расследование",
    "reports/identity": "Учётные записи и AD",
    "reports/computers": "Компьютеры",
    "reports/policies": "Политики",
    "reports/remote-access": "Удалённый доступ",
    "reports/workstations": "Рабочие станции",
    "reports/file-audit": "Аудит файловых серверов MS",
    "operations": "Операции",
    "admin": "Администрирование",
}

# Transitional exceptions are only for absent passports, never malformed ones.
# All current v2 declarations are migrated; the test pins an empty ceiling.
UNMIGRATED_REPORT_INTENTS: frozenset[str] = frozenset()


def validate_report_intents(definitions: tuple[ReportDefinition, ...]) -> None:
    missing = {definition.key for definition in definitions if definition.intent is None}
    for definition in definitions:
        if definition.intent is None:
            if definition.key not in UNMIGRATED_REPORT_INTENTS:
                raise ValueError(f"report_intent_missing:{definition.key}")
        else:
            definition.intent.validate()
            validate_report_intent(definition.intent_contract())
    if UNMIGRATED_REPORT_INTENTS - missing:
        raise ValueError("report_intent_allowlist_obsolete")


@lru_cache(maxsize=2)
def _registered_reports(generations, *, validate_intents: bool = False) -> tuple[ReportDefinition, ...]:
    """Discover reports; CI opts into passport validation without blocking runtime."""
    from server.sli.reporting.v2 import reports as package

    found: list[ReportDefinition] = []
    modules = sorted(pkgutil.iter_modules(package.__path__), key=lambda item: item.name)
    scan_order = {module.name: index for index, module in enumerate(modules)}
    positions = {}
    for module_info in modules:
        if module_info.name in PLUGIN_REPORT_MODULES:
            continue  # Its installed owner contributes the definition.
        module = importlib.import_module(f"{package.__name__}.{module_info.name}")
        definition = getattr(module, "REPORT", None)
        if isinstance(definition, ReportDefinition):
            found.append(definition)
            positions[definition.key] = scan_order[module_info.name]
    for plugin_id, plugin in registered_plugins().items():
        if fenced(plugin_id):
            continue  # A draining extension must not block core report discovery.
        if "reports" in plugin.hooks:
            with optional_admission(plugin_id) as admitted:
                if not admitted:
                    continue
                token = generation(plugin_id)
                for definition in plugin.hooks["reports"]():
                    if plugin_id == "sli.ad":
                        # Keep relocated declarations in their former catalog slots.
                        positions[definition.key] = scan_order.get(definition.query.__module__.rsplit(".", 1)[-1], len(scan_order))
                    elif plugin_id == "sli.gpo":
                        positions[definition.key] = scan_order.get("gpo", len(scan_order))
                    def guard(callback, plugin_id=plugin_id, token=token):
                        if callback is None:
                            return None
                        def invoke(*args, **kwargs):
                            with admission(plugin_id):
                                if generation(plugin_id) != token:
                                    raise RuntimeError("plugin_version_changed")
                                return callback(*args, **kwargs)
                        return invoke
                    detail = definition.detail
                    if not isinstance(detail, str):
                        detail = replace(detail, query=guard(detail.query))
                    found.append(replace(definition, query=guard(definition.query), export_csv=guard(definition.export_csv),
                                         options=guard(definition.options), detail=detail))
    found.sort(key=lambda definition: positions.get(definition.key, len(scan_order)))
    from server.sli.plugins.workstations.overview import (
        make_report as make_workstation_overview,
    )
    from server.sli.plugins.workstations.reports import REPORTS, make_report
    found.extend(make_report(family) for family in REPORTS)
    found.append(make_workstation_overview())
    keys = [definition.key for definition in found]
    if len(keys) != len(set(keys)):
        raise RuntimeError("duplicate report key in reporting_v2 registry")
    _, owners = load_registry()
    for definition in found:
        if definition.section not in SECTION_TITLES:
            raise RuntimeError(f"unknown report section {definition.section!r} for {definition.key}")
        owner = owners.get(definition.key)
        if owner is None:
            raise RuntimeError("report_navigation_owner_missing")
        if owner["owner_id"] != "sli.core" and (
            owner["access_key"] != definition.access.report_key
            or owner["definition_id"] != definition.key
            or set(owner["required_fields"]) != set(definition.access.required_fields)
            or f"/report/{definition.key}" not in owner["routes"]
        ):
            raise RuntimeError("report_navigation_declaration_mismatch")
    definitions = tuple(found)
    if validate_intents:
        validate_report_intents(definitions)
    return definitions


def registered_reports(*, validate_intents: bool = False) -> tuple[ReportDefinition, ...]:
    tokens = tuple((plugin_id, generation(plugin_id), fenced(plugin_id)) for plugin_id in registered_plugins())
    return _registered_reports(tokens, validate_intents=validate_intents)


registered_reports.cache_clear = _registered_reports.cache_clear


def get_report(key: str) -> ReportDefinition | None:
    return next((definition for definition in registered_reports() if definition.key == key), None)


def _executable(definition: ReportDefinition, access: Mapping[str, Any]) -> bool:
    """False when the grant exists but the data call would be refused (no usable domain scope or field categories)."""
    grant = report_grant(access, definition.access.report_key)
    if not grant or "view" not in set(grant.get("allowed_actions") or []):
        return False
    try:
        ReportAccess(definition, access, "view")
    except PermissionError:
        return False
    return True


def catalog(access: Mapping[str, Any], *, plugin_states=()) -> dict[str, Any]:
    """Reports on the v2 framework that this user may open, grouped by section."""
    items = []
    _, owners = load_registry()
    for definition in registered_reports():
        if report_grant(access, definition.access.report_key) is None:
            continue
        if not getattr(definition.access, "required_capabilities", frozenset()).issubset(set(access.get("capabilities") or [])):
            continue
        items.append({
            "key": definition.key,
            "title": definition.title,
            "description": definition.description,
            "section": definition.section,
            "section_title": SECTION_TITLES[definition.section],
            "owner_id": owners.get(definition.key, {}).get("owner_id", "sli.core"),
            "navigation_section": owners.get(definition.key, {}).get("section_id", definition.section),
            "executable": _executable(definition, access),
            "home_order": definition.home_order,
            "home_view": next((view.to_json() for view in definition.views if view.key == definition.home_view), None),
        })
    return {"contract_id": "sli.report-catalog.v2", "items": items, "navigation": navigation(access, plugin_states)}
