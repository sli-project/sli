"""In-place v3 report ownership and navigation; never authorizes data access."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from psycopg import Error

from server.sli.plugins.registry import BUNDLED, registered_plugins
from server.sli.sources.plugin_state import list_plugin_states

ROOT = Path(__file__).resolve().parents[3]
PLUGIN_IDS = frozenset({"sli.ad", "sli.gpo", "sli.remote-access", "sli.workstations", "sli.file-audit"})
PLUGIN_SECTIONS = {
    "sli.ad": "active-directory",
    "sli.gpo": "group-policies",
    "sli.remote-access": "remote-access",
    "sli.workstations": "workstations",
    "sli.file-audit": "file-audit",
}


def _validate_shape(value: Any, rule: Mapping[str, Any], schema: Mapping[str, Any]) -> None:
    """Validate the declarative subset used by the bundled stage-2 manifests."""
    if "$ref" in rule:
        rule = schema["$defs"][rule["$ref"].rsplit("/", 1)[1]]
    types = {"object": dict, "array": list, "string": str, "integer": int,
             "boolean": bool, "null": type(None)}
    expected = rule.get("type", [])
    expected = [expected] if isinstance(expected, str) else expected
    if expected and type(value) not in [types[name] for name in expected]:
        raise ValueError("navigation_manifest_type_invalid")
    # 0 == False in Python: a const of another type is a type error, not a value error.
    if "const" in rule and type(value) is not type(rule["const"]):
        raise ValueError("navigation_manifest_type_invalid")
    if ("const" in rule and value != rule["const"]) or ("enum" in rule and value not in rule["enum"]):
        raise ValueError("navigation_manifest_value_invalid")
    if isinstance(value, dict):
        properties = rule.get("properties", {})
        if not set(rule.get("required", [])).issubset(value):
            raise ValueError("navigation_manifest_field_required")
        if rule.get("additionalProperties") is False and set(value) - set(properties):
            raise ValueError("navigation_manifest_unknown_field")
        for key in value.keys() & properties.keys():
            _validate_shape(value[key], properties[key], schema)
    elif isinstance(value, list):
        if len(value) < rule.get("minItems", 0):
            raise ValueError("navigation_manifest_array_invalid")
        if rule.get("uniqueItems") and len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
            raise ValueError("navigation_manifest_duplicate_item")
        for item in value:
            _validate_shape(item, rule.get("items", {}), schema)
    elif isinstance(value, str):
        if not rule.get("minLength", 0) <= len(value) <= rule.get("maxLength", len(value)):
            raise ValueError("navigation_manifest_string_invalid")
        if "pattern" in rule and re.search(rule["pattern"], value) is None:
            raise ValueError("navigation_manifest_string_invalid")
    elif type(value) is int:
        if not rule.get("minimum", value) <= value <= rule.get("maximum", value):
            raise ValueError("navigation_manifest_number_invalid")


def validate_registry(registry: dict, manifests: Sequence[dict], schema: dict) -> dict[str, dict]:
    """Reject duplicate owners and unresolved declarations before contributing UI."""
    owners = {key: {"owner_id": "sli.core", "section_id": section}
              for key, section in registry["core_reports"].items()}
    sections = {section["id"]: section for section in registry["sections"]}
    if len(sections) != len(registry["sections"]):
        raise ValueError("navigation_duplicate_section")
    if registry["contract_id"] != "sli.navigation.v3" or any(
        section not in sections or section not in {"overview", "investigation", "operations", "admin"}
        for section in registry["core_reports"].values()
    ):
        raise ValueError("navigation_core_section_invalid")
    seen = set()
    routes = set()
    plugin_datasets: dict[str, set[str]] = {}
    for manifest in manifests:
        _validate_shape(manifest, schema, schema)
        plugin_id = manifest["plugin_id"]
        if plugin_id not in PLUGIN_IDS or plugin_id in seen:
            raise ValueError("navigation_plugin_id_invalid")
        seen.add(plugin_id)
        # This adapter registers reports only. Runtime/storage cutover belongs
        # to later stages; never interpret future executable declarations here.
        if plugin_id not in {"sli.workstations", "sli.file-audit"} and (any(manifest[key] for key in ("sources", "agent_modules", "handlers", "schedules", "dependencies", "home_widgets")) or manifest["data"]["migrations"]):
            raise ValueError("navigation_manifest_not_in_place")
        if plugin_id == "sli.file-audit":
            from server.sli.plugins.file_audit.manifest import validate_manifest
            validate_manifest(manifest)
        if plugin_id == "sli.workstations":
            # Declarative contributions only: queue/identity adapters own all
            # execution. This registry does not run jobs or apply migrations.
            if (manifest["agent_modules"] or manifest["home_widgets"]
                    or [item["handler_id"] for item in manifest["handlers"]] != ["workstations.evidence-retention"]
                    or any(item["handler_id"] != "workstations.evidence-retention" for item in manifest["schedules"])):
                raise ValueError("navigation_workstation_declarations_invalid")
        def version(value):
            return tuple(map(int, value.split(".")))
        api = manifest["core_api"]
        if not version(api["minimum"]) <= (3, 0, 0) < version(api["maximum_exclusive"]):
            raise ValueError("navigation_core_api_incompatible")
        datasets = {item["dataset_id"]: item for item in manifest["datasets"]}
        plugin_datasets[plugin_id] = set(datasets)
        if len(datasets) != len(manifest["datasets"]):
            raise ValueError("navigation_duplicate_dataset")
        contributed = {item["section_id"] for item in manifest["navigation"]}
        if len(contributed) != len(manifest["navigation"]):
            raise ValueError("navigation_duplicate_section")
        if contributed != {PLUGIN_SECTIONS[plugin_id]}:
            raise ValueError("navigation_plugin_section_invalid")
        for section in manifest["navigation"]:
            if section["section_id"] not in sections or sections[section["section_id"]]["title"] != section["title_key"] or section["parent_section_id"] is not None:
                raise ValueError("navigation_section_invalid")
        for report in manifest["reports"]:
            key = report["report_key"]
            if key in owners:
                raise ValueError("navigation_duplicate_report_owner")
            if report["section_id"] not in contributed or report["dataset_id"] not in datasets:
                raise ValueError("navigation_report_reference_invalid")
            if datasets[report["dataset_id"]]["reader_id"] != report["history_reader_id"]:
                raise ValueError("navigation_history_reader_invalid")
            if routes.intersection(report["routes"]):
                raise ValueError("navigation_duplicate_route")
            routes.update(report["routes"])
            owners[key] = {**report, "owner_id": plugin_id}
    if seen != PLUGIN_IDS or set(registry["enabled_plugins"]) - seen:
        raise ValueError("navigation_plugin_set_invalid")
    entries = [entry for section in sections.values() for group in section["groups"] for entry in group["entries"]]
    if len({entry["id"] for entry in entries}) != len(entries):
        raise ValueError("navigation_duplicate_entry")
    for section in sections.values():
        section_owner = next((plugin_id for plugin_id, section_id in PLUGIN_SECTIONS.items() if section_id == section["id"]), None)
        for group in section["groups"]:
            for entry in group["entries"]:
                if entry.get("plugin_id") != section_owner:
                    raise ValueError("navigation_entry_reference_invalid")
                if not set(entry.get("datasets", [])).issubset(plugin_datasets.get(section_owner, set())):
                    raise ValueError("navigation_dataset_owner_invalid")
                if section_owner is None:
                    continue
                views = entry.get("views", [])
                if views and (len({view["id"] for view in views}) != len(views)
                              or entry["path"] != views[0]["path"]
                              or set(entry["reports"]) != {key for view in views for key in view["reports"]}):
                    raise ValueError("navigation_view_reference_invalid")
                for contribution in views or [entry]:
                    report = next((item for item in owners.values() if contribution["path"] in item.get("routes", [])), None)
                    if (report is None or report["owner_id"] != entry["plugin_id"]
                            or report["section_id"] != section["id"]
                            or report["title_key"] != contribution["label"]
                            or report["access_key"] not in contribution["reports"]
                            or (views and (report["report_key"] != contribution["report_key"]
                                           or not set(contribution["reports"]).issubset({report["report_key"], report["access_key"]})))):
                        raise ValueError("navigation_entry_reference_invalid")
    destinations = {entry["path"]: entry for entry in entries}
    redirects = registry.get("redirects", [])
    if len({item["from"] for item in redirects}) != len(redirects):
        raise ValueError("navigation_duplicate_redirect")
    for item in redirects:
        target = destinations.get(item["to"])
        if item["from"] == item["to"] or item["to"] in {rule["from"] for rule in redirects}:
            raise ValueError("navigation_redirect_invalid")
        if "view" in item:
            view = next((view for view in (target or {}).get("views", []) if view["id"] == item["view"]), None)
            if view is None or (item["from"].startswith("/report/") and view["path"] != item["from"]):
                raise ValueError("navigation_redirect_invalid")
        elif item["to"] != registry["global_search"]["path"]:
            raise ValueError("navigation_redirect_invalid")
    for report in list(owners.values()):
        if "access_key" not in report:
            continue
        alias = report["access_key"]
        if alias in owners and owners[alias]["owner_id"] != report["owner_id"]:
            raise ValueError("navigation_duplicate_access_owner")
        owners.setdefault(alias, report)
    return owners


@lru_cache(maxsize=1)
def load_registry() -> tuple[dict, dict[str, dict]]:
    def read(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    registry = read(ROOT / "config/navigation_v3.json")
    # Navigation metadata can advance without rewriting the attested package
    # or changing the independent job manifests pinned by queued work.
    manifests = [read(ROOT / "config/plugin_packages/v3" / (
        "sli.workstations.1.1.0.json" if plugin_id == "sli.workstations" else f"{plugin_id}.json"
    )) for plugin_id in sorted(PLUGIN_IDS)]
    owners = validate_registry(registry, manifests, read(ROOT / "config/plugin_architecture_v3.json"))
    return registry, owners


def navigation_plugin_states() -> list[dict]:
    """Observe existing durable activation without changing lifecycle or workers."""
    try:
        states = list_plugin_states()
    except (Error, RuntimeError):
        states = []
    if not any(item["plugin_id"] == "sli.remote-access" for item in states):
        states = [*states, {"plugin_id": "sli.remote-access", "enabled": False}]
    return states


def navigation(access: Mapping[str, Any], plugin_states: Sequence[Mapping[str, Any]] = ()) -> dict:
    registry, _ = load_registry()
    enabled = set(registry["enabled_plugins"])
    enabled.difference_update(set(BUNDLED) - set(registered_plugins()))
    for state in plugin_states:
        if state.get("enabled") is not True:
            enabled.discard(state["plugin_id"])
    reports = {item["report_key"] for item in access.get("reports", []) if item.get("allowed")}
    capabilities = set(access.get("capabilities", []))

    def visible(entry: dict) -> bool:
        return ("plugin_id" not in entry or entry["plugin_id"] in enabled) and bool(
            entry.get("always") or reports.intersection(entry.get("reports", [])) or capabilities.intersection(entry.get("capabilities", []))
        )

    sections = []
    for section in registry["sections"]:
        groups = [{**group, "entries": [
            {**entry, **({"views": [view for view in entry["views"] if visible(view)]} if "views" in entry else {})}
            for entry in group["entries"] if visible(entry)
        ]} for group in section["groups"]]
        groups = [group for group in groups if group["entries"]]
        if groups:
            sections.append({**section, "groups": groups})
    return {"contract_id": registry["contract_id"], "enabled_plugins": sorted(enabled),
            "global_search": registry["global_search"], "redirects": registry["redirects"], "sections": sections}
