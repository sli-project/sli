"""Read-only validation of a selected, immutable plugin generation."""

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from deploy.linux.installed_state import PackageError, canonical_json, require_native

ROOT = Path(__file__).resolve().parents[2]


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def invalid_number(_value):
    raise ValueError("invalid JSON number")


def read_json(raw):
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=invalid_number, parse_float=invalid_number)
    except (ValueError, RecursionError) as exc:
        raise PackageError("invalid JSON document") from exc


def plain_file(path, root):
    try:
        require_native(path.resolve(strict=True).is_relative_to(root.resolve(strict=True)),
                       "source must be inside input root")
        for part in (path, *path.parents):
            require_native(not (part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction())),
                           "source links and reparse points are not allowed")
            if part == root:
                break
        require_native(path.is_file(), "source must be a regular file")
    except OSError as exc:
        raise PackageError("source is missing or inaccessible") from exc
    return path


UI_API = "sli.plugin-ui.v1"

PLUGIN_ID = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+")

ASSET_PATH = re.compile(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*\.js")

SHA256 = re.compile(r"[0-9a-f]{64}")

class PluginUiError(ValueError):
    """Only stable codes, never filesystem paths or package contents, reach UI."""

def validate_descriptor(value: Any, plugin_id: str) -> dict[str, Any]:
    if not PLUGIN_ID.fullmatch(plugin_id):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if not isinstance(value, dict) or value.get("plugin_id") != plugin_id:
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if value.get("ui_api") != UI_API:
        raise PluginUiError("plugin_ui_unsupported_api")
    if set(value) != {"plugin_id", "ui_api", "version", "routes", "entry", "required_capabilities"}:
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if not isinstance(value["version"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", value["version"]):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    routes = value["routes"]
    prefix = f"/extensions/{plugin_id}/"
    if not isinstance(routes, list) or not routes or len(routes) > 32:
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if any(not isinstance(route, str) or not route.startswith(prefix)
           or not re.fullmatch(r"[a-z0-9]+(?:[/-][a-z0-9]+)*", route[len(prefix):]) for route in routes):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if len(set(routes)) != len(routes):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    entry = value["entry"]
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if not isinstance(entry["path"], str) or not ASSET_PATH.fullmatch(entry["path"]):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if not isinstance(entry["sha256"], str) or not SHA256.fullmatch(entry["sha256"]):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    capabilities = value["required_capabilities"]
    if not isinstance(capabilities, list) or len(capabilities) > 32 or any(
        not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,95}", item)
        for item in capabilities
    ):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    if len(set(capabilities)) != len(capabilities):
        raise PluginUiError("plugin_ui_invalid_descriptor")
    return value


ALLOWLIST = {
    ("sli.remote-access", "radius-session-observation", "1.0.0"): ("light", "vpn-read"),
    ("sli.remote-access", "radius-acquisition", "1.0.0"): ("light", "vpn-read"),
    ("sli.ad", "ad-snapshot-manifest-coordinator", "1.0.0"): ("heavy", "ad-read"),
    ("sli.ad", "ad-snapshot-projection", "1.0.0"): ("heavy", "ad-read"),
    ("sli.ad", "ad-context-snapshot", "1.0.0"): ("heavy", "ad-read"),
    ("sli.ad", "computers-v6-source", "1.0.0"): ("heavy", "ad-read"),
    ("sli.ad", "users-report-v2-snapshot", "1.0.0"): ("heavy", "ad-read"),
    ("sli.gpo", "gpo-snapshot", "1.0.0"): ("long", "gpo-read"),
    ("sli.gpo", "gpo-acquisition", "1.0.0"): ("long", "gpo-read"),
    ("sli.workstations", "workstations.evidence-retention", "1.0.0"): ("light", "workstations-retention"),
    ("sli.workstations", "workstations.overview-project", "1.0.0"): ("light", "workstations-projection"),
}


def validate_shape(value, node: dict, schema: dict) -> None:
    """Validate the vocabulary used by the bundled v3 schema without extra deps."""
    if "$ref" in node:
        return validate_shape(value, schema["$defs"][node["$ref"].split("/")[-1]], schema)
    if "oneOf" in node:
        matches = 0
        for option in node["oneOf"]:
            try:
                validate_shape(value, option, schema)
                matches += 1
            except ValueError:
                pass
        if matches != 1:
            raise ValueError("manifest_shape_invalid")
    types = {"object": dict, "array": list, "string": str, "integer": int,
             "boolean": bool, "null": type(None)}
    declared = node.get("type")
    if declared is not None:
        choices = declared if isinstance(declared, list) else [declared]
        if not any(type(value) is types[choice] for choice in choices):
            raise ValueError("manifest_shape_invalid")
    if ("const" in node and (value != node["const"] or
            type(node["const"]) is bool and type(value) is not bool)
            or "enum" in node and value not in node["enum"]):
        raise ValueError("manifest_shape_invalid")
    if value is None:
        return
    if isinstance(value, dict):
        properties = node.get("properties", {})
        if not set(node.get("required", [])).issubset(value):
            raise ValueError("manifest_shape_invalid")
        if node.get("additionalProperties") is False and set(value)-set(properties):
            raise ValueError("manifest_shape_invalid")
        for key, item in value.items():
            if "propertyNames" in node:
                validate_shape(key, node["propertyNames"], schema)
            if key in properties:
                validate_shape(item, properties[key], schema)
            elif isinstance(node.get("additionalProperties"), dict):
                validate_shape(item, node["additionalProperties"], schema)
    if isinstance(value, list):
        if not node.get("minItems", 0) <= len(value) <= node.get("maxItems", len(value)):
            raise ValueError("manifest_shape_invalid")
        if node.get("uniqueItems") and len({canonical_json(item) for item in value}) != len(value):
            raise ValueError("manifest_shape_invalid")
        for item in value:
            validate_shape(item, node.get("items", {}), schema)
    if isinstance(value, str) and (
        not node.get("minLength", 0) <= len(value) <= node.get("maxLength", len(value))
        or "pattern" in node and re.search(node["pattern"], value) is None
    ):
        raise ValueError("manifest_shape_invalid")
    if type(value) is int and not node.get("minimum", value) <= value <= node.get("maximum", value):
        raise ValueError("manifest_shape_invalid")

def validate_jobs(jobs):
    schema = json.loads((ROOT / "config/plugin_architecture_v3.json").read_text("utf-8"))
    validate_shape(jobs, schema, schema)

    def version(text):
        return tuple(map(int, text.split(".")))

    if not (version(jobs["core_api"]["minimum"]) <= (1, 0, 0)
            < version(jobs["core_api"]["maximum_exclusive"])):
        raise ValueError("handler_core_api_incompatible")
    if any(dep["required"] for dep in jobs["dependencies"]):
        raise ValueError("handler_dependency_unavailable")
    ids = set()
    for handler in jobs["handlers"]:
        key = (jobs["plugin_id"], handler["handler_id"], handler["handler_version"])
        profiles = (handler["resource_profile"], handler["rights_profile"])
        if ALLOWLIST.get(key) != profiles or handler["handler_id"] in ids:
            raise ValueError("handler_not_allowlisted")
        ids.add(handler["handler_id"])

    schedule_ids = set()
    for schedule in jobs["schedules"]:
        if schedule["handler_id"] not in ids or schedule["schedule_id"] in schedule_ids:
            raise ValueError("schedule_reference_invalid")
        schedule_ids.add(schedule["schedule_id"])
        trigger = schedule["trigger"]
        interval = schedule["interval_seconds"]
        calendar = schedule["calendar"]
        if (trigger == "interval" and (not interval or calendar is not None)
                or trigger == "calendar" and (calendar is None or interval is not None)
                or trigger == "input_available" and (calendar is not None or interval is not None)):
            raise ValueError("schedule_trigger_invalid")
        ZoneInfo(schedule["timezone"])
    return ids


def read_object(path):
    value = read_json(path.read_bytes())
    require_native(isinstance(value, dict), "expected a JSON object")
    return value


def validate_payload(path, manifest):
    for item in manifest["files"]:
        local = plain_file(path / item["path"], path)
        require_native(local.stat().st_size == item["size"], "update_plugin_payload_changed")
        with local.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        require_native(checksum == item["sha256"], "update_plugin_payload_changed")

    descriptor = validate_descriptor(read_object(path / "ui/descriptor.json"), manifest["plugin_id"])
    files = {row["path"]: row for row in manifest["files"]}
    entry = files.get("ui/" + descriptor["entry"]["path"])
    require_native(entry is not None and entry["sha256"] == descriptor["entry"]["sha256"]
                   and entry["size"] <= 4 * 1024 * 1024
                   and descriptor["version"] == manifest["plugin_version"]
                   and {name for name in files if name.startswith("ui/")} == {"ui/descriptor.json", entry["path"]},
                   "update_plugin_ui_mismatch")
    jobs = read_object(path / "backend/jobs-v3.json")
    handler_ids = validate_jobs(jobs)
    require_native(jobs["plugin_id"] == manifest["plugin_id"] and jobs["plugin_version"] == manifest["plugin_version"]
                   and handler_ids == set(manifest["handlers"]), "update_plugin_handler_mismatch")
    require_native(jobs["core_api"] == manifest["core_api"], "update_plugin_api_incompatible")
