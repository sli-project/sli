"""Runtime-independent plugin contracts shared by serving, jobs and updating.

Schema lookup retains the source-root layout. Packaging and authenticating this
module and its schema are separate release responsibilities.
"""
from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
FORBIDDEN_KEYS = frozenset({
    "argv", "command", "dsn", "entrypoint", "html", "import_path",
    "javascript", "password", "secret", "sql",
})


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value: Any) -> str:
    return sha256(canonical(value).encode("utf-8")).hexdigest()


UI_API = "sli.plugin-ui.v1"


PLUGIN_ID = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+")


ASSET_PATH = re.compile(r"[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*\.js")


SHA256 = re.compile(r"[0-9a-f]{64}")


MAX_ASSET_BYTES = 4 * 1024 * 1024


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


PROFILES = {
    # The pilot inherits 50 deliveries x 10,000 observations from the consumer.
    "light": (90, 256 * 1024 * 1024, 500000),
    "heavy": (300, 1024 * 1024 * 1024, 1000000),
    "long": (1800, 1024 * 1024 * 1024, 1000000),
}


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
        if node.get("uniqueItems") and len({digest(item) for item in value}) != len(value):
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


def reject_executable_material(value: Any) -> None:
    """A manifest may describe secrets with x-secret, never contain them."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key.casefold() in FORBIDDEN_KEYS:
                raise ValueError(f"executable_or_sensitive_manifest_key:{key}")
            reject_executable_material(item)
    elif isinstance(value, list):
        for item in value:
            reject_executable_material(item)


def _validate_message(key: str, messages: dict) -> None:
    for language in ("ru", "en"):
        text = messages[language].get(key)
        if not isinstance(text, str) or not text.strip() or len(text.split()) > 12:
            raise ValueError("manifest_localized_text_invalid")


def _validate_setting_schema(node: dict) -> None:
    """Check semantics JSON Schema cannot express about another schema."""
    for lower, upper in (("minimum", "maximum"), ("minLength", "maxLength"), ("minItems", "maxItems")):
        if lower in node and upper in node and node[lower] > node[upper]:
            raise ValueError("manifest_setting_bounds_invalid")
    if "pattern" in node:
        try:
            re.compile(node["pattern"])
        except re.error:
            raise ValueError("manifest_setting_pattern_invalid") from None
    types = node["type"] if isinstance(node["type"], list) else [node["type"]]
    if "array" in types and "items" not in node:
        raise ValueError("manifest_setting_items_required")
    if "object" in types and not {"properties", "required", "additionalProperties"} <= node.keys():
        raise ValueError("manifest_setting_properties_required")
    if not set(node.get("required", [])) <= node.get("properties", {}).keys():
        raise ValueError("manifest_setting_required_invalid")
    for child in node.get("properties", {}).values():
        _validate_setting_schema(child)
    if "items" in node:
        _validate_setting_schema(node["items"])
    for child in node.get("oneOf", []):
        _validate_setting_schema(child)
    if "default" in node:
        validate_shape(node["default"], node, node)


def validate_package_settings_schema(metadata: dict, *, root: Path = ROOT) -> dict:
    """Validate separate settings declarations and their existing i18n catalogs."""
    reject_executable_material(metadata)
    if not isinstance(metadata, dict) or not {
        "name", "settings", "rules", "permissions", "migration_directory"
    } <= metadata.keys():
        raise ValueError("manifest_package_metadata_required")
    schema = _load_json(root / "config/plugin_settings_schema_v1.json")
    validate_shape(metadata, schema, schema)
    messages = {language: _load_json(root / f"config/i18n/server.{language}.json")
                for language in ("ru", "en")}
    _validate_message(metadata["name"], messages)
    settings = metadata["settings"]
    if set(settings["properties"]) & set(settings["x-core-settings"]):
        raise ValueError("manifest_setting_owner_conflict")
    if not set(settings["required"]) <= settings["properties"].keys():
        raise ValueError("manifest_setting_required_invalid")
    for setting in settings["properties"].values():
        _validate_message(setting["x-label"], messages)
        _validate_message(setting["x-help"], messages)
        _validate_setting_schema(setting)
    ids = set()
    for rule in metadata["rules"]:
        if (rule["rule_id"] in ids or not set(rule["settings"]) <= settings["properties"].keys()
                or not set(rule["core_settings"]) <= set(settings["x-core-settings"])):
            raise ValueError("manifest_rule_reference_invalid")
        ids.add(rule["rule_id"])
        _validate_message(rule["name"], messages)
    return metadata


def _load_json(path: Path) -> dict:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("manifest_duplicate_json_key")
            result[key] = value
        return result

    return json.loads(path.read_text("utf-8"), object_pairs_hook=unique_object)


def _validate_plugin_id(plugin_id: str) -> None:
    if not isinstance(plugin_id, str) or not PLUGIN_ID.fullmatch(plugin_id):
        raise ValueError("manifest_plugin_id_invalid")


def load_package_settings_schema(plugin_id: str, *, root: Path = ROOT) -> dict:
    """Bind settings to the plugin key without changing its attested manifest."""
    _validate_plugin_id(plugin_id)
    path = root / f"config/plugin_settings_schema/{plugin_id}.settings.json"
    metadata = _load_json(path)
    if not isinstance(metadata, dict) or metadata.get("plugin_id") != plugin_id:
        raise ValueError("manifest_plugin_id_mismatch")
    return validate_package_settings_schema(metadata, root=root)


def validate_package_manifest(manifest: dict, *, schema: dict | None = None,
                              metadata: dict | None = None, root: Path = ROOT) -> dict:
    """Check the immutable package and separate settings before registration.

    Return the original manifest, without merging metadata into its hashed data.
    Job-only manifests retain their independent HandlerRegistry contract.
    """
    reject_executable_material(manifest)
    if schema is None:
        schema = _load_json(root / "config/plugin_architecture_v3.json")
    validate_shape(manifest, schema, schema)
    for versions in [manifest["core_api"], *(dep["versions"] for dep in manifest["dependencies"])]:
        if tuple(map(int, versions["minimum"].split("."))) >= tuple(map(int, versions["maximum_exclusive"].split("."))):
            raise ValueError("manifest_version_range_invalid")
    if metadata is None:
        metadata = load_package_settings_schema(manifest["plugin_id"], root=root)
    else:
        validate_package_settings_schema(metadata, root=root)
        if metadata["plugin_id"] != manifest["plugin_id"]:
            raise ValueError("manifest_plugin_id_mismatch")
    directory = (root / metadata["migration_directory"]).resolve()
    if not directory.is_relative_to(root.resolve()) or not directory.is_dir():
        raise ValueError("manifest_migration_directory_invalid")
    prefix = metadata["migration_directory"] + "/"
    if any(not migration["path"].startswith(prefix) for migration in manifest["data"]["migrations"]):
        raise ValueError("manifest_migration_directory_invalid")
    return manifest


def load_package_manifest(plugin_id: str, *, root: Path = ROOT) -> dict:
    """Read and validate a package and settings without executing plugin code."""
    _validate_plugin_id(plugin_id)
    manifest = _load_json(root / f"config/plugin_packages/v3/{plugin_id}.json")
    if not isinstance(manifest, dict) or manifest.get("plugin_id") != plugin_id:
        raise ValueError("manifest_plugin_id_mismatch")
    return validate_package_manifest(manifest, root=root)


class HandlerRegistry:
    def __init__(self) -> None:
        self.handlers: dict[tuple, dict] = {}
        self.manifests: list[dict] = []

    def register(self, manifest: dict) -> None:
        # Validate the complete v3 shape before accepting executable declarations.
        schema = json.loads((ROOT / "config/plugin_architecture_v3.json").read_text("utf-8"))
        validate_shape(manifest, schema, schema)

        def version(text):
            return tuple(map(int, text.split(".")))

        if not (version(manifest["core_api"]["minimum"]) <= (1, 0, 0)
                < version(manifest["core_api"]["maximum_exclusive"])):
            raise ValueError("handler_core_api_incompatible")
        if any(dep["required"] for dep in manifest["dependencies"]):
            raise ValueError("handler_dependency_unavailable")
        manifest_hash = digest(manifest)
        pending = {}
        ids = set()
        for handler in manifest["handlers"]:
            key = (manifest["plugin_id"], handler["handler_id"], handler["handler_version"])
            profiles = (handler["resource_profile"], handler["rights_profile"])
            if ALLOWLIST.get(key) != profiles or handler["handler_id"] in ids:
                raise ValueError("handler_not_allowlisted")
            ids.add(handler["handler_id"])
            pinned = (*key, manifest["plugin_version"], manifest_hash)
            if pinned in self.handlers:
                raise ValueError("handler_registration_duplicate")
            limits = PROFILES[profiles[0]]
            budget = dict(handler["budget"])
            for field, cap in zip(("wall_seconds", "memory_bytes", "max_records"), limits):
                budget[field] = min(budget[field], cap)
            budget["cpu_seconds"] = min(budget["cpu_seconds"], limits[0])
            budget["max_result_bytes"] = min(budget["max_result_bytes"], 65536)
            budget["max_db_connections"] = 1
            budget["statement_timeout_ms"] = min(budget["statement_timeout_ms"], 10000)
            budget["lock_timeout_ms"] = min(budget["lock_timeout_ms"], 1000)
            pending[pinned] = {**handler, "budget": budget,
                               "plugin_version": manifest["plugin_version"],
                               "manifest_sha256": manifest_hash}
        schedule_ids = set()
        for schedule in manifest["schedules"]:
            if schedule["handler_id"] not in ids or schedule["schedule_id"] in schedule_ids:
                raise ValueError("schedule_reference_invalid")
            schedule_ids.add(schedule["schedule_id"])
            trigger = schedule["trigger"]
            if (trigger == "interval" and (not schedule["interval_seconds"] or schedule["calendar"] is not None)
                    or trigger == "calendar" and (schedule["calendar"] is None or schedule["interval_seconds"] is not None)
                    or trigger == "input_available" and (schedule["calendar"] is not None or schedule["interval_seconds"] is not None)):
                raise ValueError("schedule_trigger_invalid")
            ZoneInfo(schedule["timezone"])
        self.handlers.update(pending)
        self.manifests.append(manifest)

    def identities(self, profile: str) -> list[dict]:
        return [{"plugin_id": key[0], "handler_id": key[1], "handler_version": key[2],
                 "plugin_version": key[3], "manifest_sha256": key[4]}
                for key, handler in self.handlers.items() if handler["resource_profile"] == profile]

    def resolve(self, job: dict) -> dict:
        key = tuple(job[name] for name in (
            "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256"))
        handler = self.handlers.get(key)
        if handler is None or any(job[name] != handler[name] for name in (
                "resource_profile", "rights_profile", "input_contract", "result_contract", "budget", "max_attempts")):
            raise ValueError("handler_version_unavailable")
        if job["job_type"] != handler["kind"]:
            raise ValueError("handler_version_unavailable")
        if digest(job["pinned_input"]) != job["input_sha256"]:
            raise ValueError("job_input_hash_conflict")
        return handler
