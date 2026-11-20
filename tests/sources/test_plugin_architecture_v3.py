"""Static checks for the proposed contract; no runtime loading or database."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

CONTRACT_PATH = Path(__file__).resolve().parents[2] / "config/plugin_architecture_v3.json"


def _nodes(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _nodes(child)


def test_v3_is_a_proposed_manifest_schema_without_runtime_configuration() -> None:
    schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    assert schema["schema_version"] == 3
    assert schema["decision_id"] == "sli.plugin-architecture.v3"
    assert schema["supersedes"] == "sli.plugin-architecture.v2"
    assert schema["status"] == "proposed"
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert {"plugin_id", "plugin_version", "core_api", "handlers", "data", "navigation"} <= set(schema["required"])
    assert schema["properties"]["own_permanent_workers"] == {"const": False}
    assert schema["properties"]["trust"]["const"] == "bundled_reviewed_only"
    assert not {"workers", "production_runtime", "runtime_enabled", "autostart_enabled"} & schema.keys()
    assert not {"workers", "production_runtime", "command", "dsn"} & schema["properties"].keys()


@pytest.mark.parametrize("filename", ["plugin_architecture_v3.json", "plugin_settings_schema_v1.json"])
def test_schemas_have_resolvable_local_references_and_required_properties(filename) -> None:
    schema = json.loads((CONTRACT_PATH.parent / filename).read_text(encoding="utf-8"))
    for node in _nodes(schema):
        if "$ref" in node:
            assert node["$ref"].startswith("#/$defs/")
            assert node["$ref"].removeprefix("#/$defs/") in schema["$defs"]
        # A properties map may itself contain a property named "required".
        if node.get("type") == "object" and "required" in node:
            assert isinstance(node["required"], list)
            assert len(node["required"]) == len(set(node["required"]))
            assert set(node["required"]) <= node["properties"].keys()
        if node.get("type") == "object":
            additional = node["additionalProperties"]
            assert "properties" in node or isinstance(additional, dict)
            assert additional is False or isinstance(additional, dict)


def test_v3_defines_bounded_jobs_results_scope_and_agent_receipts() -> None:
    definitions = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))["$defs"]
    assert {"job", "result", "budget", "access_scope", "entity_observation", "agent_envelope", "receipt"} <= definitions.keys()
    assert {"idempotency_key", "input_sha256", "handler_version", "manifest_sha256", "budget", "partition_key"} <= set(definitions["job"]["required"])
    assert {"job_id", "lease_token", "lease_generation", "result_sha256", "continuation"} <= set(definitions["result"]["required"])
    assert {"wall_seconds", "cpu_seconds", "memory_bytes", "max_records", "max_result_bytes", "max_db_connections"} <= set(definitions["budget"]["required"])
    assert definitions["access_scope"]["properties"]["mode"]["enum"] == ["none", "restricted", "all"]
    assert definitions["scope_clause"]["properties"]["plugin_ids"]["items"] == {"$ref": "#/$defs/id"}
    assert {"agent_id", "source_instance_id", "generation", "cursor_before", "cursor_after", "policy_revision", "payload_sha256"} <= set(definitions["agent_envelope"]["required"])
    assert {"packet_id", "payload_sha256", "committed_cursor", "status"} <= set(definitions["receipt"]["required"])
