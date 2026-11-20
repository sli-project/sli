"""Validate reviewed stage-1 declarations; never apply migrations or start work."""
import hashlib
import json
import re
from pathlib import Path

from server.sli.core.job_registry import validate_shape
from server.sli.plugins.file_audit.contracts import (
    CAPABILITIES,
    PLUGIN_ID,
    REPORT_KEYS,
    SCHEMA,
    VERSION,
)

ROOT = Path(__file__).resolve().parents[4]


def _version(value):
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value):
        raise ValueError("file_audit_version_invalid")
    return tuple(map(int, value.split(".")))


def validate_manifest(value, *, core_api="3.0.0", agent_api="1.0.0", root=ROOT):
    schema = json.loads((root / "config/plugin_architecture_v3.json").read_text("utf-8"))
    validate_shape(value, schema, schema)
    if value["plugin_id"] != PLUGIN_ID or value["plugin_version"] != VERSION or value["data"]["schema"] != SCHEMA:
        raise ValueError("file_audit_identity_invalid")
    def compatible(api, actual):
        return _version(api["minimum"]) <= _version(actual) < _version(api["maximum_exclusive"])
    if not compatible(value["core_api"], core_api):
        raise ValueError("file_audit_core_api_incompatible")
    modules = value["agent_modules"]
    if (len(modules) != 1 or modules[0]["module_id"] != PLUGIN_ID or modules[0]["module_version"] != VERSION
            or modules[0]["rights_check_id"] != "windows-file-audit-local-read"
            or modules[0]["policy_schema_ref"] != "sli.file-audit.policy.v1"
            or not compatible(modules[0]["agent_api"], agent_api)):
        raise ValueError("file_audit_agent_api_incompatible")
    if any(value[key] for key in ("handlers", "schedules", "home_widgets", "dependencies")):
        raise ValueError("file_audit_stage1_declarations_invalid")
    if value["navigation"] != [{"section_id": "file-audit", "title_key": "file-audit.title", "icon_id": "report", "order": 50, "parent_section_id": None}]:
        raise ValueError("file_audit_navigation_invalid")
    if set(value["capabilities"]) != set(CAPABILITIES.values()):
        raise ValueError("file_audit_capabilities_invalid")
    sources = value["sources"]
    if len(sources) != 1 or sources[0] != {
            "pack_id": "sli.windows.file-audit", "pack_version": VERSION,
            "normalizer_id": "windows-file-audit-v1", "normalizer_version": VERSION,
            "input_contract": "sli.collection-packet.v1", "catalog_ref": "file-audit.event-catalog.v1",
            "collection_policy_schema_ref": "sli.file-audit.policy.v1"}:
        raise ValueError("file_audit_source_invalid")
    keys = {f"file-audit.{key}" for key in REPORT_KEYS}
    datasets = value["datasets"]
    reports = value["reports"]
    if (len(datasets) != len(keys) or {item["dataset_id"] for item in datasets} != keys
            or any(item["contract_id"] != "sli.report-result.v2" or item["contract_version"] != "2.0.0"
                   or item["reader_id"] != item["dataset_id"] or item["capabilities"] != [CAPABILITIES["view"]] for item in datasets)
            or len(reports) != len(keys) or {item["report_key"] for item in reports} != keys
            or any(item["access_key"] != item["report_key"] or item["dataset_id"] != item["report_key"]
                   or item["definition_id"] != item["report_key"] or item["history_reader_id"] != item["report_key"]
                   or item["section_id"] != "file-audit" or item["capabilities"] != [CAPABILITIES["view"]]
                   or item["required_fields"] != ["identity_basic", "technical", "security", "privilege"]
                   or item["routes"] != [f"/report/{item['report_key']}"] for item in reports)):
        raise ValueError("file_audit_report_contract_invalid")
    migrations = value["data"]["migrations"]
    if (len(migrations) != 7 or migrations[0]["version"] != 183 or migrations[0]["name"] != "file_audit_contracts"
            or migrations[0]["path"] != "config/postgres_migrations/183_file_audit_contracts.sql"
            or migrations[0]["core_prerequisites"] != [182] or value["data"]["existing_tables"]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[1]["version"] != 185 or migrations[1]["name"] != "file_audit_management"
            or migrations[1]["path"] != "config/postgres_migrations/185_file_audit_management.sql"
            or migrations[1]["core_prerequisites"] != [184]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[2]["version"] != 186 or migrations[2]["name"] != "file_audit_collection"
            or migrations[2]["path"] != "config/postgres_migrations/186_file_audit_collection.sql"
            or migrations[2]["core_prerequisites"] != [185]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[3]["version"] != 187 or migrations[3]["name"] != "file_audit_rules"
            or migrations[3]["path"] != "config/postgres_migrations/187_file_audit_rules.sql"
            or migrations[3]["core_prerequisites"] != [186]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[4]["version"] != 191 or migrations[4]["name"] != "file_audit_reports"
            or migrations[4]["path"] != "config/postgres_migrations/191_file_audit_reports.sql"
            or migrations[4]["core_prerequisites"] != [190]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[5]["version"] != 193 or migrations[5]["name"] != "file_audit_retention"
            or migrations[5]["path"] != "config/postgres_migrations/193_file_audit_retention.sql"
            or migrations[5]["core_prerequisites"] != [192]):
        raise ValueError("file_audit_migration_invalid")
    if (migrations[6]["version"] != 197 or migrations[6]["name"] != "workstation_file_audit"
            or migrations[6]["path"] != "config/postgres_migrations/197_workstation_file_audit.sql"
            or migrations[6]["core_prerequisites"] != [196]):
        raise ValueError("file_audit_migration_invalid")
    for migration in migrations:
        checksum = hashlib.sha256((root / migration["path"]).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if checksum != migration["sha256"]:
            raise ValueError("file_audit_migration_checksum_invalid")
    return value


def load_manifest(**kwargs):
    return validate_manifest(json.loads((ROOT / "config/plugin_packages/v3/sli.file-audit.json").read_text("utf-8")), **kwargs)
