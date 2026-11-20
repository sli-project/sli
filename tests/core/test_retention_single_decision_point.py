from __future__ import annotations

import ast
import inspect
from pathlib import Path

from server.sli.core.app_config import load_config
from server.sli.events.event_catalog import all_event_catalog_entries
from server.sli.sources.post_collection_pipeline import cleanup_post_collection_jobs
from server.sli.storage.storage_policy import (
    StoragePolicy,
    resolve_catalogue_retention,
    resolve_operational_retention,
)


ROOT = Path(__file__).resolve().parents[2]
CANONICAL_MODULE = ROOT / "server" / "sli" / "storage" / "storage_policy.py"
OWNER_APPROVED_PERIODS = {
    "raw_payload_days": 2,
    "record_days": 7,
    "warm_record_days": 365,
}


def _entry_key(entry: dict[str, object]) -> tuple[str, int, str]:
    return (
        str(entry.get("channel") or ""),
        int(entry.get("event_id") or 0),
        str(entry.get("provider_name") or ""),
    )


def test_catalogue_lifecycle_overrides_configuration_without_code_change() -> None:
    entry = {
        "lifecycle": {
            "raw_payload_days": {
                "default": 3,
                "rules": [
                    {
                        "field": "message_kind",
                        "op": "equals",
                        "value": "valuable",
                        "then": 9,
                    }
                ],
            },
            "record_days": 21,
            "warm_record_days": 400,
            "rollup": "daily",
        }
    }
    resolution = resolve_catalogue_retention(
        entry,
        event={"message_kind": "valuable"},
        policy=StoragePolicy(raw_retention_days=2, db_retention_days=7, warm_retention_days=365),
    )

    assert resolution.raw_payload.days == 9
    assert resolution.record.days == 21
    assert resolution.warm_record.days == 400
    assert resolution.raw_payload.source == "catalogue"
    assert resolution.record.source == "catalogue"
    assert resolution.warm_record.source == "catalogue"
    assert resolution.raw_payload.defaulted is False
    assert resolution.record.defaulted is False
    assert resolution.rollup == "daily"


def test_all_catalogue_entries_declare_owner_approved_periods() -> None:
    entries = all_event_catalog_entries()
    assert len(entries) == 105
    assert all("lifecycle" in entry for entry in entries)

    before = {
        _entry_key(entry): dict(OWNER_APPROVED_PERIODS)
        for entry in entries
    }
    after: dict[tuple[str, int, str], dict[str, int]] = {}
    for entry in entries:
        resolution = resolve_catalogue_retention(entry, policy=StoragePolicy())
        assert resolution.raw_payload.source == "catalogue"
        assert resolution.record.source == "catalogue"
        assert resolution.warm_record.source == "catalogue"
        assert resolution.raw_payload.defaulted is False
        assert resolution.record.defaulted is False
        assert resolution.warm_record.defaulted is False
        after[_entry_key(entry)] = {
            "raw_payload_days": resolution.raw_payload.days,
            "record_days": resolution.record.days,
            "warm_record_days": resolution.warm_record.days,
        }

    assert after == before


def test_app_config_exposes_raw_periods_without_deciding_defaults(tmp_path: Path, monkeypatch) -> None:
    for name in (
        "ADLOG_RAW_RETENTION_DAYS",
        "ADLOG_DB_RETENTION_DAYS",
        "ADLOG_WARM_RETENTION_DAYS",
        "ADLOG_BACKUP_RETENTION_DAYS",
        "ADLOG_LOG_RETENTION_DAYS",
        "ADLOG_ARTIFACT_RETENTION_DAYS",
        "ADLOG_POST_COLLECTION_RETENTION_DAYS",
        "ADLOG_ARCHIVE_AUTO_DELETE_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)

    config = load_config(tmp_path / "missing.yaml")

    assert config.raw_retention_days is None
    assert config.db_retention_days is None
    assert config.warm_retention_days is None
    assert config.backup_retention_days is None
    assert config.log_retention_days is None
    assert config.artifact_retention_days is None
    assert config.post_collection_retention_days is None
    assert config.archive_auto_delete_enabled is None
    assert not hasattr(config, "archive_raw_days")
    assert not hasattr(config, "archive_processed_days")
    assert not hasattr(config, "reports_days")
    assert not hasattr(config, "technical_logs_days")
    assert not hasattr(config, "sqlite_backup_days")


def test_post_collection_uses_canonical_operational_period() -> None:
    signature = inspect.signature(cleanup_post_collection_jobs)
    assert "retention_days" not in signature.parameters

    resolution = resolve_operational_retention(
        "post_collection_jobs",
        policy=StoragePolicy(post_collection_retention_days=30),
    )
    assert resolution.days == 30
    assert resolution.source == "configuration"
    assert resolution.policy_field == "post_collection_retention_days"


def test_owner_approved_global_policy_is_hot_7_warm_365_and_archive_fail_closed() -> None:
    policy = StoragePolicy()

    assert policy.db_retention_days == 7
    assert policy.warm_retention_days == 365
    assert policy.archive_auto_delete_enabled is False


def test_storage_policy_is_the_only_period_decision_module() -> None:
    candidates = list((ROOT / "server" / "app").glob("*.py")) + list((ROOT / "server" / "sli").glob("*/*.py"))
    candidates.append(ROOT / "server" / "api" / "http_server.py")
    period_api_owners: set[Path] = set()
    numeric_defaults_outside_owner: list[str] = []

    for path in candidates:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name in {
                    "resolve_catalogue_retention",
                    "resolve_event_retention",
                    "resolve_descriptor_retention",
                    "resolve_operational_retention",
                    "get_retention_plan",
                }:
                    period_api_owners.add(path)
                positional = [*node.args.posonlyargs, *node.args.args]
                padded_defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
                for argument, default in zip(positional, padded_defaults):
                    if (
                        argument.arg.endswith("retention_days")
                        and isinstance(default, ast.Constant)
                        and isinstance(default.value, int)
                    ):
                        numeric_defaults_outside_owner.append(f"{path}:{node.lineno}:{argument.arg}")
            if (
                path != CANONICAL_MODULE
                and isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id.endswith("retention_days")
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, int)
            ):
                numeric_defaults_outside_owner.append(f"{path}:{node.lineno}:{node.target.id}")

    assert period_api_owners == {CANONICAL_MODULE}
    assert numeric_defaults_outside_owner == []

    app_config_source = (ROOT / "server" / "sli" / "core" / "app_config.py").read_text(encoding="utf-8")
    assert "ADLOG_POST_COLLECTION_RETENTION_DAYS" in app_config_source
    assert "ADLOG_RETENTION_RAW_DAYS" not in app_config_source
    assert "ADLOG_RETENTION_PROCESSED_DAYS" not in app_config_source
    assert "ADLOG_RETENTION_REPORTS_DAYS" not in app_config_source
    assert "ADLOG_RETENTION_LOGS_DAYS" not in app_config_source
    assert "ADLOG_RETENTION_BACKUPS_DAYS" not in app_config_source
