"""Compact collection metadata keeps historical imports readable without payloads."""
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

PATH = Path(__file__).resolve().parents[2] / "config/postgres_migrations/237_entity_context_health.sql"


def test_metadata_migration_is_owner_gated_atomic_and_registered():
    sql = PATH.read_text("utf-8")
    inventory = [(row.version, row.name) for row in forward_migration_inventory(PATH.parent)]
    assert inventory[inventory.index((237, "entity_context_health")) - 1] == (236, "file_audit_evidence")
    for fragment in (
        "begin;", "pg_advisory_xact_lock",
        "pg_has_role(session_user,'adlog_storage_owner','MEMBER')",
        "version=236 and name='file_audit_evidence'", "where version>=237",
        "set local role adlog_storage_owner;", "values(237,'entity_context_health')",
    ):
        assert fragment in sql
    assert sql.strip().endswith("commit;")
    assert "delete " not in sql and "update " not in sql and "grant " not in sql


def test_generated_metadata_preserves_native_channels_and_error_precedence():
    sql = " ".join(PATH.read_text("utf-8").split())
    for fragment in (
        "collection_revision text generated always as (envelope->>'policy_revision') stored",
        "collection_channel text generated always as (coalesce(packet->'header'->>'channel',envelope->>'channel')) stored",
        "collection_read_error boolean generated always as (coalesce(packet->'context'->'workstations'->>'read_error', packet->'context'->'ad_dc'->>'read_error','')<>'') stored",
        "(agent_id,received_at desc) include(packet_id,module_id,sequence)",
        "(packet_id) include(collection_revision,collection_channel,collection_read_error,imported_at)",
    ):
        assert fragment in sql
