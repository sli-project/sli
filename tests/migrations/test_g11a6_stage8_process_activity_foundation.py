from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest



UTC = timezone.utc
BASE = datetime(2026, 8, 25, 1, tzinfo=UTC)
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


def test_stage8_catalog_contains_exact_process_service_and_task_contracts() -> None:
    catalog = json.loads(Path("config/event_catalog.json").read_text(encoding="utf-8"))
    entries = {
        (item["channel"], item["event_id"]): item for item in catalog["entries"]
    }
    for event_id in (4697, 4698, 4699, 4700, 4701, 4702):
        item = entries[("Security", event_id)]
        assert item["provider_name"] == SECURITY_PROVIDER
        assert item["lifecycle"] == {
            "raw_payload_days": 2,
            "record_days": 7,
            "warm_record_days": 365,
            "rollup": "process_activity",
        }
        assert {
            "event_id", "time_created_utc", "server_id", "event_record_id",
            "source_core_sha256", "source_facts_sha256",
        } <= set(item["required_fields"])
    for event_id in (4688, 4689):
        required = set(entries[("Security", event_id)]["required_fields"])
        assert {"process_user_sid", "process_user_name", "process_user_domain", "process_logon_id"} <= required
    assert {"process_parent_id", "process_command_line"} <= set(
        entries[("Security", 4688)]["required_fields"]
    )


class EpisodeCursor:
    def __init__(self) -> None:
        self.history: list[tuple[str, tuple[object, ...]]] = []
        self.sql = ""

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        self.sql = " ".join(sql.split()).lower()
        self.history.append((self.sql, params))

    def fetchone(self) -> dict[str, object] | None:
        if "select revision_id" in self.sql:
            return None
        if "max(revision_no)" in self.sql:
            return {"next_revision": 1}
        return None


def test_migration89_is_additive_bounded_retention_independent_and_rollback_safe() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/089_process_activity_foundation.rollback.sql").read_text(encoding="utf-8").lower()
    assert "values (89,'process_activity_foundation')" in forward
    assert "migration 089 requires migration 088" in forward
    assert "create table public.process_episode_revisions" in forward
    assert "create table public.process_episode_evidence" in forward
    assert "references events_v2_core" not in forward
    assert "event_record_id bigint not null" in forward
    assert "source_event_sha256 bytea not null" in forward
    assert "source_facts_sha256 bytea not null" in forward
    assert "octet_length(command_line) <= 4096" in forward
    assert "parent_process_id between 1 and 4294967295" in forward
    assert "event_facts_v2_process_id_windows" in forward
    assert "event_facts_v2_powershell_process_id_windows" in forward
    assert "process_id::numeric between 1 and 4294967295" in forward
    for field, limit in (
        ("process_name", 512), ("user_sid", 512), ("user_name", 512),
        ("user_domain", 512), ("logon_id", 128),
    ):
        assert f"octet_length({field}) <= {limit}" in forward
    assert "security definer" in forward
    assert "write_process_episode_revision_v89" in forward
    assert "grant execute on function public.write_process_episode_revision_v89" in forward
    assert "grant select,insert on table process_episode_revisions" not in forward
    assert "process episode evidence count mismatch" in forward
    assert "process episode start evidence mismatch" in forward
    assert "process episode end evidence mismatch" in forward
    assert "process episode evidence replay conflict" in forward
    assert "set local lock_timeout='5s'" in forward
    assert "set local statement_timeout='30s'" in forward
    assert "v_marker_count <> 1" in forward
    assert "where version>88" in forward
    assert "refuses conflicting process episode objects" in forward
    assert "lacks public schema create" in forward
    assert "evidence_order between 0 and 255" in forward
    assert "before update or delete" in forward
    assert "rollback would discard process episode evidence" in rollback
    assert "where version>89" in rollback
    assert "rollback refuses later migrations" in rollback
    assert "drop table public.process_episode_evidence" in rollback
    assert "drop table public.process_episode_revisions" in rollback


def test_migration89_pins_trusted_namespace_and_qualifies_security_boundary() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    rollback = Path("config/postgres_migrations/089_process_activity_foundation.rollback.sql").read_text(encoding="utf-8").lower()
    assert "set local search_path=pg_catalog,public" in forward
    assert "a.grantee=0 and a.privilege_type='create'" in forward
    assert "not pg_has_role(r.oid,'adlog_storage_owner','member')" in forward
    assert "set search_path=pg_catalog" in forward
    for fragment in (
        "public.schema_migrations", "public.event_facts_v2",
        "public.process_episode_revisions", "public.process_episode_evidence",
        "public.write_process_episode_revision_v89",
        "public.process_episode_evidence_reject_mutation",
        "grant execute on function public.write_process_episode_revision_v89(pg_catalog.jsonb)",
    ):
        assert fragment in forward
    assert "set local search_path=pg_catalog,public" in rollback
    for fragment in (
        "public.schema_migrations", "public.event_facts_v2",
        "public.process_episode_revisions", "public.process_episode_evidence",
        "public.write_process_episode_revision_v89",
        "public.process_episode_evidence_reject_mutation",
    ):
        assert fragment in rollback


def test_database_writer_derives_non_fabricable_identity_ordering_and_manifest_shape() -> None:
    forward = Path("config/postgres_migrations/089_process_activity_foundation.sql").read_text(encoding="utf-8").lower()
    assert "v_expected_episode_id" in forward
    assert "v_expected_revision_id" in forward
    assert "v_derived_ordering_state" in forward
    assert "process episode derived identity mismatch" in forward
    assert "process episode derived ordering mismatch" in forward
    assert "jsonb_object_keys(value))<>15" in forward
    assert "process episode evidence object shape mismatch" in forward
    assert forward.index("process episode evidence object shape mismatch") < forward.index(
        "where idempotency_key=v_idempotency"
    )


def test_database_writer_rejects_extra_and_oversized_top_level_payloads() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode writer payload shape mismatch" in forward
    shape = forward[:forward.index("process episode writer payload shape mismatch")]
    assert "jsonb_object_keys(p)" in shape
    assert "p ?& array[" in shape
    assert "process episode writer payload exceeds" in forward
    assert "octet_length(p::text)" in forward
    assert forward.index("process episode writer payload exceeds") < forward.index(
        "v_revision_id :="
    )


def test_database_writer_rejects_alternate_ignored_top_level_state() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode writer top-level state mismatch" in forward
    assert "p - array[" in forward
    assert "] <> v_state" in forward


def test_database_writer_validates_every_evidence_atom_against_hot_authorities_before_insert() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    for authority in (
        "public.events_v2_core",
        "public.event_facts_v2",
        "public.storage_v2_channel",
        "public.normalized_events",
    ):
        assert authority in forward
    for exact_match in (
        "source.id=(item.value->>'source_event_id')::integer",
        "source.domain_id<>(item.value->>'domain_id')::bigint",
        "source.server_id<>(item.value->>'source_host_id')::bigint",
        "source.time_created_utc<>(item.value->>'observed_at_utc')::timestamptz",
        "channel.value<>(item.value->>'source_channel')",
        "source.event_record_id<>(item.value->>'event_record_id')::bigint",
        "source.normalized_hash<>decode(item.value->>'source_event_sha256','hex')",
        "facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')",
        "normalized.semantic_type=item.value->>'semantic_type'",
    ):
        assert exact_match in forward
    assert "process episode evidence does not match authoritative hot source" in forward
    assert forward.index(
        "process episode evidence does not match authoritative hot source"
    ) < forward.index("insert into public.process_episode_revisions(")
    assert "confirmed_end_at_utc >= started_at_utc" not in forward


def test_database_writer_pins_one_authoritative_normalized_row_and_digest() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "semantic_contract_version integer not null" in forward
    assert "normalizer_id text not null" in forward
    assert "normalizer_version text not null" in forward
    assert "semantic_sha256 bytea not null" in forward
    assert "jsonb_object_keys(value))<>15" in forward
    for exact_match in (
        "normalized.semantic_contract_version=(item.value->>'semantic_contract_version')::integer",
        "normalized.normalizer_id=item.value->>'normalizer_id'",
        "normalized.normalizer_version=item.value->>'normalizer_version'",
        "normalized.semantic_sha256=decode(item.value->>'semantic_sha256','hex')",
        "facts.source_facts_sha256<>decode(item.value->>'source_facts_sha256','hex')",
    ):
        assert exact_match in forward
    assert "select count(*) from public.normalized_events normalized" in forward
    assert ")<>1" in forward


def test_database_writer_rejects_fabricated_boot_event_identity() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    assert "process episode boot evidence mismatch" in forward
    validation = forward[:forward.index("process episode boot evidence mismatch")]
    assert "value->>'evidence_role'='boot_scope'" in validation
    assert "value->>'semantic_type'='system.boot.boundary'" in validation
    assert "(value->>'source_event_id')::bigint=(v_state->>'boot_event_id')::bigint" in validation
    assert forward.index("process episode boot evidence mismatch") < forward.index(
        "select * into v_existing from public.process_episode_revisions"
    )


def test_database_writer_qualifies_json_manifest_value_against_channel_value() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    validation = forward[
        forward.index("-- validate caller-supplied identity/provenance only"):
        forward.index("process episode evidence does not match authoritative hot source")
    ]
    assert "from jsonb_array_elements(v_manifest) item(value)" in validation
    assert "where item.value->>'source_event_id' is null" in validation
    assert "channel.value<>(item.value->>'source_channel')" in validation
    assert "normalized.semantic_type=item.value->>'semantic_type'" in validation


def test_exact_replay_is_verified_from_durable_evidence_after_hot_source_expiry() -> None:
    forward = Path(
        "config/postgres_migrations/089_process_activity_foundation.sql"
    ).read_text(encoding="utf-8").lower()

    replay_lookup = forward.index(
        "select * into v_existing from public.process_episode_revisions"
    )
    hot_validation = forward.index(
        "process episode evidence does not match authoritative hot source"
    )
    assert replay_lookup < hot_validation
