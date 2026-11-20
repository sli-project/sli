from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

import pytest

from server.sli.sources.ad_snapshot_retention import (
    POLICY_HORIZON_DAYS,
    REQUIRED_AD_RETENTION_RELATIONS,
    plan_ad_snapshot_retention,
)


ROOT = Path(__file__).resolve().parents[2]
MIGRATIONS = ROOT / "config" / "postgres_migrations"


def _safe_inventory() -> dict[str, dict[str, object]]:
    return {
        relation: {
            "candidate_count": 0,
            "root_mapping_proven": True,
            "anchor_proven": True,
            "owner_admitted": True,
            "shared_source": False,
            "dependency_state": "safe",
            "independent_legacy_cleaner": False,
            "whole_unit_admitted": True,
        }
        for relation in REQUIRED_AD_RETENTION_RELATIONS
    }


def test_read_only_policy_is_a_seven_day_snapshot_scope_without_ad_context() -> None:
    now = datetime(2026, 9, 1, 12, tzinfo=timezone.utc)

    assert POLICY_HORIZON_DAYS == 7
    assert "ad_context_runs" not in REQUIRED_AD_RETENTION_RELATIONS
    assert REQUIRED_AD_RETENTION_RELATIONS == (
        "ad_snapshot_manifests",
        "ad_snapshot_manifest_sources",
        "ad_snapshot_projection_receipts",
        "ad_snapshot_projection_outputs",
        "users_report_v2_snapshots",
        "computers_v6_source_snapshots",
        "gpo_report_v2_source_snapshots",
    )
    result = plan_ad_snapshot_retention(now=now, inventory=_safe_inventory())
    assert result["policy_horizon_days"] == 7
    assert result["horizon_before_utc"] == "2026-08-25T12:00:00Z"
    with pytest.raises(ValueError, match="fixed at 7"):
        plan_ad_snapshot_retention(now=now, policy_horizon_days=365)


def test_migration_131_defines_a_security_definer_seven_day_expiry_ring() -> None:
    forward = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.sql").read_text(
        encoding="utf-8"
    ).casefold()
    rollback = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.rollback.sql").read_text(
        encoding="utf-8"
    ).casefold()

    assert "create or replace procedure public.expire_ad_snapshot_seven_day_ring" in forward
    assert "security definer" in forward
    assert "session_user <> 'adlog_user'" in forward
    assert "revoke all on procedure public.expire_ad_snapshot_seven_day_ring(uuid) from public" in forward
    assert "grant execute on procedure public.expire_ad_snapshot_seven_day_ring(uuid) to adlog_user" in forward
    assert "interval '7 days'" in forward
    assert "asia/novosibirsk" in forward
    assert "latest published scheduled manifest" in forward
    assert "scheduled_local_at <= cutoff_local_at" in forward
    assert "update public.ad_snapshot" not in forward
    assert "delete from public.ad_context_runs" not in forward
    assert "ad_context_runs" not in forward

    for relation in (
        "ad_snapshot_projection_outputs",
        "ad_snapshot_projection_receipts",
        "ad_snapshot_manifest_sources",
        "ad_snapshot_manifests",
        "users_report_v2_snapshots",
        "computers_v6_source_snapshots",
        "gpo_report_v2_source_snapshots",
    ):
        assert f"delete from public.{relation}" in forward

    assert "current_setting('ad_snapshot_retention.expiry_active', true) = 'on'" in forward
    assert "set_config('ad_snapshot_retention.expiry_active', 'on', true)" in forward
    assert "set_config('ad_snapshot_retention.expiry_active', 'off', true)" in forward
    assert "trg_ad_snapshot_manifests_immutable" in forward
    assert "trg_ad_snapshot_manifest_sources_immutable" in forward
    assert "trg_ad_snapshot_projection_outputs_immutable" in forward

    for constraint in (
        "what_where_when_observations_computer_source_snapshot_id_fkey",
        "what_where_when_observations_user_snapshot_id_fkey",
        "www_projection_state_computer_source_snapshot_fkey",
        "what_where_when_projection_state_user_snapshot_id_fkey",
    ):
        assert constraint in forward
    assert forward.count("on delete set null") >= 4
    assert "alter column computer_source_snapshot_id drop not null" in forward
    assert "alter column user_snapshot_id drop not null" in forward

    assert "rollback: what-where-when null snapshot references exist" in rollback
    assert "where computer_source_snapshot_id is null" in rollback
    assert "or user_snapshot_id is null" in rollback
    assert "delete from public.schema_migrations" in rollback
    assert "where version = 131" in rollback


def test_migration_131_authorizes_retention_deletes_without_cancelling_them() -> None:
    forward = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.sql").read_text(
        encoding="utf-8"
    ).casefold()
    rollback = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.rollback.sql").read_text(
        encoding="utf-8"
    ).casefold()

    for function_name in (
        "ad_snapshot_manifest_reject_mutation",
        "ad_snapshot_projection_output_reject_mutation",
    ):
        forward_function = forward.split(
            f"create or replace function public.{function_name}()", maxsplit=1
        )[1].split("alter function", maxsplit=1)[0]
        rollback_function = rollback.split(
            f"create or replace function public.{function_name}()", maxsplit=1
        )[1].split("alter function", maxsplit=1)[0]

        assert "tg_op = 'delete'" in forward_function
        assert "return old;" in forward_function
        assert "raise exception" in forward_function
        assert "return null;" in rollback_function


def test_migration_131_replaces_live_projection_computer_fk_with_short_canonical_name() -> None:
    forward = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.sql").read_text(
        encoding="utf-8"
    ).casefold()
    rollback = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.rollback.sql").read_text(
        encoding="utf-8"
    ).casefold()
    live_baseline_projection_computer_fk = (
        "what_where_when_projection_sta_computer_source_snapshot_id_fkey"
    )
    canonical_projection_computer_fk = (
        "www_projection_state_computer_source_snapshot_fkey"
    )
    rejected_projection_computer_fk = (
        "what_where_when_projection_state_computer_source_snapshot_id_fk"
    )

    assert len(live_baseline_projection_computer_fk.encode("utf-8")) == 63
    assert len(canonical_projection_computer_fk.encode("utf-8")) < 63
    assert (
        f"drop constraint if exists {live_baseline_projection_computer_fk}" in forward
    )
    assert f"add constraint {canonical_projection_computer_fk}" in forward
    assert forward.index(
        f"drop constraint if exists {live_baseline_projection_computer_fk}"
    ) < forward.index(f"add constraint {canonical_projection_computer_fk}")
    canonical_forward_start = forward.index(
        f"add constraint {canonical_projection_computer_fk}"
    )
    canonical_forward_end = forward.index(
        "alter table public.what_where_when_projection_state",
        canonical_forward_start + 1,
    )
    assert "on delete set null" in forward[
        canonical_forward_start:canonical_forward_end
    ]

    assert f"drop constraint if exists {canonical_projection_computer_fk}" in rollback
    assert f"add constraint {live_baseline_projection_computer_fk}" in rollback
    assert rollback.index(
        f"drop constraint if exists {canonical_projection_computer_fk}"
    ) < rollback.index(f"add constraint {live_baseline_projection_computer_fk}")
    assert "on delete restrict" in rollback[
        rollback.index(f"add constraint {live_baseline_projection_computer_fk}") :
        rollback.index("alter table public.what_where_when_projection_state", rollback.index(f"add constraint {live_baseline_projection_computer_fk}") + 1)
    ]

    for source in (forward, rollback):
        assert rejected_projection_computer_fk not in source

    assert "add constraint what_where_when_projection_state_user_snapshot_id_fkey" in forward


def test_migration_131_rollback_only_blocks_expired_observation_references() -> None:
    rollback = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.rollback.sql").read_text(
        encoding="utf-8"
    ).casefold()
    rollback_preflight = rollback.split(
        "drop procedure if exists public.expire_ad_snapshot_seven_day_ring(uuid);",
        maxsplit=1,
    )[0]

    assert "from public.what_where_when_observations" in rollback_preflight
    assert "where computer_source_snapshot_id is null" in rollback_preflight
    assert "or user_snapshot_id is null" in rollback_preflight
    assert "what_where_when_projection_state" not in rollback_preflight
    assert not re.search(
        r"alter table public\.what_where_when_projection_state\s+"
        r"alter column (computer_source_snapshot_id|user_snapshot_id) set not null",
        rollback,
    )


def test_migration_131_expires_every_old_unretained_source_payload_only() -> None:
    forward = (MIGRATIONS / "131_ad_snapshot_seven_day_ring.sql").read_text(
        encoding="utf-8"
    ).casefold()

    assert "cutoff_at_utc timestamptz;" in forward
    assert (
        "cutoff_at_utc := cutoff_local_at at time zone 'asia/novosibirsk';" in forward
    )
    assert (
        "-- gpo snapshots have no captured_at_utc; migration 116 indexes created_at for retention."
        in forward
    )
    gpo_reference = (MIGRATIONS / "116_gpo_report_v2_reference.sql").read_text(
        encoding="utf-8"
    ).casefold()
    assert (
        "on gpo_report_v2_source_snapshots(created_at,snapshot_id);" in gpo_reference
    )
    assert re.findall(r"delete from public\.([a-z0-9_]+)", forward) == [
        "users_report_v2_snapshots",
        "computers_v6_source_snapshots",
        "gpo_report_v2_source_snapshots",
        "ad_snapshot_projection_outputs",
        "ad_snapshot_projection_receipts",
        "ad_snapshot_manifest_sources",
        "ad_snapshot_manifests",
    ]

    sources = (
        (
            "users_report_v2_snapshots",
            "captured_at_utc",
            "users_v2",
            "snapshot_id",
            "delete from public.computers_v6_source_snapshots snapshot",
        ),
        (
            "computers_v6_source_snapshots",
            "captured_at_utc",
            "computers_v6",
            "snapshot_uuid",
            "delete from public.gpo_report_v2_source_snapshots snapshot",
        ),
        (
            "gpo_report_v2_source_snapshots",
            "created_at",
            "gpo_v2",
            "source_run_id",
            "delete from public.ad_snapshot_projection_outputs output",
        ),
    )
    for relation, timestamp_column, family, source_identifier, next_delete in sources:
        start = forward.index(f"delete from public.{relation} snapshot")
        delete_block = forward[start : forward.index(next_delete, start)]

        assert f"snapshot.domain_id = anchor_domain_id" in delete_block
        assert f"snapshot.{timestamp_column} <= cutoff_at_utc" in delete_block
        assert "expired_manifest" not in delete_block
        assert f"retained_source.family = '{family}'" in delete_block
        assert (
            f"retained_source.source_id = snapshot.{source_identifier}::text"
            in delete_block
        )
        assert "retained_manifest.domain_id = anchor_domain_id" in delete_block
        assert (
            "retained_manifest.contract_version = 'sli.ad-snapshot-manifest/2.0'"
            in delete_block
        )
        assert "retained_manifest.schedule_timezone = 'asia/novosibirsk'" in delete_block
        assert "retained_manifest.scheduled_local_at > cutoff_local_at" in delete_block
