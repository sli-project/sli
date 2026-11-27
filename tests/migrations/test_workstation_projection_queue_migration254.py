"""WR05 schema, immutable package attestations and narrow publisher authority."""
import hashlib
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/254_workstation_projection_queue.sql"
SQL = PATH.read_text("utf-8")


def test_capture_is_in_source_transaction_and_replay_has_a_unique_source_fence():
    assert "unique(kind,source_id)" in SQL
    assert "on conflict(kind,source_id) do nothing returning work_id" in SQL
    assert "after insert on sli_plugin_workstations.observations" in SQL
    for source in ("protection_state", "station_inventory"):
        assert f"after insert or update on sli_plugin_workstations.{source}" in SQL
    assert "perform sli_plugin_workstations.enqueue_projection_input(tg_table_name,to_jsonb(new)-'source_xml')" in SQL
    assert "not (payload ? 'source_xml')" in SQL
    assert "where applied_at is null" in SQL
    assert "primary key(work_id,projector_key,projection_version)" in SQL
    # Registration serializes with capture, not with a hash/sequence watermark.
    capture = SQL.split("create function sli_plugin_workstations.enqueue_projection_input", 1)[1].split("end $$;", 1)[0]
    assert capture.index("pg_advisory_xact_lock_shared") < capture.index("insert into sli_plugin_workstations.projection_work")
    registration = SQL.split("create function sli_plugin_workstations.register_projection_consumer", 1)[1].split("end $$;", 1)[0]
    assert "pg_advisory_xact_lock(hashtext('workstations.projection-consumers'))" in registration
    assert "extract(epoch from (p_payload->>'observed_at')::timestamptz)" in SQL


def test_runtime_cannot_enqueue_arbitrary_payload_or_mutate_replay_receipts():
    assert "from public,adlog_user" in SQL
    assert "grant delete" not in SQL and "grant all" not in SQL
    assert "grant execute on function sli_plugin_workstations.enqueue_projection_input" not in SQL
    assert "grant select,insert,update on sli_plugin_workstations.projection_work" not in SQL
    assert "grant select,insert,update on sli_plugin_workstations.projection_receipts" in SQL
    assert "grant select,insert on sli_plugin_workstations.station_changes" in SQL
    for function in ("register_projection_consumer", "backfill_projection_input"):
        body = SQL.split(f"create function sli_plugin_workstations.{function}", 1)[1].split("end $$;", 1)[0]
        assert "security definer set search_path=pg_catalog,public" in body
        assert "if not public.core_workstation_projection_write_allowed_v1()" in body
    assert "when 'observations' then 'id'" in SQL
    assert "if v_column is null then raise exception" in SQL
    assert "into v_payload using p_key" in SQL


def test_publisher_fence_cannot_borrow_retention_authority_or_change_evidence():
    for clause in ("j.lease_token::text=current_setting('sli.job_token',true)",
                   "j.lease_generation::text=current_setting('sli.job_generation',true)",
                   "j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()",
                   "public.core_job_profile_v1('light','publisher')"):
        assert clause in SQL
    retention = SQL.split("create or replace function public.core_workstation_job_write_allowed_v1", 1)[1].split("$$;", 1)[0]
    assert "public.core_workstation_retention_binding_v192(j.spec)" in retention
    assert "projection_binding" not in retention
    projection = SQL.split("create function public.core_workstation_projection_write_allowed_v1", 1)[1].split("$$;", 1)[0]
    assert "public.core_workstation_projection_binding_v1(j.spec)" in projection
    assert "core_workstation_retention_binding" not in projection
    assert "and exists(select 1 from public.plugin_installations_v1" in SQL
    assert "workstation_projection_write_denied" in SQL
    assert "'station_summary','check_findings','station_changes'" in SQL
    assert "grant delete,update(id)" not in SQL
