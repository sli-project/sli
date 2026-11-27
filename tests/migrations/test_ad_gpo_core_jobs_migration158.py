import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/158_ad_gpo_core_jobs.sql").read_text("utf-8")


def test_additive_migration_reuses_154_queue_and_does_not_change_installations():
    assert "version=154 and name='core_job_queue'" in SQL
    assert "migration 158 already applied" in SQL
    assert "values(158,'ad_gpo_core_jobs')" in SQL
    assert "create table" not in SQL
    assert "update public.plugin_installations" not in SQL
    assert "insert into public.plugin_installations" not in SQL
    assert "alter function public.core_job_admitted_v1(jsonb) rename to core_job_admitted_radius_v1" in SQL
    assert "else public.core_job_admitted_radius_v1(p_spec) end" in SQL


def test_enqueue_preserves_replay_quota_and_source_mutex():
    previous = (ROOT / "config/postgres_migrations/154_core_job_queue.sql").read_text("utf-8")
    previous = previous.split("create function public.enqueue_core_job_v1", 1)[1].split("end $$;", 1)[0]
    current = SQL.split("create or replace function public.enqueue_core_job_v1", 1)[1].split("end $$;", 1)[0]
    assert current == previous.replace(
        "or p_spec->>'rights_profile'<>'vpn-read'",
        "or not (p_spec->>'rights_profile'='vpn-read' or public.core_ad_job_binding_v1(p_spec))")


def test_publishers_have_separate_rights_and_cannot_write_without_current_fence():
    assert "resource_profile='heavy' and rights_profile='ad-read'" in SQL
    assert "resource_profile='long' and rights_profile='gpo-read'" in SQL
    assert ("grant select(source_run_id,payload_json,payload_sha256) on public.gpo_report_v2_source_snapshots\n"
            "    to sli_job_executor_long,sli_job_publisher_long;") in SQL
    assert "grant select,update on public.ad_snapshot_projection_receipts to sli_job_publisher_heavy,sli_job_publisher_long" in SQL
    assert "grant select,update on public.ad_snapshot_projection_receipts to sli_job_executor" not in SQL
    assert "enable row level security" in SQL
    assert "j.lease_token::text=current_setting('sli.job_token',true)" in SQL
    assert "j.lease_generation::text=current_setting('sli.job_generation',true)" in SQL
    assert "j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()" in SQL
    assert "public.core_ad_job_write_allowed_v1(manifest_id,projection_key)" in SQL
    assert "create role" not in SQL
    assert "revoke create on schema public from sli_job_owner" in SQL


def test_scheduling_is_bounded_and_quarantine_does_not_starve_new_inputs():
    assert "order by m.slot_start_utc,m.manifest_id limit 16" in SQL
    assert "j.state in ('blocked','cancelled','quarantined')" in SQL
    assert "r.status<>'completed'" in SQL
    assert "p_plugin='sli.gpo' and r.projection_key='ad.gpo.v2'" in SQL
    assert "to sli_job_owner using (true)" in SQL  # RLS permits the scheduler's metadata read.
