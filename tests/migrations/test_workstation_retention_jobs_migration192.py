"""Static admission/privilege contract; no runtime database connection."""
import json
from pathlib import Path

from scripts.maintenance.existing_postgres_bootstrap import forward_migration_inventory
from server.sli.core.job_queue import digest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "config/postgres_migrations/192_workstation_retention_jobs.sql"
SQL = PATH.read_text("utf-8")


def test_retention_migration_is_next_and_versions_are_unique():
    inventory = forward_migration_inventory(ROOT / "config/postgres_migrations")
    pairs = [(item.version, item.name) for item in inventory]
    position = pairs.index((192, "workstation_retention_jobs"))
    assert position > 0
    assert pairs[position - 1] == (191, "file_audit_reports")
    assert len(pairs) == len({version for version, _ in pairs})
    assert max(version for version, _ in pairs[:position]) + 1 == 192
    assert inventory[position].path == PATH


def test_exact_predecessor_and_pinned_manifest():
    manifest = json.loads((ROOT / "config/plugin_packages/sli.workstations.jobs-v3.json").read_text("utf-8"))
    assert f"p_spec->>'manifest_sha256'='{digest(manifest)}'" in SQL
    assert "version=191 and name='file_audit_reports'" in SQL
    assert "version=176 and name='workstation_history'" in SQL
    assert "version>=192" in SQL and "values(192,'workstation_retention_jobs')" in SQL
    assert "pg_advisory_xact_lock(hashtext('sli_workstation_retention_jobs_v192'))" in SQL
    assert "migration 192 prerequisites failed" in SQL
    assert list(PATH.parent.glob("192_*.sql")) == [PATH]


def test_only_publisher_can_delete_with_current_fence_and_process_usb_scope():
    assert "grant delete,update(id) on sli_plugin_workstations.observations to sli_job_publisher_light" in SQL
    assert "grant adlog_workstations_retention" not in SQL
    assert "tg_op<>'DELETE' or old.family not in ('processes','usb')" in SQL
    for check in ("j.lease_token::text=current_setting('sli.job_token',true)",
                  "j.lease_generation::text=current_setting('sli.job_generation',true)",
                  "j.lease_until>clock_timestamp() and j.deadline_at>clock_timestamp()",
                  "public.core_workstation_job_binding_v1(j.spec)", "public.core_job_profile_v1('light','publisher')",
                  "observation_holds h where h.observation_id=old.id"):
        assert check in SQL
    assert "workstation_retention_write_denied" in SQL
    assert "select coalesce(p_spec->>'plugin_id'='sli.workstations'" in SQL
    assert "before delete or update" in SQL
    assert "from public;" in SQL


def test_other_job_admission_and_enqueue_fences_are_preserved():
    assert "else public.core_job_admitted_before_workstations_v1(p_spec) end" in SQL
    previous = (ROOT / "config/postgres_migrations/158_ad_gpo_core_jobs.sql").read_text("utf-8")
    old_body = previous.split("create or replace function public.enqueue_core_job_v1", 1)[1].split("end $$;", 1)[0]
    new_body = SQL.split("create or replace function public.enqueue_core_job_v1", 1)[1].split("end $$;", 1)[0]
    assert new_body.replace("\n           or public.core_workstation_job_binding_v1(p_spec)", "") == old_body
