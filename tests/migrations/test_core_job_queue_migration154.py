from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SQL = (ROOT / "config/postgres_migrations/154_core_job_queue.sql").read_text("utf-8")
ROLLBACK = (ROOT / "config/postgres_migrations/154_core_job_queue.rollback.sql").read_text("utf-8")


def body(name):
    return SQL.split(f"create function public.{name}", 1)[1].split("end $$;", 1)[0]


def test_migration_uses_next_number_and_refuses_history_deletion():
    preflight = SQL.split("create role sli_job_owner", 1)[0]
    assert "not exists(select 1 from public.schema_migrations where version=153 and name='semantic_governance')" in preflight
    assert "migration 154 prerequisites failed" in preflight
    assert "if exists(select 1 from public.schema_migrations where version=154)" in preflight
    assert "migration 154 already applied" in preflight
    assert "values(154,'core_job_queue')" in SQL
    assert "version=154 and name='core_job_queue'" in ROLLBACK
    assert "version>154" in ROLLBACK
    assert "rollback 154 prerequisites failed" in ROLLBACK
    assert "rollback 154 refuses job history" in ROLLBACK
    assert "delete from public.schema_migrations where version=154 and name='core_job_queue'" in ROLLBACK
    for script in (SQL, ROLLBACK):
        assert "pg_advisory_xact_lock(hashtext('sli_core_job_queue_v154'))" in script
        assert "sli_core_job_queue_v153" not in script
    assert "if exists(select 1 from sli_jobs.jobs)" in ROLLBACK
    assert "drop table public.acquisition" not in ROLLBACK


def test_queue_has_atomic_partition_claim_and_aged_priority():
    claim = body("claim_core_job_v1")
    assert "for update skip locked" in claim
    assert "pg_try_advisory_xact_lock" in claim
    assert "create unique index core_job_partition_writer" in SQL
    assert "lease_generation=lease_generation+1" in claim
    assert "attempts=attempts+1" in claim
    assert "j.priority+floor" in claim
    assert "manifest_sha256" in claim and "plugin_version" in claim


def test_reaper_quarantines_exhausted_and_deadline_jobs_and_backs_off():
    claim = body("claim_core_job_v1")
    assert "attempts>=max_attempts or deadline_at<=v_now" in claim
    assert "state='leased' and lease_until<=v_now" in claim
    assert "then 'quarantined' else 'retry_wait'" in claim
    assert "least(3600,30*power(2" in claim
    assert "insert into sli_jobs.audit" in claim
    fail = body("fail_core_job_v1")
    assert "p_permanent or attempts>=max_attempts" in fail
    assert "lease_until>clock_timestamp()" in fail


def test_heartbeat_and_publication_check_expiry_generation_and_deadline():
    heartbeat = body("heartbeat_core_job_v1")
    finish = body("finish_core_job_result_v1")
    for function in (heartbeat, finish):
        assert "lease_token=p_token and lease_generation=p_generation" in function
        assert "lease_until>clock_timestamp() and deadline_at>clock_timestamp()" in function
    assert "least(deadline_at,clock_timestamp()+interval '60 seconds')" in heartbeat
    begin = body("begin_core_job_result_v1")
    assert "for update" in begin
    assert "v_job.lease_until<=clock_timestamp()" in begin
    assert "v_job.lease_generation<>p_generation" in begin
    assert "return 'duplicate'" in begin and "result_hash_conflict" in begin


def test_profile_roles_have_no_queue_dml_or_other_plugin_roles():
    assert "nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication" in SQL
    assert "grant adlog_radius_session_consumer to sli_job_publisher_light with inherit true, set false" in SQL
    assert "grant adlog_radius_session_consumer to sli_job_executor" not in SQL
    assert "grant execute on function public.read_radius_job_input_v1" in SQL
    assert "revoke all on all tables in schema sli_jobs from public" in SQL
    assert "set local role sli_job_executor" not in SQL
    assert "grant usage,create on schema public to sli_job_owner" in SQL
    assert "revoke create on schema public from sli_job_owner" in SQL
    assert "s.source_instance_id=j.source_instance_id" in SQL


def test_enqueue_has_unique_identity_conflict_and_source_quota():
    enqueue = body("enqueue_core_job_v1")
    assert "idempotency_key text not null unique" in SQL
    assert "v_job.spec-'available_at_utc'-'deadline_at_utc'" in enqueue
    assert "then return null" in enqueue
    assert "pg_advisory_xact_lock" in enqueue
    assert "max_inflight_per_source" in enqueue
    assert "schedule_key text unique" in SQL
    assert "where schedule_key=p_spec->>'schedule_key'" in enqueue


def test_claim_checks_canonical_plugin_activation_without_enabling_acquisition():
    assert "g.desired_activation='enabled_manual'" in SQL
    assert "g.component_runtime='running' and g.admission_mode='open'" in SQL
    assert "p_spec->>'handler_id'='radius-session-observation'" in SQL
    assert "update public.plugin_installations" not in SQL
