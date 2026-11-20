-- STAGE8-K1-K2: immutable completeness values for every semantic conclusion.
-- Source-only. It does not enable workers, policies, findings or collection.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_conclusion_completeness_v52')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 052 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=51 and name='event_catalog_revision_reference'
    ) then
        raise exception 'migration 052 requires migration 051';
    end if;
    if to_regclass('semantic_risk_evaluation_results') is null then
        raise exception 'migration 052 requires semantic risk runtime';
    end if;
end
$$;

-- collection_channel_state is owned by the legacy read role on the current
-- production topology.  The migration session owns/controls that object;
-- the storage-owner role deliberately does not.
grant select on table collection_channel_state to adlog_semantic_worker;

set local role adlog_storage_owner;

alter table semantic_risk_evaluation_results
    add column if not exists conclusion_state text not null default 'not_checked',
    add column if not exists completeness_snapshot_json jsonb not null default
        '{
          "captured_at_utc": null,
          "catalog_completeness": {
            "entry_count": 0,
            "fully_classified": 0,
            "classification_ratio": 0,
            "schema_v2_ready": 0
          },
          "collection_freshness": {
            "max_age_seconds": null,
            "budget_seconds": 1800,
            "complete": false
          },
          "channel_availability": {
            "required": [],
            "available": [],
            "available_count": 0,
            "required_count": 0,
            "complete": false
          },
          "window_closure": {
            "window_end_utc": null,
            "descriptor_close_timeout_seconds": null,
            "allowed_lateness_seconds": 0,
            "close_deadline_utc": null,
            "closed": false
          },
          "supports_negative_conclusion": false,
          "legacy_missing": true
        }'::jsonb;

do $$
begin
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_risk_evaluation_results'::regclass
          and conname='semantic_risk_result_conclusion_state'
    ) then
        alter table semantic_risk_evaluation_results
            add constraint semantic_risk_result_conclusion_state
            check (conclusion_state in ('observed','not_found','not_checked'));
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_risk_evaluation_results'::regclass
          and conname='semantic_risk_result_completeness_shape'
    ) then
        alter table semantic_risk_evaluation_results
            add constraint semantic_risk_result_completeness_shape
            check (
                jsonb_typeof(completeness_snapshot_json)='object'
                and completeness_snapshot_json ? 'catalog_completeness'
                and completeness_snapshot_json ? 'collection_freshness'
                and completeness_snapshot_json ? 'channel_availability'
                and completeness_snapshot_json ? 'window_closure'
                and completeness_snapshot_json ? 'supports_negative_conclusion'
            );
    end if;
    if not exists (
        select 1 from pg_constraint
        where conrelid='semantic_risk_evaluation_results'::regclass
          and conname='semantic_risk_result_negative_gate'
    ) then
        alter table semantic_risk_evaluation_results
            add constraint semantic_risk_result_negative_gate
            check (
                conclusion_state <> 'not_found'
                or completeness_snapshot_json->>'supports_negative_conclusion'='true'
            );
    end if;
end
$$;

create index if not exists idx_semantic_risk_result_conclusion
    on semantic_risk_evaluation_results(
        conclusion_state,created_at,job_id
    );

insert into schema_migrations(version,name)
values(52,'semantic_conclusion_completeness')
on conflict(version) do update set name=excluded.name,applied_at=now();

commit;
