begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_conclusion_completeness_v52')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 052 rollback requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from schema_migrations where version>52) then
        raise exception 'migration 052 rollback refuses later migrations';
    end if;
    if exists (
        select 1
        from semantic_risk_evaluation_results
        where not coalesce(
            (completeness_snapshot_json->>'legacy_missing')::boolean,
            false
        )
        limit 1
    ) then
        raise exception 'migration 052 rollback refuses persisted completeness evidence';
    end if;
end
$$;

revoke select on table collection_channel_state from adlog_semantic_worker;

set local role adlog_storage_owner;

drop index if exists idx_semantic_risk_result_conclusion;

alter table semantic_risk_evaluation_results
    drop constraint if exists semantic_risk_result_negative_gate,
    drop constraint if exists semantic_risk_result_completeness_shape,
    drop constraint if exists semantic_risk_result_conclusion_state,
    drop column if exists completeness_snapshot_json,
    drop column if exists conclusion_state;

delete from schema_migrations
where version=52 and name='semantic_conclusion_completeness';

commit;
