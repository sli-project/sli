-- Roll back SEMANTIC-DISPATCH-1 only before dispatch/candidate state exists.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_dispatch_v27'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 027 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from semantic_correlation_subscriptions)
       or exists (select 1 from semantic_correlation_dispatch_jobs)
       or exists (select 1 from semantic_correlation_candidates) then
        raise exception 'rollback 027 refused: semantic dispatch or candidate data exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_correlation_dispatch_partition;
drop index if exists idx_semantic_correlation_dispatch_claim;
drop index if exists idx_semantic_correlation_subscription_type;
drop table if exists semantic_correlation_dispatch_jobs;
drop trigger if exists trg_semantic_subscription_draft_only
    on semantic_correlation_subscriptions;
drop function if exists enforce_semantic_subscription_draft_only();
drop table if exists semantic_correlation_subscriptions;

alter table semantic_correlation_candidate_evidence
    drop column if exists is_late;

alter table semantic_correlation_candidates
    drop constraint if exists semantic_correlation_candidate_reopen_counts,
    drop column if exists last_evidence_occurred_at,
    drop column if exists closed_at,
    drop column if exists late_evidence_count,
    drop column if exists reopen_count;

delete from schema_migrations
where version=27 and name='semantic_dispatch_foundation';

commit;
