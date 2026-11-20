-- Roll back SEMANTIC-CORRELATION-1 only before any rule/candidate/replay data.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_correlation_v26'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 026 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from semantic_correlation_rules)
       or exists (select 1 from semantic_correlation_candidates)
       or exists (select 1 from semantic_correlation_replays) then
        raise exception 'rollback 026 refused: semantic correlation data exists';
    end if;
end
$$;

set local role adlog_storage_owner;

drop index if exists idx_semantic_correlation_replay_claim;
drop index if exists idx_semantic_correlation_candidate_evidence_event;
drop index if exists idx_semantic_correlation_candidate_partition;
drop table if exists semantic_correlation_replays;
drop table if exists semantic_correlation_candidate_evidence;
drop table if exists semantic_correlation_candidates;
drop trigger if exists trg_semantic_correlation_rule_immutability
    on semantic_correlation_rules;
drop function if exists enforce_semantic_correlation_rule_immutability();
drop table if exists semantic_correlation_rules;

delete from schema_migrations
where version=26 and name='semantic_correlation_foundation';

commit;
