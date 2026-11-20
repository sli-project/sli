-- FOUNDATION-1 rollback is deliberately fail-closed: semantic history is
-- evidence and must be preserved until an operator explicitly archives it.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_processing_foundation_v22_rollback'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 022 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from normalized_events)
       or exists (select 1 from canonical_actions)
       or exists (select 1 from canonical_action_evidence)
       or exists (select 1 from semantic_processing_outbox) then
        raise exception 'rollback 022 refused: semantic processing rows exist';
    end if;
end
$$;

set local role adlog_storage_owner;

drop table if exists canonical_action_evidence;
drop table if exists semantic_processing_outbox;
drop table if exists canonical_actions;
drop table if exists normalized_events;

delete from schema_migrations
where version=22 and name='semantic_processing_foundation';

commit;
