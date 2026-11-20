-- Revoke only before the entity-state projector has produced durable output.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_conflict_privilege_v31'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 031 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from entity_state_current)
       or exists (
           select 1 from entity_state_projection_jobs
           where status='completed'
       ) then
        raise exception 'rollback 031 refused: entity-state projection output exists';
    end if;
end
$$;

revoke select(entity_id,state_type,evidence_event_id)
    on entity_states from adlog_storage_worker;

delete from schema_migrations
where version=31 and name='entity_state_conflict_key_privilege';

commit;
