-- Roll back only before the entity-state projector has produced durable output.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_evidence_identity_v30'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 030 requires membership in adlog_storage_owner';
    end if;
    if exists (select 1 from entity_state_current)
       or exists (
           select 1 from entity_state_projection_jobs
           where status='completed'
       ) then
        raise exception 'rollback 030 refused: entity-state projection output exists';
    end if;
end
$$;

drop index if exists uq_entity_states_evidence_identity;

delete from schema_migrations
where version=30 and name='entity_state_evidence_identity';

commit;
