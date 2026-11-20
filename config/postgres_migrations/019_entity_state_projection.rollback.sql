begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_projection_rollback'));

do $$
begin
    if exists (select 1 from entity_state_projection_jobs)
       or exists (select 1 from entity_state_current) then
        raise exception 'migration 19 rollback forbidden while projection data exists; export and explicitly clear it first';
    end if;
end
$$;

revoke insert on entity_states from adlog_storage_worker;
revoke usage on sequence entity_states_id_seq from adlog_storage_worker;
drop table if exists entity_state_current;
drop table if exists entity_state_projection_jobs;
delete from schema_migrations where version=19 and name='entity_state_projection';
commit;
