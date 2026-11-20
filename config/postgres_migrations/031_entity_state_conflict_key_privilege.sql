-- ENTITY-STATE-PROJECTION-HOTFIX-2: least privilege for ON CONFLICT inference.
-- The worker may read only the three evidence identity columns, not state payloads.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_conflict_privilege_v31'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 031 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=30 and name='entity_state_evidence_identity'
    ) then
        raise exception 'migration 031 requires schema migration 030';
    end if;
end
$$;

grant select(entity_id,state_type,evidence_event_id)
    on entity_states to adlog_storage_worker;

insert into schema_migrations(version,name)
values (31,'entity_state_conflict_key_privilege')
on conflict(version) do update set name=excluded.name;

commit;
