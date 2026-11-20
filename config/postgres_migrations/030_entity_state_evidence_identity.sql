-- ENTITY-STATE-PROJECTION-HOTFIX-1: make replay-safe history insertion executable.
-- Additive only; no entity-state row is rewritten or deleted.

begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_entity_state_evidence_identity_v30'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 030 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=29 and name='semantic_risk_runtime'
    ) then
        raise exception 'migration 030 requires schema migration 029';
    end if;
    if exists (
        select 1
        from entity_states
        where evidence_event_id is not null
        group by entity_id,state_type,evidence_event_id
        having count(*) > 1
    ) then
        raise exception 'migration 030 refused: duplicate entity-state evidence identities exist';
    end if;
end
$$;

create unique index if not exists uq_entity_states_evidence_identity
    on entity_states(entity_id,state_type,evidence_event_id);

insert into schema_migrations(version,name)
values (30,'entity_state_evidence_identity')
on conflict(version) do update set name=excluded.name;

commit;
