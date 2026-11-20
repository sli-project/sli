begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_storage_v2_direct_identity_v90'));

do $$
declare
    v2_only_events bigint;
    v2_only_entities bigint;
begin
    if to_regclass('public.events') is null
       or to_regclass('public.observed_entities') is null
       or to_regclass('public.observed_entities_id_seq') is null then
        raise exception 'migration 090 rollback requires intact V1 relations';
    end if;

    select count(*) into v2_only_events
    from events_v2_core v2
    left join events v1 on v1.id=v2.id
    where v1.id is null;
    select count(*) into v2_only_entities
    from entities_v2 v2
    left join observed_entities v1 on v1.id=v2.id
    where v1.id is null;

    if v2_only_events <> 0 or v2_only_entities <> 0 then
        raise exception
            'migration 090 rollback is unsafe: % V2-only events and % V2-only entities exist',
            v2_only_events, v2_only_entities;
    end if;
end
$$;

select setval(
    'observed_entities_id_seq',
    greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0),
        1
    ),
    greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0)
    ) > 0
);

alter table entities_v2
    alter column id set default nextval('observed_entities_id_seq'::regclass);
alter table events_v2_core alter column id drop default;

drop table if exists storage_v2_event_identity_allocations;
drop table if exists storage_v2_entity_identity_allocations;
drop sequence if exists storage_v2_event_id_seq;

delete from schema_migrations
where version=90 and name='storage_v2_direct_identity';

commit;
