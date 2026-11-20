-- Irreversibly remove the three retired Storage V1 relations after final V2 acceptance.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_storage_v2_drop_legacy_v1_relations_v97')
);

set local lock_timeout = '10s';
set local statement_timeout = '120s';

do $$
declare
    legacy_oids oid[] := array[
        to_regclass('public.event_entity_links'),
        to_regclass('public.observed_entities'),
        to_regclass('public.events')
    ];
    empty_baseline boolean;
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 097 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=94 and name='storage_v2_runtime_authorization_owner'
    ) then
        raise exception 'migration 097 requires migration 094';
    end if;
    if exists(select 1 from schema_migrations where version=97) then
        raise exception 'migration 097 version is already recorded';
    end if;
    if array_position(legacy_oids, null) is not null then
        raise exception 'migration 097 requires all three legacy relations';
    end if;
    select
        not exists(select 1 from events limit 1)
        and not exists(select 1 from observed_entities limit 1)
        and not exists(select 1 from event_entity_links limit 1)
        and not exists(select 1 from events_v2_core limit 1)
        and not exists(select 1 from entities_v2 limit 1)
    into empty_baseline;
    if not exists (
        select 1 from storage_v2_cutover_state
        where singleton=true and read_mode='v2' and write_mode='v2'
    ) then
        raise exception 'migration 097 requires persisted v2/v2 cutover state';
    end if;
    if exists(select 1 from storage_v2_outbox where state<>'completed') then
        raise exception 'migration 097 requires an empty nonterminal storage v2 outbox';
    end if;
    if not empty_baseline then
        if not exists (
            select 1
            from storage_v2_runtime_authorizations authority
            join storage_v2_cutover_state state on state.singleton=true
            where authority.singleton=true
              and authority.route='v2'
              and authority.revoked_at is null
              and authority.expires_at>now()
              and authority.archive_root=state.archive_root
        ) then
            raise exception 'migration 097 requires active sealed v2 authority';
        end if;
        if not exists(select 1 from events_v2_core limit 1)
           or not exists(select 1 from entities_v2 limit 1) then
            raise exception 'migration 097 requires populated v2 event and entity roots';
        end if;
    end if;
    if exists (
        select 1
        from pg_constraint
        where contype='f'
          and confrelid=any(legacy_oids)
          and not (conrelid=any(legacy_oids))
    ) then
        raise exception 'migration 097 refuses external foreign-key dependencies';
    end if;
    if exists (
        select 1
        from pg_depend dependency
        join pg_rewrite rewrite on dependency.objid=rewrite.oid
        join pg_class dependent on rewrite.ev_class=dependent.oid
        where dependency.refobjid=any(legacy_oids)
          and dependent.relkind in ('v','m')
    ) then
        raise exception 'migration 097 refuses dependent views';
    end if;
end
$$;

drop table event_entity_links;
drop table observed_entities;
drop table events;

insert into schema_migrations(version,name)
values(97,'storage_v2_drop_legacy_v1_relations')
on conflict(version) do update set name=excluded.name;

commit;
