-- Keep legacy event entities and AD Context entities in one collision-free ID
-- space while observed_entities remains the authoritative V1 source.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_ad_context_shared_entity_identity_v45'));

do $$
declare
    greatest_id bigint;
begin
    if not exists (
        select 1 from schema_migrations
        where version=44 and name='entities_v2_recent_index'
    ) then
        raise exception 'migration 045 requires migration 044';
    end if;
    if to_regclass('observed_entities_id_seq') is null
       or to_regclass('entities_v2_id_seq') is null then
        raise exception 'migration 045 requires both entity sequences';
    end if;
    if not exists (select 1 from pg_roles where rolname='adlog_context_worker') then
        raise exception 'migration 045 requires role adlog_context_worker';
    end if;

    select greatest(
        coalesce((select max(id) from observed_entities), 0),
        coalesce((select max(id) from entities_v2), 0)
    ) into greatest_id;
    if greatest_id >= 2147483647 then
        raise exception 'entities_v2 int32 identity capacity is exhausted at %', greatest_id;
    end if;
end
$$;

-- Storage V2 copies explicit V1 IDs. AD Context must therefore reserve its new
-- IDs from the same sequence instead of a second sequence that can collide.
select setval(
    'observed_entities_id_seq',
    greatest(
        (select last_value from observed_entities_id_seq),
        coalesce((select max(id) from observed_entities), 1),
        coalesce((select max(id) from entities_v2), 1)
    ),
    true
);

alter table entities_v2
    alter column id set default nextval('observed_entities_id_seq'::regclass);

grant usage, select on sequence observed_entities_id_seq to adlog_context_worker;

insert into schema_migrations(version, name)
values (45, 'ad_context_shared_entity_identity')
on conflict(version) do update set name=excluded.name;

commit;
