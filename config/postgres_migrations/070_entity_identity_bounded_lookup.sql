begin;

do $$
begin
    if not exists (
        select 1 from schema_migrations
        where version=69 and name='entity_identity_runtime_repair'
    ) then
        raise exception 'migration 070 requires migration 069';
    end if;
    if exists (select 1 from schema_migrations where version=70) then
        raise exception 'schema migration 070 is already registered';
    end if;
end
$$;

set local role adlog_storage_owner;

-- Fixed report queries already hold an entity UUID obtained from a bounded
-- relation/version set.  This helper answers only whether that UUID was merged
-- away; it does not expose merge target, evidence or audit rows to adlog_user.
create or replace function entity_v2_is_active(p_entity_id bigint)
returns boolean
language sql
stable
strict
security definer
set search_path=pg_catalog,public
as $$
    select not exists (
        select 1
        from public.entity_identity_merges_v2 merged
        where merged.source_entity_id=p_entity_id
    )
$$;

alter function entity_v2_is_active(bigint) owner to adlog_storage_owner;
revoke all on function entity_v2_is_active(bigint) from public;
grant execute on function entity_v2_is_active(bigint) to adlog_user;

reset role;

insert into schema_migrations(version,name)
values(70,'entity_identity_bounded_lookup')
on conflict(version) do nothing;

commit;
