begin;
select pg_advisory_xact_lock(hashtext('ad_log_agent_registration_hostname_v281'));
do $$ begin
    if not exists(select 1 from public.schema_migrations where version=280 and name='service_account_origin') then
        raise exception 'migration 281 requires exact migration 280 service_account_origin';
    end if;
    if exists(select 1 from public.schema_migrations where version=281) then
        raise exception 'migration 281 already applied or occupied';
    end if;
end $$;

-- Nullable, initial-registration display claim; never identity or authority.
-- Existing rows stay NULL. Existing table SELECT/INSERT permissions suffice;
-- no permission to change this column is added to the API role.
alter table public.sli_agents add column registration_host_name text
    check(registration_host_name is null or (
        char_length(registration_host_name) between 1 and 253
        and registration_host_name ~ '^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
    ));

insert into public.schema_migrations(version,name) values(281,'agent_registration_hostname');
commit;
