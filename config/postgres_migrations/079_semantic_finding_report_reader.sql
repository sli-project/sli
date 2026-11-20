-- Least-privilege publication-membership reader for the security problems report.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_semantic_finding_report_reader_v79')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 079 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=55 and name='semantic_finding_publication'
    ) then
        raise exception 'migration 079 requires migration 055';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=78 and name='plugin_runtime_guard_read_boundary'
    ) then
        raise exception 'migration 079 requires migration 078';
    end if;
end
$$;

set local role adlog_storage_owner;

create or replace function is_semantic_finding_published_v1(
    p_finding_id bigint
)
returns boolean
language sql stable security definer
set search_path = pg_catalog, public
as $$
    select exists(
        select 1
        from public.semantic_finding_publications publication
        where publication.finding_id=p_finding_id
    )
$$;

revoke all on function is_semantic_finding_published_v1(bigint)
    from public,adlog_user;
grant execute on function is_semantic_finding_published_v1(bigint)
    to adlog_user;

insert into schema_migrations(version,name)
values(79,'semantic_finding_report_reader')
on conflict(version) do update set name=excluded.name;

commit;
