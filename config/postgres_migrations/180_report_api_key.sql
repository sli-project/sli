-- A nullable association preserves existing API-key behaviour.
begin;
select pg_advisory_xact_lock(hashtext('sli_report_api_key_v180'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 180 requires storage owner membership';
    end if;
    if exists(select 1 from public.schema_migrations where version=180) then
        raise exception 'migration 180 already applied';
    end if;
end $$;
alter table public.auth_api_keys add column report_subject_id bigint references public.auth_users(id);
insert into public.schema_migrations(version,name) values(180,'report_api_key');
commit;
