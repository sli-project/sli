begin;
select pg_advisory_xact_lock(hashtext('sli_event_storage_read_grants_v336'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'event_storage_read_grants_336_rollback_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=335 and name='event_storage_s2')
       or not exists(select 1 from public.schema_migrations where version=336 and name='event_storage_read_grants')
       or exists(select 1 from public.schema_migrations where version>336)
       or (select relowner from pg_class where oid=to_regclass('public.event_hot')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'event_storage_read_grants_336_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
revoke select on public.event_hot,public.event_cold_facts,public.event_cold_daily from adlog_user;
delete from public.schema_migrations where version=336 and name='event_storage_read_grants';
reset role;
commit;
