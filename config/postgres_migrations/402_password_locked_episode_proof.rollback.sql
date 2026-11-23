begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_locked_episode_proof402'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=402 and name='password_locked_episode_proof')
       or exists(select 1 from public.schema_migrations where version>402) then
        raise exception 'password_locked_episode_proof402_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.read_locked_password_episode402(jsonb,jsonb,text);
reset role;
delete from public.schema_migrations where version=402 and name='password_locked_episode_proof';
commit;
