begin;
select pg_advisory_xact_lock(hashtext('sli_semantic_archive_authorization_reader366'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=362 and name='detection_event_clock')
       or exists(select 1 from public.schema_migrations where version>=366)
       or (select relowner from pg_class where oid=to_regclass('public.storage_v2_runtime_authorizations')) is distinct from 'adlog_storage_owner'::regrole then
        raise exception 'semantic_archive_authorization_reader366_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The semantic reader must validate the persisted archive admission before
-- opening a published object. It cannot create, renew or revoke admission.
grant select on public.storage_v2_runtime_authorizations to adlog_semantic_worker;

insert into public.schema_migrations(version,name) values(366,'semantic_archive_authorization_reader');
reset role;
commit;
