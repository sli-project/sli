begin;
select pg_advisory_xact_lock(hashtext('sli_detection_source_lock383'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=382 and name='password_clock_catch_up')
       or exists(select 1 from public.schema_migrations where version>=383) then
        raise exception 'detection_source_lock383_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.detection_source_restore383(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.detection_source_restore383 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.detection_source_restore383(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_policy_ensure_v275(text,integer,text)'::regprocedure,
    'public.password_v2_locked_checkpoint(jsonb,jsonb,boolean)'::regprocedure,
    'public.lock_password_reservation_entities_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure,
    'public.password_producer_source382(jsonb,boolean)'::regprocedure
]);

-- Restore only the waiting semantics changed by 370. Its saved definitions
-- retain all validation and the established lock order: family, policy rows,
-- source, checkpoint, sorted entity keys. The separate source-session lock is
-- acquired before these and is never requested by policy/configuration writers.
do $$ declare r record; original record; body text; begin
    for r in select * from public.detection_source_restore383 order by signature loop
        if r.owner_oid is distinct from 'adlog_storage_owner'::regrole then
            raise exception 'detection_source_lock383_owner' using errcode='55000'; end if;
        if r.signature like '%password_producer_source382(%' then
            if strpos(r.definition,'if acquire then return pg_try_advisory_lock(k); end if;')=0 then
                raise exception 'detection_source_lock383_shape' using errcode='55000'; end if;
            body:=replace(r.definition,'if acquire then return pg_try_advisory_lock(k); end if;',
                'if acquire then perform pg_advisory_lock(k); return true; end if;');
        else
            select * into strict original from public.password_producer_restore370 where signature=r.signature;
            if r.definition is distinct from original.installed_definition
               or r.owner_oid is distinct from original.owner_oid or r.acl is distinct from original.acl then
                raise exception 'detection_source_lock383_changed' using errcode='55000'; end if;
            body:=original.definition;
        end if;
        execute body;
        update public.detection_source_restore383 set installed_definition=pg_get_functiondef(r.signature::regprocedure)
            where signature=r.signature;
        if exists(select 1 from pg_proc where oid=r.signature::regprocedure
            and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'detection_source_lock383_metadata_changed' using errcode='55000'; end if;
    end loop;
end $$;
insert into public.schema_migrations(version,name) values(383,'detection_source_lock');
reset role;
commit;
