begin;
select pg_advisory_xact_lock(hashtext('sli_password_producer_failures370'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=366 and name='semantic_archive_authorization_reader')
       or exists(select 1 from public.schema_migrations where version>=370) then
        raise exception 'password_producer370_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.password_producer_restore370(
    signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]
);
revoke all on public.password_producer_restore370 from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
insert into public.password_producer_restore370(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_policy_ensure_v275(text,integer,text)'::regprocedure,
    'public.password_v2_locked_checkpoint(jsonb,jsonb,boolean)'::regprocedure,
    'public.lock_password_reservation_entities_v2(jsonb,jsonb,bigint,bigint,text[])'::regprocedure
]);

-- Keep the lock keys and order used by policy management, domain binding and
-- publication. Contention yields immediately; the next producer cycle retries.
do $$ declare r record; body text; before_patch text; begin
    for r in select * from public.password_producer_restore370 order by signature loop
        if r.owner_oid is distinct from 'adlog_storage_owner'::regrole then
            raise exception 'password_producer370_owner' using errcode='55000';
        end if;
        body:=r.definition;
        if r.signature like '%password_policy_ensure_v275(%' then
            if strpos(body,'perform public.password_policy_family_lock_v275(s,r);')=0
               or strpos(body,'perform pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(s),''hex''),0));')=0
               or strpos(body,'for update;')=0 then
                raise exception 'password_producer370_policy_shape' using errcode='55000';
            end if;
            -- Retain the family's isolation/scope/rule validation verbatim;
            -- once acquired, its original lock call is reentrant.
            body:=replace(body,'perform public.password_policy_family_lock_v275(s,r);',
                'if not pg_try_advisory_xact_lock(hashtextextended(''sli.password.policy-family.1:''||
                    encode(public.password_v2_scope_key(s),''hex'')||'':''||r,0)) then
                    raise exception ''password_producer_busy'' using errcode=''55P03'';
                end if;
                perform public.password_policy_family_lock_v275(s,r);');
            body:=replace(body,'perform pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(s),''hex''),0));',
                'if not pg_try_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(s),''hex''),0)) then
                    raise exception ''password_producer_busy'' using errcode=''55P03'';
                end if;');
        elsif r.signature like '%password_v2_locked_checkpoint(%' then
            if strpos(body,'perform pg_advisory_xact_lock(hashtextextended(identity->>''scope_digest'',0));')=0
               or strpos(body,'for update;')=0 then
                raise exception 'password_producer370_checkpoint_shape' using errcode='55000';
            end if;
            body:=replace(body,'perform pg_advisory_xact_lock(hashtextextended(identity->>''scope_digest'',0));',
                'if not pg_try_advisory_xact_lock(hashtextextended(identity->>''scope_digest'',0)) then
                    raise exception ''password_producer_busy'' using errcode=''55P03'';
                end if;');
        else
            if strpos(body,'perform pg_advisory_xact_lock(lock_key);')=0 then
                raise exception 'password_producer370_entity_shape' using errcode='55000';
            end if;
            body:=replace(body,'perform pg_advisory_xact_lock(lock_key);',
                'if not pg_try_advisory_xact_lock(lock_key) then
                    raise exception ''password_producer_busy'' using errcode=''55P03'';
                end if;');
        end if;
        body:=replace(body,'for update;','for update nowait;');
        before_patch:=r.definition;
        if body=before_patch then raise exception 'password_producer370_shape' using errcode='55000'; end if;
        execute body;
        update public.password_producer_restore370 set installed_definition=pg_get_functiondef(r.signature::regprocedure)
            where signature=r.signature;
        if exists(select 1 from pg_proc where oid=r.signature::regprocedure
            and (proowner is distinct from r.owner_oid or proacl is distinct from r.acl)) then
            raise exception 'password_producer370_metadata_changed' using errcode='55000';
        end if;
    end loop;
end $$;
insert into public.schema_migrations(version,name) values(370,'password_producer_failures');
reset role;
commit;
