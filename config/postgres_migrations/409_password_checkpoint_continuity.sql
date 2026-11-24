begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=408 and name='index_finding_evidence_copy')
       or exists(select 1 from public.schema_migrations where version>=409) then
        raise exception 'password_checkpoint_continuity409_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The caller has already deduplicated the exact witnesses, rejected native ID
-- conflicts and sorted this continuity array by canonical native ID.
create function public.password_continuity_native_cost409(s jsonb,witnesses jsonb)
returns bigint language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare first_unit jsonb; second_unit jsonb; declared_bytes bigint; refs integer;
begin
    refs:=jsonb_array_length(witnesses);
    if refs<=10000 then return public.password_v2_native_cost(s,witnesses); end if;
    if refs>20000 then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;

    select jsonb_agg(witness order by ordinal) filter (where ordinal<=10000),
           jsonb_agg(witness order by ordinal) filter (where ordinal>10000),
           sum((witness->>'xml_bytes')::bigint)
      into first_unit,second_unit,declared_bytes
      from jsonb_array_elements(witnesses) with ordinality a(witness,ordinal);
    if declared_bytes>33554432 then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
    return public.password_v2_native_cost(s,first_unit)+public.password_v2_native_cost(s,second_unit);
end $$;
revoke all on function public.password_continuity_native_cost409(jsonb,jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create table public.password_continuity_restore409(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_continuity_restore409 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_continuity_restore409(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.password_checkpoint_native_cost403(jsonb,jsonb,bytea,text,text[])'::regprocedure
    and proowner='adlog_storage_owner'::regrole and not prosecdef and provolatile='s'
    and proconfig=array['search_path=pg_catalog, pg_temp'];

do $patch$
declare saved record; found_at integer;
    old_cost constant text:='    cost:=public.password_v2_native_cost(s,continuity);';
    new_cost constant text:='    cost:=public.password_continuity_native_cost409(s,continuity);';
begin
    select * into strict saved from public.password_continuity_restore409;
    found_at:=strpos(saved.definition,old_cost);
    if found_at=0 or strpos(substr(saved.definition,found_at+length(old_cost)),old_cost)<>0 then
        raise exception 'password_checkpoint_continuity409_shape' using errcode='55000';
    end if;
    execute replace(saved.definition,old_cost,new_cost);
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl) then
        raise exception 'password_checkpoint_continuity409_metadata' using errcode='55000';
    end if;
    update public.password_continuity_restore409 set installed_definition=pg_get_functiondef(signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(409,'password_checkpoint_continuity');
commit;
