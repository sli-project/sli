begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_index_finding_evidence_copy408'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=407 and name='bound_source_discovery')
       or exists(select 1 from public.schema_migrations where version>=408) then
        raise exception 'index_finding_evidence_copy408_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.finding_evidence_copy_restore408(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.finding_evidence_copy_restore408 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.finding_evidence_copy_restore408(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.copy_finding_event337(bigint,text,text,text,text)'::regprocedure
    and proowner='adlog_storage_owner'::regrole and prosecdef and provolatile='v'
    and proconfig=array['search_path=pg_catalog, pg_temp'];

do $patch$
declare saved record; found_at integer;
    old_entry constant text:=$old$begin
    insert into public.finding_event_copies337$old$;
    guarded_entry constant text:=$new$begin
    -- Reject non-bigint inputs before planning the indexed statement.
    if pg_input_is_valid(p_native,'bigint') is not true then return false; end if;
    insert into public.finding_event_copies337$new$;
    old_lookup constant text:=$old$    where h.event_id::text=p_native and encode(h.source_sha256,'hex')=p_hash$old$;
    indexed_lookup constant text:=$new$    where h.event_id=p_native::bigint
      and h.event_id::text=p_native and encode(h.source_sha256,'hex')=p_hash$new$;
begin
    select * into strict saved from public.finding_evidence_copy_restore408;
    found_at:=strpos(saved.definition,old_lookup);
    if found_at=0 or strpos(substr(saved.definition,found_at+length(old_lookup)),old_lookup)<>0
        or strpos(saved.definition,old_entry)=0 then
        raise exception 'index_finding_evidence_copy408_shape' using errcode='55000';
    end if;
    -- Use the partition indexes while requiring the original canonical ID and hash.
    execute replace(replace(saved.definition,old_lookup,indexed_lookup),old_entry,guarded_entry);
    if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
        and p.proacl is not distinct from saved.acl) then
        raise exception 'index_finding_evidence_copy408_metadata' using errcode='55000';
    end if;
    update public.finding_evidence_copy_restore408 set installed_definition=pg_get_functiondef(signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(408,'index_finding_evidence_copy');
commit;
