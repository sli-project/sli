begin;
select pg_advisory_xact_lock(hashtext('sli_password_live_state_bound386'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=385 and name='password_state_and_step')
       or exists(select 1 from public.schema_migrations where version>=386) then
        raise exception 'password_live_state_bound386_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
create table public.password_restore386(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.password_restore386 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore386(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.password_v2_check_state(jsonb,jsonb,text)'::regprocedure;

-- Measured with the existing 385 indexed witnesses and maximum source scope:
-- 3000 noise accounts + 9 pending failures: 9,175,630 bytes (spray: 8,460,130).
-- 16 MiB keeps those origins live without eviction. Native, ancestry, ledger,
-- per-episode proof and 10000-row/episode checks retain their existing limits.
do $$ declare r record; body text; begin
    select * into strict r from public.password_restore386;
    if r.owner_oid<>'adlog_storage_owner'::regrole then
        raise exception 'password_live_state_bound386_owner' using errcode='55000'; end if;
    body:=r.definition;
    if strpos(body,'octet_length(stored::text)>4194304')=0
       or strpos(body,'if bytes>4194304 then')=0 then
        raise exception 'password_live_state_bound386_shape' using errcode='55000'; end if;
    body:=replace(body,'octet_length(stored::text)>4194304','octet_length(stored::text)>16777216');
    body:=replace(body,'if bytes>4194304 then','if bytes>16777216 then');
    execute body;
end $$;
update public.password_restore386 d set installed_definition=pg_get_functiondef(d.signature::regprocedure);
do $$ begin
    if exists(select 1 from public.password_restore386 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_live_state_bound386_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(386,'password_live_state_bound');
reset role;
commit;
