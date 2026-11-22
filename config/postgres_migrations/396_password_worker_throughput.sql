begin;
select pg_advisory_xact_lock(hashtext('sli_password_worker_throughput396'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=393 and name='password_pass_recovery')
       or not exists(select 1 from public.schema_migrations where version=394 and name='notification_language')
       or exists(select 1 from public.schema_migrations where version>=396) then
        raise exception 'password_worker_throughput396_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

create table public.password_restore396(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_restore396 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore396(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.short_ref_allowed337(jsonb,text,text)'::regprocedure,
    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.read_password_detection_coverage(bigint[])'::regprocedure]);

-- Keep the canonical ID/hash checks on the input side so the hot partitions
-- can use their existing bigint event_id indexes for exact evidence checks.
create or replace function public.short_ref_allowed337(s jsonb,p_native text,p_hash text) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists (
        select 1 from public.finding_evidence_source_bindings b join pg_roles r
          on r.oid=b.principal_oid and r.rolname=b.principal_name and r.rolname=session_user
        join public.event_hot h on h.event_id=case
                when p_native ~ '^[1-9][0-9]{0,18}$' and pg_input_is_valid(p_native,'bigint') then p_native::bigint end
          and h.source_sha256=case when p_hash ~ '^[a-f0-9]{64}$' then decode(p_hash,'hex') end
          and (h.method->'$origin')-'agent_id'-'log_source_id'=s
          and h.method#>>'{$origin,agent_id}'=b.agent_id::text
        where b.installation_id::text=s->>'installation_id' and b.plugin_id='sli.windows.ad-dc'
          and s->>'plugin_id'=b.plugin_id and b.source_instance_id=s->>'source_instance_id'
          and b.source_generation=s->>'source_generation' and b.collection_scope_id='' and s->>'collection_scope_id'=''
          and b.storage_kind='core_event'
          and public.semantic_source_active320(b.agent_id,b.plugin_id,h.method->>'$channel'))
$$;

do $$ declare body text; begin
    select definition into strict body from public.password_restore396
        where signature='public.read_password_event_window362(jsonb,jsonb)'::regprocedure;
    if strpos(body,'candidates jsonb[];')=0
       or strpos(body,'b:=public.password_v2_source_binding(s);')=0
       or strpos(body,'m.scope_digest=public.password_v2_scope_key(s)')=0
       or strpos(body,'m.pin=public.password_v2_identity(s,execution)->>''pin''')=0 then
        raise exception 'password_worker_throughput396_reader_shape' using errcode='55000'; end if;
    body:=replace(body,'candidates jsonb[];', 'identity396 jsonb; candidates jsonb[];');
    body:=replace(body,'b:=public.password_v2_source_binding(s);',
        E'b:=public.password_v2_source_binding(s);\n    identity396:=public.password_v2_identity(s,execution);');
    body:=replace(body,'m.scope_digest=public.password_v2_scope_key(s)',
        'm.scope_digest=decode(identity396->>''scope_digest'',''hex'')');
    body:=replace(body,'m.pin=public.password_v2_identity(s,execution)->>''pin''', 'm.pin=identity396->>''pin''');
    execute body;

    select definition into strict body from public.password_restore396
        where signature='public.password_event_clock362(jsonb,jsonb)'::regprocedure;
    if strpos(body,'overflow_at timestamptz;')=0
       or strpos(body,E'    loop\n        select e.time_created_utc into overflow_at')=0
       or strpos(body,'e.time_created_utc between public.password_read_from385(s,execution,t) and t')=0 then
        raise exception 'password_worker_throughput396_clock_shape' using errcode='55000'; end if;
    body:=replace(body,'overflow_at timestamptz;', 'overflow_at timestamptz; lower396 timestamptz;');
    body:=replace(body,E'    loop\n        select e.time_created_utc into overflow_at',
        E'    loop\n        lower396:=public.password_read_from385(s,execution,t);\n        select e.time_created_utc into overflow_at');
    execute replace(body,'e.time_created_utc between public.password_read_from385(s,execution,t) and t',
        'e.time_created_utc between lower396 and t');
end $$;

-- Retire only the history cursors reconstructed from pre-393 restart forks.
-- The active live checkpoint, older proof chains and all publication jobs stay intact.
create table public.password_retired_history396(
    scope_digest bytea not null,rule_id text not null,live_pin text not null,
    history_pin text not null,history_from timestamptz not null,history_to timestamptz not null,
    primary key(scope_digest,rule_id));
revoke all on public.password_retired_history396 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_retired_history396
select p.scope_digest,p.rule_id,p.live_pin,p.history_pin,p.history_from,p.history_to
from public.password_pass_state393 p
join public.password_passes388 f on f.scope_digest=p.scope_digest and f.previous_pin=p.history_pin
join public.schema_migrations m on m.version=393 and f.created_at<m.applied_at;
update public.password_pass_state393 p set history_pin=null,history_from=null,history_to=null
from public.password_retired_history396 old where p.scope_digest=old.scope_digest and p.rule_id=old.rule_id;

-- Retired checkpoints remain available to proof validation and publication.
-- An error on a superseded pin does not describe the active source's coverage.
do $$ declare body text; begin
    select definition into strict body from public.password_restore396
        where signature='public.read_password_detection_coverage(bigint[])'::regprocedure;
    if strpos(body,'where cp.owner_domain_id=any(allowed_domains)')=0 then
        raise exception 'password_worker_throughput396_coverage_shape' using errcode='55000'; end if;
    execute replace(body,'where cp.owner_domain_id=any(allowed_domains)', $patched$where cp.owner_domain_id=any(allowed_domains)
          and not (cp.health_status='error' and cp.health_reason is not distinct from 'source_error' and exists (
              select 1 from public.password_pass_state393 p join public.password_passes388 f
                on f.scope_digest=p.scope_digest and f.previous_pin=cp.pin
              where p.scope_digest=cp.scope_digest and p.rule_id=cp.execution_json->>'rule_id'
                and p.live_pin<>cp.pin and p.history_pin is distinct from cp.pin))$patched$);
    if exists(select 1 from public.password_restore396 d join pg_proc p on p.oid=d.signature
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_worker_throughput396_metadata_changed' using errcode='55000'; end if;
end $$;

update public.password_restore396 set installed_definition=pg_get_functiondef(signature);
insert into public.schema_migrations(version,name) values(396,'password_worker_throughput');
reset role;
commit;
