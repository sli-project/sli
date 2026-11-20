begin;
select pg_advisory_xact_lock(hashtext('sli_password_window_capacity387'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=386 and name='password_live_state_bound')
       or exists(select 1 from public.schema_migrations where version>=387) then
        raise exception 'password_window_capacity387_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
create table public.password_restore387(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.password_restore387 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore387(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.password_event_clock362(jsonb,jsonb)'::regprocedure;
do $$ begin
    if exists(select 1 from public.password_restore387 where owner_oid<>'adlog_storage_owner'::regrole) then
        raise exception 'password_window_capacity387_owner' using errcode='55000'; end if;
end $$;

-- Keep the 385 decision slice, but budget its complete reader horizon BEFORE
-- excluding checkpoint members. Old checkpoints and newly arrived too_late
-- rows both consume that horizon, as does the 120-second undecided tail.
-- The reader and finalizer still enforce their exact native and window gates.
create or replace function public.password_event_clock362(s jsonb,execution jsonb) returns timestamptz
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; cutoff timestamptz; first_at timestamptz; batch_at timestamptz;
    final_target timestamptz:=statement_timestamp()-interval '120 seconds';
    decision_members integer:=6000; t timestamptz; overflow_at timestamptz; next_t timestamptz;
begin
    perform public.password_v2_source_binding(s);
    identity:=public.password_v2_identity(s,execution);
    select c.watermark into cutoff from public.semantic_password_checkpoints c
    where c.scope_digest=decode(identity->>'scope_digest','hex') and c.pin=identity->>'pin';
    select min(e.time_created_utc),max(e.time_created_utc) into first_at,batch_at from (
        select h.time_created_utc from public.event_hot h
        where h.source_sha256 is not null and h.method->>'$channel'='Security'
          and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
          and (h.method->'$origin')-'agent_id'-'log_source_id'=s
          and h.event_kind in(4624,4625,4771,4776) and h.time_created_utc<=final_target
          and h.time_created_utc>coalesce(cutoff,'-infinity'::timestamptz)
        order by h.time_created_utc,h.event_id limit decision_members
    ) e;
    if first_at is null then
        if cutoff is not null or exists(select 1 from public.event_hot h
            where h.source_sha256 is not null and h.method->>'$channel'='Security'
              and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
              and (h.method->'$origin')-'agent_id'-'log_source_id'=s
              and h.event_kind in(4624,4625,4771,4776) and h.time_created_utc<=statement_timestamp()) then
            t:=greatest(final_target,cutoff)+interval '120 seconds';
        else return null; end if;
    else
        t:=least(final_target,batch_at,case when cutoff is not null and first_at<=cutoff+interval '600 seconds'
            then cutoff+interval '1800 seconds' else first_at+interval '1800 seconds' end)+interval '120 seconds';
    end if;
    loop
        select e.time_created_utc into overflow_at from public.event_hot e
        where e.source_sha256 is not null and e.method->>'$channel'='Security'
          and e.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
          and (e.method->'$origin')-'agent_id'-'log_source_id'=s
          and e.event_kind in(4625,4771,4776)
          and e.time_created_utc between public.password_read_from385(s,execution,t) and t
        order by e.time_created_utc,e.event_id offset 10000 limit 1;
        if overflow_at is null then return t; end if;
        -- Exclude the WHOLE overflowing timestamp group, including any rows
        -- beyond the lookahead. Never finalize a decision we did not read.
        next_t:=overflow_at-interval '1 microsecond';
        if next_t<=coalesce(cutoff,first_at-interval '1 microsecond')+interval '120 seconds'
           or next_t>=t then
            -- An indivisible group / late overlap that cannot fit must still
            -- fail the unchanged reader guard, never report empty progress.
            return t;
        end if;
        t:=next_t;
        -- Recheck with the reader's lower bound for this reduced clock.
    end loop;
end $$;
update public.password_restore387 d set installed_definition=pg_get_functiondef(d.signature::regprocedure);
do $$ begin
    if exists(select 1 from public.password_restore387 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_window_capacity387_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(387,'password_window_capacity');
reset role;
commit;
