begin;
select pg_advisory_xact_lock(hashtext('sli_password_clock_catch_up382'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=381 and name='security_time_precision')
       or exists(select 1 from public.schema_migrations where version>=382) then
        raise exception 'password_clock_catch_up382_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.password_clock_restore382(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.password_clock_restore382 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_clock_restore382(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid='public.password_event_clock362(jsonb,jsonb)'::regprocedure;

-- A decision slice spans at most the 600-second continuity window, ending no
-- later than the current rule holdback. The 299-member / 2.026s COMMIT measured
-- in #1882 supplies the member unit. Amortize each full history check across
-- one 600/120 rule-window/holdback ratio of units. History is additional
-- immutable overlap; equal timestamps are indivisible. No wall-clock deadline.
create or replace function public.password_event_clock362(s jsonb,execution jsonb) returns timestamptz
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; cutoff timestamptz; first_at timestamptz; batch_at timestamptz;
    final_target timestamptz:=statement_timestamp()-interval '120 seconds';
    decision_members integer:=299*(600/120);
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
    -- Empty tails still advance: an idle source must not spin on its last event.
    if first_at is null then
        if cutoff is not null or exists(select 1 from public.event_hot h
            where h.source_sha256 is not null and h.method->>'$channel'='Security'
              and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
              and (h.method->'$origin')-'agent_id'-'log_source_id'=s
              and h.event_kind in(4624,4625,4771,4776) and h.time_created_utc<=statement_timestamp()) then
            return greatest(final_target,cutoff)+interval '120 seconds';
        end if;
        return null;
    end if;
    -- A gap with no events can be crossed directly. Never jump over a decision.
    return least(final_target,batch_at,case when cutoff is not null and first_at<=cutoff+interval '600 seconds'
        then cutoff+interval '600 seconds' else first_at+interval '480 seconds' end)+interval '120 seconds';
end $$;

-- One session owns both password rules for a source. Separate from transaction
-- publication/configuration locks: these retain their exact order and guards.
create function public.password_producer_source382(s jsonb,acquire boolean) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare k bigint;
begin
    perform public.password_v2_source_binding(s);
    k:=hashtextextended('sli.password.producer.source.1:'||encode(public.password_v2_scope_key(s),'hex'),0);
    if acquire then return pg_try_advisory_lock(k); end if;
    return pg_advisory_unlock(k);
end $$;
revoke all on function public.password_producer_source382(jsonb,boolean) from public,adlog_user,adlog_storage_worker;
grant execute on function public.password_producer_source382(jsonb,boolean) to adlog_semantic_worker;
update public.password_clock_restore382 d set installed_definition=pg_get_functiondef(d.signature::regprocedure);
do $$ begin
    if exists(select 1 from public.password_clock_restore382 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl or p.proowner<>'adlog_storage_owner'::regrole) then
        raise exception 'password_clock_catch_up382_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(382,'password_clock_catch_up');
reset role;
commit;
