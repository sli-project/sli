begin;
select pg_advisory_xact_lock(hashtext('sli_password_first_batch375'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=374 and name='semantic_source_deleted')
       or exists(select 1 from public.schema_migrations where version>=375) then
        raise exception 'password_first_batch375_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.password_batch_restore375(
    kind text not null,signature text not null,definition text not null,installed_definition text,
    owner_oid oid,acl aclitem[],primary key(kind,signature));
revoke all on public.password_batch_restore375 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_batch_restore375(kind,signature,definition,owner_oid,acl)
select 'function',oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.password_v2_state_ledger_complete()'::regprocedure,
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure]);
insert into public.password_batch_restore375(kind,signature,definition)
select 'trigger',tgname,pg_get_triggerdef(oid) from pg_trigger
where (tgrelid='public.semantic_password_checkpoints'::regclass and tgname='password_v2_state_ledger_complete')
   or (tgrelid='public.semantic_password_window_members'::regclass and tgname='password_v2_members_complete');
do $$ begin
    if exists(select 1 from public.password_batch_restore375 where kind='function'
        and owner_oid is distinct from 'adlog_storage_owner'::regrole) then
        raise exception 'password_first_batch375_owner' using errcode='55000'; end if;
end $$;

-- A private, transaction-local work set: rows are removed by the deferred
-- validator before COMMIT, or rolled back with the modifying transaction.
-- Never trust a caller GUC or a surviving "already checked" flag.
create table public.password_state_checks375(
    scope_digest bytea not null,pin text not null,primary key(scope_digest,pin));
revoke all on public.password_state_checks375 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create function public.password_schedule_state_check375() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if tg_table_name='semantic_password_checkpoints' and tg_op='UPDATE' then
        if (new.scope_digest,new.pin,new.state_document,new.state_revision,new.watermark,new.coverage_epoch)
            is not distinct from (old.scope_digest,old.pin,old.state_document,old.state_revision,old.watermark,old.coverage_epoch)
            then return null; end if;
    end if;
    if tg_op<>'INSERT' then
        insert into public.password_state_checks375 values(old.scope_digest,old.pin) on conflict do nothing;
    end if;
    if tg_op<>'DELETE' then
        insert into public.password_state_checks375 values(new.scope_digest,new.pin) on conflict do nothing;
    end if;
    return null;
end $$;
revoke all on function public.password_schedule_state_check375() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Retain the complete state/projection/episode checks verbatim, but schedule
-- them once per changed checkpoint rather than once per window member. Deleting
-- the work row also makes later writes after SET CONSTRAINTS re-arm validation.
do $$ declare definition text; begin
    select d.definition into strict definition from public.password_batch_restore375 d
        where d.signature='password_v2_state_ledger_complete()' and d.kind='function';
    if strpos(definition,E'begin\n    if tg_table_name=')=0 then
        raise exception 'password_first_batch375_state_shape' using errcode='55000'; end if;
    execute replace(definition,E'begin\n    if tg_table_name=',E'begin\n    delete from public.password_state_checks375 q where q.scope_digest=new.scope_digest and q.pin=new.pin;\n    if tg_table_name=');
end $$;
drop trigger password_v2_state_ledger_complete on public.semantic_password_checkpoints;
drop trigger password_v2_members_complete on public.semantic_password_window_members;
create trigger password_v2_state_ledger_complete after insert or update on public.semantic_password_checkpoints
    for each row execute function public.password_schedule_state_check375();
create trigger password_v2_members_complete after insert or update or delete on public.semantic_password_window_members
    for each row execute function public.password_schedule_state_check375();
create constraint trigger password_v2_state_batch_complete after insert on public.password_state_checks375
    deferrable initially deferred for each row execute function public.password_v2_state_ledger_complete();

-- Project only the changed members. The full equality check still runs at the
-- finalizer and at COMMIT, including deletion, replacement and native identity.
do $$ declare definition text; before_patch text; after_patch text; begin
    select d.definition into strict definition from public.password_batch_restore375 d
        where d.signature='complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)' and d.kind='function';
    before_patch:=$old$delete from public.semantic_password_window_members q where q.scope_digest=c.scope_digest and q.pin=c.pin;
    insert into public.semantic_password_window_members(scope_digest,pin,member_document)
        select c.scope_digest,c.pin,a.value from jsonb_array_elements(next_st->'window') a(value);$old$;
    after_patch:=$new$delete from public.semantic_password_window_members q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and q.native_id not in (select (a.value#>>'{witness,ref,native_id}')::bigint from jsonb_array_elements(next_st->'window') a(value));
    insert into public.semantic_password_window_members as current(scope_digest,pin,member_document)
        select c.scope_digest,c.pin,a.value from jsonb_array_elements(next_st->'window') a(value)
        on conflict(scope_digest,pin,native_id) do update set member_document=excluded.member_document
        where current.member_document is distinct from excluded.member_document;$new$;
    if strpos(definition,before_patch)=0 then
        raise exception 'password_first_batch375_finalizer_shape' using errcode='55000'; end if;
    execute replace(definition,before_patch,after_patch);
end $$;

-- Advance by a measured number of new decisions, retaining the rule's entire
-- 600-second history and 120-second holdback. Equal timestamps are indivisible:
-- include their whole group instead of skipping suffixes behind the watermark.
-- The existing row/XML/state bounds and native provenance gates are unchanged.
-- PostgreSQL fixture: 70k events, one / 0.7s; old 858-member COMMIT 530.146s,
-- one full check 552ms. 128 decisions + holdback gives 299 members: measured
-- full check 352ms and COMMIT 2.026s, including independent ledger checks.
create or replace function public.password_event_clock362(s jsonb,execution jsonb) returns timestamptz
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; cutoff timestamptz; batch_at timestamptz; last_at timestamptz;
begin
    perform public.password_v2_source_binding(s);
    identity:=public.password_v2_identity(s,execution);
    select c.watermark into cutoff from public.semantic_password_checkpoints c
    where c.scope_digest=decode(identity->>'scope_digest','hex') and c.pin=identity->>'pin';
    select max(e.time_created_utc) into batch_at from (
        select h.time_created_utc from public.event_hot h
        where h.source_sha256 is not null and h.method->>'$channel'='Security'
          and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
          and (h.method->'$origin')-'agent_id'-'log_source_id'=s
          and h.event_kind in(4624,4625,4771,4776) and h.time_created_utc<=statement_timestamp()
          and h.time_created_utc>coalesce(cutoff,'-infinity'::timestamptz)
        order by h.time_created_utc,h.event_id limit 128
    ) e;
    if batch_at is null then
        select h.time_created_utc into last_at from public.event_hot h
        where h.source_sha256 is not null and h.method->>'$channel'='Security'
          and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
          and (h.method->'$origin')-'agent_id'-'log_source_id'=s
          and h.event_kind in(4624,4625,4771,4776) and h.time_created_utc<=statement_timestamp()
        order by h.time_created_utc desc,h.event_id desc limit 1;
        if last_at is null then return null; end if;
    end if;
    return least(statement_timestamp(),greatest(coalesce(batch_at,last_at)+interval '120 seconds',cutoff+interval '120 seconds'));
end $$;

update public.password_batch_restore375 d set installed_definition=pg_get_functiondef(d.signature::regprocedure) where kind='function';
update public.password_batch_restore375 d set installed_definition=pg_get_triggerdef(t.oid)
from pg_trigger t where d.kind='trigger' and d.signature=t.tgname
    and t.tgrelid in ('public.semantic_password_checkpoints'::regclass,'public.semantic_password_window_members'::regclass);
do $$ begin
    if exists(select 1 from public.password_batch_restore375 d join pg_proc p on p.oid=d.signature::regprocedure
        where d.kind='function' and (p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl)) then
        raise exception 'password_first_batch375_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(375,'password_first_batch');
reset role;
commit;
