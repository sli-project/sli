begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_check_rows460'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=455 and name='account_detection_pending')
       or not exists(select 1 from public.schema_migrations where version=458 and name='file_audit_activity')
       or exists(select 1 from public.schema_migrations where version>=460) then
        raise exception 'account_check_rows460_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.semantic_account_decoy_checks add constraint account_decoy_hits460
    check(result_code='observed') not valid;
alter table public.semantic_account_watch_checks add constraint account_watch_hits460
    check(result_code='observed') not valid;
alter table public.account_detection_checkpoints451
    add column all_event_kinds boolean not null default false,
    add column last_evaluated_event_id bigint;

create table public.account_check_cleanup460(
    family text primary key check(family in ('decoy','watch')),
    after_key text not null default '',
    after_id uuid not null default '00000000-0000-0000-0000-000000000000',
    complete boolean not null default false
);
insert into public.account_check_cleanup460(family) values('decoy'),('watch');
revoke all on public.account_check_cleanup460 from public;

create table public.account_detection_restore460(signature regprocedure primary key,definition text not null);
revoke all on public.account_detection_restore460 from public;
insert into public.account_detection_restore460
select oid,pg_get_functiondef(oid) from pg_proc where oid in (
    'public.subscribe_account_checkpoint455(text,text,jsonb)'::regprocedure,
    'public.catalog_detection_event451()'::regprocedure,
    'public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.read_account_watch_events_short337(uuid,text,text,text,text,uuid)'::regprocedure);

-- Start with the 455 seed query and its exact legacy exclusion. Manual
-- detectors read all event kinds, as they did through the unregistered reader.
create function public.seed_account_checkpoint460(p_id bigint) returns boolean
language plpgsql set search_path=pg_catalog,pg_temp as $$
declare checkpoint public.account_detection_checkpoints451%rowtype; tail record;
begin
    select * into strict checkpoint from public.account_detection_checkpoints451 where id=p_id;
    if checkpoint.seed_complete then return false; end if;
    with batch as materialized (
        select h.tableoid as partition_oid,h.time_created_utc,h.event_id,h.event_kind,h.method,n.id as normalized_id
        from public.event_hot h
        cross join lateral (select md5('sli.short-event.1:'||h.event_id::text||':'||encode(h.source_sha256,'hex'))::uuid as id) n
        where h.source_sha256 is not null and h.event_id>0
          and (h.method->'$origin')-'agent_id'-'log_source_id'=checkpoint.scope
          and h.time_created_utc>=checkpoint.seed_at
          and (h.time_created_utc,n.id)>(checkpoint.seed_at,checkpoint.seed_normalized)
        order by h.time_created_utc,n.id limit 128
    ), queued as (
        insert into public.account_detection_pending451
        select p_id,b.normalized_id,b.partition_oid,b.time_created_utc,b.event_id,
            b.method#>>'{$origin,agent_id}',coalesce(b.method->'$channel','null'::jsonb)
        from batch b
        where (checkpoint.all_event_kinds or public.account_detection_event_kind455(checkpoint.family,b.event_kind))
          and case checkpoint.family when 'decoy' then not exists(
                select 1 from public.semantic_account_decoy_checks x
                where x.checkpoint_key=checkpoint.checkpoint_key and x.normalized_event_id=b.normalized_id)
              else not exists(select 1 from public.semantic_account_watch_checks x
                where x.checkpoint_key=checkpoint.checkpoint_key and x.normalized_event_id=b.normalized_id) end
        on conflict do nothing
    )
    select time_created_utc,normalized_id,count(*) over () as page_size into tail
    from batch order by time_created_utc desc,normalized_id desc limit 1;
    update public.account_detection_checkpoints451 c
    set seed_at=coalesce(tail.time_created_utc,c.seed_at),
        seed_normalized=coalesce(tail.normalized_id,c.seed_normalized),
        seed_complete=coalesce(tail.page_size,0)<128
    where c.id=p_id;
    return coalesce(tail.page_size,0)=128;
end $$;
revoke all on function public.seed_account_checkpoint460(bigint) from public;

create function public.prepare_account_checkpoint460(p_family text,p_checkpoint text,p_scope jsonb,p_live boolean)
returns boolean language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare checkpoint_id bigint;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER')
       or p_family is null or p_family not in ('decoy','watch')
       or p_checkpoint is null or p_checkpoint !~ '^[a-f0-9]{64}$' or p_live is null
       or p_scope->>'plugin_id' is distinct from 'sli.windows.ad-dc'
       or p_scope->>'collection_scope_id' is distinct from ''
       or public.finding_evidence_scope_allowed((p_scope->>'installation_id')::uuid,
           p_scope->>'plugin_id',p_scope->>'source_instance_id',p_scope->>'source_generation','','core_event') is not true then
        raise exception 'account_checkpoint460_denied' using errcode='42501';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_checkpoint,0));
    checkpoint_id:=public.register_account_checkpoint451(p_family,p_checkpoint,p_scope);
    if p_live then
        update public.account_detection_checkpoints451 c set all_event_kinds=false
        where c.id=checkpoint_id and c.all_event_kinds;
    else
        update public.account_detection_checkpoints451 c set all_event_kinds=true
        where c.id=checkpoint_id and c.seed_at='-infinity' and not c.seed_complete and not c.all_event_kinds;
    end if;
    return public.seed_account_checkpoint460(checkpoint_id);
end $$;
revoke all on function public.prepare_account_checkpoint460(text,text,jsonb,boolean) from public;
grant execute on function public.prepare_account_checkpoint460(text,text,jsonb,boolean) to adlog_semantic_worker;

create or replace function public.subscribe_account_checkpoint455(p_family text,p_checkpoint text,p_scope jsonb)
returns boolean language sql security definer set search_path=pg_catalog,pg_temp as $$
    select public.prepare_account_checkpoint460(p_family,p_checkpoint,p_scope,true)
$$;

do $patch$
declare body text; anchor constant text:='and public.account_detection_event_kind455(c.family,new.event_kind)';
begin
    select definition into strict body from public.account_detection_restore460
        where signature='public.catalog_detection_event451()'::regprocedure;
    if strpos(body,anchor)=0 then
        raise exception 'account_check_rows460_catalog_shape' using errcode='55000';
    end if;
    execute replace(body,anchor,'and (c.all_event_kinds or public.account_detection_event_kind455(c.family,new.event_kind))');
end $patch$;

-- An arrival ahead of a partial seed may already be queued. Do not consume
-- it before the seed has passed it, or the seed could enqueue it a second time.
do $patch$
declare saved record;
    anchor constant text:='where q.checkpoint_id=checkpoint451 and q.partition_oid=p.partition_oid';
begin
    for saved in select definition from public.account_detection_restore460 where signature in (
        'public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure,
        'public.read_account_watch_events_short337(uuid,text,text,text,text,uuid)'::regprocedure)
    loop
        if strpos(saved.definition,anchor)=0 then
            raise exception 'account_check_rows460_reader_shape' using errcode='55000';
        end if;
        execute replace(saved.definition,anchor,anchor||$reader$
                  and exists(select 1 from public.account_detection_checkpoints451 c
                      where c.id=checkpoint451 and (c.seed_complete
                          or (q.occurred_at,q.normalized_id)<=(c.seed_at,c.seed_normalized)))
        $reader$);
    end loop;
end $patch$;

-- The seed cursor and arrival trigger cover discovery. Acknowledge only the
-- events returned to the evaluator, since late or temporarily ineligible
-- events can appear on either side of the last evaluated event ID.
create function public.complete_account_batch460(p_family text,p_checkpoint text,p_scope jsonb,p_events jsonb)
returns void language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_checkpoint_id bigint;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER')
       or p_scope->>'plugin_id' is distinct from 'sli.windows.ad-dc'
       or p_scope->>'collection_scope_id' is distinct from ''
       or public.finding_evidence_scope_allowed((p_scope->>'installation_id')::uuid,
           p_scope->>'plugin_id',p_scope->>'source_instance_id',p_scope->>'source_generation','','core_event') is not true then
        raise exception 'account_checkpoint460_denied' using errcode='42501';
    end if;
    if p_checkpoint is null or jsonb_typeof(p_events) is distinct from 'array'
       or jsonb_array_length(p_events) not between 1 and 128 then
        raise exception 'account_check_rows460_invalid_batch' using errcode='22023';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_checkpoint,0));
    select c.id into strict v_checkpoint_id from public.account_detection_checkpoints451 c
    where c.family=p_family and c.checkpoint_key=p_checkpoint and c.scope=p_scope;
    delete from public.account_detection_pending451 q
    using jsonb_to_recordset(p_events) as e(id uuid,event_id bigint)
    where q.checkpoint_id=v_checkpoint_id and q.normalized_id=e.id and q.source_event_id=e.event_id;
    update public.account_detection_checkpoints451 c
    set last_evaluated_event_id=(p_events->-1->>'event_id')::bigint
    where c.id=v_checkpoint_id;
end $$;
revoke all on function public.complete_account_batch460(text,text,jsonb,jsonb) from public;
grant execute on function public.complete_account_batch460(text,text,jsonb,jsonb) to adlog_semantic_worker;

-- Native upgrade only installs this cleanup. The lifecycle runs each page
-- in its own transaction and resumes from the committed primary-key cursor.
create function public.prune_account_check_rows460(p_family text,p_limit integer)
returns table(deleted bigint,more boolean) language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare
    progress public.account_check_cleanup460%rowtype;
    checks regclass;
    candidate record;
    tail record;
    checkpoint_id bigint;
begin
    if p_family is null or p_family not in ('decoy','watch') or p_limit is null or p_limit not between 1 and 1000 then
        raise exception 'account_check_rows460_invalid_cleanup' using errcode='22023';
    end if;
    select * into strict progress from public.account_check_cleanup460 where family=p_family for update;
    if progress.complete then return query select 0::bigint,false; return; end if;
    checks:=case p_family when 'decoy' then 'public.semantic_account_decoy_checks'::regclass
        else 'public.semantic_account_watch_checks'::regclass end;
    execute format('select checkpoint_key,scope_json from %s
        where (checkpoint_key,normalized_event_id)>($1,$2) and result_code<>''observed''
        order by checkpoint_key,normalized_event_id limit 1',checks)
        into candidate using progress.after_key,progress.after_id;
    if candidate.checkpoint_key is null then
        -- A competing row lock can cause a page to skip rows. Verify the table
        -- before marking cleanup complete, and retry skipped rows next cycle.
        execute format('select not exists(select 1 from %s where result_code<>''observed'')',checks) into progress.complete;
        update public.account_check_cleanup460 set complete=progress.complete,
            after_key='',after_id='00000000-0000-0000-0000-000000000000' where family=p_family;
        return query select 0::bigint,false;
        return;
    end if;
    if not pg_try_advisory_xact_lock(hashtextextended(candidate.checkpoint_key,0)) then
        return query select 0::bigint,false;
        return;
    end if;

    -- A partially seeded or old standalone checkpoint still needs its exact
    -- exclusions. Seed the outstanding work before removing those exclusions.
    select c.id into checkpoint_id from public.account_detection_checkpoints451 c
    where c.family=p_family and c.checkpoint_key=candidate.checkpoint_key and c.scope=candidate.scope_json;
    if not found then
        if not pg_try_advisory_xact_lock(hashtextextended('sli.account.checkpoint.451:'||p_family||':'||candidate.scope_json::text,0)) then
            return query select 0::bigint,false;
            return;
        end if;
        checkpoint_id:=public.register_account_checkpoint451(p_family,candidate.checkpoint_key,candidate.scope_json);
        update public.account_detection_checkpoints451 set all_event_kinds=true where id=checkpoint_id;
    end if;
    if public.seed_account_checkpoint460(checkpoint_id) then
        return query select 0::bigint,true;
        return;
    end if;

    -- Lock one ordered page, advance over that page and delete only rows that
    -- this batch could lock. A skipped row is picked up on a subsequent pass.
    execute format($batch$
        with page as materialized (
            select checkpoint_key,normalized_event_id,scope_json from %1$s
            where (checkpoint_key,normalized_event_id)>($1,$2) and checkpoint_key=$3
              and result_code<>'observed'
            order by checkpoint_key,normalized_event_id limit $4
        ), locked as materialized (
            select c.ctid from %1$s c join page p using(checkpoint_key,normalized_event_id)
            where c.scope_json=$5 and c.result_code<>'observed' for update of c skip locked
        ), removed as (
            delete from %1$s c using locked l where c.ctid=l.ctid returning c.normalized_event_id
        )
        select p.checkpoint_key,p.normalized_event_id,(select count(*) from removed) as removed
        from page p order by p.normalized_event_id desc limit 1
        $batch$,checks)
        into tail using progress.after_key,progress.after_id,candidate.checkpoint_key,p_limit,candidate.scope_json;
    if tail.checkpoint_key is null then return query select 0::bigint,false; return; end if;
    update public.account_check_cleanup460 set after_key=tail.checkpoint_key,after_id=tail.normalized_event_id where family=p_family;
    return query select tail.removed,true;
end $$;
revoke all on function public.prune_account_check_rows460(text,integer) from public;
grant execute on function public.prune_account_check_rows460(text,integer) to adlog_storage_lifecycle_delete;

reset role;
insert into public.schema_migrations(version,name) values(460,'account_check_rows');
commit;
