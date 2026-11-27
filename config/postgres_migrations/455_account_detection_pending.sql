begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_account_detection_pending455'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=451 and name='detection_read_checkpoints')
       or exists(select 1 from public.schema_migrations where version>=455) then
        raise exception 'account_detection_pending455_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Other event kinds always return not_applicable from EvaluateAccount.
create function public.account_detection_event_kind455(p_family text,p_kind integer) returns boolean
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select p_kind in (4624,4625,4768,4769,4771,4776)
        or (p_family='watch' and p_kind in (4634,4647,4648,4672,4740,4767,4770,4773,
            4720,4722,4725,4726,4738,4781,4723,4724,4728,4732,4756,4729,4733,4757))
$$;
revoke all on function public.account_detection_event_kind455(text,integer) from public;

alter table public.account_detection_checkpoints451
    add column seed_at timestamptz not null default '-infinity',
    add column seed_normalized uuid not null default '00000000-0000-0000-0000-000000000000',
    add column seed_complete boolean not null default false;

-- Only the continuously scheduled consumer subscribes. A one-shot detector
-- still reads native events and uses its own exact acknowledgments.
create function public.subscribe_account_checkpoint455(p_family text,p_checkpoint text,p_scope jsonb)
returns boolean language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare checkpoint public.account_detection_checkpoints451%rowtype; checkpoint_id bigint; tail record;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER')
       or p_family is null or p_family not in ('decoy','watch')
       or p_checkpoint is null or p_checkpoint !~ '^[a-f0-9]{64}$'
       or p_scope->>'plugin_id' is distinct from 'sli.windows.ad-dc'
       or p_scope->>'collection_scope_id' is distinct from ''
       or public.finding_evidence_scope_allowed((p_scope->>'installation_id')::uuid,
           p_scope->>'plugin_id',p_scope->>'source_instance_id',p_scope->>'source_generation','','core_event') is not true then
        raise exception 'account_checkpoint455_denied' using errcode='42501';
    end if;
    perform pg_advisory_xact_lock(hashtextextended(p_checkpoint,0));
    checkpoint_id:=public.register_account_checkpoint451(p_family,p_checkpoint,p_scope);
    select * into strict checkpoint from public.account_detection_checkpoints451 where id=checkpoint_id;
    if checkpoint.seed_complete then return false; end if;

    -- Registration synchronizes with the writer before the first seed page.
    -- Subsequent arrivals go through the trigger, including events older than
    -- the seed cursor. Advance the cursor in the same transaction as the page.
    with batch as materialized (
        select h.tableoid as partition_oid,h.time_created_utc,h.event_id,h.event_kind,h.method,n.id as normalized_id
        from public.event_hot h
        cross join lateral (select md5('sli.short-event.1:'||h.event_id::text||':'||encode(h.source_sha256,'hex'))::uuid as id) n
        where h.source_sha256 is not null and h.event_id>0
          and (h.method->'$origin')-'agent_id'-'log_source_id'=p_scope
          and h.time_created_utc>=checkpoint.seed_at
          and (h.time_created_utc,n.id)>(checkpoint.seed_at,checkpoint.seed_normalized)
        order by h.time_created_utc,n.id limit 128
    ), queued as (
        insert into public.account_detection_pending451
        select checkpoint.id,b.normalized_id,b.partition_oid,b.time_created_utc,b.event_id,
            b.method#>>'{$origin,agent_id}',coalesce(b.method->'$channel','null'::jsonb)
        from batch b where public.account_detection_event_kind455(p_family,b.event_kind)
          and case p_family when 'decoy' then not exists(
                select 1 from public.semantic_account_decoy_checks x
                where x.checkpoint_key=p_checkpoint and x.normalized_event_id=b.normalized_id)
              else not exists(select 1 from public.semantic_account_watch_checks x
                where x.checkpoint_key=p_checkpoint and x.normalized_event_id=b.normalized_id) end
        on conflict do nothing
    )
    select time_created_utc,normalized_id,count(*) over () as page_size into tail
    from batch order by time_created_utc desc,normalized_id desc limit 1;
    update public.account_detection_checkpoints451 c
    set seed_at=coalesce(tail.time_created_utc,c.seed_at),
        seed_normalized=coalesce(tail.normalized_id,c.seed_normalized),
        seed_complete=coalesce(tail.page_size,0)<128
    where c.id=checkpoint.id;
    return coalesce(tail.page_size,0)=128;
end $$;
revoke all on function public.subscribe_account_checkpoint455(text,text,jsonb) from public;
grant execute on function public.subscribe_account_checkpoint455(text,text,jsonb) to adlog_semantic_worker;

create table public.account_detection_restore455(signature regprocedure primary key,definition text not null);
revoke all on public.account_detection_restore455 from public;
insert into public.account_detection_restore455
select p.oid,pg_get_functiondef(p.oid) from pg_proc p where p.oid in (
    'public.register_account_checkpoint451(text,text,jsonb)'::regprocedure,
    'public.catalog_detection_event451()'::regprocedure,
    'public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.read_account_watch_events_short337(uuid,text,text,text,text,uuid)'::regprocedure);

do $patch$
declare saved record; body text; anchor text; family text; seed_end integer;
begin
    for saved in select * from public.account_detection_restore455 loop
        if saved.signature='public.register_account_checkpoint451(text,text,jsonb)'::regprocedure then
            anchor:='    insert into public.account_detection_pending451';
            seed_end:=strpos(saved.definition,'    on conflict do nothing;');
            if seed_end<=strpos(saved.definition,anchor) then
                raise exception 'account_detection_pending455_seed_shape' using errcode='55000';
            end if;
            body:=substr(saved.definition,1,strpos(saved.definition,anchor)-1)||
                substr(saved.definition,seed_end+length('    on conflict do nothing;'));
        elsif saved.signature='public.catalog_detection_event451()'::regprocedure then
            anchor:='from public.account_detection_checkpoints451 c where c.scope=event_scope';
            body:=replace(saved.definition,anchor,anchor||
                E'\n      and public.account_detection_event_kind455(c.family,new.event_kind)');
        else
            family:=case when saved.signature='public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure
                then 'decoy' else 'watch' end;
            anchor:=format('checkpoint451:=public.register_account_checkpoint451(%L,p_checkpoint,scope451);',family);
            body:=replace(saved.definition,anchor,format($lookup$
                select c.id into checkpoint451 from public.account_detection_checkpoints451 c
                where c.family=%L and c.checkpoint_key=p_checkpoint and c.scope=scope451;
            $lookup$,family));
            if body=saved.definition then
                raise exception 'account_detection_pending455_reader_shape' using errcode='55000';
            end if;
            anchor:='            ) pending';
            body:=replace(body,anchor,anchor||format($fallback$
            union all
            (select e.* from public.short_account_candidates337 e
             where p_normalized is null and checkpoint451 is null
               and e.origin-'agent_id'-'log_source_id'=scope451
               and e.origin->>'agent_id'=source_binding.agent_id::text
               and e.occurred_at_utc<=statement_timestamp()
               and not exists(select 1 from public.semantic_account_%1$s_checks checked
                   where checked.checkpoint_key=p_checkpoint and checked.normalized_event_id=e.normalized_event_id)
               and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
                   e.source_event_id::text,e.native_sha256)
             order by e.normalized_at,e.normalized_event_id limit 128)
            $fallback$,family));
        end if;
        if strpos(saved.definition,anchor)=0 then
            raise exception 'account_detection_pending455_function_shape' using errcode='55000';
        end if;
        execute body;
    end loop;
end $patch$;

-- The account rules evaluate individual hot events. Their five-minute episode
-- grouping and notification freshness do not limit finding eligibility.
-- Expiry uses the same hot cutoff as native storage, plus exact acknowledgments
-- and partition detach. An older timestamp alone never proves evaluation.
create function public.prune_account_detection_pending455(p_hot timestamptz,p_limit integer)
returns bigint language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare removed bigint;
begin
    if p_hot is null or not isfinite(p_hot) or p_hot>statement_timestamp()
       or p_limit is null or p_limit not between 1 and 1000 then
        raise exception 'account_detection_pending455_cutoff_invalid' using errcode='22023';
    end if;
    with attached as materialized (
        select inhrelid from pg_inherits
        where inhparent='public.event_hot'::regclass and not inhdetachpending
    ), expired as materialized (
        select q.ctid
        from public.account_detection_pending451 q
        join public.account_detection_checkpoints451 c on c.id=q.checkpoint_id
        left join attached a on a.inhrelid=q.partition_oid
        where q.occurred_at<p_hot or a.inhrelid is null
           or case c.family when 'decoy' then exists(
                select 1 from public.semantic_account_decoy_checks x
                where x.checkpoint_key=c.checkpoint_key and x.normalized_event_id=q.normalized_id)
              else exists(
                select 1 from public.semantic_account_watch_checks x
                where x.checkpoint_key=c.checkpoint_key and x.normalized_event_id=q.normalized_id) end
        limit p_limit for update of q skip locked
    )
    delete from public.account_detection_pending451 q using expired e where q.ctid=e.ctid;
    get diagnostics removed=row_count;
    return removed;
end $$;
revoke all on function public.prune_account_detection_pending455(timestamptz,integer) from public;
grant execute on function public.prune_account_detection_pending455(timestamptz,integer) to adlog_storage_lifecycle_delete;

-- Reset the disposable pointers and indexes atomically. Live subscriptions
-- rebuild in pages from event_hot and exact checks. This avoids
-- holding millions of row locks in the native package's single transaction.
truncate public.account_detection_pending451,public.account_detection_checkpoints451;
reset role;
insert into public.schema_migrations(version,name) values(455,'account_detection_pending');
commit;
