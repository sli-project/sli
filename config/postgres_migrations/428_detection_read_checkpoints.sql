begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_detection_read_checkpoints428'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=421 and name='sli_own_actions')
       or exists(select 1 from public.schema_migrations where version>=428) then
        raise exception 'detection_read_checkpoints428_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Table OIDs identify attached partitions without inspecting their rows on
-- discovery. The binding itself still belongs to the current semantic login.
create table public.detection_source_catalog428(
    partition_oid oid not null,
    origin jsonb not null,
    channel jsonb not null,
    primary key(partition_oid,origin,channel)
);
create table public.account_detection_checkpoints428(
    id bigint generated always as identity unique,
    family text not null check(family in ('decoy','watch')),
    checkpoint_key text not null check(checkpoint_key ~ '^[a-f0-9]{64}$'),
    scope jsonb not null,
    primary key(family,checkpoint_key,scope)
);
create index account_detection_checkpoint_scope428 on public.account_detection_checkpoints428(scope);
create table public.account_detection_pending428(
    checkpoint_id bigint not null references public.account_detection_checkpoints428(id) on delete cascade,
    normalized_id uuid not null,
    partition_oid oid not null,
    occurred_at timestamptz not null,
    source_event_id bigint not null,
    agent_id text not null,
    channel jsonb not null,
    primary key(checkpoint_id,normalized_id,partition_oid,occurred_at)
);
create index account_detection_pending_order428 on public.account_detection_pending428
    (checkpoint_id,partition_oid,agent_id,channel,occurred_at,normalized_id);
create index account_detection_pending_partition428 on public.account_detection_pending428(partition_oid);
create index account_detection_pending_event428 on public.account_detection_pending428(normalized_id);
create table public.detection_reader_restore428(
    signature regprocedure primary key,
    definition text not null,
    owner_oid oid not null,
    acl aclitem[],
    installed_definition text
);
revoke all on public.detection_source_catalog428,public.account_detection_checkpoints428,
    public.account_detection_pending428,public.detection_reader_restore428
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create index event_hot_detection_scope428 on public.event_hot
    (((method->'$origin')-'agent_id'-'log_source_id'),time_created_utc)
    where source_sha256 is not null;
create index event_hot_detection_normalized428 on public.event_hot
    ((md5('sli.short-event.1:'||event_id::text||':'||encode(source_sha256,'hex'))::uuid))
    where source_sha256 is not null;

create function public.catalog_detection_event428() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare event_origin jsonb; event_channel jsonb; old_origin jsonb; old_channel jsonb; event_scope jsonb; event_normalized uuid; hot boolean;
begin
    hot:=tg_argv[0]='hot';
    if tg_op<>'DELETE' then
        event_origin:=new.method->'$origin'; event_channel:=coalesce(new.method->'$channel','null'::jsonb);
        if hot then
            if new.source_sha256 is null then event_origin:=null; end if;
        end if;
        if event_origin->>'plugin_id' is distinct from 'sli.windows.ad-dc' then event_origin:=null; end if;
    end if;
    if tg_op<>'INSERT' then
        old_origin:=old.method->'$origin'; old_channel:=coalesce(old.method->'$channel','null'::jsonb);
        if hot then
            if old.source_sha256 is null then old_origin:=null; end if;
        end if;
        if old_origin->>'plugin_id' is distinct from 'sli.windows.ad-dc' then old_origin:=null; end if;
        if tg_op='UPDATE' and event_origin is not distinct from old_origin and event_channel=old_channel then
            if not hot then return null; end if;
            if new.source_sha256 is not distinct from old.source_sha256
                and (new.time_created_utc,new.event_id)=(old.time_created_utc,old.event_id) then return null; end if;
        end if;
    end if;
    if old_origin is not null then
        if hot then
            delete from public.account_detection_pending428 q where q.partition_oid=tg_relid
                and q.normalized_id=md5('sli.short-event.1:'||old.event_id::text||':'||encode(old.source_sha256,'hex'))::uuid;
            execute format('delete from public.detection_source_catalog428 c
                where c.partition_oid=$1 and c.origin=$2 and c.channel=$3 and not exists (
                    select 1 from %s h where h.source_sha256 is not null
                        and h.method->''$origin''=$2 and coalesce(h.method->''$channel'',''null''::jsonb)=$3)',tg_relid::regclass)
                using tg_relid,old_origin,old_channel;
        else
            execute format('delete from public.detection_source_catalog428 c
                where c.partition_oid=$1 and c.origin=$2 and c.channel=$3 and not exists (
                    select 1 from %s h where h.method->''$origin''=$2
                        and coalesce(h.method->''$channel'',''null''::jsonb)=$3)',tg_relid::regclass)
                using tg_relid,old_origin,old_channel;
        end if;
    end if;
    if event_origin is null then return null; end if;
    insert into public.detection_source_catalog428(partition_oid,origin,channel)
    select tg_relid,event_origin,event_channel where not exists (
        select 1 from public.detection_source_catalog428 c
        where c.partition_oid=tg_relid and c.origin=event_origin and c.channel=event_channel)
    on conflict do nothing;
    if not hot then return null; end if;
    if new.event_id<=0 then return null; end if;

    event_scope:=event_origin-'agent_id'-'log_source_id';
    event_normalized:=md5('sli.short-event.1:'||new.event_id::text||':'||encode(new.source_sha256,'hex'))::uuid;
    -- Only checkpoint registration needs the exclusive side of this lock.
    -- The account pass itself does not take it once the checkpoint exists.
    perform pg_advisory_xact_lock_shared(hashtextextended('sli.account.checkpoint.428:decoy:'||event_scope::text,0));
    perform pg_advisory_xact_lock_shared(hashtextextended('sli.account.checkpoint.428:watch:'||event_scope::text,0));
    insert into public.account_detection_pending428
    select c.id,event_normalized,tg_relid,new.time_created_utc,new.event_id,event_origin->>'agent_id',event_channel
    from public.account_detection_checkpoints428 c where c.scope=event_scope
      and case c.family when 'decoy' then not exists(
            select 1 from public.semantic_account_decoy_checks x
            where x.checkpoint_key=c.checkpoint_key and x.normalized_event_id=event_normalized)
          else not exists(
            select 1 from public.semantic_account_watch_checks x
            where x.checkpoint_key=c.checkpoint_key and x.normalized_event_id=event_normalized) end
    on conflict do nothing;
    return null;
end $$;
revoke all on function public.catalog_detection_event428() from public;

create trigger catalog_detection_hot428 after insert or update or delete on public.event_hot
    for each row execute function public.catalog_detection_event428('hot');
create trigger catalog_detection_cold428 after insert or update or delete on public.event_cold_daily
    for each row execute function public.catalog_detection_event428('cold');
insert into public.detection_source_catalog428
select distinct h.tableoid,h.method->'$origin',coalesce(h.method->'$channel','null'::jsonb)
from public.event_hot h where h.source_sha256 is not null and h.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
union
select distinct h.tableoid,h.method->'$origin',coalesce(h.method->'$channel','null'::jsonb)
from public.event_cold_daily h where h.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc';

create function public.register_account_checkpoint428(p_family text,p_checkpoint text,p_scope jsonb) returns bigint
language plpgsql set search_path=pg_catalog,pg_temp as $$
declare checkpoint_id bigint;
begin
    select c.id into checkpoint_id from public.account_detection_checkpoints428 c
    where c.family=p_family and c.checkpoint_key=p_checkpoint and c.scope=p_scope;
    if found then return checkpoint_id; end if;
    perform pg_advisory_xact_lock(hashtextextended('sli.account.checkpoint.428:'||p_family||':'||p_scope::text,0));
    select c.id into checkpoint_id from public.account_detection_checkpoints428 c
    where c.family=p_family and c.checkpoint_key=p_checkpoint and c.scope=p_scope;
    if found then return checkpoint_id; end if;
    insert into public.account_detection_checkpoints428(family,checkpoint_key,scope) values(p_family,p_checkpoint,p_scope)
    returning id into checkpoint_id;
    insert into public.account_detection_pending428
    select checkpoint_id,u.id,h.tableoid,h.time_created_utc,h.event_id,
        h.method#>>'{$origin,agent_id}',coalesce(h.method->'$channel','null'::jsonb)
    from public.event_hot h
    cross join lateral (select md5('sli.short-event.1:'||h.event_id::text||':'||encode(h.source_sha256,'hex'))::uuid as id) u
    where h.source_sha256 is not null and h.event_id>0
      and (h.method->'$origin')-'agent_id'-'log_source_id'=p_scope
      and case p_family when 'decoy' then not exists(
            select 1 from public.semantic_account_decoy_checks x
            where x.checkpoint_key=p_checkpoint and x.normalized_event_id=u.id)
          else not exists(
            select 1 from public.semantic_account_watch_checks x
            where x.checkpoint_key=p_checkpoint and x.normalized_event_id=u.id) end
    on conflict do nothing;
    return checkpoint_id;
end $$;
revoke all on function public.register_account_checkpoint428(text,text,jsonb) from public;

create function public.complete_account_checkpoint_event428() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform pg_advisory_xact_lock_shared(hashtextextended('sli.account.checkpoint.428:'||tg_argv[0]||':'||new.scope_json::text,0));
    delete from public.account_detection_pending428 q using public.account_detection_checkpoints428 c
    where c.id=q.checkpoint_id and c.family=tg_argv[0] and c.checkpoint_key=new.checkpoint_key
      and q.normalized_id=new.normalized_event_id;
    return null;
end $$;
revoke all on function public.complete_account_checkpoint_event428() from public;
create trigger complete_account_decoy428 after insert on public.semantic_account_decoy_checks
    for each row execute function public.complete_account_checkpoint_event428('decoy');
create trigger complete_account_watch428 after insert on public.semantic_account_watch_checks
    for each row execute function public.complete_account_checkpoint_event428('watch');

-- Resume installed checkpoints, including holes in an old checked prefix.
do $$ declare c record; begin
    for c in
        select distinct 'decoy' as family,checkpoint_key,scope_json from public.semantic_account_decoy_checks
        union all
        select distinct 'watch',checkpoint_key,scope_json from public.semantic_account_watch_checks
    loop
        perform public.register_account_checkpoint428(c.family,c.checkpoint_key,c.scope_json);
    end loop;
end $$;
analyze public.detection_source_catalog428;
analyze public.account_detection_pending428;

insert into public.detection_reader_restore428(signature,definition,owner_oid,acl)
select p.oid,pg_get_functiondef(p.oid),p.proowner,p.proacl from pg_proc p where p.oid in (
    'public.short_detection_sources337()'::regprocedure,
    'public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.read_account_watch_events_short337(uuid,text,text,text,text,uuid)'::regprocedure);

create or replace function public.short_detection_sources337() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER') then
        raise exception 'detection_source_denied' using errcode='42501'; end if;
    select oid into strict login from pg_roles where rolname=session_user;
    -- DETACH does not fire row triggers. Ignore detached partitions immediately
    -- and reclaim their private work pointers in bounded portions.
    with detached as materialized (
        select distinct c.partition_oid from public.detection_source_catalog428 c
        where not exists(select 1 from pg_inherits i where i.inhrelid=c.partition_oid)
    ), expired as materialized (
        select q.ctid from detached d join public.account_detection_pending428 q using(partition_oid)
        limit 128 for update of q skip locked
    )
    delete from public.account_detection_pending428 q using expired e where q.ctid=e.ctid;
    delete from public.detection_source_catalog428 c
    where not exists(select 1 from pg_inherits i where i.inhrelid=c.partition_oid)
      and not exists(select 1 from public.account_detection_pending428 q where q.partition_oid=c.partition_oid);
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
        source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
    select distinct login,session_user,(c.origin->>'installation_id')::uuid,'sli.windows.ad-dc',
        c.origin->>'source_instance_id',c.origin->>'source_generation','','core_event',
        (c.origin->>'log_source_id')::bigint,(c.origin->>'agent_id')::uuid
    from public.detection_source_catalog428 c join pg_inherits i on i.inhrelid=c.partition_oid
        and i.inhparent in ('public.event_hot'::regclass,'public.event_cold_daily'::regclass) and not i.inhdetachpending
    where public.semantic_source_active320((c.origin->>'agent_id')::uuid,'sli.windows.ad-dc',c.channel#>>'{}')
      and not exists(select 1 from public.finding_evidence_source_bindings b
          where b.principal_oid=login and b.installation_id::text=c.origin->>'installation_id'
            and b.plugin_id='sli.windows.ad-dc' and b.source_instance_id=c.origin->>'source_instance_id'
            and b.source_generation=c.origin->>'source_generation' and b.collection_scope_id='' and b.storage_kind='core_event')
    on conflict do nothing;
    return query select distinct jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,'source_generation',b.source_generation,'collection_scope_id',''),
        'agent_id',a.id::text,'instance_name',a.instance_name,'host_name',a.registration_host_name,'config',coalesce(m->'config','{}'))
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id=b.agent_id
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
      and b.storage_kind='core_event' and a.status='active' and m->>'module_id'=b.plugin_id and m->'enabled'='true'::jsonb;
end $$;

-- The account labels, identities, proof and output schemas remain in the
-- installed functions. Replace their candidate selection and preserve ACLs.
do $patch$
declare saved record; patched text; family text; start_at integer; end_at integer;
    candidates constant text := $candidates$
    scope428:=jsonb_build_object('installation_id',p_installation::text,'plugin_id',p_plugin,
        'source_instance_id',p_source,'source_generation',p_generation,'collection_scope_id','');
    if p_normalized is null then
        checkpoint428:=public.register_account_checkpoint428(%1$L,p_checkpoint,scope428);
    end if;
    return query
    with bound as materialized (
        -- The reference verifier's login and binding predicate is common to
        -- this batch. Recheck it in the same snapshot as the evidence join.
        select b.agent_id from public.finding_evidence_source_bindings b join pg_roles r
          on r.oid=b.principal_oid and r.rolname=b.principal_name and r.rolname=session_user
        where p_normalized is null and b.installation_id=p_installation and b.plugin_id=p_plugin
          and b.source_instance_id=p_source and b.source_generation=p_generation
          and b.collection_scope_id='' and b.storage_kind='core_event'
          and b.agent_id=source_binding.agent_id
    ), partitions as materialized (
        select distinct c.partition_oid,c.channel
        from public.detection_source_catalog428 c join pg_inherits i on i.inhrelid=c.partition_oid
          and i.inhparent='public.event_hot'::regclass and not i.inhdetachpending
        join bound b on c.origin->>'agent_id'=b.agent_id::text
        where c.origin-'agent_id'-'log_source_id'=scope428
          and public.semantic_source_active320(b.agent_id,p_plugin,c.channel#>>'{}')
    ), events as materialized (
        select ranked.* from (
            select pending.* from partitions p cross join lateral (
                select event.* from public.account_detection_pending428 q cross join lateral (
                    -- The exact native row supplies its own hash and channel.
                    -- It must match the authorized scope and queued witness
                    -- before counting toward the batch limit.
                    select e.* from public.short_account_candidates337 e
                    where e.occurred_at_utc=q.occurred_at and e.source_event_id=q.source_event_id
                      and e.normalized_event_id=q.normalized_id
                      and e.origin-'agent_id'-'log_source_id'=scope428
                      and e.origin->>'agent_id'=source_binding.agent_id::text
                      and e.source_event_id>0 and e.native_sha256 ~ '^[a-f0-9]{64}$'
                      and e.item->>'channel' is not distinct from (p.channel#>>'{}') offset 0
                ) event
                where q.checkpoint_id=checkpoint428 and q.partition_oid=p.partition_oid
                  and q.agent_id=source_binding.agent_id::text and q.channel=p.channel
                  and q.occurred_at<=statement_timestamp()
                  and (select true from public.semantic_account_%1$s_checks checked
                      where checked.checkpoint_key=p_checkpoint and checked.normalized_event_id=q.normalized_id) is null
                order by q.occurred_at,q.normalized_id limit 128
            ) pending
            union all
            select e.* from public.short_account_candidates337 e
            where p_normalized is not null and e.normalized_event_id=p_normalized
              and e.origin-'agent_id'-'log_source_id'=scope428 and e.origin->>'agent_id'=source_binding.agent_id::text
              and e.occurred_at_utc<=statement_timestamp()
              and public.resolve_finding_evidence_ref(p_installation,p_plugin,p_source,p_generation,'','core_event',
                  e.source_event_id::text,e.native_sha256)
        ) ranked order by ranked.normalized_at,ranked.normalized_event_id limit 128
    )
    $candidates$;
begin
    for saved in select * from public.detection_reader_restore428
        where signature<>'public.short_detection_sources337()'::regprocedure loop
        family:=case when saved.signature='public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid)'::regprocedure
            then 'decoy' else 'watch' end;
        start_at:=strpos(saved.definition,E'    return query\n    with source_candidates as materialized (');
        end_at:=strpos(saved.definition,E'\n    select e.normalized_event_id,e.source_event_id');
        if start_at=0 or end_at<=start_at or strpos(saved.definition,'declare source_binding ') = 0
           or strpos(saved.definition,'where public.resolve_finding_evidence_ref(')=0
           or not exists(select 1 from pg_proc p where p.oid=saved.signature and p.provolatile='v') then
            raise exception 'detection_read_checkpoints428_reader_shape: %',saved.signature using errcode='55000';
        end if;
        patched:=substr(saved.definition,1,start_at-1)||format(candidates,family)||substr(saved.definition,end_at);
        patched:=replace(patched,'declare source_binding public.finding_evidence_source_bindings%rowtype;',
            'declare source_binding public.finding_evidence_source_bindings%rowtype; scope428 jsonb; checkpoint428 bigint;');
        execute patched;
    end loop;
    if exists(select 1 from public.detection_reader_restore428 d join pg_proc p on p.oid=d.signature
        where p.proowner<>d.owner_oid or p.proacl is distinct from d.acl or not p.prosecdef) then
        raise exception 'detection_read_checkpoints428_reader_metadata' using errcode='55000';
    end if;
    update public.detection_reader_restore428 d set installed_definition=pg_get_functiondef(d.signature);
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(428,'detection_read_checkpoints');
commit;
