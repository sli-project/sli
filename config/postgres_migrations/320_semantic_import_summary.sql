-- Imported packet facts are an acceleration structure, NEVER evidence authority.
-- No scan/index build on the retained core. Bootstrap uses the inbox PK in
-- committed portions; triggers capture changes even behind that bootstrap key.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_semantic_summary_v320'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role(session_user,'adlog_user','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=319 and name='storage_lifecycle_roles')
       or exists(select 1 from public.schema_migrations where version>=320) then
        raise exception 'semantic_summary_320_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Capture definitions in the database for an exact, OID/ACL-preserving rollback.
create table public.semantic_summary_definitions320(signature text primary key,definition text not null);
insert into public.semantic_summary_definitions320
select oid::regprocedure::text,pg_get_functiondef(oid) from pg_proc where oid in (
    'public.t109_detection_sources()'::regprocedure,
    'public.default_detection_sources_before_v301()'::regprocedure,
    'public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,
    'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure);
create table public.semantic_import_state320(
    singleton boolean primary key default true check(singleton),
    bootstrap_after uuid,
    bootstrap_done boolean not null default false,bootstrap_packets bigint not null default 0,revision bigint not null default 0);
insert into public.semantic_import_state320 default values;
-- Append-only invalidations: ingest never contends with detector-owned rows.
create table public.semantic_import_dirty320(notification_id bigint generated always as identity primary key,packet_id uuid not null);
create table public.semantic_default_dirty320(notification_id bigint generated always as identity primary key,agent_id uuid not null,module_id text not null);
create table public.semantic_default_state320(
    agent_id uuid not null,module_id text not null,dirty boolean not null default true,
    tail jsonb not null default '[]',primary key(agent_id,module_id));
create table public.semantic_packet_facts320(
    packet_id uuid not null,agent_id uuid not null,module_id text not null,
    source_instance_id text not null,source_generation text not null,native_channel text not null,
    log_source_id bigint not null,primary key(packet_id,log_source_id));
create table public.semantic_stream_facts320(
    agent_id uuid not null,module_id text not null,source_instance_id text not null,
    source_generation text not null,native_channel text not null,log_source_id bigint not null,
    packets bigint not null check(packets>=0),
    primary key(agent_id,module_id,source_instance_id,source_generation,native_channel,log_source_id));
create table public.semantic_event_facts320(
    core_id bigint primary key,packet_id uuid not null,agent_id uuid not null,
    source_instance_id text not null,source_generation text not null,
    log_source_id bigint not null,event_id integer not null,revision bigint not null);
create index semantic_event_packet320 on public.semantic_event_facts320(packet_id);
create index semantic_event_cursor320 on public.semantic_event_facts320
    (agent_id,md5(source_instance_id),md5(source_generation),revision,core_id);
create index semantic_seen_scope320 on public.semantic_t109_seen(md5(scope_json::text),native_id);
create table public.semantic_source_cursor320(
    principal_oid oid not null,principal_name name not null,scope_key text not null,
    kind text not null,checkpoint text not null,scope_json jsonb not null,
    revision bigint not null default 0,core_id bigint not null default 0,
    channels jsonb not null default '[]',
    primary key(principal_oid,principal_name,scope_key,kind,checkpoint));
create table public.semantic_source_pending320(
    principal_oid oid not null,principal_name name not null,scope_key text not null,
    kind text not null,checkpoint text not null,core_id bigint not null,
    primary key(principal_oid,principal_name,scope_key,kind,checkpoint,core_id));
revoke all on public.semantic_summary_definitions320,public.semantic_import_state320,
    public.semantic_import_dirty320,public.semantic_default_dirty320,public.semantic_default_state320,public.semantic_packet_facts320,public.semantic_stream_facts320,
    public.semantic_event_facts320,public.semantic_source_cursor320,public.semantic_source_pending320
    from public,adlog_user,adlog_semantic_worker;

-- Native UUID validation plus canonical roundtrip retains the exact lower-case
-- UUID admission without a regex per retained row during bulk DELETE.
-- Statement transition tables deduplicate a packet per write statement. The
-- ingest invalidates stream metadata and enqueues without taking the global
-- import watermark lock.
create function public.semantic_import_notify320() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare ids uuid[];
begin
    if tg_table_name in ('sli_agent_packet_inbox','sli_agent_receipts') then
        select array_agg(distinct packet_id) into ids from changed;
    elsif tg_table_name='raw_log_files' then
        select array_agg(distinct substr(file_path,14)::uuid) into ids from changed
        where case when left(file_path,13)='agent-packet:' and octet_length(file_path)=49
            and pg_input_is_valid(substr(file_path,14),'uuid')
            then substr(file_path,14)::uuid::text=substr(file_path,14) else false end;
    elsif tg_table_name='events_v2_core' then
        select array_agg(distinct substr(raw.file_path,14)::uuid) into ids from
            (select distinct raw_log_file_id from changed) c
        join public.raw_log_files raw on raw.id=c.raw_log_file_id
        where case when left(raw.file_path,13)='agent-packet:' and octet_length(raw.file_path)=49
            and pg_input_is_valid(substr(raw.file_path,14),'uuid')
            then substr(raw.file_path,14)::uuid::text=substr(raw.file_path,14) else false end;
    else
        select array_agg(distinct substr(raw.file_path,14)::uuid) into ids from
            (select distinct source_event_id from changed) n
        join public.events_v2_core e on e.id=n.source_event_id
        join public.raw_log_files raw on raw.id=e.raw_log_file_id
        where case when left(raw.file_path,13)='agent-packet:' and octet_length(raw.file_path)=49
            and pg_input_is_valid(substr(raw.file_path,14),'uuid')
            then substr(raw.file_path,14)::uuid::text=substr(raw.file_path,14) else false end;
    end if;
    insert into public.semantic_import_dirty320(packet_id) select id from unnest(ids) id;
    if tg_table_name='sli_agent_receipts' then
        -- OLD receipt transition data also invalidates a deleted stream.
        insert into public.semantic_default_dirty320(agent_id,module_id)
        select distinct agent_id,module_id from changed where module_id in ('sli.windows.ad-dc','sli.vpn-nps') order by agent_id,module_id;
    elsif tg_table_name<>'normalized_events' then
        insert into public.semantic_default_dirty320(agent_id,module_id)
        select distinct r.agent_id,r.module_id from unnest(ids) id join public.sli_agent_receipts r on r.packet_id=id
        where r.module_id in ('sli.windows.ad-dc','sli.vpn-nps') order by r.agent_id,r.module_id;
    end if;
    return null;
end $$;
revoke all on function public.semantic_import_notify320() from public,adlog_user,adlog_semantic_worker;
-- Legacy tables can belong to postgres on upgraded installations. Use the
-- migration session for DDL; the definer above remains adlog_storage_owner.
reset role;
do $$ declare t text; begin
    foreach t in array array['sli_agent_packet_inbox','sli_agent_receipts','raw_log_files','events_v2_core','normalized_events'] loop
        execute format('create trigger semantic_import_insert320 after insert on public.%I referencing new table as changed for each statement execute function public.semantic_import_notify320()',t);
        execute format('create trigger semantic_import_update320 after update on public.%I referencing new table as changed for each statement execute function public.semantic_import_notify320()',t);
        execute format('create trigger semantic_import_old320 after update on public.%I referencing old table as changed for each statement execute function public.semantic_import_notify320()',t);
        execute format('create trigger semantic_import_delete320 after delete on public.%I referencing old table as changed for each statement execute function public.semantic_import_notify320()',t);
    end loop;
end $$;
set local role adlog_storage_owner;

create function public.semantic_import_refresh320() returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare state public.semantic_import_state320%rowtype; ids uuid[]; tail uuid; batch uuid[]; rev bigint;
begin
    -- One writer gives revisions commit order, not sequence allocation order.
    -- SKIP LOCKED makes competing workers reuse the previous committed facts.
    select * into state from public.semantic_import_state320 where singleton for update skip locked;
    if not found then return; end if;
    -- Consume only visible notification identities. A lower identity committed
    -- later remains queued; neither queue uses an allocation-order watermark.
    with picked as (select notification_id from public.semantic_default_dirty320 order by notification_id limit 512),
    removed as (delete from public.semantic_default_dirty320 d using picked p where d.notification_id=p.notification_id returning d.agent_id,d.module_id)
    insert into public.semantic_default_state320(agent_id,module_id)
    select distinct agent_id,module_id from removed
    on conflict(agent_id,module_id) do update set dirty=true;
    -- Cache the EXACT original 128-receipt generation tail, including empty
    -- imported packets. It is invalidated by writes, never re-read on idle
    -- cycles. Live module bindings/status/config remain outside this cache.
    insert into public.semantic_default_state320(agent_id,module_id)
    select agent_id,module_id from public.sli_agent_module_bindings
    where module_id in ('sli.windows.ad-dc','sli.vpn-nps') on conflict do nothing;
    batch:=null;
    select * into strict state from public.semantic_import_state320 where singleton;
    if not state.bootstrap_done then
        select array_agg(i.packet_id order by i.packet_id) into batch from (
            select packet_id from public.sli_agent_packet_inbox
            where packet_id>=coalesce(state.bootstrap_after,'00000000-0000-0000-0000-000000000000'::uuid)
              and (state.bootstrap_after is null or packet_id>state.bootstrap_after) order by packet_id limit 512) i;
        tail:=batch[array_length(batch,1)];
        update public.semantic_import_state320 set bootstrap_after=coalesce(tail,bootstrap_after),
            bootstrap_done=coalesce(array_length(batch,1),0)<512,
            bootstrap_packets=bootstrap_packets+coalesce(array_length(batch,1),0) where singleton;
    end if;
    -- Notifications append distinct identities even for an in-flight packet.
    with picked as (select notification_id from public.semantic_import_dirty320 order by notification_id limit 512),
    removed as (delete from public.semantic_import_dirty320 d using picked p where d.notification_id=p.notification_id returning d.packet_id)
    select array_agg(packet_id) into ids from removed;
    select array_agg(distinct id) into ids from unnest(coalesce(ids,'{}')||coalesce(batch,'{}')) id;
    if ids is null then return; end if;
    update public.semantic_import_state320 set revision=revision+1 where singleton returning revision into rev;
    -- Remove old contributions before recomputing the changed packets. This
    -- includes revocation, envelope edits, deletes and changed raw/core mappings.
    with old as (delete from public.semantic_packet_facts320 where packet_id=any(ids) returning *),
    counts as (select agent_id,module_id,source_instance_id,source_generation,native_channel,log_source_id,count(*) n
        from old group by 1,2,3,4,5,6)
    update public.semantic_stream_facts320 s set packets=s.packets-c.n from counts c
    where (s.agent_id,s.module_id,s.source_instance_id,s.source_generation,s.native_channel,s.log_source_id)=
        (c.agent_id,c.module_id,c.source_instance_id,c.source_generation,c.native_channel,c.log_source_id);
    delete from public.semantic_stream_facts320 where packets=0;
    delete from public.semantic_event_facts320 where packet_id=any(ids);
    with admitted as materialized (
        select i.packet_id,r.agent_id,r.module_id,r.envelope->>'source_instance_id' source_instance_id,
            coalesce(r.envelope->>'generation','') source_generation,coalesce(i.collection_channel,'') native_channel
        from unnest(ids) id join public.sli_agent_packet_inbox i on i.packet_id=id
        join public.sli_agent_receipts r on r.packet_id=i.packet_id
        where i.imported_at is not null and r.receipt->>'status'='committed' and i.envelope=r.envelope
          and r.envelope->>'source_instance_id' is not null
          -- Workstation admission uses the receipt's source, while observation
          -- generations are independent (including historical receipt formats).
          and (r.envelope->>'generation' is not null or r.module_id='sli.workstations')
    ), facts as (
        insert into public.semantic_packet_facts320
        select a.*,coalesce(e.log_source_id,0) from admitted a left join lateral (
            select distinct core.log_source_id from public.events_v2_core core
            where core.raw_log_file_id=(select raw.id from public.raw_log_files raw where raw.file_path='agent-packet:'||a.packet_id::text)
            offset 0) e on true returning *
    )
    insert into public.semantic_stream_facts320
    select agent_id,module_id,source_instance_id,source_generation,native_channel,log_source_id,count(*) from facts group by 1,2,3,4,5,6
    on conflict(agent_id,module_id,source_instance_id,source_generation,native_channel,log_source_id)
    do update set packets=semantic_stream_facts320.packets+excluded.packets;
    insert into public.semantic_event_facts320
    select core.id,p.packet_id,p.agent_id,p.source_instance_id,p.source_generation,core.log_source_id,core.event_id,rev
    from (select distinct packet_id,agent_id,source_instance_id,source_generation from public.semantic_packet_facts320
          where packet_id=any(ids)) p cross join lateral (
        select e.* from public.events_v2_core e where e.raw_log_file_id=(select raw.id from public.raw_log_files raw
            where raw.file_path='agent-packet:'||p.packet_id::text) offset 0) core
    where core.event_id in (4688,4104,1102,4719,7036,7040,7045,4624,4625,4768,4769,4771,4776);

end $$;
revoke all on function public.semantic_import_refresh320() from public,adlog_user;
grant execute on function public.semantic_import_refresh320() to adlog_semantic_worker;

-- A slow/cancelled tail must never roll back packet bootstrap progress.
create function public.semantic_default_refresh320() returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare stream record; head jsonb;
begin
    for stream in select * from public.semantic_default_state320 d where d.dirty
        and d.module_id in ('sli.windows.ad-dc','sli.vpn-nps') order by d.agent_id,d.module_id limit 1 for update skip locked
    loop
        select coalesce(jsonb_agg(jsonb_build_object('packet_id',r.packet_id,'sequence',r.sequence,
            'source_instance_id',r.envelope->>'source_instance_id','source_generation',r.envelope->>'generation',
            'native_channel',i.collection_channel,'log_source_id',core.log_source_id)),'[]') into head
        from (select receipt.* from public.sli_agent_receipts receipt
            where receipt.agent_id=stream.agent_id and receipt.module_id=stream.module_id
            order by receipt.sequence desc limit 128) r
        join public.sli_agent_packet_inbox i on i.packet_id=r.packet_id
            and i.imported_at is not null and i.envelope=r.envelope
        left join lateral (select e.log_source_id from public.events_v2_core e
            where e.raw_log_file_id=(select raw.id from public.raw_log_files raw where raw.file_path='agent-packet:'||r.packet_id::text)
              and e.log_source_id is not null order by e.id limit 1) core on true
        where r.receipt->>'status'='committed';
        update public.semantic_default_state320 d set dirty=false,tail=head
        where d.agent_id=stream.agent_id and d.module_id=stream.module_id;
        return true;
    end loop;
    return false;
end $$;
revoke all on function public.semantic_default_refresh320() from public,adlog_user;
grant execute on function public.semantic_default_refresh320() to adlog_semantic_worker;

-- Preserve the complete discovery branches until every historical packet has
-- been traversed. Helpers are private; public functions retain their OIDs/ACLs.
do $$ declare r record; helper text; begin
    for r in select * from public.semantic_summary_definitions320
        where signature in ('t109_detection_sources()','default_detection_sources_before_v301()') loop
        helper:=case when r.signature='t109_detection_sources()' then 'semantic_t109_full320' else 'semantic_default_full320' end;
        execute replace(r.definition,split_part(r.signature,'(',1)||'()',helper||'()');
        execute format('revoke all on function public.%I() from public,adlog_user,adlog_semantic_worker',helper);
    end loop;
end $$;
create function public.semantic_import_progress320() returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('bootstrap_done',bootstrap_done,'bootstrap_after',bootstrap_after,
        'bootstrap_packets',bootstrap_packets,'revision',revision,
        'pending',not bootstrap_done or exists(select 1 from public.semantic_import_dirty320)
            or exists(select 1 from public.semantic_default_dirty320) or exists(select 1 from public.semantic_default_state320 where dirty)) from public.semantic_import_state320 where singleton
$$;
revoke all on function public.semantic_import_progress320() from public,adlog_user;
grant execute on function public.semantic_import_progress320() to adlog_semantic_worker;

create function public.semantic_source_active320(a uuid,plugin text,channel text default null) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.sli_agents agent cross join lateral jsonb_array_elements(agent.assigned_modules) m
        where agent.id=a and agent.status='active' and m->>'module_id'=plugin and m->'enabled'='true'::jsonb
          and (channel is null or coalesce(m#>array['config','channels',channel],'true'::jsonb)='true'::jsonb))
$$;
revoke all on function public.semantic_source_active320(uuid,text,text) from public,adlog_user,adlog_semantic_worker;

-- Read-time admission: discovery is not a fence for newly imported channels.
create function public.semantic_channels_refresh320() returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid;
begin
    select oid into strict login from pg_roles where rolname=session_user;
    delete from public.semantic_t109_channels where principal_oid=login and principal_name=session_user;
    insert into public.semantic_t109_channels
    select distinct login,session_user,b.installation_id,b.source_instance_id,b.source_generation,
        f.log_source_id,f.native_channel
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id=b.agent_id
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    join public.semantic_stream_facts320 f on f.agent_id=b.agent_id and f.module_id='sli.windows.ad-dc'
        and f.source_instance_id=b.source_instance_id and f.source_generation=b.source_generation
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
      and b.storage_kind='core_event' and b.collection_scope_id='' and a.status='active'
      and m->>'module_id'='sli.windows.ad-dc' and m->'enabled'='true'::jsonb
      and f.log_source_id<>0 and f.native_channel in ('System','Microsoft-Windows-PowerShell/Operational')
      and coalesce(m#>array['config','channels',f.native_channel],'true'::jsonb)='true'::jsonb
    on conflict do nothing;
end $$;
revoke all on function public.semantic_channels_refresh320() from public,adlog_user,adlog_semantic_worker;

create function public.semantic_source_candidates320(a uuid,s jsonb,k text,c text,
    first_at timestamptz default null,last_at timestamptz default null,reference uuid default null)
returns table(id bigint) language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid; key text:=md5(s::text||a::text); cursor_row public.semantic_source_cursor320%rowtype; high_rev bigint; high_id bigint; bound_log bigint; admitted_revision bigint; channels_now jsonb;
begin
    if k not in ('native','decoy') or c is null or
       (k='decoy' and (octet_length(c)<>64 or c !~ '^[a-f0-9]{64}$')) or (k='native' and c<>'') then
        raise exception 'semantic_summary_checkpoint_invalid' using errcode='22023';
    end if;
    select oid into strict login from pg_roles where rolname=session_user;
    select b.log_source_id into strict bound_log from public.finding_evidence_source_bindings b
    where b.principal_oid=login and b.principal_name=session_user and b.agent_id=a
      and b.installation_id=(s->>'installation_id')::uuid and b.plugin_id=s->>'plugin_id'
      and b.source_instance_id=s->>'source_instance_id' and b.source_generation=s->>'source_generation'
      and b.collection_scope_id=s->>'collection_scope_id' and b.storage_kind='core_event';
    -- Freeze the candidate revision BEFORE channel admission. A maintenance
    -- commit between admission and the candidate query is deferred to next read.
    select revision into admitted_revision from public.semantic_import_state320 where singleton;
    if k='native' then perform public.semantic_channels_refresh320();end if;
    -- A partially populated acceleration structure must never hide evidence.
    if not (select bootstrap_done from public.semantic_import_state320 where singleton) then
        return query select core.id from public.sli_agent_packet_inbox i
        cross join lateral (select e.* from public.events_v2_core e
            where e.raw_log_file_id=(select raw.id from public.raw_log_files raw
                where raw.file_path='agent-packet:'||i.packet_id::text) offset 0) core
        where md5(i.envelope->>'agent_id')=md5(a::text) and i.envelope->>'agent_id'=a::text
          and md5(i.envelope->>'source_instance_id')=md5(s->>'source_instance_id')
          and i.envelope->>'source_instance_id'=s->>'source_instance_id'
          and md5(i.envelope->>'generation')=md5(s->>'source_generation')
          and i.envelope->>'generation'=s->>'source_generation';
        return;
    end if;
    if reference is not null then
        return query select n.source_event_id from public.normalized_events n where n.normalized_event_id=reference;return;
    end if;
    if first_at is not null then
        -- Explicit <=2-day context is validated by the public reader. Never
        -- restrict it to unseen rows or the current ingestion cursor.
        return query select f.core_id from public.semantic_event_facts320 f
          join public.events_v2_core core on core.id=f.core_id where f.agent_id=a
          and md5(f.source_instance_id)=md5(s->>'source_instance_id') and md5(f.source_generation)=md5(s->>'source_generation')
          and f.source_instance_id=s->>'source_instance_id' and f.source_generation=s->>'source_generation'
          and core.time_created_utc between first_at and last_at;return;
    end if;
    -- Serialize new-cursor admission per principal, including concurrent calls.
    perform pg_advisory_xact_lock(hashtextextended('semantic_cursor320:'||login::text,0));
    -- Cursors are disposable acceleration, never acknowledgement authority.
    -- A new rule revision may restart from zero: persisted decoy checks still
    -- suppress processed rows for that checkpoint. Drop its superseded cursor
    -- and pending atomically, without touching another principal/source/kind.
    with obsolete as (
        delete from public.semantic_source_cursor320 q
        where q.principal_oid=login and q.principal_name=session_user and q.kind='decoy'
          and k='decoy' and q.scope_key=key and q.scope_json=s and q.checkpoint<>c
        returning q.*
    ) delete from public.semantic_source_pending320 p using obsolete q
      where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=
            (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint);
    if not exists(select 1 from public.semantic_source_cursor320 q
        where (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint)=(login,session_user,key,k,c))
       and (select count(*) from public.semantic_source_cursor320 q
            where q.principal_oid=login and q.principal_name=session_user)>=256 then
        raise exception 'semantic_summary_cursor_limit' using errcode='54000';
    end if;
    insert into public.semantic_source_cursor320(principal_oid,principal_name,scope_key,kind,checkpoint,scope_json)
    values(login,session_user,key,k,c,s) on conflict do nothing;
    select * into strict cursor_row from public.semantic_source_cursor320 q
    where (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint)=(login,session_user,key,k,c) for update;
    if cursor_row.scope_json<>s then raise exception 'semantic_summary_scope_collision' using errcode='55000';end if;
    if k='native' then
        select coalesce(jsonb_agg(ch.log_source_id order by ch.log_source_id),'[]') into channels_now
        from public.semantic_t109_channels ch
        where ch.principal_oid=login and ch.principal_name=session_user
          and ch.installation_id=(s->>'installation_id')::uuid and ch.source_instance_id=s->>'source_instance_id'
          and ch.source_generation=s->>'source_generation';
        -- A disabled channel never enters pending. When admission expands,
        -- replay this exact stream in the same bounded portions; seen remains
        -- acknowledgement authority. Only one small channel set is retained,
        -- regardless of how long the channel was disabled or how much arrived.
        if not channels_now <@ cursor_row.channels then
            cursor_row.revision:=0;cursor_row.core_id:=0;
        end if;
        update public.semantic_source_cursor320 q set revision=cursor_row.revision,core_id=cursor_row.core_id,channels=channels_now
        where (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint)=(login,session_user,key,k,c);
    end if;
    with incoming as materialized (
        select f.core_id,f.revision from public.semantic_event_facts320 f
        where f.agent_id=a and md5(f.source_instance_id)=md5(s->>'source_instance_id')
          and md5(f.source_generation)=md5(s->>'source_generation')
          and f.source_instance_id=s->>'source_instance_id' and f.source_generation=s->>'source_generation'
          and f.revision<=admitted_revision
          and (f.revision,f.core_id)>(cursor_row.revision,cursor_row.core_id)
        order by f.revision,f.core_id limit 4096
    ), added as (
        insert into public.semantic_source_pending320
        select login,session_user,key,k,c,i.core_id from incoming i
        join public.semantic_event_facts320 f on f.core_id=i.core_id
        where case when k='native' then f.event_id in(4688,4104,1102,4719,7036,7040,7045)
                   else f.event_id in(4624,4625,4768,4769,4771,4776) end
          and (f.log_source_id=bound_log or k='native' and exists(select 1 from public.semantic_t109_channels ch
            where ch.principal_oid=login and ch.principal_name=session_user
              and ch.installation_id=(s->>'installation_id')::uuid and ch.source_instance_id=s->>'source_instance_id'
              and ch.source_generation=s->>'source_generation' and ch.log_source_id=f.log_source_id)) on conflict do nothing
    )
    select revision,core_id into high_rev,high_id from incoming order by revision desc,core_id desc limit 1;
    if found then update public.semantic_source_cursor320 q set revision=high_rev,core_id=high_id
        where (q.principal_oid,q.principal_name,q.scope_key,q.kind,q.checkpoint)=(login,session_user,key,k,c);end if;
    delete from public.semantic_source_pending320 p
    where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c)
      and (not exists(select 1 from public.semantic_event_facts320 f where f.core_id=p.core_id
            and (f.log_source_id=bound_log or k='native' and exists(select 1 from public.semantic_t109_channels ch
                where ch.principal_oid=login and ch.principal_name=session_user
                  and ch.installation_id=(s->>'installation_id')::uuid and ch.source_instance_id=s->>'source_instance_id'
                  and ch.source_generation=s->>'source_generation' and ch.log_source_id=f.log_source_id)))
        or k='native' and exists(select 1 from public.semantic_t109_seen seen
            where md5(seen.scope_json::text)=md5(s::text) and seen.scope_json=s and seen.native_id=p.core_id::text)
        or k='decoy' and not exists(select 1 from public.normalized_events n where n.source_event_id=p.core_id
            and n.normalizer_id='windows.named-eventdata' and n.semantic_contract_version=1
            and not exists(select 1 from public.normalized_events newer
                where newer.source_event_id=n.source_event_id and newer.normalizer_id=n.normalizer_id
                  and (newer.normalized_at,newer.normalized_event_id)>(n.normalized_at,n.normalized_event_id))
            and not exists(select 1 from public.semantic_account_decoy_checks checks
                where checks.checkpoint_key=c and checks.normalized_event_id=n.normalized_event_id)));
    return query select p.core_id from public.semantic_source_pending320 p
        where (p.principal_oid,p.principal_name,p.scope_key,p.kind,p.checkpoint)=(login,session_user,key,k,c);
end $$;
revoke all on function public.semantic_source_candidates320(uuid,jsonb,text,text,timestamptz,timestamptz,uuid)
    from public,adlog_user,adlog_semantic_worker;

-- Replace just the candidate relations. All native receipt/envelope/hash and
-- current assignment checks, ordering and accepted-row limits remain intact.
do $patch$
declare definition text; first_pos integer; last_pos integer;
begin
    definition:=pg_get_functiondef('public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure);
    first_pos:=strpos(definition,'            from (');
    last_pos:=strpos(definition,'            where (e.log_source_id=b.log_source_id');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_native_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$            from public.semantic_source_candidates320(b.agent_id,s,'native','',p_start,p_end) candidate_key
            cross join lateral (select core.* from public.events_v2_core core where core.id=candidate_key.id offset 0) e
            cross join lateral (
                -- Preserve the original exact envelope predicates even if a
                -- dirty packet has not reached the summary portion yet.
                select 1 from public.raw_log_files raw join public.sli_agent_packet_inbox i on i.packet_id=case
                    when raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                    then substr(raw.file_path,14)::uuid end
                where raw.id=e.raw_log_file_id and i.envelope->>'agent_id'=b.agent_id::text
                  and i.envelope->>'source_instance_id'=b.source_instance_id and i.envelope->>'generation'=b.source_generation
                offset 0
            ) packet_scope
$sql$||substr(definition,last_pos);
    definition:=replace(definition,'seen.scope_json=s','md5(seen.scope_json::text)=md5(s::text) and seen.scope_json=s');
    definition:=replace(definition,$old$if b.storage_kind='core_event' then$old$,
        $new$if b.storage_kind='core_event' then
        perform public.semantic_channels_refresh320();
        if not public.semantic_source_active320(b.agent_id,b.plugin_id) then return;end if;$new$);
    definition:=replace(definition,'if doc is not null and public.resolve_finding_evidence_ref',
        $new$if doc is not null and public.semantic_source_active320(b.agent_id,b.plugin_id,doc#>>'{event_row,channel}')
                and public.resolve_finding_evidence_ref$new$);
    -- Reads now advance persistent cursors in the caller's transaction.
    execute replace(definition,' STABLE',' VOLATILE');
    definition:=pg_get_functiondef('public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure);
    definition:=replace(definition,$old$or p_checkpoint !~ '^[a-f0-9]{64}$'$old$,
        $new$or octet_length(p_checkpoint)<>64 or p_checkpoint !~ '^[a-f0-9]{64}$'$new$);
    first_pos:=strpos(definition,'        from (');last_pos:=strpos(definition,'        where e.log_source_id=source_binding.log_source_id');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_decoy_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$        from public.semantic_source_candidates320(source_binding.agent_id,
            jsonb_build_object('installation_id',p_installation::text,'plugin_id',p_plugin,'source_instance_id',p_source,
                'source_generation',p_generation,'collection_scope_id',''),'decoy',p_checkpoint,null,null,p_normalized) candidate_key
        cross join lateral (select core.* from public.events_v2_core core where core.id=candidate_key.id offset 0) e
        cross join lateral (select i.* from public.sli_agent_packet_inbox i where i.packet_id=(
            select substr(raw.file_path,14)::uuid from public.raw_log_files raw where raw.id=e.raw_log_file_id
              and raw.file_path ~ '^agent-packet:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') offset 0) inbox
        cross join lateral (select normalized.* from public.normalized_events normalized where normalized.source_event_id=e.id offset 0) n
$sql$||substr(definition,last_pos);
    definition:=replace(definition,'where e.log_source_id=source_binding.log_source_id',
        $new$where e.log_source_id=source_binding.log_source_id
          and public.semantic_source_active320(source_binding.agent_id,p_plugin,inbox.collection_channel)$new$);
    execute replace(definition,' STABLE',' VOLATILE');
end $patch$;

do $patch$
declare definition text; first_pos integer; last_pos integer;
begin
    definition:=pg_get_functiondef('public.t109_detection_sources()'::regprocedure);
    first_pos:=strpos(definition,'    -- Fence channel selection');
    last_pos:=strpos(definition,'    -- WS XML:');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_discovery_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$    -- Rebuild this principal's small authorization projection from maintained
    -- packet facts and LIVE assignments. A changed/disabled channel cannot
    -- inherit yesterday's admission. Retained bindings are never rewritten.
    perform public.semantic_channels_refresh320();
$sql$||substr(definition,last_pos);
    -- The full-history workstation receipt search uses the same packet facts.
    first_pos:=strpos(definition,'            select 1 from public.sli_agent_receipts r cross join lateral (');
    last_pos:=strpos(definition,'        ) receipt');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_ws_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$            select 1 from public.semantic_stream_facts320 f
            where f.agent_id=a.id and f.module_id='sli.workstations' and f.source_instance_id=a.host_id::text
            limit 1
$sql$||substr(definition,last_pos);
    definition:=replace(definition,E'\nbegin\n',E'\nbegin\n' || $fallback$
    if not (select bootstrap_done from public.semantic_import_state320 where singleton) then
        delete from public.semantic_t109_channels where principal_oid=(select oid from pg_roles where rolname=session_user) and principal_name=session_user;
        return query select * from public.semantic_t109_full320();return;
    end if;
$fallback$);
    execute definition;
    definition:=pg_get_functiondef('public.default_detection_sources_before_v301()'::regprocedure);
    first_pos:=strpos(definition,'    -- Limit the receipt PK tail');
    last_pos:=strpos(definition,'    ), current_scope as (');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_tail_shape';end if;
    definition:=substr(definition,1,first_pos-1)||$sql$    with eligible as materialized (
        select module.agent_id,module.module_id,module.source_instance_id,t.packet_id,t.sequence,t.native_channel,t.log_source_id,
            jsonb_build_object('source_instance_id',t.source_instance_id,'generation',t.source_generation) envelope
        from public.sli_agent_module_bindings module
        join public.sli_agents agent on agent.id=module.agent_id and agent.status='active'
        join public.semantic_default_state320 head on head.agent_id=module.agent_id and head.module_id=module.module_id
        cross join lateral jsonb_to_recordset(head.tail) t(packet_id uuid,sequence bigint,source_instance_id text,
            source_generation text,native_channel text,log_source_id bigint)
        where module.module_id in ('sli.windows.ad-dc','sli.vpn-nps') and t.source_instance_id=module.source_instance_id
          and exists(select 1 from jsonb_array_elements(agent.assigned_modules) m
              where m->>'module_id'=module.module_id and m->'enabled'='true'::jsonb)
$sql$||substr(definition,last_pos);
    first_pos:=strpos(definition,'                select e.log_source_id from public.events_v2_core e');
    last_pos:=strpos(definition,'                order by e.id limit 1');
    if first_pos=0 or last_pos<=first_pos then raise exception 'semantic_summary_320_default_shape';end if;
    last_pos:=last_pos+length('                order by e.id limit 1');
    definition:=substr(definition,1,first_pos-1)||$sql$                select witness.log_source_id where witness.log_source_id is not null$sql$||substr(definition,last_pos);
    definition:=replace(definition,E'\nbegin\n',E'\nbegin\n' || $fallback$
    if not (select bootstrap_done from public.semantic_import_state320 where singleton) then
        return query select * from public.semantic_default_full320();return;
    end if;
$fallback$);
    execute definition;
end $patch$;
insert into public.schema_migrations(version,name) values(320,'semantic_import_summary');
reset role;
commit;
