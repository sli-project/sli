-- S3 detection readers. The old functions remain executable via one setting.
begin;
select pg_advisory_xact_lock(hashtext('sli_detection_short_events_v337'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=336 and name='event_storage_read_grants')
       or exists(select 1 from public.schema_migrations where version>=337)
       or (select relowner from pg_class where oid='public.event_hot'::regclass)<>'adlog_storage_owner'::regrole then
        raise exception 'detection_short_events_337_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.detection_definitions337(signature text primary key,definition text not null,name text not null);
revoke all on public.detection_definitions337 from public,adlog_user,adlog_semantic_worker;
insert into public.detection_definitions337
select p.oid::regprocedure::text,pg_get_functiondef(p.oid),p.proname from pg_proc p where p.oid in (
    'public.default_detection_sources_before_v301()'::regprocedure,
    'public.t109_detection_sources()'::regprocedure,
    'public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure,
    'public.link_finding_evidence_ref(bigint,uuid,text,text,text,text,text,text,text)'::regprocedure,
    'public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure,
    'public.read_t109_native(jsonb,timestamptz,timestamptz)'::regprocedure,
    'public.read_default_password_events(jsonb)'::regprocedure,
    'public.read_default_password_window_v2(jsonb)'::regprocedure,
    'public.read_password_retained_proof_v2(jsonb,jsonb)'::regprocedure,
    'public.password_v2_native_cost(jsonb,jsonb)'::regprocedure,
    'public.read_account_decoy_events(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.read_account_watch_events(uuid,text,text,text,text,uuid)'::regprocedure,
    'public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure);
do $$ begin
    if exists(select 1 from public.detection_definitions337 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner<>'adlog_storage_owner'::regrole or not p.prosecdef) then
        raise exception 'detection_short_events_337_function_owner' using errcode='55000';
    end if;
end $$;

-- This setting is deliberately a persisted owner choice, never a caller GUC.
create table public.detection_storage337(singleton boolean primary key default true check(singleton),
    source text not null check(source in ('short','legacy')));
insert into public.detection_storage337 values(true,'short');
revoke all on public.detection_storage337 from public,adlog_user,adlog_semantic_worker;
grant select,update(source) on public.detection_storage337 to adlog_user;
create function public.detections_use_short337() returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select source='short' from public.detection_storage337 where singleton
$$;
revoke all on function public.detections_use_short337() from public;
grant execute on function public.detections_use_short337() to adlog_user,adlog_semantic_worker;

-- The importer is the sole writer. Admit provenance while the packet still
-- exists, in the SAME transaction as the short row, rather than at read time.
alter table public.event_hot add column source_sha256 bytea check(source_sha256 is null or octet_length(source_sha256)=32);
alter table public.event_cold_facts add column source_sha256 bytea check(source_sha256 is null or octet_length(source_sha256)=32);
alter table public.event_hot add column event_record_id bigint;
alter table public.event_cold_facts add column event_record_id bigint;
create function public.attest_short_event337() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare origin jsonb; digest bytea; record_id bigint;
begin
    new.method:=new.method-'$origin'; new.source_sha256:=null; new.event_record_id:=null;
    select jsonb_build_object('installation_id',installation.installation_id::text,'plugin_id','sli.windows.ad-dc',
        'source_instance_id',i.envelope->>'source_instance_id','source_generation',i.envelope->>'generation',
        'collection_scope_id','','agent_id',r.agent_id::text,'log_source_id',e.log_source_id),e.normalized_hash,e.event_record_id
    into origin,digest,record_id
    from public.events_v2_core e join public.raw_log_files raw on raw.id=e.raw_log_file_id
    join public.sli_agent_packet_inbox i on raw.file_path='agent-packet:'||i.packet_id::text
    join public.sli_agent_receipts r on r.packet_id=i.packet_id and r.envelope=i.envelope
    cross join public.semantic_default_installation installation
    where e.id=new.event_id and e.event_id=new.event_kind and e.time_created_utc=new.time_created_utc
      and e.domain_id=new.domain_id and e.server_id::text=new.method->>'$server_id'
      and r.module_id='sli.windows.ad-dc' and r.receipt->>'status'='committed'
      and i.envelope->>'agent_id'=r.agent_id::text
      and i.collection_channel=new.method->>'$channel';
    if found then new.method:=new.method||jsonb_build_object('$origin',origin); new.source_sha256:=digest; new.event_record_id:=record_id; end if;
    return new;
end $$;
revoke all on function public.attest_short_event337() from public;
create trigger attest_short_event337 before insert on public.event_hot for each row execute function public.attest_short_event337();
create index event_hot_detection337 on public.event_hot((method#>>'{$origin,source_instance_id}'),time_created_utc,event_id);

create function public.short_event_document337(h public.event_hot) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('version','sli.short-event.1','source_event_id',h.event_id,'event_id',h.event_kind,
        'occurred_at_utc',to_char(h.time_created_utc at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'scope',(h.method->'$origin')-'agent_id'-'log_source_id','computer',coalesce(h.method->>'$machine_name',h.computer),
        'channel',h.method->>'$channel','provider',h.method->>'$provider',
        'fields',coalesce(h.method->'$principals','{}')||
            (select coalesce(jsonb_object_agg(key,value),'{}') from jsonb_each(h.method) where left(key,1)<>'$')||h.outcome||h.fields)
$$;
revoke all on function public.short_event_document337(public.event_hot) from public;

-- Compatibility relations are private to the reviewed reader bodies. There
-- is no runtime SELECT grant on either raw short events or the old core.
create view public.detection_events337 as
    select h.event_id as id,h.event_kind as event_id,h.time_created_utc,h.source_sha256 as normalized_hash,
        (h.method#>>'{$origin,log_source_id}')::bigint as log_source_id,
        (h.method->'$origin')-'agent_id'-'log_source_id' as scope_json from public.event_hot h
    where h.source_sha256 is not null and h.method->>'$channel'='Security';
revoke all on public.detection_events337 from public,adlog_user,adlog_semantic_worker;
create function public.short_native_source337(p_id bigint) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case when count(*)=1 then jsonb_agg(jsonb_build_object('event_row',jsonb_build_object(
        'xml',public.short_event_document337(h)::text,'channel',h.method->>'$channel')))->0 end
    from public.event_hot h where h.event_id=p_id and h.source_sha256 is not null
$$;
revoke all on function public.short_native_source337(bigint) from public;

create function public.short_ref_allowed337(s jsonb,p_native text,p_hash text) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select p_native ~ '^[1-9][0-9]{0,18}$' and p_hash ~ '^[a-f0-9]{64}$' and exists (
        select 1 from public.finding_evidence_source_bindings b join pg_roles r
          on r.oid=b.principal_oid and r.rolname=b.principal_name and r.rolname=session_user
        join public.event_hot h on h.event_id::text=p_native and encode(h.source_sha256,'hex')=p_hash
          and (h.method->'$origin')-'agent_id'-'log_source_id'=s
          and h.method#>>'{$origin,agent_id}'=b.agent_id::text
        where b.installation_id::text=s->>'installation_id' and b.plugin_id='sli.windows.ad-dc'
          and s->>'plugin_id'=b.plugin_id and b.source_instance_id=s->>'source_instance_id'
          and b.source_generation=s->>'source_generation' and b.collection_scope_id='' and s->>'collection_scope_id'=''
          and b.storage_kind='core_event'
          and public.semantic_source_active320(b.agent_id,b.plugin_id,h.method->>'$channel'))
$$;
revoke all on function public.short_ref_allowed337(jsonb,text,text) from public;

create function public.short_detection_sources337() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare login oid;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER') then
        raise exception 'detection_source_denied' using errcode='42501'; end if;
    select oid into strict login from pg_roles where rolname=session_user;
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
        source_instance_id,source_generation,collection_scope_id,storage_kind,log_source_id,agent_id)
    select distinct login,session_user,(o->>'installation_id')::uuid,'sli.windows.ad-dc',
        o->>'source_instance_id',o->>'source_generation','','core_event',
        (o->>'log_source_id')::bigint,(o->>'agent_id')::uuid
    from (select method,source_sha256 from public.event_hot
          union all select method,decode(repeat('00',32),'hex') from public.event_cold_daily) h
    cross join lateral (select h.method->'$origin' as o) origin
    where h.source_sha256 is not null and public.semantic_source_active320((o->>'agent_id')::uuid,'sli.windows.ad-dc',h.method->>'$channel')
    on conflict do nothing;
    return query select distinct jsonb_build_object('scope',jsonb_build_object('installation_id',b.installation_id::text,
        'plugin_id',b.plugin_id,'source_instance_id',b.source_instance_id,'source_generation',b.source_generation,'collection_scope_id',''),
        'agent_id',a.id::text,'instance_name',a.instance_name,'host_name',a.registration_host_name,'config',coalesce(m->'config','{}'))
    from public.finding_evidence_source_bindings b join public.sli_agents a on a.id=b.agent_id
    cross join lateral jsonb_array_elements(a.assigned_modules) m
    where b.principal_oid=login and b.principal_name=session_user and b.plugin_id='sli.windows.ad-dc'
      and b.storage_kind='core_event' and a.status='active' and m->>'module_id'=b.plugin_id and m->'enabled'='true'::jsonb;
end $$;
revoke all on function public.short_detection_sources337() from public;

create function public.short_t109_events337(s jsonb,p_start timestamptz,p_end timestamptz)
returns table(native_id text,event_id integer,occurred_at_utc timestamptz,sha256 text,source_xml text,collection_scope_id text,document jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform public.password_v2_source_binding(s);
    return query select h.event_id::text,h.event_kind,h.time_created_utc,encode(h.source_sha256,'hex'),
        public.short_event_document337(h)::text,''::text,null::jsonb from public.event_hot h
    where (h.method->'$origin')-'agent_id'-'log_source_id'=s and h.time_created_utc<=statement_timestamp()
      and h.event_kind in(1102,104,4719,4688,4104,7036,7040,7045)
      and (p_start is null or h.time_created_utc>=p_start) and (p_end is null or h.time_created_utc<=p_end)
      and (p_start is not null or not exists(select 1 from public.semantic_t109_seen seen where seen.scope_json=s and seen.native_id=h.event_id::text))
      and public.short_ref_allowed337(s,h.event_id::text,encode(h.source_sha256,'hex'))
    order by h.time_created_utc,h.event_id limit 10001;
end $$;
revoke all on function public.short_t109_events337(jsonb,timestamptz,timestamptz) from public;

-- Copies belong to a finding, not to a source partition or a normalized row.
create table public.finding_event_copies337(
    finding_id bigint not null references public.findings(id) on delete cascade,
    event_id bigint not null,time_created_utc timestamptz not null,event_kind integer not null,domain_id bigint not null,
    actor text,target text,source text,computer text not null,method jsonb not null,outcome jsonb not null,fields jsonb not null,
    source_sha256 bytea not null,evidence_role text not null,note text,event_record_id bigint,
    primary key(finding_id,time_created_utc,event_id,evidence_role));
revoke all on public.finding_event_copies337 from public,adlog_user,adlog_semantic_worker;
grant select on public.finding_event_copies337 to adlog_user;
grant select(finding_id,event_id,evidence_role) on public.finding_event_copies337 to adlog_semantic_worker;
create function public.copy_finding_event337(p_finding bigint,p_native text,p_hash text,p_role text,p_note text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added bigint;
begin
    insert into public.finding_event_copies337
    select p_finding,h.event_id,h.time_created_utc,h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,
        h.method,h.outcome,h.fields,h.source_sha256,p_role,p_note,h.event_record_id from public.event_hot h
    where h.event_id::text=p_native and encode(h.source_sha256,'hex')=p_hash
    on conflict do nothing;
    get diagnostics added=row_count; return added>0;
end $$;
revoke all on function public.copy_finding_event337(bigint,text,text,text,text) from public;

create function public.copy_linked_finding_event337() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if public.detections_use_short337() then
        perform public.copy_finding_event337(new.finding_id,new.event_id::text,encode(h.source_sha256,'hex'),new.evidence_role,new.note)
        from public.event_hot h where h.event_id=new.event_id and h.source_sha256 is not null;
    end if;
    return new;
end $$;
revoke all on function public.copy_linked_finding_event337() from public;
reset role;
create trigger copy_linked_finding_event337 after insert on public.finding_evidence for each row execute function public.copy_linked_finding_event337();
set local role adlog_storage_owner;

create view public.finding_event_details337 as
select h.finding_id,h.event_id as event_db_id,h.event_kind as event_id,h.method->>'$channel' as channel,
    h.time_created_utc,h.event_record_id,h.computer as hostname,h.evidence_role,h.note,h.domain_id,
    h.method#>>'{$principals,SubjectUserSid}' as subject_user_sid,h.method#>>'{$principals,SubjectUserName}' as subject_user_name,
    h.method#>>'{$principals,SubjectDomainName}' as subject_domain_name,
    coalesce(h.method#>>'{$principals,TargetSid}',h.method#>>'{$principals,TargetUserSid}') as target_user_sid,
    h.method#>>'{$principals,TargetUserName}' as target_user_name,
    coalesce(h.method#>>'{$principals,IpAddress}',h.method#>>'{$principals,ClientAddress}') as ip_address,
    coalesce(h.method#>>'{$principals,WorkstationName}',h.method#>>'{$principals,Workstation}') as workstation_name,
    h.method#>>'{$principals,TargetDomainName}' as target_domain_name,h.fields->>'MemberSid' as membership_member_sid,
    h.method->>'$provider' as identity_provider,h.fields->>'ServiceName' as service_name,
    (h.method->>'$server_id')::bigint as server_id
from public.finding_event_copies337 h;
revoke all on public.finding_event_details337 from public,adlog_user,adlog_semantic_worker;
grant select on public.finding_event_details337 to adlog_user;

-- A deterministic cursor identity replaces the normalizer-owned UUID. The
-- registry's existing temporal identity/label joins below remain unchanged.
create view public.short_account_candidates337 as
select h.event_id as source_event_id,h.event_kind as event_id,h.domain_id,h.time_created_utc as occurred_at_utc,
    h.time_created_utc as normalized_at,md5('sli.short-event.1:'||h.event_id::text||':'||encode(h.source_sha256,'hex'))::uuid as normalized_event_id,
    encode(h.source_sha256,'hex') as native_sha256,h.method->'$origin' as origin,
    roles.doc as roles_json,(select jsonb_build_object('identity_roles',coalesce(jsonb_object_agg(key,
        jsonb_build_object('key',value,'state',case when value like 'sid:%' then 'resolved' else 'provisional' end,
            'provisional',value not like 'sid:%')),'{}')) from jsonb_each_text(roles.doc)) as quality_json,
    jsonb_build_object('event_id',h.event_kind,'channel',h.method->>'$channel','provider_name',h.method->>'$provider',
        'event_data',(public.short_event_document337(h))->'fields') as item,
    case h.event_kind when 4624 then 'authentication.session.created' when 4625 then 'authentication.session.failed'
        when 4768 then 'authentication.kerberos.tgt.requested' when 4769 then 'authentication.kerberos.service_ticket.requested'
        when 4771 then 'authentication.kerberos.preauthentication.failed' when 4776 then 'authentication.credentials.validated'
        when 4648 then 'authentication.explicit_credentials.used' when 4672 then 'authentication.privileged_session.created'
        when 4740 then 'authentication.account.locked' when 4767 then 'authentication.account.unlocked'
        when 4770 then 'authentication.kerberos.service_ticket.renewed' when 4773 then 'authentication.kerberos.service_ticket.failed'
        when 4720 then 'directory.account.created' when 4722 then 'directory.account.enabled'
        when 4725 then 'directory.account.disabled' when 4726 then 'directory.account.deleted'
        when 4738 then 'directory.account.changed' when 4781 then 'directory.account.renamed'
        when 4723 then 'account.password.change.attempted' when 4724 then 'account.password.reset.attempted'
        when 4728 then 'group.member.added' when 4732 then 'group.member.added' when 4756 then 'group.member.added'
        when 4729 then 'group.member.removed' when 4733 then 'group.member.removed' when 4757 then 'group.member.removed' end as semantic_type
from public.event_hot h cross join lateral (select coalesce(h.method->'$principals','{}') as p) principal
cross join lateral (select jsonb_strip_nulls(jsonb_build_object(
    'actor',case when p->>'SubjectUserSid' ~ '^S-1-' then 'sid:'||(p->>'SubjectUserSid') end,
    'affected_entity',case when coalesce(p->>'TargetSid',p->>'TargetUserSid') ~ '^S-1-' then 'sid:'||coalesce(p->>'TargetSid',p->>'TargetUserSid')
        when h.event_kind=4625 and nullif(p->>'TargetUserName','-') is not null then 'sam:'||lower(p->>'TargetDomainName')||':'||lower(p->>'TargetUserName') end,
    'session_principal',case when h.event_kind=4624 and p->>'TargetUserSid' ~ '^S-1-' then 'sid:'||(p->>'TargetUserSid') end)) as doc) roles
where h.source_sha256 is not null;
revoke all on public.short_account_candidates337 from public,adlog_user,adlog_semantic_worker;

-- Save the exact installed definition, then preserve its signature, ACL and
-- existing validation. Only candidate/native storage changes in these bodies.
do $patch$
declare saved record; short_name text; short_definition text; original_name text; arguments text; scalar boolean;
    packet_start integer; packet_end integer; prefix text;
begin
    for saved in select * from public.detection_definitions337 where name in (
        'read_identity_attack_events_v301','read_default_password_events',
        'read_default_password_window_v2','read_password_retained_proof_v2',
        'password_v2_native_cost') loop
        original_name:=saved.name; short_name:=original_name||'_short337';
        short_definition:=replace(saved.definition,'FUNCTION public.'||original_name||'(', 'FUNCTION public.'||short_name||'(');
        short_definition:=replace(short_definition,'public.events_v2_core','public.detection_events337');
        short_definition:=replace(short_definition,'public.read_agent_semantic_source_v190','public.short_native_source337');
        -- The former per-read packet fence is now the importer-owned origin
        -- plus the fresh short_ref_allowed337 check. No packet is retained.
        loop
            packet_start:=strpos(short_definition,'select i.packet_id from public.raw_log_files raw');
            exit when packet_start=0;
            prefix:=regexp_replace(substr(short_definition,1,packet_start-1),'cross join lateral [(][[:space:]]*$','');
            packet_end:=strpos(substr(short_definition,packet_start),') inbox');
            if packet_end=0 then raise exception 'detection_short_events_337_packet_shape' using errcode='55000'; end if;
            short_definition:=prefix||substr(short_definition,packet_start+packet_end+length(') inbox')-1);
        end loop;
        short_definition:=replace(short_definition,'e.log_source_id=b.log_source_id','e.scope_json=s');
        short_definition:=replace(short_definition,'core.log_source_id=b.log_source_id','core.scope_json=s');
        if short_definition like '%public.raw_log_files%' or short_definition like '%public.sli_agent_packet_inbox%' then
            raise exception 'detection_short_events_337_native_shape' using errcode='55000'; end if;
        execute short_definition;
        execute format('revoke all on function %s from public,adlog_user,adlog_semantic_worker',replace(saved.signature,original_name,short_name));
        arguments:=case original_name when 'read_identity_attack_events_v301' then 's,p_refs'
            when 'read_password_retained_proof_v2' then 's,occurrences' when 'password_v2_native_cost' then 's,occurrences' else 's' end;
        scalar:=original_name='password_v2_native_cost';
        execute replace(saved.definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() then '||
            case when scalar then 'return public.'||short_name||'('||arguments||');'
            else 'return query select * from public.'||short_name||'('||arguments||'); return;' end||' end if;'||E'\n');
    end loop;
    select definition into strict short_definition from public.detection_definitions337 where name='default_detection_sources_before_v301';
    execute replace(short_definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() then return query select * from public.short_detection_sources337(); return; end if;\n');
    select definition into strict short_definition from public.detection_definitions337 where name='t109_detection_sources';
    execute replace(short_definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() then return query select * from public.short_detection_sources337(); return; end if;\n');
    select definition into strict short_definition from public.detection_definitions337 where name='read_t109_native';
    execute replace(short_definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() and s->>''plugin_id''=''sli.windows.ad-dc'' then return query select * from public.short_t109_events337(s,p_start,p_end); return; end if;\n');
    select definition into strict short_definition from public.detection_definitions337 where name='resolve_finding_evidence_ref';
    execute replace(short_definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() and p_kind=''core_event'' then return public.short_ref_allowed337(jsonb_build_object(''installation_id'',p_installation::text,''plugin_id'',p_plugin,''source_instance_id'',p_source,''source_generation'',p_generation,''collection_scope_id'',p_collection),p_native,p_sha256); end if;\n');
    select definition into strict short_definition from public.detection_definitions337 where name='link_finding_evidence_ref';
    -- Keep resolution, exact ref insertion and replay-conflict checks. The new
    -- branch replaces only the FK link to an expiring source event.
    execute replace(short_definition,'if p_kind=''core_event'' then',
        'if public.detections_use_short337() and p_kind=''core_event'' then
            v_added:=public.copy_finding_event337(p_finding,p_native,p_sha256,''semantic_scenario'',''enabled semantic scenario evidence'');
            -- S3 still dual-writes the old store. Mirror its link only while
            -- that exact old event exists, so the single legacy switch can
            -- also display problems created on the short path.
            insert into public.finding_evidence(finding_id,event_id,evidence_role,note)
            select p_finding,e.id,''semantic_scenario'',''enabled semantic scenario evidence'' from public.events_v2_core e
            where e.id=p_native::bigint and encode(e.normalized_hash,''hex'')=p_sha256
            on conflict(finding_id,event_id,evidence_role) do nothing;
            return v_added;
        end if;
        if p_kind=''core_event'' then');
    select definition into strict short_definition from public.detection_definitions337 where name='semantic_finding_in_domains_v265';
    execute replace(short_definition,
        'select e.domain_id from public.finding_evidence fe left join public.events_v2_core e on e.id=fe.event_id where fe.finding_id=p_finding',
        'select c.domain_id from public.finding_event_copies337 c where c.finding_id=p_finding and public.detections_use_short337()
         union all select e.domain_id from public.finding_evidence fe left join public.events_v2_core e on e.id=fe.event_id
            where fe.finding_id=p_finding and not public.detections_use_short337()');
    for saved in select * from public.detection_definitions337 where name in ('read_account_decoy_events','read_account_watch_events') loop
        original_name:=saved.name; short_name:=original_name||'_short337';
        short_definition:=replace(saved.definition,'FUNCTION public.'||original_name||'(', 'FUNCTION public.'||short_name||'(');
        short_definition:=regexp_replace(short_definition,'with source_candidates as (?:not )?materialized \(.*?\), events as materialized \(',
            'with source_candidates as materialized (
                select e.* from public.short_account_candidates337 e
                where e.origin-''agent_id''-''log_source_id''=jsonb_build_object(''installation_id'',p_installation::text,
                    ''plugin_id'',p_plugin,''source_instance_id'',p_source,''source_generation'',p_generation,''collection_scope_id'','''')
                  and e.origin->>''agent_id''=source_binding.agent_id::text and e.occurred_at_utc<=statement_timestamp()
                  and ((p_normalized is not null and e.normalized_event_id=p_normalized) or (p_normalized is null and not exists(
                      select 1 from public.semantic_account_'||case when original_name='read_account_watch_events' then 'watch' else 'decoy' end||'_checks c
                      where c.checkpoint_key=p_checkpoint and c.normalized_event_id=e.normalized_event_id)))
            ), events as materialized (','s');
        if original_name='read_account_watch_events' then
            short_definition:=replace(short_definition,$old$(select to_jsonb(core)||jsonb_build_object('channel',channel.value,'provider_name',provider.value)
         from public.events_v2_core core
         join public.storage_v2_channel channel on channel.id=core.channel_id
         join public.storage_v2_provider provider on provider.id=core.provider_id
         where core.id=e.source_event_id)$old$,'e.item');
        end if;
        if short_definition like '%public.normalized_events%' or short_definition like '%public.events_v2_core%' then
            raise exception 'detection_short_events_337_account_shape' using errcode='55000'; end if;
        execute short_definition;
        execute format('revoke all on function %s from public,adlog_user,adlog_semantic_worker',replace(saved.signature,original_name,short_name));
        execute replace(saved.definition,E'\nbegin\n',E'\nbegin\n    if public.detections_use_short337() then return query select * from public.'||short_name||E'(p_installation,p_plugin,p_source,p_generation,p_checkpoint,p_normalized); return; end if;\n');
    end loop;
end $patch$;

insert into public.schema_migrations(version,name) values(337,'detection_short_events');
reset role;
commit;
