-- WR04 publication through domain-bound, leased WR05 jobs. No table grants.
begin;
select pg_advisory_xact_lock(hashtext('workstation_inventory_job_v287'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=285 and name='report_producer')
       or not exists(select 1 from public.schema_migrations where version=286 and name='sigma_rule_labels')
       or exists(select 1 from public.schema_migrations where version>=287) then
        raise exception 'migration 287 prerequisites failed';
    end if;
end $$;

grant create on schema public to sli_job_owner;
set local role sli_job_owner;
create function public.core_workstation_inventory_binding_v1(s jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select coalesce(s->>'plugin_id'='sli.workstations' and s->>'plugin_version'='1.0.0'
      and s->>'handler_id'='workstations.overview-project' and s->>'handler_version'='1.0.0'
      and s->>'job_type'='reconcile' and s->>'resource_profile'='light'
      and s->>'rights_profile'='workstations-projection'
      and s->>'input_contract'='workstations.projection-input.v1'
      and s->>'result_contract'='sli.core-job-result.v1'
      and s->>'manifest_sha256'='2a198ad3cfc421c48610daa11cb7b7a49d1bd7c136e99316a354256dccb144cb'
      and s->'budget'->>'max_records'='100'
      and s->>'source_instance_id' ~ '^workstations:inventory:(0|[1-9][0-9]{0,17})$'
      and s->>'partition_key'=s->>'source_instance_id'
      and s->'access_scope'=jsonb_build_object('mode','restricted','clauses',jsonb_build_array(
          jsonb_build_object('source_instance_ids',jsonb_build_array(s->>'source_instance_id'),
          'collection_scope_ids',jsonb_build_array('ad-domain:'||split_part(s->>'source_instance_id',':',3)),
          'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
          'decision_id','core-workstation-inventory-v1','policy_revision','1')
      and exists(select 1 from public.plugin_installations_v1 i where i.plugin_id='sli.workstations'
        and i.package_lifecycle='registered' and i.package_version='1.0.0'
        and i.desired_activation='enabled_manual' and i.component_runtime='running'),false)
$$;
create or replace function public.core_workstation_job_binding_v1(p_spec jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select public.core_workstation_retention_binding_v192(p_spec)
      or public.core_workstation_projection_binding_v1(p_spec)
      or public.core_workstation_inventory_binding_v1(p_spec)
$$;
create function public.core_workstation_inventory_scope_v1(p_job uuid,p_token uuid,p_generation bigint) returns bigint
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare j sli_jobs.jobs%rowtype;
begin
    if session_user not in ('sli_job_executor_light','sli_job_publisher_light') then
        raise exception 'workstation_inventory_access_denied';
    end if;
    if session_user='sli_job_publisher_light' then
        select * into j from sli_jobs.jobs where job_id=p_job for update;
    else
        select * into j from sli_jobs.jobs where job_id=p_job;
    end if;
    if not found or j.state<>'leased' or j.lease_token is distinct from p_token
       or j.lease_generation<>p_generation or j.lease_until<=clock_timestamp() or j.deadline_at<=clock_timestamp()
       or j.plugin_id<>'sli.workstations' or j.resource_profile<>'light' or j.rights_profile<>'workstations-projection'
       or j.source_instance_id is distinct from j.spec->>'source_instance_id'
       or j.partition_key is distinct from j.spec->>'partition_key'
       or not public.core_workstation_inventory_binding_v1(j.spec) then
        raise exception 'workstation_inventory_access_denied';
    end if;
    return split_part(j.source_instance_id,':',3)::bigint;
end $$;
create function public.core_workstation_inventory_receipt_v1(p_job uuid,p_token uuid,p_generation bigint,
    p_source_sha text,p_ids jsonb,p_deferred jsonb,p_status text) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from sli_jobs.jobs j
        where session_user='sli_job_publisher_light' and j.job_id=p_job and j.state='completed'
          and j.lease_token=p_token and j.lease_generation=p_generation
          and public.core_workstation_inventory_binding_v1(j.spec)
          and j.result_sha256 ~ '^[0-9a-f]{64}$'
          and j.result_ref->>'result_sha256'=j.result_sha256
          and j.result_ref->>'job_id'=p_job::text and j.result_ref->>'lease_token'=p_token::text
          and j.result_ref->>'plugin_id'=j.plugin_id
          and j.result_ref->>'plugin_version'=j.spec->>'plugin_version'
          and j.result_ref->>'handler_id'=j.spec->>'handler_id'
          and j.result_ref->>'handler_version'=j.spec->>'handler_version'
          and j.result_ref->>'contract_id'='sli.core-job-result.v1'
          and j.result_ref->>'output_contract'='sli.core-job-result.v1'
          and j.result_ref->>'coverage_state'='not_proven'
          and j.result_payload->>'coverage_state'='not_proven'
          and (j.result_ref->>'lease_generation')::bigint=p_generation
          and j.result_ref->>'status'=p_status and j.result_payload->>'status'=p_status
          and j.result_payload->>'inventory_source_sha256'=p_source_sha
          and j.result_payload->'inventory_ids'=p_ids
          and j.result_payload->'inventory_deferred'=p_deferred
          and octet_length(j.result_payload::text)<=65536)
$$;
create function public.core_workstation_inventory_lease_v1(p_job uuid,p_token uuid,p_generation bigint) returns timestamptz
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare deadline timestamptz;
begin
    perform public.core_workstation_inventory_scope_v1(p_job,p_token,p_generation);
    select lease_until into deadline from sli_jobs.jobs where job_id=p_job;
    return deadline;
end $$;
revoke all on function public.core_workstation_inventory_binding_v1(jsonb),
    public.core_workstation_inventory_scope_v1(uuid,uuid,bigint),
    public.core_workstation_inventory_lease_v1(uuid,uuid,bigint),
    public.core_workstation_inventory_receipt_v1(uuid,uuid,bigint,text,jsonb,jsonb,text) from public;
reset role;
revoke create on schema public from sli_job_owner;

-- The non-login definer owns only this boundary. Workers gain EXECUTE only.
do $$ declare owner_id oid; storage_owner_id oid;
begin
    select oid into owner_id from pg_roles where rolname='sli_workstation_inventory_owner';
    select oid into storage_owner_id from pg_roles where rolname='adlog_storage_owner';
    if owner_id is not null then
        if exists(select 1 from pg_roles where rolname='sli_workstation_inventory_owner'
            and (rolcanlogin or rolinherit or rolsuper or rolcreatedb or rolcreaterole or rolbypassrls or rolreplication))
           or exists(select 1 from pg_auth_members m where m.member=owner_id
               or (m.roleid=owner_id and m.member<>storage_owner_id)) then
            raise exception 'workstation_inventory_owner_invalid';
        end if;
    else
        create role sli_workstation_inventory_owner nologin noinherit nosuperuser nocreatedb nocreaterole nobypassrls noreplication;
    end if;
end $$;
grant sli_workstation_inventory_owner to adlog_storage_owner;
grant usage,create on schema public,sli_plugin_workstations to sli_workstation_inventory_owner;
grant select(id,domain_id,display_name,entity_type_id) on public.entities_v2_active to sli_workstation_inventory_owner;
grant select(id,value) on public.storage_v2_entity_type to sli_workstation_inventory_owner;
grant select(id,entity_id,source_section,valid_to_utc,last_observed_at_utc,attributes_json)
    on public.ad_context_entity_versions to sli_workstation_inventory_owner;
grant select(id,host_id,assigned_modules) on public.sli_agents to sli_workstation_inventory_owner;
grant select(natural_key,plugin_id,source_instance_id,entity_type,resolution,entity_id,display_name)
    on public.core_entity_scope_resources to sli_workstation_inventory_owner;
grant select(relation,source_entity_id,target_entity_id) on public.core_entity_associations to sli_workstation_inventory_owner;
grant select,insert,update on sli_plugin_workstations.station_inventory to sli_workstation_inventory_owner;
grant execute on function public.core_workstation_inventory_scope_v1(uuid,uuid,bigint) to sli_workstation_inventory_owner;
grant execute on function public.core_workstation_inventory_lease_v1(uuid,uuid,bigint) to sli_workstation_inventory_owner;
grant execute on function public.core_workstation_inventory_receipt_v1(uuid,uuid,bigint,text,jsonb,jsonb,text)
    to sli_workstation_inventory_owner;
set local role sli_workstation_inventory_owner;
-- Exactly one bounded page per job, even for callers bypassing Python.
-- Constraint validation requires the final core receipt in the same transaction.
-- SET CONSTRAINTS can fire it early: the lease/deadline fence belongs to core
-- finish under the job lock, not the wall-clock time of an outer COMMIT.
-- Workers cannot write this table or satisfy the obligation with a caller GUC.
create table sli_plugin_workstations.inventory_publications (
    job_id uuid primary key,
    lease_token uuid not null,
    lease_generation bigint not null check(lease_generation>0),
    lease_until timestamptz not null,
    source_sha256 text not null check(source_sha256 ~ '^[0-9a-f]{64}$'),
    station_ids jsonb not null check(jsonb_typeof(station_ids)='array' and jsonb_array_length(station_ids)<=100),
    deferred jsonb not null check(jsonb_typeof(deferred)='array' and jsonb_array_length(deferred)<=100),
    status text not null check(status in ('success','partial')),
    transaction_id xid8 not null default pg_current_xact_id()
);
revoke all on sli_plugin_workstations.inventory_publications from public;
create function sli_plugin_workstations.inventory_require_receipt_v1() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    if new.transaction_id<>pg_current_xact_id()
       or not public.core_workstation_inventory_receipt_v1(new.job_id,new.lease_token,new.lease_generation,
           new.source_sha256,new.station_ids,new.deferred,new.status) then
        raise exception 'workstation_inventory_core_receipt_required';
    end if;
    return new;
end $$;
revoke all on function sli_plugin_workstations.inventory_require_receipt_v1() from public;
create constraint trigger inventory_core_receipt
    after insert on sli_plugin_workstations.inventory_publications
    deferrable initially deferred for each row execute function sli_plugin_workstations.inventory_require_receipt_v1();
create table sli_plugin_workstations.inventory_deferred (
    domain_id bigint not null check(domain_id>=0),
    station_id text not null check(length(station_id) between 1 and 256),
    reason text not null check(reason in ('identity_owner_conflict','source_identity_unavailable')),
    state text not null check(state in ('pending','resolved')),
    source_sha256 text not null check(source_sha256 ~ '^[0-9a-f]{64}$'),
    last_job_id uuid not null,
    attempts bigint not null default 1 check(attempts>0),
    first_deferred_at timestamptz not null default clock_timestamp(),
    last_attempt_at timestamptz not null default clock_timestamp(),
    next_retry_at timestamptz not null,
    primary key(domain_id,station_id)
);
create index inventory_deferred_retry on sli_plugin_workstations.inventory_deferred(domain_id,next_retry_at,station_id)
    where state='pending';
revoke all on sli_plugin_workstations.inventory_deferred from public;
create table sli_plugin_workstations.inventory_checkpoints (
    domain_id bigint primary key check(domain_id>=0),
    last_key text not null check(length(last_key)<=256),
    revision bigint not null default 1 check(revision>0),
    updated_at timestamptz not null default now()
);
revoke all on sli_plugin_workstations.inventory_checkpoints from public;
create function sli_plugin_workstations.inventory_inputs_v1(p_domain bigint) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,public as $$
declare result jsonb;
begin
    with directory as materialized (
        select e.id as ad_computer_id,e.domain_id,e.display_name,
               v.last_observed_at_utc as metadata_observed_at,
               case when v.id is not null then jsonb_build_object(
                   'organizational_unit',v.attributes_json->'attributes'->'organizational_unit',
                   'distinguished_name',v.attributes_json->'attributes'->'distinguished_name',
                   'operating_system',v.attributes_json->'attributes'->'operating_system',
                   'operating_system_version',v.attributes_json->'attributes'->'operating_system_version',
                   'ip_addresses',v.attributes_json->'attributes'->'ip_addresses') end as attributes
        from public.entities_v2_active e
        join public.storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
        left join public.ad_context_entity_versions v on v.entity_id=e.id
          and v.valid_to_utc is null and v.source_section='directory_accounts'
        order by e.id limit 10001
    ), registered as materialized (
        select a.id::text as agent_key,a.host_id::text as source_instance_id,
            'core:'||encode(sha256(convert_to('["device","sli.agent.key","agent-registry","'||a.id::text||'"]','UTF8')),'hex') as identity_key
        from public.sli_agents a where exists(select 1 from jsonb_array_elements(a.assigned_modules) m
            where m->>'module_id'='sli.workstations') order by a.id limit 10001
    ), devices as materialized (
        select distinct a.agent_key,a.source_instance_id,r.entity_id,r.display_name
        from registered a join public.core_entity_scope_resources r on r.natural_key=a.identity_key
            and r.plugin_id='sli.workstations' and r.source_instance_id=a.source_instance_id
            and r.entity_type='device' and r.resolution='resolved'
    ), links as materialized (
        select distinct c.source_entity_id,c.target_entity_id from public.core_entity_associations c
        where c.relation='directory_computer' and exists(select 1 from devices d where d.entity_id=c.source_entity_id)
    ), mapped as (
        select a.agent_key,a.source_instance_id,
            (select count(distinct d.entity_id) from devices d where d.agent_key=a.agent_key) as devices,
            (select min(d.entity_id) from devices d where d.agent_key=a.agent_key) as device_id
        from registered a
    ), candidates as (
        select m.*, (select count(*) from links l where l.source_entity_id=m.device_id) as targets,
            (select min(l.target_entity_id) from links l where l.source_entity_id=m.device_id) as target_id,
            (select count(distinct d.agent_key) from devices d where d.entity_id=m.device_id) as shared
        from mapped m
    ), resolved as (
        select c.*,d.ad_computer_id,d.domain_id,
            count(*) filter(where c.devices=1 and c.targets=1 and c.shared=1)
                over(partition by d.ad_computer_id) as target_agents
        from candidates c left join directory d on d.ad_computer_id=c.target_id
    ), classified as materialized (
        select r.*,case when devices=1 and targets=1 and shared=1 and target_agents=1
                 and ad_computer_id is not null and domain_id>0 then domain_id else 0 end as owned_domain,
            (devices>1 or targets>1 or shared>1 or (ad_computer_id is not null and target_agents>1)) as ambiguous
        from resolved r
    ), selected as materialized (select * from classified where owned_domain=p_domain),
    own_directory as (select * from directory where p_domain>0 and domain_id=p_domain),
    own_devices as (select d.* from devices d join selected s using(agent_key)
        where not s.ambiguous and s.devices=1),
    own_links as (select l.* from links l join selected s on s.device_id=l.source_entity_id
        where p_domain>0 and not s.ambiguous and s.owned_domain=p_domain),
    prior as (
        select station_id,entity_id,ad_computer_id,agent_key from sli_plugin_workstations.station_inventory i
        where (i.ad_computer_id is null or i.ad_computer_id in(select d.ad_computer_id from own_directory d))
          and (i.ad_computer_id in(select d.ad_computer_id from own_directory d)
           or i.agent_key in(select s.agent_key from selected s)
           or i.entity_id in(select d.entity_id from own_devices d))
    )
    select jsonb_build_object(
        'overflow',((select count(*) from directory)>10000 or (select count(*) from registered)>10000
            or (select count(*) from devices)>10000 or (select count(*) from links)>10000
            or (select count(*) from prior)>10000),
        'directory',coalesce((select jsonb_agg(to_jsonb(d) order by ad_computer_id) from own_directory d),'[]'),
        'agents',coalesce((select jsonb_agg(jsonb_build_object('agent_key',agent_key,
            'source_instance_id',source_instance_id) order by agent_key) from selected),'[]'),
        'devices',coalesce((select jsonb_agg(to_jsonb(d) order by agent_key,entity_id) from own_devices d),'[]'),
        'associations',coalesce((select jsonb_agg(to_jsonb(l) order by source_entity_id,target_entity_id) from own_links l),'[]'),
        'existing',coalesce((select jsonb_agg(to_jsonb(i) order by station_id) from prior i),'[]'),
        'ambiguous_agents',coalesce((select jsonb_agg(agent_key order by agent_key) from selected where ambiguous),'[]')
    ) into result;
    if (result->>'overflow')::boolean or octet_length(result::text)>16777216 then
        raise exception 'workstation_inventory_source_limit';
    end if;
    return result-'overflow';
end $$;
revoke all on function sli_plugin_workstations.inventory_inputs_v1(bigint) from public;

-- The database derives values, order and cursor. Caller hashes/field whitelists
-- alone do not authorize fabricated metadata or a caller-selected subset.
create function sli_plugin_workstations.inventory_text_v1(v jsonb) returns text
language sql immutable set search_path=pg_catalog,public as $$
    select case when jsonb_typeof(v)='string'
        then nullif(regexp_replace(v#>>'{}','^[[:space:]]+|[[:space:]]+$','','g'),'') end
$$;
create function sli_plugin_workstations.inventory_metadata_v1(attrs jsonb,label jsonb) returns jsonb
language plpgsql immutable set search_path=pg_catalog,public as $$
declare dn text; parent_dn text; part text:=''; parts text[]:='{}'; escaped boolean:=false;
    ch text; pos integer; ip jsonb; address text; normalized text; ips text[]:='{}';
    zone text; dotted text; parsed inet; hex text; hextets text[]; idx integer; start_idx integer;
    best_idx integer; best_size integer;
begin
    dn:=coalesce(sli_plugin_workstations.inventory_text_v1(attrs->'distinguished_name'),'');
    for pos in 1..length(dn) loop
        ch:=substr(dn,pos,1);
        if ch=',' and not escaped then
            parts:=array_append(parts,btrim(part)); part:='';
        else
            part:=part||ch;
            escaped:=ch=chr(92) and not escaped;
        end if;
    end loop;
    if part<>'' then parts:=array_append(parts,btrim(part)); end if;
    parent_dn:=nullif(array_to_string(parts[2:cardinality(parts)],','),'');
    for ip in select value from jsonb_array_elements(case when jsonb_typeof(attrs->'ip_addresses')='array'
        then attrs->'ip_addresses' else '[]'::jsonb end) loop
        if jsonb_typeof(ip)<>'string' then continue; end if;
        address:=ip#>>'{}';
        zone:=null;
        if strpos(address,'%')>0 then
            zone:=substr(address,strpos(address,'%')+1); address:=split_part(address,'%',1);
            if zone='' or strpos(zone,'%')>0 or strpos(zone,'/')>0 then continue; end if;
        end if;
        if address<>btrim(address) or strpos(address,'/')>0 then continue; end if;
        if strpos(address,'.')>0 then
            dotted:=reverse(split_part(reverse(address),':',1));
            if dotted !~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' or dotted ~ '(^|\.)0[0-9]' then continue; end if;
        elsif strpos(address,':')=0 then continue;
        end if;
        begin
            parsed:=address::inet;
            if zone is not null and family(parsed)<>6 then continue; end if;
            normalized:=host(parsed);
            if family(parsed)=6 then
                -- Match Python 3.14: longest first zero run, dotted mapped
                -- IPv4 tail, hex compatible tail, and preserved scope ID.
                hex:=right(encode(inet_send(parsed),'hex'),32); hextets:='{}';
                for idx in 1..8 loop
                    hextets:=array_append(hextets,coalesce(nullif(ltrim(substr(hex,(idx-1)*4+1,4),'0'),''),'0'));
                end loop;
                idx:=1; best_idx:=0; best_size:=1;
                while idx<=8 loop
                    if hextets[idx]<>'0' then idx:=idx+1; continue; end if;
                    start_idx:=idx;
                    while idx<=8 and hextets[idx]='0' loop idx:=idx+1; end loop;
                    if idx-start_idx>best_size then best_idx:=start_idx; best_size:=idx-start_idx; end if;
                end loop;
                normalized:=case when best_idx=0 then array_to_string(hextets,':') else
                    coalesce(array_to_string(hextets[1:best_idx-1],':'),'')||'::'||
                    coalesce(array_to_string(hextets[best_idx+best_size:8],':'),'') end;
                if left(hex,24)='00000000000000000000ffff' then normalized:=host(parsed); end if;
            end if;
            if zone is not null then normalized:=normalized||'%'||zone; end if;
            ips:=array_append(ips,normalized);
        exception when invalid_text_representation then continue;
        end;
    end loop;
    return jsonb_build_object('display_name',sli_plugin_workstations.inventory_text_v1(label),
        'ou_path',coalesce(sli_plugin_workstations.inventory_text_v1(attrs->'organizational_unit'),parent_dn),
        'operating_system',sli_plugin_workstations.inventory_text_v1(attrs->'operating_system'),
        'operating_system_version',sli_plugin_workstations.inventory_text_v1(attrs->'operating_system_version'),
        'ip_addresses',coalesce((select jsonb_agg(x order by x collate "C") from(select distinct unnest(ips) as x) q),'[]'));
end $$;
create function sli_plugin_workstations.inventory_page_v1(input jsonb) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,public as $$
declare source jsonb:=input->'sources'; candidate record; metadata jsonb;
    row_value jsonb; selected jsonb:='[]'; station text; pending_ids jsonb;
    previous_ad jsonb; previous_agent jsonb; previous_device jsonb;
    attempted jsonb:='[]'; deferred jsonb:='[]'; next_cursor text:='';
    observed jsonb; quality text; station_kind text; more boolean:=false; normal_more boolean:=false;
begin
    select coalesce(jsonb_object_agg(value->>'ad_computer_id',value)
               filter(where value->>'ad_computer_id' is not null),'{}'),
           coalesce(jsonb_object_agg(value->>'agent_key',value) filter(where value->>'agent_key' is not null),'{}'),
           coalesce(jsonb_object_agg(value->>'entity_id',value) filter(where value->>'entity_id' is not null),'{}')
        into previous_ad,previous_agent,previous_device from jsonb_array_elements(source->'existing');
    select coalesce(jsonb_object_agg(value->>'station_id',true),'{}') into pending_ids
        from jsonb_array_elements(input->'deferred');
    for candidate in
        with directory as(select value as computer from jsonb_array_elements(source->'directory')),
        agents as(select value->>'agent_key' as agent from jsonb_array_elements(source->'agents')),
        devices as(select value as device from jsonb_array_elements(source->'devices')),
        links as(select value as link from jsonb_array_elements(source->'associations')),
        paired as(select a.agent,d.device,c.computer
            from agents a join devices d on d.device->>'agent_key'=a.agent
            join links l on l.link->>'source_entity_id'=d.device->>'entity_id'
            join directory c on c.computer->>'ad_computer_id'=l.link->>'target_entity_id'),
        candidates as(
            select c.computer,p.agent,p.device from directory c left join paired p on p.computer=c.computer
            union all
            select null::jsonb,a.agent,d.device from agents a left join devices d on d.device->>'agent_key'=a.agent
            where not exists(select 1 from paired p where p.agent=a.agent)),
        prior as(select c.*,previous_ad->(c.computer->>'ad_computer_id') as saved_ad,
                coalesce(previous_agent->c.agent,previous_device->(c.device->>'entity_id')) as fallback
            from candidates c),
        identified as(select c.*,coalesce((case when saved_ad is not null then saved_ad
                when fallback->>'ad_computer_id' is null or fallback->>'ad_computer_id'=computer->>'ad_computer_id'
                    then fallback end)->>'station_id',case when c.computer is not null
                then 'ws:ad:'||(c.computer->>'ad_computer_id') else 'ws:agent:'||c.agent end) as canonical_station
            from prior c),
        normal as(select i.*,row_number() over(order by canonical_station collate "C") as position
            from identified i where canonical_station collate "C">(input->>'cursor') collate "C"
              and not (pending_ids ? canonical_station)
            order by canonical_station collate "C" limit 81),
        retries as(select value->>'station_id' as station_id,ordinality::bigint as position
            from jsonb_array_elements(input->'deferred') with ordinality
            where (value->>'due')::boolean order by ordinality limit 20),
        picked as(select computer,agent,device,canonical_station,position,'normal' as lane,false as missing from normal
            union all select i.computer,i.agent,i.device,q.station_id,q.position,'retry',i.canonical_station is null
            from retries q left join identified i on i.canonical_station=q.station_id)
        select * from picked order by lane,position
    loop
        if candidate.lane='normal' and candidate.position=81 then normal_more:=true; continue; end if;
        station:=candidate.canonical_station;
        if candidate.lane='normal' then next_cursor:=station; end if;
        attempted:=attempted||jsonb_build_array(station);
        if candidate.missing then
            deferred:=deferred||jsonb_build_array(jsonb_build_object('station_id',station,'reason','source_identity_unavailable'));
            continue;
        end if;
        metadata:=sli_plugin_workstations.inventory_metadata_v1(candidate.computer->'attributes',
            case when candidate.computer is not null then candidate.computer->'display_name'
                 else candidate.device->'display_name' end);
        observed:=candidate.computer->'metadata_observed_at';
        quality:=case when observed is null or observed='null'::jsonb then 'not_collected'
            when metadata->>'ou_path' is null or metadata->>'operating_system' is null
              or metadata->'ip_addresses'='[]'::jsonb then 'partial' else 'complete' end;
        station_kind:=case when metadata->>'operating_system' is null
              or lower(metadata->>'operating_system') in ('unknown','неизвестно') then 'unknown'
            when strpos(lower(metadata->>'operating_system'),'server')>0 then 'server' else 'workstation' end;
        row_value:=jsonb_build_object('station_id',station,'entity_id',candidate.device->'entity_id',
            'ad_computer_id',candidate.computer->'ad_computer_id','agent_key',candidate.agent,
            'domain_id',candidate.computer->'domain_id','ou_entity_id',null,'station_type',station_kind,
            'association_status',case when candidate.agent is not null and candidate.computer is not null
                then 'unique' else 'unlinked' end,'metadata',metadata,'metadata_observed_at',observed,
            'quality',jsonb_build_object('status',quality,'reasons','[]'::jsonb));
        if (source->'ambiguous_agents') ? candidate.agent then
            row_value:=row_value||jsonb_build_object('entity_id',null,'association_status','ambiguous',
                'station_type','unknown','quality',jsonb_build_object('status','partial','reasons','[]'::jsonb));
        end if;
        if exists(select 1 from sli_plugin_workstations.station_inventory i where i.station_id<>station
            and (i.ad_computer_id=(row_value->>'ad_computer_id')::bigint
              or i.entity_id=(row_value->>'entity_id')::bigint or i.agent_key=row_value->>'agent_key')) then
            deferred:=deferred||jsonb_build_array(jsonb_build_object('station_id',station,'reason','identity_owner_conflict'));
        end if;
        selected:=selected||jsonb_build_array(row_value);
    end loop;
    select coalesce(jsonb_agg(value order by value->>'station_id' collate "C"),'[]') into selected
        from jsonb_array_elements(selected);
    select coalesce(jsonb_agg(value order by value collate "C"),'[]') into attempted
        from jsonb_array_elements_text(attempted);
    select coalesce(jsonb_agg(value order by value->>'station_id' collate "C"),'[]') into deferred
        from jsonb_array_elements(deferred);
    more:=normal_more or jsonb_array_length(deferred)>0 or exists(select 1 from jsonb_array_elements(input->'deferred') q
        where not (attempted ? (q->>'station_id')));
    return jsonb_build_object('rows',selected,'attempted_ids',attempted,'deferred',deferred,'more',more,
        'next_cursor',case when normal_more then next_cursor else '' end);
end $$;
revoke all on function sli_plugin_workstations.inventory_text_v1(jsonb),
    sli_plugin_workstations.inventory_metadata_v1(jsonb,jsonb),
    sli_plugin_workstations.inventory_page_v1(jsonb) from public;

create function public.read_workstation_inventory_input_v1(p_job uuid,p_token uuid,p_generation bigint) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare scope bigint; input jsonb; cursor_value text; pending jsonb;
begin
    scope:=public.core_workstation_inventory_scope_v1(p_job,p_token,p_generation);
    input:=sli_plugin_workstations.inventory_inputs_v1(scope);
    select last_key into cursor_value from sli_plugin_workstations.inventory_checkpoints where domain_id=scope;
    select coalesce(jsonb_agg(jsonb_build_object('station_id',station_id,'reason',reason,
        'due',next_retry_at<=transaction_timestamp()) order by next_retry_at,station_id),'[]') into pending
        from (select * from sli_plugin_workstations.inventory_deferred where domain_id=scope and state='pending'
            order by next_retry_at,station_id limit 10001) q;
    if jsonb_array_length(pending)>10000 then raise exception 'workstation_inventory_deferred_limit'; end if;
    input:=jsonb_build_object('sources',input,'cursor',coalesce(cursor_value,''),'deferred',pending);
    input:=input||jsonb_build_object('page',sli_plugin_workstations.inventory_page_v1(input));
    return input||jsonb_build_object('source_sha256',encode(sha256(convert_to(input::text,'UTF8')),'hex'));
end $$;
revoke all on function public.read_workstation_inventory_input_v1(uuid,uuid,bigint) from public;
grant execute on function public.read_workstation_inventory_input_v1(uuid,uuid,bigint)
    to sli_job_executor_light,sli_job_publisher_light;

create function public.read_workstation_inventory_job_sources_v1() returns setof jsonb
language plpgsql stable security definer set search_path=pg_catalog,public as $$
declare d bigint; domains bigint[]; source text;
begin
    if session_user<>'sli_job_dispatcher_light' then raise exception 'workstation_inventory_access_denied'; end if;
    select array_agg(domain_id order by domain_id) into domains from (
        select distinct e.domain_id from public.entities_v2_active e
        join public.storage_v2_entity_type t on t.id=e.entity_type_id and t.value='ad_computer'
        where e.domain_id>0
        union select domain_id from sli_plugin_workstations.inventory_deferred where domain_id>0 and state='pending'
        order by domain_id limit 100) q;
    if cardinality(domains)>99 then raise exception 'workstation_inventory_source_limit'; end if;
    foreach d in array array_prepend(0::bigint,coalesce(domains,'{}'::bigint[])) loop
        source:='workstations:inventory:'||d::text;
        return next jsonb_build_object('plugin_id','sli.workstations','source_instance_id',source,'revision','1',
            'access_scope',jsonb_build_object('mode','restricted','clauses',jsonb_build_array(jsonb_build_object(
                'source_instance_ids',jsonb_build_array(source),'collection_scope_ids',jsonb_build_array('ad-domain:'||d::text),
                'device_ids','[]'::jsonb,'entity_ids','[]'::jsonb)),
                'decision_id','core-workstation-inventory-v1','policy_revision','1'));
    end loop;
end $$;
revoke all on function public.read_workstation_inventory_job_sources_v1() from public;
grant execute on function public.read_workstation_inventory_job_sources_v1() to sli_job_dispatcher_light;

create function public.publish_workstation_inventory_v1(p_job uuid,p_token uuid,p_generation bigint,
    p_source_sha text,p_rows jsonb,p_cursor text) returns integer
language plpgsql volatile security definer set search_path=pg_catalog,public as $$
declare scope bigint; snapshot jsonb; expected jsonb; item jsonb; r sli_plugin_workstations.station_inventory%rowtype;
    affected integer:=0; changed integer;
begin
    if session_user<>'sli_job_publisher_light' then raise exception 'workstation_inventory_access_denied'; end if;
    scope:=public.core_workstation_inventory_scope_v1(p_job,p_token,p_generation);
    if exists(select 1 from sli_plugin_workstations.inventory_publications where job_id=p_job) then
        raise exception 'workstation_inventory_page_already_published';
    end if;
    perform pg_advisory_xact_lock(hashtext('workstations.inventory-publication'));
    snapshot:=public.read_workstation_inventory_input_v1(p_job,p_token,p_generation);
    if p_source_sha is distinct from snapshot->>'source_sha256' then
        raise exception 'workstation_inventory_input_changed';
    end if;
    expected:=snapshot->'page';
    if p_rows is distinct from expected->'rows' or p_cursor is distinct from expected->>'next_cursor' then
        raise exception 'workstation_inventory_canonical_page_required';
    end if;
    if p_rows is null or jsonb_typeof(p_rows)<>'array' or jsonb_array_length(p_rows)>100
       or octet_length(p_rows::text)>3276800 or p_cursor is null or length(p_cursor)>256 then
        raise exception 'workstation_inventory_input_invalid';
    end if;
    -- Validate the complete page before any DML. The caller cannot substitute
    -- another domain, agent, explicit device association, or persisted ID.
    for item in select value from jsonb_array_elements(p_rows) loop
        if jsonb_typeof(item)<>'object' or item-array['station_id','entity_id','ad_computer_id','agent_key',
            'domain_id','ou_entity_id','station_type','association_status','metadata','metadata_observed_at','quality']<>'{}'
           or not item ?& array['station_id','entity_id','ad_computer_id','agent_key','domain_id','ou_entity_id',
               'station_type','association_status','metadata','metadata_observed_at','quality'] then
            raise exception 'workstation_inventory_input_invalid';
        end if;
        r:=jsonb_populate_record(null::sli_plugin_workstations.station_inventory,item);
        if jsonb_typeof(r.metadata)<>'object' or r.metadata-array['display_name','ou_path','operating_system',
            'operating_system_version','ip_addresses']<>'{}' or jsonb_typeof(r.quality)<>'object'
           or r.quality-array['status','reasons']<>'{}' or r.quality->'reasons'<>'[]' then
            raise exception 'workstation_inventory_input_invalid';
        end if;
        if r.domain_id is distinct from nullif(scope,0) or r.ou_entity_id is not null
           or r.station_id is null
           or (scope>0 and (r.ad_computer_id is null or not exists(select 1 from
               jsonb_array_elements(snapshot->'sources'->'directory') d
               where (d->>'ad_computer_id')::bigint=r.ad_computer_id)))
           or (scope=0 and (r.ad_computer_id is not null or r.agent_key is null))
           or (r.agent_key is not null and not exists(select 1 from
               jsonb_array_elements(snapshot->'sources'->'agents') a where a->>'agent_key'=r.agent_key))
           or (r.entity_id is not null and (r.agent_key is null or not exists(select 1 from
               jsonb_array_elements(snapshot->'sources'->'devices') d
               where d->>'agent_key'=r.agent_key and (d->>'entity_id')::bigint=r.entity_id)))
           or (scope>0 and r.agent_key is not null and not exists(select 1 from
               jsonb_array_elements(snapshot->'sources'->'devices') d
               join jsonb_array_elements(snapshot->'sources'->'associations') a
                 on a->>'source_entity_id'=d->>'entity_id'
               where d->>'agent_key'=r.agent_key and (a->>'target_entity_id')::bigint=r.ad_computer_id)) then
            raise exception 'workstation_inventory_scope_denied';
        end if;
        if r.station_id not in (case when r.ad_computer_id is not null then 'ws:ad:'||r.ad_computer_id::text
                                    else 'ws:agent:'||r.agent_key end,
                                (case when r.ad_computer_id is not null then 'ws:ad:'||r.ad_computer_id::text
                                    else 'ws:agent:'||r.agent_key end)||':unlinked')
           and not exists(select 1 from jsonb_array_elements(snapshot->'sources'->'existing') e
               where e->>'station_id'=r.station_id
                 and (e->>'ad_computer_id' is null or (e->>'ad_computer_id')::bigint=r.ad_computer_id)
                 and ((e->>'ad_computer_id')::bigint=r.ad_computer_id or e->>'agent_key'=r.agent_key
                     or (e->>'entity_id')::bigint=r.entity_id)) then
            raise exception 'workstation_inventory_identity_conflict';
        end if;
        if scope=0 and (r.metadata_observed_at is not null or r.station_type<>'unknown'
            or r.metadata->>'ou_path' is not null or r.metadata->>'operating_system' is not null
            or r.metadata->>'operating_system_version' is not null or r.metadata->'ip_addresses'<>'[]'
            or r.quality->>'status' not in ('not_collected','partial')) then
            raise exception 'workstation_inventory_input_invalid';
        end if;
        if scope>0 and r.metadata_observed_at is distinct from (select (d->>'metadata_observed_at')::timestamptz
            from jsonb_array_elements(snapshot->'sources'->'directory') d
            where (d->>'ad_computer_id')::bigint=r.ad_computer_id) then
            raise exception 'workstation_inventory_input_changed';
        end if;
    end loop;
    if (select count(distinct value->>'station_id') from jsonb_array_elements(p_rows))<>jsonb_array_length(p_rows)
       or jsonb_array_length(expected->'attempted_ids')>100 then
        raise exception 'workstation_inventory_input_invalid';
    end if;
    for item in select value from jsonb_array_elements(p_rows) loop
        r:=jsonb_populate_record(null::sli_plugin_workstations.station_inventory,item);
        if exists(select 1 from jsonb_array_elements(expected->'deferred') d where d->>'station_id'=r.station_id) then
            continue;
        end if;
        insert into sli_plugin_workstations.station_inventory as i
            (station_id,entity_id,ad_computer_id,agent_key,domain_id,ou_entity_id,station_type,
             association_status,metadata,metadata_observed_at,quality)
        values(r.station_id,r.entity_id,r.ad_computer_id,r.agent_key,r.domain_id,r.ou_entity_id,r.station_type,
               r.association_status,r.metadata,r.metadata_observed_at,r.quality)
        on conflict(station_id) do update set entity_id=excluded.entity_id,ad_computer_id=excluded.ad_computer_id,
            agent_key=excluded.agent_key,domain_id=excluded.domain_id,ou_entity_id=excluded.ou_entity_id,
            station_type=excluded.station_type,association_status=excluded.association_status,
            metadata=excluded.metadata,metadata_observed_at=excluded.metadata_observed_at,
            quality=excluded.quality,revision=i.revision+1,updated_at=clock_timestamp()
        where (i.entity_id,i.ad_computer_id,i.agent_key,i.domain_id,i.ou_entity_id,i.station_type,
               i.association_status,i.metadata,i.metadata_observed_at,i.quality) is distinct from
              (excluded.entity_id,excluded.ad_computer_id,excluded.agent_key,excluded.domain_id,excluded.ou_entity_id,
               excluded.station_type,excluded.association_status,excluded.metadata,excluded.metadata_observed_at,excluded.quality);
        get diagnostics changed=row_count;
        affected:=affected+changed;
        update sli_plugin_workstations.inventory_deferred set state='resolved',last_job_id=p_job,
            last_attempt_at=clock_timestamp(),attempts=attempts+1,source_sha256=p_source_sha
        where domain_id=scope and station_id=r.station_id and state='pending';
    end loop;
    for item in select value from jsonb_array_elements(expected->'deferred') loop
        if (select count(*) from sli_plugin_workstations.inventory_deferred where state='pending')>=10000
           and not exists(select 1 from sli_plugin_workstations.inventory_deferred
               where domain_id=scope and station_id=item->>'station_id' and state='pending') then
            raise exception 'workstation_inventory_deferred_limit';
        end if;
        insert into sli_plugin_workstations.inventory_deferred as d
            (domain_id,station_id,reason,state,source_sha256,last_job_id,next_retry_at)
        values(scope,item->>'station_id',item->>'reason','pending',p_source_sha,p_job,clock_timestamp()+interval '5 minutes')
        on conflict(domain_id,station_id) do update set reason=excluded.reason,state='pending',
            source_sha256=excluded.source_sha256,last_job_id=p_job,attempts=d.attempts+1,
            last_attempt_at=clock_timestamp(),next_retry_at=excluded.next_retry_at;
    end loop;
    insert into sli_plugin_workstations.inventory_checkpoints as c(domain_id,last_key)
    values(scope,p_cursor)
    on conflict(domain_id) do update set last_key=excluded.last_key,
        revision=c.revision+1,updated_at=clock_timestamp()
    where c.last_key is distinct from excluded.last_key;
    insert into sli_plugin_workstations.inventory_publications
        (job_id,lease_token,lease_generation,lease_until,source_sha256,station_ids,deferred,status)
    values(p_job,p_token,p_generation,public.core_workstation_inventory_lease_v1(p_job,p_token,p_generation),
           p_source_sha,expected->'attempted_ids',expected->'deferred',
           case when (expected->>'more')::boolean then 'partial' else 'success' end);
    perform public.core_workstation_inventory_scope_v1(p_job,p_token,p_generation);
    return affected;
end $$;
revoke all on function public.publish_workstation_inventory_v1(uuid,uuid,bigint,text,jsonb,text) from public;
grant execute on function public.publish_workstation_inventory_v1(uuid,uuid,bigint,text,jsonb,text)
    to sli_job_publisher_light;
reset role;
revoke create on schema public,sli_plugin_workstations from sli_workstation_inventory_owner;
insert into public.schema_migrations(version,name) values(287,'workstation_inventory_job');
commit;
