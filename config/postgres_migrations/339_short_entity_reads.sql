-- Entity lookups use compact native identities, never the old link blocks.
begin;
select pg_advisory_xact_lock(hashtext('sli_short_entity_reads_v339'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=337 and name='detection_short_events')
       or exists(select 1 from public.schema_migrations where version>=339) then
        raise exception 'short_entity_reads_339_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- The same SID / domain-SAM / unscoped-name ladder as native admission.
-- Built-in SIDs belong to their recorder, not every computer in a domain.
create function public.short_entity_principal339(sid text,account text,domain_name text,computer text)
returns text language sql immutable set search_path=pg_catalog,pg_temp as $$
    select lower(case
        when nullif(btrim(sid),'-') ~ '^S-1-[0-9]+(-[0-9]+)*$' then
            case when sid ~ '^S-1-5-(18|19|20)$|^S-1-5-32-[0-9]+$'
                then 'sid:'||split_part(computer,'.',1)||':'||sid else 'sid:'||sid end
        when nullif(btrim(account),'-') is null or lower(btrim(account))='anonymous logon' then null
        when account like 'S-1-%' then 'sid:'||account
        when position(E'\\' in account)>0 then 'sam:'||split_part(split_part(account,E'\\',1),'.',1)||':'||split_part(account,E'\\',2)
        when nullif(btrim(domain_name),'-') is not null then 'sam:'||split_part(domain_name,'.',1)||':'||
            case when account like '%=%' and account like '%,%' then split_part(split_part(account,',',1),'=',2) else account end
        else 'name:'||account end)
$$;

create function public.short_event_entity_links339(kind integer,actor text,target text,source text,computer text,method jsonb,fields jsonb)
returns table(natural_key text,link_role text) language sql immutable set search_path=pg_catalog,pg_temp as $$
    select distinct k,r from (values
        (public.short_entity_principal339(method#>>'{$principals,SubjectUserSid}',
            method#>>'{$principals,SubjectUserName}',method#>>'{$principals,SubjectDomainName}',computer),'actor'),
        (public.short_entity_principal339(coalesce(method#>>'{$principals,TargetUserSid}',method#>>'{$principals,TargetSid}'),
            method#>>'{$principals,TargetUserName}',method#>>'{$principals,TargetDomainName}',computer),
            case when kind in (4727,4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758) then 'affected' else 'target' end),
        (public.short_entity_principal339(fields->>'MemberSid',coalesce(fields->>'MemberName',fields->>'MemberSid'),
            coalesce(method#>>'{$principals,TargetDomainName}',method#>>'{$principals,SubjectDomainName}'),computer),'affected'),
        -- Compact rows written before native principals were retained.
        (case when not method ? '$principals' then public.short_entity_principal339(null,actor,null,computer) end,
            case when kind in (4624,4625,4771,4776) then 'target' else 'actor' end),
        (case when not method ? '$principals' then public.short_entity_principal339(null,target,null,computer) end,'target'),
        ('server:'||lower(computer),'recorder'),
        (coalesce(method->>'$target_server',case when kind in (4648,4769)
            then 'server:'||lower(coalesce(fields->>'TargetServerName',fields->>'ServiceName',case when kind=4769 then target end)) end),'target'),
        ('log:'||lower(method->>'$channel'),'context'),
        ('provider:'||lower(method->>'$provider'),'context'),
        (case when coalesce(method#>>'{$principals,WorkstationName}',method#>>'{$principals,Workstation}') not in ('','-')
            then 'workstation:'||lower(coalesce(method#>>'{$principals,WorkstationName}',method#>>'{$principals,Workstation}')) end,'source'),
        (case when source not in ('','-','::1','127.0.0.1') and source ~ '^[0-9a-fA-F:.]+$' then 'ip:'||source end,'source')
    ) links(k,r) where k is not null
$$;
create function public.short_event_entity_keys339(kind integer,actor text,target text,source text,computer text,method jsonb,fields jsonb)
returns text[] language sql immutable set search_path=pg_catalog,pg_temp as $$
    select coalesce(array_agg(distinct natural_key order by natural_key),array[]::text[])
    from public.short_event_entity_links339(kind,actor,target,source,computer,method,fields)
$$;

-- Resolve once per query. Alias metadata stays behind a read-only definer,
-- just as security_candidate_sid_matches_v307 does; event data does not.
create function public.entity_event_keys339(p_entity integer)
returns table(domain_id bigint,server_id bigint,natural_keys text[])
language sql stable strict security definer set search_path=pg_catalog,pg_temp as $$
    with canonical as (
        select e.* from public.entities_v2 e
        where e.id=public.resolve_entity_identity_v2(p_entity) and public.entity_v2_is_active(e.id)
    ), identities as (
        select c.id,c.natural_key from canonical c
        union all select m.source_entity_id,m.source_natural_key from public.entity_identity_merges_v2 m join canonical c on c.id=m.target_entity_id
    ), keys as (
        select lower(i.natural_key) as key from identities i
        union select lower(a.value) from identities i join public.entity_details_v2 d on d.entity_id=i.id
            cross join lateral jsonb_array_elements_text(case when jsonb_typeof(d.attributes_json->'identity_aliases')='array'
                then d.attributes_json->'identity_aliases' else '[]'::jsonb end) a(value)
        union select 'sid:'||lower(a.normalized_value) from public.ad_context_entity_aliases a join canonical c on c.id=a.entity_id
            where a.domain_id=c.domain_id and a.alias_type='object_sid' and a.normalized_value like 's-1-%'
    ) select c.domain_id,c.server_id,array(select key from keys where key is not null and key<>'' order by key) from canonical c
$$;
revoke all on function public.short_entity_principal339(text,text,text,text),
    public.short_event_entity_links339(integer,text,text,text,text,jsonb,jsonb),
    public.short_event_entity_keys339(integer,text,text,text,text,jsonb,jsonb),public.entity_event_keys339(integer) from public;
grant execute on function public.short_entity_principal339(text,text,text,text),
    public.short_event_entity_links339(integer,text,text,text,text,jsonb,jsonb),
    public.short_event_entity_keys339(integer,text,text,text,text,jsonb,jsonb) to adlog_user,adlog_storage_worker;
grant execute on function public.entity_event_keys339(integer) to adlog_user;

-- CREATE INDEX on each partitioned parent builds existing child indexes.
-- create_event_storage_partitions uses CREATE TABLE ... PARTITION OF, which
-- inherits these indexes for every future day/month without changing the function.
create index event_hot_entity339 on public.event_hot using gin
    (public.short_event_entity_keys339(event_kind,actor,target,source,computer,method,fields));
create index event_cold_facts_entity339 on public.event_cold_facts using gin
    (public.short_event_entity_keys339(event_kind,actor,target,source,computer,method,fields));
create index event_cold_daily_entity339 on public.event_cold_daily using gin
    (public.short_event_entity_keys339(event_kind,actor,target,source,computer,method,'{}'::jsonb));
insert into public.schema_migrations(version,name) values(339,'short_entity_reads');
reset role;
commit;
