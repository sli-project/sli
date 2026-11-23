begin;
select pg_advisory_xact_lock(hashtext('sli_password_queue_projection399'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=398 and name='password_proof_budget_progress')
       or exists(select 1 from public.schema_migrations where version>=399) then
        raise exception 'password_queue_projection399_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;
create index finding_event_copy_scope399 on public.finding_event_copies337(finding_id,domain_id);

create table public.password_queue_scope_restore399(definition text not null, owner_oid oid not null, acl aclitem[],
    security_definer boolean not null, settings text[], installed_definition text);
revoke all on public.password_queue_scope_restore399 from public;
insert into public.password_queue_scope_restore399(definition,owner_oid,acl,security_definer,settings)
select pg_get_functiondef(oid),proowner,proacl,prosecdef,proconfig from pg_proc
where oid='public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure;

-- Native retained copies have a non-null domain. With no external references,
-- one requested domain permits a finding exactly when copies exist and none are outside it.
do $$ declare installed text; rewritten text; begin
    select definition into strict installed from public.password_queue_scope_restore399;
    installed:=replace(installed,chr(13),'');
    rewritten:=replace(installed,$marker$begin
    with native_domains as materialized ($marker$,$branch$begin
    if cardinality(p_domains)=1 and array_lower(p_domains,1)=1 and p_domains[1] is not null
       and not exists(select 1 from public.finding_evidence_refs
           where finding_id=p_finding and storage_kind is distinct from 'core_event') then
        return exists(select 1 from public.finding_event_copies337 where finding_id=p_finding)
            and not exists(select 1 from public.finding_event_copies337 where finding_id=p_finding and domain_id<p_domains[1])
            and not exists(select 1 from public.finding_event_copies337 where finding_id=p_finding and domain_id>p_domains[1]);
    end if;
    with native_domains as materialized ($branch$);
    if rewritten=installed then raise exception 'password_queue_projection399_scope_shape'; end if;
    execute rewritten;
    if exists(select 1 from pg_proc p cross join public.password_queue_scope_restore399 old
        where p.oid='public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure
          and (p.proowner is distinct from old.owner_oid or p.proacl is distinct from old.acl
              or p.prosecdef is distinct from old.security_definer or p.proconfig is distinct from old.settings)) then
        raise exception 'password_queue_projection399_scope_grants';
    end if;
end $$;
update public.password_queue_scope_restore399
set installed_definition=pg_get_functiondef('public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure);

create table public.password_queue_context399(
    domain_id bigint primary key,
    revision uuid not null,
    changed_xid xid8 not null,
    changed_at timestamptz not null
);
create table public.password_queue_evidence_versions399(
    finding_id bigint primary key references public.findings(id) on delete cascade,
    revision uuid not null,
    changed_xid xid8 not null,
    changed_at timestamptz not null
);
create table public.password_queue_source_resets399(relation_name name primary key,revision uuid not null);
create table public.password_queue_projection399(
    finding_id bigint primary key references public.findings(id) on delete cascade,
    rule_code text not null,
    valid boolean not null default false,
    evidence_revision uuid,
    source_resets uuid[] not null,
    context_versions jsonb not null default '{}'::jsonb,
    attempted_at timestamptz,
    facts jsonb,
    aliases jsonb
);
revoke all on public.password_queue_context399,public.password_queue_projection399,
    public.password_queue_evidence_versions399,public.password_queue_source_resets399 from public;

create function public.invalidate_password_queue_evidence399() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare changes text;
begin
    changes:=case tg_op
        when 'INSERT' then 'select finding_id,event_kind from new_copies'
        when 'DELETE' then 'select finding_id,event_kind from old_copies'
        when 'UPDATE' then 'select finding_id,event_kind from old_copies union all select finding_id,event_kind from new_copies' end;
    execute format($sql$
        insert into public.password_queue_evidence_versions399(finding_id,revision,changed_xid,changed_at)
        select id,gen_random_uuid(),pg_current_xact_id(),statement_timestamp() from public.findings where id in (
            select distinct finding_id from (%s) changes where event_kind in (4624,4625,4771,4776))
        and rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray') order by id
        on conflict(finding_id) do update set revision=excluded.revision,changed_xid=excluded.changed_xid,changed_at=excluded.changed_at
        where password_queue_evidence_versions399.changed_xid<>excluded.changed_xid
           or password_queue_evidence_versions399.changed_at<>excluded.changed_at$sql$,changes);
    return null;
end $$;
revoke all on function public.invalidate_password_queue_evidence399() from public;

-- TRUNCATE already holds the source relation. It must never wait on a cache row.
-- Independent source resets use distinct rows to preserve their lock order.
create function public.record_password_queue_source_reset399() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    insert into public.password_queue_source_resets399(relation_name,revision) values(tg_table_name,gen_random_uuid())
    on conflict(relation_name) do update set revision=excluded.revision;
    return null;
end $$;
revoke all on function public.record_password_queue_source_reset399() from public;

create function public.invalidate_password_queue_context399() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare old_domain bigint; new_domain bigint;
begin
    if tg_op<>'INSERT' then
        if tg_table_name='domains' then old_domain:=old.id;
        elsif tg_table_name in ('ad_context_runs','ad_context_entity_aliases') then old_domain:=old.domain_id;
        elsif tg_table_name='ad_context_entity_versions' then
            if old.source_section='directory_accounts' then
                select domain_id into old_domain from public.ad_context_runs where run_id=old.source_run_id;
            end if;
        elsif tg_table_name='ad_context_sections' then
            if old.section_name='directory_accounts' then
                select domain_id into old_domain from public.ad_context_runs where run_id=old.run_id;
            end if;
        end if;
    end if;
    if tg_op<>'DELETE' then
        if tg_table_name='domains' then new_domain:=new.id;
        elsif tg_table_name in ('ad_context_runs','ad_context_entity_aliases') then new_domain:=new.domain_id;
        elsif tg_table_name='ad_context_entity_versions' then
            if new.source_section='directory_accounts' then
                select domain_id into new_domain from public.ad_context_runs where run_id=new.source_run_id;
            end if;
        elsif tg_table_name='ad_context_sections' then
            if new.section_name='directory_accounts' then
                select domain_id into new_domain from public.ad_context_runs where run_id=new.run_id;
            end if;
        end if;
    end if;
    -- Use a durable generation independent of transaction IDs in a restored database.
    insert into public.password_queue_context399(domain_id,revision,changed_xid,changed_at)
    select affected.domain_id,gen_random_uuid(),pg_current_xact_id(),statement_timestamp()
    from (select distinct domain_id from unnest(array[old_domain,new_domain]) domain_id
          where domain_id is not null) affected order by affected.domain_id
    on conflict(domain_id) do update set revision=excluded.revision,changed_xid=excluded.changed_xid,changed_at=excluded.changed_at
    where password_queue_context399.changed_xid<>excluded.changed_xid or password_queue_context399.changed_at<>excluded.changed_at;
    return null;
end $$;
revoke all on function public.invalidate_password_queue_context399() from public;

create function public.password_queue_source_resets399() returns uuid[]
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(array_agg(revision order by relation_name),'{}'::uuid[]) from public.password_queue_source_resets399
$$;
revoke all on function public.password_queue_source_resets399() from public;

create function public.password_queue_context_current399(p_versions jsonb) returns boolean
language sql stable set search_path=pg_catalog,pg_temp as $$
    select not exists (
        select 1 from jsonb_each_text(p_versions) e
        left join public.password_queue_context399 d on d.domain_id=e.key::bigint
        where e.value is distinct from coalesce(d.revision::text,'0'))
$$;
revoke all on function public.password_queue_context_current399(jsonb) from public;

create function public.password_queue_projection_current399(c public.password_queue_projection399,
    p_evidence_revision uuid,p_source_resets uuid[]) returns boolean
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(c.valid and (c.evidence_revision is not distinct from p_evidence_revision)
        and c.source_resets=p_source_resets and public.password_queue_context_current399(c.context_versions),false)
$$;
revoke all on function public.password_queue_projection_current399(public.password_queue_projection399,uuid,uuid[]) from public;

create function public.refresh_password_queue_presentation399(p_finding bigint) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare rule text; evidence_version uuid; resets uuid[]; epochs jsonb; live_facts jsonb; live_aliases jsonb; computed boolean:=true;
begin
    if not pg_try_advisory_xact_lock(hashtextextended('sli_password_queue_projection399:'||p_finding,0)) then return; end if;
    -- Capture source versions before reading the inputs. A concurrent change
    -- makes the result stale even if it commits before the projection is saved.
    select f.rule_code,e.revision,public.password_queue_source_resets399() into rule,evidence_version,resets
    from public.findings f left join public.password_queue_evidence_versions399 e on e.finding_id=f.id
    where f.id=p_finding and f.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray');
    if not found then return; end if;
    if exists(select 1 from public.password_queue_projection399 c
        where c.finding_id=p_finding and c.rule_code=rule
          and public.password_queue_projection_current399(c,evidence_version,resets)) then return; end if;
    select coalesce(jsonb_object_agg(d.domain_id::text,coalesce(c.revision::text,'0')),'{}'::jsonb) into epochs
    from (select distinct domain_id from public.finding_event_copies337 where finding_id=p_finding
          and event_kind in (4624,4625,4771,4776)) d
    left join public.password_queue_context399 c on c.domain_id=d.domain_id;
    begin
        live_facts:=public.password_problem_facts395(p_finding,rule);
        select to_jsonb(list) into live_aliases from (
            select p_finding as finding_id,
                (array_agg(distinct account order by account) filter(where account is not null))[1:8] as accounts,
                (array_agg(distinct address order by address) filter(where address is not null))[1:8] as addresses
            from (
                select case when target_user_name not in ('','-') and event_id<>4624 then left(btrim(target_user_name),256) end as account,
                    case when ip_address not in ('','-','::','::1','0.0.0.0','127.0.0.1') then left(btrim(ip_address),256) end as address
                from public.finding_event_details337 where finding_id=p_finding and event_id in (4624,4625,4771,4776)
                offset 0
            ) names having count(*)>0
        ) list;
    exception when data_exception then
        computed:=false;
        live_facts:=null;
        live_aliases:=null;
    end;
    insert into public.password_queue_projection399(finding_id,rule_code,valid,evidence_revision,source_resets,context_versions,attempted_at,facts,aliases)
    values(p_finding,rule,computed,evidence_version,resets,epochs,clock_timestamp(),live_facts,live_aliases)
    on conflict(finding_id) do update set rule_code=excluded.rule_code,valid=excluded.valid,evidence_revision=excluded.evidence_revision,
        source_resets=excluded.source_resets,context_versions=excluded.context_versions,attempted_at=excluded.attempted_at,
        facts=excluded.facts,aliases=excluded.aliases;
end $$;
revoke all on function public.refresh_password_queue_presentation399(bigint) from public;
grant execute on function public.refresh_password_queue_presentation399(bigint) to adlog_semantic_worker;

-- Refresh recent projections out of band after publication or AD writes.
create function public.refresh_stale_password_queue399() returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare finding bigint; resets uuid[]:=public.password_queue_source_resets399();
begin
    for finding in select f.id from public.findings f
        left join public.password_queue_projection399 c on c.finding_id=f.id
        left join public.password_queue_evidence_versions399 e on e.finding_id=f.id
        where f.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
          and (c.rule_code is distinct from f.rule_code or not public.password_queue_projection_current399(c,e.revision,resets))
          and case when pg_input_is_valid(f.last_seen_utc,'timestamp with time zone')
                   then f.last_seen_utc::timestamptz>=statement_timestamp()-interval '7 days' else false end
          and public.is_semantic_finding_published_v1(f.id)
        order by c.attempted_at nulls first,f.id limit 4 loop
        perform public.refresh_password_queue_presentation399(finding);
    end loop;
end $$;
revoke all on function public.refresh_stale_password_queue399() from public;
grant execute on function public.refresh_stale_password_queue399() to adlog_semantic_worker;

create function public.password_queue_presentation399(p_finding bigint,p_rule text) returns table(facts jsonb,aliases jsonb)
language plpgsql stable security definer rows 1 set search_path=pg_catalog,pg_temp as $$
begin
    if p_rule is null or p_rule not in ('semantic.qw.password-brute-force','semantic.qw.password-spray') then return; end if;
    return query select c.facts,c.aliases from public.password_queue_projection399 c
    left join public.password_queue_evidence_versions399 e on e.finding_id=c.finding_id
    where c.finding_id=p_finding and c.rule_code=p_rule
      and public.password_queue_projection_current399(c,e.revision,public.password_queue_source_resets399());
    if not found then return query select public.password_problem_facts395(p_finding,p_rule),null::jsonb; end if;
end $$;
revoke all on function public.password_queue_presentation399(bigint,text) from public;
grant execute on function public.password_queue_presentation399(bigint,text) to adlog_user;

reset role;
create trigger invalidate_password_queue_insert399 after insert on public.finding_event_copies337
referencing new table as new_copies for each statement execute function public.invalidate_password_queue_evidence399();
create trigger invalidate_password_queue_update399 after update on public.finding_event_copies337
referencing old table as old_copies new table as new_copies for each statement execute function public.invalidate_password_queue_evidence399();
create trigger invalidate_password_queue_delete399 after delete on public.finding_event_copies337
referencing old table as old_copies for each statement execute function public.invalidate_password_queue_evidence399();
create trigger truncate_password_queue_evidence399 after truncate on public.finding_event_copies337
for each statement execute function public.record_password_queue_source_reset399();
create trigger invalidate_password_queue_context399 after insert or update of id,fqdn,netbios_name or delete on public.domains
for each row execute function public.invalidate_password_queue_context399();
create trigger invalidate_password_queue_context399 after insert or update of run_id,domain_id,observed_at_utc,status or delete on public.ad_context_runs
for each row execute function public.invalidate_password_queue_context399();
create trigger invalidate_password_queue_context399 after insert or update of domain_id,entity_id,alias_type,normalized_value or delete on public.ad_context_entity_aliases
for each row execute function public.invalidate_password_queue_context399();
create trigger invalidate_password_queue_context399 after insert or update of id,entity_id,source_run_id,source_section,valid_from_utc,valid_to_utc,attributes_json or delete on public.ad_context_entity_versions
for each row execute function public.invalidate_password_queue_context399();
create trigger invalidate_password_queue_context399 after insert or update of run_id,section_name,status or delete on public.ad_context_sections
for each row execute function public.invalidate_password_queue_context399();
do $$ declare relation_name text; begin
    foreach relation_name in array array['domains','ad_context_runs','ad_context_entity_aliases','ad_context_entity_versions','ad_context_sections'] loop
        execute format('create trigger truncate_password_queue_context399 after truncate on public.%I for each statement execute function public.record_password_queue_source_reset399()',relation_name);
    end loop;
end $$;

set local role adlog_storage_owner;
-- Older rows remain readable through the live fallback. Seed the normal
-- seven-day view without rewriting existing findings or evidence.
do $$ declare finding bigint; begin
    for finding in select id from public.findings
        where rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
          and case when pg_input_is_valid(last_seen_utc,'timestamp with time zone')
                   then last_seen_utc::timestamptz>=statement_timestamp()-interval '7 days' else false end
          and public.is_semantic_finding_published_v1(id)
        order by id loop
        perform public.refresh_password_queue_presentation399(finding);
    end loop;
end $$;
insert into public.schema_migrations(version,name) values(399,'password_queue_projection');
reset role;
commit;
