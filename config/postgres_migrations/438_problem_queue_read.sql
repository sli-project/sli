begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_problem_queue_read438'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=426 and name='semantic_outbox_retention')
       or exists(select 1 from public.schema_migrations where version>=438) then
        raise exception 'problem_queue_read438_preflight' using errcode='55000';
    end if;
end $$;

-- Backfill and trigger installation share a snapshot with no intervening writes.
lock table public.findings,public.semantic_security_scenarios,public.finding_event_copies337 in share row exclusive mode;
set local role adlog_storage_owner;

create type public.problem_queue_representative438 as (
    id bigint,status text,risk_accepted boolean,severity text,assignee text,password_aliases jsonb
);
create type public.problem_queue_password438 as (severity text,facts jsonb);

create function public.problem_queue_object438(p_id bigint,p_rule text,p_target text,p_source text)
returns text language sql stable set search_path=pg_catalog,pg_temp as $$
    select case when length(key)<=4096 then key else jsonb_build_array('finding',p_id)::text end
    from (select case
        when nullif(btrim(p_target),'') is not null and length(p_target)<=2048
            then jsonb_build_array('rule-object',p_rule,lower(btrim(p_target)))
        when nullif(btrim(p_source),'') is not null and length(p_source)<=2048
            then jsonb_build_array('rule-source',p_rule,lower(btrim(p_source)))
        else jsonb_build_array('finding',p_id) end::text as key) object
$$;
revoke all on function public.problem_queue_object438(bigint,text,text,text) from public;

create table public.problem_queue_entries438 (
    id bigint primary key references public.findings(id) on delete cascade,
    status text not null,
    severity text not null,
    rule_code text not null,
    assigned_to text,
    repeat_count bigint not null,
    evidence_count bigint not null,
    created_at timestamptz not null,
    updated_at timestamptz not null,
    first_seen_utc timestamptz,
    last_seen_utc timestamptz,
    object_key text not null,
    scenario_key bytea
);
create index problem_queue_state438 on public.problem_queue_entries438
    (status,coalesce(last_seen_utc,updated_at) desc,id desc);
create index problem_queue_seen438 on public.problem_queue_entries438
    (coalesce(last_seen_utc,updated_at) desc,id desc);

create function public.problem_queue_entry438() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp set timezone='UTC' as $$
begin
    insert into public.problem_queue_entries438 as q
    values(new.id,new.status,new.severity,new.rule_code,new.assigned_to,new.repeat_count,new.evidence_count,
        new.created_at,new.updated_at,new.first_seen_utc::timestamptz,new.last_seen_utc::timestamptz,
        public.problem_queue_object438(new.id,new.rule_code,new.target,new.source),
        case when new.fingerprint ~ '^semantic:[0-9a-f]{64}$' then decode(substring(new.fingerprint from 10),'hex') end)
    on conflict(id) do update set status=excluded.status,severity=excluded.severity,rule_code=excluded.rule_code,
        assigned_to=excluded.assigned_to,repeat_count=excluded.repeat_count,evidence_count=excluded.evidence_count,
        created_at=excluded.created_at,updated_at=excluded.updated_at,first_seen_utc=excluded.first_seen_utc,
        last_seen_utc=excluded.last_seen_utc,object_key=excluded.object_key,scenario_key=excluded.scenario_key;
    return null;
end $$;
revoke all on function public.problem_queue_entry438() from public;

set local timezone='UTC';
insert into public.problem_queue_entries438
select id,status,severity,rule_code,assigned_to,repeat_count,evidence_count,created_at,updated_at,
    first_seen_utc::timestamptz,last_seen_utc::timestamptz,
    public.problem_queue_object438(id,rule_code,target,source),
    case when fingerprint ~ '^semantic:[0-9a-f]{64}$' then decode(substring(fingerprint from 10),'hex') end
from public.findings;

create function public.problem_queue_scenario438(p_kind text,p_partition text,p_entity text)
returns text language sql stable set search_path=pg_catalog,pg_temp as $$
    select case when length(key)<=4096 then key end
    from (select jsonb_build_array('rule-entity','semantic.'||p_kind,p_partition,p_entity)::text as key) scenario
    where length(p_partition) between 1 and 2048 and length(p_entity) between 1 and 2048
$$;
revoke all on function public.problem_queue_scenario438(text,text,text) from public;

create table public.problem_queue_scenarios438 (
    scenario_id uuid primary key references public.semantic_security_scenarios(scenario_id) on delete cascade,
    scenario_key bytea not null unique,
    rule_code text not null,
    cohort text
);
create function public.problem_queue_scenario438() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if length(new.strict_keys_json->>'entity') between 1 and 2048 and length(new.partition_key) between 1 and 2048 then
        insert into public.problem_queue_scenarios438
        values(new.scenario_id,new.scenario_key,'semantic.'||new.scenario_kind,
            public.problem_queue_scenario438(new.scenario_kind,new.partition_key,new.strict_keys_json->>'entity'))
        on conflict(scenario_id) do update set scenario_key=excluded.scenario_key,rule_code=excluded.rule_code,cohort=excluded.cohort;
    else
        delete from public.problem_queue_scenarios438 where scenario_id=new.scenario_id;
    end if;
    return null;
end $$;
revoke all on function public.problem_queue_scenario438() from public;
create trigger problem_queue_scenario438 after insert or update of scenario_key,scenario_kind,partition_key,strict_keys_json
    on public.semantic_security_scenarios for each row execute function public.problem_queue_scenario438();
insert into public.problem_queue_scenarios438
select scenario_id,scenario_key,'semantic.'||scenario_kind,
    public.problem_queue_scenario438(scenario_kind,partition_key,strict_keys_json->>'entity')
from public.semantic_security_scenarios
where length(strict_keys_json->>'entity') between 1 and 2048 and length(partition_key) between 1 and 2048;

-- Reference counts keep the domain proof exact for updates, deletes, and
-- multiple roles attached to the same event. No evidence payload is copied.
create table public.problem_queue_domains438 (
    finding_id bigint not null,
    domain_id bigint not null,
    copies bigint not null check(copies>=0),
    primary key(finding_id,domain_id)
);
insert into public.problem_queue_domains438
select finding_id,domain_id,count(*) from public.finding_event_copies337 group by finding_id,domain_id;

create index problem_queue_occurrence_witness438 on public.finding_event_copies337(finding_id,event_kind,event_id)
    where event_kind in (104,1102,4719,4728,4732,4756);
create index problem_queue_subject_witness438 on public.finding_event_copies337
    (domain_id,left(method#>>'{$principals,SubjectUserSid}',256),finding_id)
    where method#>>'{$principals,SubjectUserSid}' is not null;
create index problem_queue_audit_witness438 on public.finding_event_copies337(domain_id,finding_id)
    where event_kind=4719;

create view public.problem_queue_occurrence_source438 as
select finding_id,
    count(distinct event_id) filter(where event_kind in (4728,4732,4756)) as group_additions,
    count(distinct event_id) filter(where event_kind in (104,1102)) as log_clears,
    count(distinct event_id) filter(where event_kind=4719) as audit_changes
from public.finding_event_copies337
where event_kind in (104,1102,4719,4728,4732,4756)
group by finding_id;

create table public.problem_queue_evidence438 (
    finding_id bigint primary key,
    domain_ids bigint[] not null default '{}',
    group_additions bigint not null default 0,
    log_clears bigint not null default 0,
    audit_changes bigint not null default 0
);
create index problem_queue_domain438 on public.problem_queue_evidence438((domain_ids[1]),finding_id)
    where cardinality(domain_ids)=1;
insert into public.problem_queue_evidence438
select domains.finding_id,domains.ids,coalesce(occurrences.group_additions,0),
    coalesce(occurrences.log_clears,0),coalesce(occurrences.audit_changes,0)
from (
    select finding_id,array_agg(domain_id order by domain_id) as ids
    from public.problem_queue_domains438 group by finding_id
) domains
left join public.problem_queue_occurrence_source438 occurrences using(finding_id);

create function public.problem_queue_domains438() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare removed text; added text; previous_ids text; incoming_ids text; delta record; changed record;
    domain_changes bigint[]:='{}'; remaining bigint;
    witness_filter constant text:=' where event_kind in (104,1102,4719,4728,4732,4756)';
begin
    if tg_op='TRUNCATE' then
        truncate public.problem_queue_domains438,public.problem_queue_evidence438;
        return null;
    end if;
    if tg_op in ('DELETE','UPDATE') then
        removed:='select finding_id,domain_id,-count(*) as copies from previous group by finding_id,domain_id';
        previous_ids:='select finding_id,true as witnesses from previous'||witness_filter;
    end if;
    if tg_op in ('INSERT','UPDATE') then
        added:='select finding_id,domain_id,count(*) as copies from incoming group by finding_id,domain_id';
        incoming_ids:='select finding_id,true as witnesses from incoming'||witness_filter;
    end if;
    for delta in execute 'select finding_id,domain_id,sum(copies)::bigint as copies from (' ||
        concat_ws(' union all ',removed,added) ||
        ') d group by finding_id,domain_id having sum(copies)<>0 order by finding_id,domain_id'
    loop
        if delta.copies>0 then
            insert into public.problem_queue_domains438 as d values(delta.finding_id,delta.domain_id,delta.copies)
            on conflict(finding_id,domain_id) do update set copies=d.copies+excluded.copies returning d.copies into remaining;
            if remaining=delta.copies then domain_changes:=array_append(domain_changes,delta.finding_id); end if;
        else
            update public.problem_queue_domains438 set copies=copies+delta.copies
            where finding_id=delta.finding_id and domain_id=delta.domain_id returning copies into remaining;
            if not found then raise exception 'problem_queue_domain_missing438'; end if;
            if remaining=0 then
                domain_changes:=array_append(domain_changes,delta.finding_id);
                delete from public.problem_queue_domains438 where finding_id=delta.finding_id and domain_id=delta.domain_id;
            end if;
        end if;
    end loop;

    for changed in execute 'select finding_id,bool_or(witnesses) as witnesses from (' ||
        concat_ws(' union all ','select unnest($1) as finding_id,false as witnesses',previous_ids,incoming_ids) ||
        ') changed group by finding_id order by finding_id' using domain_changes
    loop
        -- Serialize writes for the same finding before reading its latest
        -- copies. The indexed aggregate deduplicates different evidence roles.
        insert into public.problem_queue_evidence438(finding_id) values(changed.finding_id)
        on conflict(finding_id) do update set finding_id=excluded.finding_id;
        update public.problem_queue_evidence438 e set domain_ids=coalesce((
            select array_agg(domain_id order by domain_id) from public.problem_queue_domains438
            where finding_id=changed.finding_id),'{}')
        where e.finding_id=changed.finding_id;
        if changed.witnesses then
            update public.problem_queue_evidence438 e
            set (group_additions,log_clears,audit_changes)=(
                select coalesce(source.group_additions,0),coalesce(source.log_clears,0),coalesce(source.audit_changes,0)
                from (values(changed.finding_id)) finding(id)
                left join public.problem_queue_occurrence_source438 source on source.finding_id=finding.id)
            where e.finding_id=changed.finding_id;
        end if;
        delete from public.problem_queue_evidence438 where finding_id=changed.finding_id and cardinality(domain_ids)=0;
    end loop;
    return null;
end $$;
revoke all on function public.problem_queue_domains438() from public;
create trigger problem_queue_domains_insert438 after insert on public.finding_event_copies337
    referencing new table as incoming for each statement execute function public.problem_queue_domains438();
create trigger problem_queue_domains_update438 after update on public.finding_event_copies337
    referencing old table as previous new table as incoming for each statement execute function public.problem_queue_domains438();
create trigger problem_queue_domains_delete438 after delete on public.finding_event_copies337
    referencing old table as previous for each statement execute function public.problem_queue_domains438();
create trigger problem_queue_domains_truncate438 after truncate on public.finding_event_copies337
    for each statement execute function public.problem_queue_domains438();

create view public.problem_queue_visible438 with (security_barrier=true) as
select q.*,superseded.new_finding_id as superseded_by_finding_id
from public.problem_queue_entries438 q
left join public.entity_identity_finding_supersessions_v2 superseded on superseded.old_finding_id=q.id
where (superseded.old_finding_id is null or q.status<>'new' or q.assigned_to is not null)
  and exists(select 1 from public.semantic_finding_publications p where p.finding_id=q.id);

create index problem_queue_external_evidence438 on public.finding_evidence_refs(finding_id)
    where storage_kind is distinct from 'core_event';
create view public.problem_queue_external438 with (security_barrier=true) as
select distinct r.finding_id from public.finding_evidence_refs r
where r.storage_kind is distinct from 'core_event'
  and exists(select 1 from public.semantic_finding_publications p where p.finding_id=r.finding_id);
create view public.problem_queue_scenario_keys438 as select scenario_key,rule_code,cohort from public.problem_queue_scenarios438;
grant select on public.problem_queue_visible438,public.problem_queue_external438,public.problem_queue_scenario_keys438,
    public.problem_queue_evidence438 to adlog_user;
revoke all on type public.problem_queue_representative438,public.problem_queue_password438 from public;
grant usage on type public.problem_queue_representative438,public.problem_queue_password438 to adlog_user;

reset role;
create trigger problem_queue_entry438 after insert or update of status,severity,rule_code,assigned_to,repeat_count,
    evidence_count,created_at,updated_at,first_seen_utc,last_seen_utc,target,source,fingerprint
    on public.findings for each row execute function public.problem_queue_entry438();
insert into public.schema_migrations(version,name) values(438,'problem_queue_read');
commit;
