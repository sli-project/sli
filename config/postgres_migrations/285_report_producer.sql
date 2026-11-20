-- T015: separate bounded report producer, aggregate and fixed delivery APIs.
-- Unapplied review candidate. No LOGIN, secret, principal binding or service.
begin;
select pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('sli_report_producer_v285'));
do $$ begin
    if not pg_catalog.pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations
           where version=284 and name='event_source_identity')
       or exists(select 1 from public.schema_migrations where version>=285) then
        raise exception 'migration 285 prerequisites failed';
    end if;
end $$;


do $$ begin
    if not pg_catalog.pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'report_producer_proposal_requires_owner';
    end if;
    if not exists(select 1 from pg_catalog.pg_roles where rolname='adlog_report_producer') then
        create role adlog_report_producer nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
    end if;
    if not exists(select 1 from pg_catalog.pg_roles where rolname='adlog_report_producer_owner') then
        create role adlog_report_producer_owner nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
    end if;
end $$;

create table public.report_producer_principals (
    principal_oid oid primary key,
    principal_name name not null unique
);
create table public.report_producer_claims (
    id uuid primary key default pg_catalog.gen_random_uuid(),
    schedule_id uuid not null unique references public.report_schedules(id),
    schedule_revision bigint not null,
    slot timestamptz not null,
    period_from timestamptz not null,
    checked_at timestamptz not null,
    lease uuid not null default pg_catalog.gen_random_uuid(),
    lease_until timestamptz not null,
    principal_oid oid not null,
    leader_token uuid not null,
    acl_facts jsonb,
    candidates jsonb,
    check(period_from<slot)
);
create table public.report_producer_leader (
    singleton boolean primary key default true check(singleton),
    token uuid not null, principal_oid oid not null, lease_until timestamptz not null
);
alter table public.report_producer_leader owner to adlog_report_producer_owner;
revoke all on public.report_producer_leader from public,adlog_report_producer;
alter table public.report_producer_principals owner to adlog_report_producer_owner;
alter table public.report_producer_claims owner to adlog_report_producer_owner;
revoke all on public.report_producer_principals,public.report_producer_claims from public,adlog_report_producer;
grant usage on schema public to adlog_report_producer,adlog_report_producer_owner;
grant select on public.report_schedules,public.report_schedule_subscriptions,
    public.notification_subscriptions,public.notification_channels to adlog_report_producer_owner;
grant update(last_checked_at) on public.report_schedules to adlog_report_producer_owner;
grant select,insert on public.report_schedule_runs,public.notification_outbox to adlog_report_producer_owner;
grant select(id,role,is_active) on public.auth_users to adlog_report_producer_owner;
grant select on public.access_platform_owners,public.access_group_members,public.access_groups,
    public.access_role_packages,public.access_packages,public.access_subject_packages,
    public.access_package_capabilities,public.access_capabilities,public.access_capability_assignments,
    public.access_package_reports,public.access_report_assignments,public.report_registry_v4,
    public.report_datasets_v4 to adlog_report_producer_owner;

create function public.report_producer_identity() returns oid
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare v_oid oid;
begin
    select r.oid into v_oid from pg_catalog.pg_roles r
    join public.report_producer_principals b on b.principal_oid=r.oid and b.principal_name=r.rolname
    where r.rolname=session_user and r.rolcanlogin and not r.rolsuper and not r.rolbypassrls
      and not r.rolcreaterole and not r.rolcreatedb and not r.rolreplication
      and pg_catalog.pg_has_role(session_user,'adlog_report_producer','MEMBER');
    if v_oid is null or exists(select 1 from pg_catalog.pg_roles r
        where r.rolname in ('adlog_storage_owner','adlog_user','adlog_notification_worker',
                           'adlog_file_audit_owner','adlog_report_producer_owner',
                           'pg_read_all_data','pg_write_all_data')
          and pg_catalog.pg_has_role(session_user,r.oid,'MEMBER')) then
        raise exception 'report_producer_identity_denied' using errcode='42501';
    end if;
    return v_oid;
end $$;
alter function public.report_producer_identity() owner to adlog_report_producer_owner;
revoke all on function public.report_producer_identity() from public,adlog_report_producer;

create function public.report_producer_lead(p_token uuid default null) returns uuid
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare principal oid; result uuid;
begin
    principal:=public.report_producer_identity();
    insert into public.report_producer_leader(singleton,token,principal_oid,lease_until)
    values(true,pg_catalog.gen_random_uuid(),principal,clock_timestamp()+interval '30 seconds')
    on conflict(singleton) do update set
        token=case when report_producer_leader.token=p_token then p_token else excluded.token end,
        principal_oid=excluded.principal_oid,lease_until=excluded.lease_until
    where report_producer_leader.lease_until<=clock_timestamp()
       or report_producer_leader.token=p_token and report_producer_leader.principal_oid=principal
    returning token into result;
    return result;
end $$;
alter function public.report_producer_lead(uuid) owner to adlog_report_producer_owner;
revoke all on function public.report_producer_lead(uuid) from public;
grant execute on function public.report_producer_lead(uuid) to adlog_report_producer;

-- Exact minute advancement, then the earliest UTC witness of that wall minute.
-- The second-resolution search includes historical sub-minute UTC offsets.
-- Hard bounded searches; statement/cycle deadlines also apply at the client.
create function public.report_calendar_instant(p_naive timestamp,p_zone text) returns timestamptz
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with wall as materialized (
        select n from pg_catalog.generate_series(p_naive,p_naive+interval '1440 minutes',interval '1 minute') n
        where pg_catalog.timezone(p_zone,pg_catalog.timezone(p_zone,n))=n order by n limit 1
    ), seed as materialized (select n,pg_catalog.timezone(p_zone,n) as instant from wall)
    select min(candidate) from seed,
        pg_catalog.generate_series(instant-interval '2 days',instant,interval '1 second') candidate
    where pg_catalog.timezone(p_zone,candidate)=n
$$;
alter function public.report_calendar_instant(timestamp,text) owner to adlog_report_producer_owner;
revoke all on function public.report_calendar_instant(timestamp,text) from public,adlog_report_producer;

create function public.report_calendar_latest(p_schedule jsonb,p_now timestamptz) returns timestamptz
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare day date; instant timestamptz; i integer;
begin
    for i in 0..8 loop
        day:=pg_catalog.timezone(p_schedule->>'timezone',p_now)::date-i;
        if p_schedule->>'weekday' is not null
           and extract(isodow from day)::integer-1<>(p_schedule->>'weekday')::integer then continue; end if;
        instant:=public.report_calendar_instant(day+(p_schedule->>'local_time')::time,p_schedule->>'timezone');
        if instant between (p_schedule->>'created_at')::timestamptz and p_now then return instant; end if;
    end loop;
    return null;
end $$;
alter function public.report_calendar_latest(jsonb,timestamptz) owner to adlog_report_producer_owner;
revoke all on function public.report_calendar_latest(jsonb,timestamptz) from public,adlog_report_producer;

create function public.report_schedule_claim(p_leader uuid,p_limit integer)
returns table(job_id uuid,lease uuid,lease_until timestamptz,schedule jsonb,evaluated_at timestamptz,
    slot timestamptz,period_from timestamptz)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_principal oid; v_now timestamptz := pg_catalog.clock_timestamp(); v_schedule record; v_claim record;
    v_slot timestamptz; v_from timestamptz;
begin
    v_principal := public.report_producer_identity();
    perform l.token from public.report_producer_leader l where l.token=p_leader
        and l.principal_oid=v_principal and l.lease_until>clock_timestamp() for share;
    if not found then
        raise exception 'report_producer_leader_denied' using errcode='42501';
    end if;
    if p_limit is null or p_limit<1 or p_limit>50 then
        raise exception 'report_producer_batch_invalid';
    end if;
    for v_schedule in
        select s.* from public.report_schedules s
        where s.enabled and not exists(select 1 from public.report_producer_claims c
            where c.schedule_id=s.id and c.lease_until>v_now)
        order by s.last_checked_at,s.id limit p_limit for update of s skip locked
    loop
        update public.report_schedules set last_checked_at=v_now where id=v_schedule.id;
        v_slot:=public.report_calendar_latest(pg_catalog.to_jsonb(v_schedule),v_now);
        if v_slot is null or exists(select 1 from public.report_schedule_runs r where r.schedule_id=v_schedule.id
            and r.schedule_revision=v_schedule.revision and r.slot=v_slot) then continue; end if;
        v_from:=public.report_calendar_instant(pg_catalog.timezone(v_schedule.timezone,v_slot)
            -v_schedule.period_days*interval '1 day',v_schedule.timezone);
        insert into public.report_producer_claims(schedule_id,schedule_revision,slot,period_from,checked_at,lease_until,principal_oid,leader_token)
        values(v_schedule.id,v_schedule.revision,v_slot,v_from,v_now,v_now+interval '30 seconds',v_principal,p_leader)
        on conflict(schedule_id) do update set id=pg_catalog.gen_random_uuid(),lease=pg_catalog.gen_random_uuid(),
            schedule_revision=excluded.schedule_revision,lease_until=excluded.lease_until,
            principal_oid=excluded.principal_oid,leader_token=excluded.leader_token,slot=excluded.slot,period_from=excluded.period_from,
            checked_at=excluded.checked_at,
            acl_facts=null,candidates=null
        returning * into v_claim;
        job_id:=v_claim.id; lease:=v_claim.lease; lease_until:=v_claim.lease_until;
        schedule:=pg_catalog.to_jsonb(v_schedule)-'last_checked_at'; evaluated_at:=v_now;
        slot:=v_slot; period_from:=v_from;
        return next;
    end loop;
end $$;
alter function public.report_schedule_claim(uuid,integer) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_claim(uuid,integer) from public;
grant execute on function public.report_schedule_claim(uuid,integer) to adlog_report_producer;

create function public.report_locked_claim(p_job uuid,p_lease uuid) returns public.report_producer_claims
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare principal oid; result public.report_producer_claims;
begin
    principal:=public.report_producer_identity();
    -- Fixed order: leader, schedule, claim, subscriptions/channels. The leader
    -- function never takes schedule locks. Takeover cannot interleave this RPC.
    select c.* into result from public.report_producer_claims c where c.id=p_job and c.lease=p_lease
        and c.principal_oid=principal and c.lease_until>clock_timestamp();
    if not found then raise exception 'report_schedule_lease_denied' using errcode='42501'; end if;
    perform l.token from public.report_producer_leader l where l.token=result.leader_token
        and l.principal_oid=principal and l.lease_until>clock_timestamp() for share;
    if not found then raise exception 'report_schedule_lease_denied' using errcode='42501'; end if;
    perform s.id from public.report_schedules s join public.report_producer_claims c on c.schedule_id=s.id
    where c.id=p_job and c.lease=p_lease and c.principal_oid=principal and s.enabled
      and s.revision=c.schedule_revision and c.lease_until>clock_timestamp() for share of s;
    if not found then raise exception 'report_schedule_lease_denied' using errcode='42501'; end if;
    select c.* into result from public.report_producer_claims c where c.id=p_job and c.lease=p_lease
        and c.principal_oid=principal and c.lease_until>clock_timestamp() for update;
    if not found then
        raise exception 'report_schedule_lease_denied' using errcode='42501';
    end if;
    return result;
end $$;
alter function public.report_locked_claim(uuid,uuid) owner to adlog_report_producer_owner;
revoke all on function public.report_locked_claim(uuid,uuid) from public,adlog_report_producer;

create function public.report_actor_acl_facts(p_user bigint,p_key text,p_at timestamptz)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare v_result jsonb;
begin
    -- Private helper only: there is no producer EXECUTE for arbitrary actors.
    with actor as materialized (
        select u.id,u.role,u.is_active,exists(select 1 from public.access_platform_owners o where o.user_id=u.id) as is_owner
        from public.auth_users u where u.id=p_user
    ), groups as materialized (
        select g.id,m.valid_from,m.valid_until from public.access_group_members m
        join public.access_groups g on g.id=m.group_id and g.is_active
        where m.user_id=p_user and (m.valid_from is null or m.valid_from<=p_at)
          and (m.valid_until is null or m.valid_until>p_at)
        limit 2049
    ), role_packages as materialized (
        select p.id,p.package_key,'role'::text as source_kind,a.role as source_key,'allow'::text as effect
        from actor a join public.access_role_packages rp on rp.coarse_role=a.role
        join public.access_packages p on p.id=rp.package_id
        limit 2049
    ), subject_packages as materialized (
        select p.id,p.package_key,sp.source_type as source_kind,
            sp.subject_type||':'||sp.subject_id::text as source_key,sp.effect,sp.valid_from,sp.valid_until
        from public.access_subject_packages sp join public.access_packages p on p.id=sp.package_id
        where ((sp.subject_type='user' and sp.subject_id=p_user)
            or (sp.subject_type='group' and sp.subject_id in(select id from groups)))
          and (sp.valid_from is null or sp.valid_from<=p_at) and (sp.valid_until is null or sp.valid_until>p_at)
        limit 2049
    ), owner_packages as materialized (
        select p.id,p.package_key,'platform_owner'::text as source_kind,'owner:primary'::text as source_key,
            'allow'::text as effect from public.access_packages p where exists(select 1 from actor where is_owner)
        limit 2049
    ), packages as materialized (
        select id from role_packages union select id from subject_packages union select id from owner_packages
    ), definition as materialized (
        select r.report_key,r.version,d.dataset_key,d.version as dataset_version,
            (select coalesce(pg_catalog.jsonb_object_agg(f.key,f.value),'{}'::jsonb)
                from pg_catalog.jsonb_each(r.definition_json) f
                where f.key in ('field_categories','actions','required_capabilities')) as definition_json,
            (select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('category',f->'category'))
                from pg_catalog.jsonb_array_elements(d.fields_json) f) as fields_json,d.actions_json
        from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
        where r.report_key=p_key and r.status='published' order by r.version desc limit 1
    ), needed_capabilities as materialized (
        select pg_catalog.jsonb_array_elements_text(d.definition_json->'required_capabilities') as key from definition d
        union select 'field.'||pg_catalog.jsonb_array_elements_text(d.definition_json->'field_categories') from definition d
        union select 'field.'||(f->>'category') from definition d,
            pg_catalog.jsonb_array_elements(d.fields_json) f
        union select 'evidence.exact' union select 'reports.export' union select 'file-audit.view' union select 'file-audit.export'
    ), package_capabilities as materialized (
        select c.capability_key,p.package_key from public.access_package_capabilities pc
        join public.access_capabilities c on c.id=pc.capability_id
        join public.access_packages p on p.id=pc.package_id
        where pc.package_id in(select id from packages) and c.capability_key in(select key from needed_capabilities)
        limit 2049
    ), direct_capabilities as materialized (
        select c.capability_key,a.effect,a.subject_type,a.subject_id,a.source_type,a.valid_from,a.valid_until,a.scope_json
        from public.access_capability_assignments a join public.access_capabilities c on c.id=a.capability_id
        where c.capability_key in(select key from needed_capabilities)
          and ((a.subject_type='user' and a.subject_id=p_user)
            or (a.subject_type='group' and a.subject_id in(select id from groups)))
          and (a.valid_from is null or a.valid_from<=p_at) and (a.valid_until is null or a.valid_until>p_at)
        limit 2049
    ), package_reports as materialized (
        select pr.report_key,pr.field_categories,pr.allowed_actions,pr.scope_json,p.package_key
        from public.access_package_reports pr join public.access_packages p on p.id=pr.package_id
        where pr.report_key=p_key and pr.package_id in(select id from packages)
        limit 2049
    ), assignments as materialized (
        select a.id,a.report_key,a.subject_type,a.subject_id,a.source_type,a.effect,a.scope_json,
            a.field_categories,a.allowed_actions,a.valid_from,a.valid_until
        from public.access_report_assignments a where a.report_key=p_key
          and ((a.subject_type='user' and a.subject_id=p_user)
            or (a.subject_type='group' and a.subject_id in(select id from groups)))
          and (a.valid_from is null or a.valid_from<=p_at) and (a.valid_until is null or a.valid_until>p_at)
        limit 2049
    )
    select pg_catalog.jsonb_build_object(
        'subject',(select pg_catalog.jsonb_build_object('type','session','id',id,'role',role,'is_active',is_active) from actor),
        'facts',pg_catalog.jsonb_build_object(
            'is_owner',pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('is_owner',coalesce((select is_owner from actor),false))),
            'groups',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by id) from groups x),'[]'::jsonb),
            'role_packages',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by package_key) from role_packages x),'[]'::jsonb),
            'subject_packages',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by package_key,effect desc) from subject_packages x),'[]'::jsonb),
            'owner_packages',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by package_key) from owner_packages x),'[]'::jsonb),
            'package_capabilities',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by capability_key,package_key) from package_capabilities x),'[]'::jsonb),
            'direct_capabilities',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by capability_key,effect desc) from direct_capabilities x),'[]'::jsonb),
            'all_capabilities',coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('capability_key',c.capability_key) order by c.capability_key)
                from public.access_capabilities c where c.capability_key in(select key from needed_capabilities)
                  and exists(select 1 from actor where is_owner)),'[]'::jsonb),
            'package_reports',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by package_key) from package_reports x),'[]'::jsonb),
            'report_assignments',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x) order by report_key,effect desc,id) from assignments x),'[]'::jsonb),
            'definitions',coalesce((select pg_catalog.jsonb_agg(pg_catalog.to_jsonb(x)) from definition x),'[]'::jsonb))) into v_result;
    if pg_catalog.octet_length(v_result::text)>262144 or exists(
        select 1 from pg_catalog.jsonb_each(v_result->'facts') f
        where pg_catalog.jsonb_array_length(f.value)>2048) then
        raise exception 'report_schedule_facts_limit';
    end if;
    return v_result;
end $$;
alter function public.report_actor_acl_facts(bigint,text,timestamptz) owner to adlog_report_producer_owner;
revoke all on function public.report_actor_acl_facts(bigint,text,timestamptz) from public,adlog_report_producer;

create function public.report_schedule_acl_facts(p_job uuid,p_lease uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_principal oid; v_now timestamptz := pg_catalog.clock_timestamp(); v_schedule record; v_claim record;
    v_key text; v_result jsonb;
begin
    v_principal := public.report_producer_identity();
    v_claim:=public.report_locked_claim(p_job,p_lease);
    select s.* into v_schedule from public.report_schedules s where s.id=v_claim.schedule_id;
    v_key := case v_schedule.report_key when 'security.problems' then 'security.queue'
        when 'file-audit.mass-operations' then 'file-audit.mass-operations' end;
    if v_key is null then raise exception 'report_schedule_report_denied'; end if;
    with bindings as materialized (
        select sub.*,ch.revision as channel_revision from public.notification_subscriptions sub
        join public.report_schedule_subscriptions b on b.subscription_id=sub.id
        join public.notification_channels ch on ch.kind=sub.channel
        where b.schedule_id=v_schedule.id and sub.owner_user_id=v_schedule.owner_user_id
          and sub.enabled
    ), actors as (
        select v_schedule.owner_user_id as id union select recipient_user_id from bindings
    ) select pg_catalog.jsonb_build_object('evaluated_at',v_now,'schedule_revision',v_schedule.revision,
        'owner_user_id',v_schedule.owner_user_id,
        'report_key',v_schedule.report_key,
        -- The existing file query conditionally probes QW details. Only this
        -- saved owner's named dependency is needed to preserve that quality path.
        'dependencies',case when v_schedule.report_key='file-audit.mass-operations' then
            pg_catalog.jsonb_build_object('security.queue',public.report_actor_acl_facts(
                v_schedule.owner_user_id,'security.queue',v_now)) else '{}'::jsonb end,
        'actors',coalesce((select pg_catalog.jsonb_agg(
            public.report_actor_acl_facts(id,v_key,v_now) order by id) from actors),'[]'::jsonb),
        'bindings',coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id',id,'revision',revision,'recipient_user_id',recipient_user_id,'channel',channel,
            'channel_revision',channel_revision) order by id)
            from bindings),'[]'::jsonb)) into v_result;
    if pg_catalog.octet_length(v_result::text)>2097152
       or pg_catalog.jsonb_array_length(v_result->'actors')>101
       or pg_catalog.jsonb_array_length(v_result->'bindings')>100 then
        raise exception 'report_schedule_facts_limit';
    end if;
    update public.report_producer_claims set acl_facts=v_result-'evaluated_at' where id=p_job and lease=p_lease;
    return v_result;
end $$;
alter function public.report_schedule_acl_facts(uuid,uuid) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_acl_facts(uuid,uuid) from public;
grant execute on function public.report_schedule_acl_facts(uuid,uuid) to adlog_report_producer;
-- No LOGIN, credential, principal binding, raw source grant or runtime is provisioned.
-- Remaining APIs below form the same atomic migration.

-- The fixed security aggregate uses this existing NOLOGIN source owner.
-- These referenced columns do not become readable by either service login.
grant select(id,rule_code,severity,status,evidence_count,target,last_seen_utc,repeat_count)
    on public.findings_active to adlog_storage_owner;
grant select(id) on public.auth_users to adlog_storage_owner;
grant select(id,fqdn) on public.domains to adlog_storage_owner;
grant select(pipeline_name,last_status) on public.findings_refresh_state to adlog_storage_owner;
grant select(worker_name,status,heartbeat_at,expected_interval_seconds,details_json)
    on public.runtime_worker_heartbeats to adlog_storage_owner;

-- BEGIN GENERATED SECURITY COUNTS

-- Generated from the same population and exact queue-cohort builders.
create function public.report_security_candidate_counts(p_filters jsonb,p_zone text,p_start timestamptz,p_end timestamptz)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare v_result jsonb; v_heartbeat jsonb; v_refresh boolean := false; v_coverage boolean := false;
    v_domains bigint[]; v_page jsonb; v_generated timestamptz;
begin
    if p_filters is null or jsonb_typeof(p_filters)<>'object'
       or exists(select 1 from jsonb_object_keys(p_filters) k where k not in ('severity','status','population'))
       or exists(select 1 from jsonb_each(p_filters) e where jsonb_typeof(e.value)<>'string')
       or (p_filters ? 'severity' and p_filters->>'severity' not in ('critical','high','medium','low'))
       or (p_filters ? 'status' and p_filters->>'status' not in ('new','repeated','confirmed','active','review','false_positive','closed'))
       or (p_filters ? 'population' and p_filters->>'population' not in ('open','attention','all'))
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '32 days' then
        raise exception 'report_candidate_parameters_invalid';
    end if;
    with queue_population as materialized (
        select findings.id,cohort.key as problem_cohort,findings.severity,
               (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) as status,(coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false)) as risk_accepted,
               count(*) over(partition by cohort.key) as occurrence_count,
               max(findings.id) over(partition by cohort.key) as queue_cursor_id,
               row_number() over(partition by cohort.key order by
                   case (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) when 'new' then 1 when 'repeated' then 2
                       when 'confirmed' then 3 when 'active' then 4 when 'review' then 5
                       when 'false_positive' then 6 when 'closed' then 7 else 8 end,
                   case findings.severity when 'critical' then 1 when 'high' then 2
                       when 'medium' then 3 when 'low' then 4 else 5 end,
                   findings.id desc) as representative_rank
        from public.findings_active findings
        left join lateral (select s.* from public.semantic_suppressions s
            join public.auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance'
            order by s.id desc limit 1) risk on true
    cross join (select p_zone::text as time_zone) cohort_config
    left join lateral (
        select count(*) as retained_count,
               count(*) filter(where e.event_id in (4728,4732,4756)) as membership_count,
               bool_and(coalesce(channel.value='Security' and provider.value='Microsoft-Windows-Security-Auditing',false)) as membership_source,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date,
                   e.target_user_sid,f.membership_member_sid)) as membership_identities,
               count(distinct (e.domain_id,e.server_id,
                   timezone(cohort_config.time_zone,e.time_created_utc)::date)) as source_days,
               bool_and(e.domain_id is not null and e.server_id is not null
                   and e.time_created_utc is not null) as source_complete,
               bool_and(e.target_user_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and f.membership_member_sid ~ '^S-1-([0-9]+-)*[0-9]+$'
                   and e.target_user_sid is not null and f.membership_member_sid is not null) as identities_complete,
               min(e.domain_id) as domain_id,min(e.server_id) as server_id,
               min(timezone(cohort_config.time_zone,e.time_created_utc)::date)::text as day,
               min(e.target_user_sid) as group_sid,min(f.membership_member_sid) as member_sid,
               case when count(distinct e.domain_id)=1 then min(d.fqdn) end as domain_name
        from public.finding_evidence fe join public.events_v2_core e on e.id=fe.event_id
        left join public.event_facts_v2 f on f.event_id=e.id
        left join public.storage_v2_channel channel on channel.id=e.channel_id
        left join public.storage_v2_provider provider on provider.id=e.provider_id
        left join public.domains d on d.id=e.domain_id
        where fe.finding_id=findings.id
    ) witness on true
    cross join lateral (
        select case
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.identities_complete and witness.membership_source
                and witness.membership_count=witness.retained_count and witness.membership_identities=1
            then jsonb_build_array('membership',findings.rule_code,witness.domain_id,witness.server_id,
                witness.member_sid,witness.group_sid,witness.day)
            when witness.retained_count=findings.evidence_count and witness.retained_count>0
                and witness.source_complete and witness.membership_count=0 and witness.source_days=1
                and nullif(btrim(findings.target),'') is not null and length(findings.target)<=2048
            then jsonb_build_array('object',findings.rule_code,witness.domain_id,witness.server_id,
                findings.target,witness.day)
            else jsonb_build_array('finding',findings.id)
        end as key
    ) raw_cohort
    cross join lateral (
        select case when length(raw_cohort.key::text)<=4096 then raw_cohort.key
                    else jsonb_build_array('finding',findings.id) end as key
    ) cohort
 where public.is_semantic_finding_published_v1(findings.id) and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or public.semantic_finding_in_domains_v265(findings.id,null)) and not coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false) and not public.semantic_finding_suppressed_v160(findings.id,findings.rule_code) and ((p_filters->>'severity') is null or findings.severity=p_filters->>'severity') and ((p_filters->>'status') is null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end)=p_filters->>'status') and (coalesce(p_filters->>'population','open')<>'attention' or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated')) and (coalesce(p_filters->>'population','open')<>'open' or p_filters->>'status' is not null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated','active','review')) and findings.last_seen_utc::timestamptz >= p_start and findings.last_seen_utc::timestamptz < p_end
    ), queue_groups as (
        select * from queue_population where representative_rank=1
    ) , individual_counts as (
        select count(*) as total from public.findings_active findings
        left join lateral (select s.* from public.semantic_suppressions s
            join public.auth_users u on u.id=s.responsible_user_id
            where s.finding_id=findings.id and s.kind='risk_acceptance'
            order by s.id desc limit 1) risk on true where public.is_semantic_finding_published_v1(findings.id) and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or public.semantic_finding_in_domains_v265(findings.id,null)) and not coalesce(risk.state='active' and risk.expires_at > statement_timestamp(),false) and not public.semantic_finding_suppressed_v160(findings.id,findings.rule_code) and ((p_filters->>'severity') is null or findings.severity=p_filters->>'severity') and ((p_filters->>'status') is null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end)=p_filters->>'status') and (coalesce(p_filters->>'population','open')<>'attention' or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated')) and (coalesce(p_filters->>'population','open')<>'open' or p_filters->>'status' is not null or (case when risk.state='active' and risk.expires_at <= statement_timestamp()
        then case when coalesce(findings.repeat_count,0)>0 then 'repeated' else 'new' end
        else findings.status end) in ('new','confirmed','repeated','active','review')) and findings.last_seen_utc::timestamptz >= p_start and findings.last_seen_utc::timestamptz < p_end
    ), cohort_counts as (select count(*) as total from queue_groups)
    select jsonb_build_object('counts',jsonb_build_object(
        'individual',(select jsonb_build_object('total',total,'has_more',total>50) from individual_counts),
        'cohorts',(select jsonb_build_object('total',total,'has_more',total>50) from cohort_counts))) into v_result;
    
    v_generated:=clock_timestamp();
    select jsonb_build_object('status',case when status in ('running','idle') then status else 'other' end,
        'heartbeat_at',heartbeat_at,'expected_interval_seconds',expected_interval_seconds,
        'details_json',jsonb_build_object('runtime_mode',case when btrim(details_json->>'runtime_mode')
            in ('facts-v1','investigation-v1','findings-v1') then btrim(details_json->>'runtime_mode') end,
            'manual_runtime',case when details_json->'manual_runtime'='false'::jsonb then false else true end))
    into v_heartbeat from public.runtime_worker_heartbeats where worker_name='semantic' limit 1;
    begin
        select coalesce(last_status='failed',false) into v_refresh from public.findings_refresh_state
            where pipeline_name='events_to_findings_v1';
        perform max(id) from public.events_v2_core;
    exception when others then v_refresh:=true;
    end;
    begin
        select coalesce(array_agg(id order by id),'{}'::bigint[]) into v_domains from public.domains;
        if cardinality(v_domains)>0 then
            v_page:=public.read_password_detection_coverage(v_domains);
            v_coverage:=jsonb_typeof(v_page) is distinct from 'object'
                or jsonb_typeof(v_page->'rows') is distinct from 'array'
                or jsonb_typeof(v_page->'has_more') is distinct from 'boolean'
                or (v_page->>'has_more')::boolean or jsonb_array_length(v_page->'rows')=0
                or exists(select 1 from jsonb_array_elements(v_page->'rows') r
                    where r->>'policy_state' in ('unknown','disabled_last_known')
                       or r->>'frozen_episode_count'<>'0'
                       or r->>'policy_state'='enabled' and r->>'status'<>'healthy');
        end if;
    exception when others then v_coverage:=true;
    end;
    return v_result || jsonb_build_object('quality_inputs',jsonb_build_object(
        'heartbeat',coalesce(v_heartbeat,'{}'::jsonb),'refresh_limited',coalesce(v_refresh,false),
        'coverage_incomplete',coalesce(v_coverage,false)), 'generated_at',v_generated);
end $$;
alter function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) owner to adlog_storage_owner;
revoke all on function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) from public,adlog_report_producer;
grant execute on function public.report_security_candidate_counts(jsonb,text,timestamptz,timestamptz) to adlog_report_producer_owner;

-- END GENERATED SECURITY COUNTS

create function public.report_file_candidate_roots(p_filters jsonb,p_start timestamptz,p_end timestamptz)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare roots jsonb; root jsonb; rows jsonb:='[]'::jsonb; kind jsonb;
begin
    if p_filters is null or jsonb_typeof(p_filters)<>'object'
       or exists(select 1 from jsonb_object_keys(p_filters) k where k not in ('operation','source_kind'))
       or exists(select 1 from jsonb_each(p_filters) e where jsonb_typeof(e.value)<>'string')
       or p_start is null or p_end is null or p_end<=p_start or p_end-p_start>interval '31 days' then
        raise exception 'report_candidate_parameters_invalid';
    end if;
    roots:=sli_plugin_file_audit.report_roots();
    -- Match the report's initial, pre-filter root-limit boundary.
    if jsonb_array_length(roots)>1000 then
        return jsonb_build_object('report_key','file-audit.mass-operations','quality','partial',
            'counts','{}'::jsonb,'roots','[]'::jsonb,'root_limit',true);
    end if;
    for root in select value from jsonb_array_elements(roots) loop
        kind:=case when root ? 'source_kind' then root->'source_kind' else '"server"'::jsonb end;
        if p_filters ? 'source_kind' and kind is distinct from p_filters->'source_kind' then continue; end if;
        -- Metadata only. The owner-admitted subset is read at publication;
        -- an unreadable root denied by ACL cannot poison the authorized report.
        rows:=rows||jsonb_build_array(jsonb_build_object('agent_id',root->'agent_id',
            'source_instance_id',root->'source_instance_id','collection_scope_id',root->'collection_scope_id',
            'source_kind',kind));
    end loop;
    return jsonb_build_object('report_key','file-audit.mass-operations','quality','partial',
        'counts','{}'::jsonb,'roots',rows,'root_limit',false);
end $$;
alter function public.report_file_candidate_roots(jsonb,timestamptz,timestamptz) owner to adlog_file_audit_owner;
revoke all on function public.report_file_candidate_roots(jsonb,timestamptz,timestamptz) from public,adlog_report_producer;
grant execute on function public.report_file_candidate_roots(jsonb,timestamptz,timestamptz) to adlog_report_producer_owner;

create function public.report_schedule_candidates(p_job uuid,p_lease uuid)
returns jsonb language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare principal oid; claim record; schedule record; result jsonb;
begin
    principal:=public.report_producer_identity();
    claim:=public.report_locked_claim(p_job,p_lease);
    select s.* into schedule from public.report_schedules s where s.id=claim.schedule_id
        and s.enabled and s.revision=claim.schedule_revision for share;
    if not found or claim.acl_facts is null then
        raise exception 'report_schedule_lease_denied' using errcode='42501';
    end if;
    if claim.candidates is not null then return claim.candidates; end if;
    begin
        if schedule.report_key='security.problems' then
            result:=public.report_security_candidate_counts(schedule.filters,schedule.timezone,claim.period_from,claim.slot);
        elsif schedule.report_key='file-audit.mass-operations' then
            result:=public.report_file_candidate_roots(schedule.filters,claim.period_from,claim.slot);
        else raise exception 'report_schedule_report_denied';
        end if;
    exception when others then
        -- Fixed quality only; never retain exception text/source values.
        result:=jsonb_build_object('report_key',schedule.report_key,'quality','error','counts','{}'::jsonb,'roots','[]'::jsonb);
        if schedule.report_key='file-audit.mass-operations' then result:=result||'{"root_limit":false}'::jsonb; end if;
    end;
    result:=result||jsonb_build_object('report_key',schedule.report_key);
    if octet_length(result::text)>262144 then raise exception 'report_candidate_limit'; end if;
    update public.report_producer_claims set candidates=result where id=p_job and lease=p_lease;
    return result;
end $$;
alter function public.report_schedule_candidates(uuid,uuid) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_candidates(uuid,uuid) from public;
grant execute on function public.report_schedule_candidates(uuid,uuid) to adlog_report_producer;

-- The API's existing run INSERT privilege cannot forge this private provenance.
create table public.report_producer_publications (
    run_id uuid primary key references public.report_schedule_runs(id),
    owner_user_id bigint not null,
    selection jsonb not null,
    binding_snapshot jsonb not null,
    root_scope jsonb not null
);
alter table public.report_producer_publications owner to adlog_report_producer_owner;
revoke all on public.report_producer_publications from public,adlog_user,adlog_report_producer,adlog_notification_worker;
grant update(revision) on public.notification_subscriptions,public.notification_channels to adlog_report_producer_owner;

create function public.report_candidate_quality(p_data jsonb,p_count bigint,p_more boolean) returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare heartbeat jsonb; generated timestamptz; stamp timestamptz; expected bigint; fresh boolean;
    quality text;
begin
    if p_data->>'quality' in ('error','denied','not_collected','processing') then return p_data->>'quality'; end if;
    if p_data->>'report_key'='file-audit.mass-operations' then return 'partial'; end if;
    heartbeat:=p_data->'quality_inputs'->'heartbeat';
    generated:=(p_data->>'generated_at')::timestamptz;
    stamp:=(heartbeat->>'heartbeat_at')::timestamptz;
    expected:=greatest(1,coalesce(nullif((heartbeat->>'expected_interval_seconds')::bigint,0),30));
    fresh:=stamp is not null and greatest(0,trunc(extract(epoch from generated-stamp)))<=greatest(60,expected*2+30);
    if heartbeat->'details_json'->>'runtime_mode'='findings-v1' and not fresh then return 'stale'; end if;
    if heartbeat->'details_json'->>'runtime_mode' is distinct from 'findings-v1'
       or heartbeat->>'status' not in ('running','idle')
       or heartbeat->'details_json'->'manual_runtime' is distinct from 'false'::jsonb then return 'partial'; end if;
    quality:=case when p_count=0 then 'empty' else 'ok' end;
    if coalesce((p_data->'quality_inputs'->>'refresh_limited')::boolean,false)
       or coalesce((p_data->'quality_inputs'->>'coverage_incomplete')::boolean,false) or p_more then
        quality:='partial';
    end if;
    return quality;
end $$;
alter function public.report_candidate_quality(jsonb,bigint,boolean) owner to adlog_report_producer_owner;
revoke all on function public.report_candidate_quality(jsonb,bigint,boolean) from public,adlog_report_producer;

grant usage on schema sli_plugin_file_audit to adlog_storage_owner;
grant execute on function sli_plugin_file_audit.report_rows(jsonb,text,timestamptz,timestamptz,text,boolean,text,text,jsonb,integer) to adlog_storage_owner;

create function public.report_file_projected_counts(p_roots jsonb,p_qw_roots jsonb,p_filters jsonb,
    p_start timestamptz,p_end timestamptz) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare page jsonb; ids jsonb;
begin
    -- The interactive file report conditionally performs this exact detail
    -- query. Rows/evidence stay inside SQL; only success/failure can leave.
    page:=sli_plugin_file_audit.report_rows(p_roots,'mass-operations',p_start,p_end,
        null,true,null,p_filters->>'operation',null,50);
    if jsonb_array_length(p_qw_roots)>0 and jsonb_array_length(page->'items')>0 then
        select jsonb_agg(item->'id') into ids from jsonb_array_elements(page->'items') item;
        perform public.read_file_ransom_details(p_qw_roots,ids);
    end if;
    return jsonb_build_object('quality','partial','total',page->'filtered_count','has_more',page->'has_more');
exception when others then
    return jsonb_build_object('quality','error','total',null,'has_more',false);
end $$;
alter function public.report_file_projected_counts(jsonb,jsonb,jsonb,timestamptz,timestamptz) owner to adlog_storage_owner;
revoke all on function public.report_file_projected_counts(jsonb,jsonb,jsonb,timestamptz,timestamptz) from public,adlog_report_producer;
grant execute on function public.report_file_projected_counts(jsonb,jsonb,jsonb,timestamptz,timestamptz) to adlog_report_producer_owner;

create function public.report_schedule_failure(p_job uuid,p_lease uuid,p_quality text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare claim record; key text;
begin
    claim:=public.report_locked_claim(p_job,p_lease);
    if p_quality not in ('error','denied') then raise exception 'report_failure_invalid'; end if;
    select report_key into key from public.report_schedules where id=claim.schedule_id;
    update public.report_producer_claims set candidates=jsonb_build_object(
        'report_key',key,'quality',p_quality,'counts','{}'::jsonb,'roots','[]'::jsonb,
        'root_limit',false) where id=p_job and lease=p_lease;
    if key='security.problems' then
        update public.report_producer_claims set candidates=candidates-'root_limit' where id=p_job and lease=p_lease;
    end if;
    return true;
end $$;
alter function public.report_schedule_failure(uuid,uuid,text) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_failure(uuid,uuid,text) from public;
grant execute on function public.report_schedule_failure(uuid,uuid,text) to adlog_report_producer;

create function public.report_schedule_publish(p_job uuid,p_lease uuid,p_selection jsonb) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare claim record; schedule record; fresh jsonb; staged jsonb; selection_keys text[];
    idx integer; ids integer[]:='{}'; qw_ids integer[]:='{}'; qw_roots jsonb:='[]'::jsonb;
    total bigint:=0; item_count bigint; more boolean:=false;
    quality text; variant text; root jsonb; roots jsonb:='[]'::jsonb;
    run_id uuid; jobs integer; live_total bigint; live_reports bigint; projected jsonb;
begin
    claim:=public.report_locked_claim(p_job,p_lease);
    select * into schedule from public.report_schedules where id=claim.schedule_id;
    if exists(select 1 from public.report_schedule_runs r where r.schedule_id=schedule.id
        and r.schedule_revision=schedule.revision and r.slot=claim.slot) then
        return '{"published":false,"jobs":0}'::jsonb;
    end if;
    if claim.acl_facts is null or claim.candidates is null then raise exception 'report_not_staged'; end if;
    -- Acquire configuration locks before the last authoritative facts read.
    perform sub.id from public.notification_subscriptions sub
        join public.report_schedule_subscriptions b on b.subscription_id=sub.id
        where b.schedule_id=schedule.id order by sub.id for share of sub;
    perform ch.kind from public.notification_channels ch where ch.kind in (
        select sub.channel from public.notification_subscriptions sub
        join public.report_schedule_subscriptions b on b.subscription_id=sub.id where b.schedule_id=schedule.id)
        order by ch.kind for share of ch;
    -- Re-read the fixed DB facts at publication time, including expirations.
    -- No producer-supplied ACL boolean/digest is used as evidence of permission.
    fresh:=public.report_schedule_acl_facts(p_job,p_lease);
    if fresh-'evaluated_at' is distinct from claim.acl_facts then
        raise exception 'report_schedule_access_changed' using errcode='42501';
    end if;
    select array_agg(k order by k) into selection_keys from jsonb_object_keys(p_selection) k;
    if selection_keys is distinct from array['include_count','owner_state','qw_root_indexes','root_indexes','variant']::text[]
       or jsonb_typeof(p_selection->'include_count') is distinct from 'boolean'
       or jsonb_typeof(p_selection->'root_indexes') is distinct from 'array'
       or jsonb_array_length(p_selection->'root_indexes')>1000
       or jsonb_typeof(p_selection->'qw_root_indexes') is distinct from 'array'
       or jsonb_array_length(p_selection->'qw_root_indexes')>1000
       or p_selection->>'owner_state' not in ('denied','readable') then
        raise exception 'report_selection_invalid';
    end if;
    staged:=claim.candidates; variant:=p_selection->>'variant';
    if p_selection->>'owner_state'='denied' then
        if (p_selection->>'include_count')::boolean then raise exception 'report_selection_invalid'; end if;
        quality:='denied'; total:=null;
    elsif staged->>'quality' in ('error','denied','processing') then
        quality:=staged->>'quality'; total:=null;
    elsif schedule.report_key='security.problems' then
        if variant is null or variant not in ('individual','cohorts')
           or jsonb_array_length(p_selection->'root_indexes')<>0
           or jsonb_array_length(p_selection->'qw_root_indexes')<>0 then raise exception 'report_selection_invalid'; end if;
        total:=(staged->'counts'->variant->>'total')::bigint;
        more:=(staged->'counts'->variant->>'has_more')::boolean;
        quality:=public.report_candidate_quality(staged,total,more);
    else
        if variant is not null then raise exception 'report_selection_invalid'; end if;
        for idx in select value::text::integer from jsonb_array_elements(p_selection->'root_indexes') loop
            if idx<0 or idx>=jsonb_array_length(staged->'roots') or idx=any(ids) then
                raise exception 'report_selection_invalid';
            end if;
            ids:=array_append(ids,idx); root:=staged->'roots'->idx;
            roots:=roots||jsonb_build_array(jsonb_build_object('agent_id',root->'agent_id',
                'source_instance_id',root->'source_instance_id','collection_scope_id',root->'collection_scope_id'));
        end loop;
        for idx in select value::text::integer from jsonb_array_elements(p_selection->'qw_root_indexes') loop
            if not idx=any(ids) or idx=any(qw_ids) then raise exception 'report_selection_invalid'; end if;
            qw_ids:=array_append(qw_ids,idx); root:=staged->'roots'->idx;
            qw_roots:=qw_roots||jsonb_build_array(jsonb_build_object('agent_id',root->'agent_id',
                'source_instance_id',root->'source_instance_id','collection_scope_id',root->'collection_scope_id'));
        end loop;
        if (staged->>'root_limit')::boolean then
            if cardinality(ids)>0 then raise exception 'report_selection_invalid'; end if;
            quality:='partial'; total:=null;
        elsif cardinality(ids)=0 then quality:='not_collected'; total:=null;
        else
            projected:=public.report_file_projected_counts(roots,qw_roots,schedule.filters,claim.period_from,claim.slot);
            quality:=projected->>'quality'; total:=(projected->>'total')::bigint;
            more:=(projected->>'has_more')::boolean;
        end if;
    end if;
    item_count:=case when (p_selection->>'include_count')::boolean and quality in ('ok','empty','partial','stale') then total end;
    select count(*) into jobs from (select distinct b->>'recipient_user_id',b->>'channel'
        from jsonb_array_elements(fresh->'bindings') b) bindings;
    if jobs=0 then return '{"published":false,"jobs":0}'::jsonb; end if;
    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    select count(*),count(*) filter(where object_kind='report_schedule') into live_total,live_reports
        from public.notification_outbox where state in ('pending','sending','retry');
    -- Explicit proposed admission policy, not a promise about delivery latency.
    if live_total+jobs>9000 or live_reports+jobs>1000 then
        raise exception 'notification_queue_full' using errcode='P7001';
    end if;
    run_id:=gen_random_uuid();
    insert into public.report_schedule_runs(id,schedule_id,schedule_revision,report_key,slot,period_from,period_to,
        generated_at,quality,item_count,truncated,delayed,language)
    values(run_id,schedule.id,schedule.revision,schedule.report_key,claim.slot,claim.period_from,claim.slot,
        claim.checked_at,quality,item_count,more,claim.checked_at-claim.slot>=interval '1 minute',schedule.language);
    insert into public.report_producer_publications(run_id,owner_user_id,selection,binding_snapshot,root_scope)
        values(run_id,schedule.owner_user_id,p_selection,fresh->'bindings',roots);
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,recipient_user_id,channel)
    select gen_random_uuid(),(b->>'id')::uuid,(b->>'revision')::bigint,'report_schedule',run_id,
        (b->>'recipient_user_id')::bigint,b->>'channel'
    from (select distinct on(b->>'recipient_user_id',b->>'channel') b
          from jsonb_array_elements(fresh->'bindings') b
          order by b->>'recipient_user_id',b->>'channel',b->>'id') chosen;
    return jsonb_build_object('published',true,'jobs',jobs,'run_id',run_id);
end $$;
alter function public.report_schedule_publish(uuid,uuid,jsonb) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_publish(uuid,uuid,jsonb) from public;
grant execute on function public.report_schedule_publish(uuid,uuid,jsonb) to adlog_report_producer;

-- PostgreSQL requires some UPDATE privilege for SELECT ... FOR UPDATE.
-- This NOLOGIN definer receives only a single column privilege for its fixed
-- job lock; the delivery role/login receives no new direct UPDATE privilege.
grant update(id) on public.notification_outbox to adlog_report_producer_owner;

create function public.report_delivery_identity() returns void
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not exists(select 1 from pg_catalog.pg_roles r where r.rolname=session_user and r.rolcanlogin
        and not r.rolsuper and not r.rolbypassrls and not r.rolcreatedb and not r.rolcreaterole
        and not r.rolreplication and pg_has_role(session_user,'adlog_notification_worker','MEMBER'))
       or exists(select 1 from pg_catalog.pg_roles r where r.rolname in ('adlog_storage_owner','adlog_user',
            'adlog_file_audit_owner','adlog_report_producer','adlog_report_producer_owner',
            'pg_read_all_data','pg_write_all_data') and pg_has_role(session_user,r.oid,'MEMBER')) then
        raise exception 'report_delivery_identity_denied' using errcode='42501';
    end if;
end $$;
alter function public.report_delivery_identity() owner to adlog_report_producer_owner;
revoke all on function public.report_delivery_identity() from public,adlog_user,adlog_report_producer,adlog_notification_worker;

-- Only claim-policy metadata. No service receives direct counter access.
create table public.report_delivery_fairness (
    singleton boolean primary key default true check(singleton),
    alert_streak integer not null default 0 check(alert_streak between 0 and 3)
);
alter table public.report_delivery_fairness owner to adlog_report_producer_owner;
revoke all on public.report_delivery_fairness from public,adlog_user,adlog_report_producer,adlog_notification_worker;
insert into public.report_delivery_fairness values(true,0);
-- Fixed claim function alone writes these existing job metadata columns.
grant update(state,lease_token,lease_until,attempts,updated_at) on public.notification_outbox to adlog_report_producer_owner;

create function public.notification_claim_fair() returns setof public.notification_outbox
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare streak integer; job public.notification_outbox;
begin
    perform public.report_delivery_identity();
    select alert_streak into streak from public.report_delivery_fairness where singleton for update;
    if not found then raise exception 'notification_claim_policy_missing'; end if;
    -- Proposed 3:1 fair share when both classes are eligible. Report-only
    -- claims reset the counter, so a newly arriving alert is preferred next.
    -- This is persistent across processes; no cadence/timer window is needed.
    with candidate as (
        select j.id from public.notification_outbox j
        where ((j.state in ('pending','retry') and j.available_at<=clock_timestamp())
           or (j.state='sending' and j.lease_until<=clock_timestamp()))
          and j.channel in ('smtp','telegram')
          and j.object_kind in ('test_problem','semantic_finding','report_schedule')
          and (j.channel<>'telegram' or exists(select 1 from public.notification_channels c
              where c.kind='telegram' and c.next_delivery_at<=clock_timestamp()))
        order by case when streak>=3 then case when j.object_kind='report_schedule' then 0 else 1 end
                      else case when j.object_kind='report_schedule' then 1 else 0 end end,
                 j.created_at,j.id for update skip locked limit 1
    ) update public.notification_outbox j set state='sending',lease_token=gen_random_uuid(),
        lease_until=clock_timestamp()+interval '60 seconds',attempts=j.attempts+1,updated_at=clock_timestamp()
      from candidate where j.id=candidate.id returning j.* into job;
    if not found then return; end if;
    update public.report_delivery_fairness set alert_streak=
        case when job.object_kind='report_schedule' then 0 else least(3,streak+1) end where singleton;
    return next job;
end $$;
alter function public.notification_claim_fair() owner to adlog_report_producer_owner;
revoke all on function public.notification_claim_fair() from public,adlog_user,adlog_report_producer;
grant execute on function public.notification_claim_fair() to adlog_notification_worker;

create function public.report_schedule_delivery(p_job uuid,p_lease uuid) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_schedule_id uuid; job record; schedule record; run record; subscription record;
    provenance record; binding jsonb; channel_revision bigint;
begin
    perform public.report_delivery_identity();
    -- Schedule precedes job/subscription locks, matching configuration edits.
    select s.id into v_schedule_id from public.report_schedules s
        join public.report_schedule_runs r on r.schedule_id=s.id
        join public.notification_outbox j on j.object_id=r.id
        join public.report_producer_publications p on p.run_id=r.id
        where j.id=p_job and j.object_kind='report_schedule' and j.state='sending'
          and j.lease_token=p_lease and j.lease_until>clock_timestamp()
          and s.enabled and s.revision=r.schedule_revision and s.report_key=r.report_key
        for share of s;
    if not found then return null; end if;
    select * into job from public.notification_outbox j where j.id=p_job and j.state='sending'
        and j.lease_token=p_lease and j.lease_until>clock_timestamp() for update;
    if not found then return null; end if;
    select * into run from public.report_schedule_runs r where r.id=job.object_id;
    select * into schedule from public.report_schedules s where s.id=v_schedule_id;
    select * into provenance from public.report_producer_publications p where p.run_id=run.id;
    select sub.* into subscription from public.notification_subscriptions sub
        join public.report_schedule_subscriptions b on b.subscription_id=sub.id and b.schedule_id=schedule.id
        where sub.id=job.subscription_id and sub.enabled and sub.revision=job.subscription_revision
          and sub.recipient_user_id=job.recipient_user_id and sub.channel=job.channel
          and sub.owner_user_id=schedule.owner_user_id for share of sub;
    if not found or provenance.owner_user_id<>schedule.owner_user_id then return null; end if;
    select b into binding from jsonb_array_elements(provenance.binding_snapshot) b
        where b->>'id'=subscription.id::text and (b->>'revision')::bigint=subscription.revision
          and (b->>'recipient_user_id')::bigint=job.recipient_user_id and b->>'channel'=job.channel;
    if binding is null then return null; end if;
    select revision into channel_revision from public.notification_channels ch where ch.kind=job.channel and ch.enabled;
    if not found or channel_revision<>(binding->>'channel_revision')::bigint then return null; end if;
    return jsonb_build_object('subscription',jsonb_build_object('id',subscription.id,
        'owner_user_id',subscription.owner_user_id,'recipient_user_id',subscription.recipient_user_id,
        'channel',subscription.channel,'enabled',subscription.enabled,'revision',subscription.revision),
        'owner_user_id',schedule.owner_user_id,'channel_revision',channel_revision,
        'selection',provenance.selection,'root_scope',case when run.item_count is null then '[]'::jsonb else provenance.root_scope end,
        'run',jsonb_build_object('id',run.id,'schedule_id',run.schedule_id,'schedule_revision',run.schedule_revision,
            'report_key',run.report_key,'slot',run.slot,'period_from',run.period_from,'period_to',run.period_to,
            'generated_at',run.generated_at,'quality',run.quality,'item_count',run.item_count,'truncated',run.truncated,
            'delayed',run.delayed,'language',run.language,'filters',schedule.filters,'timezone',schedule.timezone));
end $$;
alter function public.report_schedule_delivery(uuid,uuid) owner to adlog_report_producer_owner;
revoke all on function public.report_schedule_delivery(uuid,uuid) from public,adlog_user,adlog_report_producer;
grant execute on function public.report_schedule_delivery(uuid,uuid) to adlog_notification_worker;

insert into public.schema_migrations(version,name) values(285,'report_producer');
commit;
