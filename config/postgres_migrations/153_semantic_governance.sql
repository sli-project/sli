-- Explicit, versioned admission and scoped suppression. No findings are removed.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_semantic_governance_v153'));
do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 153 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from schema_migrations where version=152 and name='plugin_state') then
        raise exception 'migration 153 requires exact migration 152 plugin_state';
    end if;
    if not exists(select 1 from schema_migrations where version=146 and name='platform_settings') then
        raise exception 'migration 153 requires migration 146 platform_settings';
    end if;
    if exists(select 1 from schema_migrations where version=153 and name <> 'semantic_governance') then
        raise exception 'migration 153 is owned by another contract';
    end if;
end $$;
-- The owner role needs REFERENCES on domains for the scoped suppression FK (pattern of 019).
grant references on domains to adlog_storage_owner;
set local role adlog_storage_owner;

create table semantic_suppressions (
    id bigint generated always as identity primary key,
    semantic_type text not null check (semantic_type ~ '^[a-z][a-z0-9_.-]{1,159}$'),
    domain_id bigint not null references domains(id),
    scope_kind text not null check (scope_kind in ('subject_sid','bucket')),
    scope_value text not null,
    reason text not null check (length(trim(reason)) between 1 and 2000),
    expires_at timestamptz not null,
    created_at timestamptz not null default clock_timestamp(),
    created_by text not null check (length(trim(created_by)) between 1 and 256),
    changed_by text check (length(trim(changed_by)) between 1 and 256),
    state text not null default 'active' check (state in ('active','expired','revoked')),
    check (expires_at > created_at and expires_at <= created_at + interval '2160 hours'),
    check ((scope_kind='subject_sid' and length(scope_value)<=184 and scope_value ~ '^S-1-([0-9]+-)+[0-9]+$')
        or (scope_kind='bucket' and scope_value in
            ('machine_account','system_account','known_gpo_refresh','interactive_admin','unknown')))
);
create index semantic_suppressions_active on semantic_suppressions(semantic_type,domain_id,expires_at)
    where state='active';
create table semantic_policy_admission (
    policy_id text not null,
    policy_version integer not null,
    enabled boolean not null default false,
    updated_by text not null check (length(trim(updated_by)) between 1 and 256),
    updated_at timestamptz not null default now(),
    primary key(policy_id,policy_version),
    foreign key(policy_id,policy_version) references semantic_risk_policies(policy_id,policy_version)
);
-- Empty overrides preserve the current lifecycle. Newly registered draft,
-- validated, test and shadow versions remain default-off for publication.
create table semantic_control_audit (
    id bigint generated always as identity primary key,
    action text not null,
    target text not null,
    actor text not null,
    occurred_at timestamptz not null default clock_timestamp(),
    details jsonb not null
);
create function semantic_control_audit_v160() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
begin
    if TG_TABLE_NAME='semantic_suppressions' then
        if TG_OP='UPDATE' and (old.state <> 'active' or new.state not in ('expired','revoked')) then
            raise exception 'suppression transition is immutable';
        end if;
        if TG_OP='UPDATE' and (to_jsonb(new)-'state'-'changed_by') <> (to_jsonb(old)-'state'-'changed_by') then
            raise exception 'suppression scope and expiry are immutable';
        end if;
        insert into public.semantic_control_audit(action,target,actor,occurred_at,details)
        values ('suppression_' || case when TG_OP='INSERT' then 'create' else new.state end,
            new.id::text,coalesce(new.changed_by,new.created_by),
            case when new.state='expired' then new.expires_at else clock_timestamp() end,
            jsonb_build_object('rule',to_jsonb(new)));
    else
        insert into public.semantic_control_audit(action,target,actor,details)
        values ('policy_admission',new.policy_id || ':' || new.policy_version,new.updated_by,
            jsonb_build_object('enabled',new.enabled,'previous',case when TG_OP='UPDATE' then old.enabled else null end));
    end if;
    return new;
end $$;
create trigger semantic_suppressions_audit after insert or update on semantic_suppressions
    for each row execute function semantic_control_audit_v160();
create trigger semantic_policy_admission_audit after insert or update on semantic_policy_admission
    for each row execute function semantic_control_audit_v160();

create function expire_semantic_suppressions_v160() returns integer
language plpgsql security definer set search_path=pg_catalog,public as $$
declare affected integer;
begin
    with expired as (select id from public.semantic_suppressions
        where state='active' and expires_at <= clock_timestamp() order by expires_at,id
        for update skip locked limit 100)
    update public.semantic_suppressions s set state='expired',changed_by='system:expiry' from expired where s.id=expired.id;
    get diagnostics affected = row_count;
    return affected;
end $$;

create function semantic_policy_mode_v160(p_id text,p_version integer,p_state text) returns text
language sql stable security definer set search_path=pg_catalog,public as $$
    select case
        when p_state not in ('test','shadow','enabled') then null
        when a.enabled is false then null
        when a.enabled is true and p_state in ('shadow','enabled') then 'enabled'
        else p_state end
    from (select 1) seed left join public.semantic_policy_admission a
        on a.policy_id=p_id and a.policy_version=p_version
$$;

-- The classifier reads at most 21 linked 4719 observations, plus bounded
-- session/GPO context. It does not read raw payloads or alter stored findings.
create function semantic_finding_review_v160(p_id bigint) returns jsonb
language sql stable security definer set search_path=pg_catalog,public as $$
    with samples as materialized (
        select distinct e.id,e.event_id,e.domain_id,e.server_id,e.subject_user_sid,e.subject_user_name,
            facts.process_name,
            e.logon_id,e.correlation_id,e.time_created_utc
        from public.finding_evidence fe join public.events_v2_core e on e.id=fe.event_id
        left join public.event_facts_v2 facts on facts.event_id=e.id
        where fe.finding_id=p_id
        order by e.time_created_utc desc,e.id desc limit 21
    ), review_samples as materialized (
        select * from samples order by time_created_utc desc,id desc limit 20
    ), classified as (
        select s.*,
            case
            when s.event_id <> 4719 then 'unknown'
            when (s.process_name is null or lower(s.process_name) ~ '(^|[\\/])(gpupdate|svchost|gpscript)[.]exe$')
                and exists(select 1 from public.events_v2_core g
                join public.storage_v2_provider provider on provider.id=g.provider_id
                where g.server_id=s.server_id and g.domain_id=s.domain_id
                and s.correlation_id is not null and s.correlation_id <> ''
                and g.correlation_id=s.correlation_id
                and provider.value='Microsoft-Windows-GroupPolicy'
                and g.event_id in (4000,4004,8000,8004)
                and g.time_created_utc between s.time_created_utc-interval '5 minutes'
                    and s.time_created_utc+interval '5 minutes' limit 1) then 'known_gpo_refresh'
            when s.subject_user_sid in ('S-1-5-18','S-1-5-19','S-1-5-20') then 'system_account'
            when s.subject_user_sid is not null and right(s.subject_user_name,1)='$' then 'machine_account'
            when exists(select 1 from public.events_v2_core l
                join public.event_facts_v2 facts on facts.event_id=l.id
                where l.server_id=s.server_id and l.domain_id=s.domain_id
                and s.logon_id is not null and s.logon_id <> '' and l.logon_id=s.logon_id
                and l.event_id=4624 and l.target_user_sid=s.subject_user_sid
                and facts.logon_type in ('2','10')
                and l.time_created_utc between s.time_created_utc-interval '12 hours' and s.time_created_utc
                and exists(select 1 from public.events_v2_core privilege
                    where privilege.server_id=s.server_id and privilege.domain_id=s.domain_id
                    and privilege.logon_id=s.logon_id and privilege.event_id=4672
                    and privilege.subject_user_sid=s.subject_user_sid
                    and privilege.time_created_utc between l.time_created_utc and s.time_created_utc limit 1)
                limit 1) then 'interactive_admin'
            else 'unknown' end as bucket
        from review_samples s
    )
    select jsonb_build_object('kind','hint','verdict',false,
        'bucket',case when count(distinct bucket)=1 then min(bucket) else 'unknown' end,
        'sample_count',count(*),'truncated',(select count(*)>20 from samples),
        'process_observed',coalesce(bool_or(process_name is not null),false),
        'has_audit_change',coalesce(bool_or(event_id=4719),false),
        'mixed',count(distinct bucket)>1,
        'gpo_correlated',coalesce(bool_and(bucket='known_gpo_refresh'),false),
        'machine_account',coalesce(bool_and(bucket='machine_account'),false),
        'interactive_session',coalesce(bool_and(bucket='interactive_admin'),false),
        'privileged_session',coalesce(bool_and(bucket='interactive_admin'),false),
        'domain_id',case when count(distinct domain_id)=1 then min(domain_id) else null end,
        'subject_sid',case when count(subject_user_sid)=count(*) and count(distinct subject_user_sid)=1
            then min(subject_user_sid) else null end)
    from classified
$$;

create function semantic_finding_suppressed_v160(p_id bigint,p_type text) returns boolean
language sql stable security definer set search_path=pg_catalog,public as $$
    select exists(select 1 from public.semantic_suppressions rule,
        lateral (select public.semantic_finding_review_v160(p_id) as hint) review
        where rule.state='active' and rule.expires_at > statement_timestamp()
        and rule.semantic_type=p_type and rule.domain_id=(hint->>'domain_id')::bigint
        and ((rule.scope_kind='bucket' and rule.scope_value=hint->>'bucket'
                and (hint->>'has_audit_change')::boolean is true
                and (hint->>'truncated')::boolean is false)
            or (rule.scope_kind='subject_sid' and rule.scope_value=hint->>'subject_sid'))
        -- A subject-scoped rule cannot spill into another domain/subject,
        -- even when a finding contains more evidence than the hint sample.
        and not exists(select 1 from public.finding_evidence fe
            join public.events_v2_core e on e.id=fe.event_id
            where fe.finding_id=p_id
            and (e.domain_id <> rule.domain_id or e.subject_user_sid is distinct from hint->>'subject_sid')))
$$;

revoke all on function semantic_control_audit_v160() from public;
revoke all on function expire_semantic_suppressions_v160() from public;
revoke all on function semantic_policy_mode_v160(text,integer,text) from public;
revoke all on function semantic_finding_review_v160(bigint) from public;
revoke all on function semantic_finding_suppressed_v160(bigint,text) from public;
grant execute on function semantic_policy_mode_v160(text,integer,text),expire_semantic_suppressions_v160()
    to adlog_user,adlog_semantic_worker;
grant execute on function semantic_finding_review_v160(bigint),semantic_finding_suppressed_v160(bigint,text)
    to adlog_user;
grant select,insert on semantic_suppressions to adlog_user;
grant update(state,changed_by) on semantic_suppressions to adlog_user;
grant select,insert,update on semantic_policy_admission to adlog_user;
grant select on semantic_risk_policies,semantic_control_audit to adlog_user;
grant update(updated_at) on semantic_risk_policies to adlog_user;
grant select on semantic_policy_admission to adlog_semantic_worker;
grant usage,select on sequence semantic_suppressions_id_seq to adlog_user;

insert into schema_migrations(version,name) values(153,'semantic_governance');
commit;
