-- Dedicated delivery identity: queue DML and access resolution reads only.
begin;
select pg_advisory_xact_lock(hashtext('sli_telegram_delivery_v261'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=259 and name='admin_problem_evidence')
       or exists(select 1 from public.schema_migrations where version>=261) then
        raise exception 'migration 261 prerequisites failed';
    end if;
    if not exists(select 1 from pg_roles where rolname='adlog_notification_worker') then
        create role adlog_notification_worker nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
    end if;
end $$;
grant usage on schema public to adlog_notification_worker;
grant select on public.schema_migrations, public.notification_outbox, public.notification_channels,
    public.notification_subscriptions to adlog_notification_worker;
grant update(state,attempts,lease_token,lease_until,available_at,result_code,updated_at)
    on public.notification_outbox to adlog_notification_worker;
grant update(next_delivery_at) on public.notification_channels to adlog_notification_worker;
-- PostgreSQL row locks require UPDATE privilege, even for FOR SHARE.
grant update(revision) on public.notification_subscriptions to adlog_notification_worker;
grant insert on public.notification_attempts to adlog_notification_worker;
grant select(id,username,role,is_active) on public.auth_users to adlog_notification_worker;
grant select on public.access_platform_owners, public.access_group_members, public.access_groups,
    public.access_role_packages, public.access_packages, public.access_subject_packages,
    public.access_package_capabilities, public.access_capabilities, public.access_capability_assignments,
    public.access_package_reports, public.access_report_assignments, public.report_registry_v4,
    public.report_datasets_v4, public.report_access_requests_v4, public.user_report_preferences
    to adlog_notification_worker;
-- Expose schema metadata required by the access guard, without audit row reads.
grant references on public.access_audit_v4 to adlog_notification_worker;
grant execute on function public.notification_finding_object(uuid) to adlog_notification_worker;
set local role adlog_storage_owner;
-- Return a fixed category and reference, never source names or evidence.
create function public.notification_finding_brief(p_scenario_id uuid)
returns table(finding_id bigint, notification_kind text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select p.finding_id, case s.scenario_kind
        when 'qw.nps-denials' then 'remote_access'
        when 'qw.account-decoy' then 'account_decoy'
        when 'qw.file-decoy' then 'file_decoy'
        when 'qw.account-watch' then 'account_watch'
        else 'security' end
    from public.semantic_finding_publications p join public.semantic_security_scenarios s using(scenario_id)
    where p.scenario_id=p_scenario_id and s.evidence_state='ready'
$$;
revoke all on function public.notification_finding_brief(uuid) from public;
grant execute on function public.notification_finding_brief(uuid) to adlog_notification_worker;
-- All publication producers share the outbox. Telegram admission is limited
-- to newly published high/critical problems, including future producers.
create function public.notification_telegram_severity_gate() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    if new.channel='telegram' and new.object_kind='semantic_finding'
       and new.object_severity is distinct from 'high' and new.object_severity is distinct from 'critical' then
        return null;
    end if;
    return new;
end $$;
revoke all on function public.notification_telegram_severity_gate() from public;
create trigger notification_telegram_severity_gate before insert on public.notification_outbox
    for each row execute function public.notification_telegram_severity_gate();
reset role;
insert into public.schema_migrations(version,name) values(261,'telegram_delivery');
commit;
