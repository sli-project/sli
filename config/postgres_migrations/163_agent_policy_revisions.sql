begin;
select pg_advisory_xact_lock(hashtext('sli_agent_policy_revisions_v163'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 163 requires membership in adlog_storage_owner';
    end if;
    if exists(select 1 from public.schema_migrations where version=163) then
        raise exception 'migration 163 already applied';
    end if;
    if not exists(select 1 from public.schema_migrations where version=162 and name='finding_risk_acceptance')
       or exists(select 1 from public.schema_migrations where version>162) then
        raise exception 'migration 163 requires exact migration 162 finding_risk_acceptance';
    end if;
end $$;
set local role adlog_storage_owner;
alter table public.sli_agents
    add column policy_revision bigint not null default 1 check(policy_revision between 1 and 9007199254740991),
    add column applied_policy_revision bigint not null default 0,
    add column rights_probe jsonb not null default '{}'::jsonb check(jsonb_typeof(rights_probe)='object'),
    add constraint sli_agent_policy_ack_check check(applied_policy_revision between 0 and policy_revision);
grant update(policy_revision,applied_policy_revision,rights_probe) on public.sli_agents to adlog_user;
alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
alter table public.sli_agent_audit add constraint sli_agent_audit_action_check
    check(action in ('token_create','token_list','token_revoke','agent_list','issue','renew','revoke','disable',
                    'module_assign','policy_ack','probe_request','probe_report'));
insert into public.schema_migrations(version,name) values(163,'agent_policy_revisions');
commit;
