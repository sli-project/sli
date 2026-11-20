-- Preparation only: no installation, certificate issuance or policy activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_onboarding_v178'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 178 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=177 and name='agent_removal')
       or exists(select 1 from public.schema_migrations where version>=178) then
        raise exception 'migration 178 requires exact migration 177 agent_removal';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_policy_templates (
    id uuid not null,
    version bigint not null check(version between 1 and 9007199254740991),
    assigned_modules jsonb not null check(jsonb_typeof(assigned_modules)='array' and octet_length(assigned_modules::text)<=65536),
    collection_policy jsonb not null check(jsonb_typeof(collection_policy)='object' and octet_length(collection_policy::text)<=4096),
    policy_sha256 text not null check(policy_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz not null default clock_timestamp(),
    primary key(id,version)
);
create table public.sli_agent_onboarding_copies (
    enrollment_token_id uuid primary key references public.sli_agent_enrollment_tokens(id),
    request_id uuid not null unique references public.sli_agent_group_requests(id),
    template_id uuid not null,
    template_version bigint not null,
    foreign key(template_id,template_version) references public.sli_agent_policy_templates(id,version)
);
alter table public.sli_agent_group_requests drop constraint sli_agent_group_requests_status_check;
alter table public.sli_agent_group_requests add constraint sli_agent_group_requests_status_check
    check(status in ('pending','cancelled','approved'));
alter table public.sli_agents
    add column template_id uuid,
    add column template_version bigint,
    add column template_sha256 text check(template_sha256 ~ '^[0-9a-f]{64}$'),
    add constraint sli_agents_template_version_fk foreign key(template_id,template_version)
        references public.sli_agent_policy_templates(id,version),
    add constraint sli_agents_template_provenance_check check(
        (template_id is null and template_version is null and template_sha256 is null)
        or (template_id is not null and template_version is not null and template_sha256 is not null));
revoke all on public.sli_agent_policy_templates,public.sli_agent_onboarding_copies from public,adlog_user;
-- Append-only versions and selections: runtime cannot rewrite shared policies.
grant select,insert on public.sli_agent_policy_templates,public.sli_agent_onboarding_copies to adlog_user;
grant update(template_id,template_version,template_sha256) on public.sli_agents to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''template_save'',''template_list'',''template_copy'',''onboarding_list'',''onboarding_decision'',''onboarding_batch''))',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(178,'agent_onboarding');
commit;
