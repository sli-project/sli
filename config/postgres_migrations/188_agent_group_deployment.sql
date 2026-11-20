-- Preparation only. Existing migrations remain immutable; no deployment runs.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_group_deployment_v188'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 188 requires membership in adlog_storage_owner';
    end if;
    if not exists(select 1 from public.schema_migrations where version=187 and name='file_audit_rules')
       or exists(select 1 from public.schema_migrations where version>=188) then
        raise exception 'migration 188 requires exact migration 187 file_audit_rules and unused version 188';
    end if;
end $$;
set local role adlog_storage_owner;
create table public.sli_agent_enrollment_groups (
    id uuid primary key,
    domain_id bigint not null references public.domains(id),
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    created_at timestamptz not null default clock_timestamp(),
    unique(id,domain_id,ou_entity_ids)
);
-- Historical tokens each retain their original immutable domain/OU scope.
insert into public.sli_agent_enrollment_groups(id,domain_id,ou_entity_ids)
    select id,domain_id,ou_entity_ids from public.sli_agent_group_tokens;
alter table public.sli_agent_group_tokens add column group_id uuid;
update public.sli_agent_group_tokens set group_id=id;
alter table public.sli_agent_group_tokens alter column group_id set not null;
alter table public.sli_agent_group_tokens add constraint sli_agent_group_tokens_scope_fk
    foreign key(group_id,domain_id,ou_entity_ids)
    references public.sli_agent_enrollment_groups(id,domain_id,ou_entity_ids);
do $$
declare ttl_constraint text;
begin
    select conname into strict ttl_constraint from pg_constraint
        where conrelid='public.sli_agent_group_tokens'::regclass and contype='c'
        and pg_get_expr(conbin,conrelid) like '%expires_at%'
        and pg_get_expr(conbin,conrelid) like '%created_at%';
    execute format('alter table public.sli_agent_group_tokens drop constraint %I',ttl_constraint);
end $$;
alter table public.sli_agent_group_tokens add constraint sli_agent_group_tokens_ttl_check
    check(expires_at >= created_at+interval '60 seconds' and expires_at <= created_at+interval '7 days');
alter table public.sli_agent_group_requests drop constraint sli_agent_group_requests_status_check;
alter table public.sli_agent_group_requests add constraint sli_agent_group_requests_status_check
    check(status in ('pending','cancelled','approved'));
create table public.sli_agent_group_approvals (
    request_id uuid primary key references public.sli_agent_group_requests(id),
    enrollment_token_id uuid not null unique references public.sli_agent_enrollment_tokens(id)
);
-- Include approvals prepared by migration 178's template onboarding path.
create view public.sli_agent_group_approval_links with(security_invoker=true) as
    select request_id,enrollment_token_id from public.sli_agent_group_approvals
    union
    select request_id,enrollment_token_id from public.sli_agent_onboarding_copies;
revoke all on public.sli_agent_group_approval_links from public,adlog_user;
grant select on public.sli_agent_group_approval_links to adlog_user;
create table public.sli_agent_group_members (
    agent_id uuid primary key references public.sli_agents(id),
    group_id uuid not null references public.sli_agent_enrollment_groups(id)
);
create index sli_agent_group_tokens_group on public.sli_agent_group_tokens(group_id,id);
create index sli_agent_group_requests_pending on public.sli_agent_group_requests(token_id,id) where status='pending';
revoke all on public.sli_agent_enrollment_groups,public.sli_agent_group_approvals,public.sli_agent_group_members from public,adlog_user;
grant select,insert on public.sli_agent_enrollment_groups,public.sli_agent_group_approvals,public.sli_agent_group_members to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''group_pending_list'',''group_approval'',''group_approval_batch''))',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(188,'agent_group_deployment');
commit;
