-- Credential-bound intentions only. No command queue, passwords or AD writes.
begin;
select pg_advisory_xact_lock(hashtext('sli_gpo_plan_credentials_v242'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=241 and name='report_schedules')
       or exists(select 1 from public.schema_migrations where version>=242) then
        raise exception 'migration 242 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Explicit assignment only; the web login cannot authorize its own recipient.
-- Updating this assignment, certificate renewal or disable invalidates previews.
create table public.sli_gpo_plan_recipients (
    domain_id bigint primary key references public.domains(id) on delete restrict,
    agent_id uuid not null references public.sli_agents(id) on delete restrict,
    certificate_sha256 text not null check(certificate_sha256 ~ '^[0-9a-f]{64}$'),
    revision bigint not null check(revision>0),
    enabled boolean not null default true
);
create table public.sli_gpo_plan_last_credentials (
    actor text not null check(actor ~ '^session:[1-9][0-9]*$'),
    domain_id bigint not null references public.domains(id) on delete restrict,
    credential_id uuid not null,
    credential_revision bigint not null check(credential_revision>0),
    primary key(actor,domain_id)
);
alter table public.sli_agent_gpo_plan_audit
    add column credential_id uuid,
    add column credential_revision bigint,
    add column recipient_agent_id uuid,
    add column recipient_certificate_sha256 text,
    add column expires_at timestamptz;
revoke all on public.sli_gpo_plan_recipients,public.sli_gpo_plan_last_credentials from public;

-- Include the whole assignment in the preview hash, even when a changed grant
-- still contains every selected OU. Existing version 231 remains immutable.
create or replace function public.sli_agent_gpo_plan_scope(p_actor text,p_domain bigint,p_permission text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare assignment public.sli_agent_gpo_deployment_grants; scope public.sli_agent_gpo_plan_scopes;
begin
    select * into assignment from public.sli_agent_gpo_deployment_grants
        where actor=p_actor and domain_id=p_domain and enabled is true
          and p_permission=any(permissions) for share;
    if not found then return null; end if;
    select * into scope from public.sli_agent_gpo_plan_scopes where domain_id=p_domain for share;
    return coalesce(to_jsonb(scope),'{}'::jsonb)
        || jsonb_build_object('grant_ou_entity_ids',assignment.ou_entity_ids,'grant_permissions',assignment.permissions);
end $$;
revoke all on function public.sli_agent_gpo_plan_scope(text,bigint,text) from public;
grant execute on function public.sli_agent_gpo_plan_scope(text,bigint,text) to adlog_user;

create function public.sli_gpo_plan_recipient(p_domain bigint) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare assignment public.sli_gpo_plan_recipients; agent public.sli_agents;
        certificate public.sli_agent_certificates;
begin
    select * into assignment from public.sli_gpo_plan_recipients
        where domain_id=p_domain and enabled is true for share;
    if not found then return null; end if;
    -- Same agent -> certificate lock order as registry.authenticate/disable.
    select * into agent from public.sli_agents where id=assignment.agent_id for share;
    if not found or agent.status<>'active' then return null; end if;
    select * into certificate from public.sli_agent_certificates
        where agent_id=agent.id and fingerprint=assignment.certificate_sha256
        and revoked_at is null and not_before<=clock_timestamp() and not_after>clock_timestamp()
        order by id desc limit 1 for share;
    if not found then return null; end if;
    return jsonb_build_object('agent_id',agent.id,'certificate_sha256',certificate.fingerprint,
        'assignment_revision',assignment.revision);
end $$;
revoke all on function public.sli_gpo_plan_recipient(bigint) from public;
grant execute on function public.sli_gpo_plan_recipient(bigint) to adlog_user;
grant select,insert on public.sli_gpo_plan_last_credentials to adlog_user;
grant update(credential_id,credential_revision) on public.sli_gpo_plan_last_credentials to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(242,'gpo_plan_credentials');
commit;
