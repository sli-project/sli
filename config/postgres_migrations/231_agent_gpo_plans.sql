-- Stage 2: explicit SLI grants and durable intentions, no AD writer queue.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_gpo_plans_v231'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=230 and name='nps_threshold')
       or exists(select 1 from public.schema_migrations where version>=231) then
        raise exception 'migration 231 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

-- Populated by explicit administrative preparation, never by preview/confirm.
-- No implicit owner grant, no AD permissions, no default deployment assignment.
create table public.sli_agent_gpo_deployment_grants (
    actor text not null check(actor ~ '^session:[1-9][0-9]*$'),
    domain_id bigint not null references public.domains(id) on delete restrict,
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    permissions text[] not null check(cardinality(permissions)>0 and permissions <@ array['preview','apply']::text[]
        and array_position(permissions,null) is null),
    enabled boolean not null default true,
    primary key(actor,domain_id)
);
create table public.sli_agent_gpo_plan_scopes (
    domain_id bigint primary key references public.domains(id) on delete restrict,
    ou_entity_ids bigint[] not null check(cardinality(ou_entity_ids) between 1 and 128
        and array_position(ou_entity_ids,null) is null),
    revision bigint not null check(revision>0),
    evidence_sha256 text not null check(evidence_sha256 ~ '^[0-9a-f]{64}$'),
    package jsonb not null default '{}' check(jsonb_typeof(package)='object')
);
create table public.sli_agent_gpo_plans (
    id uuid primary key,
    actor text not null,
    domain_id bigint not null references public.domains(id) on delete restrict,
    selection jsonb not null check(jsonb_typeof(selection)='object'),
    snapshot jsonb not null check(jsonb_typeof(snapshot)='object'),
    plan_sha256 text not null check(plan_sha256 ~ '^[0-9a-f]{64}$'),
    status text not null default 'preview' check(status in ('preview','confirmed','cancelled')),
    created_at timestamptz not null default clock_timestamp(),
    expires_at timestamptz not null,
    finished_at timestamptz,
    check(expires_at>created_at and expires_at<=created_at+interval '10 minutes'),
    check((status='preview')=(finished_at is null))
);
create table public.sli_agent_gpo_plan_audit (
    id bigint generated always as identity primary key,
    occurred_at timestamptz not null default clock_timestamp(),
    actor text not null,
    domain_id bigint references public.domains(id) on delete restrict,
    action text not null check(action in ('preview','confirmed','cancelled','denied')),
    plan_id uuid references public.sli_agent_gpo_plans(id) on delete restrict,
    result text not null
);
revoke all on public.sli_agent_gpo_deployment_grants,public.sli_agent_gpo_plan_scopes,
    public.sli_agent_gpo_plans,public.sli_agent_gpo_plan_audit from public;
-- Row locks require UPDATE privilege. Keep that privilege inside this fixed
-- function instead of giving the web login permission to edit its own grants.
create function public.sli_agent_gpo_plan_scope(p_actor text,p_domain bigint,p_permission text) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare assignment public.sli_agent_gpo_deployment_grants; scope public.sli_agent_gpo_plan_scopes;
begin
    select * into assignment from public.sli_agent_gpo_deployment_grants
        where actor=p_actor and domain_id=p_domain and enabled is true
          and p_permission=any(permissions) for share;
    if not found then return null; end if;
    select * into scope from public.sli_agent_gpo_plan_scopes where domain_id=p_domain for share;
    return coalesce(to_jsonb(scope),'{}'::jsonb)
        || jsonb_build_object('grant_ou_entity_ids',assignment.ou_entity_ids);
end $$;
revoke all on function public.sli_agent_gpo_plan_scope(text,bigint,text) from public;
grant execute on function public.sli_agent_gpo_plan_scope(text,bigint,text) to adlog_user;
grant select,insert on public.sli_agent_gpo_plans to adlog_user;
grant update(status,finished_at) on public.sli_agent_gpo_plans to adlog_user;
grant insert on public.sli_agent_gpo_plan_audit to adlog_user;
grant usage on sequence public.sli_agent_gpo_plan_audit_id_seq to adlog_user;
reset role;
insert into public.schema_migrations(version,name) values(231,'agent_gpo_plans');
commit;
