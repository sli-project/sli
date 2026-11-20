-- Stage 10 durable core registry for bundled plugin lifecycle planning.
-- This migration does not execute lifecycle actions or control processes.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_lifecycle_v73'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 073 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=67 and name='plugin_remote_access_namespace'
    ) or not exists (
        select 1 from schema_migrations
        where version=72 and name='administrative_activity_reader'
    ) then
        raise exception 'migration 073 requires migrations 067 and 072';
    end if;
    if to_regrole('adlog_plugin_lifecycle_owner') is not null
       or to_regrole('adlog_plugin_lifecycle_executor') is not null
       or to_regclass('public.plugin_installations_v1') is not null
       or to_regclass('public.plugin_lifecycle_operations_v1') is not null then
        raise exception 'migration 073 requires absent lifecycle objects';
    end if;
end
$$;

create role adlog_plugin_lifecycle_owner
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
create role adlog_plugin_lifecycle_executor
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_plugin_lifecycle_owner to adlog_storage_owner;
grant adlog_plugin_lifecycle_executor to adlog_storage_owner;

create table plugin_installations_v1 (
    plugin_id text primary key
        check (plugin_id ~ '^[a-z0-9][a-z0-9.-]{2,79}$'),
    manifest_id text not null,
    manifest_sha256 text not null check (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    package_version text not null
        check (package_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
    rollback_version text
        check (rollback_version is null or rollback_version ~ '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'),
    package_lifecycle text not null
        check (package_lifecycle in ('validated','registered','detached')),
    desired_activation text not null
        check (desired_activation in ('disabled','enabled_manual')),
    observed_health text not null
        check (observed_health in ('unknown','ready','degraded','blocked')),
    component_runtime text not null
        check (component_runtime in ('stopped','starting','running','draining','failed')),
    queue_state text not null
        check (queue_state in ('drained','backlog','quarantined')),
    revision bigint not null check (revision >= 1),
    immutable_evidence_count bigint not null check (immutable_evidence_count >= 1),
    detach_reader_ready boolean not null default false,
    read_report_parity boolean not null default false,
    created_at_utc timestamptz not null default now(),
    updated_at_utc timestamptz not null default now()
);

create table plugin_lifecycle_operations_v1 (
    operation_id bigint generated always as identity primary key,
    operation_uid uuid not null unique,
    plugin_id text not null references plugin_installations_v1(plugin_id),
    requested_action text not null
        check (requested_action in ('install','upgrade','rollback','enable','drain','disable','detach')),
    expected_revision bigint not null check (expected_revision >= 1),
    committed_revision bigint check (committed_revision is null or committed_revision >= expected_revision),
    plan_sha256 text not null check (plan_sha256 ~ '^[0-9a-f]{64}$'),
    confirmation_sha256 text not null check (confirmation_sha256 ~ '^[0-9a-f]{64}$'),
    actor_kind text not null
        check (actor_kind in ('session','api_key','windows','system','local_operator')),
    actor_key text not null check (btrim(actor_key)<>'' and length(actor_key)<=200),
    outcome text not null
        check (outcome in ('started','succeeded','failed','denied','cancelled')),
    reason_code text check (reason_code is null or reason_code ~ '^[a-z][a-z0-9_.-]{0,119}$'),
    created_at_utc timestamptz not null default now()
);

create function reject_plugin_lifecycle_operation_mutation_v1()
returns trigger
language plpgsql
set search_path = pg_catalog, public
as $$
begin
    raise exception 'plugin lifecycle operation history is append-only';
end
$$;

create trigger plugin_lifecycle_operations_reject_update_delete
before update or delete on plugin_lifecycle_operations_v1
for each row execute function reject_plugin_lifecycle_operation_mutation_v1();
create trigger plugin_lifecycle_operations_reject_truncate
before truncate on plugin_lifecycle_operations_v1
for each statement execute function reject_plugin_lifecycle_operation_mutation_v1();

insert into plugin_installations_v1(
    plugin_id,manifest_id,manifest_sha256,package_version,rollback_version,
    package_lifecycle,desired_activation,observed_health,component_runtime,
    queue_state,revision,immutable_evidence_count,detach_reader_ready,
    read_report_parity
) values (
    'sli.remote-access','sli.remote-access.package.v1',
    '78ae9bcc2e65f54c8469dd0494f5c951df0cfa53ae33cff84478bc70eaa958bf',
    '0.1.0',null,'validated','disabled','unknown','stopped','drained',1,1,
    false,false
);

create function read_plugin_installations_v1(p_limit integer)
returns table(
    plugin_id text,manifest_id text,manifest_sha256 text,package_version text,
    rollback_version text,package_lifecycle text,desired_activation text,
    observed_health text,component_runtime text,queue_state text,revision bigint,
    immutable_evidence_count bigint,detach_reader_ready boolean,
    read_report_parity boolean,updated_at_utc timestamptz
)
language plpgsql stable security definer
set search_path = pg_catalog, public
as $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 20 then
        raise exception 'plugin lifecycle reader limit is invalid';
    end if;
    return query
    select current.plugin_id,current.manifest_id,current.manifest_sha256,
           current.package_version,current.rollback_version,
           current.package_lifecycle,current.desired_activation,
           current.observed_health,current.component_runtime,current.queue_state,
           current.revision,current.immutable_evidence_count,
           current.detach_reader_ready,current.read_report_parity,
           current.updated_at_utc
    from public.plugin_installations_v1 current
    order by current.plugin_id
    limit p_limit;
end
$$;

revoke all on table plugin_installations_v1 from public,adlog_user;
revoke all on table plugin_lifecycle_operations_v1 from public,adlog_user;
revoke all on sequence plugin_lifecycle_operations_v1_operation_id_seq
    from public,adlog_user;
revoke all on function reject_plugin_lifecycle_operation_mutation_v1()
    from public,adlog_user;
revoke all on function read_plugin_installations_v1(integer) from public;
grant execute on function read_plugin_installations_v1(integer) to adlog_user;

grant usage,create on schema public to adlog_plugin_lifecycle_owner;
alter table plugin_installations_v1 owner to adlog_plugin_lifecycle_owner;
alter table plugin_lifecycle_operations_v1 owner to adlog_plugin_lifecycle_owner;
alter sequence plugin_lifecycle_operations_v1_operation_id_seq
    owner to adlog_plugin_lifecycle_owner;
alter function reject_plugin_lifecycle_operation_mutation_v1()
    owner to adlog_plugin_lifecycle_owner;
alter function read_plugin_installations_v1(integer)
    owner to adlog_plugin_lifecycle_owner;
revoke create on schema public from adlog_plugin_lifecycle_owner;

insert into access_capabilities(capability_key,label,description)
values(
    'plugins.manage','Управление плагинами',
    'Планирование подтверждаемых lifecycle-действий bundled-плагинов'
)
on conflict(capability_key) do update
set label=excluded.label,description=excluded.description;

insert into access_package_capabilities(package_id,capability_id)
select package.id,capability.id
from access_packages package
join access_capabilities capability on capability.capability_key='plugins.manage'
where package.package_key='access_admin'
on conflict do nothing;

do $$
begin
    if not exists (
        select 1 from access_package_capabilities mapping
        join access_packages package on package.id=mapping.package_id
        join access_capabilities capability on capability.id=mapping.capability_id
        where package.package_key='access_admin'
          and capability.capability_key='plugins.manage'
    ) then
        raise exception 'migration 073 plugins.manage mapping failed';
    end if;
end
$$;

insert into schema_migrations(version,name)
values(73,'plugin_lifecycle_registry')
on conflict(version) do update set name=excluded.name;

commit;
