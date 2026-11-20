-- G11A-3: fixed-scope, execute-only preflight state for the runtime DSN role.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_g11a3_preflight_read_boundary_v81')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 081 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=58
          and name='radius_accounting_transaction_foundation'
    ) or not exists (
        select 1 from schema_migrations
        where version=59
          and name='radius_identity_spine_resolver'
    ) then
        raise exception 'migration 081 requires migrations 058 and 059';
    end if;
    if exists(select 1 from schema_migrations where version=81) then
        raise exception 'migration 081 version is already recorded';
    end if;
    if to_regrole('adlog_user') is null then
        raise exception 'migration 081 requires adlog_user';
    end if;
    if to_regrole('adlog_radius_preflight_reader') is not null then
        raise exception 'migration 081 requires absent preflight owner';
    end if;
    if to_regprocedure('public.sli_g11a3_preflight_state_v1()') is not null then
        raise exception 'migration 081 requires absent preflight function';
    end if;
end
$$;

create role adlog_radius_preflight_reader
    noinherit nologin nosuperuser nocreatedb nocreaterole
    nobypassrls noreplication;
grant adlog_radius_preflight_reader to adlog_storage_owner;

grant usage,create on schema public to adlog_radius_preflight_reader;
grant select(version,name) on table schema_migrations
to adlog_radius_preflight_reader;
grant select(source_instance_id,desired_activation)
on table acquisition_source_instances
to adlog_radius_preflight_reader;
grant select(source_instance_id,stream_id,transport_binding,revision)
on table acquisition_stream_cursors
to adlog_radius_preflight_reader;
grant select(
    subscription_id,source_instance_id,stream_id,transport_binding,
    desired_activation
) on table acquisition_consumer_subscriptions
to adlog_radius_preflight_reader;

set local role adlog_storage_owner;

create or replace function public.sli_g11a3_preflight_state_v1()
returns table(
    source_subscription_disabled boolean,
    no_temporary_login boolean,
    no_worker_started boolean,
    cursor_revision bigint
)
language plpgsql
stable
security definer
set search_path = pg_catalog, public
as $$
declare
    registration_count bigint;
    activation_disabled boolean;
    observed_revision bigint;
begin
    select
      count(*),
      coalesce(bool_and(
        source.desired_activation='disabled'
        and subscription.desired_activation='disabled'
        and exists(
          select 1 from public.schema_migrations
          where version=58
            and name='radius_accounting_transaction_foundation'
        )
        and exists(
          select 1 from public.schema_migrations
          where version=59
            and name='radius_identity_spine_resolver'
        )
      ),false),
      min(cursor_row.revision)::bigint
    into registration_count,activation_disabled,observed_revision
    from public.acquisition_source_instances source
    join public.acquisition_stream_cursors cursor_row
      on cursor_row.source_instance_id=source.source_instance_id
    join public.acquisition_consumer_subscriptions subscription
      on subscription.source_instance_id=cursor_row.source_instance_id
     and subscription.stream_id=cursor_row.stream_id
     and subscription.transport_binding=cursor_row.transport_binding
    where cursor_row.stream_id='radius-accounting'
      and cursor_row.transport_binding=
          'windows-rpc-smb-readonly-tail-v1'
      and subscription.subscription_id=
          'vpn-radius-session-observations-msservices-v1';

    if registration_count<>1 or observed_revision is null then
        raise exception 'g11a3_preflight_registration_invalid'
            using errcode='P0001';
    end if;

    return query
    select
      activation_disabled,
      not exists(
        select 1 from pg_catalog.pg_roles
        where left(rolname,20)='adlog_radius_manual_'
      ),
      not exists(
        select 1 from pg_catalog.pg_stat_activity
        where application_name='sli_stage9_radius_manual_worker'
          and pid<>pg_backend_pid()
      ),
      observed_revision;
end
$$;

revoke all on function public.sli_g11a3_preflight_state_v1()
from public;
grant execute on function public.sli_g11a3_preflight_state_v1()
to adlog_user;
alter function public.sli_g11a3_preflight_state_v1()
owner to adlog_radius_preflight_reader;

reset role;
revoke create on schema public from adlog_radius_preflight_reader;
set local role adlog_storage_owner;

insert into schema_migrations(version,name)
values(81,'g11a3_preflight_read_boundary');

commit;
