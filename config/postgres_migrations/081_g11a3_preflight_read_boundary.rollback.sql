-- Remove only the unused G11A-3 execute-only preflight boundary.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_g11a3_preflight_read_boundary_v81')
);

do $$
declare
    function_oid oid;
    function_owner text;
    owner_restricted boolean;
    public_execute boolean;
    runtime_execute boolean;
    actual_columns text[];
    expected_columns constant text[] := array[
      'acquisition_consumer_subscriptions.desired_activation',
      'acquisition_consumer_subscriptions.source_instance_id',
      'acquisition_consumer_subscriptions.stream_id',
      'acquisition_consumer_subscriptions.subscription_id',
      'acquisition_consumer_subscriptions.transport_binding',
      'acquisition_source_instances.desired_activation',
      'acquisition_source_instances.source_instance_id',
      'acquisition_stream_cursors.revision',
      'acquisition_stream_cursors.source_instance_id',
      'acquisition_stream_cursors.stream_id',
      'acquisition_stream_cursors.transport_binding',
      'schema_migrations.name',
      'schema_migrations.version'
    ];
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 081 requires membership in adlog_storage_owner';
    end if;
    if not exists(
        select 1 from schema_migrations
        where version=81 and name='g11a3_preflight_read_boundary'
    ) then
        raise exception 'rollback 081 exact marker is missing';
    end if;
    if to_regrole('adlog_radius_preflight_reader') is null then
        raise exception 'rollback 081 preflight owner is missing';
    end if;
    function_oid := to_regprocedure(
        'public.sli_g11a3_preflight_state_v1()'
    );
    if function_oid is null then
        raise exception 'rollback 081 preflight function is missing';
    end if;

    select pg_get_userbyid(proowner)
    into function_owner
    from pg_proc where oid=function_oid;
    if function_owner<>'adlog_radius_preflight_reader' then
        raise exception 'rollback 081 function owner drift';
    end if;

    select
      not rolcanlogin and not rolinherit and not rolsuper
      and not rolcreatedb and not rolcreaterole and not rolbypassrls
      and not rolreplication
    into owner_restricted
    from pg_roles where rolname='adlog_radius_preflight_reader';
    if owner_restricted is not true
       or pg_has_role(
            'adlog_radius_preflight_reader','adlog_storage_owner','MEMBER'
          )
       or pg_has_role(
            'adlog_radius_preflight_reader',
            'adlog_radius_accounting_worker','MEMBER'
          )
       or has_schema_privilege(
            'adlog_radius_preflight_reader','public','CREATE'
          ) then
        raise exception 'rollback 081 owner attributes drift';
    end if;

    select
      coalesce(bool_or(
        privilege_type='EXECUTE'
        and grantee=(select oid from pg_roles where rolname='adlog_user')
      ),false),
      coalesce(bool_or(privilege_type='EXECUTE' and grantee=0),false)
    into runtime_execute,public_execute
    from aclexplode((select proacl from pg_proc where oid=function_oid));
    if runtime_execute is not true or public_execute is true then
        raise exception 'rollback 081 function acl drift';
    end if;

    select array_agg(
      table_name || '.' || column_name
      order by table_name,column_name
    )
    into actual_columns
    from information_schema.column_privileges
    where table_schema='public'
      and grantee='adlog_radius_preflight_reader'
      and privilege_type='SELECT';
    if actual_columns is distinct from expected_columns then
        raise exception 'rollback 081 column privilege drift';
    end if;
end
$$;

set local role adlog_radius_preflight_reader;

revoke execute on function public.sli_g11a3_preflight_state_v1()
from adlog_user;
drop function public.sli_g11a3_preflight_state_v1();

reset role;
set local role adlog_storage_owner;

delete from schema_migrations
where version=81 and name='g11a3_preflight_read_boundary';

reset role;

revoke select(version,name) on table schema_migrations
from adlog_radius_preflight_reader;
revoke select(source_instance_id,desired_activation)
on table acquisition_source_instances
from adlog_radius_preflight_reader;
revoke select(source_instance_id,stream_id,transport_binding,revision)
on table acquisition_stream_cursors
from adlog_radius_preflight_reader;
revoke select(
    subscription_id,source_instance_id,stream_id,transport_binding,
    desired_activation
) on table acquisition_consumer_subscriptions
from adlog_radius_preflight_reader;
revoke usage on schema public from adlog_radius_preflight_reader;
revoke adlog_radius_preflight_reader from adlog_storage_owner;
drop role adlog_radius_preflight_reader;

commit;
