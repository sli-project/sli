-- Rollback is allowed only before the first runtime transition.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_v76'));

do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 076 rollback requires storage owner';
    end if;
    if exists(
        select 1 from plugin_lifecycle_operations_v1
        where requested_action in ('enable','drain','disable')
    ) then
        raise exception 'migration 076 rollback forbidden after first runtime transition';
    end if;
    if exists(
        select 1 from plugin_installations_v1
        where plugin_id='sli.remote-access'
          and (desired_activation<>'disabled' or component_runtime<>'stopped'
               or queue_state<>'drained')
    ) or exists(
        select 1 from plugin_component_admission_v1
        where plugin_id='sli.remote-access' and admission_mode<>'closed'
    ) or exists(select 1 from plugin_component_leases_v1) then
        raise exception 'migration 076 rollback requires unused stopped runtime';
    end if;
end
$$;

delete from schema_migrations
where version=76 and name='plugin_runtime_activation_executor';
revoke execute on function execute_plugin_runtime_transition_v1(
    uuid,text,bigint,text,text,text,text
) from adlog_plugin_lifecycle_executor;
drop function execute_plugin_runtime_transition_v1(
    uuid,text,bigint,text,text,text,text
);
revoke execute on function read_plugin_runtime_queue_nonterminal_v1()
from adlog_plugin_lifecycle_owner;
drop function read_plugin_runtime_queue_nonterminal_v1();
commit;
