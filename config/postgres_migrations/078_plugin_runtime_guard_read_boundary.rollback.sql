begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_plugin_runtime_guard_read_boundary_v78'));

revoke all on function read_plugin_component_runtime_guard_v1(text,text)
    from public,adlog_user;
drop function if exists read_plugin_component_runtime_guard_v1(text,text);

delete from schema_migrations
where version=78 and name='plugin_runtime_guard_read_boundary';

commit;
