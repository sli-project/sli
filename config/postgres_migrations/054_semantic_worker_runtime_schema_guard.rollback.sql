begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_worker_v54'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 054 rollback requires membership in adlog_storage_owner';
    end if;
end
$$;

revoke select on table schema_migrations from adlog_semantic_worker;

do $$
begin
    if has_table_privilege(
        'adlog_semantic_worker', 'schema_migrations', 'SELECT'
    ) then
        raise exception 'migration 054 rollback failed to revoke schema marker read';
    end if;
end
$$;

set local role adlog_storage_owner;

delete from schema_migrations
where version=54 and name='semantic_worker_runtime_schema_guard';

commit;
