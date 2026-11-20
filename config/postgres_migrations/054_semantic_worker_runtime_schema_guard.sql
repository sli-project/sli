-- Stage 8 additive least-privilege repair for the accepted runtime schema guard.
-- It grants no finding, collection, survey, ownership or schema-change rights.
begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_semantic_worker_v54'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 054 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=53 and name='semantic_canonical_action_risk'
    ) then
        raise exception 'migration 054 requires schema migration 053';
    end if;
    if to_regrole('adlog_semantic_worker') is null then
        raise exception 'migration 054 requires NOLOGIN role adlog_semantic_worker';
    end if;
end
$$;

-- schema_migrations is owned by adlog_user in production. The maintenance
-- session performs this exact grant before reducing its active role; a role
-- that only has SELECT without GRANT OPTION would merely emit a warning.
grant select on table schema_migrations to adlog_semantic_worker;

do $$
begin
    if not has_table_privilege(
        'adlog_semantic_worker', 'schema_migrations', 'SELECT'
    ) then
        raise exception 'migration 054 failed to grant schema marker read';
    end if;
end
$$;

set local role adlog_storage_owner;

insert into schema_migrations(version,name)
values (54,'semantic_worker_runtime_schema_guard')
on conflict(version) do update set name=excluded.name;

commit;
