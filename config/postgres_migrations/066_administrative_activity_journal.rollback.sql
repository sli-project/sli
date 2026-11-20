-- Roll back only before the unified journal receives its first activity.
begin;

select pg_advisory_xact_lock(
    hashtext('ad_log_reports_administrative_activity_v66')
);

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'rollback 066 requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from pg_roles
        where rolname=session_user and rolsuper
    ) then
        raise exception 'rollback 066 requires migration superuser session';
    end if;
    if exists (select 1 from schema_migrations where version>66) then
        raise exception 'rollback 066 is blocked by later migrations';
    end if;
    if not exists (
        select 1 from schema_migrations
        where version=66 and name='administrative_activity_journal'
    ) then
        raise exception 'rollback 066 requires schema migration 066';
    end if;
    if exists (select 1 from administrative_activity_v1) then
        raise exception 'rollback 066 forbidden after administrative activity';
    end if;
end
$$;

revoke execute on function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
) from adlog_user;

drop table administrative_activity_v1;
drop function append_administrative_activity_v1(
    uuid,timestamptz,text,text,text,text,text,text,text,text,jsonb,inet,uuid
);
drop function reject_administrative_activity_mutation_v1();
delete from schema_migrations
where version=66 and name='administrative_activity_journal';
revoke usage on schema public
from adlog_administrative_activity_owner;

revoke adlog_administrative_activity_owner from adlog_storage_owner;
drop role adlog_administrative_activity_owner;

commit;
