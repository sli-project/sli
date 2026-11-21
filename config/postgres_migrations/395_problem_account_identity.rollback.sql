begin;
select pg_advisory_xact_lock(hashtext('sli_problem_account_identity395'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=395 and name='problem_account_identity')
       or exists(select 1 from public.schema_migrations where version>395) then
        raise exception 'problem_account_identity395_rollback_preflight' using errcode='55000';
    end if;
end $$;

update public.findings f set severity=b.previous_severity from public.problem_severity_backup395 b
where f.id=b.finding_id and f.severity=b.applied_severity and f.updated_at is not distinct from b.updated_at;

set local role adlog_storage_owner;
create or replace function public.password_definition_revision393(r text) returns integer
language sql immutable set search_path=pg_catalog,pg_temp as $$ select 2 $$;
drop function public.notification_password_facts395(uuid,uuid);
drop function public.password_problem_facts395(bigint,text);
drop table public.problem_severity_backup395;
reset role;
revoke select(domain_id,entity_id,alias_type,normalized_value) on public.ad_context_entity_aliases from adlog_storage_owner;
delete from public.schema_migrations where version=395 and name='problem_account_identity';
commit;
