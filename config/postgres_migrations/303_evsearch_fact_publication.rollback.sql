begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_evsearch_fact_publication_v303'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'rollback 303 requires adlog_storage_owner membership';
    end if;
    if not pg_has_role(session_user,'adlog_storage_owner','USAGE')
       or not pg_has_role(session_user,'adlog_user','USAGE') then
        raise exception 'rollback 303 requires existing storage and report-owner privileges';
    end if;
    if not exists(select 1 from public.schema_migrations where version=303 and name='evsearch_fact_publication')
       or exists(select 1 from public.schema_migrations where version>303) then
        raise exception 'rollback requires exact migration 303 and no successors';
    end if;
end $$;
lock table public.report_datasets_v4, public.report_registry_v4 in share row exclusive mode;
do $$ begin
    if not exists(select 1 from public.evsearch_publication_rollback_v303)
       or exists(select 1 from public.evsearch_publication_rollback_v303 s
           left join public.report_registry_v4 r on r.id=s.report_id
           left join public.report_datasets_v4 d on d.id=s.dataset_id
           where r.dataset_id is distinct from s.dataset_id
           or d.fields_json is distinct from s.fields_after
           or r.definition_json is distinct from s.definition_after) then
        raise exception 'rollback 303 publication changed after migration';
    end if;
end $$;
update public.report_datasets_v4 d set fields_json=s.fields_before
from public.evsearch_publication_rollback_v303 s where d.id=s.dataset_id;
update public.report_registry_v4 r set definition_json=s.definition_before
from public.evsearch_publication_rollback_v303 s where r.id=s.report_id;
set local role adlog_storage_owner;
drop table public.evsearch_publication_rollback_v303;
delete from public.schema_migrations where version=303 and name='evsearch_fact_publication';
reset role;
commit;
