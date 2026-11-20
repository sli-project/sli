-- Add only existing canonical fact projections to the search publication.
-- No collection, event rewrite, grants, or legacy report-column changes.
begin;
select pg_advisory_xact_lock(hashtext('ad_log_reports_evsearch_fact_publication_v303'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 303 requires adlog_storage_owner membership';
    end if;
    if not pg_has_role(session_user,'adlog_storage_owner','USAGE')
       or not pg_has_role(session_user,'adlog_user','USAGE') then
        raise exception 'migration 303 requires existing storage and report-owner privileges';
    end if;
    if not exists(select 1 from public.schema_migrations where version=300 and name='owner_recovery') then
        raise exception 'migration 303 requires exact migration 300 owner_recovery';
    end if;
    if exists(select 1 from public.schema_migrations where version>=303) then
        raise exception 'migration 303 already applied, occupied or superseded';
    end if;
end $$;
lock table public.report_datasets_v4, public.report_registry_v4 in share row exclusive mode;

do $$
begin
    if not exists (select 1 from public.report_registry_v4 r
        join public.report_datasets_v4 d on d.id=r.dataset_id
        where r.report_key='events.explorer' and r.version=1
        and d.dataset_key='events.v2' and d.version=1) then
        raise exception 'evsearch publication prerequisite missing';
    end if;
    if exists (select 1 from public.report_datasets_v4 d,
        jsonb_array_elements(d.fields_json) f
        where d.dataset_key='events.v2' and d.version=1
        and ((f->>'key'='provider' and f->>'category' is distinct from 'technical')
          or (f->>'key' in ('outcome','title') and f->>'category' is distinct from 'security'))) then
        raise exception 'evsearch publication category conflict';
    end if;
end $$;

-- Only the new private rollback object is storage-owned. Existing report
-- metadata stays owned by adlog_user; the authorized admin performs its update.
set local role adlog_storage_owner;
create table public.evsearch_publication_rollback_v303 (
    report_id bigint primary key,
    dataset_id bigint not null,
    fields_before jsonb not null,
    definition_before jsonb not null,
    fields_after jsonb not null,
    definition_after jsonb not null
);
revoke all on public.evsearch_publication_rollback_v303
    from public, adlog_user, adlog_storage_worker, adlog_semantic_worker;
reset role;
insert into public.evsearch_publication_rollback_v303
select r.id,d.id,d.fields_json,r.definition_json,d.fields_json,r.definition_json
from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
where r.report_key='events.explorer' and r.version=1
and d.dataset_key='events.v2' and d.version=1;

with additions as (
    select '[{"key": "provider", "label": "Provider", "category": "technical"}, {"key": "outcome", "label": "Authentication outcome", "category": "security"}, {"key": "title", "label": "Catalog title", "category": "security"}, {"key": "action", "label": "Native action", "category": "security"}, {"key": "reason", "label": "Native result code", "category": "security"}, {"key": "logon_type", "label": "Native logon type", "category": "security"}, {"key": "account", "label": "Account roles", "category": "security"}, {"key": "account_kind", "label": "Known account classification", "category": "security"}, {"key": "source_station", "label": "Source station identity", "category": "security"}, {"key": "ip", "label": "Source IP", "category": "security"}, {"key": "related_object", "label": "Linked object identities", "category": "security"}, {"key": "server_id", "label": "Recording server identity", "category": "technical"}, {"key": "domain_id", "label": "Domain identity", "category": "technical"}, {"key": "task_identity", "label": "Task identity", "category": "security"}, {"key": "process_identity", "label": "Process identity", "category": "security"}, {"key": "file_identity", "label": "File identity", "category": "security"}, {"key": "group_identity_complete", "label": "Grouping identity proof", "category": "technical"}, {"key": "source_payload_state", "label": "Source payload availability", "category": "technical"}]'::jsonb as fields
)
update public.report_datasets_v4 d set fields_json=d.fields_json || coalesce((
    select jsonb_agg(f) from additions, jsonb_array_elements(additions.fields) f
    where not exists (select 1 from jsonb_array_elements(d.fields_json) old
                      where old->>'key'=f->>'key')
), '[]'::jsonb)
where d.dataset_key='events.v2' and d.version=1;

update public.report_registry_v4 r set definition_json = jsonb_set(
    jsonb_set(r.definition_json, '{evsearch_columns}', (
        select jsonb_agg(value order by value) from (
            select distinct value from jsonb_array_elements_text(
                coalesce(r.definition_json->'evsearch_columns','[]'::jsonb)
                || '["provider", "outcome", "title", "action", "reason", "logon_type", "account", "account_kind", "source_station", "ip", "related_object", "server_id", "domain_id", "task_identity", "process_identity", "file_identity", "group_identity_complete", "source_payload_state"]'::jsonb)
        ) columns
    )), '{evsearch_questions}',
    coalesce(r.definition_json->'evsearch_questions','{}'::jsonb) ||
    '{"failed_logons":["provider","channel","event_id","outcome"],
      "lockouts":["provider","channel","event_id"],
      "group_changes":["provider","channel","event_id"],
      "log_cleared":["provider","channel","event_id"]}'::jsonb
)
from public.report_datasets_v4 d
where r.dataset_id=d.id and d.dataset_key='events.v2' and d.version=1
and r.report_key='events.explorer' and r.version=1;

update public.evsearch_publication_rollback_v303 s
set fields_after=d.fields_json, definition_after=r.definition_json
from public.report_registry_v4 r join public.report_datasets_v4 d on d.id=r.dataset_id
where s.report_id=r.id and s.dataset_id=d.id;
set local role adlog_storage_owner;
insert into public.schema_migrations(version,name) values(303,'evsearch_fact_publication');
reset role;
commit;
