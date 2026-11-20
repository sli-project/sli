begin;

select pg_advisory_xact_lock(hashtext('ad_log_reports_stage6_report_access_requests'));

alter table report_registry_v4
    add column if not exists discoverable boolean not null default true,
    add column if not exists requestable boolean not null default false,
    add column if not exists request_profile_json jsonb not null default
        '{"scope_kinds":["all"],"max_duration_days":90}'::jsonb;

update report_registry_v4 report
set discoverable = true,
    requestable = true,
    request_profile_json = jsonb_build_object(
        'scope_kinds',
        case
            when dataset.dataset_key = 'events.v2'
                then jsonb_build_array('all','server','domain','channel')
            when dataset.dataset_key in (
                'entities.v2','ad.audit.snapshot','ad.accounts.privileged',
                'ad.accounts.vpn','ad.gpo.governance'
            )
                then jsonb_build_array('all','server','domain')
            else jsonb_build_array('all')
        end,
        'field_categories', coalesce(report.definition_json->'field_categories','[]'::jsonb),
        'allowed_actions', coalesce(report.definition_json->'actions','["view"]'::jsonb),
        'max_duration_days', 90
    )
from report_datasets_v4 dataset
where report.dataset_id=dataset.id and report.status = 'published';

create table if not exists report_access_requests_v4 (
    id bigserial primary key,
    requester_user_id bigint not null references auth_users(id) on delete cascade,
    report_key text not null,
    report_version integer not null check(report_version > 0),
    dataset_version integer not null check(dataset_version > 0),
    requested_scope_json jsonb not null,
    requested_valid_until timestamptz not null,
    business_reason text not null,
    requested_field_categories text[] not null,
    requested_actions text[] not null,
    status text not null default 'submitted' check(status in (
        'submitted','reviewing','approved','approved_limited','rejected',
        'expired','system_cancelled'
    )),
    decision_reason text,
    granted_scope_json jsonb,
    granted_valid_until timestamptz,
    granted_field_categories text[],
    granted_actions text[],
    assignment_id bigint,
    decided_by bigint references auth_users(id),
    decided_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists report_access_requests_v4_active_unique
    on report_access_requests_v4(requester_user_id, report_key, requested_scope_json)
    where status in ('submitted','reviewing');

create index if not exists report_access_requests_v4_status_idx
    on report_access_requests_v4(status, created_at desc);

do $$
begin
    if exists(select 1 from pg_roles where rolname='adlog_user') then
        execute 'grant select,insert,update on report_access_requests_v4 to adlog_user';
        execute 'grant usage,select on sequence report_access_requests_v4_id_seq to adlog_user';
    end if;
end $$;

insert into schema_migrations(version,name)
values(40,'stage6_report_access_requests')
on conflict(version) do update set name=excluded.name;

commit;
