-- N09: calendar schedules and immutable report-period releases; no message bodies.
begin;
select pg_advisory_xact_lock(hashtext('sli_report_schedules_v241'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=240 and name='file_ransom_details')
       or exists(select 1 from public.schema_migrations where version>=241) then
        raise exception 'migration 241 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.report_schedules (
    id uuid primary key,
    owner_user_id bigint not null check(owner_user_id>0),
    report_key text not null check(report_key in ('security.problems','file-audit.mass-operations')),
    filters jsonb not null check(jsonb_typeof(filters)='object' and octet_length(filters::text)<=2048),
    timezone text not null check(length(timezone) between 1 and 100),
    local_time text not null check(local_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
    weekday integer check(weekday between 0 and 6),
    period_days integer not null check(period_days in (1,7,30)),
    language text not null check(language in ('ru','en')),
    enabled boolean not null default false,
    revision bigint not null default 1 check(revision>0),
    last_checked_at timestamptz not null default 'epoch',
    created_at timestamptz not null default clock_timestamp()
);
create table public.report_schedule_subscriptions (
    schedule_id uuid not null references public.report_schedules(id),
    subscription_id uuid not null references public.notification_subscriptions(id),
    primary key(schedule_id,subscription_id)
);
create table public.report_schedule_runs (
    id uuid primary key,
    schedule_id uuid not null references public.report_schedules(id),
    schedule_revision bigint not null check(schedule_revision>0),
    report_key text not null check(report_key in ('security.problems','file-audit.mass-operations')),
    slot timestamptz not null,
    period_from timestamptz not null,
    period_to timestamptz not null,
    generated_at timestamptz not null,
    quality text not null check(quality in ('ok','empty','partial','stale','not_collected','denied','error','processing')),
    item_count bigint check(item_count>=0),
    truncated boolean not null,
    delayed boolean not null,
    language text not null check(language in ('ru','en')),
    unique(schedule_id,schedule_revision,slot),
    check(period_from<period_to and period_to=slot),
    check(item_count is null or quality in ('ok','empty','partial','stale'))
);
alter table public.notification_outbox drop constraint notification_outbox_object_kind_check;
alter table public.notification_outbox add constraint notification_outbox_object_kind_check
    check(object_kind in ('test_problem','semantic_finding','report_schedule'));
alter table public.notification_outbox drop constraint notification_outbox_publication;
alter table public.notification_outbox add constraint notification_outbox_publication check (
    (object_kind in ('test_problem','report_schedule') and publication_scenario_id is null)
    or (object_kind='semantic_finding' and publication_scenario_id is not null and object_id=publication_scenario_id)
);
revoke all on public.report_schedules,public.report_schedule_subscriptions,public.report_schedule_runs from public,adlog_user;
grant select,insert on public.report_schedules,public.report_schedule_subscriptions,public.report_schedule_runs to adlog_user;
grant delete on public.report_schedule_subscriptions to adlog_user;
grant update(report_key,filters,timezone,local_time,weekday,period_days,language,enabled,revision,last_checked_at)
    on public.report_schedules to adlog_user;
reset role;
update public.report_datasets_v4 set fields_json=fields_json ||
    '[{"key":"period_from","category":"technical"},{"key":"period_to","category":"technical"},
      {"key":"quality","category":"technical"}]'::jsonb
    where dataset_key='notifications.deliveries' and version=1;
update public.report_registry_v4 set purpose='Проблемы и выпуски отчётов: период, качество, независимый результат каналов'
    where report_key='notifications.deliveries' and version=1;
insert into public.schema_migrations(version,name) values(241,'report_schedules');
commit;
