-- N03: durable simulated jobs; channel credentials and real transports are absent.
begin;
select pg_advisory_xact_lock(hashtext('sli_notification_outbox_v225'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=224 and name='notification_channels')
       or exists(select 1 from public.schema_migrations where version>=225) then
        raise exception 'migration 225 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.notification_subscriptions (
    id uuid primary key,
    owner_user_id bigint not null,
    recipient_user_id bigint not null,
    channel text not null references public.notification_channels(kind),
    enabled boolean not null default false,
    revision bigint not null default 1 check(revision>0),
    updated_at timestamptz not null default clock_timestamp(),
    check(owner_user_id>0 and recipient_user_id>0)
);
create table public.notification_outbox (
    id uuid primary key,
    subscription_id uuid not null references public.notification_subscriptions(id),
    subscription_revision bigint not null check(subscription_revision>0),
    object_kind text not null check(object_kind='test_problem'),
    object_id uuid not null,
    recipient_user_id bigint not null check(recipient_user_id>0),
    channel text not null references public.notification_channels(kind),
    state text not null default 'pending'
        check(state in ('pending','sending','dry_run','retry','failed','blocked','cancelled')),
    attempts integer not null default 0 check(attempts>=0),
    lease_token uuid,
    lease_until timestamptz,
    available_at timestamptz not null default clock_timestamp(),
    result_code text check(result_code in ('simulated','subscription_changed','recipient_denied',
                                         'access_unavailable','transport_unavailable')),
    created_at timestamptz not null default clock_timestamp(),
    updated_at timestamptz not null default clock_timestamp(),
    unique(object_kind,object_id,recipient_user_id,channel),
    check((state='sending' and lease_token is not null and lease_until is not null)
       or (state<>'sending' and lease_token is null and lease_until is null))
);
create index notification_outbox_due on public.notification_outbox(available_at,created_at,id)
    where state in ('pending','retry');
create index notification_outbox_expired on public.notification_outbox(lease_until)
    where state='sending';
create index notification_outbox_subscription on public.notification_outbox(subscription_id);
create table public.notification_attempts (
    job_id uuid not null references public.notification_outbox(id),
    attempt integer not null check(attempt>0),
    state text not null check(state in ('dry_run','retry','failed','blocked','cancelled')),
    result_code text not null check(result_code in ('simulated','subscription_changed','recipient_denied',
                                                  'access_unavailable','transport_unavailable')),
    finished_at timestamptz not null default clock_timestamp(),
    primary key(job_id,attempt)
);
revoke all on public.notification_subscriptions,public.notification_outbox,public.notification_attempts
    from public,adlog_user;
grant select,insert on public.notification_subscriptions,public.notification_outbox,public.notification_attempts
    to adlog_user;
grant update(recipient_user_id,channel,enabled,revision,updated_at) on public.notification_subscriptions to adlog_user;
grant update(state,attempts,lease_token,lease_until,available_at,result_code,updated_at)
    on public.notification_outbox to adlog_user;
reset role;

insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('notifications.deliveries',1,'Журнал уведомлений','notification_delivery',
    '[{"key":"id","category":"technical"},{"key":"subscription_id","category":"technical"},
      {"key":"object_id","category":"technical"},{"key":"channel","category":"technical"},
      {"key":"state","category":"technical"},{"key":"attempts","category":"technical"},
      {"key":"result_code","category":"technical"},{"key":"created_at","category":"technical"},
      {"key":"updated_at","category":"technical"}]'::jsonb,
    '[]'::jsonb,'["view"]'::jsonb,'published');
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,
    definition_json,sensitivity,status,published_at)
select 'notifications.deliveries',1,'Журнал уведомлений','SLI',
    'Тестовая очередь: dry_run не означает доставку',id,
    '{"target_path":"/report/notifications.deliveries","required_capabilities":["access.manage"],
      "field_categories":["technical"],"actions":["view"],"export_policy":"denied"}'::jsonb,
    'restricted','published',now()
from public.report_datasets_v4 where dataset_key='notifications.deliveries' and version=1;
insert into public.access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select id,'notifications.deliveries',array['technical'],array['view'],'{"kind":"all"}'::jsonb
from public.access_packages where package_key='access_admin';

insert into public.schema_migrations(version,name) values(225,'notification_outbox');
commit;
