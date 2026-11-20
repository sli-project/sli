-- N01: installation channel metadata only; no credentials or delivery state claims.
begin;
select pg_advisory_xact_lock(hashtext('sli_notification_channels_v224'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=223 and name='home_previous_login')
       or exists(select 1 from public.schema_migrations where version>=224) then
        raise exception 'migration 224 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.notification_channels (
    kind text primary key check(kind in ('smtp','telegram')),
    enabled boolean not null default false,
    tls_mode text not null,
    secret_ref text not null,
    state text not null default 'not_configured' check(state='not_configured'),
    revision bigint not null default 1 check(revision>0),
    updated_at timestamptz not null default clock_timestamp(),
    check((kind='smtp' and tls_mode in ('starttls','tls') and secret_ref='SLI_NOTIFY_SMTP_PASSWORD')
       or (kind='telegram' and tls_mode='tls' and secret_ref='SLI_NOTIFY_TELEGRAM_TOKEN'))
);
insert into public.notification_channels(kind,tls_mode,secret_ref) values
    ('smtp','starttls','SLI_NOTIFY_SMTP_PASSWORD'),
    ('telegram','tls','SLI_NOTIFY_TELEGRAM_TOKEN');
revoke all on public.notification_channels from public,adlog_user;
grant select on public.notification_channels to adlog_user;
grant update(enabled,tls_mode,secret_ref,revision,updated_at) on public.notification_channels to adlog_user;
reset role;

insert into public.report_datasets_v4(dataset_key,version,name,object_type,fields_json,filters_json,actions_json,status)
values('notifications.channels',1,'Каналы уведомлений','notification_channel',
    '[{"key":"kind","category":"technical"},{"key":"enabled","category":"technical"},
      {"key":"tls_mode","category":"technical"},{"key":"secret_ref","category":"technical"},
      {"key":"state","category":"technical"},{"key":"revision","category":"technical"},
      {"key":"updated_at","category":"technical"}]'::jsonb,
    '[]'::jsonb,'["view","configure_channel"]'::jsonb,'published');
insert into public.report_registry_v4(report_key,version,name,owner_name,purpose,dataset_id,
    definition_json,sensitivity,status,published_at)
select 'notifications.channels',1,'Каналы уведомлений','SLI',
    'Метаданные каналов без секретов и отправки',id,
    '{"target_path":"/report/notifications.channels","required_capabilities":["access.manage"],
      "field_categories":["technical"],"actions":["view","configure_channel"],"export_policy":"denied"}'::jsonb,
    'restricted','published',now()
from public.report_datasets_v4 where dataset_key='notifications.channels' and version=1;
insert into public.access_package_reports(package_id,report_key,field_categories,allowed_actions,scope_json)
select id,'notifications.channels',array['technical'],array['view','configure_channel'],'{"kind":"all"}'::jsonb
from public.access_packages where package_key='access_admin';

insert into public.schema_migrations(version,name) values(224,'notification_channels');
commit;
