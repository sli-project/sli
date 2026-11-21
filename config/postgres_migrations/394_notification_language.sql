begin;
select pg_advisory_xact_lock(hashtext('sli_notification_language394'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=392 and name='ad_snapshot_schedule')
       or exists(select 1 from public.schema_migrations where version>=394) then
        raise exception 'notification_language394_preflight' using errcode='55000';
    end if;
end $$;

set local role adlog_storage_owner;
create table public.user_interface_languages (
    user_id bigint primary key references public.auth_users(id) on delete cascade,
    language text not null check(language in ('en','ru'))
);
grant select,insert,update on public.user_interface_languages to adlog_user;
grant select on public.user_interface_languages to adlog_notification_worker;

create table public.telegram_chat_languages (
    bot_id text not null check(bot_id ~ '^[1-9][0-9]*$'),
    chat_id bigint not null check(chat_id between 1 and 9999999999999999),
    language text not null check(language in ('en','ru')),
    primary key(bot_id,chat_id)
);
grant select,insert,update on public.telegram_chat_languages to adlog_notification_worker;

create table public.telegram_discovered_chats (
    bot_generation text not null check(bot_generation ~ '^[a-f0-9]{64}$'),
    chat_id bigint not null check(chat_id between 1 and 9999999999999999),
    chat_name text not null check(length(chat_name) between 1 and 128),
    seen_at timestamptz not null,
    primary key(bot_generation,chat_id)
);
grant select on public.telegram_discovered_chats to adlog_user;
grant select,insert,update,delete on public.telegram_discovered_chats to adlog_notification_worker;

create function public.notification_server_zone() returns text
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select value from public.platform_settings where key='server.timezone'
$$;
revoke all on function public.notification_server_zone() from public;
grant execute on function public.notification_server_zone() to adlog_notification_worker;

-- Projection is available only for a currently leased alert.
create function public.notification_alert_finding(job_id uuid, lease uuid) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('id',f.id,'rule_code',f.rule_code,'severity',f.severity,
        'first_seen_utc',f.first_seen_utc,'last_seen_utc',f.last_seen_utc,
        'repeat_count',f.repeat_count,'evidence_count',f.evidence_count,
        'actor',left(f.actor,2048),'target',left(f.target,2048),'source',left(f.source,2048))
    from public.notification_outbox j
    cross join lateral public.notification_finding_brief(j.object_id) b
    join public.findings f on f.id=b.finding_id
    where j.id=job_id and j.lease_token=lease and j.state='sending'
      and j.object_kind='semantic_finding' and j.lease_until>statement_timestamp()
$$;
revoke all on function public.notification_alert_finding(uuid,uuid) from public;
grant execute on function public.notification_alert_finding(uuid,uuid) to adlog_notification_worker;

create function public.notification_alert_events(job_id uuid, lease uuid)
returns table(finding_id bigint,event_db_id bigint,event_id integer,time_created_utc timestamptz,
    target_user_name text,target_domain_name text,ip_address text,workstation_name text,hostname text,
    service_name text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select e.finding_id,e.event_db_id,e.event_id,e.time_created_utc,
        e.target_user_name,e.target_domain_name,e.ip_address,e.workstation_name,e.hostname,e.service_name
    from public.finding_event_details337 e
    where e.finding_id=(public.notification_alert_finding(job_id,lease)->>'id')::bigint
$$;
revoke all on function public.notification_alert_events(uuid,uuid) from public;
grant execute on function public.notification_alert_events(uuid,uuid) to adlog_notification_worker;

reset role;
grant select(value,key) on public.platform_settings to adlog_storage_owner;
insert into public.schema_migrations(version,name) values(394,'notification_language');
commit;
