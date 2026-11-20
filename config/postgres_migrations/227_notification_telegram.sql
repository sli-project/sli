-- N05: independent Telegram acceptance and a durable bot-wide cooldown.
begin;
select pg_advisory_xact_lock(hashtext('sli_notification_telegram_v227'));

do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=226 and name='notification_smtp')
       or exists(select 1 from public.schema_migrations where version>=227) then
        raise exception 'migration 227 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.notification_channels
    add column next_delivery_at timestamptz not null default '-infinity';
grant update(next_delivery_at) on public.notification_channels to adlog_user;

alter table public.notification_outbox drop constraint notification_outbox_result_code_check;
alter table public.notification_outbox add constraint notification_outbox_result_code_check
    check(result_code in ('simulated','subscription_changed','recipient_denied','access_unavailable',
        'transport_unavailable','accepted','smtp_not_configured','smtp_auth_failed','smtp_rejected',
        'smtp_unavailable','smtp_outcome_unknown','telegram_not_configured','telegram_auth_failed',
        'telegram_chat_denied','telegram_rejected','telegram_rate_limited','telegram_unavailable',
        'telegram_outcome_unknown'));
alter table public.notification_attempts drop constraint notification_attempts_result_code_check;
alter table public.notification_attempts add constraint notification_attempts_result_code_check
    check(result_code in ('simulated','subscription_changed','recipient_denied','access_unavailable',
        'transport_unavailable','accepted','smtp_not_configured','smtp_auth_failed','smtp_rejected',
        'smtp_unavailable','smtp_outcome_unknown','telegram_not_configured','telegram_auth_failed',
        'telegram_chat_denied','telegram_rejected','telegram_rate_limited','telegram_unavailable',
        'telegram_outcome_unknown'));
alter table public.notification_outbox drop constraint notification_outbox_smtp_acceptance_check;
alter table public.notification_outbox add constraint notification_outbox_provider_acceptance_check
    check((state='accepted')=(result_code is not distinct from 'accepted')
          and (state<>'accepted' or channel in ('smtp','telegram')));
reset role;

update public.report_registry_v4
set purpose='Тестовые проблемы: dry_run — без отправки; accepted — приём SMTP или Telegram, не подтверждение прочтения'
where report_key='notifications.deliveries' and version=1;
insert into public.schema_migrations(version,name) values(227,'notification_telegram');
commit;
