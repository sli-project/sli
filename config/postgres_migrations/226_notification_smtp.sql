-- N04: SMTP acceptance is independent per job and never claims inbox receipt.
begin;
select pg_advisory_xact_lock(hashtext('sli_notification_smtp_v226'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=225 and name='notification_outbox')
       or exists(select 1 from public.schema_migrations where version>=226) then
        raise exception 'migration 226 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;

alter table public.notification_outbox drop constraint notification_outbox_state_check;
alter table public.notification_outbox add constraint notification_outbox_state_check
    check(state in ('pending','sending','dry_run','retry','failed','blocked','cancelled','accepted','delivery_unknown'));
alter table public.notification_attempts drop constraint notification_attempts_state_check;
alter table public.notification_attempts add constraint notification_attempts_state_check
    check(state in ('dry_run','retry','failed','blocked','cancelled','accepted','delivery_unknown'));
alter table public.notification_outbox drop constraint notification_outbox_result_code_check;
alter table public.notification_outbox add constraint notification_outbox_result_code_check
    check(result_code in ('simulated','subscription_changed','recipient_denied','access_unavailable',
        'transport_unavailable','accepted','smtp_not_configured','smtp_auth_failed','smtp_rejected',
        'smtp_unavailable','smtp_outcome_unknown'));
alter table public.notification_attempts drop constraint notification_attempts_result_code_check;
alter table public.notification_attempts add constraint notification_attempts_result_code_check
    check(result_code in ('simulated','subscription_changed','recipient_denied','access_unavailable',
        'transport_unavailable','accepted','smtp_not_configured','smtp_auth_failed','smtp_rejected',
        'smtp_unavailable','smtp_outcome_unknown'));
-- A Telegram dry_run cannot masquerade as SMTP provider acceptance.
alter table public.notification_outbox add constraint notification_outbox_smtp_acceptance_check
    check((state='accepted')=(result_code is not distinct from 'accepted')
          and (state<>'accepted' or channel='smtp'));
alter table public.notification_attempts add constraint notification_attempts_smtp_acceptance_check
    check((state='accepted')=(result_code='accepted'));
reset role;

update public.report_registry_v4
set purpose='Тестовые проблемы: dry_run — без отправки; accepted — приём SMTP, не подтверждение получения'
where report_key='notifications.deliveries' and version=1;
insert into public.schema_migrations(version,name) values(226,'notification_smtp');
commit;
