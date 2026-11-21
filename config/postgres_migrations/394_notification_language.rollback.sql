begin;
select pg_advisory_xact_lock(hashtext('sli_notification_language394'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=394 and name='notification_language')
       or exists(select 1 from public.schema_migrations where version>394) then
        raise exception 'notification_language394_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
drop function public.notification_alert_events(uuid,uuid);
drop function public.notification_alert_finding(uuid,uuid);
drop function public.notification_server_zone();
drop table public.telegram_discovered_chats,public.telegram_chat_languages,public.user_interface_languages;
reset role;
revoke select(value,key) on public.platform_settings from adlog_storage_owner;
delete from public.schema_migrations where version=394 and name='notification_language';
commit;
