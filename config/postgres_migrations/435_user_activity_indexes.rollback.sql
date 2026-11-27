begin;
select pg_advisory_xact_lock(hashtext('sli_user_activity_indexes435'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=435 and name='user_activity_indexes')
       or exists(select 1 from public.schema_migrations where version>435) then
        raise exception 'user_activity_indexes435_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop index public.event_hot_user_logon_coverage435,
    public.event_hot_user_logon_account435,public.event_cold_facts_user_logon_account435,public.event_cold_daily_user_logon_account435,
    public.event_hot_user_workplace435,public.event_hot_user_workplace_long435,
    public.event_cold_facts_user_workplace435,public.event_cold_daily_user_workplace435,
    public.event_hot_user_card_sid435,public.event_cold_facts_user_card_sid435,public.event_cold_daily_user_card_sid435,
    public.event_hot_user_card_name435,public.event_cold_facts_user_card_name435,public.event_cold_daily_user_card_name435;
drop trigger user_logon_recorder435 on public.event_hot;
drop function public.store_user_logon_recorder435();
alter table public.event_hot drop column ad_user_logon_recorder435, drop column ad_user_workplace_type435;
alter table public.event_cold_facts drop column ad_user_logon_recorder435, drop column ad_user_workplace_type435;
drop function public.user_workplace_type435(jsonb);
drop function public.user_logon_recorder435(jsonb);
delete from public.schema_migrations where version=435 and name='user_activity_indexes';
commit;
