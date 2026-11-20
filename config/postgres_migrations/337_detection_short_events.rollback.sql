begin;
select pg_advisory_xact_lock(hashtext('sli_detection_short_events_v337'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=337 and name='detection_short_events')
       or exists(select 1 from public.schema_migrations where version>337) then
        raise exception 'detection_short_events_337_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
do $$ declare saved record;begin
    for saved in select * from public.detection_definitions337 loop execute saved.definition;end loop;
end $$;
drop function public.read_identity_attack_events_v301_short337(jsonb,bigint[]);
drop function public.read_default_password_events_short337(jsonb);
drop function public.read_default_password_window_v2_short337(jsonb);
drop function public.read_password_retained_proof_v2_short337(jsonb,jsonb);
drop function public.password_v2_native_cost_short337(jsonb,jsonb);
drop function public.read_account_decoy_events_short337(uuid,text,text,text,text,uuid);
drop function public.read_account_watch_events_short337(uuid,text,text,text,text,uuid);
drop function public.short_t109_events337(jsonb,timestamptz,timestamptz);
drop function public.short_detection_sources337();
drop function public.short_ref_allowed337(jsonb,text,text);
drop function public.short_native_source337(bigint);
reset role;
drop trigger copy_linked_finding_event337 on public.finding_evidence;
set local role adlog_storage_owner;
drop function public.copy_linked_finding_event337();
drop function public.copy_finding_event337(bigint,text,text,text,text);
drop view public.short_account_candidates337;
drop view public.finding_event_details337;
-- A schema rollback must not discard copies already owned by problems. Refuse
-- until the old path can account for every retained copy.
do $$ begin
    if exists(select 1 from public.finding_event_copies337 c where not exists(
        select 1 from public.finding_evidence e where e.finding_id=c.finding_id and e.event_id=c.event_id and e.evidence_role=c.evidence_role)) then
        raise exception 'detection_short_events_337_retained_copies' using errcode='55000'; end if;
end $$;
drop table public.finding_event_copies337;
drop view public.detection_events337;
drop function public.short_event_document337(public.event_hot);
drop index public.event_hot_detection337;
drop trigger attest_short_event337 on public.event_hot;
drop function public.attest_short_event337();
alter table public.event_hot drop column source_sha256;
alter table public.event_cold_facts drop column source_sha256;
alter table public.event_hot drop column event_record_id;
alter table public.event_cold_facts drop column event_record_id;
drop function public.detections_use_short337();
drop table public.detection_storage337;
drop table public.detection_definitions337;
delete from public.schema_migrations where version=337;
reset role;
commit;
