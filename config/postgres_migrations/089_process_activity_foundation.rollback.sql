-- Evidence-preserving rollback for Stage 8 process/activity foundation.
begin;
set local lock_timeout='5s';
set local statement_timeout='30s';
set local search_path=pg_catalog,public;
select pg_advisory_xact_lock(hashtext('ad_log_reports_process_activity_foundation_v89'));

do $$
begin
    if not pg_has_role(session_user, 'adlog_storage_owner', 'MEMBER') then
        raise exception 'migration 089 rollback requires membership in adlog_storage_owner';
    end if;
    if not exists (
        select 1 from public.schema_migrations
        where version=89 and name='process_activity_foundation'
    ) then
        raise exception 'migration 089 rollback requires its exact marker';
    end if;
    if exists(select 1 from public.schema_migrations where version>89) then
        raise exception 'migration 089 rollback refuses later migrations';
    end if;
    if to_regclass('public.process_episode_revisions') is null
       or to_regclass('public.process_episode_evidence') is null
       or to_regprocedure('public.write_process_episode_revision_v89(jsonb)') is null then
        raise exception 'migration 089 rollback requires all owned objects';
    end if;
    if exists(select 1 from public.process_episode_revisions)
       or exists(select 1 from public.process_episode_evidence)
       or exists(
           select 1 from public.event_facts_v2 where
               process_parent_id is not null or process_command_line is not null
               or process_user_sid is not null or process_user_name is not null
               or process_user_domain is not null or process_logon_id is not null
               or service_file is not null or service_account is not null
               or service_start_type is not null or task_content is not null
               or task_change is not null or native_process_id is not null
       ) then
        raise exception 'migration 089 rollback would discard process episode evidence';
    end if;
end
$$;

set local role adlog_storage_owner;
revoke all on function public.write_process_episode_revision_v89(pg_catalog.jsonb) from public,adlog_semantic_worker;
drop function public.write_process_episode_revision_v89(pg_catalog.jsonb);
drop trigger process_episode_evidence_no_truncate on public.process_episode_evidence;
drop trigger process_episode_evidence_immutable on public.process_episode_evidence;
drop trigger process_episode_revisions_no_truncate on public.process_episode_revisions;
drop trigger process_episode_revisions_immutable on public.process_episode_revisions;
drop table public.process_episode_evidence;
drop table public.process_episode_revisions;
drop function public.process_episode_evidence_reject_mutation();

alter table public.event_facts_v2
    drop constraint event_facts_v2_process_name_bounded,
    drop constraint event_facts_v2_process_id_windows,
    drop constraint event_facts_v2_powershell_process_id_windows,
    add constraint event_facts_v2_process_name_bounded check (process_name is null or length(process_name) <= 512),
    add constraint event_facts_v2_process_id_bounded check (process_id is null or length(process_id) <= 128),
    add constraint event_facts_v2_powershell_process_id_bounded check (powershell_process_id is null or length(powershell_process_id) <= 128),
    drop column process_parent_id,
    drop column process_command_line,
    drop column process_user_sid,
    drop column process_user_name,
    drop column process_user_domain,
    drop column process_logon_id,
    drop column service_file,
    drop column service_account,
    drop column service_start_type,
    drop column task_content,
    drop column task_change,
    drop column native_process_id;

delete from public.schema_migrations where version=89 and name='process_activity_foundation';
commit;
