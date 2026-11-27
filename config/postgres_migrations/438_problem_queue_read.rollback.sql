begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_problem_queue_read438'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=438 and name='problem_queue_read')
       or exists(select 1 from public.schema_migrations where version>438) then
        raise exception 'problem_queue_read438_rollback_preflight' using errcode='55000';
    end if;
end $$;
lock table public.findings,public.semantic_security_scenarios,public.finding_event_copies337 in share row exclusive mode;
drop trigger problem_queue_entry438 on public.findings;
set local role adlog_storage_owner;
drop view public.problem_queue_visible438,public.problem_queue_external438,public.problem_queue_scenario_keys438,
    public.problem_queue_occurrence_source438;
drop trigger problem_queue_scenario438 on public.semantic_security_scenarios;
drop trigger problem_queue_domains_insert438 on public.finding_event_copies337;
drop trigger problem_queue_domains_update438 on public.finding_event_copies337;
drop trigger problem_queue_domains_delete438 on public.finding_event_copies337;
drop trigger problem_queue_domains_truncate438 on public.finding_event_copies337;
drop function public.problem_queue_entry438(),public.problem_queue_object438(bigint,text,text,text),
    public.problem_queue_scenario438(),public.problem_queue_scenario438(text,text,text),public.problem_queue_domains438();
drop index public.problem_queue_occurrence_witness438,public.problem_queue_subject_witness438,
    public.problem_queue_audit_witness438,public.problem_queue_external_evidence438;
drop table public.problem_queue_entries438,public.problem_queue_scenarios438,public.problem_queue_domains438,
    public.problem_queue_evidence438;
drop type public.problem_queue_representative438,public.problem_queue_password438;
reset role;
delete from public.schema_migrations where version=438 and name='problem_queue_read';
commit;
