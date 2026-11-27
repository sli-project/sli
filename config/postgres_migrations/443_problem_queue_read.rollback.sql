begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_problem_queue_read443'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=443 and name='problem_queue_read')
       or exists(select 1 from public.schema_migrations where version>443) then
        raise exception 'problem_queue_read443_rollback_preflight' using errcode='55000';
    end if;
end $$;
reset role;
lock table public.findings,public.semantic_security_scenarios,public.finding_event_copies337 in share row exclusive mode;
drop trigger problem_queue_entry443 on public.findings;
set local role adlog_storage_owner;
drop view public.problem_queue_visible443,public.problem_queue_external443,public.problem_queue_scenario_keys443,
    public.problem_queue_occurrence_source443;
drop trigger problem_queue_scenario443 on public.semantic_security_scenarios;
drop trigger problem_queue_domains_insert443 on public.finding_event_copies337;
drop trigger problem_queue_domains_update443 on public.finding_event_copies337;
drop trigger problem_queue_domains_delete443 on public.finding_event_copies337;
drop trigger problem_queue_domains_truncate443 on public.finding_event_copies337;
drop function public.problem_queue_entry443(),public.problem_queue_object443(bigint,text,text,text),
    public.problem_queue_scenario443(),public.problem_queue_scenario443(text,text,text),public.problem_queue_domains443();
drop index public.problem_queue_occurrence_witness443,public.problem_queue_subject_witness443,
    public.problem_queue_audit_witness443,public.problem_queue_external_evidence443;
drop table public.problem_queue_entries443,public.problem_queue_scenarios443,public.problem_queue_domains443,
    public.problem_queue_evidence443;
drop type public.problem_queue_representative443,public.problem_queue_password443;
reset role;
delete from public.schema_migrations where version=443 and name='problem_queue_read';
commit;
