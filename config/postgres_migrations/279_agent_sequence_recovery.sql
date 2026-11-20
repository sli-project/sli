begin;
select pg_advisory_xact_lock(hashtext('ad_log_agent_sequence_recovery_v279'));
do $$ declare prior text; begin
    if not exists(select 1 from public.schema_migrations where version=278 and name='file_ransom_policy_readiness') then
        raise exception 'migration 279 requires exact migration 278 file_ransom_policy_readiness';
    end if;
    if exists(select 1 from public.schema_migrations where version=279) then
        raise exception 'migration 279 already applied or occupied';
    end if;
    select pg_get_expr(conbin,conrelid) into strict prior from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action in (''sequence_gap_observed'',''sequence_gap_authorized'',''sequence_gap_accepted''))',prior);
end $$;
create index sli_agent_sequence_gap_tip on public.sli_agent_audit(target,(details->>'module_id'),id desc)
    where action='sequence_gap_observed';
create index sli_agent_sequence_gap_decision on public.sli_agent_audit(action,(details->>'observation_id'),id desc)
    where action in ('sequence_gap_authorized','sequence_gap_accepted');
create index sli_agent_sequence_gap_history on public.sli_agent_audit(target,id desc)
    where action='sequence_gap_accepted';
insert into public.schema_migrations(version,name) values(279,'agent_sequence_recovery');
commit;
