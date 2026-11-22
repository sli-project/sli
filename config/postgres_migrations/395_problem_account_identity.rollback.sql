begin;
select pg_advisory_xact_lock(hashtext('sli_problem_account_identity395'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=395 and name='problem_account_identity')
       or exists(select 1 from public.schema_migrations where version>395) then
        raise exception 'problem_account_identity395_rollback_preflight' using errcode='55000';
    end if;
end $$;

update public.findings f set severity=b.previous_severity from public.problem_severity_backup395 b
where f.id=b.finding_id and f.severity=b.applied_severity and f.updated_at is not distinct from b.updated_at;

set local role adlog_storage_owner;
create or replace function public.password_definition_revision393(r text) returns integer
language sql immutable set search_path=pg_catalog,pg_temp as $$ select 2 $$;
do $$ declare planner text; restored text; begin
    select pg_get_functiondef('public.password_plan388(jsonb,text)'::regprocedure) into planner;
    restored:=replace(planner,'coalesce(c.watermark,least(first_at,seam))','coalesce(c.watermark,first_at,seam)');
    if restored=planner then
        raise exception 'problem_account_identity395_planner_rollback_shape' using errcode='55000';
    end if;
    execute restored;
end $$;
do $$ declare r record; installed text; restored text; begin
    for r in select * from (values
        ('public.read_password_event_window362(jsonb,jsonb)',
            'e.event_id in (4625,4771,4776)',
            '(e.event_id in (4625,4771,4776) or (e.event_id=4624 and (execution->>''rule_version'')::integer>=395))'),
        ('public.read_password_retained_proof_v2_short337(jsonb,jsonb)',
            'event_id in (4625,4771,4776)','event_id in (4624,4625,4771,4776)'),
        ('public.password_v2_native_cost_short337(jsonb,jsonb)',
            'event_id in (4625,4771,4776)','event_id in (4624,4625,4771,4776)'),
        ('public.password_v2_check_state(jsonb,jsonb,text)',
            '''too_late''','''too_late'',''successful_logon''')
    ) v(signature,prev_fragment,next_fragment) loop
        select pg_get_functiondef(r.signature::regprocedure) into installed;
        restored:=replace(installed,r.next_fragment,r.prev_fragment);
        if restored=installed then
            raise exception 'problem_account_identity395_password_rollback_shape:%',r.signature using errcode='55000';
        end if;
        execute restored;
    end loop;
end $$;
drop function public.notification_password_facts395(uuid,uuid);
drop function public.password_problem_facts395(bigint,text);
drop table public.problem_severity_backup395;
reset role;
revoke select(domain_id,entity_id,alias_type,normalized_value) on public.ad_context_entity_aliases from adlog_storage_owner;
delete from public.schema_migrations where version=395 and name='problem_account_identity';
commit;
