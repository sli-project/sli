begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_threshold418'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=418 and name='password_threshold_rules')
       or exists(select 1 from public.schema_migrations where version>418) then
        raise exception 'password_threshold418_rollback_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

drop function public.password_problem_facts395(bigint,text);
alter function public.password_problem_facts_before418(bigint,text) rename to password_problem_facts395;
drop function public.publish_password_threshold_facts418(bigint,uuid);
drop function public.read_password_threshold_status418(bigint[]);
drop function public.write_password_threshold_pass418(jsonb,text,bigint,text,jsonb);
drop function public.read_password_threshold_episodes418(jsonb,text,timestamptz);
drop function public.read_password_threshold_events418(jsonb,text,timestamptz,timestamptz,bigint,timestamptz,bigint);
drop function public.password_threshold_pass418(jsonb,text,timestamptz);
drop function public.admit_password_threshold418(text,text);
drop function public.password_threshold_scope418(jsonb,text);
delete from public.semantic_identity_attack_episodes_v301 where password_state418 is not null;
alter table public.semantic_identity_attack_episodes_v301 drop column password_state418,drop column password_finding418;
reset role;
revoke select(closed_at) on public.findings from adlog_storage_owner;
alter table public.findings drop column password_threshold_facts418;
set local role adlog_storage_owner;
delete from public.schema_migrations where version=418 and name='password_threshold_rules';
reset role;
commit;
