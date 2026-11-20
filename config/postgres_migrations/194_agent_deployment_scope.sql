-- Preparation only; auto approval is disabled unless an administrator opts in.
begin;
select pg_advisory_xact_lock(hashtext('sli_agent_deployment_scope_v194'));
do $$
begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=193 and name='file_audit_retention')
       or exists(select 1 from public.schema_migrations where version>=194) then
        raise exception 'migration 194 prerequisites failed';
    end if;
end $$;
set local role adlog_storage_owner;
do $$
declare target regclass; constraint_name text;
begin
    foreach target in array array['public.sli_agent_enrollment_groups'::regclass,'public.sli_agent_group_tokens'::regclass]
    loop
        select conname into strict constraint_name from pg_constraint
            where conrelid=target and contype='c' and pg_get_expr(conbin,conrelid) like '%cardinality(ou_entity_ids)%';
        execute format('alter table %s drop constraint %I',target,constraint_name);
        execute format('alter table %s add check(cardinality(ou_entity_ids) between 0 and 128 and array_position(ou_entity_ids,null) is null)',target);
    end loop;
end $$;
alter table public.sli_agent_group_tokens
    add column computer_entity_ids bigint[] not null default '{}'
        check(cardinality(computer_entity_ids) between 0 and 1000 and array_position(computer_entity_ids,null) is null),
    add column enrollment_policy jsonb not null default '{}' check(jsonb_typeof(enrollment_policy)='object');
-- Admission retries rotate an unused, key-bound credential after a lost reply.
grant update(token_hash,created_at,expires_at) on public.sli_agent_enrollment_tokens to adlog_user;
do $$
declare prior_check text;
begin
    select pg_get_expr(conbin,conrelid) into strict prior_check from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''group_auto_approval'')',prior_check);
end $$;
reset role;
insert into public.schema_migrations(version,name) values(194,'agent_deployment_scope');
commit;
