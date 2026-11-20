-- GAP126: preserve the complete deployed audit predicate and append only the
-- source-emitted delivery event. This does not approve any enrollment itself.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_agent_group_delivery_v305'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'agent_group_delivery_preflight' using errcode='55000';
    end if;
    if not exists(select 1 from public.schema_migrations where version=300 and name='owner_recovery')
       or not exists(select 1 from public.schema_migrations where version=301 and name='identity_attack_rules')
       or not exists(select 1 from public.schema_migrations where version=302 and name='attack_precursors')
       or not exists(select 1 from public.schema_migrations where version=303 and name='evsearch_fact_publication')
       or not exists(select 1 from public.schema_migrations where version=304 and name='nps_agent_row_lock')
       or exists(select 1 from public.schema_migrations where version>=305) then
        raise exception 'agent_group_delivery_preflight' using errcode='55000';
    end if;
    if (select relowner from pg_catalog.pg_class where oid='public.sli_agent_audit'::regclass)
         is distinct from 'adlog_storage_owner'::regrole
       or not exists(select 1 from pg_catalog.pg_attribute where attrelid='public.sli_agent_audit'::regclass
            and attname='action' and attnotnull and not attisdropped)
       or not exists(select 1 from pg_catalog.pg_constraint where conrelid='public.sli_agent_audit'::regclass
            and conname='sli_agent_audit_action_check' and contype='c' and convalidated and conislocal)
       or to_regclass('public.sli_agent_group_delivery_restore_v305') is not null then
        raise exception 'agent_group_delivery_contract_invalid' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;
lock table public.sli_agent_audit in access exclusive mode;
create table public.sli_agent_group_delivery_restore_v305 (
    singleton boolean primary key check(singleton),
    prior_definition text not null,
    prior_comment text,
    installed_definition text not null,
    installed_comment text
);
revoke all on public.sli_agent_group_delivery_restore_v305
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
do $$ declare prior text; expression text; no_inherit boolean; note text; begin
    select pg_get_constraintdef(oid),pg_get_expr(conbin,conrelid),connoinherit,
           obj_description(oid,'pg_constraint')
      into strict prior,expression,no_inherit,note from pg_catalog.pg_constraint
      where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''group_approval_delivery'')%s',
        expression,case when no_inherit then ' no inherit' else '' end);
    execute format('comment on constraint sli_agent_audit_action_check on public.sli_agent_audit is %L',note);
    insert into public.sli_agent_group_delivery_restore_v305
      select true,prior,note,pg_get_constraintdef(oid),obj_description(oid,'pg_constraint') from pg_catalog.pg_constraint
      where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
end $$;
insert into public.schema_migrations(version,name) values(305,'agent_group_approval_delivery');
reset role;
commit;
