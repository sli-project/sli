-- Explicit stopped-system rollback: schema305 retains the known producer conflict.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_policy_reconciliation_v306'));
do $$ begin
 if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
 or not exists(select 1 from public.schema_migrations where version=306 and name='password_policy_reconciliation')
 or exists(select 1 from public.schema_migrations where version>306)
 or (select relowner from pg_catalog.pg_class where oid='public.password_policy_restore_v306'::regclass) is distinct from 'adlog_storage_owner'::regrole
 or (select relowner from pg_catalog.pg_class where oid='public.identity_attack_rollback_v301'::regclass) is distinct from 'adlog_storage_owner'::regrole
 or exists(select 1 from pg_catalog.pg_class c, lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a where c.oid='public.identity_attack_rollback_v301'::regclass and a.grantee<>c.relowner)
 or exists(select 1 from pg_catalog.pg_class c, lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a where c.oid='public.password_policy_restore_v306'::regclass and a.grantee<>c.relowner)
 then raise exception 'password_policy_306_rollback_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
lock table public.password_policy_restore_v306 in access exclusive mode;
do $$ declare r record; source text; expected text; fn_name text; begin
 if (select count(*) from public.password_policy_restore_v306)<>6
 or (select array_agg(signature order by signature) from public.password_policy_restore_v306) is distinct from array[
 'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)',
 'public.ensure_default_qw_policy_v262(text,integer,text)',
 'public.password_v2_check_state(jsonb,jsonb,text)',
 'public.password_v2_native_cost(jsonb,jsonb)',
 'public.read_default_password_window_v2(jsonb)',
 'public.read_password_retained_proof_v2(jsonb,jsonb)']::text[]
 or exists(select 1 from public.password_policy_restore_v306 j left join pg_catalog.pg_proc p on p.oid=j.fn_oid
  where to_regprocedure(j.signature)::oid is distinct from j.fn_oid
  or p.oid is null or pg_get_functiondef(p.oid) is distinct from j.installed_definition
  or p.proowner is distinct from j.installed_owner or p.proacl is distinct from j.installed_acl
  or obj_description(p.oid,'pg_proc') is distinct from j.installed_comment
  or j.prior_owner is distinct from j.installed_owner or j.prior_acl is distinct from j.installed_acl
  or j.prior_comment is distinct from j.installed_comment) then
  raise exception 'password_policy_306_rollback_drift' using errcode='55000'; end if;
 -- Bind the saved 305 definitions back to the immutable 301 predecessor journal.
 for r in select * from public.password_policy_restore_v306 order by signature loop
  if r.signature='public.ensure_default_qw_policy_v262(text,integer,text)' then
   if encode(sha256(convert_to(split_part(r.prior_definition,'$function$',2),'UTF8')),'hex') is distinct from '97ffd996d821b4152462c9b106a2474f3a924412fc3ef645216f10a1b4228a61' then raise exception 'password_policy_306_prior_drift' using errcode='55000'; end if;
  else
   fn_name:=split_part(split_part(r.signature,'.',2),'(',1);
   select statement into strict source from public.identity_attack_rollback_v301 where phase=10 and statement like 'CREATE OR REPLACE FUNCTION public.'||fn_name||'(%';
   expected:=case when fn_name in ('read_default_password_window_v2','read_password_retained_proof_v2','password_v2_native_cost') then replace(source,'(4625,4771,4776)','(4624,4625,4771,4776)')
    when fn_name='password_v2_check_state' then replace(source,'''too_late''','''too_late'',''successful_logon''')
    else replace(source,'where m.value->''reason''=''null''::jsonb','where (m.value->''reason''=''null''::jsonb or (execution->>''rule_id''=''qw.password-spray'' and m.value->>''reason''=''successful_logon''))') end;
   if expected=source or expected is distinct from r.prior_definition or source is distinct from r.installed_definition then raise exception 'password_policy_306_prior_drift' using errcode='55000'; end if;
  end if;
 end loop;
 for r in select * from public.password_policy_restore_v306 order by signature loop
  execute r.prior_definition;
  if pg_get_functiondef(r.fn_oid) is distinct from r.prior_definition
    or (select proowner from pg_catalog.pg_proc where oid=r.fn_oid) is distinct from r.prior_owner
    or (select proacl from pg_catalog.pg_proc where oid=r.fn_oid) is distinct from r.prior_acl
    or obj_description(r.fn_oid,'pg_proc') is distinct from r.prior_comment then
    raise exception 'password_policy_306_rollback_restore_mismatch' using errcode='55000'; end if;
 end loop;
end $$;
drop table public.password_policy_restore_v306;
delete from public.schema_migrations where version=306 and name='password_policy_reconciliation';
reset role;
commit;
