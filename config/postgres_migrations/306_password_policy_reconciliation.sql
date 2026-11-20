-- Reconcile schema300 password contract and policy admission after 305.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_policy_reconciliation_v306'));
do $$ begin
 if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
 or not exists(select 1 from public.schema_migrations where version=301 and name='identity_attack_rules')
 or not exists(select 1 from public.schema_migrations where version=302 and name='attack_precursors')
 or not exists(select 1 from public.schema_migrations where version=303 and name='evsearch_fact_publication')
 or not exists(select 1 from public.schema_migrations where version=304 and name='nps_agent_row_lock')
 or not exists(select 1 from public.schema_migrations where version=305 and name='agent_group_approval_delivery')
 or exists(select 1 from public.schema_migrations where version>=306)
 or to_regclass('public.password_policy_restore_v306') is not null
 or (select relowner from pg_catalog.pg_class where oid='public.identity_attack_rollback_v301'::regclass) is distinct from 'adlog_storage_owner'::regrole
 or exists(select 1 from pg_catalog.pg_class c, lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a where c.oid='public.identity_attack_rollback_v301'::regclass and a.grantee<>c.relowner)
 then raise exception 'password_policy_306_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
lock table public.identity_attack_rollback_v301 in access share mode;
create table public.password_policy_restore_v306 (
 signature text primary key, fn_oid oid not null, prior_definition text not null, prior_owner oid not null, prior_acl aclitem[], prior_comment text,
 installed_definition text, installed_owner oid, installed_acl aclitem[], installed_comment text
);
revoke all on public.password_policy_restore_v306 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
do $$ begin
 if exists(select 1 from pg_catalog.pg_class c, lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a where c.oid='public.password_policy_restore_v306'::regclass and a.grantee<>c.relowner)
 then raise exception 'password_policy_306_journal_acl' using errcode='55000'; end if;
end $$;
do $$
declare r record; prior text; expected text; body text; fn oid;
begin
 for r in select * from (values
  ('public.read_default_password_window_v2(jsonb)','read_default_password_window_v2','b8cec9fda7c7c035ee1b6cc103c12dcf0ea092e5c5f8357272166998e3837c27'),
  ('public.read_password_retained_proof_v2(jsonb,jsonb)','read_password_retained_proof_v2','c9a1ae44fcf41c1842fa51457ee99f5f5c04976889b39215b732218c244a75bf'),
  ('public.password_v2_native_cost(jsonb,jsonb)','password_v2_native_cost','973b6fc0acc3c0cd1718eb013ad26e8cca8c0eb5dfa200c62cadde8a8ed331ac'),
  ('public.password_v2_check_state(jsonb,jsonb,text)','password_v2_check_state','916d9da3f0996eadfd8a93f0999ff209b1b74519a3c39be070c28a2115ad93b8'),
  ('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)','complete_password_producer_batch_v2','78dca857150c39d8e94b0da802927abd3cd3345fa97769b91d3cf424b393c880')
 ) as v(signature,fn_name,source_hash) loop
  fn:=r.signature::regprocedure;
  if (select proowner from pg_catalog.pg_proc where oid=fn) is distinct from 'adlog_storage_owner'::regrole then raise exception 'password_policy_306_owner' using errcode='55000'; end if;
  select statement into strict prior from public.identity_attack_rollback_v301 where phase=10 and statement like 'CREATE OR REPLACE FUNCTION public.'||r.fn_name||'(%';
  if encode(sha256(convert_to(split_part(prior,'$function$',2),'UTF8')),'hex') is distinct from r.source_hash then raise exception 'password_policy_306_source_mismatch' using errcode='55000'; end if;
  expected:=case when r.fn_name in ('read_default_password_window_v2','read_password_retained_proof_v2','password_v2_native_cost') then replace(prior,'(4625,4771,4776)','(4624,4625,4771,4776)')
   when r.fn_name='password_v2_check_state' then replace(prior,'''too_late''','''too_late'',''successful_logon''')
   else replace(prior,'where m.value->''reason''=''null''::jsonb','where (m.value->''reason''=''null''::jsonb or (execution->>''rule_id''=''qw.password-spray'' and m.value->>''reason''=''successful_logon''))') end;
  if expected=prior or expected is distinct from pg_get_functiondef(fn) then raise exception 'password_policy_306_installed_mismatch' using errcode='55000'; end if;
  insert into public.password_policy_restore_v306(signature,fn_oid,prior_definition,prior_owner,prior_acl,prior_comment)
   select r.signature,p.oid,pg_get_functiondef(p.oid),p.proowner,p.proacl,obj_description(p.oid,'pg_proc') from pg_catalog.pg_proc p where p.oid=fn;
  execute prior;
  if pg_get_functiondef(fn) is distinct from prior then raise exception 'password_policy_306_restore_mismatch' using errcode='55000'; end if;
 end loop;
 fn:='public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure;
 if (select proowner from pg_catalog.pg_proc where oid=fn) is distinct from 'adlog_storage_owner'::regrole or (select encode(sha256(convert_to(prosrc,'UTF8')),'hex') from pg_catalog.pg_proc where oid=fn) is distinct from '97ffd996d821b4152462c9b106a2474f3a924412fc3ef645216f10a1b4228a61' then raise exception 'password_policy_306_admission_mismatch' using errcode='55000'; end if;
 select pg_get_functiondef(fn) into body;
 insert into public.password_policy_restore_v306(signature,fn_oid,prior_definition,prior_owner,prior_acl,prior_comment)
  select 'public.ensure_default_qw_policy_v262(text,integer,text)',p.oid,body,p.proowner,p.proacl,obj_description(p.oid,'pg_proc') from pg_catalog.pg_proc p where p.oid=fn;
 if position('''qw.disabled-account-logon''' in body)=0 or position('-- A prior decision' in body)=0 or position('when s->>''plugin_id''=''sli.workstations'' then ''workstation_observation''' in body)=0 then raise exception 'password_policy_306_admission_anchor' using errcode='55000'; end if;
    body:=replace(body,'''qw.disabled-account-logon''',
        '''qw.disabled-account-logon'',''qw.kerberoasting'',''qw.asrep-roasting'',''qw.ad-preauth-disabled'',''qw.logon-fanout'',''qw.privileged-group-addition''');
    body:=replace(body,'when s->>''plugin_id''=''sli.workstations'' then ''workstation_observation''',
        'when s->>''plugin_id''=''sli.ad-snapshot'' then ''ad_directory_observation'' when s->>''plugin_id''=''sli.workstations'' then ''workstation_observation''');
    body:=replace(body,'-- A prior decision',
        'if pin->>''rule_id'' in (''qw.kerberoasting'',''qw.asrep-roasting'',''qw.ad-preauth-disabled'',''qw.logon-fanout'',''qw.privileged-group-addition'') then
            if pin->>''kind'' is distinct from ''threshold'' or pin->>''rule_version'' is distinct from ''1''
                or d->>''scenario_kind'' is distinct from pin->>''rule_id''
                or s->>''plugin_id'' is distinct from (case when pin->>''rule_id''=''qw.ad-preauth-disabled'' then ''sli.ad-snapshot'' else ''sli.windows.ad-dc'' end)
                or d#>>''{risk,class}'' is distinct from (case when pin->>''rule_id''=''qw.ad-preauth-disabled'' then ''medium'' else ''high'' end)
                or d->>''merge_window_seconds'' is distinct from ''600'' then
                raise exception ''identity_attack_policy_denied'' using errcode=''42501'';
            end if;
        end if;
        -- A prior decision');
    execute body;
    update public.password_policy_restore_v306 j set installed_definition=pg_get_functiondef(p.oid),installed_owner=p.proowner,installed_acl=p.proacl,installed_comment=obj_description(p.oid,'pg_proc') from pg_catalog.pg_proc p where p.oid=j.fn_oid;
    if (select count(*) from public.password_policy_restore_v306)<>6 or exists(select 1 from public.password_policy_restore_v306 where prior_owner is distinct from installed_owner or prior_acl is distinct from installed_acl or prior_comment is distinct from installed_comment or installed_definition is null) then raise exception 'password_policy_306_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(306,'password_policy_reconciliation');
reset role;
commit;
