-- T109a: bounded native identity behaviours and directory configuration evidence.
begin;
select pg_advisory_xact_lock(hashtext('sli_identity_attack_rules_v301'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=286 and name='sigma_rule_labels')
       or not exists(select 1 from public.schema_migrations where version=300 and name='owner_recovery')
       or exists(select 1 from public.schema_migrations where version>=301) then
        raise exception 'migration 301 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

-- Retain exact predecessor definitions, including changes from independent PRs.
-- This journal contains DDL only and is inaccessible to runtime principals.
create table public.identity_attack_rollback_v301(phase integer not null,statement text not null);
revoke all on public.identity_attack_rollback_v301 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.identity_attack_rollback_v301
select 10,pg_get_functiondef(signature::regprocedure) from unnest(array[
    'public.ensure_default_qw_policy_v262(text,integer,text)',
    'public.read_default_password_window_v2(jsonb)',
    'public.read_password_retained_proof_v2(jsonb,jsonb)',
    'public.password_v2_native_cost(jsonb,jsonb)',
    'public.password_v2_check_state(jsonb,jsonb,text)',
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)',
    'public.semantic_finding_in_domains_v265(bigint,bigint[])']) signature;
insert into public.identity_attack_rollback_v301
select 30,format('alter table %s drop constraint %I; alter table %s add constraint %I %s',
    conrelid::regclass,conname,conrelid::regclass,conname,pg_get_constraintdef(oid))
from pg_constraint where conrelid in ('public.finding_evidence_source_bindings'::regclass,
    'public.finding_evidence_refs'::regclass) and contype='c' and pg_get_constraintdef(oid) like '%storage_kind%';
do $$
declare signature text; a record; v record;
begin
    foreach signature in array array['public.default_detection_sources()',
        'public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'] loop
        insert into public.identity_attack_rollback_v301 values(20,
            format('revoke all on function %s from public,adlog_user,adlog_storage_worker,adlog_semantic_worker',signature));
        for a in select * from aclexplode(coalesce((select proacl from pg_proc where oid=signature::regprocedure),
            acldefault('f',(select proowner from pg_proc where oid=signature::regprocedure)))) loop
            insert into public.identity_attack_rollback_v301 values(21,
                format('grant %s on function %s to %s%s',a.privilege_type,signature,
                    case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end,
                    case when a.is_grantable then ' with grant option' else '' end));
        end loop;
    end loop;
    if to_regclass('public.findings_active') is not null then
        select pg_get_viewdef(oid,true) as body,reloptions,relowner,relacl into v
            from pg_class where oid='public.findings_active'::regclass;
        insert into public.identity_attack_rollback_v301 values(40,
            'drop view public.findings_active; create view public.findings_active'
            ||case when v.reloptions is null then '' else ' with ('||array_to_string(v.reloptions,',')||')' end
            ||' as '||v.body);
        insert into public.identity_attack_rollback_v301 values(41,
            'revoke all on public.findings_active from public,adlog_user,adlog_storage_worker,adlog_semantic_worker');
        for a in select * from aclexplode(coalesce(v.relacl,acldefault('r',v.relowner))) loop
            insert into public.identity_attack_rollback_v301 values(42,
                format('grant %s on public.findings_active to %s%s',a.privilege_type,
                    case when a.grantee=0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end,
                    case when a.is_grantable then ' with grant option' else '' end));
        end loop;
        insert into public.identity_attack_rollback_v301 values(43,
            format('alter view public.findings_active owner to %I',pg_get_userbyid(v.relowner)));
    end if;
end $$;
insert into public.identity_attack_rollback_v301
select 90,format('revoke select on %s from adlog_storage_owner',c.oid::regclass)
from pg_class c where c.oid in ('public.ad_context_runs'::regclass,'public.ad_context_sections'::regclass,
    'public.ad_context_evidence'::regclass,'public.ad_context_entity_versions'::regclass,'public.entities_v2'::regclass)
and not exists(select 1 from aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
    where a.grantee='adlog_storage_owner'::regrole and a.privilege_type='SELECT');

-- findings and directory tables can belong to other baseline owners.
reset role;
alter table public.findings add column identity_presentation_json jsonb;
grant select(identity_presentation_json) on public.findings to adlog_storage_owner;
grant select on public.ad_context_runs,public.ad_context_sections,public.ad_context_evidence,
    public.ad_context_entity_versions,public.entities_v2 to adlog_storage_owner;
set local role adlog_storage_owner;
do $$
declare body text;
begin
    if to_regclass('public.findings_active') is not null then
        select rtrim(pg_get_viewdef('public.findings_active'::regclass,true),';' || chr(10) || ' ') into body;
        execute 'create or replace view public.findings_active with (security_barrier=true) as select prior.*,current_finding.identity_presentation_json from ('
            ||body||') prior join public.findings current_finding on current_finding.id=prior.id';
    end if;
end $$;
-- Preserve every previous type constraint verbatim, adding one exact snapshot type.
do $$
declare t text; c record; extra text;
begin
    foreach t in array array['finding_evidence_source_bindings','finding_evidence_refs'] loop
        for c in select conname,pg_get_expr(conbin,conrelid) as expression from pg_constraint
            where conrelid=('public.'||t)::regclass and contype='c'
              and pg_get_constraintdef(oid) like '%storage_kind%' loop
            extra:='storage_kind=''ad_directory_observation'' and plugin_id=''sli.ad-snapshot'' and collection_scope_id=''''';
            if t='finding_evidence_source_bindings' then
                extra:=extra||' and log_source_id is null and agent_key is null and agent_id is null';
            else
                extra:=extra||' and case when native_id ~ ''^[1-9][0-9]{0,18}$'' then native_id::numeric<9223372036854775808 else false end';
            end if;
            execute format('alter table public.%I drop constraint %I',t,c.conname);
            execute format('alter table public.%I add constraint %I check ((%s) or (%s))',t,c.conname,c.expression,extra);
        end loop;
    end loop;
end $$;

create index idx_identity_attack_source_time_v301 on public.events_v2_core(log_source_id,time_created_utc,id)
    where event_id in (4624,4720,4728,4732,4756,4768,4769);

create function public.identity_snapshot_rows_v301(s jsonb,p_refs bigint[])
returns table(source_event_id bigint,occurred_at_utc timestamptz,sha256 text,storage_kind text,attributes_json jsonb)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select evidence.id,evidence.observed_at_utc,
        encode(sha256(convert_to(jsonb_build_object('run',run.run_id,'bundle',encode(run.bundle_sha256,'hex'),
            'evidence',evidence.id,'integrity',encode(evidence.integrity_sha256,'hex'),
            'record',version.attributes_json)::text,'UTF8')),'hex'),
        'ad_directory_observation'::text,version.attributes_json
    from public.ad_context_runs run
    join public.ad_context_sections section on section.run_id=run.run_id
        and section.section_name='directory_accounts' and section.status='complete'
    join public.ad_context_evidence evidence on evidence.source_run_id=run.run_id
        and evidence.evidence_type='entity_observation' and evidence.locator_json->>'section'='directory_accounts'
    join public.entities_v2 entity on entity.domain_id=run.domain_id
    join public.ad_context_entity_versions version on version.entity_id=entity.id
        and version.source_section='directory_accounts'
        and version.attributes_json->>'record_key'=evidence.locator_json->>'record_key'
        and version.valid_from_utc<=evidence.observed_at_utc
        and (version.valid_to_utc is null or version.valid_to_utc>evidence.observed_at_utc)
    where s->>'plugin_id'='sli.ad-snapshot' and s->>'collection_scope_id'=''
      and s->>'source_generation'='directory-v1' and 'domain:'||run.domain_id::text=s->>'source_instance_id'
      and run.source_pack_id='sli.windows.ad-context' and run.status='completed'
      and (p_refs is null or evidence.id=any(p_refs))
      and (p_refs is not null or run.run_id=(
          select latest.run_id from public.ad_context_runs latest
          join public.ad_context_sections sec on sec.run_id=latest.run_id and sec.section_name='directory_accounts'
          where latest.domain_id=run.domain_id and latest.source_pack_id='sli.windows.ad-context'
            and latest.observed_at_utc<=statement_timestamp()
          order by latest.observed_at_utc desc,latest.created_at desc,latest.run_id desc limit 1))
    order by evidence.id limit 10001
$$;
revoke all on function public.identity_snapshot_rows_v301(jsonb,bigint[]) from public,adlog_user,adlog_semantic_worker;

create function public.read_identity_attack_snapshot_v301(s jsonb,p_refs bigint[] default null)
returns table(source_event_id bigint,occurred_at_utc timestamptz,sha256 text,storage_kind text,attributes_json jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if (p_refs is not null and cardinality(p_refs) not between 1 and 256)
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
            s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id','ad_directory_observation') is not true then
        raise exception 'identity_attack_source_denied' using errcode='42501';
    end if;
    return query select * from public.identity_snapshot_rows_v301(s,p_refs);
end $$;
revoke all on function public.read_identity_attack_snapshot_v301(jsonb,bigint[]) from public;
grant execute on function public.read_identity_attack_snapshot_v301(jsonb,bigint[]) to adlog_semantic_worker;

alter function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)
    rename to resolve_finding_evidence_ref_before_v301;
revoke all on function public.resolve_finding_evidence_ref_before_v301(uuid,text,text,text,text,text,text,text)
    from public,adlog_user,adlog_semantic_worker;
create function public.resolve_finding_evidence_ref(p_installation uuid,p_plugin text,p_source text,p_generation text,
    p_collection text,p_kind text,p_native text,p_sha256 text) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_kind is distinct from 'ad_directory_observation' then
        return public.resolve_finding_evidence_ref_before_v301(p_installation,p_plugin,p_source,p_generation,p_collection,p_kind,p_native,p_sha256);
    end if;
    if p_plugin is distinct from 'sli.ad-snapshot' or p_collection is distinct from ''
       or p_native is null or p_native !~ '^[1-9][0-9]{0,18}$' or p_native::numeric>=9223372036854775808
       or public.finding_evidence_scope_allowed(p_installation,p_plugin,p_source,p_generation,p_collection,p_kind) is not true then return false; end if;
    return exists(select 1 from public.identity_snapshot_rows_v301(jsonb_build_object('plugin_id',p_plugin,
        'source_instance_id',p_source,'source_generation',p_generation,'collection_scope_id',p_collection),array[p_native::bigint]) r
        where r.sha256=p_sha256);
end $$;
revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;

create function public.read_identity_attack_events_v301(s jsonb,p_refs bigint[] default null)
returns table(source_event_id bigint,event_id integer,occurred_at_utc timestamptz,sha256 text,source_xml text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; tail timestamptz; r record; native jsonb;
begin
    b:=public.password_v2_source_binding(s);
    if p_refs is not null and cardinality(p_refs) not between 1 and 256 then
        raise exception 'identity_attack_arguments_invalid' using errcode='22023'; end if;
    select max(e.time_created_utc) into tail from public.events_v2_core e
        where e.log_source_id=b.log_source_id and e.event_id in (4624,4720,4728,4732,4756,4768,4769)
          and e.time_created_utc<=statement_timestamp();
    for r in select e.id,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex') as digest
        from public.events_v2_core e where e.log_source_id=b.log_source_id
          and e.event_id in (4624,4720,4728,4732,4756,4768,4769)
          and ((p_refs is null and e.time_created_utc between tail-interval '1200 seconds' and tail)
               or (p_refs is not null and e.id=any(p_refs)))
        order by e.time_created_utc,e.id limit 10001 loop
        native:=public.read_agent_semantic_source_v190(r.id);
        if native is null or native#>>'{event_row,xml}' is null
           or public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
             b.source_generation,'','core_event',r.id::text,r.digest) is not true then
            raise exception 'identity_attack_native_unavailable'; end if;
        source_event_id:=r.id; event_id:=r.event_id; occurred_at_utc:=r.time_created_utc;
        sha256:=r.digest; source_xml:=native#>>'{event_row,xml}'; return next;
    end loop;
end $$;
revoke all on function public.read_identity_attack_events_v301(jsonb,bigint[]) from public;
grant execute on function public.read_identity_attack_events_v301(jsonb,bigint[]) to adlog_semantic_worker;

-- Add only enumerated rules to the existing admission path. Its owner-disable,
-- audit, conflict and source-authority logic is retained without new table grants.
do $$
declare body text;
begin
    select pg_get_functiondef('public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure) into body;
    if position('''qw.disabled-account-logon''' in body)=0 then raise exception 'identity_attack_admission_baseline'; end if;
    body:=replace(body,'''qw.disabled-account-logon''',
        '''qw.disabled-account-logon'',''qw.kerberoasting'',''qw.asrep-roasting'',''qw.ad-preauth-disabled'',''qw.logon-fanout'',''qw.privileged-group-addition''');
    body:=replace(body,'case when s->>''plugin_id''=''sli.file-audit'' then ''file_audit_observation'' else ''core_event'' end',
        'case when s->>''plugin_id''=''sli.file-audit'' then ''file_audit_observation'' when s->>''plugin_id''=''sli.ad-snapshot'' then ''ad_directory_observation'' else ''core_event'' end');
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
end $$;

-- A successful 4624 is an optional continuation of the SAME v2 spray episode.
-- Transport and native reservation validators remain in force. No v1 replay.
do $$
declare fn regprocedure; body text;
begin
    foreach fn in array array['public.read_default_password_window_v2(jsonb)'::regprocedure,
        'public.read_password_retained_proof_v2(jsonb,jsonb)'::regprocedure,
        'public.password_v2_native_cost(jsonb,jsonb)'::regprocedure] loop
        select pg_get_functiondef(fn) into body;
        if position('(4625,4771,4776)' in body)=0 then raise exception 'identity_attack_password_baseline'; end if;
        execute replace(body,'(4625,4771,4776)','(4624,4625,4771,4776)');
    end loop;
    select pg_get_functiondef('public.password_v2_check_state(jsonb,jsonb,text)'::regprocedure) into body;
    if position('''too_late''' in body)=0 then raise exception 'identity_attack_state_baseline'; end if;
    execute replace(body,'''too_late''','''too_late'',''successful_logon''');
    select pg_get_functiondef('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure) into body;
    if position('where m.value->''reason''=''null''::jsonb' in body)=0 then
        raise exception 'identity_attack_finalizer_baseline'; end if;
    execute replace(body,'where m.value->''reason''=''null''::jsonb',
        'where (m.value->''reason''=''null''::jsonb or (execution->>''rule_id''=''qw.password-spray'' and m.value->>''reason''=''successful_logon''))');
end $$;

create table public.semantic_identity_attack_episodes_v301 (
    scope_key text not null,rule_id text not null,entity_key text not null,
    episode_key text not null,last_at timestamptz not null,
    primary key(scope_key,rule_id,entity_key,episode_key)
);
revoke all on public.semantic_identity_attack_episodes_v301 from public,adlog_user,adlog_semantic_worker;
create function public.identity_attack_episode_v301(s jsonb,p_rule text,p_entity text,p_at timestamptz,p_seed text) returns text
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare v_scope_key text:=encode(sha256(convert_to(s::text,'UTF8')),'hex'); result text; last_seen timestamptz;
begin
    if p_rule not in ('qw.kerberoasting','qw.asrep-roasting','qw.ad-preauth-disabled','qw.logon-fanout','qw.privileged-group-addition')
       or p_entity !~ '^[a-f0-9]{64}$' or p_seed !~ '^[a-f0-9]{64}$' or p_at is null
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',s->>'source_instance_id',
          s->>'source_generation',s->>'collection_scope_id',case when s->>'plugin_id'='sli.ad-snapshot'
              then 'ad_directory_observation' else 'core_event' end) is not true then
        raise exception 'identity_attack_source_denied' using errcode='42501'; end if;
    perform pg_advisory_xact_lock(hashtextextended(v_scope_key||p_rule||p_entity,0));
    select e.episode_key,e.last_at into result,last_seen from public.semantic_identity_attack_episodes_v301 e
      where e.scope_key=v_scope_key and e.rule_id=p_rule and e.entity_key=p_entity
      order by e.last_at desc,e.episode_key limit 1;
    if result is null or p_at>last_seen+interval '600 seconds' then result:=p_seed; end if;
    insert into public.semantic_identity_attack_episodes_v301 values(v_scope_key,p_rule,p_entity,result,p_at)
    on conflict on constraint semantic_identity_attack_episodes_v301_pkey do update
      set last_at=greatest(excluded.last_at,semantic_identity_attack_episodes_v301.last_at);
    return result;
end $$;
revoke all on function public.identity_attack_episode_v301(jsonb,text,text,timestamptz,text) from public;
grant execute on function public.identity_attack_episode_v301(jsonb,text,text,timestamptz,text) to adlog_semantic_worker;

create function public.identity_attack_episode_known_v301(s jsonb,p_rule text,p_entity text,p_episode text) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',s->>'source_instance_id',
        s->>'source_generation',s->>'collection_scope_id',case when s->>'plugin_id'='sli.ad-snapshot'
        then 'ad_directory_observation' else 'core_event' end)
    and exists(select 1 from public.semantic_identity_attack_episodes_v301 e
        where e.scope_key=encode(sha256(convert_to(s::text,'UTF8')),'hex') and e.rule_id=p_rule
          and e.entity_key=p_entity and e.episode_key=p_episode)
$$;
revoke all on function public.identity_attack_episode_known_v301(jsonb,text,text,text) from public;
grant execute on function public.identity_attack_episode_known_v301(jsonb,text,text,text) to adlog_semantic_worker;

alter function public.default_detection_sources() rename to default_detection_sources_before_v301;
revoke all on function public.default_detection_sources_before_v301() from public,adlog_semantic_worker;
create function public.default_detection_sources() returns table(source jsonb)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare installation uuid; r record; s jsonb;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER') then
        raise exception 'identity_attack_source_denied' using errcode='42501'; end if;
    return query select * from public.default_detection_sources_before_v301();
    select installation_id into strict installation from public.semantic_default_installation;
    for r in select latest.* from (
        select distinct on (run.domain_id) run.* from public.ad_context_runs run
        join public.ad_context_sections section on section.run_id=run.run_id and section.section_name='directory_accounts'
        where run.source_pack_id='sli.windows.ad-context' and run.observed_at_utc<=statement_timestamp()
        order by run.domain_id,run.observed_at_utc desc,run.created_at desc,run.run_id desc
    ) latest join public.ad_context_sections section on section.run_id=latest.run_id and section.section_name='directory_accounts'
      where latest.status='completed' and section.status='complete' order by latest.domain_id limit 128 loop
        s:=jsonb_build_object('installation_id',installation::text,'plugin_id','sli.ad-snapshot',
            'source_instance_id','domain:'||r.domain_id::text,'source_generation','directory-v1','collection_scope_id','');
        insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
            source_instance_id,source_generation,collection_scope_id,storage_kind)
        values((select oid from pg_roles where rolname=session_user),session_user,installation,'sli.ad-snapshot',
            s->>'source_instance_id',s->>'source_generation','','ad_directory_observation') on conflict do nothing;
        source:=jsonb_build_object('scope',s); return next;
    end loop;
end $$;
revoke all on function public.default_detection_sources() from public;
grant execute on function public.default_detection_sources() to adlog_semantic_worker;

-- Preserve the every-witness domain gate, with a distinct directory branch.
do $$
declare body text;
begin
    select pg_get_functiondef('public.semantic_finding_in_domains_v265(bigint,bigint[])'::regprocedure) into body;
    body:=replace(body,'(''core_event'',''file_audit_snapshot'')','(''core_event'',''file_audit_snapshot'',''ad_directory_observation'')');
    if position(') select count(*)>0' in body)=0 then raise exception 'identity_attack_domain_baseline'; end if;
    body:=replace(body,') select count(*)>0',
        'union all select case when proof.sha256=ref.sha256 then run.domain_id end
         from public.finding_evidence_refs ref
         left join public.ad_context_evidence evidence on evidence.id=case when ref.storage_kind=''ad_directory_observation'' then ref.native_id::bigint end
         left join public.ad_context_runs run on run.run_id=evidence.source_run_id
         left join lateral public.identity_snapshot_rows_v301(jsonb_build_object(''plugin_id'',ref.plugin_id,
             ''source_instance_id'',ref.source_instance_id,''source_generation'',ref.source_generation,
             ''collection_scope_id'',ref.collection_scope_id),array[case when ref.storage_kind=''ad_directory_observation'' then ref.native_id::bigint end]) proof on true
         where ref.finding_id=p_finding and ref.storage_kind=''ad_directory_observation''
         ) select count(*)>0');
    execute body;
end $$;

create function public.read_identity_snapshot_finding_evidence_v301(p_finding bigint,p_domains bigint[],p_after bigint,p_limit integer)
returns table(evidence_id bigint,storage_kind text,time_created_utc timestamptz,evidence_role text,
    run_id text,account text,availability text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_limit not between 1 and 200 or p_after<0
       or public.is_semantic_finding_published_v1(p_finding) is not true
       or public.semantic_finding_in_domains_v265(p_finding,p_domains) is not true then
        raise exception 'identity_attack_evidence_denied' using errcode='42501'; end if;
    return query select ref.native_id::bigint,ref.storage_kind,proof.occurred_at_utc,ref.evidence_role,
        native_evidence.source_run_id::text,
        case when proof.sha256=ref.sha256 then proof.attributes_json#>>'{attributes,sam_account_name}' end,
        case when proof.sha256=ref.sha256 then 'available' else 'unavailable' end
    from public.finding_evidence_refs ref
    left join public.ad_context_evidence native_evidence on native_evidence.id=ref.native_id::bigint
    left join lateral public.identity_snapshot_rows_v301(jsonb_build_object('plugin_id',ref.plugin_id,
        'source_instance_id',ref.source_instance_id,'source_generation',ref.source_generation,
        'collection_scope_id',ref.collection_scope_id),array[ref.native_id::bigint]) proof on true
    where ref.finding_id=p_finding and ref.storage_kind='ad_directory_observation' and ref.native_id::bigint>p_after
    order by ref.native_id::bigint limit p_limit;
end $$;
revoke all on function public.read_identity_snapshot_finding_evidence_v301(bigint,bigint[],bigint,integer) from public;
grant execute on function public.read_identity_snapshot_finding_evidence_v301(bigint,bigint[],bigint,integer) to adlog_user;

-- Do not inherit application EXECUTE from installation-specific default ACLs.
do $$
declare fn regprocedure;
begin
    foreach fn in array array[
        'public.identity_snapshot_rows_v301(jsonb,bigint[])'::regprocedure,
        'public.read_identity_attack_snapshot_v301(jsonb,bigint[])'::regprocedure,
        'public.read_identity_attack_events_v301(jsonb,bigint[])'::regprocedure,
        'public.identity_attack_episode_v301(jsonb,text,text,timestamptz,text)'::regprocedure,
        'public.identity_attack_episode_known_v301(jsonb,text,text,text)'::regprocedure,
        'public.read_identity_snapshot_finding_evidence_v301(bigint,bigint[],bigint,integer)'::regprocedure,
        'public.default_detection_sources()'::regprocedure,
        'public.default_detection_sources_before_v301()'::regprocedure,
        'public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text)'::regprocedure,
        'public.resolve_finding_evidence_ref_before_v301(uuid,text,text,text,text,text,text,text)'::regprocedure] loop
        execute format('revoke all on function %s from public,adlog_user,adlog_storage_worker,adlog_semantic_worker',fn);
    end loop;
end $$;
grant execute on function public.read_identity_attack_snapshot_v301(jsonb,bigint[]),
    public.read_identity_attack_events_v301(jsonb,bigint[]),
    public.identity_attack_episode_v301(jsonb,text,text,timestamptz,text),
    public.identity_attack_episode_known_v301(jsonb,text,text,text),public.default_detection_sources(),
    public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;
grant execute on function public.read_identity_snapshot_finding_evidence_v301(bigint,bigint[],bigint,integer) to adlog_user;

insert into public.schema_migrations(version,name) values(301,'identity_attack_rules');
commit;
