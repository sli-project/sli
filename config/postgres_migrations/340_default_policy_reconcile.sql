-- A release that rewords a default detection policy no longer breaks admission.
-- The stored version is immutable, so an untouched old default is retired and the
-- new text is registered under a derived id; an admin-modified policy is kept.
begin;
select pg_advisory_xact_lock(hashtext('sli_default_policy_reconcile_v340'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=337 and name='detection_short_events')
       or exists(select 1 from public.schema_migrations where version>=340) then
        raise exception 'default_policy_reconcile_340_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.default_policy_restore_v340(signature text primary key,definition text not null);
revoke all on public.default_policy_restore_v340 from public,adlog_user,adlog_semantic_worker;
insert into public.default_policy_restore_v340
select 'public.ensure_default_qw_policy_v262(text,integer,text)',pg_get_functiondef(p.oid)
from pg_proc p where p.oid='public.ensure_default_qw_policy_v262(text,integer,text)'::regprocedure;

-- Returns the policy id under which the given default document must be registered,
-- or NULL when an admin-modified policy for the same execution must be kept.
create function public.default_qw_policy_effective_id_v340(p_id text,p_version integer,p_document text) returns text
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}'; digest bytea:=sha256(convert_to(p_document,'UTF8'));
    stale record; derived text:=p_id||':r'||substr(encode(sha256(convert_to(p_document,'UTF8')),'hex'),1,12);
    current_id text; customized boolean:=false; has_base boolean:=false;
begin
    -- Password rules keep their own exact-id management.
    if pin->>'rule_id' in ('qw.password-spray','qw.password-brute-force') then return p_id; end if;
    select p.policy_id into current_id from public.semantic_risk_policies p
        where p.source_kind='qw_signal' and p.policy_version=p_version and p.definition_json#>'{source_selector,execution}'=pin
          and (p.policy_id=p_id or starts_with(p.policy_id,p_id||':r')) and p.definition_sha256=digest and p.definition_json=d
        order by p.policy_id limit 1;
    if found then return current_id; end if;
    for stale in select p.policy_id,p.policy_version,p.lifecycle_status,p.definition_sha256,a.enabled,a.updated_by,
            exists(select 1 from public.semantic_control_audit c where c.target=p.policy_id||':'||p.policy_version
                and c.action='policy_admission' and c.actor is distinct from 'system:defaults'
                and c.actor is distinct from 'system:defaults-superseded') as touched
        from public.semantic_risk_policies p left join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.policy_version=p_version and p.definition_json#>'{source_selector,execution}'=pin
          and (p.policy_id=p_id or starts_with(p.policy_id,p_id||':r'))
          and a.updated_by is distinct from 'system:defaults-superseded'
        order by p.policy_id for update of p loop
        if stale.policy_id=p_id then has_base:=true; end if;
        if stale.updated_by is distinct from 'system:defaults' or stale.enabled is not true
           or stale.lifecycle_status<>'shadow' or stale.touched then
            customized:=true;
            insert into public.semantic_control_audit(action,target,actor,details)
            select 'default_policy_customized_kept',stale.policy_id||':'||stale.policy_version,'system:defaults',
                jsonb_build_object('stored_sha256',encode(stale.definition_sha256,'hex'),'current_sha256',encode(digest,'hex'),
                    'policy_id',stale.policy_id,'policy_version',stale.policy_version)
            where not exists(select 1 from public.semantic_control_audit c where c.target=stale.policy_id||':'||stale.policy_version
                and c.action='default_policy_customized_kept' and c.details->>'current_sha256'=encode(digest,'hex'));
        end if;
    end loop;
    if customized then return null; end if;
    for stale in select p.policy_id,p.policy_version from public.semantic_risk_policies p
        join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.policy_version=p_version and p.definition_json#>'{source_selector,execution}'=pin
          and (p.policy_id=p_id or starts_with(p.policy_id,p_id||':r')) and a.updated_by='system:defaults'
        order by p.policy_id for update of p loop
        update public.semantic_risk_policies set lifecycle_status='deprecated' where policy_id=stale.policy_id and policy_version=stale.policy_version;
        update public.semantic_policy_admission set enabled=false,updated_by='system:defaults-superseded',updated_at=now()
            where policy_id=stale.policy_id and policy_version=stale.policy_version;
    end loop;
    return case when has_base or exists(select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version)
        then derived else p_id end;
end $$;
revoke all on function public.default_qw_policy_effective_id_v340(text,integer,text) from public,adlog_user,adlog_semantic_worker;

do $patch$
declare body text; patched text; anchor text;
begin
    select definition into strict body from public.default_policy_restore_v340 where signature='public.ensure_default_qw_policy_v262(text,integer,text)';
    patched:=body;
    anchor:='s jsonb; digest bytea;';
    if position(anchor in patched)=0 then raise exception 'default_policy_reconcile_340_baseline' using errcode='55000'; end if;
    patched:=replace(patched,anchor,'s jsonb; digest bytea; effective text;');
    anchor:='and (a.enabled is false or p.lifecycle_status in (''disabled'',''deprecated''))) then';
    if position(anchor in patched)=0 then raise exception 'default_policy_reconcile_340_baseline' using errcode='55000'; end if;
    patched:=replace(patched,anchor,'and a.updated_by is distinct from ''system:defaults-superseded''
          and (a.enabled is false or p.lifecycle_status in (''disabled'',''deprecated''))) then');
    anchor:='    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)';
    if position(anchor in patched)=0 then raise exception 'default_policy_reconcile_340_baseline' using errcode='55000'; end if;
    patched:=replace(patched,anchor,'    -- A reworded default replaces an untouched old one; an admin-modified policy stays as it is.
    effective:=public.default_qw_policy_effective_id_v340(p_id,p_version,p_document);
    if effective is null then
        return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
            where p.source_kind=''qw_signal'' and p.policy_version=p_version and p.definition_json#>''{source_selector,execution}''=pin
              and a.enabled and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)=''enabled'');
    end if;
    p_id:=effective;
'||anchor);
    execute patched;
end $patch$;

insert into public.schema_migrations(version,name) values(340,'default_policy_reconcile');
reset role;
commit;
