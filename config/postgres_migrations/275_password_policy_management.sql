-- B5 managed password metadata only. No discovery, native read or activation.
begin;
select pg_advisory_xact_lock(hashtext('sli_password_policy_management_v275'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=274 and name='agent_ad_binding_issuer')
       or exists(select 1 from public.schema_migrations where version>=275) then
        raise exception 'password_policy_preflight' using errcode='55000'; end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

create index idx_password_policy_family_v275 on public.semantic_risk_policies
    ((definition_json#>'{source_selector,execution,scope}'),(definition_json#>>'{source_selector,execution,rule_id}'),policy_id,policy_version)
    where source_kind='qw_signal' and definition_json#>>'{source_selector,execution,rule_id}'
        in ('qw.password-brute-force','qw.password-spray');
create index idx_password_policy_audit_v275 on public.semantic_control_audit(target,action,occurred_at desc,id desc)
    where action in ('policy_admission','password_policy_lifecycle','password_policy_managed');

-- RiskPolicyDefinition uses UTF-8 (ensure_ascii=False), unlike the ASCII scope codec.
create function public.password_policy_json_v275(j jsonb,depth integer default 0) returns text
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare result text;
begin
    if depth>16 or octet_length(j::text)>131072 then
        raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    case jsonb_typeof(j)
    when 'object' then
        select '{'||coalesce(string_agg(to_jsonb(key)::text||':'||public.password_policy_json_v275(value,depth+1),
            ',' order by key collate "C"),'')||'}' into result from jsonb_each(j);
    when 'array' then
        select '['||coalesce(string_agg(public.password_policy_json_v275(value,depth+1),',' order by n),'')||']'
            into result from jsonb_array_elements(j) with ordinality a(value,n);
    else result:=j::text;
    end case;
    if octet_length(result)>65536 then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    return result;
end $$;

create function public.password_policy_definition_v275(x jsonb) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('type','scenario_policy','source_selector',jsonb_build_object('rule_id',x->>'rule_id','execution',x),
        'scenario_kind',x->>'rule_id','result_class','security_incident','merge_window_seconds',
        case when x->>'rule_version'='1' then 300 else 600 end,
        'title',case when x->>'rule_id'='qw.password-brute-force' then 'Repeated password attempts against one account'
            else 'Passwords tried across several accounts' end,
        'explanation','Review the linked sign-in attempts and secure the affected accounts.',
        'risk',jsonb_build_object('class','high','raw_score','60','display_points',60,
            'rationale','Observed password attack evidence requires review.'))
$$;

create function public.password_policy_legacy_execution_v275(s jsonb,r text) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('version','sli.qw.execution.v1','kind','threshold','rule_id',r,'rule_version',1,'scope',s,
        'rule_sha256',encode(sha256(convert_to(public.password_v2_json_compact(jsonb_build_object(
            'version',1,'rule',r,'window_seconds',300,'threshold',10,'spray_accounts',5)),'UTF8')),'hex'))
$$;

create function public.password_policy_family_lock_v275(s jsonb,r text) returns void
language plpgsql volatile set search_path=pg_catalog,pg_temp as $$
begin
    if current_setting('transaction_isolation')<>'read committed' then
        raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    if r is null or r not in ('qw.password-brute-force','qw.password-spray')
       or not public.password_v2_keys(s,array['collection_scope_id','installation_id','plugin_id','source_generation','source_instance_id']) then
        raise exception 'password_policy_denied' using errcode='42501'; end if;
    perform pg_advisory_xact_lock(hashtextextended('sli.password.policy-family.1:'||
        encode(public.password_v2_scope_key(s),'hex')||':'||r,0));
end $$;

-- Replace only153's policy audit branch. Suppression semantics remain verbatim.
create or replace function public.semantic_control_audit_v160() returns trigger
language plpgsql security definer set search_path=pg_catalog,public as $$
declare p public.semantic_risk_policies%rowtype;
begin
    if TG_TABLE_NAME='semantic_suppressions' then
        if TG_OP='UPDATE' and (old.state <> 'active' or new.state not in ('expired','revoked')) then
            raise exception 'suppression transition is immutable';
        end if;
        if TG_OP='UPDATE' and (to_jsonb(new)-'state'-'changed_by') <> (to_jsonb(old)-'state'-'changed_by') then
            raise exception 'suppression scope and expiry are immutable';
        end if;
        insert into public.semantic_control_audit(action,target,actor,occurred_at,details)
        values ('suppression_' || case when TG_OP='INSERT' then 'create' else new.state end,
            new.id::text,coalesce(new.changed_by,new.created_by),
            case when new.state='expired' then new.expires_at else clock_timestamp() end,
            jsonb_build_object('rule',to_jsonb(new)));
    else
        select * into strict p from public.semantic_risk_policies where policy_id=new.policy_id and policy_version=new.policy_version;
        insert into public.semantic_control_audit(action,target,actor,details)
        values ('policy_admission',new.policy_id || ':' || new.policy_version,new.updated_by,
            jsonb_build_object('enabled',new.enabled,'previous',case when TG_OP='UPDATE' then old.enabled else null end,
                'policy_id',p.policy_id,'policy_version',p.policy_version,'definition_sha256',encode(p.definition_sha256,'hex'),
                'execution',p.definition_json#>'{source_selector,execution}','lifecycle_status',p.lifecycle_status,'db_actor',session_user));
    end if;
    return new;
end $$;

create function public.password_policy_lifecycle_audit_v275() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if old.lifecycle_status is distinct from new.lifecycle_status and new.source_kind='qw_signal'
       and new.definition_json#>>'{source_selector,execution,rule_id}' in ('qw.password-brute-force','qw.password-spray') then
        insert into public.semantic_control_audit(action,target,actor,details)
        values('password_policy_lifecycle',new.policy_id||':'||new.policy_version,session_user,
            jsonb_build_object('previous',old.lifecycle_status,'status',new.lifecycle_status,'policy_id',new.policy_id,
                'policy_version',new.policy_version,'definition_sha256',encode(new.definition_sha256,'hex'),
                'execution',new.definition_json#>'{source_selector,execution}','db_actor',session_user));
    end if;
    return new;
end $$;
create trigger password_policy_lifecycle_audit_v275 after update of lifecycle_status on public.semantic_risk_policies
    for each row execute function public.password_policy_lifecycle_audit_v275();

create function public.password_policy_provenance_v275(p_id text,p_version integer,kind text) returns void
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare p public.semantic_risk_policies%rowtype; a public.semantic_policy_admission%rowtype;
    admission public.semantic_control_audit%rowtype; life public.semantic_control_audit%rowtype;
begin
    select * into strict p from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version;
    select * into a from public.semantic_policy_admission where policy_id=p_id and policy_version=p_version;
    select * into admission from public.semantic_control_audit where target=p_id||':'||p_version and action='policy_admission'
        order by occurred_at desc,id desc limit 1;
    select * into life from public.semantic_control_audit where target=p_id||':'||p_version and action='password_policy_lifecycle'
        order by occurred_at desc,id desc limit 1;
    insert into public.semantic_control_audit(action,target,actor,details)
    values('password_policy_managed',p_id||':'||p_version,'system:password-defaults',
        jsonb_build_object('kind',kind,'policy_id',p_id,'policy_version',p_version,
            'definition_sha256',encode(p.definition_sha256,'hex'),'execution',p.definition_json#>'{source_selector,execution}',
            'status',p.lifecycle_status,'enabled',a.enabled,'admission_audit_id',admission.id,
            'admission_at',public.password_v2_iso(admission.occurred_at),'lifecycle_audit_id',life.id,'lifecycle_at',public.password_v2_iso(life.occurred_at)));
end $$;

-- Shared read-only decision. Exact family page and three indexed latest-event
-- lookups per policy, never an audit-history or all-policy scan. No row locks.
create function public.password_policy_decision_v275(x jsonb) returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare p record; a public.semantic_policy_admission%rowtype; admission public.semantic_control_audit%rowtype;
    life public.semantic_control_audit%rowtype; provenance public.semantic_control_audit%rowtype;
    n integer:=0; exact_veto boolean:=false; uncertain boolean:=false; admitted boolean:=false;
    admission_match boolean; life_match boolean; common_match boolean;
    deny_at timestamptz; deny_id bigint:=0; enable_at timestamptz; enable_id bigint:=0;
begin
    for p in select * from public.semantic_risk_policies where source_kind='qw_signal'
        and definition_json#>>'{source_selector,execution,rule_id}' in ('qw.password-brute-force','qw.password-spray')
        and definition_json#>'{source_selector,execution,scope}'=x->'scope'
        and definition_json#>>'{source_selector,execution,rule_id}'=x->>'rule_id'
        order by policy_id,policy_version limit 257 loop
        n:=n+1;
        if n>256 then return 'unknown'; end if;
        select * into a from public.semantic_policy_admission where policy_id=p.policy_id and policy_version=p.policy_version;
        if p.definition_json#>'{source_selector,execution}'=x and
            (a.enabled is false or p.lifecycle_status in ('disabled','deprecated')) then exact_veto:=true; end if;
        if p.definition_sha256 is distinct from sha256(convert_to(public.password_policy_json_v275(p.definition_json),'UTF8')) then
            uncertain:=true; continue; end if;
        select * into admission from public.semantic_control_audit where target=p.policy_id||':'||p.policy_version
            and action='policy_admission' order by occurred_at desc,id desc limit 1;
        select * into life from public.semantic_control_audit where target=p.policy_id||':'||p.policy_version
            and action='password_policy_lifecycle' order by occurred_at desc,id desc limit 1;
        select * into provenance from public.semantic_control_audit where target=p.policy_id||':'||p.policy_version
            and action='password_policy_managed' order by occurred_at desc,id desc limit 1;
        common_match:=coalesce(provenance.details->>'definition_sha256'=encode(p.definition_sha256,'hex')
            and provenance.details->'execution'=p.definition_json#>'{source_selector,execution}'
            and provenance.details->>'policy_id'=p.policy_id and provenance.details->>'policy_version'=p.policy_version::text,false);
        admission_match:=common_match and provenance.details->>'admission_audit_id'=admission.id::text
            and provenance.details->'admission_at'=to_jsonb(public.password_v2_iso(admission.occurred_at))
            and provenance.details->'enabled'=to_jsonb(a.enabled);
        life_match:=common_match and provenance.details->>'lifecycle_audit_id'=life.id::text
            and provenance.details->'lifecycle_at'=to_jsonb(public.password_v2_iso(life.occurred_at))
            and provenance.details->>'status'=p.lifecycle_status;
        if a.policy_id is not null then
            if admission.details->>'definition_sha256' is distinct from encode(p.definition_sha256,'hex')
               or admission.details->'execution' is distinct from p.definition_json#>'{source_selector,execution}'
               or admission.details->'enabled' is distinct from to_jsonb(a.enabled) then uncertain:=true;
            elsif coalesce(admission_match,false) and provenance.details->>'kind' in ('seed','preserved-owner-choice','retirement') then null;
            elsif admission.actor ~ '^(session|api_key):[1-9][0-9]*$' then
                if a.enabled is false and (deny_at is null or (admission.occurred_at,admission.id)>(deny_at,deny_id)) then
                    deny_at:=admission.occurred_at; deny_id:=admission.id;
                elsif a.enabled and p.definition_json#>'{source_selector,execution}'=x
                    and (enable_at is null or (admission.occurred_at,admission.id)>(enable_at,enable_id)) then
                    enable_at:=admission.occurred_at; enable_id:=admission.id;
                end if;
            else uncertain:=true;
            end if;
        end if;
        if p.lifecycle_status in ('disabled','deprecated') then
            if coalesce(life_match,false) and provenance.details->>'kind'='retirement' then null;
            elsif life.details->>'definition_sha256'=encode(p.definition_sha256,'hex')
                and life.details->'execution'=p.definition_json#>'{source_selector,execution}'
                and life.details->>'status'=p.lifecycle_status then
                if deny_at is null or (life.occurred_at,life.id)>(deny_at,deny_id) then deny_at:=life.occurred_at; deny_id:=life.id; end if;
            else uncertain:=true;
            end if;
        end if;
        if p.definition_json#>'{source_selector,execution}'=x and a.enabled
           and p.lifecycle_status in ('shadow','enabled') and exists(select 1 from public.semantic_risk_policy_subscriptions sub
            where sub.policy_id=p.policy_id and sub.policy_version=p.policy_version and sub.source_kind='qw_signal'
                and sub.selector_value=x->>'rule_id' and sub.definition_sha256=p.definition_sha256) then admitted:=true; end if;
    end loop;
    if exact_veto then return 'disabled'; end if;
    if uncertain then return 'unknown'; end if;
    if deny_at is not null and (enable_at is null or (deny_at,deny_id)>(enable_at,enable_id)) then return 'disabled'; end if;
    if admitted then return 'enabled'; end if;
    return 'absent';
end $$;

create function public.password_policy_ensure_v275(p_id text,p_version integer,p_document text) returns boolean
-- Existing029's subscription trigger resolves its owned table unqualified.
-- pg_catalog first, trusted public next, and explicit pg_temp LAST preserve it.
language plpgsql volatile security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb; x jsonb; s jsonb; r text; digest bytea; row_key record; b public.finding_evidence_source_bindings;
    context jsonb; decision text; existed boolean; legacy jsonb; legacy_id text; retired record; n integer;
begin
    if p_document is null or octet_length(p_document)>65536 or p_version is distinct from 1 then
        raise exception 'password_policy_denied' using errcode='42501'; end if;
    d:=p_document::jsonb; x:=d#>'{source_selector,execution}'; s:=x->'scope'; r:=x->>'rule_id';
    perform public.password_policy_family_lock_v275(s,r);
    if x is distinct from public.password_v2_coverage_execution(s,r)
       or d is distinct from public.password_policy_definition_v275(x)
       or p_document is distinct from public.password_policy_json_v275(d)
       or p_id is distinct from 'default:'||r||':'||substr(encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex'),1,32) then
        raise exception 'password_policy_denied' using errcode='42501'; end if;
    digest:=sha256(convert_to(p_document,'UTF8'));
    select count(*) into n from(select 1 from public.semantic_risk_policies where source_kind='qw_signal'
        and definition_json#>>'{source_selector,execution,rule_id}' in ('qw.password-brute-force','qw.password-spray')
        and definition_json#>'{source_selector,execution,scope}'=s
        and definition_json#>>'{source_selector,execution,rule_id}'=r limit 257) bounded;
    if n>256 then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    for row_key in select policy_id,policy_version from public.semantic_risk_policies where source_kind='qw_signal'
        and definition_json#>>'{source_selector,execution,rule_id}' in ('qw.password-brute-force','qw.password-spray')
        and definition_json#>'{source_selector,execution,scope}'=s
        and definition_json#>>'{source_selector,execution,rule_id}'=r
        or (policy_id=p_id and policy_version=p_version) order by policy_id,policy_version loop
        perform 1 from public.semantic_risk_policies where policy_id=row_key.policy_id and policy_version=row_key.policy_version for update;
        perform 1 from public.semantic_policy_admission where policy_id=row_key.policy_id and policy_version=row_key.policy_version for update;
        perform 1 from public.semantic_risk_policy_subscriptions where policy_id=row_key.policy_id and policy_version=row_key.policy_version for update;
    end loop;
    perform pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(s),'hex'),0));
    -- Separate fresh statements after waiting for the source lock. Metadata only.
    b:=public.password_v2_source_binding(s);
    context:=public.password_v2_configured_identity(b.agent_id);
    if context is null or context->'scope' is distinct from s or context->>'domain_id' is null then
        raise exception 'password_policy_source_unavailable' using errcode='42501'; end if;
    decision:=public.password_policy_decision_v275(x);
    if decision='unknown' then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    select exists(select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version) into existed;
    if existed then
        if not exists(select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
            and source_kind='qw_signal' and definition_json=d and definition_sha256=digest) then
            raise exception 'password_policy_conflict' using errcode='55000'; end if;
    else
        -- A full page cannot grow beyond the decision's bound in this transaction.
        if n>=256 then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
        insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
            values(p_id,p_version,'qw_signal','draft',d,digest);
        insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
            values(p_id,p_version,'qw_signal',r,digest);
        update public.semantic_risk_policies set lifecycle_status='shadow',updated_at=now() where policy_id=p_id and policy_version=p_version;
        insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
            values(p_id,p_version,decision<>'disabled',case when decision='disabled' then 'system:preserved-owner-choice' else 'system:defaults' end);
        perform public.password_policy_provenance_v275(p_id,p_version,case when decision='disabled' then 'preserved-owner-choice' else 'seed' end);
    end if;
    -- Only the byte-reproducible managed predecessor may retire; custom and
    -- manually denied policies remain untouched, including their admission rows.
    legacy:=public.password_policy_legacy_execution_v275(s,r);
    legacy_id:='default:'||r||':'||substr(encode(sha256(convert_to(public.password_v2_json_compact(legacy),'UTF8')),'hex'),1,32);
    for retired in select p.policy_id,p.policy_version from public.semantic_risk_policies p
        join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id=legacy_id and p.policy_version=1 and p.source_kind='qw_signal'
          and p.definition_json=public.password_policy_definition_v275(legacy)
          and p.definition_sha256=sha256(convert_to(public.password_policy_json_v275(p.definition_json),'UTF8'))
          and p.lifecycle_status in ('shadow','enabled') and a.enabled loop
        update public.semantic_risk_policies set lifecycle_status='deprecated',updated_at=now()
            where policy_id=retired.policy_id and policy_version=retired.policy_version;
        perform public.password_policy_provenance_v275(retired.policy_id,retired.policy_version,'retirement');
    end loop;
    decision:=public.password_policy_decision_v275(x);
    if decision not in ('enabled','disabled') then raise exception 'password_policy_unconfirmed' using errcode='55000'; end if;
    return decision='enabled';
end $$;

create or replace function public.password_v2_coverage_policy(x jsonb) returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare decision text;
begin
    decision:=public.password_policy_decision_v275(x);
    return case when decision in ('enabled','disabled') then decision else 'unknown' end;
end $$;

create or replace function public.ensure_default_qw_policy(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb; pin jsonb; resource jsonb; digest bytea; legacy_existed boolean; result boolean;
begin
    if octet_length(p_document)>65536 then raise exception 'default_detection_policy_denied' using errcode='42501'; end if;
    d:=p_document::jsonb; pin:=d#>'{source_selector,execution}';
    if pin->>'rule_id' in ('qw.password-brute-force','qw.password-spray') then
      if pin->>'rule_version'='2' then
        return public.password_policy_ensure_v275(p_id,p_version,p_document);
      end if;
      if pin->>'rule_version' is distinct from '1' then
        raise exception 'password_policy_denied' using errcode='42501'; end if;
      -- Preserve265's classifier before delegating legacy metadata to262.
      if coalesce(pin->>'kind','')='acl' or pin ? 'resource' then
        raise exception 'file_acl_medium_policy_required' using errcode='42501'; end if;
      perform public.password_policy_family_lock_v275(pin->'scope',pin->>'rule_id');
      select exists(select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version)
        into legacy_existed;
      result:=public.ensure_default_qw_policy_v262(p_id,p_version,p_document);
      if not legacy_existed and result and p_version=1
         and pin=public.password_policy_legacy_execution_v275(pin->'scope',pin->>'rule_id')
         and p_id='default:'||(pin->>'rule_id')||':'||substr(encode(sha256(convert_to(public.password_v2_json_compact(pin),'UTF8')),'hex'),1,32)
         and d=public.password_policy_definition_v275(pin)
         and p_document=public.password_policy_json_v275(d) then
        perform public.password_policy_provenance_v275(p_id,p_version,'seed');
      end if;
      return result;
    end if;
    if not (coalesce(pin->>'kind','')='acl' or pin ? 'resource'
       or starts_with(coalesce(pin->>'rule_id',''),'qw.file-acl-')) then
      return public.ensure_default_qw_policy_v262(p_id,p_version,p_document);
    end if;
    resource:=pin->'resource'; digest:=sha256(convert_to(p_document,'UTF8'));
    if p_version<>1 or p_id is distinct from 'default:qw.file-acl-broad-write:'||substr(public.file_acl_digest_v265(pin),1,32)
       or public.file_acl_resource_allowed_v265(resource) is not true
       or pin is distinct from public.file_acl_execution_v265(resource)
       or d->>'type' is distinct from 'scenario_policy'
       or d#>>'{source_selector,rule_id}' is distinct from 'qw.file-acl-broad-write'
       or d->>'scenario_kind' is distinct from 'qw.file-acl-broad-write'
       or d#>>'{risk,class}' is distinct from 'medium' or d#>>'{risk,raw_score}' is distinct from '25'
       or d#>>'{risk,display_points}' is distinct from '25' or d->>'expected_evidence_count' is distinct from '1'
       or d->>'merge_window_seconds' is distinct from '300' then
      raise exception 'file_acl_medium_policy_required' using errcode='42501'; end if;
    if exists(select 1 from public.semantic_risk_policies p left join public.semantic_policy_admission a using(policy_id,policy_version)
      where p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=pin
        and (a.enabled is false or p.lifecycle_status in ('disabled','deprecated'))) then return false; end if;
    -- A separately authored policy is an owner choice. Feed its compatible,
    -- already admitted version without creating a competing default revision.
    if exists(select 1 from public.semantic_risk_policies p where p.policy_id<>p_id and p.source_kind='qw_signal'
        and p.definition_json#>'{source_selector,execution}'=pin) then
      return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id<>p_id and p.policy_version=1 and p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=pin
          and p.definition_json#>>'{risk,class}'='medium' and a.enabled
          and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
    end if;
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
      values(p_id,p_version,'qw_signal','draft',d,digest) on conflict do nothing;
    perform 1 from public.semantic_risk_policies p where p.policy_id=p_id and p.policy_version=p_version
      and p.definition_json=d and p.definition_sha256=digest for update;
    if not found then raise exception 'default_detection_policy_conflict'; end if;
    insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
      select p_id,p_version,'qw_signal','qw.file-acl-broad-write',digest where not exists(
        select 1 from public.semantic_risk_policy_subscriptions p where p.policy_id=p_id and p.policy_version=p_version);
    update public.semantic_risk_policies p set lifecycle_status='shadow',updated_at=now()
      where p.policy_id=p_id and p.policy_version=p_version and p.lifecycle_status='draft';
    insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
      select p_id,p_version,true,'system:defaults' where exists(select 1 from public.semantic_risk_policies p
        where p.policy_id=p_id and p.policy_version=p_version and p.lifecycle_status in ('shadow','enabled')) on conflict do nothing;
    return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
      where p.policy_id=p_id and p.policy_version=p_version and a.enabled
        and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
end $$;

do $$
declare fn regprocedure;
begin
    for fn in select p.oid::regprocedure from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        where n.nspname='public' and p.proname like 'password_policy_%_v275' loop
        execute format('revoke all on function %s from public,adlog_user,adlog_storage_worker,adlog_semantic_worker',fn);
    end loop;
    -- Explicit revokes do not remove an unexpected owner default-ACL grantee.
    -- All NEW helpers are private, including provenance's metadata-write definer.
    if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
        where n.nspname='public' and p.proname=any(array[
            'password_policy_json_v275','password_policy_definition_v275',
            'password_policy_legacy_execution_v275','password_policy_family_lock_v275',
            'password_policy_lifecycle_audit_v275','password_policy_provenance_v275',
            'password_policy_decision_v275','password_policy_ensure_v275'])
          and a.grantee<>p.proowner) then
        raise exception 'password_policy_private_acl_unexpected' using errcode='42501'; end if;
end $$;
insert into public.schema_migrations(version,name) values(275,'password_policy_management');
commit;
