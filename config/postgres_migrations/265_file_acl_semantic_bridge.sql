-- Everyone broad-medium native authority. No source or policy is enabled here.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_acl_semantic_bridge_v265'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=264 and name='file_audit_acl_bridge')
       or exists(select 1 from public.schema_migrations where version>=265) then
        raise exception 'migration 265 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
grant select on sli_plugin_file_audit.rule_results,sli_plugin_file_audit.rule_snapshots to adlog_storage_owner;
set local role adlog_storage_owner;

-- A total parse is mandatory: an unsupported later ACE invalidates earlier
-- grants. bigint preserves unsigned32 masks; ACE order matches acl.access_mask.
create function public.file_acl_dacl_mask_v265(descriptor text,token_sids text[],explicit_only boolean)
returns jsonb language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare unsupported constant jsonb:='{"supported":false,"mask":null}';
    aliases constant jsonb:='{"WD":"S-1-1-0","AU":"S-1-5-11","SY":"S-1-5-18","BA":"S-1-5-32-544","BU":"S-1-5-32-545","AN":"S-1-5-7","CO":"S-1-3-0","CG":"S-1-3-1"}';
    rights_map constant jsonb:='{"FA":2032127,"FR":1179785,"FW":1179926,"FX":1179808,"SD":65536,"RC":131072,"WD":262144,"WO":524288,"GA":2032127,"GR":1179785,"GW":1179926,"GX":1179808}';
    remainder text; header text; matched text[]; fields text[]; sid text; rights text; pair text;
    mask bigint; allowed bigint:=0; denied bigint:=0; digit integer; i integer;
    inherited boolean; inherit_only boolean;
begin
    if descriptor is null or length(descriptor)>65536 or left(descriptor,2)<>'D:'
       or token_sids is null or cardinality(token_sids)>2048 or explicit_only is null then return unsupported; end if;
    remainder:=substring(descriptor from 3);
    header:=split_part(remainder,'(',1);
    if header !~ '^(P|AI|AR)*$' then return unsupported; end if;
    remainder:=substring(remainder from length(header)+1);
    while remainder<>'' loop
        matched:=regexp_match(remainder,'^\(([^()]*)\)');
        if matched is null then return unsupported; end if;
        fields:=string_to_array(matched[1],';');
        if cardinality(fields)<>6 or fields[1] not in ('A','D')
           or fields[2] !~ '^(OI|CI|NP|IO|ID)*$' or fields[4]<>'' or fields[5]<>'' then return unsupported; end if;
        sid:=coalesce(aliases->>fields[6],fields[6]);
        if sid !~ '^S-1-([0-9]+-)*[0-9]+$' then return unsupported; end if;
        inherited:=false; inherit_only:=false;
        for i in 1..length(fields[2])/2 loop
            inherited:=inherited or substr(fields[2],2*i-1,2)='ID';
            inherit_only:=inherit_only or substr(fields[2],2*i-1,2)='IO';
        end loop;
        rights:=fields[3]; mask:=0;
        if starts_with(rights,'0x') then
            -- Deliberately narrower than Python int's whitespace/underscore
            -- lexemes. Supported masks must agree; rejected input is unknown.
            if rights !~ '^0x[0-9a-fA-F]+$' then return unsupported; end if;
            for i in 3..length(rights) loop
                digit:=strpos('0123456789abcdef',lower(substr(rights,i,1)))-1;
                mask:=mask*16+digit;
                if mask>4294967295 then return unsupported; end if;
            end loop;
        else
            if length(rights)%2<>0 then return unsupported; end if;
            i:=1;
            while i<=length(rights) loop
                pair:=substr(rights,i,2);
                if not rights_map ? pair then return unsupported; end if;
                mask:=mask|(rights_map->>pair)::bigint; i:=i+2;
            end loop;
        end if;
        if (mask&268435456)<>0 then mask:=(mask & ~268435456::bigint)|2032127; end if;
        if (mask&2147483648)<>0 then mask:=(mask & ~2147483648::bigint)|1179785; end if;
        if (mask&1073741824)<>0 then mask:=(mask & ~1073741824::bigint)|1179926; end if;
        if (mask&536870912)<>0 then mask:=(mask & ~536870912::bigint)|1179808; end if;
        if not inherit_only and (not explicit_only or not inherited)
           and sid=any(token_sids) then
            if fields[1]='D' then denied:=denied|(mask & ~allowed);
            else allowed:=allowed|(mask & ~denied); end if;
        end if;
        remainder:=substring(remainder from length(matched[1])+3);
    end loop;
    return jsonb_build_object('supported',true,'mask',allowed);
end $$;
create function public.file_acl_dacl_mask_v265(descriptor text,token_sids text[])
returns jsonb language sql immutable set search_path=pg_catalog,pg_temp as $$
    select public.file_acl_dacl_mask_v265(descriptor,token_sids,false)
$$;
revoke all on function public.file_acl_dacl_mask_v265(text,text[],boolean) from public;
revoke all on function public.file_acl_dacl_mask_v265(text,text[]) from public;

create function public.file_acl_resource_allowed_v265(resource jsonb) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare field text;
begin
    -- Reject coercible JSON before any native lookup or protected issuance.
    -- The supported shape exactly matches Python file_acl_input.resource_key.
    if jsonb_typeof(resource) is distinct from 'object' then return false; end if;
    if resource-array['installation_id','plugin_id','agent_id','source_instance_id','collection_scope_id']<>'{}'::jsonb
       or (select count(*) from jsonb_object_keys(resource))<>5 then return false; end if;
    foreach field in array array['installation_id','plugin_id','agent_id','source_instance_id','collection_scope_id'] loop
      if jsonb_typeof(resource->field) is distinct from 'string'
         or length(resource->>field) not between 1 and 256 then return false; end if;
    end loop;
    if resource->>'plugin_id'<>'sli.file-audit'
       or resource->>'installation_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or resource->>'agent_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return false; end if;
    return coalesce(pg_has_role(session_user,'adlog_semantic_worker','MEMBER')
      and exists(select 1 from public.semantic_default_installation i
          where i.installation_id::text=resource->>'installation_id')
      and exists(select 1 from public.sli_agents a
          cross join lateral jsonb_array_elements(a.assigned_modules) m
          cross join lateral jsonb_array_elements(m#>'{config,roots}') root
          where a.id::text=resource->>'agent_id' and a.status='active'
            and a.host_id::text=resource->>'source_instance_id'
            and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
            and root->>'collection_scope_id'=resource->>'collection_scope_id'),false);
end
$$;
revoke all on function public.file_acl_resource_allowed_v265(jsonb) from public;

create function public.file_acl_native_verdict_v265(resource jsonb,result_id text,result_sha256 text)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare r sli_plugin_file_audit.rule_results%rowtype; s sli_plugin_file_audit.access_snapshots%rowtype;
    provenance jsonb; config jsonb; current_config jsonb; details jsonb; native_details jsonb; object jsonb; descriptor text;
    native_mask jsonb; mask bigint; count_links integer; subject text; selected_snapshot uuid; expected_id text;
begin
    if public.file_acl_resource_allowed_v265(resource) is not true then return jsonb_build_object('status','source_unbound'); end if;
    select * into r from sli_plugin_file_audit.rule_results q
      where q.result_id=file_acl_native_verdict_v265.result_id
        and q.result_sha256=file_acl_native_verdict_v265.result_sha256
        and q.agent_id::text=resource->>'agent_id' and q.source_instance_id=resource->>'source_instance_id'
        and q.collection_scope_id=resource->>'collection_scope_id';
    if not found or r.result_sha256<>encode(sha256(convert_to(r.result::text,'UTF8')),'hex') then
      return jsonb_build_object('status','result_hash_mismatch'); end if;
    if r.rule_version<>1 or r.conclusion_state<>'observed'
       or r.rule_code not in ('file-audit.broad-write','file-audit.direct-user-rights')
       or r.result->>'result_id' is distinct from r.result_id
       or r.result->>'rule_code' is distinct from r.rule_code
       or jsonb_typeof(r.result->'rule_version') is distinct from 'number'
       or r.result->>'rule_version' is distinct from '1'
       or r.result->>'agent_id' is distinct from r.agent_id::text
       or r.result->>'source_instance_id' is distinct from r.source_instance_id
       or r.result->>'collection_scope_id' is distinct from r.collection_scope_id
       or r.result->>'conclusion_state' is distinct from 'observed'
       or r.result->'action_ids' is distinct from '[]'::jsonb
       or r.result-array['result_id','rule_code','rule_version','agent_id','source_instance_id','collection_scope_id',
           'subject_sid','observed_at','conclusion_state','action_ids','snapshot_ids','details']<>'{}'::jsonb
       or (select count(*) from jsonb_object_keys(r.result))<>12 then
      return jsonb_build_object('status','blocked_result_detail_subset'); end if;
    select count(*),min(q.snapshot_id::text)::uuid into count_links,selected_snapshot
      from (select rs.snapshot_id from sli_plugin_file_audit.rule_snapshots rs
        where rs.result_id=r.result_id order by rs.snapshot_id limit 2) q;
    if count_links<>1 or r.result->'snapshot_ids' is distinct from jsonb_build_array(selected_snapshot::text) then
      return jsonb_build_object('status','snapshot_proof_mismatch'); end if;
    select * into s from sli_plugin_file_audit.access_snapshots q where q.snapshot_id=selected_snapshot
      and q.agent_id=r.agent_id and q.source_instance_id=r.source_instance_id and q.collection_scope_id=r.collection_scope_id;
    if not found then return jsonb_build_object('status','snapshot_proof_mismatch'); end if;
    provenance:=public.file_audit_snapshot_provenance_v264(r.agent_id,s.snapshot_id);
    if provenance is null or r.result->>'observed_at' is distinct from s.snapshot->>'observed_at_utc'
       or r.observed_at is distinct from s.observed_at then return jsonb_build_object('status','snapshot_proof_mismatch'); end if;
    select p.policy into strict config from sli_plugin_file_audit.policy_revisions p
      where p.agent_id=r.agent_id and p.source_instance_id=r.source_instance_id
        and p.revision=(provenance->>'policy_revision')::bigint;
    details:=r.result->'details'; subject:=r.result->>'subject_sid';
    if jsonb_typeof(details) is distinct from 'object' or subject is null or subject !~ '^S-1-([0-9]+-)*[0-9]+$'
       or details-array['path','layer','ntfs_mask','share_mask','effective_smb_mask','effective_smb_state',
         'limitations','coverage_state','membership_complete','snapshot_sha256','principal']<>'{}'::jsonb
       or (select count(*) from jsonb_object_keys(details))<>11 then
      return jsonb_build_object('status','blocked_result_detail_subset'); end if;
    if coalesce(config->'service_account_exclusions','[]'::jsonb) ? subject then
      return jsonb_build_object('status','blocked_result_detail_subset'); end if;
    select m->'config' into strict current_config from public.sli_agents a
      cross join lateral jsonb_array_elements(a.assigned_modules) m
      where a.id=r.agent_id and a.status='active' and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb;
    if coalesce(current_config->'service_account_exclusions','[]'::jsonb) ? subject then
      return jsonb_build_object('status','owner_denied'); end if;
    if details->>'layer'='ntfs' then
      select value into strict object from jsonb_array_elements(s.snapshot->'objects')
        where value->>'path'=details->>'path';
      descriptor:=object->>'dacl';
    elsif details->>'layer'='smb' and coalesce(config->>'source_kind','server')='server'
          and details->>'path'=s.snapshot#>>'{share,path}' then descriptor:=s.snapshot#>>'{share,dacl}';
    else return jsonb_build_object('status','blocked_result_detail_subset'); end if;
    native_mask:=public.file_acl_dacl_mask_v265(descriptor,array[subject],r.rule_code='file-audit.direct-user-rights');
    if native_mask->'supported' is distinct from 'true'::jsonb then return jsonb_build_object('status','unsupported_descriptor'); end if;
    mask:=(native_mask->>'mask')::bigint;
    if r.rule_code='file-audit.direct-user-rights' then
      if octet_length(details::text)>4096 then return jsonb_build_object('status','blocked_result_detail_subset'); end if;
      expected_id:=encode(sha256(convert_to(public.file_audit_snapshot_canonical_v264(jsonb_build_array(
        r.rule_code,1,jsonb_build_array(r.agent_id::text,r.source_instance_id,r.collection_scope_id),subject,
        '[]'::jsonb,jsonb_build_array(s.snapshot_id::text),details)),'UTF8')),'hex');
      if expected_id<>r.result_id then return jsonb_build_object('status','producer_identity_mismatch'); end if;
      return jsonb_build_object('status',case when (mask&852038)=0 then 'verified_excluded' else 'blocked_direct_ad_proof_unsupported' end);
    end if;
    -- A non-Everyone SID is unknown here; do not label it Domain Users from
    -- caller principal fields or a SID suffix.
    if subject<>'S-1-1-0' then return jsonb_build_object('status','blocked_broad_principal_unsupported'); end if;
    native_details:=jsonb_build_object('path',details->>'path','layer',details->>'layer',
      'ntfs_mask',case when details->>'layer'='ntfs' then mask else null end,
      'share_mask',case when details->>'layer'='smb' then mask else null end,
      'effective_smb_mask',null,'effective_smb_state','requires_review',
      'limitations',jsonb_build_array('privileges_and_conditional_aces_not_evaluated'),
      'coverage_state',s.completeness,'membership_complete',false,'snapshot_sha256',s.snapshot_sha256,'principal','{}'::jsonb);
    if details<>native_details or (mask&852038)=0 then return jsonb_build_object('status','blocked_result_detail_subset'); end if;
    expected_id:=encode(sha256(convert_to(public.file_audit_snapshot_canonical_v264(jsonb_build_array(
      r.rule_code,1,jsonb_build_array(r.agent_id::text,r.source_instance_id,r.collection_scope_id),subject,
      '[]'::jsonb,jsonb_build_array(s.snapshot_id::text),native_details)),'UTF8')),'hex');
    if expected_id<>r.result_id then return jsonb_build_object('status','producer_identity_mismatch'); end if;
    return jsonb_build_object('status','verified','severity','medium','resource',resource,'result',r.result,
      'result_sha256',r.result_sha256,'snapshot',s.snapshot,'config',config,'provenance',provenance,
      'grant_mask',mask,'evidence_ref',jsonb_build_object('scope',jsonb_build_object(
        'installation_id',resource->>'installation_id','plugin_id','sli.file-audit','source_instance_id',r.source_instance_id,
        'source_generation','audit-command:'||(provenance->>'command_id'),'collection_scope_id',r.collection_scope_id),
        'storage_kind','file_audit_snapshot','native_id',s.snapshot_id::text,'sha256',s.snapshot_sha256));
exception when no_data_found or too_many_rows or invalid_text_representation or numeric_value_out_of_range then
    return jsonb_build_object('status','blocked_result_detail_subset');
end $$;
revoke all on function public.file_acl_native_verdict_v265(jsonb,text,text) from public;

create table public.semantic_file_acl_episodes(
    resource_key text primary key check(resource_key ~ '^[a-f0-9]{64}$'),resource jsonb not null,
    domain_id bigint not null,created_at timestamptz not null default now());
create table public.semantic_file_acl_portions(
    portion_id text primary key check(portion_id ~ '^[a-f0-9]{64}$'),
    resource_key text not null references public.semantic_file_acl_episodes,
    principal_oid oid not null,principal_name name not null,
    manifest jsonb not null check(jsonb_array_length(manifest) between 1 and 32),
    document_json jsonb not null,signal_id text not null unique,created_at timestamptz not null default now());
create table public.semantic_file_acl_members(
    resource_key text not null references public.semantic_file_acl_episodes,
    result_id text not null,result_sha256 text not null,
    portion_id text not null references public.semantic_file_acl_portions,
    processed boolean not null default false,processed_at timestamptz,
    primary key(resource_key,result_id,result_sha256));
revoke all on public.semantic_file_acl_episodes,public.semantic_file_acl_portions,public.semantic_file_acl_members
    from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
create trigger file_acl_portion_immutable before update or delete on public.semantic_file_acl_portions
    for each row execute function public.reject_qw_signal_mutation();
create trigger file_acl_portion_no_truncate before truncate on public.semantic_file_acl_portions
    for each statement execute function public.reject_qw_signal_mutation();

create function public.file_acl_digest_v265(value jsonb) returns text
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select encode(sha256(convert_to(public.file_audit_snapshot_canonical_v264(value),'UTF8')),'hex')
$$;
revoke all on function public.file_acl_digest_v265(jsonb) from public;
create function public.file_acl_timestamp_v265(value timestamptz) returns text
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select to_char(value at time zone 'UTC',case when extract(microseconds from value)::bigint%1000000=0
      then 'YYYY-MM-DD"T"HH24:MI:SS' else 'YYYY-MM-DD"T"HH24:MI:SS.US' end)||'+00:00'
$$;
revoke all on function public.file_acl_timestamp_v265(timestamptz) from public;

create function public.prepare_file_acl_portion_v265(resource jsonb,result_ids jsonb) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
<<issuer>>
declare v jsonb; requested jsonb; manifest jsonb:='[]'; refs jsonb:='[]'; doc jsonb; context jsonb; resource_key text;
    portion_id text; proof_hash text; signal_id text; rule_hash text; episode text; login oid;
    command_id text; one_command text; domain_id bigint; one_domain bigint; occurred timestamptz;
    quality text:='good'; existing public.semantic_file_acl_portions%rowtype;
begin
    if public.file_acl_resource_allowed_v265(resource) is not true or jsonb_typeof(result_ids) is distinct from 'array'
       or jsonb_array_length(result_ids) not between 1 and 32 or octet_length(result_ids::text)>8192 then
      raise exception 'file_acl_portion_denied' using errcode='42501'; end if;
    if (select count(distinct x->>'result_id') from jsonb_array_elements(result_ids) x)<>jsonb_array_length(result_ids) then
      raise exception 'file_acl_portion_denied' using errcode='42501'; end if;
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    resource_key:=public.file_acl_digest_v265(jsonb_build_array('file-acl-resource.v1',resource->>'installation_id',
      resource->>'agent_id',resource->>'source_instance_id',resource->>'collection_scope_id'));
    perform pg_advisory_xact_lock(hashtextextended(resource_key,0));
    for requested in select value from jsonb_array_elements(result_ids) order by value->>'result_id' collate "C" loop
      if requested-array['result_id','result_sha256']<>'{}'::jsonb then
        raise exception 'file_acl_portion_denied' using errcode='42501'; end if;
      v:=public.file_acl_native_verdict_v265(resource,requested->>'result_id',requested->>'result_sha256');
      if v->>'status' is distinct from 'verified' then raise exception 'file_acl_native_verdict_blocked' using errcode='42501'; end if;
      command_id:=v#>>'{provenance,command_id}'; domain_id:=(v#>>'{provenance,domain_id}')::bigint;
      if one_command is not null and command_id<>one_command or one_domain is not null and domain_id<>one_domain then
        raise exception 'file_acl_portion_scope_denied' using errcode='42501'; end if;
      one_command:=command_id; one_domain:=domain_id;
      occurred:=greatest(occurred,(v#>>'{result,observed_at}')::timestamptz);
      if v#>>'{snapshot,completeness}'<>'complete' then quality:='degraded'; end if;
      manifest:=manifest||jsonb_build_array(jsonb_build_object('result_id',requested->>'result_id',
        'result_sha256',requested->>'result_sha256','snapshot_id',v#>>'{snapshot,snapshot_id}',
        'snapshot_sha256',v#>>'{snapshot,snapshot_sha256}','command_id',command_id,'domain_id',domain_id));
      refs:=refs||jsonb_build_array(v->'evidence_ref');
    end loop;
    select jsonb_agg(ref order by ref#>>'{scope,installation_id}' collate "C",ref#>>'{scope,plugin_id}' collate "C",
      ref#>>'{scope,source_instance_id}' collate "C",ref#>>'{scope,source_generation}' collate "C",
      ref#>>'{scope,collection_scope_id}' collate "C",ref->>'storage_kind' collate "C",
      ref->>'native_id' collate "C",ref->>'sha256' collate "C") into refs
      from (select distinct value as ref from jsonb_array_elements(refs)) deduped;
    proof_hash:=public.file_acl_digest_v265(jsonb_build_array('file-acl-proof.v1',resource_key,manifest));
    portion_id:=public.file_acl_digest_v265(jsonb_build_array('file-acl-portion.v1',resource_key,manifest));
    episode:=public.file_acl_digest_v265(jsonb_build_array('file-acl-episode.v1',resource_key,'qw.file-acl-broad-write'));
    rule_hash:=public.file_acl_digest_v265(jsonb_build_array('sli.qw.file-acl-broad-write.v1','everyone','medium','native-v265'));
    context:=jsonb_build_object('version','sli.file-acl-context.v1','resource',resource,'resource_key',resource_key,
      'portion_id',portion_id,'proof_sha256',proof_hash,'members',manifest);
    doc:=jsonb_build_object('kind','acl','rule_id','qw.file-acl-broad-write','rule_version',1,'rule_sha256',rule_hash,
      'policy_revision',1,'evaluation_mode','enabled','entity_key',resource_key,'episode_key',episode,
      'occurred_at_utc',public.file_acl_timestamp_v265(occurred),'received_at_utc',public.file_acl_timestamp_v265(occurred),
      'evidence_refs',refs,'base_severity','medium','effective_severity','medium','severity_reasons','[]'::jsonb,
      'quality',quality,'conclusion_state','observed','evidence_total',jsonb_array_length(refs),
      'acl_context',context,'processing_mode','historical_replay');
    signal_id:=public.file_acl_digest_v265(doc-'received_at_utc');
    if exists(select 1 from public.semantic_file_acl_members m cross join lateral jsonb_array_elements(manifest) member
      where m.resource_key=issuer.resource_key and m.result_id=member->>'result_id' and m.result_sha256=member->>'result_sha256'
        and m.portion_id<>issuer.portion_id) then raise exception 'file_acl_member_already_pinned' using errcode='42501'; end if;
    insert into public.semantic_file_acl_episodes values(resource_key,resource,one_domain,now()) on conflict do nothing;
    if not exists(select 1 from public.semantic_file_acl_episodes e where e.resource_key=issuer.resource_key
        and e.resource=prepare_file_acl_portion_v265.resource and e.domain_id=one_domain) then
      raise exception 'file_acl_resource_changed' using errcode='42501'; end if;
    insert into public.semantic_file_acl_portions values(portion_id,resource_key,login,session_user,manifest,doc,signal_id,now())
      on conflict do nothing;
    select * into strict existing from public.semantic_file_acl_portions p where p.portion_id=issuer.portion_id;
    if existing.manifest<>manifest or existing.document_json<>doc or existing.principal_oid<>login
       or existing.principal_name<>session_user then raise exception 'file_acl_portion_conflict' using errcode='42501'; end if;
    insert into public.semantic_file_acl_members(resource_key,result_id,result_sha256,portion_id)
      select resource_key,x->>'result_id',x->>'result_sha256',portion_id from jsonb_array_elements(manifest) x on conflict do nothing;
    -- Issuance binds only the native, verified command snapshot refs to this
    -- authenticated worker; no caller-supplied binding/agent/domain is accepted.
    insert into public.finding_evidence_source_bindings(principal_oid,principal_name,installation_id,plugin_id,
      source_instance_id,source_generation,collection_scope_id,storage_kind,agent_id)
      select login,session_user,(resource->>'installation_id')::uuid,'sli.file-audit',resource->>'source_instance_id',
        'audit-command:'||one_command,resource->>'collection_scope_id','file_audit_snapshot',(resource->>'agent_id')::uuid
      where not exists(select 1 from public.finding_evidence_source_bindings b where b.principal_oid=login and b.principal_name=session_user
        and b.installation_id=(resource->>'installation_id')::uuid and b.plugin_id='sli.file-audit'
        and b.source_instance_id=resource->>'source_instance_id' and b.source_generation='audit-command:'||one_command
        and b.collection_scope_id=resource->>'collection_scope_id' and b.storage_kind='file_audit_snapshot') on conflict do nothing;
    return jsonb_build_object('portion_id',portion_id,'signal_id',signal_id,'document',doc);
end $$;
revoke all on function public.prepare_file_acl_portion_v265(jsonb,jsonb) from public;
grant execute on function public.prepare_file_acl_portion_v265(jsonb,jsonb) to adlog_semantic_worker;

-- Dispatch by native ref/context markers, never only by caller kind.
create function public.file_acl_qw_document_allowed_v265(document jsonb) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare p public.semantic_file_acl_portions%rowtype; member jsonb; v jsonb; resource jsonb; login oid;
begin
    if document->>'kind' is distinct from 'acl' or document->>'rule_id' is distinct from 'qw.file-acl-broad-write'
       or document->>'base_severity' is distinct from 'medium' or document->>'effective_severity' is distinct from 'medium' then return false; end if;
    resource:=document#>'{acl_context,resource}';
    if public.file_acl_resource_allowed_v265(resource) is not true then return false; end if;
    select oid into strict login from pg_catalog.pg_roles where rolname=session_user;
    select * into p from public.semantic_file_acl_portions q
      where q.portion_id=document#>>'{acl_context,portion_id}' and q.principal_oid=login and q.principal_name=session_user;
    if not found or p.document_json<>document then return false; end if;
    for member in select value from jsonb_array_elements(p.manifest) loop
      v:=public.file_acl_native_verdict_v265(resource,member->>'result_id',member->>'result_sha256');
      if v->>'status' is distinct from 'verified' or v#>>'{snapshot,snapshot_id}' is distinct from member->>'snapshot_id'
         or v#>>'{snapshot,snapshot_sha256}' is distinct from member->>'snapshot_sha256'
         or v#>>'{provenance,command_id}' is distinct from member->>'command_id'
         or v#>>'{provenance,domain_id}' is distinct from member->>'domain_id' then return false; end if;
    end loop;
    return true;
exception when no_data_found or invalid_text_representation then return false;
end $$;
revoke all on function public.file_acl_qw_document_allowed_v265(jsonb) from public;
grant execute on function public.file_acl_qw_document_allowed_v265(jsonb) to adlog_semantic_worker;
create function public.qw_signal_evidence_allowed_v228(document jsonb, verify boolean) returns boolean
language sql stable set search_path=pg_catalog,pg_temp as $$
    select coalesce(bool_and(coalesce(case when verify then
        public.resolve_finding_evidence_ref(
            (ref#>>'{scope,installation_id}')::uuid,ref#>>'{scope,plugin_id}',
            ref#>>'{scope,source_instance_id}',ref#>>'{scope,source_generation}',
            ref#>>'{scope,collection_scope_id}',ref->>'storage_kind',ref->>'native_id',ref->>'sha256')
        else public.finding_evidence_scope_allowed(
            (ref#>>'{scope,installation_id}')::uuid,ref#>>'{scope,plugin_id}',
            ref#>>'{scope,source_instance_id}',ref#>>'{scope,source_generation}',
            ref#>>'{scope,collection_scope_id}',ref->>'storage_kind') end,false)),false)
    from jsonb_array_elements(document->'evidence_refs') ref
$$;
revoke all on function public.qw_signal_evidence_allowed_v228(jsonb,boolean) from public;
grant execute on function public.qw_signal_evidence_allowed_v228(jsonb,boolean) to adlog_semantic_worker;
-- The old SECURITY INVOKER gate remains callable for all legacy kinds. Its
-- policy is replaced below so a direct call cannot authorize a durable row.
create or replace function public.qw_signal_evidence_allowed(document jsonb,verify boolean) returns boolean
language sql stable set search_path=pg_catalog,pg_temp as $$
    select public.qw_signal_evidence_allowed_v228(document,verify) and
      case when document->>'kind'='acl' or document ? 'acl_context'
        or document->>'rule_id' in ('qw.file-acl-broad-write','qw.file-acl-direct-write')
        or exists(select 1 from jsonb_array_elements(document->'evidence_refs') ref where ref->>'storage_kind'='file_audit_snapshot')
      then public.file_acl_qw_document_allowed_v265(document) else true end
$$;
revoke all on function public.qw_signal_evidence_allowed(jsonb,boolean) from public;
grant execute on function public.qw_signal_evidence_allowed(jsonb,boolean) to adlog_semantic_worker;
drop policy qw_signal_scope on public.semantic_qw_signals;
create policy qw_signal_scope on public.semantic_qw_signals to adlog_semantic_worker
  using(public.qw_signal_evidence_allowed(document_json,false))
  with check(public.qw_signal_evidence_allowed(document_json,true));

create function public.file_acl_qw_row_allowed_v265(p_signal_id text,p_mode text,p_document jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.semantic_file_acl_portions p join pg_catalog.pg_roles r
      on r.oid=p.principal_oid and r.rolname=p.principal_name where r.rolname=session_user
        and p.signal_id=p_signal_id and p.document_json=p_document and p_mode=p_document->>'evaluation_mode'
        and public.file_acl_resource_allowed_v265(p_document#>'{acl_context,resource}'))
$$;
revoke all on function public.file_acl_qw_row_allowed_v265(text,text,jsonb) from public;
grant execute on function public.file_acl_qw_row_allowed_v265(text,text,jsonb) to adlog_semantic_worker;
alter table public.semantic_qw_signals add constraint semantic_qw_acl_identity_v265 check(
    case when document_json->>'kind'='acl' or document_json ? 'acl_context'
      or starts_with(document_json->>'rule_id','qw.file-acl-')
      or jsonb_path_exists(document_json,'$.evidence_refs[*] ? (@.storage_kind == "file_audit_snapshot")')
    then public.file_acl_qw_row_allowed_v265(signal_id,evaluation_mode,document_json) else true end);

create function public.read_file_acl_result_by_id(resource jsonb,result_id text,result_sha256 text) returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select public.file_acl_native_verdict_v265(resource,result_id,result_sha256)
$$;
revoke all on function public.read_file_acl_result_by_id(jsonb,text,text) from public;
grant execute on function public.read_file_acl_result_by_id(jsonb,text,text) to adlog_semantic_worker;
create function public.read_file_acl_portion_v265(resource jsonb,portion_id text) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare p public.semantic_file_acl_portions%rowtype;
begin
    if public.file_acl_resource_allowed_v265(resource) is not true then raise exception 'file_acl_source_denied' using errcode='42501'; end if;
    select * into p from public.semantic_file_acl_portions q where q.portion_id=read_file_acl_portion_v265.portion_id
      and q.document_json#>'{acl_context,resource}'=read_file_acl_portion_v265.resource;
    if not found or public.file_acl_qw_document_allowed_v265(p.document_json) is not true then
      raise exception 'file_acl_portion_unavailable' using errcode='42501'; end if;
    return jsonb_build_object('portion_id',p.portion_id,'signal_id',p.signal_id,'document',p.document_json);
end $$;
revoke all on function public.read_file_acl_portion_v265(jsonb,text) from public;
grant execute on function public.read_file_acl_portion_v265(jsonb,text) to adlog_semantic_worker;

create table public.semantic_file_acl_checks(
    resource_key text not null,result_id text not null,result_sha256 text not null,status text not null,
    checked_at timestamptz not null default now(),retry_at timestamptz not null,
    primary key(resource_key,result_id,result_sha256));
create table public.semantic_file_acl_scan_state(resource_key text primary key,after_key jsonb,updated_at timestamptz not null default now());
revoke all on public.semantic_file_acl_checks,public.semantic_file_acl_scan_state from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;

create function public.read_file_acl_results(resource jsonb,after_key jsonb default null,page_limit integer default 32) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
<<reader>>
declare r record; v jsonb; items jsonb:='[]'; diagnostics jsonb:='{}'; cursor_key jsonb; key text;
    bytes integer:=0; seen integer:=0; has_more boolean:=false;
begin
    if public.file_acl_resource_allowed_v265(resource) is not true or page_limit not between 1 and 32 then
      raise exception 'file_acl_source_denied' using errcode='42501'; end if;
    key:=public.file_acl_digest_v265(jsonb_build_array('file-acl-resource.v1',resource->>'installation_id',resource->>'agent_id',
      resource->>'source_instance_id',resource->>'collection_scope_id'));
    perform pg_advisory_xact_lock(hashtextextended(key,0));
    cursor_key:=after_key;
    if cursor_key is null then select s.after_key into cursor_key from public.semantic_file_acl_scan_state s where s.resource_key=key; end if;
    for r in select q.* from sli_plugin_file_audit.rule_results q
      where q.agent_id::text=resource->>'agent_id' and q.source_instance_id=resource->>'source_instance_id'
        and q.collection_scope_id=resource->>'collection_scope_id'
        and q.rule_code in ('file-audit.broad-write','file-audit.direct-user-rights')
        and (cursor_key is null or (q.observed_at,q.result_id)>((cursor_key->>0)::timestamptz,cursor_key->>1))
        and not exists(select 1 from public.semantic_file_acl_members m where m.resource_key=key
          and m.result_id=q.result_id and m.result_sha256=q.result_sha256)
        and not exists(select 1 from public.semantic_file_acl_checks c where c.resource_key=key
          and c.result_id=q.result_id and c.result_sha256=q.result_sha256 and c.retry_at>now())
      order by q.observed_at,q.result_id limit page_limit+1 loop
      seen:=seen+1;
      if seen>page_limit then has_more:=true; exit; end if;
      v:=public.file_acl_native_verdict_v265(resource,r.result_id,r.result_sha256);
      if v->>'status'='verified' then
        if bytes+octet_length(v::text)>4194304 then has_more:=true; exit; end if;
        items:=items||jsonb_build_array(v); bytes:=bytes+octet_length(v::text);
      else
        diagnostics:=jsonb_set(diagnostics,array[v->>'status'],to_jsonb(coalesce((diagnostics->>(v->>'status'))::integer,0)+1));
        insert into public.semantic_file_acl_checks(resource_key,result_id,result_sha256,status,retry_at)
          values(key,r.result_id,r.result_sha256,v->>'status',case when v->>'status'='verified_excluded'
            then 'infinity'::timestamptz else now()+interval '5 minutes' end)
          on conflict(resource_key,result_id,result_sha256) do update set status=excluded.status,checked_at=now(),retry_at=excluded.retry_at;
      end if;
      cursor_key:=jsonb_build_array(r.observed_at,r.result_id);
    end loop;
    -- Wrap only at EOF. A late old result is revisited, not lost behind a
    -- permanent observed_at watermark; blocked retries cannot starve neighbors.
    insert into public.semantic_file_acl_scan_state values(key,case when has_more then cursor_key else null end,now())
      on conflict(resource_key) do update set after_key=excluded.after_key,updated_at=now();
    return jsonb_build_object('items',items,'diagnostics',diagnostics,'byte_count',bytes,
      'has_more',has_more,'next_key',case when has_more then cursor_key else null end);
end $$;
revoke all on function public.read_file_acl_results(jsonb,jsonb,integer) from public;
grant execute on function public.read_file_acl_results(jsonb,jsonb,integer) to adlog_semantic_worker;

create function public.read_pending_file_acl_portions_v265(resource jsonb) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare items jsonb;
begin
    if public.file_acl_resource_allowed_v265(resource) is not true then raise exception 'file_acl_source_denied' using errcode='42501'; end if;
    select coalesce(jsonb_agg(jsonb_build_object('portion_id',q.portion_id,'signal_id',q.signal_id,'document',q.document_json)),'[]'::jsonb)
      into items from (select p.* from public.semantic_file_acl_portions p
        where p.document_json#>'{acl_context,resource}'=read_pending_file_acl_portions_v265.resource
          and public.file_acl_qw_document_allowed_v265(p.document_json)
          and exists(select 1 from public.semantic_file_acl_members m where m.portion_id=p.portion_id and not m.processed)
        order by p.created_at,p.portion_id limit 1) q;
    return items;
end $$;
revoke all on function public.read_pending_file_acl_portions_v265(jsonb) from public;
grant execute on function public.read_pending_file_acl_portions_v265(jsonb) to adlog_semantic_worker;

create function public.file_acl_execution_v265(resource jsonb) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('version','sli.qw.file-acl-execution.v1','kind','acl','rule_id','qw.file-acl-broad-write',
      'rule_version',1,'rule_sha256',public.file_acl_digest_v265(jsonb_build_array(
        'sli.qw.file-acl-broad-write.v1','everyone','medium','native-v265')),'resource',resource)
$$;
revoke all on function public.file_acl_execution_v265(jsonb) from public;

create function public.ensure_default_qw_policy_v262(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}'; s jsonb; digest bytea;
begin
    s:=pin->'scope'; digest:=sha256(convert_to(p_document,'UTF8'));
    if p_version<>1 or octet_length(p_document)>65536 or p_id not like 'default:qw.%'
       or d->>'type' is distinct from 'scenario_policy'
       or d#>>'{source_selector,rule_id}' is distinct from pin->>'rule_id'
       or pin->>'rule_id' not in ('qw.account-decoy','qw.account-watch','qw.file-decoy','qw.file-ransom',
           'qw.nps-denials','qw.password-spray','qw.password-brute-force','qw.disabled-account-logon')
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
           s->>'source_instance_id',s->>'source_generation',s->>'collection_scope_id',
           case when s->>'plugin_id'='sli.file-audit' then 'file_audit_observation' else 'core_event' end) is not true then
        raise exception 'default_detection_policy_denied' using errcode='42501';
    end if;
    -- A prior decision for this exact execution wins, even under a custom ID.
    if exists(select 1 from public.semantic_risk_policies p
        left join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=pin
          and (a.enabled is false or p.lifecycle_status in ('disabled','deprecated'))) then
        return false;
    end if;
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
    values(p_id,p_version,'qw_signal','draft',d,digest) on conflict do nothing;
    perform 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
        and definition_sha256=digest and definition_json=d for update;
    if not found then raise exception 'default_detection_policy_conflict'; end if;
    insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
    select p_id,p_version,'qw_signal',pin->>'rule_id',digest
    where not exists(select 1 from public.semantic_risk_policy_subscriptions where policy_id=p_id and policy_version=p_version);
    update public.semantic_risk_policies set lifecycle_status='shadow',updated_at=now()
        where policy_id=p_id and policy_version=p_version and lifecycle_status='draft';
    insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
    select p_id,p_version,true,'system:defaults' where exists(
        select 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=p_version
          and lifecycle_status in ('shadow','enabled'))
    on conflict(policy_id,policy_version) do nothing;
    return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id=p_id and p.policy_version=p_version and a.enabled
          and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
end $$;
revoke all on function public.ensure_default_qw_policy_v262(text,integer,text) from public,adlog_semantic_worker;
create or replace function public.ensure_default_qw_policy(p_id text,p_version integer,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb; pin jsonb; resource jsonb; digest bytea;
begin
    if octet_length(p_document)>65536 then raise exception 'default_detection_policy_denied' using errcode='42501'; end if;
    d:=p_document::jsonb; pin:=d#>'{source_selector,execution}';
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
revoke all on function public.ensure_default_qw_policy(text,integer,text) from public;
grant execute on function public.ensure_default_qw_policy(text,integer,text) to adlog_semantic_worker;

create function public.advance_file_acl_checkpoint_v265(resource jsonb,portion_id text,signal_id text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare p public.semantic_file_acl_portions%rowtype; pin jsonb;
begin
    select * into p from public.semantic_file_acl_portions q where q.portion_id=advance_file_acl_checkpoint_v265.portion_id
      and q.signal_id=advance_file_acl_checkpoint_v265.signal_id and q.document_json#>'{acl_context,resource}'=resource;
    if not found or public.file_acl_qw_document_allowed_v265(p.document_json) is not true
       or not exists(select 1 from public.semantic_qw_signals s where s.signal_id=p.signal_id and s.document_json=p.document_json) then
      raise exception 'file_acl_checkpoint_denied' using errcode='42501'; end if;
    pin:=public.file_acl_execution_v265(resource);
    if not exists(select 1 from public.semantic_risk_policies policy join public.semantic_policy_admission admission using(policy_id,policy_version)
      where policy.source_kind='qw_signal' and policy.definition_json#>'{source_selector,execution}'=pin
        and admission.enabled and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled')
       or exists(select 1 from public.semantic_risk_policies policy join public.semantic_policy_admission admission using(policy_id,policy_version)
        where policy.source_kind='qw_signal' and policy.definition_json#>'{source_selector,execution}'=pin and admission.enabled
          and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
          and (policy.definition_json#>>'{risk,class}'<>'medium' or not exists(
            select 1 from public.semantic_risk_evaluation_jobs job where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version
              and job.source_kind='qw_signal' and job.qw_signal_id=p.signal_id and job.evaluation_mode='enabled'))) then
      raise exception 'file_acl_checkpoint_jobs_missing' using errcode='42501'; end if;
    update public.semantic_file_acl_members m set processed=true,processed_at=now()
      where m.portion_id=p.portion_id and not m.processed;
    return true;
end $$;
revoke all on function public.advance_file_acl_checkpoint_v265(jsonb,text,text) from public;
grant execute on function public.advance_file_acl_checkpoint_v265(jsonb,text,text) to adlog_semantic_worker;

create function public.read_default_file_acl_resources(after_key jsonb default null,page_limit integer default 128) returns jsonb
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare installation uuid; cursor_key jsonb; rows jsonb; items jsonb; next_key jsonb; has_more boolean;
begin
    if not pg_has_role(session_user,'adlog_semantic_worker','MEMBER') or page_limit not between 1 and 128 then
      raise exception 'file_acl_source_denied' using errcode='42501'; end if;
    select installation_id into strict installation from public.semantic_default_installation;
    perform pg_advisory_xact_lock(hashtext('sli_file_acl_resource_discovery_v265'));
    cursor_key:=after_key;
    if cursor_key is null then select s.after_key into cursor_key from public.semantic_file_acl_scan_state s where s.resource_key='_resources'; end if;
    with candidates as (
      select distinct jsonb_build_array(a.id::text,a.host_id::text,root->>'collection_scope_id') as key,
        jsonb_build_object('installation_id',installation::text,'plugin_id','sli.file-audit','agent_id',a.id::text,
          'source_instance_id',a.host_id::text,'collection_scope_id',root->>'collection_scope_id') as resource
      from public.sli_agents a cross join lateral jsonb_array_elements(a.assigned_modules) m
      cross join lateral jsonb_array_elements(m#>'{config,roots}') root
      where a.status='active' and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
        and root->>'collection_scope_id' is not null
        and (cursor_key is null or jsonb_build_array(a.id::text,a.host_id::text,root->>'collection_scope_id')>cursor_key)
      order by key limit page_limit+1
    ) select coalesce(jsonb_agg(jsonb_build_object('key',key,'resource',resource) order by key),'[]'::jsonb) into rows from candidates;
    has_more:=jsonb_array_length(rows)>page_limit;
    select coalesce(jsonb_agg(value->'resource' order by ord),'[]'::jsonb) into items
      from jsonb_array_elements(rows) with ordinality t(value,ord) where ord<=page_limit;
    next_key:=case when has_more then rows->(page_limit-1)->'key' else null end;
    insert into public.semantic_file_acl_scan_state values('_resources',next_key,now()) on conflict(resource_key)
      do update set after_key=excluded.after_key,updated_at=now();
    return jsonb_build_object('items',items,'has_more',has_more,'next_key',next_key);
end $$;
revoke all on function public.read_default_file_acl_resources(jsonb,integer) from public;
grant execute on function public.read_default_file_acl_resources(jsonb,integer) to adlog_semantic_worker;

create index semantic_file_acl_portion_manifest_v265 on public.semantic_file_acl_portions using gin(manifest jsonb_path_ops);
create function public.file_acl_link_binding_v265(p_finding bigint,p_installation uuid,p_source text,p_generation text,
    p_collection text,p_native text,p_sha text) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare candidates jsonb; resource jsonb; episode_domain bigint; policy jsonb; current_config jsonb;
    old_root jsonb; current_root jsonb; provenance jsonb; count_domains integer; current_domain bigint; command text;
begin
    if not public.is_semantic_finding_published_v1(p_finding) or not starts_with(p_generation,'audit-command:')
       or not exists(select 1 from public.finding_evidence_refs f where f.finding_id=p_finding
        and f.installation_id=p_installation and f.plugin_id='sli.file-audit' and f.source_instance_id=p_source
        and f.source_generation=p_generation and f.collection_scope_id=p_collection
        and f.storage_kind='file_audit_snapshot' and f.native_id=p_native and f.sha256=p_sha) then return null; end if;
    command:=substr(p_generation,15);
    select jsonb_agg(jsonb_build_object('resource',q.resource,'domain_id',q.domain_id)) into candidates from (
      select distinct e.resource,e.domain_id from public.semantic_file_acl_portions p join public.semantic_file_acl_episodes e using(resource_key)
      where p.manifest @> jsonb_build_array(jsonb_build_object('snapshot_id',p_native,'snapshot_sha256',p_sha,'command_id',command))
        and e.resource->>'installation_id'=p_installation::text and e.resource->>'source_instance_id'=p_source
        and e.resource->>'collection_scope_id'=p_collection order by e.resource limit 2) q;
    if jsonb_array_length(candidates) is distinct from 1 then return null; end if;
    resource:=candidates->0->'resource'; episode_domain:=(candidates->0->>'domain_id')::bigint;
    if not exists(select 1 from public.semantic_default_installation where installation_id=p_installation) then return null; end if;
    select m->'config' into strict current_config from public.sli_agents a
      cross join lateral jsonb_array_elements(a.assigned_modules) m
      where a.id::text=resource->>'agent_id' and a.host_id::text=p_source and a.status='active'
        and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb;
    select pr.policy into strict policy from sli_plugin_file_audit.audit_commands c
      join sli_plugin_file_audit.policy_revisions pr on pr.agent_id=c.agent_id and pr.source_instance_id=c.source_instance_id and pr.revision=c.policy_revision
      where c.command_id=command and c.agent_id::text=resource->>'agent_id' and c.source_instance_id=p_source
        and p_collection=any(c.collection_scope_ids)
        and pr.policy_sha256=encode(sha256(convert_to(pr.policy::text,'UTF8')),'hex');
    select value into strict old_root from jsonb_array_elements(policy->'roots') where value->>'collection_scope_id'=p_collection;
    select value into strict current_root from jsonb_array_elements(current_config->'roots') where value->>'collection_scope_id'=p_collection;
    if policy->>'source_name' is distinct from current_config->>'source_name'
       or old_root->>'path' is distinct from current_root->>'path'
       or old_root->>'share_name' is distinct from current_root->>'share_name' then return null; end if;
    select count(*),min(domain_id) into count_domains,current_domain from public.servers
      where hostname=policy->>'source_name' and is_active;
    if count_domains<>1 or current_domain is distinct from episode_domain then return null; end if;
    if exists(select 1 from sli_plugin_file_audit.access_snapshots where snapshot_id=p_native::uuid) then
      provenance:=public.file_audit_snapshot_provenance_v264((resource->>'agent_id')::uuid,p_native::uuid);
      if provenance is null or provenance->>'command_id' is distinct from command
         or provenance->>'domain_id' is distinct from episode_domain::text
         or not exists(select 1 from sli_plugin_file_audit.access_snapshots s where s.snapshot_id=p_native::uuid and s.snapshot_sha256=p_sha) then return null; end if;
    end if;
    return jsonb_build_object('resource',resource,'domain_id',episode_domain);
exception when no_data_found or too_many_rows or invalid_text_representation then return null;
end $$;
revoke all on function public.file_acl_link_binding_v265(bigint,uuid,text,text,text,text,text) from public;

-- The old every-ref/all-domains union is retained, with only snapshots split
-- out of its packet-receipt branch into the exact owner-native proof above.
create function public.semantic_finding_in_domains_v265(p_finding bigint,p_domains bigint[]) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare allowed boolean;
begin
    with native_domains as materialized (
      select scopes.*,case when count(distinct b.agent_id)=1 then min(b.agent_id::text)::uuid end as agent_id,
        case when count(distinct server.domain_id)=1 and bool_and(server.domain_id is not null) then min(server.domain_id) end as domain_id
      from (select distinct installation_id,plugin_id,source_instance_id,source_generation,collection_scope_id,storage_kind
        from public.finding_evidence_refs where finding_id=p_finding and storage_kind not in ('core_event','file_audit_snapshot')) scopes
      left join public.finding_evidence_source_bindings b on b.installation_id=scopes.installation_id and b.plugin_id=scopes.plugin_id
        and b.source_instance_id=scopes.source_instance_id and b.source_generation=scopes.source_generation
        and b.collection_scope_id=scopes.collection_scope_id and b.storage_kind=scopes.storage_kind
      left join (public.sli_agent_receipts receipt join public.sli_agent_packet_inbox inbox on inbox.packet_id=receipt.packet_id
        and inbox.imported_at is not null and inbox.envelope=receipt.envelope and receipt.receipt->>'status'='committed')
        on receipt.agent_id=b.agent_id and receipt.module_id='sli.file-audit'
          and receipt.envelope->>'generation'=b.source_generation and receipt.envelope->>'source_instance_id'=b.source_instance_id
      left join public.servers server on server.hostname=inbox.packet#>>'{header,source}'
      group by scopes.installation_id,scopes.plugin_id,scopes.source_instance_id,scopes.source_generation,scopes.collection_scope_id,scopes.storage_kind
    ), evidence_domains as (
      select e.domain_id from public.finding_evidence fe left join public.events_v2_core e on e.id=fe.event_id where fe.finding_id=p_finding
      union all
      select case when o.evidence_key is not null then domains.domain_id end
      from public.finding_evidence_refs ref left join native_domains domains on domains.installation_id=ref.installation_id
        and domains.plugin_id=ref.plugin_id and domains.source_instance_id=ref.source_instance_id and domains.source_generation=ref.source_generation
        and domains.collection_scope_id=ref.collection_scope_id and domains.storage_kind=ref.storage_kind
      left join sli_plugin_file_audit.observations o on o.evidence_key=ref.native_id and o.agent_id=domains.agent_id
        and o.source_instance_id=ref.source_instance_id and o.generation=ref.source_generation and o.payload_sha256=ref.sha256
      where ref.finding_id=p_finding and ref.storage_kind not in ('core_event','file_audit_snapshot')
      union all
      select (public.file_acl_link_binding_v265(p_finding,ref.installation_id,ref.source_instance_id,ref.source_generation,
        ref.collection_scope_id,ref.native_id,ref.sha256)->>'domain_id')::bigint
      from public.finding_evidence_refs ref where ref.finding_id=p_finding and ref.storage_kind='file_audit_snapshot'
    ) select count(*)>0 and coalesce(bool_and(domain_id is not null and (p_domains is null or domain_id=any(p_domains))),false)
      into allowed from evidence_domains;
    return allowed;
end $$;
revoke all on function public.semantic_finding_in_domains_v265(bigint,bigint[]) from public;
grant execute on function public.semantic_finding_in_domains_v265(bigint,bigint[]) to adlog_user;

create function public.read_file_acl_finding_resources_v265(p_finding bigint,p_domains bigint[]) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare resources jsonb;
begin
    if public.semantic_finding_in_domains_v265(p_finding,p_domains) is not true then return '[]'::jsonb; end if;
    select coalesce(jsonb_agg(q.resource),'[]'::jsonb) into resources from (
      select distinct public.file_acl_link_binding_v265(p_finding,f.installation_id,f.source_instance_id,f.source_generation,
        f.collection_scope_id,f.native_id,f.sha256)->'resource' as resource
      from public.finding_evidence_refs f where f.finding_id=p_finding and f.storage_kind='file_audit_snapshot' limit 129) q;
    return resources;
end $$;
revoke all on function public.read_file_acl_finding_resources_v265(bigint,bigint[]) from public;
grant execute on function public.read_file_acl_finding_resources_v265(bigint,bigint[]) to adlog_user;

create function public.read_file_acl_finding_evidence(p_finding bigint,p_resources jsonb,p_after text,p_limit integer,
    p_watermark timestamptz,p_domains bigint[]) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare items jsonb:='[]'; f record; binding jsonb; snapshot jsonb; grants jsonb; grants_count integer;
    item jsonb; native_key text; total bigint; more boolean:=false;
begin
    if p_limit not between 1 and 200 or jsonb_typeof(p_resources) is distinct from 'array' or jsonb_array_length(p_resources)>128
       or public.semantic_finding_in_domains_v265(p_finding,p_domains) is not true then raise exception 'file_acl_evidence_denied' using errcode='42501'; end if;
    select count(*) into total from (select 1 from public.finding_evidence_refs ref
      where ref.finding_id=p_finding and ref.storage_kind='file_audit_snapshot' and ref.created_at<=p_watermark
        and (public.file_acl_link_binding_v265(p_finding,ref.installation_id,ref.source_instance_id,ref.source_generation,
          ref.collection_scope_id,ref.native_id,ref.sha256)->'resource') in (select value from jsonb_array_elements(p_resources))
      limit 10001) counted;
    for f in select ref.*,encode(sha256(convert_to(jsonb_build_array(ref.installation_id,ref.plugin_id,ref.source_instance_id,
      ref.source_generation,ref.collection_scope_id,ref.storage_kind,ref.native_id,ref.evidence_role)::text,'UTF8')),'hex') as key
      from public.finding_evidence_refs ref where ref.finding_id=p_finding and ref.storage_kind='file_audit_snapshot'
        and ref.created_at<=p_watermark
        and (public.file_acl_link_binding_v265(p_finding,ref.installation_id,ref.source_instance_id,ref.source_generation,
          ref.collection_scope_id,ref.native_id,ref.sha256)->'resource') in (select value from jsonb_array_elements(p_resources))
        and (p_after is null or encode(sha256(convert_to(jsonb_build_array(ref.installation_id,ref.plugin_id,ref.source_instance_id,
          ref.source_generation,ref.collection_scope_id,ref.storage_kind,ref.native_id,ref.evidence_role)::text,'UTF8')),'hex')>p_after)
      order by key limit p_limit+1 loop
      if jsonb_array_length(items)>=p_limit then more:=true; exit; end if;
      binding:=public.file_acl_link_binding_v265(p_finding,f.installation_id,f.source_instance_id,f.source_generation,
        f.collection_scope_id,f.native_id,f.sha256); native_key:=f.key;
      select s.snapshot into snapshot from sli_plugin_file_audit.access_snapshots s where s.snapshot_id=f.native_id::uuid and s.snapshot_sha256=f.sha256;
      item:=jsonb_build_object('storage_kind','file_audit_snapshot','evidence_key',native_key,'evidence_role','semantic_scenario',
        'historical',true,'availability','unavailable','observed_at_utc',null,'resource',null,
        'coverage',jsonb_build_object('state','unknown','unread_objects',null,'has_more',null),
        'grants','[]'::jsonb,'grants_has_more',false,'limitations',jsonb_build_array('native_source_unavailable'),'_native_key',native_key);
      if snapshot is not null then
        select coalesce(jsonb_agg(q.grant order by q.path,q.layer),'[]'::jsonb),count(*) into grants,grants_count from (
          select distinct r.result#>>'{details,path}' as path,r.result#>>'{details,layer}' as layer,
            jsonb_build_object('path',r.result#>>'{details,path}','layer',r.result#>>'{details,layer}','principal','everyone',
              'grant_mask',coalesce(nullif(r.result#>'{details,ntfs_mask}','null'::jsonb),r.result#>'{details,share_mask}'),'severity','medium') as grant
          from public.semantic_file_acl_portions p cross join lateral jsonb_array_elements(p.manifest) member
          join sli_plugin_file_audit.rule_results r on r.result_id=member->>'result_id' and r.result_sha256=member->>'result_sha256'
          where p.document_json#>'{acl_context,resource}'=binding->'resource' and member->>'snapshot_id'=f.native_id
            and member->>'snapshot_sha256'=f.sha256 and member->>'command_id'=substr(f.source_generation,15)
            and r.result_sha256=encode(sha256(convert_to(r.result::text,'UTF8')),'hex')
          order by path,layer limit 33) q;
        if grants_count>0 then
          select coalesce(jsonb_agg(value order by ord),'[]'::jsonb) into grants from jsonb_array_elements(grants) with ordinality t(value,ord) where ord<=32;
          item:=item||jsonb_build_object('availability','available','observed_at_utc',snapshot->>'observed_at_utc',
            'resource',(binding->'resource')-array['installation_id','plugin_id'],
            'coverage',jsonb_build_object('state',snapshot->>'completeness','unread_objects',snapshot->'unread_objects','has_more',snapshot->'has_more'),
            'grants',grants,'grants_has_more',grants_count>32,'limitations',jsonb_build_array('privileges_and_conditional_aces_not_evaluated'));
        end if;
      end if;
      items:=items||jsonb_build_array(item);
    end loop;
    return jsonb_build_object('items',items,'has_more',more,'total',case when total<=10000 then total else null end,
      'total_lower_bound',case when total>10000 then total else null end);
end $$;
revoke all on function public.read_file_acl_finding_evidence(bigint,jsonb,text,integer,timestamptz,bigint[]) from public;
grant execute on function public.read_file_acl_finding_evidence(bigint,jsonb,text,integer,timestamptz,bigint[]) to adlog_user;

-- ACL retained snapshots use the existing historical suppression receipt;
-- all earlier QW notification branches remain verbatim.
create or replace function public.enqueue_qw_finding_notifications(p_scenario_id uuid) returns integer
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare added integer; required integer; delivery_key text; severity text;
    contextual boolean; reason text := 'live'; minutes integer := 0; event_at timestamptz;
begin
    if not exists (
        select 1 from public.semantic_finding_publications publication
        join public.semantic_security_scenarios scenario on scenario.scenario_id=publication.scenario_id
        join public.semantic_risk_evaluation_results result on result.job_id=publication.first_job_id
        join public.semantic_risk_evaluation_jobs job on job.job_id=result.job_id
        join public.semantic_risk_policies policy using(policy_id,policy_version)
        join public.semantic_policy_admission admission using(policy_id,policy_version)
        where publication.scenario_id=p_scenario_id and result.scenario_id=p_scenario_id
          and scenario.evidence_state='ready'
          and result.evaluation_mode='enabled' and result.conclusion_state='observed'
          and job.source_kind='qw_signal' and admission.enabled is true
          and public.semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
    ) or not exists(select 1 from public.semantic_scenario_steps where scenario_id=p_scenario_id)
      or exists (
        select 1 from public.semantic_scenario_steps step
        left join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=p_scenario_id and (step.source_kind<>'qw_signal'
            or signal.evaluation_mode is distinct from 'enabled'
            or signal.document_json->>'conclusion_state' is distinct from 'observed'
            or public.qw_signal_evidence_allowed(signal.document_json,true) is not true)
    ) then
        raise exception 'qw_publication_unavailable';
    end if;
    select case when scenario_kind in ('qw.nps-denials','qw.account-watch') then risk_class else 'initial' end,risk_class
    into delivery_key,severity from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    select scenario_kind in ('qw.account-decoy','qw.file-decoy','qw.account-watch','qw.file-acl-broad-write')
      into contextual from public.semantic_security_scenarios where scenario_id=p_scenario_id;
    if contextual then
        -- Explicit provenance, never event age, distinguishes history from delay.
        -- Mixed episodes notify for their latest live observation.
        select case when bool_and(coalesce(signal.document_json->>'processing_mode','live')='history_import')
                    then 'history_import'
                    when bool_and(coalesce(signal.document_json->>'processing_mode','live') in ('historical_replay','history_import'))
                    then 'historical_replay' else 'live' end,
               max((signal.document_json->>'occurred_at_utc')::timestamptz)
                   filter(where coalesce(signal.document_json->>'processing_mode','live')='live')
        into reason,event_at
        from public.semantic_scenario_steps step
        join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
        where step.scenario_id=p_scenario_id;
        if reason='live' and event_at<clock_timestamp()-interval '15 minutes' then
            if exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
                and scenario_kind='qw.account-watch') then
                return 0;
            end if;
            reason := 'pipeline_delay';
            minutes := least(2147483647,floor(extract(epoch from (clock_timestamp()-event_at))/60))::integer;
        end if;
    elsif exists(select 1 from public.semantic_security_scenarios where scenario_id=p_scenario_id
        and scenario_kind='qw.nps-denials' and last_seen_utc<clock_timestamp()-interval '15 minutes') then
        -- Preserve the separate threshold notification policy.
        return 0;
    end if;
    if delivery_key not in ('initial','low','medium','high','critical') then
        raise exception 'qw_publication_unavailable';
    end if;
    if reason in ('historical_replay','history_import') then
        -- A suppression receipt must not consume a later live delivery's key.
        delivery_key := delivery_key || ':' || reason;
    end if;
    perform pg_advisory_xact_lock(hashtext('notification_outbox_admission'));
    -- Lock approved bindings against revision/disable edits until publication
    -- commits. Recipient grants are re-resolved by the delivery worker.
    perform 1 from public.notification_subscriptions where enabled order by id for share;
    select count(*) into required from (
        select distinct recipient_user_id,channel from public.notification_subscriptions s
        where enabled and not exists (
            select 1 from public.notification_outbox j where j.object_kind='semantic_finding'
                and j.object_id=p_scenario_id and j.recipient_user_id=s.recipient_user_id and j.channel=s.channel and j.change_key=delivery_key)
    ) recipients;
    if reason not in ('historical_replay','history_import') and required+(select count(*) from public.notification_outbox where state in ('pending','sending','retry'))>10000 then
        raise exception 'notification_queue_full';
    end if;
    insert into public.notification_outbox(id,subscription_id,subscription_revision,object_kind,object_id,
                                         publication_scenario_id,recipient_user_id,channel,change_key,object_severity,
                                         delivery_reason,delay_minutes,state,result_code)
    select gen_random_uuid(),s.id,s.revision,'semantic_finding',p_scenario_id,p_scenario_id,s.recipient_user_id,s.channel,delivery_key,severity,
        reason,minutes,
        case when reason in ('historical_replay','history_import') then 'cancelled' else 'pending' end,
        case when reason in ('historical_replay','history_import') then reason else null end
    from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s
    on conflict(object_kind,object_id,recipient_user_id,channel,change_key) do nothing;
    get diagnostics added=row_count;
    return added;
end $$;
revoke all on function public.enqueue_qw_finding_notifications(uuid) from public;
grant execute on function public.enqueue_qw_finding_notifications(uuid) to adlog_semantic_worker;

-- The resource episode keeps late historical steps. Its allowance derives only
-- from retained owner-issued facts, never current source/login/policy authority.
-- Keep CHECK row-local; the ordinary24h cap remains the trigger default.
alter table public.semantic_security_scenarios drop constraint semantic_scenario_time_window,
  add constraint semantic_scenario_time_window check(last_seen_utc>=first_seen_utc);

create function public.file_acl_scenario_history_span_allowed_v265(s public.semantic_security_scenarios)
returns boolean language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
<<history>>
declare resource jsonb; resource_key text; episode text; identity_hash text; raw_uuid bytea;
    field text; total bigint; first_at timestamptz; last_at timestamptz; all_sealed boolean;
begin
    if s.scenario_kind is distinct from 'qw.file-acl-broad-write' then return false; end if;
    select e.resource into resource from public.semantic_file_acl_episodes e where e.resource_key=s.partition_key;
    if not found or jsonb_typeof(resource) is distinct from 'object'
       or resource-array['installation_id','plugin_id','agent_id','source_instance_id','collection_scope_id']<>'{}'::jsonb
       or not resource ?& array['installation_id','plugin_id','agent_id','source_instance_id','collection_scope_id'] then return false; end if;
    foreach field in array array['installation_id','plugin_id','agent_id','source_instance_id','collection_scope_id'] loop
      if jsonb_typeof(resource->field) is distinct from 'string' or length(resource->>field) not between 1 and 256 then return false; end if;
    end loop;
    if resource->>'plugin_id'<>'sli.file-audit'
       or resource->>'installation_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
       or resource->>'agent_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then return false; end if;
    resource_key:=public.file_acl_digest_v265(jsonb_build_array('file-acl-resource.v1',resource->>'installation_id',
      resource->>'agent_id',resource->>'source_instance_id',resource->>'collection_scope_id'));
    episode:=public.file_acl_digest_v265(jsonb_build_array('file-acl-episode.v1',resource_key,'qw.file-acl-broad-write'));
    if s.partition_key<>resource_key or s.strict_keys_json<>jsonb_build_object('kind','acl','entity',resource_key,'episode',episode) then return false; end if;
    -- This fixed ASCII material exactly matches ScenarioProposal.identity_sha256.
    -- Custom-compatible result_class/window stay identity inputs, not defaults.
    identity_hash:=public.file_acl_digest_v265(jsonb_build_object('scenario_kind',s.scenario_kind,
      'result_class',s.result_class,'partition_key',s.partition_key,'strict_keys',s.strict_keys_json,
      'merge_window_seconds',s.merge_window_seconds));
    raw_uuid:=substring(public.digest(uuid_send('6ba7b811-9dad-11d1-80b4-00c04fd430c8'::uuid)
      ||convert_to('adlog:semantic-scenario:'||identity_hash,'UTF8'),'sha1') from 1 for 16);
    raw_uuid:=set_byte(raw_uuid,6,(get_byte(raw_uuid,6)&15)|80);
    raw_uuid:=set_byte(raw_uuid,8,(get_byte(raw_uuid,8)&63)|128);
    if s.identity_key<>decode(identity_hash,'hex') or s.scenario_key<>decode(identity_hash,'hex')
       or s.scenario_id<>encode(raw_uuid,'hex')::uuid then return false; end if;
    -- No LIMIT or supported subset: an extra foreign/unsealed/altered-time step
    -- invalidates the entire widened row, including direct SQL without refresh.
    select count(*),min(step.occurred_at_utc),max(step.occurred_at_utc),bool_and(
      case when signal.signal_id is null or portion.signal_id is null then false else coalesce(
      step.source_kind='qw_signal' and signal.signal_id=portion.signal_id
      and signal.evaluation_mode='enabled' and signal.document_json=portion.document_json
      and portion.resource_key=history.resource_key
      and portion.signal_id=public.file_acl_digest_v265(portion.document_json-'received_at_utc')
      and portion.document_json->>'kind'='acl'
      and portion.document_json->>'rule_id'='qw.file-acl-broad-write'
      and portion.document_json->'rule_version'='1'::jsonb and portion.document_json->'policy_revision'='1'::jsonb
      and portion.document_json->>'evaluation_mode'='enabled'
      and portion.document_json->>'conclusion_state'='observed'
      and portion.document_json->>'base_severity'='medium' and portion.document_json->>'effective_severity'='medium'
      and portion.document_json->'severity_reasons'='[]'::jsonb
      and portion.document_json->>'processing_mode'='historical_replay'
      and portion.document_json->>'entity_key'=history.resource_key and portion.document_json->>'episode_key'=history.episode
      and portion.document_json#>'{acl_context,resource}'=history.resource
      and portion.document_json#>>'{acl_context,resource_key}'=history.resource_key
      and portion.document_json#>>'{acl_context,portion_id}'=portion.portion_id
      and portion.document_json#>'{acl_context,members}'=portion.manifest
      and portion.portion_id=public.file_acl_digest_v265(jsonb_build_array('file-acl-portion.v1',history.resource_key,portion.manifest))
      and portion.document_json#>>'{acl_context,proof_sha256}'=
        public.file_acl_digest_v265(jsonb_build_array('file-acl-proof.v1',history.resource_key,portion.manifest))
      and step.occurred_at_utc=(portion.document_json->>'occurred_at_utc')::timestamptz,false) end)
      into total,first_at,last_at,all_sealed
      from public.semantic_scenario_steps step
      left join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
      left join public.semantic_file_acl_portions portion on portion.signal_id=step.qw_signal_id
      where step.scenario_id=s.scenario_id;
    return total>0 and all_sealed and s.first_seen_utc=first_at and s.last_seen_utc=last_at;
exception when invalid_text_representation or datetime_field_overflow or invalid_datetime_format then return false;
end $$;
revoke all on function public.file_acl_scenario_history_span_allowed_v265(public.semantic_security_scenarios)
  from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;

create function public.file_acl_scenario_time_guard_v265() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if TG_OP='UPDATE' then
      if row(NEW.scenario_id,NEW.scenario_kind,NEW.result_class,NEW.identity_key,NEW.scenario_key,NEW.partition_key,
             NEW.strict_keys_json,NEW.merge_window_seconds,NEW.first_seen_utc,NEW.last_seen_utc)
        is not distinct from
         row(OLD.scenario_id,OLD.scenario_kind,OLD.result_class,OLD.identity_key,OLD.scenario_key,OLD.partition_key,
             OLD.strict_keys_json,OLD.merge_window_seconds,OLD.first_seen_utc,OLD.last_seen_utc) then return NEW; end if;
      if OLD.last_seen_utc<=OLD.first_seen_utc+interval '24 hours'
         and NEW.last_seen_utc<=NEW.first_seen_utc+interval '24 hours' then return NEW; end if;
      if (OLD.last_seen_utc<=OLD.first_seen_utc+interval '24 hours' or
          row(NEW.scenario_id,NEW.scenario_kind,NEW.result_class,NEW.identity_key,NEW.scenario_key,NEW.partition_key,
              NEW.strict_keys_json,NEW.merge_window_seconds) is not distinct from
          row(OLD.scenario_id,OLD.scenario_kind,OLD.result_class,OLD.identity_key,OLD.scenario_key,OLD.partition_key,
              OLD.strict_keys_json,OLD.merge_window_seconds))
         and public.file_acl_scenario_history_span_allowed_v265(NEW) then return NEW; end if;
    elsif NEW.last_seen_utc<=NEW.first_seen_utc+interval '24 hours' then return NEW;
    end if;
    raise exception 'semantic scenario time window denied' using errcode='23514',
      constraint='semantic_scenario_time_window',table='semantic_security_scenarios',schema='public';
end $$;
revoke all on function public.file_acl_scenario_time_guard_v265()
  from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
create trigger file_acl_scenario_time_guard_v265 before insert or update on public.semantic_security_scenarios
  for each row execute function public.file_acl_scenario_time_guard_v265();

create function public.file_acl_step_history_guard_v265() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare ids uuid[]; s public.semantic_security_scenarios%rowtype;
begin
    if TG_OP='INSERT' then ids:=array[NEW.scenario_id];
    elsif TG_OP='DELETE' then ids:=array[OLD.scenario_id];
    else ids:=array[OLD.scenario_id,NEW.scenario_id]; end if;
    -- Step FK checks hold KEY SHARE: NO KEY UPDATE serializes final checks
    -- without waiting for unrelated concurrent child inserts to release it.
    for s in select * from public.semantic_security_scenarios where scenario_id=any(ids) order by scenario_id for no key update loop
      if s.last_seen_utc>s.first_seen_utc+interval '24 hours' then
        -- Also create a row-write serialization fence: a read lock alone lets
        -- REPEATABLE READ writers validate different stale step snapshots.
        update public.semantic_security_scenarios set title=title where scenario_id=s.scenario_id returning * into s;
        if public.file_acl_scenario_history_span_allowed_v265(s) is not true then
          raise exception 'semantic scenario retained history denied' using errcode='23514',
            constraint='semantic_scenario_time_window',table='semantic_security_scenarios',schema='public';
        end if;
      end if;
    end loop;
    return null;
end $$;
revoke all on function public.file_acl_step_history_guard_v265()
  from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
create constraint trigger file_acl_step_history_guard_v265 after insert or update or delete on public.semantic_scenario_steps
  deferrable initially deferred for each row execute function public.file_acl_step_history_guard_v265();

insert into public.schema_migrations(version,name) values(265,'file_acl_semantic_bridge');
commit;
