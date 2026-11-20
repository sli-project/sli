-- Phase one only: typed ACL snapshot evidence; no admission or publication.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_acl_bridge_v264'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=263 and name='native_source_lookup_index')
       or exists(select 1 from public.schema_migrations where version>=264)
       or not exists(select 1 from pg_catalog.pg_extension where extname='pgcrypto')
       or getdatabaseencoding()<>'UTF8'
       or not exists(select 1 from pg_catalog.pg_collation
           where collnamespace='pg_catalog'::regnamespace and collname='pg_unicode_fast'
             and collprovider='b' and collisdeterministic) then
        raise exception 'migration 264 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
grant usage on schema sli_plugin_file_audit to adlog_storage_owner;
grant select on sli_plugin_file_audit.access_snapshots,sli_plugin_file_audit.audit_commands,
    sli_plugin_file_audit.audit_receipts,sli_plugin_file_audit.policy_revisions to adlog_storage_owner;
grant select(hostname,is_active,domain_id) on public.servers to adlog_storage_owner;
set local role adlog_storage_owner;

-- Match envelope.canonical exactly: ASCII, sorted Unicode keys, no whitespace.
-- Inventory contracts contain integers, never binary floats or arbitrary depth.
-- 98304 bounds preliminary JSONB presentation work, whose added whitespace
-- can exceed compact PAGE_BYTES. Canonical output itself stays <=49152 bytes.
create function public.file_audit_snapshot_quote_v264(p text) returns text
language plpgsql immutable strict set search_path=pg_catalog,pg_temp as $$
declare output text := '"'; point integer; ch text;
begin
    if octet_length(p)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
    -- PostgreSQL already quotes ASCII JSON in the same form. Escape DEL too,
    -- as ensure_ascii does. Avoid quadratic per-character work for large SDDL.
    if octet_length(p)=length(p) then
        output:=replace(to_jsonb(p)::text,chr(127),E'\\u007f');
        if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        return output;
    end if;
    for i in 1..length(p) loop
        ch:=substr(p,i,1); point:=ascii(ch);
        output:=output||case point
            when 34 then E'\\"' when 92 then E'\\\\' when 8 then E'\\b'
            when 9 then E'\\t' when 10 then E'\\n' when 12 then E'\\f' when 13 then E'\\r'
            else case when point<32 or point>=127 then
                case when point<=65535 then E'\\u'||lpad(to_hex(point),4,'0')
                else E'\\u'||lpad(to_hex(55296+(point-65536)/1024),4,'0')
                    ||E'\\u'||lpad(to_hex(56320+(point-65536)%1024),4,'0') end
                else ch end end;
        if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
    end loop;
    if octet_length(output)+1>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
    return output||'"';
end $$;
create function public.file_audit_snapshot_canonical_v264(p jsonb,p_depth integer default 0) returns text
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare output text; part record; separator text:=''; kind text:=jsonb_typeof(p);
begin
    if p is null or p_depth is null or p_depth<0 or p_depth>16 or octet_length(p::text)>98304 then
        raise exception 'file_audit_snapshot_content_invalid';
    end if;
    if kind='string' then return public.file_audit_snapshot_quote_v264(p#>>'{}');
    elsif kind='number' then
        if p::text !~ '^-?(0|[1-9][0-9]*)$' or abs((p::text)::numeric)>9007199254740991 then
            raise exception 'file_audit_snapshot_content_invalid';
        end if;
        return p::text;
    elsif kind in ('boolean','null') then return p::text;
    elsif kind='array' then
        output:='[';
        for part in select value from jsonb_array_elements(p) loop
            output:=output||separator||public.file_audit_snapshot_canonical_v264(part.value,p_depth+1);
            separator:=',';
            if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        end loop;
        if octet_length(output)+1>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        return output||']';
    elsif kind='object' then
        output:='{';
        for part in select key,value from jsonb_each(p) order by key collate "C" loop
            output:=output||separator||public.file_audit_snapshot_quote_v264(part.key)||':'
                ||public.file_audit_snapshot_canonical_v264(part.value,p_depth+1);
            separator:=',';
            if octet_length(output)>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        end loop;
        if octet_length(output)+1>49152 then raise exception 'file_audit_snapshot_content_invalid'; end if;
        return output||'}';
    end if;
    raise exception 'file_audit_snapshot_content_invalid';
end $$;
create function public.file_audit_snapshot_uuid_v264(p_command text,p_hash text) returns uuid
language plpgsql immutable strict set search_path=pg_catalog,pg_temp as $$
declare raw bytea;
begin
    if p_command !~ '^[a-zA-Z0-9_-]{1,128}$' or p_hash !~ '^[a-f0-9]{64}$' then
        raise exception 'file_audit_snapshot_content_invalid';
    end if;
    raw:=substring(public.digest(uuid_send('6ba7b811-9dad-11d1-80b4-00c04fd430c8'::uuid)
        ||convert_to(p_command||p_hash,'UTF8'),'sha1') from 1 for 16);
    raw:=set_byte(raw,6,(get_byte(raw,6)&15)|80);
    raw:=set_byte(raw,8,(get_byte(raw,8)&63)|128);
    return encode(raw,'hex')::uuid;
end $$;
create function public.file_audit_path_in_root_v264(p_path text,p_root text) returns boolean
language plpgsql immutable strict set search_path=pg_catalog,pg_temp as $$
declare path text:=replace(p_path,'/','\'); root text:=replace(p_root,'/','\'); part text;
begin
    if length(path) not between 3 and 4096 or length(root) not between 3 and 4096
       or substr(path,1,3) !~ '^[a-zA-Z]:\\$' or substr(root,1,3) !~ '^[a-zA-Z]:\\$'
       or substr(path,3) ~ '[:*?"<>|[:cntrl:]]' or substr(root,3) ~ '[:*?"<>|[:cntrl:]]' then return false; end if;
    foreach part in array string_to_array(substr(path,4),'\')||string_to_array(substr(root,4),'\') loop
        if part in ('.','..') or (part<>'' and part ~ '[ .]$') then return false; end if;
    end loop;
    -- PostgreSQL 18 builtin full Unicode lower matches Python str.lower;
    -- OS/default locale and Unicode casefold are not containment authority.
    path:=lower(path collate pg_catalog."pg_unicode_fast");
    root:=lower(rtrim(root,'\') collate pg_catalog."pg_unicode_fast");
    return (path collate pg_catalog."C")=(root collate pg_catalog."C")
        or starts_with(path collate pg_catalog."C",root||'\');
end $$;

-- The internal resolver reads retained facts only. Nothing accepts a caller's
-- domain, importance, policy, command hash or Python verification flag.
create function public.file_audit_snapshot_provenance_v264(p_agent uuid,p_snapshot uuid) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare snap sli_plugin_file_audit.access_snapshots%rowtype; doc jsonb; body jsonb;
    command sli_plugin_file_audit.audit_commands%rowtype; policy jsonb; root jsonb; current_config jsonb;
    current_root jsonb; object jsonb; group_row jsonb; actual_hash text; matches integer:=0;
    domain bigint; domains integer; result jsonb; canonical text;
begin
    select * into snap from sli_plugin_file_audit.access_snapshots where snapshot_id=p_snapshot and agent_id=p_agent;
    if not found or snap.contract_version<>1 then return null; end if;
    doc:=snap.snapshot;
    if jsonb_typeof(doc) is distinct from 'object' or octet_length(doc::text)>98304
       or doc- array['contract_id','collection_scope_id','policy_revision','observed_at_utc','scan_id','page_number',
           'has_more','completeness','unread_objects','share','local_groups','objects','snapshot_sha256','snapshot_id']<>'{}'::jsonb
       or (select count(*) from jsonb_object_keys(doc))<>14
       or doc->>'contract_id' is distinct from 'sli.file-audit.inventory.v1'
       or doc->>'snapshot_id' is distinct from snap.snapshot_id::text
       or doc->>'snapshot_sha256' is distinct from snap.snapshot_sha256
       or doc->>'collection_scope_id' is distinct from snap.collection_scope_id
       or jsonb_typeof(doc->'policy_revision') is distinct from 'string'
       or jsonb_typeof(doc->'observed_at_utc') is distinct from 'string'
       or length(doc->>'observed_at_utc')>40
       or doc->>'observed_at_utc' !~ '(Z|\+00:00)$'
       or doc->>'policy_revision' !~ '^[1-9][0-9]{0,15}$'
       or (doc->>'observed_at_utc')::timestamptz is distinct from snap.observed_at
       or doc->>'completeness' is distinct from snap.completeness
       or doc->>'completeness' not in ('complete','partial')
       or jsonb_typeof(doc->'page_number') is distinct from 'number'
       or jsonb_typeof(doc->'unread_objects') is distinct from 'number'
       or (doc->>'page_number')::integer not between 0 and 100000
       or (doc->>'unread_objects')::integer is distinct from snap.unread_objects
       or snap.unread_objects not between 0 and 100000
       or jsonb_typeof(doc->'has_more') is distinct from 'boolean'
       or jsonb_typeof(doc->'objects') is distinct from 'array'
       or jsonb_array_length(doc->'objects')>100000
       or jsonb_typeof(doc->'share') is distinct from 'object'
       or jsonb_typeof(doc->'local_groups') is distinct from 'object'
       or jsonb_typeof(doc->'scan_id') is distinct from 'string'
       or doc->>'scan_id' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
       or snap.completeness='complete' and (snap.unread_objects<>0 or doc->'has_more'<>'false'::jsonb or doc->>'page_number'<>'0')
    then return null; end if;
    canonical:=public.file_audit_snapshot_canonical_v264(doc);
    if octet_length(canonical)>49152 then return null; end if;
    body:=doc-'snapshot_sha256'-'snapshot_id';
    actual_hash:=encode(sha256(convert_to(public.file_audit_snapshot_canonical_v264(body),'UTF8')),'hex');
    if actual_hash is distinct from snap.snapshot_sha256 then return null; end if;
    select m->'config' into strict current_config from public.sli_agents agent
        cross join lateral jsonb_array_elements(agent.assigned_modules) m
        where agent.id=p_agent and agent.status='active' and agent.host_id::text=snap.source_instance_id
          and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb;
    for command in select c.* from sli_plugin_file_audit.audit_commands c
        where c.agent_id=p_agent and c.source_instance_id=snap.source_instance_id
          and c.policy_revision::text=doc->>'policy_revision' and snap.collection_scope_id=any(c.collection_scope_ids)
          and c.command_id ~ '^[a-zA-Z0-9_-]{1,128}$'
          and c.command_sha256=encode(sha256(convert_to(jsonb_build_object(
              'contract_id','sli.file-audit.audit-command.v1','command_id',c.command_id,
              'action',c.action,'policy_revision',c.policy_revision::text,
              'collection_scope_ids',to_jsonb(c.collection_scope_ids))::text,'UTF8')),'hex') limit 2 loop
        if public.file_audit_snapshot_uuid_v264(command.command_id,actual_hash)<>snap.snapshot_id then continue; end if;
        select p.policy into strict policy from sli_plugin_file_audit.policy_revisions p
            where p.agent_id=p_agent and p.source_instance_id=snap.source_instance_id and p.revision=command.policy_revision
              and p.policy_sha256=encode(sha256(convert_to(p.policy::text,'UTF8')),'hex');
        if policy->>'policy_revision' is distinct from doc->>'policy_revision'
           or coalesce(policy->>'source_kind','server') is distinct from coalesce(current_config->>'source_kind','server')
           or policy->>'source_name' is null or policy->>'source_name' is distinct from current_config->>'source_name'
        then continue; end if;
        select value into strict root from jsonb_array_elements(policy->'roots') where value->>'collection_scope_id'=snap.collection_scope_id;
        select value into strict current_root from jsonb_array_elements(current_config->'roots') where value->>'collection_scope_id'=snap.collection_scope_id;
        if root->>'path' is distinct from current_root->>'path' or root->>'share_name' is distinct from current_root->>'share_name'
           or jsonb_typeof(root->'important') is distinct from 'boolean'
           or doc#>>'{share,path}' is distinct from root->>'path' or doc#>>'{share,name}' is distinct from root->>'share_name'
           or jsonb_typeof(doc#>'{share,complete}') is distinct from 'boolean'
           or jsonb_typeof(doc#>'{share,dacl}') is distinct from 'string'
           or (doc->'share')-array['name','path','dacl','complete']<>'{}'::jsonb
           or (select count(*) from jsonb_object_keys(doc->'share'))<>4
           or jsonb_typeof(doc#>'{local_groups,complete}') is distinct from 'boolean'
           or jsonb_typeof(doc#>'{local_groups,groups}') is distinct from 'array'
           or jsonb_array_length(doc#>'{local_groups,groups}')>100
           or (doc->'local_groups')-array['complete','groups']<>'{}'::jsonb
           or (select count(*) from jsonb_object_keys(doc->'local_groups'))<>2
        then continue; end if;
        for object in select value from jsonb_array_elements(doc->'objects') loop
            if jsonb_typeof(object) is distinct from 'object'
               or (select count(*) from jsonb_object_keys(object))<>8
               or object-array['path','object_id','object_type','owner_sid','dacl','sacl','sacl_protected','sacl_missing']<>'{}'::jsonb
               or public.file_audit_path_in_root_v264(object->>'path',root->>'path') is not true
               or jsonb_typeof(object->'object_type') is distinct from 'string'
               or jsonb_typeof(object->'owner_sid') is distinct from 'string'
               or object->>'object_type' not in ('file','directory')
               or object->>'owner_sid' !~ '^S-1-([0-9]+-)*[0-9]+$'
               or jsonb_typeof(object->'object_id') is distinct from 'string' or length(object->>'object_id') not between 1 and 256
               or jsonb_typeof(object->'dacl') is distinct from 'string' or length(object->>'dacl') not between 1 and 65536
               or jsonb_typeof(object->'sacl') is distinct from 'string' or length(object->>'sacl') not between 1 and 65536
               or jsonb_typeof(object->'sacl_protected') is distinct from 'boolean'
               or jsonb_typeof(object->'sacl_missing') is distinct from 'boolean'
            then return null; end if;
        end loop;
        if exists(select 1 from jsonb_array_elements(doc->'objects') o
            group by lower((o->>'path') collate pg_catalog."pg_unicode_fast") having count(*)>1) then return null; end if;
        for group_row in select value from jsonb_array_elements(doc#>'{local_groups,groups}') loop
            if jsonb_typeof(group_row) is distinct from 'object'
               or group_row-array['group_sid','member_sids']<>'{}'::jsonb
               or (select count(*) from jsonb_object_keys(group_row))<>2
               or jsonb_typeof(group_row->'group_sid') is distinct from 'string'
               or group_row->>'group_sid' !~ '^S-1-([0-9]+-)*[0-9]+$'
               or jsonb_typeof(group_row->'member_sids') is distinct from 'array'
               or jsonb_array_length(group_row->'member_sids')>100
               or exists(select 1 from jsonb_array_elements(group_row->'member_sids') member
                   where jsonb_typeof(member)<>'string' or member#>>'{}' !~ '^S-1-([0-9]+-)*[0-9]+$')
            then return null; end if;
        end loop;
        if not exists(select 1 from sli_plugin_file_audit.audit_receipts receipt
            where receipt.command_id=command.command_id and receipt.agent_id=p_agent
              and receipt.source_instance_id=snap.source_instance_id and receipt.policy_revision=command.policy_revision
              and receipt.collection_scope_id=snap.collection_scope_id and receipt.state in ('verified','partial')
              and receipt.observed_at=snap.observed_at) then continue; end if;
        select count(*),min(server.domain_id) into domains,domain from public.servers server
            where server.hostname=policy->>'source_name' and server.is_active;
        if domains<>1 or domain is null then continue; end if;
        matches:=matches+1;
        result:=jsonb_build_object('command_id',command.command_id,'policy_revision',command.policy_revision,
            'domain_id',domain,'important',root->'important','snapshot_sha256',actual_hash,
            'source_instance_id',snap.source_instance_id,'collection_scope_id',snap.collection_scope_id);
    end loop;
    if matches=1 then return result; end if;
    return null;
exception when data_exception or no_data_found or too_many_rows then return null;
    when raise_exception then return null;
end $$;

alter table public.finding_evidence_source_bindings drop constraint finding_evidence_source_bindings_check;
alter table public.finding_evidence_source_bindings add constraint finding_evidence_source_bindings_check check (
    (storage_kind='core_event' and plugin_id in ('sli.windows.ad-dc','sli.vpn-nps') and collection_scope_id=''
        and log_source_id is not null and agent_key is null and agent_id is not null)
    or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
        and log_source_id is null and agent_key is not null and agent_id is null)
    or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
        and log_source_id is null and agent_key is null and agent_id is not null)
    or (storage_kind='file_audit_snapshot' and plugin_id='sli.file-audit' and collection_scope_id<>''
        and source_generation ~ '^audit-command:[a-zA-Z0-9_-]{1,128}$'
        and log_source_id is null and agent_key is null and agent_id is not null));
alter table public.finding_evidence_refs drop constraint finding_evidence_refs_check;
alter table public.finding_evidence_refs add constraint finding_evidence_refs_check check (
    (storage_kind='core_event' and plugin_id in ('sli.windows.ad-dc','sli.vpn-nps') and collection_scope_id=''
        and case when native_id ~ '^[1-9][0-9]{0,18}$' then native_id::numeric<9223372036854775808 else false end)
    or (storage_kind='workstation_observation' and plugin_id='sli.workstations' and collection_scope_id=''
        and native_id ~ '^[a-f0-9]{64}$')
    or (storage_kind='file_audit_observation' and plugin_id='sli.file-audit' and collection_scope_id<>''
        and native_id ~ '^[a-f0-9]{64}$')
    or (storage_kind='file_audit_snapshot' and plugin_id='sli.file-audit' and collection_scope_id<>''
        and native_id ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'));

revoke all on function public.file_audit_snapshot_quote_v264(text) from public;
revoke all on function public.file_audit_snapshot_canonical_v264(jsonb,integer) from public;
revoke all on function public.file_audit_snapshot_uuid_v264(text,text) from public;
revoke all on function public.file_audit_path_in_root_v264(text,text) from public;
revoke all on function public.file_audit_snapshot_provenance_v264(uuid,uuid) from public;
-- No raw native reads or provenance inspection are granted to application/worker.
create or replace function public.resolve_finding_evidence_ref(
    p_installation uuid,p_plugin text,p_source text,p_generation text,p_collection text,
    p_kind text,p_native text,p_sha256 text
) returns boolean language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
begin
    if p_sha256 is null or p_sha256 !~ '^[a-f0-9]{64}$' or p_native is null then return false; end if;
    select a.* into b from public.finding_evidence_source_bindings a join pg_catalog.pg_roles r
        on r.oid=a.principal_oid and r.rolname=a.principal_name
        where r.rolname=session_user and a.installation_id=p_installation and a.plugin_id=p_plugin
          and a.source_instance_id=p_source and a.source_generation=p_generation
          and a.collection_scope_id=p_collection and a.storage_kind=p_kind;
    if not found then return false; end if;
    if p_kind='file_audit_snapshot' then
        if p_native !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
           or p_plugin<>'sli.file-audit' or p_collection='' then return false; end if;
        return exists(select 1 from public.file_audit_snapshot_provenance_v264(b.agent_id,p_native::uuid) provenance
            where provenance->>'command_id'=substring(p_generation from 15)
              and provenance->>'snapshot_sha256'=p_sha256
              and provenance->>'source_instance_id'=p_source
              and provenance->>'collection_scope_id'=p_collection);
    elsif p_kind='core_event' then
        if p_native !~ '^[1-9][0-9]{0,18}$' or p_native::numeric>=9223372036854775808 then return false; end if;
        return exists(select 1 from public.events_v2_core e
            join public.raw_log_files raw on raw.id=e.raw_log_file_id
            join public.sli_agent_packet_inbox inbox on raw.file_path='agent-packet:'||inbox.packet_id::text
            join public.sli_agent_receipts receipt on receipt.packet_id=inbox.packet_id
            where e.id=p_native::bigint and e.log_source_id=b.log_source_id
              and encode(e.normalized_hash,'hex')=p_sha256 and inbox.imported_at is not null
              and receipt.receipt->>'status'='committed' and inbox.envelope=receipt.envelope
              and receipt.module_id=p_plugin and inbox.envelope->>'agent_id'=b.agent_id::text
              and inbox.envelope->>'source_instance_id'=p_source
              and inbox.envelope->>'generation'=p_generation);
    elsif p_kind='workstation_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_workstations.observations o
            where o.id=p_native and o.agent_key=b.agent_key and o.observation_sha256=p_sha256
              and o.observation->>'generation'=p_generation and o.observation->>'agent_key'=b.agent_key
              and encode(sha256(convert_to(o.source_xml,'UTF8')),'hex')=o.observation->>'source_sha256');
    elsif p_kind='file_audit_observation' and p_native ~ '^[a-f0-9]{64}$' then
        return exists(select 1 from sli_plugin_file_audit.observations o
            where o.evidence_key=p_native and o.agent_id=b.agent_id and o.source_instance_id=p_source
              and o.generation=p_generation and o.payload_sha256=p_sha256
              and o.normalized->>'payload_sha256'=p_sha256 and o.normalized->>'evidence_key'=p_native
              and (o.collection_scope_id=p_collection
                   or public.file_ransom_evidence_in_root(b.agent_id,p_source,p_collection,p_native)
                   or public.file_decoy_evidence_in_root(b.agent_id,p_source,p_generation,p_collection,p_native)));
    end if;
    return false;
end $$;

revoke all on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) from public;
grant execute on function public.resolve_finding_evidence_ref(uuid,text,text,text,text,text,text,text) to adlog_semantic_worker;
insert into public.schema_migrations(version,name) values(264,'file_audit_acl_bridge');
commit;
