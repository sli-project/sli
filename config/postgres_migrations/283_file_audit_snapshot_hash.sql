-- T065: derive canonical integrity once per write; do not cache access decisions.
-- Backfill rewrites every retained row under a transaction/table lock, with WAL
-- and disk costs. Apply only through the controlled updater, never a live probe.
begin;
select pg_advisory_xact_lock(hashtext('sli_file_audit_snapshot_hash_v283'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not pg_has_role('adlog_storage_owner','adlog_file_audit_owner','USAGE')
       or not exists(select 1 from public.schema_migrations
           where version=282 and name='plugin_receipt_import_lookup')
       or exists(select 1 from public.schema_migrations where version>=283)
       or not exists(select 1 from pg_catalog.pg_class
           where oid='sli_plugin_file_audit.access_snapshots'::regclass
             and relowner=(select oid from pg_catalog.pg_roles where rolname='adlog_file_audit_owner'))
       or (select count(*) from pg_catalog.pg_proc
           where oid in (to_regprocedure('public.file_audit_snapshot_canonical_v264(jsonb,integer)'),
                         to_regprocedure('public.file_audit_snapshot_provenance_v264(uuid,uuid)'))
             and proowner=(select oid from pg_catalog.pg_roles where rolname='adlog_storage_owner'))<>2 then
        raise exception 'migration 283 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_file_audit_owner;
alter table sli_plugin_file_audit.access_snapshots add column canonical_body_sha256 text
    check(canonical_body_sha256 is null or canonical_body_sha256 ~ '^[a-f0-9]{64}$');
set local role adlog_storage_owner;

-- The existing native-owner membership permits trigger creation; no new grants.
-- Runtime INSERT has no EXECUTE on the private canonicalizer. Trigger execution
-- uses this narrow owner callback, not caller-supplied verification flags.
create function public.file_audit_snapshot_hash_v283() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare canonical text;
begin
    if tg_relid<>'sli_plugin_file_audit.access_snapshots'::regclass
       or tg_op not in ('INSERT','UPDATE') then
        raise exception 'file_audit_snapshot_hash_trigger_invalid';
    end if;
    -- Always overwrite, even on cache-only UPDATE. Never UPDATE the table here.
    new.canonical_body_sha256:=null;
    begin
        canonical:=public.file_audit_snapshot_canonical_v264(new.snapshot);
        if octet_length(canonical)<=49152 then
            new.canonical_body_sha256:=encode(sha256(convert_to(
                public.file_audit_snapshot_canonical_v264(new.snapshot-'snapshot_sha256'-'snapshot_id'),
                'UTF8')),'hex');
        end if;
    exception when data_exception or raise_exception then
        -- Preserve retention of content rejected by old provenance, not access.
        -- Cancellation and permission errors must abort; do not catch OTHERS.
        new.canonical_body_sha256:=null;
    end;
    return new;
end $$;
revoke all on function public.file_audit_snapshot_hash_v283() from public;
create trigger file_audit_snapshot_hash_v283 before insert or update
    on sli_plugin_file_audit.access_snapshots for each row
    execute function public.file_audit_snapshot_hash_v283();

set local role adlog_file_audit_owner;
-- Every legacy row uses exactly the same integrity computation as future writes.
update sli_plugin_file_audit.access_snapshots set canonical_body_sha256=null;
set local role adlog_storage_owner;

create or replace function public.file_audit_snapshot_provenance_v264(p_agent uuid,p_snapshot uuid) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare snap sli_plugin_file_audit.access_snapshots%rowtype; doc jsonb;
    command sli_plugin_file_audit.audit_commands%rowtype; policy jsonb; root jsonb; current_config jsonb;
    current_root jsonb; object jsonb; group_row jsonb; actual_hash text; matches integer:=0;
    domain bigint; domains integer; result jsonb;
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
    -- Trigger-derived digest includes successful full-document canonical bounds.
    -- NULL never authorizes legacy/invalid content. All live authority stays below.
    actual_hash:=snap.canonical_body_sha256;
    if actual_hash is null or actual_hash is distinct from snap.snapshot_sha256 then return null; end if;
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

insert into public.schema_migrations(version,name) values(283,'file_audit_snapshot_hash');
commit;
