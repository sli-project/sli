begin;
select pg_advisory_xact_lock(hashtext('sli_file_action_intake389'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=388 and name='password_live_first')
       or exists(select 1 from public.schema_migrations where version>=389) then
        raise exception 'file_action_intake389_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Only the file writer can admit a packet to the shared event_hot trigger.
-- Its row is created and removed in the writer's transaction for each packet.
create table public.file_action_projection389 (
    packet_id uuid primary key, backend_pid integer not null, transaction_id xid8 not null
);
revoke all on public.file_action_projection389 from public,adlog_user,adlog_storage_worker;

-- File packet documents use compact, ASCII JSON with integer numbers,
-- including the signed 64-bit record IDs and counters of the agent protocol.
create function public.file_action_canonical389(p jsonb,depth integer default 0) returns text
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare result text;
begin
    if depth>16 then raise exception 'file_action_attestation_failed' using errcode='22023'; end if;
    case jsonb_typeof(p)
    when 'object' then
        select '{'||coalesce(string_agg(public.file_audit_snapshot_quote_v264(key)||':'||
            public.file_action_canonical389(value,depth+1),',' order by key collate "C"),'')||'}' into result
        from jsonb_each(p);
    when 'array' then
        select '['||coalesce(string_agg(public.file_action_canonical389(value,depth+1),',' order by ordinal),'')||']' into result
        from jsonb_array_elements(p) with ordinality a(value,ordinal);
    when 'string' then result:=public.file_audit_snapshot_quote_v264(p#>>'{}');
    when 'number' then
        if p::text !~ '^-?(0|[1-9][0-9]*)$' then raise exception 'file_action_attestation_failed' using errcode='22023'; end if;
        result:=p::text;
    when 'boolean','null' then result:=p::text;
    else raise exception 'file_action_attestation_failed' using errcode='22023';
    end case;
    return result;
end $$;
revoke all on function public.file_action_canonical389(jsonb,integer) from public;

-- Bind the exact stored envelope, packet and ordered projection to the receipt.
-- The ingress service verifies the agent's certificate and signature before storing it.
create function public.verify_file_action_packet389(i public.sli_agent_packet_inbox) returns void
language plpgsql set search_path=pg_catalog,pg_temp as $$
declare receipt public.sli_agent_receipts; records jsonb; projected jsonb; payload_bytes text;
begin
    select r.* into strict receipt from public.sli_agent_receipts r
    join public.sli_agent_stream_receipts s on s.packet_id=r.packet_id and s.agent_id=r.agent_id
        and s.module_id=r.module_id and s.sequence=r.sequence and s.collection_channel=i.collection_channel
    where r.packet_id=i.packet_id and r.envelope=i.envelope and i.module_disabled_at is null
      and r.module_id='sli.file-audit' and r.receipt->>'status'='committed'
      and i.envelope->>'module_id'=r.module_id and i.envelope->>'agent_id'=r.agent_id::text
      and i.envelope->>'packet_id'=r.packet_id::text and i.envelope->'sequence'=to_jsonb(r.sequence)
      and i.collection_channel='Security'
      and not exists(select 1 from public.sli_agent_packet_quarantine q where q.packet_id=i.packet_id);

    records:=i.packet->'records';
    if jsonb_typeof(records) is distinct from 'array'
       or octet_length(i.packet::text)>98304 or octet_length(i.envelope::text)>98304
       or i.envelope->>'payload_contract' is distinct from 'sli.collection-packet.v1'
       or i.packet->>'contract' is distinct from i.envelope->>'payload_contract'
       or i.packet#>>'{header,channel}' is distinct from i.collection_channel
       or i.packet#>>'{header,generation}' is distinct from i.envelope->>'generation'
       or receipt.receipt->>'packet_id' is distinct from i.packet_id::text
       or receipt.receipt->'committed_cursor' is distinct from i.envelope->'cursor_after'
       or receipt.receipt->>'payload_sha256' is distinct from i.envelope->>'payload_sha256' then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
    if jsonb_array_length(records)>256
       or jsonb_array_length(records)<>jsonb_array_length(i.event_rows)
       or i.envelope->'record_count' is distinct from to_jsonb(jsonb_array_length(records)) then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
    select coalesce(jsonb_agg(value->'payload' order by ordinal),'[]'::jsonb) into projected
    from jsonb_array_elements(records) with ordinality a(value,ordinal)
    where value->>'format'='file_action' and value->'record_id'=value#>'{payload,record_id}';
    if projected is distinct from i.event_rows
       or receipt.envelope_sha256 is distinct from
           encode(sha256(convert_to(public.file_action_canonical389(i.envelope),'UTF8')),'hex') then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
    payload_bytes:=public.file_action_canonical389(i.packet);
    if octet_length(payload_bytes)>45056
       or i.envelope->'payload_bytes' is distinct from to_jsonb(octet_length(payload_bytes))
       or i.envelope->>'payload_sha256' is distinct from encode(sha256(convert_to(payload_bytes,'UTF8')),'hex') then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
end $$;
revoke all on function public.verify_file_action_packet389(public.sli_agent_packet_inbox) from public;

-- A file path is a scoped file identity, never a domain-controller identity.
-- Full Unicode lowercase matches the agent's path comparison, including final sigma.
create function public.file_action_path389(p_path text,p_root text) returns boolean
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select coalesce(char_length(p_path) between 3 and 4096
      and p_path ~ '^[A-Za-z]:\\' and p_path !~ '[[:cntrl:]*?"<>|/]'
      and strpos(substr(p_path,3),':')=0
      and not exists(select 1 from unnest(string_to_array(substr(p_path,4),E'\\')) s
          where s in ('.','..') or s<>rtrim(s,' .') or s='')
      and (lower(p_path collate pg_catalog.pg_unicode_fast)=lower(p_root collate pg_catalog.pg_unicode_fast)
        or starts_with(lower(p_path collate pg_catalog.pg_unicode_fast),
                       rtrim(lower(p_root collate pg_catalog.pg_unicode_fast),E'\\')||E'\\')),false)
$$;
revoke all on function public.file_action_path389(text,text) from public;

-- Rebuild all short fields from admitted data. Callers cannot supply origin,
-- weight, operation, domain or file scope independently of the receipt.
create function public.file_action_row389(p_packet uuid,p_ordinal integer) returns public.event_hot
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare i public.sli_agent_packet_inbox; a public.sli_agents; doc jsonb; current_assignment jsonb;
    config jsonb; scope jsonb; result public.event_hot; operation text; kind integer;
    minute timestamptz; first_seen timestamptz; last_seen timestamptz; weight bigint;
    server_ids bigint[]; domain_ids bigint[]; origin jsonb;
begin
    if not public.agent_module_enabled_v380('sli.file-audit') then
        raise exception 'module_disabled' using errcode='55000';
    end if;
    if not exists(select 1 from public.file_action_projection389 p where p.packet_id=p_packet
        and p.backend_pid=pg_backend_pid() and p.transaction_id=pg_current_xact_id_if_assigned()) then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
    select * into strict i from public.sli_agent_packet_inbox where packet_id=p_packet;
    select * into strict a from public.sli_agents where id=(i.envelope->>'agent_id')::uuid and status='active';
    if i.envelope->>'source_instance_id'<>coalesce(a.source_host_id,a.host_id)::text
       or not (i.envelope->>'generation'=i.envelope->>'source_instance_id'
          or i.envelope->>'generation' like (i.envelope->>'source_instance_id')||':%') then
        raise exception 'file_action_origin_invalid' using errcode='22023';
    end if;
    select m into strict current_assignment from jsonb_array_elements(a.assigned_modules) m
      where m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb;
    if coalesce(current_assignment#>>'{config,policy_revision}','1')=i.envelope->>'policy_revision' then
        config:=current_assignment->'config';
    else
        select m->'config' into strict config from public.sli_agent_policy_history h
        cross join lateral jsonb_array_elements(h.assigned_modules) m
        where h.agent_id=a.id and m->>'module_id'='sli.file-audit' and m->'enabled'='true'::jsonb
          and coalesce(m#>>'{config,policy_revision}','1')=i.envelope->>'policy_revision'
        order by h.revision limit 1;
    end if;
    if coalesce(config->>'source_kind','server')<>'server'
       or coalesce(current_assignment#>>'{config,source_kind}','server')<>'server'
       or config->>'source_name' is distinct from current_assignment#>>'{config,source_name}' then
        raise exception 'file_action_source_invalid' using errcode='22023';
    end if;
    doc:=i.event_rows->p_ordinal;
    if p_ordinal<0 or doc is null or jsonb_typeof(doc)<>'object'
       or i.packet#>>array['records',p_ordinal::text,'format']<>'file_action'
       or doc is distinct from i.packet#>array['records',p_ordinal::text,'payload']
       or doc->'record_id' is distinct from i.packet#>array['records',p_ordinal::text,'record_id']
       or doc->>'contract'<>'sli.file-audit.action.v1'
       or doc->>'computer_name' is distinct from coalesce(config->>'source_name',i.envelope->>'source_instance_id')
       or doc->>'computer_name' is distinct from i.packet#>>'{header,source}'
       or doc->>'provider_name'<>'Microsoft-Windows-Security-Auditing' or doc->>'channel'<>'Security'
       or not doc ?& array['contract','record_id','event_id','computer_name','channel','provider_name','collection_scope_id',
          'path','old_path','operation','subject_user_sid','client_ip','minute_utc','time_created','first_seen_utc','last_seen_utc','count','outcome']
       or doc-array['contract','record_id','event_id','computer_name','channel','provider_name','collection_scope_id',
          'path','old_path','operation','subject_user_sid','client_ip','minute_utc','time_created','first_seen_utc','last_seen_utc','count','outcome']<>'{}'::jsonb
       or exists(select 1 from jsonb_each(doc) f where
          case when key in ('record_id','event_id','count') then jsonb_typeof(value)<>'number'
               when key in ('old_path','client_ip') then jsonb_typeof(value) not in ('string','null')
               else jsonb_typeof(value)<>'string' end) then
        raise exception 'file_action_document_invalid' using errcode='22023';
    end if;
    kind:=(doc->>'event_id')::integer; operation:=doc->>'operation';
    if not (kind=4663 and operation in ('read','write','rename')
        or kind=4660 and operation='delete' or kind=4670 and operation='permissions'
        or kind in (4656,5145) and operation='access_denied') then
        raise exception 'file_action_kind_invalid' using errcode='22023';
    end if;
    weight:=(doc->>'count')::bigint; minute:=(doc->>'minute_utc')::timestamptz;
    first_seen:=(doc->>'first_seen_utc')::timestamptz; last_seen:=(doc->>'last_seen_utc')::timestamptz;
    if jsonb_typeof(doc->'count')<>'number' or weight<=0 or (doc->>'record_id')::bigint<=0
       or not isfinite(minute) or not isfinite(first_seen) or not isfinite(last_seen)
       or date_trunc('minute',minute)<>minute or first_seen<minute or last_seen<first_seen or last_seen>=minute+interval '1 minute'
       or (doc->>'time_created')::timestamptz<>first_seen or weight=1 and first_seen<>last_seen
       or doc->>'subject_user_sid' !~ '^S-1-([0-9]+-)*[0-9]+$' or char_length(doc->>'subject_user_sid')>184
       or doc->>'outcome'<>(case when operation='access_denied' then 'failure' else 'success' end)
       or (doc->>'client_ip' is not null and (char_length(doc->>'client_ip')>45 or not pg_input_is_valid(doc->>'client_ip','inet'))) then
        raise exception 'file_action_values_invalid' using errcode='22023';
    end if;
    select r into strict scope from jsonb_array_elements(config->'roots') r
        where r->>'collection_scope_id'=doc->>'collection_scope_id';
    if not public.file_action_path389(doc->>'path',scope->>'path')
       or (operation='rename')<>(doc->>'old_path' is not null)
       or operation='rename' and (not public.file_action_path389(doc->>'old_path',scope->>'path')
           or lower((doc->>'old_path') collate pg_catalog.pg_unicode_fast)=
              lower((doc->>'path') collate pg_catalog.pg_unicode_fast)) then
        raise exception 'file_action_scope_invalid' using errcode='22023';
    end if;
    select array_agg(id),array_agg(domain_id) into server_ids,domain_ids from public.servers
        where is_active and (lower(hostname)=lower(doc->>'computer_name') or lower(fqdn)=lower(doc->>'computer_name'));
    if cardinality(server_ids) is distinct from 1 then
        raise exception 'file_action_server_unavailable' using errcode='55000';
    end if;
    select jsonb_build_object('installation_id',installation_id::text,'plugin_id','sli.file-audit',
        'source_instance_id',i.envelope->>'source_instance_id','source_generation',i.envelope->>'generation',
        'collection_scope_id',doc->>'collection_scope_id','agent_id',a.id::text) into strict origin
        from public.semantic_default_installation;
    result.time_created_utc:=first_seen; result.event_kind:=kind; result.domain_id:=domain_ids[1];
    result.actor:=doc->>'subject_user_sid'; result.target:=null; result.source:=doc->>'client_ip'; result.computer:=doc->>'computer_name';
    result.method:=jsonb_build_object('$file_packet',p_packet::text,'$file_ordinal',p_ordinal,
        '$server_id',server_ids[1],'$channel','Security','$provider','Microsoft-Windows-Security-Auditing',
        'operation',operation,'collection_scope_id',doc->>'collection_scope_id');
    result.outcome:=jsonb_build_object('outcome',doc->>'outcome');
    result.fields:=jsonb_build_object('path',doc->>'path','operation',operation,'old_path',doc->>'old_path',
        'aggregate',jsonb_build_object('count',weight,'first_seen_utc',doc->>'first_seen_utc','last_seen_utc',doc->>'last_seen_utc'));
    result.source_sha256:=sha256(convert_to(doc::text,'UTF8')); result.event_record_id:=(doc->>'record_id')::bigint;
    result.method:=result.method||jsonb_build_object('$origin',origin);
    return result;
end $$;
revoke all on function public.file_action_row389(uuid,integer) from public;

create function public.attest_file_action389(p_row public.event_hot) returns public.event_hot
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare expected public.event_hot;
begin
    expected:=public.file_action_row389((p_row.method->>'$file_packet')::uuid,(p_row.method->>'$file_ordinal')::integer);
    expected.event_id:=p_row.event_id;
    if (to_jsonb(p_row)-'source_sha256'-'event_record_id') is distinct from
       (to_jsonb(expected)-'source_sha256'-'event_record_id') then
        raise exception 'file_action_attestation_failed' using errcode='22023';
    end if;
    expected.method:=expected.method-'$file_packet'-'$file_ordinal';
    return expected;
end $$;
revoke all on function public.attest_file_action389(public.event_hot) from public;

-- Extend admission in a separate branch; retain every DC check from 381.
do $patch389$ declare definition text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict definition;
    patched:=replace(definition,$old$    admission_packet:=new.method->>'$packet_id';$old$,
      $new$    if new.method ? '$file_packet' then return public.attest_file_action389(new); end if;
    admission_packet:=new.method->>'$packet_id';$new$);
    if patched=definition then raise exception 'file_action_intake389_trigger_shape' using errcode='55000'; end if;
    execute patched;
end $patch389$;

create function public.write_file_actions389(p_packet uuid,p_rows jsonb) returns void
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare i public.sli_agent_packet_inbox; h public.event_hot; actions public.event_hot[];
    operation text; group_day date; grouping bytea; dimensions jsonb;
    first_seen timestamptz; last_seen timestamptz; weight bigint;
begin
    if not public.agent_module_enabled_v380('sli.file-audit') then raise exception 'module_disabled' using errcode='55000'; end if;
    select * into strict i from public.sli_agent_packet_inbox where packet_id=p_packet for update;
    if i.event_rows is distinct from p_rows then raise exception 'file_action_attestation_failed' using errcode='22023'; end if;
    -- The receipt/inbox is the replay fence, retained by the ordinary expiry
    -- path. A retry after hot retention must not recreate rows or add totals.
    if i.imported_at is not null then return; end if;
    perform public.verify_file_action_packet389(i);
    insert into public.file_action_projection389 values(p_packet,pg_backend_pid(),pg_current_xact_id());
    actions:=array(select public.file_action_row389(p_packet,ordinal)
        from generate_series(0,jsonb_array_length(p_rows)-1) s(ordinal) order by ordinal);
    perform public.create_event_storage_partitions(d,d) from (
        select distinct (a.time_created_utc at time zone 'UTC')::date as d from unnest(actions) a
    ) days order by d;
    foreach h in array actions loop
        h.event_id:=nextval('public.storage_v2_event_id_seq');
        group_day:=(h.time_created_utc at time zone 'UTC')::date;
        insert into public.event_hot select h.* returning * into h;
        operation:=h.fields->>'operation';
        if operation in ('delete','rename','permissions') then
            insert into public.event_cold_facts select h.*;
        elsif operation in ('read','write') then
            -- No packet, ordinal, generation or minute in daily dimensions.
            -- File paths stay in hot; a day is grouped by user/source/server,
            -- selected root, operation and outcome rather than individual file.
            dimensions:=h.method-'$origin'||jsonb_build_object('source_instance_id',i.envelope->>'source_instance_id');
            grouping:=sha256(convert_to(jsonb_build_array(h.event_kind,h.domain_id,h.actor,h.source,h.computer,dimensions,h.outcome)::text,'UTF8'));
            weight:=(h.fields#>>'{aggregate,count}')::bigint;
            first_seen:=(h.fields#>>'{aggregate,first_seen_utc}')::timestamptz;
            last_seen:=(h.fields#>>'{aggregate,last_seen_utc}')::timestamptz;
            insert into public.event_cold_daily as existing(day,grouping_key,event_kind,domain_id,actor,target,source,computer,method,outcome,event_count,first_seen_utc,last_seen_utc)
                values(group_day,grouping,h.event_kind,h.domain_id,h.actor,null,h.source,h.computer,dimensions,h.outcome,weight,first_seen,last_seen)
            on conflict(day,grouping_key) do update set event_count=existing.event_count+excluded.event_count,
                first_seen_utc=least(existing.first_seen_utc,excluded.first_seen_utc),last_seen_utc=greatest(existing.last_seen_utc,excluded.last_seen_utc)
            where (existing.event_kind,existing.domain_id,existing.actor,existing.target,existing.source,existing.computer,existing.method,existing.outcome)
                is not distinct from (excluded.event_kind,excluded.domain_id,excluded.actor,excluded.target,excluded.source,excluded.computer,excluded.method,excluded.outcome);
            if not found then raise exception 'short_event_summary_conflict' using errcode='22023'; end if;
        end if;
    end loop;
    update public.sli_agent_packet_inbox set imported_at=clock_timestamp() where packet_id=p_packet;
    delete from public.file_action_projection389 where packet_id=p_packet;
end $$;
revoke all on function public.write_file_actions389(uuid,jsonb) from public;
grant execute on function public.write_file_actions389(uuid,jsonb) to adlog_user;
insert into public.schema_migrations(version,name) values(389,'file_action_intake');
reset role;
commit;
