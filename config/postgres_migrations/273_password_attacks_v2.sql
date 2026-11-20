-- Password v2 B1 WIP: native boundary + blocked state/health; not a complete release.
begin;
select pg_advisory_xact_lock(hashtext('sli_password_attacks_v2_v273'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER') then
        raise exception 'migration 273 prerequisites failed';
    end if;
    if not exists(select 1 from public.schema_migrations where version=272 and name='file_audit_assignment_policy')
       or exists(select 1 from public.schema_migrations where version>=273) then
        raise exception 'migration 273 prerequisites failed';
    end if;
end $$;
set local lock_timeout='5s';
set local role adlog_storage_owner;

create index idx_password_v2_source_time on public.events_v2_core(log_source_id,time_created_utc,id)
    where event_id in (4625,4771,4776);

-- Private authority helper: never accepts current_user, a GUC, or a verified flag.
create function public.password_v2_source_binding(s jsonb)
returns public.finding_evidence_source_bindings
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; keys text[]; k text; value text;
begin
    if s is null or jsonb_typeof(s)<>'object' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023';
    end if;
    select array_agg(key order by key) into keys from jsonb_object_keys(s) key;
    if keys is distinct from array['collection_scope_id','installation_id','plugin_id','source_generation','source_instance_id'] then
        raise exception 'password_v2_arguments_invalid' using errcode='22023';
    end if;
    foreach k in array keys loop
        if jsonb_typeof(s->k)<>'string' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        value:=s->>k;
        if value ~ '^[[:space:]]|[[:space:]]$' or length(value)>(case k
            when 'plugin_id' then 128 when 'source_instance_id' then 256
            when 'source_generation' then 512 when 'collection_scope_id' then 256 else 36 end)
            or (k<>'collection_scope_id' and length(value)=0) then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
    end loop;
    if s->>'installation_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023';
    end if;
    select binding.* into b from public.finding_evidence_source_bindings binding
    join pg_catalog.pg_roles r on r.oid=binding.principal_oid and r.rolname=binding.principal_name
    where r.rolname=session_user and binding.installation_id=(s->>'installation_id')::uuid
      and binding.plugin_id='sli.windows.ad-dc' and s->>'plugin_id'='sli.windows.ad-dc'
      and binding.source_instance_id=s->>'source_instance_id'
      and binding.source_generation=s->>'source_generation'
      and binding.collection_scope_id='' and s->>'collection_scope_id'=''
      and binding.storage_kind='core_event';
    if not found then raise exception 'password_v2_source_denied' using errcode='42501'; end if;
    return b;
end $$;
revoke all on function public.password_v2_source_binding(jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Metadata is a real first record even when the bounded source window is empty.
create function public.read_default_password_window_v2(s jsonb)
returns table(record_kind text,metadata jsonb,source_event_id bigint,event_id integer,
    occurred_at_utc timestamptz,sha256 text,source_xml text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype;
    t timestamptz:=statement_timestamp(); candidates jsonb[]; candidate jsonb; native jsonb;
    buffered jsonb[]:=array[]::jsonb[]; item jsonb; xml text; bytes bigint; total_bytes bigint:=0;
    n integer:=0; checked integer:=0; unverifiable integer:=0; oversized integer:=0; failure text;
begin
    b:=public.password_v2_source_binding(s);
    -- The sentinel is selected and counted BEFORE either native authority call.
    with bounded_candidates as materialized (
        select e.id,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex') as normalized_sha256
        from public.events_v2_core e
        where e.log_source_id=b.log_source_id and e.event_id in (4625,4771,4776)
          and e.time_created_utc between t-interval '720 seconds' and t
        order by e.time_created_utc,e.id limit 10001
    ) select array_agg(to_jsonb(c) order by c.time_created_utc,c.id),count(*)::integer
      into candidates,n from bounded_candidates c;
    if n>10000 then
        failure:='password_v2_window_truncated';
    elsif n>0 then
        foreach candidate in array candidates loop
            native:=public.read_agent_semantic_source_v190((candidate->>'id')::bigint);
            checked:=checked+1;
            if native is null or jsonb_typeof(native#>'{event_row,xml}') is distinct from 'string' then
                failure:='password_v2_native_unavailable';
            elsif public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
                    b.source_generation,'','core_event',candidate->>'id',candidate->>'normalized_sha256') is not true then
                failure:='password_v2_native_unavailable';
            end if;
            if failure is not null then
                unverifiable:=unverifiable+1;
                buffered:=array[]::jsonb[];
                exit;
            end if;
            xml:=native#>>'{event_row,xml}';
            bytes:=octet_length(convert_to(xml,'UTF8'));
            total_bytes:=total_bytes+bytes;
            if bytes>4194304 then oversized:=oversized+1; end if;
            -- The failing lookahead ends native work; no suffix or partial output.
            if oversized>0 or total_bytes>33554432 then
                failure:='password_v2_xml_budget_exceeded';
                buffered:=array[]::jsonb[];
                exit;
            end if;
            buffered:=array_append(buffered,candidate||jsonb_build_object('source_xml',xml));
        end loop;
    end if;
    return query select 'metadata'::text,jsonb_build_object(
        'version','sli.password.v2.window.1',
        'read_from',to_char((t-interval '720 seconds') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'read_to',to_char(t at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'finalizable_through',to_char((t-interval '120 seconds') at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
        'candidate_count',n,'truncated',n>10000,
        'native_checked_count',checked,'native_checks_complete',n<=10000 and checked=n,
        'unverifiable_count',unverifiable,
        'oversized_count',oversized,'error_code',failure),null::bigint,null::integer,null::timestamptz,null::text,null::text;
    if failure is null then
        foreach item in array buffered loop
            return query select 'event'::text,null::jsonb,(item->>'id')::bigint,(item->>'event_id')::integer,
                (item->>'time_created_utc')::timestamptz,item->>'normalized_sha256',item->>'source_xml';
        end loop;
    end if;
end $$;
revoke all on function public.read_default_password_window_v2(jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.read_default_password_window_v2(jsonb) to adlog_semantic_worker;

-- Exact retained occurrences only: no time-range/history export or trusted cache.
create function public.read_password_retained_proof_v2(s jsonb,occurrences jsonb)
returns table(occurrence_index integer,source_event_id bigint,event_id integer,occurred_at_utc timestamptz,
    sha256 text,source_xml text,xml_bytes integer,xml_sha256 text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; witness jsonb; ref jsonb; keys text[];
    core record; native jsonb; xml text; bytes bigint; total_bytes bigint:=0; digest text;
    at_time timestamptz; n integer:=0; buffered jsonb[]:=array[]::jsonb[]; item jsonb;
begin
    b:=public.password_v2_source_binding(s);
    if occurrences is null or jsonb_typeof(occurrences)<>'array' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023';
    end if;
    if jsonb_array_length(occurrences)>10000 then
        raise exception 'password_v2_proof_budget_exceeded' using errcode='54000';
    end if;
    for witness in select value from jsonb_array_elements(occurrences) loop
        n:=n+1;
        if jsonb_typeof(witness)<>'object' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        select array_agg(key order by key) into keys from jsonb_object_keys(witness) key;
        if keys is distinct from array['at','ref','xml_bytes','xml_sha256']
           or jsonb_typeof(witness->'ref') is distinct from 'object'
           or jsonb_typeof(witness->'at') is distinct from 'string'
           or length(witness->>'at')>64
           or jsonb_typeof(witness->'xml_sha256') is distinct from 'string'
           or witness->>'xml_sha256' !~ '^[a-f0-9]{64}$'
           or jsonb_typeof(witness->'xml_bytes') is distinct from 'number'
           or length(witness->>'xml_bytes')>10
           or witness->>'xml_bytes' !~ '^[0-9]+$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        ref:=witness->'ref';
        select array_agg(key order by key) into keys from jsonb_object_keys(ref) key;
        if keys is distinct from array['native_id','scope','sha256','storage_kind']
           or jsonb_typeof(ref->'native_id') is distinct from 'string'
           or jsonb_typeof(ref->'sha256') is distinct from 'string'
           or jsonb_typeof(ref->'storage_kind') is distinct from 'string'
           or ref->>'storage_kind'<>'core_event'
           or ref->>'native_id' !~ '^[1-9][0-9]{0,18}$'
           or ref->>'sha256' !~ '^[a-f0-9]{64}$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        if (ref->>'native_id')::numeric>=9223372036854775808 then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        if ref->'scope' is distinct from s then
            raise exception 'password_v2_retained_unavailable' using errcode='42501';
        end if;
        if witness->>'at' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T.*(Z|[+-][0-9]{2}:[0-9]{2})$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end if;
        begin
            at_time:=(witness->>'at')::timestamptz;
        exception when invalid_datetime_format or datetime_field_overflow then
            raise exception 'password_v2_arguments_invalid' using errcode='22023';
        end;
        select e.id,e.event_id,e.time_created_utc,encode(e.normalized_hash,'hex') as normalized_sha256
        into core from public.events_v2_core e
        where e.id=(ref->>'native_id')::bigint and e.log_source_id=b.log_source_id and e.event_id in (4625,4771,4776);
        if not found or core.normalized_sha256 is distinct from ref->>'sha256'
           or core.time_created_utc is distinct from at_time then
            raise exception 'password_v2_retained_unavailable' using errcode='42501';
        end if;
        if public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,
                b.source_generation,'','core_event',ref->>'native_id',ref->>'sha256') is not true then
            raise exception 'password_v2_retained_unavailable' using errcode='42501';
        end if;
        native:=public.read_agent_semantic_source_v190(core.id);
        if native is null or jsonb_typeof(native#>'{event_row,xml}') is distinct from 'string' then
            raise exception 'password_v2_retained_unavailable' using errcode='42501';
        end if;
        xml:=native#>>'{event_row,xml}';
        bytes:=octet_length(convert_to(xml,'UTF8'));
        total_bytes:=total_bytes+bytes;
        if bytes>4194304 or total_bytes>33554432 then
            raise exception 'password_v2_proof_budget_exceeded' using errcode='54000';
        end if;
        digest:=encode(sha256(convert_to(xml,'UTF8')),'hex');
        if bytes::numeric is distinct from (witness->>'xml_bytes')::numeric
           or digest is distinct from witness->>'xml_sha256' then
            raise exception 'password_v2_retained_unavailable' using errcode='42501';
        end if;
        buffered:=array_append(buffered,jsonb_build_object('occurrence_index',n,'source_event_id',core.id,
            'event_id',core.event_id,'occurred_at_utc',core.time_created_utc,'sha256',core.normalized_sha256,
            'source_xml',xml,'xml_bytes',bytes,'xml_sha256',digest));
    end loop;
    -- No RETURN NEXT/QUERY occurs until the complete current-content pass fits.
    foreach item in array buffered loop
        return query select (item->>'occurrence_index')::integer,(item->>'source_event_id')::bigint,
            (item->>'event_id')::integer,(item->>'occurred_at_utc')::timestamptz,item->>'sha256',
            item->>'source_xml',(item->>'xml_bytes')::integer,item->>'xml_sha256';
    end loop;
end $$;
revoke all on function public.read_password_retained_proof_v2(jsonb,jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.read_password_retained_proof_v2(jsonb,jsonb) to adlog_semantic_worker;

-- B1 state/health only. State admission remains blocked until reservation authority.
create table public.semantic_password_checkpoints (
    scope_digest bytea not null check(octet_length(scope_digest)=32),
    pin text not null check(pin ~ '^[a-f0-9]{64}$'),
    scope_json jsonb not null, execution_json jsonb not null,
    state_revision bigint not null default 0 check(state_revision>=0),
    state_document jsonb, watermark timestamptz, coverage_epoch bigint not null default 0 check(coverage_epoch>=0),
    history_started boolean not null default false,
    active_token bigint not null default 0 check(active_token>=0),
    last_observed_token bigint not null default 0 check(last_observed_token>=0 and last_observed_token<=active_token),
    last_attempt_at timestamptz, last_completed_at timestamptz, last_successful_cutoff timestamptz,
    health_status text not null default 'unknown' check(health_status in ('unknown','healthy','partial','error')),
    health_reason text, loss_buckets jsonb not null default '{}'::jsonb
        check(jsonb_typeof(loss_buckets)='object' and octet_length(loss_buckets::text)<=1048576),
    primary key(scope_digest,pin),
    check((not history_started and state_document is null and watermark is null and state_revision=0 and coverage_epoch=0)
        or (history_started and state_document is not null))
);
create table public.semantic_password_window_members (
    scope_digest bytea not null, pin text not null, member_document jsonb not null,
    native_id bigint generated always as ((member_document#>>'{witness,ref,native_id}')::bigint) stored not null check(native_id>0),
    native_sha256 text generated always as (member_document#>>'{witness,ref,sha256}') stored not null,
    occurred_at_utc text generated always as (member_document#>>'{witness,at}') stored not null,
    xml_bytes integer generated always as ((member_document#>>'{witness,xml_bytes}')::integer) stored not null,
    xml_sha256 text generated always as (member_document#>>'{witness,xml_sha256}') stored not null,
    primary key(scope_digest,pin,native_id),
    foreign key(scope_digest,pin) references public.semantic_password_checkpoints(scope_digest,pin) on delete restrict
);
create sequence public.semantic_password_attempt_seq as bigint minvalue 1 no cycle;
revoke all on public.semantic_password_checkpoints,public.semantic_password_window_members
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
revoke all on sequence public.semantic_password_attempt_seq
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Only bounded typed password shapes call these private scalar/JSON helpers.
create function public.password_v2_json_compact(j jsonb,depth integer default 0)
returns text language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare result text;
begin
    if depth>16 then raise exception 'password_v2_state_bound' using errcode='54000'; end if;
    case jsonb_typeof(j)
    when 'object' then
        select '{'||coalesce(string_agg(public.file_audit_snapshot_quote_v264(key)||':'||
            public.password_v2_json_compact(value,depth+1),',' order by key collate "C"),'')||'}' into result
        from jsonb_each(j);
    when 'array' then
        select '['||coalesce(string_agg(public.password_v2_json_compact(value,depth+1),',' order by ordinal),'')||']'
        into result from jsonb_array_elements(j) with ordinality a(value,ordinal);
    when 'string' then
        if length(j#>>'{}')>512 then raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        result:=public.file_audit_snapshot_quote_v264(j#>>'{}');
    when 'number' then
        if j::text !~ '^-?(0|[1-9][0-9]*)$' or length(j::text)>20 then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        result:=j::text;
    when 'boolean','null' then result:=j::text;
    else raise exception 'password_v2_state_invalid' using errcode='22023';
    end case;
    return result;
end $$;
create function public.password_v2_check_witness(w jsonb,s jsonb)
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare r jsonb;
begin
    if not public.password_v2_keys(w,array['at','ref','xml_bytes','xml_sha256'])
       or not public.password_v2_keys(w->'ref',array['native_id','scope','sha256','storage_kind']) then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    r:=w->'ref';
    if r->'scope' is distinct from s or r->>'storage_kind' is distinct from 'core_event'
       or jsonb_typeof(r->'native_id') is distinct from 'string'
       or r->>'native_id' !~ '^[1-9][0-9]{0,18}$'
       or jsonb_typeof(r->'sha256') is distinct from 'string' or r->>'sha256' !~ '^[a-f0-9]{64}$'
       or jsonb_typeof(w->'xml_sha256') is distinct from 'string' or w->>'xml_sha256' !~ '^[a-f0-9]{64}$'
       or not public.password_v2_uint(w->'xml_bytes',4194304) or w->>'xml_bytes'='0' then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    if (r->>'native_id')::numeric>=9223372036854775808 then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    perform public.password_v2_time(w->'at');
end $$;
create function public.password_v2_check_state(st jsonb,s jsonb,p_pin text)
returns bigint language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare m jsonb; e jsonb; w jsonb; budget jsonb; k text; value jsonb;
    previous_at timestamptz; previous_id bigint; at_time timestamptz; nid bigint; bytes bigint;
begin
    if not public.password_v2_keys(st,array['epoch','episodes','pin','version','watermark','window'])
       or st->>'version' is distinct from 'sli.password.v2.state.1' or jsonb_typeof(st->'pin') is distinct from 'string'
       or st->>'pin' is distinct from p_pin or not public.password_v2_uint(st->'epoch',9223372036854775807)
       or jsonb_typeof(st->'window') is distinct from 'array' or jsonb_typeof(st->'episodes') is distinct from 'array' then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    if jsonb_array_length(st->'window')>10000 or jsonb_array_length(st->'episodes')>10000
       or octet_length(st::text)>4194304 then
        raise exception 'password_v2_state_bound' using errcode='54000'; end if;
    if jsonb_typeof(st->'watermark')='null' then
        if jsonb_array_length(st->'window')<>0 or jsonb_array_length(st->'episodes')<>0 then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    else perform public.password_v2_time(st->'watermark'); end if;
    for m in select a.value from jsonb_array_elements(st->'window') a(value) loop
        if not public.password_v2_keys(m,array['client_key','client_kind','failure','reason','target_key','witness']) then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        foreach k in array array['client_key','target_key'] loop
            value:=m->k;
            if (jsonb_typeof(value)='null' or (jsonb_typeof(value)='string' and value#>>'{}' ~ '^[a-f0-9]{64}$')) is not true then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        end loop;
        if (jsonb_typeof(m->'client_kind')='null' or (jsonb_typeof(m->'client_kind')='string' and m->>'client_kind' in ('ip','host'))) is not true
           or (jsonb_typeof(m->'failure')='null' or (jsonb_typeof(m->'failure')='string' and m->>'failure' in
               ('known_bad_password','unknown_account','other_failure'))) is not true
           or (jsonb_typeof(m->'reason')='null' or (jsonb_typeof(m->'reason')='string' and m->>'reason' in
               ('missing_target','unclassified_failure','ambiguous_failure','conflicting_client','missing_client','too_late'))) is not true then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        w:=m->'witness'; perform public.password_v2_check_witness(w,s);
        at_time:=public.password_v2_time(w->'at'); nid:=(w#>>'{ref,native_id}')::bigint;
        if previous_at is not null and (at_time,nid)<=(previous_at,previous_id) then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        previous_at:=at_time; previous_id:=nid;
    end loop;
    if (select count(distinct a.value#>>'{witness,ref,native_id}') from jsonb_array_elements(st->'window') a(value))
       <>jsonb_array_length(st->'window') then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    for e in select a.value from jsonb_array_elements(st->'episodes') a(value) loop
        if not public.password_v2_keys(e,array['budget','entity','frozen','key','last','last_emission','prequalification','root_id','seed','sequence'])
           or jsonb_typeof(e->'key') is distinct from 'string' or e->>'key' !~ '^[a-f0-9]{64}$'
           or jsonb_typeof(e->'entity') is distinct from 'string' or e->>'entity' !~ '^[a-f0-9]{64}$'
           or jsonb_typeof(e->'frozen') is distinct from 'boolean'
           or not public.password_v2_uint(e->'sequence',256)
           or jsonb_typeof(e->'prequalification') is distinct from 'array'
           or not public.password_v2_keys(e->'budget',array['portions','ref_occurrences','xml_bytes']) then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        if jsonb_array_length(e->'prequalification')>10000 then
            raise exception 'password_v2_state_bound' using errcode='54000'; end if;
        budget:=e->'budget';
        if not public.password_v2_uint(budget->'ref_occurrences',10000)
           or not public.password_v2_uint(budget->'portions',256)
           or not public.password_v2_uint(budget->'xml_bytes',33554432) then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        foreach k in array array['root_id','last_emission'] loop
            value:=e->k;
            if (jsonb_typeof(value)='null' or (jsonb_typeof(value)='string' and value#>>'{}' ~ '^[a-f0-9]{64}$')) is not true then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        end loop;
        if (e->'root_id'='null'::jsonb) is distinct from (e->'last_emission'='null'::jsonb)
           or ((e->>'sequence')::bigint=0) is distinct from (e->'root_id'='null'::jsonb) then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        perform public.password_v2_check_witness(e->'seed',s);
        perform public.password_v2_check_witness(e->'last',s);
        if public.password_v2_time(e#>'{last,at}')<public.password_v2_time(e#>'{seed,at}') then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        previous_at:=null; previous_id:=null;
        for w in select a.value from jsonb_array_elements(e->'prequalification') a(value) loop
            perform public.password_v2_check_witness(w,s);
            at_time:=public.password_v2_time(w->'at'); nid:=(w#>>'{ref,native_id}')::bigint;
            if previous_at is not null and (at_time,nid)<=(previous_at,previous_id) then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
            previous_at:=at_time; previous_id:=nid;
        end loop;
    end loop;
    if (select count(distinct a.value->>'entity') from jsonb_array_elements(st->'episodes') a(value))<>jsonb_array_length(st->'episodes')
       or (select count(distinct a.value->>'key') from jsonb_array_elements(st->'episodes') a(value))<>jsonb_array_length(st->'episodes') then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    if exists(with witnesses as (
        select a.value->'witness' as w from jsonb_array_elements(st->'window') a(value)
        union all select a.value->'seed' from jsonb_array_elements(st->'episodes') a(value)
        union all select a.value->'last' from jsonb_array_elements(st->'episodes') a(value)
        union all select p.value from jsonb_array_elements(st->'episodes') a(value)
            cross join lateral jsonb_array_elements(a.value->'prequalification') p(value)
    ) select 1 from witnesses all_w group by all_w.w#>>'{ref,native_id}' having count(distinct all_w.w)>1) then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    bytes:=public.password_v2_json_bytes(st);
    if bytes>4194304 then raise exception 'password_v2_state_bound' using errcode='54000'; end if;
    return bytes;
end $$;
create function public.password_v2_json_bytes(j jsonb,depth integer default 0)
returns bigint language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare total bigint; n bigint;
begin
    if depth>16 then raise exception 'password_v2_state_bound' using errcode='54000'; end if;
    case jsonb_typeof(j)
    when 'object' then
        select count(*),coalesce(sum(octet_length(public.file_audit_snapshot_quote_v264(key))+2+
            public.password_v2_json_bytes(value,depth+1)),0) into n,total from jsonb_each(j);
        return 2+total+greatest(n-1,0)*2;
    when 'array' then
        select count(*),coalesce(sum(public.password_v2_json_bytes(value,depth+1)),0) into n,total
        from jsonb_array_elements(j);
        return 2+total+greatest(n-1,0)*2;
    else return octet_length(public.password_v2_json_compact(j,depth));
    end case;
end $$;
create function public.password_v2_keys(j jsonb,expected text[])
returns boolean language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare actual text[];
begin
    if j is null or jsonb_typeof(j)<>'object' then return false; end if;
    select array_agg(key order by key) into actual from jsonb_object_keys(j) key;
    return actual is not distinct from (select array_agg(k order by k) from unnest(expected) k);
end $$;
create function public.password_v2_uint(j jsonb,maximum bigint)
returns boolean language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
begin
    if jsonb_typeof(j) is distinct from 'number' or j::text !~ '^(0|[1-9][0-9]*)$' or length(j::text)>19 then return false; end if;
    return j::numeric<=maximum;
end $$;
create function public.password_v2_iso(t timestamptz)
returns text language sql stable set search_path=pg_catalog,pg_temp as $$
    select to_char(t at time zone 'UTC','YYYY-MM-DD"T"HH24:MI:SS')||
        case when extract(microseconds from t)::bigint%1000000=0 then ''
             else '.'||to_char(t at time zone 'UTC','US') end||'+00:00'
$$;
create function public.password_v2_time(j jsonb)
returns timestamptz language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare t timestamptz;
begin
    if jsonb_typeof(j) is distinct from 'string' or length(j#>>'{}')>32
       or j#>>'{}' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{6})?\+00:00$' then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    begin t:=(j#>>'{}')::timestamptz;
    exception when invalid_datetime_format or datetime_field_overflow then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end;
    if public.password_v2_iso(t)<>j#>>'{}' then
        raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
    return t;
end $$;
create function public.password_v2_identity(s jsonb,x jsonb)
returns jsonb language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare definition jsonb; rule text; threshold integer;
begin
    perform public.password_v2_source_binding(s);
    if not public.password_v2_keys(x,array['kind','rule_id','rule_sha256','rule_version','scope','version'])
       or x->>'version' is distinct from 'sli.qw.execution.v1' or x->>'kind' is distinct from 'threshold'
       or jsonb_typeof(x->'rule_version') is distinct from 'number' or x->>'rule_version' is distinct from '2'
       or x->'scope' is distinct from s or jsonb_typeof(x->'rule_id') is distinct from 'string'
       or coalesce(x->>'rule_id','') not in ('qw.password-brute-force','qw.password-spray') then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    rule:=x->>'rule_id'; threshold:=case when rule='qw.password-brute-force' then 10 else 5 end;
    definition:=jsonb_build_object('contract','sli.password.v2.phase-a.1','rule',rule,'window',600,'inclusive',true,
        'threshold',threshold,'holdback',120,'horizon',720,'rows',10000,'lifetime_refs',10000,'lifetime_portions',256,
        'lifetime_xml_bytes',33554432,'classification','bad-unknown-other/native-v1',
        'client','native-ip-mapped-or-explicit-workstation/v1','late','drop-finalized/v1',
        'gap','new-epoch/v1','continuity','native-adjacency/v1');
    if jsonb_typeof(x->'rule_sha256') is distinct from 'string'
       or x->>'rule_sha256'<>encode(sha256(convert_to(public.password_v2_json_compact(definition),'UTF8')),'hex') then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    return jsonb_build_object('scope_digest',encode(sha256(convert_to(public.password_v2_json_compact(s),'UTF8')),'hex'),
        'pin',encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex'));
end $$;

create function public.password_v2_assert_checkpoint(c public.semantic_password_checkpoints)
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare projected jsonb; expected_time timestamptz;
begin
    if c.state_document is null then
        if c.history_started or c.state_revision<>0 or c.watermark is not null or c.coverage_epoch<>0
           or exists(select 1 from public.semantic_password_window_members m where m.scope_digest=c.scope_digest and m.pin=c.pin) then
            raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
        return;
    end if;
    perform public.password_v2_check_state(c.state_document,c.scope_json,c.pin);
    if jsonb_typeof(c.state_document->'watermark')<>'null' then
        expected_time:=public.password_v2_time(c.state_document->'watermark'); end if;
    select coalesce(jsonb_agg(m.member_document order by m.occurred_at_utc,m.native_id),'[]'::jsonb)
    into projected from public.semantic_password_window_members m where m.scope_digest=c.scope_digest and m.pin=c.pin;
    if not c.history_started or c.state_revision<=0 or c.watermark is distinct from expected_time
       or c.coverage_epoch is distinct from (c.state_document->>'epoch')::bigint
       or projected is distinct from c.state_document->'window' then
        raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
end $$;
create function public.password_v2_locked_checkpoint(s jsonb,x jsonb,create_missing boolean)
returns public.semantic_password_checkpoints
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; c public.semantic_password_checkpoints%rowtype; digest bytea; pin_value text; owner_context jsonb;
begin
    identity:=public.password_v2_identity(s,x); digest:=decode(identity->>'scope_digest','hex'); pin_value:=identity->>'pin';
    -- Exact existing default_detections source lock, independent of login/rule.
    perform pg_advisory_xact_lock(hashtextextended(identity->>'scope_digest',0));
    if create_missing then
        owner_context:=public.password_v2_configured_identity((public.password_v2_source_binding(s)).agent_id);
        insert into public.semantic_password_checkpoints(scope_digest,pin,scope_json,execution_json,owner_domain_id)
        values(digest,pin_value,s,x,case when owner_context->'scope'=s then (owner_context->>'domain_id')::bigint end)
        on conflict(scope_digest,pin) do nothing;
    end if;
    select q.* into c from public.semantic_password_checkpoints q
    where q.scope_digest=digest and q.pin=pin_value for update;
    if not found then return null; end if;
    if c.scope_json is distinct from s or c.execution_json is distinct from x then
        raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
    perform public.password_v2_assert_checkpoint(c);
    return c;
end $$;
create function public.password_v2_diagnostic(code text)
returns boolean language sql immutable set search_path=pg_catalog,pg_temp as $$
    select code=any(array['source_error','password_v2_native_unavailable','password_v2_window_truncated',
        'password_v2_xml_budget_exceeded','xml_invalid','state_bound','clock_regression','too_late','coverage_gap',
        'gap_native_unavailable','prequalification_native_unavailable','episode_evidence_budget_exhausted',
        'prequalification_proof_budget_exhausted','missing_target','unclassified_failure','ambiguous_failure','conflicting_client','missing_client'])
$$;
create function public.password_v2_health(c public.semantic_password_checkpoints,as_of timestamptz)
returns jsonb language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare code text; slots jsonb; bucket jsonb; cutoff timestamptz:=as_of-interval '24 hours';
    minimum timestamptz; maximum timestamptz; loss_from timestamptz; loss_to timestamptz;
    enclosure_from timestamptz; enclosure_to timestamptz; observed_from timestamptz;
    total numeric; exact boolean; result jsonb:='{}'::jsonb; status text:=c.health_status; reason text:=c.health_reason;
begin
    for code,slots in select key,value from jsonb_each(c.loss_buckets) loop
        if public.password_v2_diagnostic(code) is not true or jsonb_typeof(slots)<>'array' then
            raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
        if jsonb_array_length(slots)<>25 then raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
        total:=0; exact:=true; enclosure_from:=null; enclosure_to:=null; observed_from:=null;
        for bucket in select value from jsonb_array_elements(slots) loop
            if bucket='null'::jsonb then continue; end if;
            if not public.password_v2_keys(bucket,array['count','from','hour','observed_max','observed_min','to'])
               or not public.password_v2_uint(bucket->'count',9223372036854775807) or bucket->>'count'='0'
               or not public.password_v2_uint(bucket->'hour',9223372036854775807) then
                raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
            minimum:=public.password_v2_time(bucket->'observed_min'); maximum:=public.password_v2_time(bucket->'observed_max');
            if minimum>maximum or maximum>as_of then raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
            if maximum<cutoff then continue; end if;
            if minimum>=cutoff then total:=total+(bucket->>'count')::numeric;
            else total:=total+1; exact:=false; end if;
            observed_from:=least(observed_from,greatest(minimum,cutoff));
            loss_from:=null; loss_to:=null;
            if jsonb_typeof(bucket->'from')<>'null' then loss_from:=public.password_v2_time(bucket->'from'); end if;
            if jsonb_typeof(bucket->'to')<>'null' then loss_to:=public.password_v2_time(bucket->'to'); end if;
            enclosure_from:=least(enclosure_from,loss_from); enclosure_to:=greatest(enclosure_to,loss_to);
        end loop;
        if total>0 then result:=result||jsonb_build_object(code,jsonb_build_object('count_lower_bound',total,'count_exact',exact,
            'from',public.password_v2_iso(enclosure_from),'to',public.password_v2_iso(enclosure_to),
            'observation_window_from',public.password_v2_iso(observed_from),'as_of',public.password_v2_iso(as_of))); end if;
    end loop;
    if status='healthy' and (c.last_completed_at is null or c.last_completed_at>as_of) then
        status:='unknown'; reason:='clock_regression';
    elsif status='healthy' and as_of>=c.last_completed_at+interval '300 seconds' then
        status:='stale'; reason:='attempt_stale';
    elsif status='healthy' and result<>'{}'::jsonb then status:='partial'; reason:='recent_loss'; end if;
    return jsonb_build_object('status',status,'reason',reason,'last_attempt_at',public.password_v2_iso(c.last_attempt_at),
        'last_completed_at',public.password_v2_iso(c.last_completed_at),
        'last_successful_cutoff',public.password_v2_iso(c.last_successful_cutoff),'loss',result,'as_of',public.password_v2_iso(as_of));
end $$;
create function public.begin_password_attempt(s jsonb,execution jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; token bigint; stamp timestamptz;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,true);
    stamp:=clock_timestamp();
    token:=nextval('public.semantic_password_attempt_seq'::regclass);
    update public.semantic_password_checkpoints set active_token=token,last_attempt_at=stamp
    where scope_digest=c.scope_digest and pin=c.pin;
    return jsonb_build_object('token',token,'attempted_at',public.password_v2_iso(stamp),'state_revision',c.state_revision);
end $$;
create function public.read_password_checkpoint_v2(s jsonb,execution jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null then raise exception 'password_v2_checkpoint_absent' using errcode='55000'; end if;
    return jsonb_build_object('state_revision',c.state_revision,'state_document',c.state_document,
        'watermark',public.password_v2_iso(c.watermark),'epoch',c.coverage_epoch,'active_token',c.active_token,
        'last_observed_token',c.last_observed_token,'health',public.password_v2_health(c,clock_timestamp()));
end $$;
create function public.commit_password_state_v2(s jsonb,execution jsonb,token bigint,expected_revision bigint,next_state jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or token is null or token<>c.active_token or token<=c.last_observed_token then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    if expected_revision is distinct from c.state_revision then
        raise exception 'password_v2_state_conflict' using errcode='55000'; end if;
    perform public.password_v2_check_state(next_state,s,c.pin);
    if (next_state->>'epoch')::numeric<c.coverage_epoch or (next_state->>'epoch')::numeric>c.coverage_epoch+1
       or (c.watermark is not null and (jsonb_typeof(next_state->'watermark')='null'
           or public.password_v2_time(next_state->'watermark')<c.watermark)) then
        raise exception 'password_v2_state_conflict' using errcode='55000'; end if;
    -- Deliberately NO successful UPDATE path in this slice. Typed data alone
    -- cannot prove lifetime reservations/native semantics/cross-epoch barriers.
    raise exception 'password_v2_state_authority_unavailable' using errcode='55000';
end $$;
create function public.observe_password_failure_v2(s jsonb,execution jsonb,token bigint,diagnostics jsonb)
returns boolean language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; code text; item jsonb; bucket jsonb; slots jsonb;
    all_buckets jsonb; stamp timestamptz; hour_id bigint; slot integer; amount bigint;
    source_from timestamptz; source_to timestamptz; minimum timestamptz; maximum timestamptz;
    reason text; status text:='partial';
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or token is null or token<>c.active_token or token<=c.last_observed_token then return false; end if;
    stamp:=clock_timestamp();
    if diagnostics is null or jsonb_typeof(diagnostics)<>'object' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    if diagnostics='{}'::jsonb then raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    all_buckets:=c.loss_buckets; hour_id:=floor(extract(epoch from stamp)/3600)::bigint; slot:=(hour_id%25)::integer;
    if c.last_completed_at>stamp then raise exception 'password_v2_clock_regression' using errcode='55000'; end if;
    -- Validate existing bounded metadata before applying any overwrite.
    perform public.password_v2_health(c,stamp);
    for code,item in select key,value from jsonb_each(diagnostics) order by key loop
        if public.password_v2_diagnostic(code) is not true or not public.password_v2_keys(item,array['count','from','to'])
           or not public.password_v2_uint(item->'count',9223372036854775807) or item->>'count'='0' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        amount:=(item->>'count')::bigint; source_from:=null; source_to:=null;
        if jsonb_typeof(item->'from')<>'null' then source_from:=public.password_v2_time(item->'from'); end if;
        if jsonb_typeof(item->'to')<>'null' then source_to:=public.password_v2_time(item->'to'); end if;
        if (source_from is null)<>(source_to is null) or source_from>source_to then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        slots:=coalesce(all_buckets->code,to_jsonb(array_fill(null::jsonb,array[25])));
        bucket:=slots->slot;
        if bucket='null'::jsonb or (bucket->>'hour')::bigint<>hour_id then
            bucket:=jsonb_build_object('hour',hour_id,'count',amount,'observed_min',public.password_v2_iso(stamp),
                'observed_max',public.password_v2_iso(stamp),'from',public.password_v2_iso(source_from),'to',public.password_v2_iso(source_to));
        else
            if (bucket->>'count')::numeric+amount>9223372036854775807 then
                raise exception 'password_v2_health_counter_overflow' using errcode='22003'; end if;
            minimum:=public.password_v2_time(bucket->'observed_min'); maximum:=public.password_v2_time(bucket->'observed_max');
            if jsonb_typeof(bucket->'from')<>'null' then source_from:=least(source_from,public.password_v2_time(bucket->'from')); end if;
            if jsonb_typeof(bucket->'to')<>'null' then source_to:=greatest(source_to,public.password_v2_time(bucket->'to')); end if;
            bucket:=jsonb_build_object('hour',hour_id,'count',(bucket->>'count')::bigint+amount,
                'observed_min',public.password_v2_iso(least(minimum,stamp)),
                'observed_max',public.password_v2_iso(greatest(maximum,stamp)),
                'from',public.password_v2_iso(source_from),'to',public.password_v2_iso(source_to));
        end if;
        slots:=jsonb_set(slots,array[slot::text],bucket,false); all_buckets:=jsonb_set(all_buckets,array[code],slots,true);
        reason:=coalesce(reason,code);
        if code in ('source_error','password_v2_native_unavailable','xml_invalid','clock_regression') then status:='error'; reason:=code; end if;
    end loop;
    update public.semantic_password_checkpoints set last_observed_token=token,last_completed_at=stamp,
        health_status=status,health_reason=reason,loss_buckets=all_buckets where scope_digest=c.scope_digest and pin=c.pin;
    return true;
end $$;

-- B1 lifetime storage: trusted Python semantics, SQL commitments and atomicity.
create table public.semantic_password_episode_budgets (
    scope_digest bytea not null check(octet_length(scope_digest)=32), pin text not null check(pin ~ '^[a-f0-9]{64}$'),
    episode_key text not null check(episode_key ~ '^[a-f0-9]{64}$'), scope_json jsonb not null, execution_json jsonb not null,
    coverage_epoch bigint not null check(coverage_epoch>=0), entity text not null check(entity ~ '^[a-f0-9]{64}$'),
    seed jsonb not null, root_id text not null check(root_id ~ '^[a-f0-9]{64}$'),
    last_sequence integer not null check(last_sequence between 0 and 256),
    last_emission_id text check(last_emission_id ~ '^[a-f0-9]{64}$'), last_admitted_endpoint jsonb,
    reserved_ref_occurrences bigint not null check(reserved_ref_occurrences between 0 and 10000),
    reserved_portions integer not null check(reserved_portions between 0 and 256),
    reserved_xml_bytes bigint not null check(reserved_xml_bytes between 0 and 33554432),
    last_admitted_as_of timestamptz, admitted_revision bigint not null check(admitted_revision>=0),
    first_ledger_revision bigint not null check(first_ledger_revision>0),
    admitted_attempt_token bigint not null check(admitted_attempt_token>0), admission_xid xid8 not null,
    admission_first_sequence integer not null check(admission_first_sequence between 1 and 256),
    check(last_sequence=0 or admission_first_sequence<=last_sequence),
    check((last_sequence=0 and admitted_revision=0) or (last_sequence>0 and admitted_revision>=first_ledger_revision)),
    frozen boolean not null default false, frozen_at timestamptz, frozen_reason text,
    barrier_unresolved boolean not null default false,
    tracking_endpoint jsonb, tracking_epoch bigint, tracking_through timestamptz,
    successor_episode_key text check(successor_episode_key ~ '^[a-f0-9]{64}$'),
    successor_seed jsonb, successor_epoch bigint,
    predecessor_episode_key text check(predecessor_episode_key ~ '^[a-f0-9]{64}$'),
    primary key(scope_digest,pin,episode_key),
    foreign key(scope_digest,pin) references public.semantic_password_checkpoints(scope_digest,pin) on delete restrict,
    check((not frozen and frozen_at is null and frozen_reason is null and not barrier_unresolved)
        or (frozen and frozen_at is not null and frozen_reason='episode_evidence_budget_exhausted')),
    check(last_sequence>0 or (frozen and reserved_ref_occurrences=0 and reserved_portions=0 and reserved_xml_bytes=0)),
    check((successor_episode_key is null and successor_seed is null and successor_epoch is null)
        or (frozen and successor_episode_key is not null and successor_seed is not null and successor_epoch>=0))
);
create unique index password_v2_frozen_entity on public.semantic_password_episode_budgets(scope_digest,pin,entity)
    where barrier_unresolved;
revoke all on public.semantic_password_episode_budgets from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create function public.password_v2_managed(d jsonb) returns boolean
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select coalesce(d ? 'password_context' or (d->>'rule_id' in ('qw.password-brute-force','qw.password-spray')
        and d->>'rule_version'='2'),false)
$$;
create function public.password_v2_scope_key(s jsonb) returns bytea
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select sha256(convert_to(public.password_v2_json_compact(s),'UTF8'))
$$;
create function public.password_v2_entity_key(scope_digest bytea,p_pin text,p_entity text) returns bigint
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select hashtextextended('sli.password.v2.entity.1:'||encode(scope_digest,'hex')||':'||p_pin||':'||p_entity,0)
$$;
-- Future B2 preacquires ALL entity keys in stable order before any ledger rows.
create function public.lock_password_reservation_entities_v2(s jsonb,execution jsonb,attempt_token bigint,
    expected_checkpoint_revision bigint,entity_keys text[]) returns void
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; entity_key text; lock_key bigint;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or attempt_token is distinct from c.active_token or attempt_token<=c.last_observed_token
       or expected_checkpoint_revision is distinct from c.state_revision then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    if entity_keys is null or cardinality(entity_keys)>10000
       or (cardinality(entity_keys)>0 and array_ndims(entity_keys)<>1) then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    foreach entity_key in array entity_keys loop
        if entity_key is null or entity_key !~ '^[a-f0-9]{64}$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    end loop;
    for lock_key in select distinct public.password_v2_entity_key(c.scope_digest,c.pin,k)
        from unnest(entity_keys) k order by 1 loop
        perform pg_advisory_xact_lock(lock_key);
    end loop;
end $$;
alter table public.semantic_qw_signals add column password_scope_digest bytea
    check(password_scope_digest is null or octet_length(password_scope_digest)=32);
create function public.password_v2_qw_index_key() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if public.password_v2_managed(new.document_json) then
        perform public.password_v2_source_binding(new.document_json#>'{evidence_refs,0,scope}');
        new.password_scope_digest:=public.password_v2_scope_key(new.document_json#>'{evidence_refs,0,scope}');
    else
        new.password_scope_digest:=null;
    end if;
    return new;
end $$;
revoke all on function public.password_v2_qw_index_key() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create trigger password_v2_qw_index_key before insert on public.semantic_qw_signals
    for each row execute function public.password_v2_qw_index_key();
create unique index password_v2_immutable_portion on public.semantic_qw_signals(
    password_scope_digest,(document_json#>>'{password_context,pin}'),(document_json#>>'{password_context,episode_key}'),
    ((document_json#>>'{password_context,sequence}')::bigint),
    ((document_json#>>'{password_context,portion_index}')::bigint)) where password_scope_digest is not null;
create function public.password_v2_tuple(s jsonb,t jsonb) returns jsonb
language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare w jsonb;
begin
    if jsonb_typeof(t) is distinct from 'array' or jsonb_array_length(t)<>5 then
        raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
    w:=jsonb_build_object('ref',jsonb_build_object('storage_kind','core_event','native_id',t->0,'sha256',t->1,'scope',s),
        'at',t->2,'xml_bytes',t->3,'xml_sha256',t->4);
    perform public.password_v2_check_witness(w,s); return w;
end $$;
create function public.password_v2_episode_key(p_pin text,epoch bigint,entity text,seed jsonb) returns text
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select encode(sha256(convert_to(public.password_v2_json_compact(jsonb_build_array(p_pin,epoch,entity,
        jsonb_build_array(seed#>'{ref,scope,installation_id}',seed#>'{ref,scope,plugin_id}',
            seed#>'{ref,scope,source_instance_id}',seed#>'{ref,scope,source_generation}',
            seed#>'{ref,scope,collection_scope_id}',seed#>'{ref,storage_kind}',seed#>'{ref,native_id}',seed#>'{ref,sha256}'))),'UTF8')),'hex')
$$;

-- Typed transport/hash reconstruction only. This never classifies native XML.
create function public.password_v2_decode(s jsonb,x jsonb,documents jsonb) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; d jsonb; ctx jsonb; common jsonb; header jsonb; w jsonb; seed jsonb;
    occurrence jsonb; occurrences jsonb; witness_array jsonb[]:=array[]::jsonb[]; refs jsonb; actual_refs jsonb; doc_keys text[];
    emission jsonb; origin jsonb; proof jsonb; new_events jsonb; ids jsonb:='[]'; costs bigint:=0;
    n integer:=0; total integer; portions integer; seq integer; origin_n integer; root_n integer; k text;
    previous_at timestamptz; previous_id bigint; t timestamptz; nid bigint; expected_id text;
begin
    identity:=public.password_v2_identity(s,x);
    if jsonb_typeof(documents) is distinct from 'array' or jsonb_array_length(documents) not between 1 and 256
       or octet_length(documents::text)>134217728 then
        raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
    for d in select a.value from jsonb_array_elements(documents) a(value) loop
        if jsonb_typeof(d) is distinct from 'object' then raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        select array_agg(key order by key) into doc_keys from jsonb_object_keys(d-'evidence_total'-'processing_mode') key;
        if doc_keys is distinct from (select array_agg(key order by key) from unnest(array[
            'kind','rule_id','rule_version','rule_sha256','policy_revision','evaluation_mode','entity_key','episode_key',
            'occurred_at_utc','received_at_utc','evidence_refs','base_severity','effective_severity','severity_reasons',
            'quality','conclusion_state','password_context']) key)
           or d->>'kind' is distinct from 'threshold' or d->>'rule_id' is distinct from x->>'rule_id'
           or d->'rule_version' is distinct from '2'::jsonb or d->'rule_sha256' is distinct from x->'rule_sha256'
           or not public.password_v2_uint(d->'policy_revision',2147483647) or d->>'policy_revision'='0'
           or jsonb_typeof(d->'evaluation_mode') is distinct from 'string' or d->>'evaluation_mode' not in ('test','shadow','enabled')
           or d->>'conclusion_state' is distinct from 'observed'
           or d->>'base_severity' not in ('info','low','medium','high','critical')
           or d->>'effective_severity' not in ('info','low','medium','high','critical')
           or array_position(array['info','low','medium','high','critical'],d->>'effective_severity')
                <array_position(array['info','low','medium','high','critical'],d->>'base_severity')
           or d->>'quality' not in ('good','degraded','unknown')
           or jsonb_typeof(d->'severity_reasons') is distinct from 'array'
           or jsonb_typeof(d->'evidence_refs') is distinct from 'array' then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        if jsonb_array_length(d->'severity_reasons')>16 or exists(select 1 from jsonb_array_elements(d->'severity_reasons') a
            where jsonb_typeof(a.value)<>'string' or a.value#>>'{}' !~ '^[a-z][a-z0-9_.-]{0,79}$')
           or (d ? 'processing_mode' and (jsonb_typeof(d->'processing_mode') is distinct from 'string'
                or d->>'processing_mode' not in ('historical_replay','history_import')))
           or octet_length(d::text)>524288 or octet_length(public.password_v2_json_compact(d))>524288 then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        perform public.password_v2_time(d->'received_at_utc'); perform public.password_v2_time(d->'occurred_at_utc');
        ctx:=d->'password_context';
        if not public.password_v2_keys(ctx,array['version','episode_key','pin','epoch','entity','sequence','emission_id',
            'root_id','previous_id','seed','endpoint_ordinal','origin_count','root_from','root_count','new_from','new_count',
            'occurrence_total','portion_total','known_bad_password','unknown_account','other_failure','distinct_names',
            'portion_index','occurrence_from','occurrences'])
           or ctx->>'version' is distinct from 'sli.password.v2.portion.1'
           or ctx->>'pin' is distinct from identity->>'pin' then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        foreach k in array array['base_severity','effective_severity','quality','entity_key','episode_key','rule_sha256'] loop
            if jsonb_typeof(d->k) is distinct from 'string' then
                raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        end loop;
        foreach k in array array['episode_key','pin','entity','emission_id','root_id'] loop
            if jsonb_typeof(ctx->k) is distinct from 'string' or ctx->>k !~ '^[a-f0-9]{64}$' then
                raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        end loop;
        if not public.password_v2_uint(ctx->'epoch',9223372036854775807)
           or not public.password_v2_uint(ctx->'sequence',257) or ctx->>'sequence'='0' then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        foreach k in array array['endpoint_ordinal','origin_count','root_from','root_count','new_from','new_count',
            'occurrence_total','portion_total','known_bad_password','unknown_account','other_failure','distinct_names',
            'portion_index','occurrence_from'] loop
            if not public.password_v2_uint(ctx->k,10000) then
                raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        end loop;
        total:=(ctx->>'occurrence_total')::integer; portions:=(ctx->>'portion_total')::integer;
        if total<1 or portions<>(total+255)/256 or portions<>jsonb_array_length(documents)
           or (ctx->>'portion_index')::integer<>n or (ctx->>'occurrence_from')::integer<>256*n
           or (ctx->>'endpoint_ordinal')::integer<>total-1
           or jsonb_typeof(ctx->'occurrences') is distinct from 'array' then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        if jsonb_array_length(ctx->'occurrences')<>least(256,total-256*n)
           or octet_length(public.password_v2_json_compact(ctx))>65536 then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        common:=ctx-'portion_index'-'occurrence_from'-'occurrences';
        if n=0 then header:=common; seed:=public.password_v2_tuple(s,ctx->'seed');
        elsif common is distinct from header or (d-'password_context'-'evidence_refs'-'received_at_utc')
                is distinct from ((documents->0)-'password_context'-'evidence_refs'-'received_at_utc') then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        refs:='[]';
        for occurrence in select a.value from jsonb_array_elements(ctx->'occurrences') a(value) loop
            w:=public.password_v2_tuple(s,occurrence); t:=public.password_v2_time(w->'at'); nid:=(w#>>'{ref,native_id}')::bigint;
            if previous_at is not null and (t,nid)<=(previous_at,previous_id) then
                raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
            previous_at:=t; previous_id:=nid; witness_array:=array_append(witness_array,w);
            refs:=refs||jsonb_build_array(w->'ref'); costs:=costs+(w->>'xml_bytes')::bigint;
        end loop;
        select jsonb_agg(a.value order by a.value->>'native_id' collate "C",a.value->>'sha256' collate "C") into actual_refs
            from jsonb_array_elements(refs) a(value);
        if d->'evidence_refs' is distinct from actual_refs or d->>'entity_key' is distinct from ctx->>'entity'
           or d->>'episode_key' is distinct from ctx->>'episode_key'
           or (d ? 'evidence_total' and (not public.password_v2_uint(d->'evidence_total',10000)
                or (d->>'evidence_total')::integer<jsonb_array_length(refs))) then
            raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
        expected_id:=encode(sha256(convert_to(public.password_v2_json_compact(d-'received_at_utc'),'UTF8')),'hex');
        ids:=ids||jsonb_build_array(expected_id); n:=n+1;
    end loop;
    occurrences:=to_jsonb(witness_array);
    if jsonb_array_length(occurrences)<>total
       or (select count(distinct a.value#>>'{ref,native_id}') from jsonb_array_elements(occurrences) a(value))<>total
       or documents#>>'{0,occurred_at_utc}' is distinct from occurrences#>>array[(total-1)::text,'at'] then
        raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
    seq:=(header->>'sequence')::integer; origin_n:=(header->>'origin_count')::integer; root_n:=(header->>'root_count')::integer;
    if (seq=1 and (header->'previous_id'<>'null'::jsonb or header->>'root_id'<>header->>'emission_id'
            or not (root_n>=1 and root_n<=origin_n and origin_n<=total)
            or (header->>'root_from')::integer+root_n<>origin_n
            or (header->>'new_from')::integer<>origin_n or (header->>'new_count')::integer<>total-origin_n
            or seed is distinct from occurrences->0))
       or (seq>1 and (jsonb_typeof(header->'previous_id') is distinct from 'string'
            or header->>'previous_id' !~ '^[a-f0-9]{64}$' or origin_n<>0 or root_n<>0
            or header->>'root_from'<>'0' or header->>'new_from'<>'1'
            or (header->>'new_count')::integer<>total-1 or total<2))
       or header->>'episode_key'<>public.password_v2_episode_key(identity->>'pin',(header->>'epoch')::bigint,header->>'entity',seed) then
        raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
    if (header->>'known_bad_password')::integer+(header->>'unknown_account')::integer+(header->>'other_failure')::integer
        <>(case when seq=1 then root_n else total-1 end)
       or (header->>'distinct_names')::integer not between 1 and (case when seq=1 then root_n else total-1 end) then
        raise exception 'password_v2_portion_invalid' using errcode='22023'; end if;
    select coalesce(jsonb_agg(a.value order by a.ord),'[]') into origin
        from jsonb_array_elements(occurrences) with ordinality a(value,ord) where a.ord<=origin_n;
    select coalesce(jsonb_agg(a.value order by a.ord),'[]') into proof
        from jsonb_array_elements(occurrences) with ordinality a(value,ord)
        where a.ord>(header->>'root_from')::integer and a.ord<=origin_n;
    select coalesce(jsonb_agg(a.value order by a.ord),'[]') into new_events
        from jsonb_array_elements(occurrences) with ordinality a(value,ord) where a.ord>(header->>'new_from')::integer;
    emission:=jsonb_build_object('episode_key',header->'episode_key','pin',header->'pin','epoch',header->'epoch',
        'entity',header->'entity','sequence',header->'sequence','seed',seed,'root_proof',proof,'new_events',new_events,
        'predecessor',case when seq>1 then occurrences->0 else 'null'::jsonb end,'previous_id',header->'previous_id',
        'known_bad_password',header->'known_bad_password','unknown_account',header->'unknown_account',
        'other_failure',header->'other_failure','distinct_names',header->'distinct_names','origin',origin);
    expected_id:=encode(sha256(convert_to(public.password_v2_json_compact(emission),'UTF8')),'hex');
    if expected_id<>header->>'emission_id' then raise exception 'password_v2_emission_hash_conflict' using errcode='22023'; end if;
    return jsonb_build_object('emission',emission,'emission_id',expected_id,'root_id',header->'root_id',
        'occurrences',occurrences,'endpoint',occurrences->(total-1),'signal_ids',ids,
        'delta',jsonb_build_object('ref_occurrences',total,'portions',portions,'xml_bytes',costs));
end $$;
create function public.password_v2_native_cost(s jsonb,occurrences jsonb) returns bigint
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare b public.finding_evidence_source_bindings%rowtype; w jsonb; e record; native jsonb; xml text;
    bytes bigint; total bigint:=0; declared_total bigint:=0;
begin
    b:=public.password_v2_source_binding(s);
    if jsonb_typeof(occurrences) is distinct from 'array' or jsonb_array_length(occurrences)>10000 then
        raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
    -- Declared bytes only reject oversized input; actual native costs remain authoritative.
    for w in select a.value from jsonb_array_elements(occurrences) a(value) loop
        perform public.password_v2_check_witness(w,s);
        declared_total:=declared_total+(w->>'xml_bytes')::bigint;
    end loop;
    if declared_total>33554432 then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
    for w in select a.value from jsonb_array_elements(occurrences) a(value) loop
        perform public.password_v2_check_witness(w,s);
        select core.* into e from public.events_v2_core core where core.id=(w#>>'{ref,native_id}')::bigint
            and core.log_source_id=b.log_source_id and core.event_id in (4625,4771,4776);
        if not found or encode(e.normalized_hash,'hex') is distinct from w#>>'{ref,sha256}'
           or e.time_created_utc is distinct from public.password_v2_time(w->'at')
           or public.resolve_finding_evidence_ref(b.installation_id,b.plugin_id,b.source_instance_id,b.source_generation,
                '','core_event',w#>>'{ref,native_id}',w#>>'{ref,sha256}') is not true then
            raise exception 'password_v2_retained_unavailable' using errcode='42501'; end if;
        native:=public.read_agent_semantic_source_v190(e.id);
        if jsonb_typeof(native#>'{event_row,xml}') is distinct from 'string' then
            raise exception 'password_v2_retained_unavailable' using errcode='42501'; end if;
        xml:=native#>>'{event_row,xml}'; bytes:=octet_length(convert_to(xml,'UTF8'));
        if bytes>4194304 or total+bytes>33554432 then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
        if bytes<>(w->>'xml_bytes')::bigint
           or encode(sha256(convert_to(xml,'UTF8')),'hex') is distinct from w->>'xml_sha256' then
            raise exception 'password_v2_retained_unavailable' using errcode='42501'; end if;
        total:=total+bytes;
    end loop;
    -- Only a scalar cost crosses this boundary, never XML beyond the32MiB cap.
    return total;
end $$;
create function public.password_v2_totals(l public.semantic_password_episode_budgets) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('ref_occurrences',l.reserved_ref_occurrences,'portions',l.reserved_portions,'xml_bytes',l.reserved_xml_bytes)
$$;
create function public.password_v2_ledger_immutable() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    if tg_op in ('DELETE','TRUNCATE') then raise exception 'password_v2_lifetime_immutable' using errcode='55000'; end if;
    if (new.scope_digest,new.pin,new.episode_key,new.scope_json,new.execution_json,new.coverage_epoch,new.entity,new.seed,new.root_id,
        new.predecessor_episode_key,new.first_ledger_revision) is distinct from
       (old.scope_digest,old.pin,old.episode_key,old.scope_json,old.execution_json,old.coverage_epoch,old.entity,old.seed,old.root_id,
        old.predecessor_episode_key,old.first_ledger_revision)
       or new.admitted_revision<old.admitted_revision or new.last_sequence<old.last_sequence or new.reserved_ref_occurrences<old.reserved_ref_occurrences
       or new.reserved_portions<old.reserved_portions or new.reserved_xml_bytes<old.reserved_xml_bytes
       or (old.frozen and not new.frozen) or (old.frozen and (new.last_sequence,new.last_emission_id,new.last_admitted_endpoint,
            new.reserved_ref_occurrences,new.reserved_portions,new.reserved_xml_bytes,new.last_admitted_as_of,new.admitted_revision)
            is distinct from (old.last_sequence,old.last_emission_id,old.last_admitted_endpoint,
                old.reserved_ref_occurrences,old.reserved_portions,old.reserved_xml_bytes,old.last_admitted_as_of,old.admitted_revision))
       or (old.successor_episode_key is not null and
            (new.successor_episode_key,new.successor_seed,new.successor_epoch) is distinct from
            (old.successor_episode_key,old.successor_seed,old.successor_epoch)) then
        raise exception 'password_v2_lifetime_immutable' using errcode='55000'; end if;
    return new;
end $$;
create trigger password_v2_ledger_immutable before update or delete on public.semantic_password_episode_budgets
    for each row execute function public.password_v2_ledger_immutable();
create trigger password_v2_ledger_no_truncate before truncate on public.semantic_password_episode_budgets
    for each statement execute function public.password_v2_ledger_immutable();

create function public.password_v2_episode_documents(s jsonb,p_pin text,p_key text) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare docs jsonb; n integer;
begin
    select coalesce(jsonb_agg(q.document_json order by (q.document_json#>>'{password_context,sequence}')::bigint,
            (q.document_json#>>'{password_context,portion_index}')::bigint),'[]'),count(*) into docs,n
    from (select v.document_json from public.semantic_qw_signals v where v.password_scope_digest=public.password_v2_scope_key(s)
        and v.document_json#>>'{password_context,pin}'=p_pin and v.document_json#>>'{password_context,episode_key}'=p_key
        order by (v.document_json#>>'{password_context,sequence}')::bigint,
            (v.document_json#>>'{password_context,portion_index}')::bigint limit 257) q;
    if n>256 then raise exception 'password_v2_episode_bound' using errcode='54000'; end if;
    return docs;
end $$;
create function public.password_v2_assert_episode(l public.semantic_password_episode_budgets) returns void
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare docs jsonb; group_docs jsonb; decoded jsonb; emission jsonb; previous jsonb; n integer:=0;
    refs bigint:=0; portions integer:=0; bytes bigint:=0; c public.semantic_password_checkpoints%rowtype;
    ep jsonb; first_root text; expected_jobs integer; actual_jobs integer; d jsonb; predecessor public.semantic_password_episode_budgets%rowtype;
    successor public.semantic_password_episode_budgets%rowtype;
begin
    if l.scope_digest is distinct from public.password_v2_scope_key(l.scope_json)
       or l.pin is distinct from public.password_v2_identity(l.scope_json,l.execution_json)->>'pin' then
        raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
    perform public.password_v2_check_witness(l.seed,l.scope_json);
    if l.episode_key<>public.password_v2_episode_key(l.pin,l.coverage_epoch,l.entity,l.seed) then
        raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
    docs:=public.password_v2_episode_documents(l.scope_json,l.pin,l.episode_key);
    for group_docs in select jsonb_agg(a.value order by (a.value#>>'{password_context,portion_index}')::integer)
        from jsonb_array_elements(docs) a(value) group by (a.value#>>'{password_context,sequence}')::integer
        order by (a.value#>>'{password_context,sequence}')::integer loop
        decoded:=public.password_v2_decode(l.scope_json,l.execution_json,group_docs); emission:=decoded->'emission'; n:=n+1;
        if (emission->>'sequence')::integer<>n or emission->>'entity'<>l.entity
           or (emission->>'epoch')::bigint<>l.coverage_epoch or emission->'seed' is distinct from l.seed
           or emission->>'episode_key'<>l.episode_key then
            raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
        if n=1 then first_root:=decoded->>'emission_id';
        elsif emission->'predecessor' is distinct from previous->'endpoint'
            or emission->>'previous_id' is distinct from previous->>'emission_id' then
            raise exception 'password_v2_ancestry_conflict' using errcode='55000'; end if;
        if decoded->>'root_id'<>first_root then raise exception 'password_v2_ancestry_conflict' using errcode='55000'; end if;
        refs:=refs+(decoded#>>'{delta,ref_occurrences}')::bigint; portions:=portions+(decoded#>>'{delta,portions}')::integer;
        bytes:=bytes+(decoded#>>'{delta,xml_bytes}')::bigint; previous:=decoded;
    end loop;
    if n<>l.last_sequence or refs<>l.reserved_ref_occurrences or portions<>l.reserved_portions or bytes<>l.reserved_xml_bytes
       or (n>0 and (first_root<>l.root_id or previous->>'emission_id'<>l.last_emission_id
            or previous->'endpoint' is distinct from l.last_admitted_endpoint))
       or (n=0 and not l.frozen) then
        raise exception 'password_v2_admission_incomplete' using errcode='55000'; end if;
    if l.predecessor_episode_key is not null then
        select q.* into predecessor from public.semantic_password_episode_budgets q
            where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.predecessor_episode_key;
        if not found or not predecessor.frozen or predecessor.barrier_unresolved
           or predecessor.entity<>l.entity or predecessor.scope_json is distinct from l.scope_json
           or predecessor.successor_episode_key is distinct from l.episode_key
           or predecessor.successor_seed is distinct from l.seed or predecessor.successor_epoch is distinct from l.coverage_epoch then
            raise exception 'password_v2_barrier_unresolved' using errcode='55000'; end if;
    end if;
    if l.successor_episode_key is not null then
        select q.* into successor from public.semantic_password_episode_budgets q
            where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.successor_episode_key;
        if not found or l.barrier_unresolved or successor.last_sequence<=0
            or successor.scope_json is distinct from l.scope_json or successor.execution_json is distinct from l.execution_json
            or successor.entity is distinct from l.entity or successor.predecessor_episode_key is distinct from l.episode_key
            or successor.seed is distinct from l.successor_seed or successor.coverage_epoch is distinct from l.successor_epoch then
            raise exception 'password_v2_successor_admission_incomplete' using errcode='55000'; end if;
    end if;
    if l.admission_xid=pg_current_xact_id() and n>0 then
        select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=l.scope_digest and q.pin=l.pin;
        perform public.password_v2_assert_checkpoint(c);
        if c.state_revision<>l.admitted_revision or c.active_token<>l.admitted_attempt_token
           or c.last_observed_token<>l.admitted_attempt_token or c.coverage_epoch<>l.coverage_epoch then
            raise exception 'password_v2_checkpoint_admission_incomplete' using errcode='55000'; end if;
        select a.value into ep from jsonb_array_elements(c.state_document->'episodes') a(value) where a.value->>'key'=l.episode_key;
        if ep is null or ep->>'entity'<>l.entity or ep->'seed' is distinct from l.seed
           or ep->>'root_id'<>l.root_id or ep->>'last_emission'<>l.last_emission_id
           or (ep->>'sequence')::integer<>l.last_sequence or ep->'budget' is distinct from public.password_v2_totals(l)
           or (ep->>'frozen')::boolean<>l.frozen then
            raise exception 'password_v2_checkpoint_admission_incomplete' using errcode='55000'; end if;
        -- Every sequence newly staged in this transaction needs every eligible job.
        for d in select a.value from jsonb_array_elements(docs) a(value)
            where (a.value#>>'{password_context,sequence}')::integer>=l.admission_first_sequence loop
            select count(*) into expected_jobs from public.semantic_risk_policies p
            join public.semantic_risk_policy_subscriptions sub using(policy_id,policy_version)
            where p.source_kind='qw_signal' and sub.source_kind='qw_signal'
              and sub.selector_value=d->>'rule_id' and sub.definition_sha256=p.definition_sha256
              and p.definition_json#>'{source_selector,execution}'=l.execution_json
              and p.policy_version=(d->>'policy_revision')::integer
              and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)=d->>'evaluation_mode'
              and (d->>'evaluation_mode'<>'enabled' or exists(select 1 from public.semantic_policy_admission a
                  where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled));
            select count(*) into actual_jobs from public.semantic_risk_evaluation_jobs j
            join public.semantic_risk_policies p using(policy_id,policy_version)
            join public.semantic_risk_policy_subscriptions sub using(policy_id,policy_version)
            where j.source_kind='qw_signal' and j.qw_signal_id=encode(sha256(convert_to(public.password_v2_json_compact(d-'received_at_utc'),'UTF8')),'hex')
              and j.source_reference=j.qw_signal_id and j.evaluation_mode=d->>'evaluation_mode'
              and j.idempotency_key=sha256(convert_to(public.password_v2_json_compact(jsonb_build_object(
                  'policy_id',p.policy_id,'policy_version',p.policy_version,'policy_sha256',encode(p.definition_sha256,'hex'),
                  'source_kind','qw_signal','source_id',j.qw_signal_id,'evaluation_mode',j.evaluation_mode)),'UTF8'))
              and p.source_kind='qw_signal' and sub.source_kind='qw_signal'
              and sub.selector_value=d->>'rule_id' and sub.definition_sha256=p.definition_sha256
              and p.definition_json#>'{source_selector,execution}'=l.execution_json
              and p.policy_version=(d->>'policy_revision')::integer
              and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)=d->>'evaluation_mode'
              and (d->>'evaluation_mode'<>'enabled' or exists(select 1 from public.semantic_policy_admission a
                  where a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled));
            if expected_jobs=0 or actual_jobs<>expected_jobs then
                raise exception 'password_v2_jobs_incomplete' using errcode='55000'; end if;
        end loop;
    end if;
end $$;
create function public.password_v2_qw_allowed(p_id text,p_mode text,d jsonb) returns boolean
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare s jsonb; x jsonb; identity jsonb; l public.semantic_password_episode_budgets%rowtype;
begin
    if not public.password_v2_managed(d) then return true; end if;
    if d->>'rule_version'<>'2' or not(d ? 'password_context') then return false; end if;
    s:=d#>'{evidence_refs,0,scope}'; x:=jsonb_build_object('version','sli.qw.execution.v1','kind',d->'kind',
        'rule_id',d->'rule_id','rule_version',d->'rule_version','rule_sha256',d->'rule_sha256','scope',s);
    identity:=public.password_v2_identity(s,x);
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=decode(identity->>'scope_digest','hex')
        and q.pin=identity->>'pin' and q.episode_key=d#>>'{password_context,episode_key}';
    return found and not l.frozen and l.scope_json=s and l.execution_json=x
        and p_mode is not distinct from d->>'evaluation_mode'
        and p_id=encode(sha256(convert_to(public.password_v2_json_compact(d-'received_at_utc'),'UTF8')),'hex');
end $$;
alter table public.semantic_qw_signals add constraint password_v2_qw_identity check(public.password_v2_qw_allowed(signal_id,evaluation_mode,document_json));

create function public.password_v2_deferred() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare l public.semantic_password_episode_budgets%rowtype; d jsonb; s jsonb; p_pin text; p_key text; key bytea;
    c public.semantic_password_checkpoints%rowtype; ep jsonb;
begin
    if tg_table_name='semantic_password_episode_budgets' then
        key:=new.scope_digest; p_pin:=new.pin; p_key:=new.episode_key;
    elsif tg_table_name='semantic_qw_signals' then
        d:=new.document_json;
        if not public.password_v2_managed(d) then return null; end if;
        s:=d#>'{evidence_refs,0,scope}'; key:=public.password_v2_scope_key(s);
        p_pin:=d#>>'{password_context,pin}'; p_key:=d#>>'{password_context,episode_key}';
    else
        select q.document_json into d from public.semantic_qw_signals q where q.signal_id=coalesce(new.qw_signal_id,old.qw_signal_id);
        if not public.password_v2_managed(d) then return null; end if;
        s:=d#>'{evidence_refs,0,scope}'; key:=public.password_v2_scope_key(s);
        p_pin:=d#>>'{password_context,pin}'; p_key:=d#>>'{password_context,episode_key}';
    end if;
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=key and q.pin=p_pin and q.episode_key=p_key;
    if not found then raise exception 'password_v2_admission_incomplete' using errcode='55000'; end if;
    -- The private staged ledger has its own deferred event. Avoid rebuilding a
    -- complete lifetime once per supplied portion/job; direct inserts still validate.
    if l.admission_xid=pg_current_xact_id() and tg_table_name<>'semantic_password_episode_budgets'
       and ((d#>>'{password_context,sequence}')::integer<>l.last_sequence
            or (d#>>'{password_context,portion_index}')::integer<>0) then return null; end if;
    if tg_table_name='semantic_password_episode_budgets' and tg_op='UPDATE' then
        if not old.frozen and new.frozen and new.last_sequence>0 then
            select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=key and q.pin=p_pin;
            select a.value into ep from jsonb_array_elements(c.state_document->'episodes') a(value) where a.value->>'key'=p_key;
            if ep is null or ep->'frozen' is distinct from 'true'::jsonb
                or ep->'budget' is distinct from public.password_v2_totals(l)
                or ep->>'root_id' is distinct from l.root_id or ep->>'last_emission' is distinct from l.last_emission_id
                or (ep->>'sequence')::integer<>l.last_sequence
                or c.last_observed_token<>c.active_token or c.state_revision<=old.admitted_revision then
                raise exception 'password_v2_freeze_completion_incomplete' using errcode='55000'; end if;
        end if;
    end if;
    perform public.password_v2_assert_episode(l); return null;
end $$;
create constraint trigger password_v2_ledger_complete after insert or update on public.semantic_password_episode_budgets
    deferrable initially deferred for each row execute function public.password_v2_deferred();
create constraint trigger password_v2_qw_complete after insert on public.semantic_qw_signals
    deferrable initially deferred for each row execute function public.password_v2_deferred();
create constraint trigger password_v2_jobs_complete after insert or update or delete on public.semantic_risk_evaluation_jobs
    deferrable initially deferred for each row execute function public.password_v2_deferred();
create function public.read_password_episode_portions_v2(s jsonb,execution jsonb,episode_key text)
returns table(signal_id text,document_json jsonb)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; l public.semantic_password_episode_budgets%rowtype; d jsonb;
begin
    identity:=public.password_v2_identity(s,execution);
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=decode(identity->>'scope_digest','hex')
        and q.pin=identity->>'pin' and q.episode_key=read_password_episode_portions_v2.episode_key;
    if not found then raise exception 'password_v2_episode_absent' using errcode='55000'; end if;
    if l.scope_json is distinct from s or l.execution_json is distinct from execution then
        raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
    perform public.password_v2_assert_episode(l);
    for d in select a.value from jsonb_array_elements(public.password_v2_episode_documents(s,l.pin,l.episode_key)) a(value) loop
        return query select encode(sha256(convert_to(public.password_v2_json_compact(d-'received_at_utc'),'UTF8')),'hex'),d;
    end loop;
end $$;

create function public.reserve_password_episode_emission(s jsonb,execution jsonb,attempt_token bigint,
    expected_checkpoint_revision bigint,expected_ledger jsonb,portion_documents jsonb) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; l public.semantic_password_episode_budgets%rowtype;
    barrier public.semantic_password_episode_budgets%rowtype; decoded jsonb; em jsonb; old_docs jsonb; old_em jsonb;
    d jsonb; n integer:=0; actual_bytes bigint; refs bigint; parts integer; bytes bigint; p_key text; seq integer;
    pred text; as_of timestamptz; expected jsonb; has_l boolean; ident text;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or attempt_token is distinct from c.active_token or attempt_token<=c.last_observed_token
       or expected_checkpoint_revision is distinct from c.state_revision then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    decoded:=public.password_v2_decode(s,execution,portion_documents); em:=decoded->'emission';
    p_key:=em->>'episode_key'; seq:=(em->>'sequence')::integer;
    perform pg_advisory_xact_lock(public.password_v2_entity_key(c.scope_digest,c.pin,em->>'entity'));
    -- Same source/checkpoint lock serializes entity relations; ledger locks use one stable order.
    perform 1 from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and (q.episode_key=p_key or (q.entity=em->>'entity' and q.barrier_unresolved))
        order by q.episode_key for update;
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=p_key;
    has_l:=found;
    if has_l and (l.scope_json is distinct from s or l.execution_json is distinct from execution
        or l.entity is distinct from em->>'entity' or l.coverage_epoch<>(em->>'epoch')::bigint or l.seed is distinct from em->'seed') then
        raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
    if has_l and seq<=l.last_sequence then
        old_docs:=public.password_v2_episode_documents(s,c.pin,p_key);
        select jsonb_agg(a.value order by (a.value#>>'{password_context,portion_index}')::integer) into old_docs
            from jsonb_array_elements(old_docs) a(value) where (a.value#>>'{password_context,sequence}')::integer=seq;
        if old_docs is null then raise exception 'password_v2_replay_conflict' using errcode='55000'; end if;
        old_em:=public.password_v2_decode(s,execution,old_docs);
        if old_em is distinct from decoded
            or (select jsonb_agg(a.value-'received_at_utc' order by a.ord) from jsonb_array_elements(old_docs) with ordinality a(value,ord))
                is distinct from (select jsonb_agg(a.value-'received_at_utc' order by a.ord) from jsonb_array_elements(portion_documents) with ordinality a(value,ord)) then
            raise exception 'password_v2_replay_conflict' using errcode='55000'; end if;
        perform public.password_v2_assert_episode(l);
        return jsonb_build_object('status','replay','episode_key',p_key,'emission_id',decoded->'emission_id','sequence',seq,
            'delta',jsonb_build_object('ref_occurrences',0,'portions',0,'xml_bytes',0),'totals',public.password_v2_totals(l),
            'signal_ids',decoded->'signal_ids','reason',null,'snapshot_as_of',public.password_v2_iso(l.last_admitted_as_of));
    end if;
    if has_l then
        expected:=public.password_v2_totals(l)||jsonb_build_object('last_sequence',l.last_sequence,'last_emission_id',l.last_emission_id);
        if expected_ledger is distinct from expected or seq<>l.last_sequence+1
           or em->>'previous_id' is distinct from l.last_emission_id
           or em->'predecessor' is distinct from l.last_admitted_endpoint or decoded->>'root_id'<>l.root_id then
            raise exception 'password_v2_ledger_cas_conflict' using errcode='55000'; end if;
        if l.frozen then return jsonb_build_object('status','frozen','episode_key',p_key,'emission_id',decoded->'emission_id',
            'sequence',seq,'delta',jsonb_build_object('ref_occurrences',0,'portions',0,'xml_bytes',0),
            'totals',public.password_v2_totals(l),'signal_ids','[]'::jsonb,'reason','episode_evidence_budget_exhausted',
            'snapshot_as_of',public.password_v2_iso(l.last_admitted_as_of)); end if;
    elsif expected_ledger is not null or seq<>1 then
        raise exception 'password_v2_ledger_cas_conflict' using errcode='55000';
    end if;
    select q.* into barrier from public.semantic_password_episode_budgets q
        where q.scope_digest=c.scope_digest and q.pin=c.pin and q.entity=em->>'entity' and q.barrier_unresolved;
    if found and barrier.episode_key<>p_key then
        if barrier.successor_episode_key is distinct from p_key or barrier.successor_seed is distinct from em->'seed'
           or barrier.successor_epoch is distinct from (em->>'epoch')::bigint then
            raise exception 'password_v2_barrier_unresolved' using errcode='55000'; end if;
        pred:=barrier.episode_key;
    end if;
    actual_bytes:=public.password_v2_native_cost(s,decoded->'occurrences');
    if actual_bytes<>(decoded#>>'{delta,xml_bytes}')::bigint then
        raise exception 'password_v2_retained_unavailable' using errcode='42501'; end if;
    refs:=coalesce(l.reserved_ref_occurrences,0)+(decoded#>>'{delta,ref_occurrences}')::bigint;
    parts:=coalesce(l.reserved_portions,0)+(decoded#>>'{delta,portions}')::integer;
    bytes:=coalesce(l.reserved_xml_bytes,0)+actual_bytes; as_of:=clock_timestamp();
    if pred is not null then
        update public.semantic_password_episode_budgets q set barrier_unresolved=false
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=pred;
    end if;
    if refs>10000 or parts>256 or bytes>33554432 then
        if has_l then
            update public.semantic_password_episode_budgets q set frozen=true,frozen_at=as_of,
                frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,
                tracking_endpoint=decoded->'endpoint',tracking_epoch=(em->>'epoch')::bigint,
                tracking_through=public.password_v2_time(decoded#>'{endpoint,at}')
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=p_key returning q.* into l;
        else
            insert into public.semantic_password_episode_budgets(scope_digest,pin,episode_key,scope_json,execution_json,
                coverage_epoch,entity,seed,root_id,last_sequence,last_emission_id,last_admitted_endpoint,
                reserved_ref_occurrences,reserved_portions,reserved_xml_bytes,last_admitted_as_of,admitted_revision,first_ledger_revision,
                admitted_attempt_token,admission_xid,admission_first_sequence,frozen,frozen_at,frozen_reason,barrier_unresolved,
                tracking_endpoint,tracking_epoch,tracking_through,predecessor_episode_key)
            values(c.scope_digest,c.pin,p_key,s,execution,(em->>'epoch')::bigint,em->>'entity',em->'seed',decoded->>'root_id',
                0,null,null,0,0,0,null,0,c.state_revision+1,attempt_token,pg_current_xact_id(),1,true,as_of,'episode_evidence_budget_exhausted',true,
                decoded->'endpoint',(em->>'epoch')::bigint,public.password_v2_time(decoded#>'{endpoint,at}'),pred) returning * into l;
        end if;
        return jsonb_build_object('status','frozen','episode_key',p_key,'emission_id',decoded->'emission_id','sequence',seq,
            'delta',jsonb_build_object('ref_occurrences',0,'portions',0,'xml_bytes',0),'totals',public.password_v2_totals(l),
            'signal_ids','[]'::jsonb,'reason','episode_evidence_budget_exhausted','snapshot_as_of',public.password_v2_iso(l.last_admitted_as_of));
    end if;

    if has_l then
        update public.semantic_password_episode_budgets q set last_sequence=seq,last_emission_id=decoded->>'emission_id',
            last_admitted_endpoint=decoded->'endpoint',reserved_ref_occurrences=refs,reserved_portions=parts,
            reserved_xml_bytes=bytes,last_admitted_as_of=as_of,admitted_revision=c.state_revision+1,
            admitted_attempt_token=attempt_token,admission_xid=pg_current_xact_id(),
            admission_first_sequence=case when q.admission_xid=pg_current_xact_id() then q.admission_first_sequence else seq end
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=p_key returning q.* into l;
    else
        insert into public.semantic_password_episode_budgets(scope_digest,pin,episode_key,scope_json,execution_json,
            coverage_epoch,entity,seed,root_id,last_sequence,last_emission_id,last_admitted_endpoint,
            reserved_ref_occurrences,reserved_portions,reserved_xml_bytes,last_admitted_as_of,admitted_revision,first_ledger_revision,
            admitted_attempt_token,admission_xid,admission_first_sequence,predecessor_episode_key)
        values(c.scope_digest,c.pin,p_key,s,execution,(em->>'epoch')::bigint,em->>'entity',em->'seed',decoded->>'root_id',seq,
            decoded->>'emission_id',decoded->'endpoint',refs,parts,bytes,as_of,c.state_revision+1,c.state_revision+1,attempt_token,pg_current_xact_id(),seq,pred)
        returning * into l;
    end if;
    for d in select a.value from jsonb_array_elements(portion_documents) a(value) loop
        ident:=decoded#>>array['signal_ids',n::text]; n:=n+1;
        insert into public.semantic_qw_signals(signal_id,evaluation_mode,document_json) values(ident,d->>'evaluation_mode',d);
    end loop;
    return jsonb_build_object('status','reserved','episode_key',p_key,'emission_id',decoded->'emission_id','sequence',seq,
        'delta',decoded->'delta','totals',public.password_v2_totals(l),'signal_ids',decoded->'signal_ids',
        'reason',null,'snapshot_as_of',public.password_v2_iso(l.last_admitted_as_of));
end $$;

create function public.lock_password_publication_v2(s jsonb,execution jsonb,episode_key text) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; l public.semantic_password_episode_budgets%rowtype; pred public.semantic_password_episode_budgets%rowtype;
    barrier public.semantic_password_episode_budgets%rowtype; historical jsonb:='null';
begin
    identity:=public.password_v2_identity(s,execution);
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=decode(identity->>'scope_digest','hex')
        and q.pin=identity->>'pin' and q.episode_key=lock_password_publication_v2.episode_key;
    if not found then raise exception 'password_v2_episode_absent' using errcode='55000'; end if;
    -- Shared ENTITY lock protects absence of a cross-epoch frozen barrier.
    perform pg_advisory_xact_lock_shared(public.password_v2_entity_key(l.scope_digest,l.pin,l.entity));
    -- No checkpoint/source lock: publisher already holds its existing scenario lock.
    perform 1 from public.semantic_password_episode_budgets q where q.scope_digest=l.scope_digest and q.pin=l.pin
        and (q.episode_key=l.episode_key or q.episode_key=l.predecessor_episode_key or (q.entity=l.entity and q.barrier_unresolved))
        order by q.episode_key for share;
    select q.* into l from public.semantic_password_episode_budgets q
        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;
    if l.scope_json is distinct from s or l.execution_json is distinct from execution then
        raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
    if l.frozen then raise exception 'episode_frozen' using errcode='55000'; end if;
    select q.* into barrier from public.semantic_password_episode_budgets q
        where q.scope_digest=l.scope_digest and q.pin=l.pin and q.entity=l.entity
        and q.barrier_unresolved and q.episode_key<>l.episode_key;
    if found then
        if not barrier.frozen or barrier.scope_json is distinct from s or barrier.execution_json is distinct from execution
           or barrier.entity is distinct from l.entity or l.last_sequence<=0
           or l.admitted_revision is null or l.admitted_revision<=0
           or barrier.first_ledger_revision is null or barrier.first_ledger_revision<=0
           or l.admitted_revision>=barrier.first_ledger_revision then
            raise exception 'password_v2_barrier_unresolved' using errcode='55000'; end if;
        perform public.password_v2_check_witness(barrier.seed,s);
        if barrier.episode_key is distinct from public.password_v2_episode_key(barrier.pin,barrier.coverage_epoch,barrier.entity,barrier.seed) then
            raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
        -- Eligibility only: Python proves actual A-chain/B-seed entity and separation
        -- on BOTH fresh bounded native passes before finding/link output.
        historical:=jsonb_build_object('version','sli.password.v2.historical-barrier.1',
            'barrier_episode_key',barrier.episode_key,'barrier_first_ledger_revision',barrier.first_ledger_revision,
            'barrier_seed',barrier.seed,'target_last_admitted_revision',l.admitted_revision,
            'target_last_sequence',l.last_sequence,'target_last_emission_id',l.last_emission_id);
    end if;
    perform public.password_v2_assert_episode(l);
    if l.predecessor_episode_key is not null then
        select q.* into pred from public.semantic_password_episode_budgets q where q.scope_digest=l.scope_digest and q.pin=l.pin
            and q.episode_key=l.predecessor_episode_key;
    end if;
    return jsonb_build_object('episode_key',l.episode_key,'entity',l.entity,'epoch',l.coverage_epoch,'root_id',l.root_id,
        'last_sequence',l.last_sequence,'last_emission_id',l.last_emission_id,'totals',public.password_v2_totals(l),'frozen',l.frozen,
        'predecessor_episode_key',l.predecessor_episode_key,'predecessor_endpoint',pred.tracking_endpoint,
        'successor_seed',case when l.predecessor_episode_key is not null then l.seed else null end,
        'successor_epoch',pred.successor_epoch,'predecessor_tracking_through',public.password_v2_iso(pred.tracking_through),
        'historical_barrier',historical);
end $$;
create function public.assert_password_publication_entity_v2(s jsonb,execution jsonb,episode_key text,actual_entity text,
    expected_historical_barrier jsonb) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; entity text; locked jsonb;
begin
    identity:=public.password_v2_identity(s,execution);
    select q.entity into entity from public.semantic_password_episode_budgets q where q.scope_digest=decode(identity->>'scope_digest','hex')
        and q.pin=identity->>'pin' and q.episode_key=assert_password_publication_entity_v2.episode_key;
    if not found then raise exception 'password_v2_episode_absent' using errcode='55000'; end if;
    if actual_entity is distinct from entity then raise exception 'password_v2_publication_entity_conflict' using errcode='55000'; end if;
    locked:=public.lock_password_publication_v2(s,execution,episode_key);
    if coalesce(expected_historical_barrier,'null'::jsonb) is distinct from locked->'historical_barrier' then
        raise exception 'password_v2_publication_descriptor_conflict' using errcode='55000'; end if;
    return locked;
end $$;
create function public.assert_password_publication_entity_v2(s jsonb,execution jsonb,episode_key text,actual_entity text) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
begin
    -- Existing callers cannot silently ignore a newly returned historical proof.
    return public.assert_password_publication_entity_v2(s,execution,episode_key,actual_entity,null::jsonb);
end $$;

create function public.track_password_frozen_entity_v2(s jsonb,execution jsonb,attempt_token bigint,
    expected_checkpoint_revision bigint,episode_key text,endpoint jsonb,coverage_epoch bigint,
    covered_from timestamptz,finalized_through timestamptz) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; l public.semantic_password_episode_budgets%rowtype;
    old_time timestamptz; new_time timestamptz; successor text;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or attempt_token is distinct from c.active_token or attempt_token<=c.last_observed_token
       or expected_checkpoint_revision is distinct from c.state_revision then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and q.episode_key=track_password_frozen_entity_v2.episode_key;
    if not found then raise exception 'password_v2_episode_absent' using errcode='55000'; end if;
    perform pg_advisory_xact_lock(public.password_v2_entity_key(c.scope_digest,c.pin,l.entity));
    select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and q.episode_key=track_password_frozen_entity_v2.episode_key for update;
    if not l.frozen or not l.barrier_unresolved or l.successor_episode_key is not null then
        raise exception 'password_v2_barrier_conflict' using errcode='55000'; end if;
    perform public.password_v2_check_witness(endpoint,s); new_time:=public.password_v2_time(endpoint->'at');
    if coverage_epoch is null or coverage_epoch<l.coverage_epoch or covered_from is null or finalized_through is null
       or covered_from>finalized_through or covered_from<finalized_through-interval '600 seconds'
       or new_time>finalized_through or finalized_through>statement_timestamp()-interval '120 seconds'
       or finalized_through<l.tracking_through then
        raise exception 'password_v2_tracking_invalid' using errcode='22023'; end if;
    perform public.password_v2_native_cost(s,jsonb_build_array(endpoint));
    if l.tracking_endpoint is not null then
        perform public.password_v2_native_cost(s,jsonb_build_array(l.tracking_endpoint));
        old_time:=public.password_v2_time(l.tracking_endpoint->'at');
        if new_time<old_time then raise exception 'password_v2_tracking_invalid' using errcode='22023'; end if;
    end if;
    if l.tracking_epoch=coverage_epoch and covered_from<=l.tracking_through and new_time>old_time+interval '600 seconds' then
        successor:=public.password_v2_episode_key(l.pin,coverage_epoch,l.entity,endpoint);
        update public.semantic_password_episode_budgets q set successor_episode_key=successor,successor_seed=endpoint,
            successor_epoch=track_password_frozen_entity_v2.coverage_epoch where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;
    else
        update public.semantic_password_episode_budgets q set tracking_endpoint=endpoint,tracking_epoch=track_password_frozen_entity_v2.coverage_epoch,
            tracking_through=finalized_through where q.scope_digest=l.scope_digest and q.pin=l.pin and q.episode_key=l.episode_key;
    end if;
    return jsonb_build_object('status',case when successor is null then 'held' else 'successor_authorized' end,
        'successor_episode_key',successor);
end $$;

-- No public successful State path is added; commit_password_state_v2 remains55000.
revoke all on function public.password_v2_qw_allowed(text,text,jsonb) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.password_v2_qw_allowed(text,text,jsonb) to adlog_semantic_worker;
do $$
declare f record;
begin
    for f in select p.oid,p.proname,p.proowner from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        where n.nspname='public' and p.proname=any(array['password_v2_managed','password_v2_scope_key','password_v2_tuple',
            'password_v2_entity_key','lock_password_reservation_entities_v2','password_v2_episode_key','password_v2_decode','password_v2_native_cost','password_v2_totals',
            'password_v2_ledger_immutable','password_v2_episode_documents','password_v2_assert_episode','password_v2_deferred',
            'read_password_episode_portions_v2','reserve_password_episode_emission','lock_password_publication_v2',
            'assert_password_publication_entity_v2','track_password_frozen_entity_v2']) loop
        execute format('revoke all on function %s from public,adlog_user,adlog_storage_worker,adlog_semantic_worker',f.oid::regprocedure);
        if f.proname=any(array['lock_password_reservation_entities_v2','read_password_episode_portions_v2','reserve_password_episode_emission','lock_password_publication_v2',
            'assert_password_publication_entity_v2','track_password_frozen_entity_v2']) then
            execute format('grant execute on function %s to adlog_semantic_worker',f.oid::regprocedure);
        end if;
    end loop;
    if exists(select 1 from pg_class c cross join lateral aclexplode(coalesce(c.relacl,'{}'::aclitem[])) a
        where c.oid='public.semantic_password_episode_budgets'::regclass and a.grantee<>c.relowner) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
end $$;
create function public.password_v2_job_guard() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare d jsonb; l public.semantic_password_episode_budgets%rowtype;
begin
    if tg_op='DELETE' then return old; end if;
    if new.source_kind<>'qw_signal' then return new; end if;
    select q.document_json into d from public.semantic_qw_signals q where q.signal_id=new.qw_signal_id;
    if not public.password_v2_managed(d) then return new; end if;
    perform public.password_v2_source_binding(d#>'{evidence_refs,0,scope}');
    select q.* into l from public.semantic_password_episode_budgets q
        where q.scope_digest=public.password_v2_scope_key(d#>'{evidence_refs,0,scope}')
        and q.pin=d#>>'{password_context,pin}' and q.episode_key=d#>>'{password_context,episode_key}' for share;
    if not found then raise exception 'password_v2_admission_incomplete' using errcode='55000'; end if;
    if tg_op='INSERT' and l.frozen then raise exception 'episode_frozen' using errcode='55000'; end if;
    if tg_op='UPDATE' and (new.qw_signal_id,new.policy_id,new.policy_version,new.source_reference,new.evaluation_mode,new.idempotency_key)
        is distinct from (old.qw_signal_id,old.policy_id,old.policy_version,old.source_reference,old.evaluation_mode,old.idempotency_key) then
        raise exception 'password_v2_job_identity_immutable' using errcode='55000'; end if;
    return new;
end $$;
create trigger password_v2_job_guard before insert or update on public.semantic_risk_evaluation_jobs
    for each row execute function public.password_v2_job_guard();
create function public.password_v2_state_ledger_complete() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; e jsonb; l public.semantic_password_episode_budgets%rowtype;
begin
    if tg_table_name='semantic_password_checkpoints' then
        if tg_op='UPDATE' and (new.state_document,new.state_revision,new.watermark,new.coverage_epoch)
            is not distinct from (old.state_document,old.state_revision,old.watermark,old.coverage_epoch) then return null; end if;
        select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=new.scope_digest and q.pin=new.pin;
    else
        select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=coalesce(new.scope_digest,old.scope_digest)
            and q.pin=coalesce(new.pin,old.pin);
    end if;
    perform public.password_v2_assert_checkpoint(c);
    if c.state_document is null then return null; end if;
    for e in select a.value from jsonb_array_elements(c.state_document->'episodes') a(value) loop
        if e->>'sequence'='0' then
            if e->'budget'<>jsonb_build_object('ref_occurrences',0,'portions',0,'xml_bytes',0) then
                raise exception 'password_v2_state_ledger_conflict' using errcode='55000'; end if;
            continue;
        end if;
        select q.* into l from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
            and q.episode_key=e->>'key';
        if not found or e->'budget' is distinct from public.password_v2_totals(l)
           or e->>'entity'<>l.entity or e->'seed' is distinct from l.seed or e->>'root_id'<>l.root_id
           or e->>'last_emission'<>l.last_emission_id or (e->>'sequence')::integer<>l.last_sequence
           or (e->>'frozen')::boolean<>l.frozen then
            raise exception 'password_v2_state_ledger_conflict' using errcode='55000'; end if;
    end loop;
    return null;
end $$;
create constraint trigger password_v2_state_ledger_complete after insert or update on public.semantic_password_checkpoints
    deferrable initially deferred for each row execute function public.password_v2_state_ledger_complete();
create constraint trigger password_v2_members_complete after insert or update or delete on public.semantic_password_window_members
    deferrable initially deferred for each row execute function public.password_v2_state_ledger_complete();
revoke all on function public.password_v2_job_guard(),public.password_v2_state_ledger_complete()
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
do $$ begin
    if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        cross join lateral aclexplode(coalesce(p.proacl,'{}'::aclitem[])) a
        where n.nspname='public' and p.proname=any(array['password_v2_managed','password_v2_scope_key','password_v2_tuple',
            'password_v2_entity_key','lock_password_reservation_entities_v2','password_v2_episode_key','password_v2_decode','password_v2_native_cost','password_v2_totals',
            'password_v2_ledger_immutable','password_v2_episode_documents','password_v2_assert_episode','password_v2_deferred',
            'password_v2_qw_allowed','password_v2_qw_index_key','password_v2_job_guard','password_v2_state_ledger_complete',
            'read_password_episode_portions_v2','reserve_password_episode_emission','lock_password_publication_v2',
            'assert_password_publication_entity_v2','track_password_frozen_entity_v2'])
        and a.grantee<>p.proowner and not (a.grantee='adlog_semantic_worker'::regrole and a.privilege_type='EXECUTE'
            and not a.is_grantable and p.proname=any(array['lock_password_reservation_entities_v2','password_v2_qw_allowed','read_password_episode_portions_v2',
                'reserve_password_episode_emission','lock_password_publication_v2','assert_password_publication_entity_v2',
                'track_password_frozen_entity_v2']))) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
end $$;

-- Controlled B2 producer: trusted working semantics; guarded storage completion.
create function public.password_v2_require_entity_lock(d bytea,p text,e text) returns void
language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare k bigint:=public.password_v2_entity_key(d,p,e);
begin
    if not exists(select 1 from pg_locks where locktype='advisory' and pid=pg_backend_pid()
        and granted and mode='ExclusiveLock' and objsubid=1
        and classid::bigint=((k>>32)&4294967295) and objid::bigint=(k&4294967295)) then
        raise exception 'password_v2_entity_prelock_required' using errcode='55000'; end if;
end $$;

create function public.prepare_password_producer_batch_v2(s jsonb,execution jsonb,attempt_token bigint,
    expected_revision bigint,entity_keys text[]) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; l public.semantic_password_episode_budgets%rowtype;
    bars jsonb:='[]'; result jsonb; all_entities text[]; entity text;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or attempt_token is distinct from c.active_token or attempt_token<=c.last_observed_token
        or expected_revision is distinct from c.state_revision then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    if entity_keys is null or cardinality(entity_keys)>10000
        or (cardinality(entity_keys)>0 and array_ndims(entity_keys)<>1) then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    foreach entity in array entity_keys loop
        if entity is null or entity !~ '^[a-f0-9]{64}$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    end loop;
    -- Source/CP serializes producer changes; inspect ONLY this canonical C's current barriers.
    with current_entities as materialized (
        select q.entity from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved
            order by q.entity limit 10001
    )
    select coalesce(array_agg(u.entity order by u.entity),'{}'::text[]) into all_entities from (
        select distinct unnest(entity_keys) as entity
        union select ce.entity from current_entities ce
    ) u;
    if cardinality(all_entities)>10000 then raise exception 'password_v2_context_bound' using errcode='54000'; end if;
    perform public.lock_password_reservation_entities_v2(s,execution,attempt_token,expected_revision,all_entities);
    for l in select q.* from public.semantic_password_episode_budgets q
        where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved
        order by q.episode_key loop
        if l.scope_json is distinct from s or l.execution_json is distinct from execution or not l.frozen
            or l.episode_key<>public.password_v2_episode_key(c.pin,l.coverage_epoch,l.entity,l.seed) then
            raise exception 'password_v2_ledger_conflict' using errcode='55000'; end if;
        bars:=bars||jsonb_build_array(jsonb_build_object('episode_key',l.episode_key,'entity',l.entity,
            'coverage_epoch',l.coverage_epoch,'seed',l.seed,'root_id',l.root_id,'last_sequence',l.last_sequence,
            'last_emission_id',l.last_emission_id,'last_admitted_endpoint',l.last_admitted_endpoint,
            'totals',public.password_v2_totals(l),'last_admitted_as_of',public.password_v2_iso(l.last_admitted_as_of),
            'admitted_revision',l.admitted_revision,'first_ledger_revision',l.first_ledger_revision,
            'tracking_endpoint',l.tracking_endpoint,'tracking_epoch',l.tracking_epoch,
            'tracking_through',public.password_v2_iso(l.tracking_through),
            'successor_episode_key',l.successor_episode_key,'successor_seed',l.successor_seed,'successor_epoch',l.successor_epoch));
        if public.password_v2_json_bytes(bars)>4194304 then
            raise exception 'password_v2_context_bound' using errcode='54000'; end if;
    end loop;
    result:=jsonb_build_object('status','prepared','state_revision',c.state_revision,'barriers',bars,'prelocked_entities',to_jsonb(all_entities));
    if public.password_v2_json_bytes(result)>4194304 then
        raise exception 'password_v2_context_bound' using errcode='54000'; end if;
    return result;
end $$;

create function public.complete_password_producer_batch_v2(s jsonb,execution jsonb,attempt_token bigint,
    expected_revision bigint,mode text,payload jsonb) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype; l public.semantic_password_episode_budgets%rowtype;
    next_st jsonb; win jsonb; diag jsonb; touched jsonb; e jsonb; old_e jsonb; w jsonb; k text; track_endpoint jsonb;
    witnesses jsonb:='[]'; actual bigint; pair_bytes bigint; stamp timestamptz; t timestamptz; f timestamptz;
    lower_bound timestamptz; next_epoch bigint; entities text[]; frozen_keys jsonb; unresolved boolean; tracked boolean;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null or attempt_token is distinct from c.active_token or attempt_token<=c.last_observed_token
        or expected_revision is distinct from c.state_revision then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    if payload->>'version' is distinct from 'sli.password.v2.producer-batch.1' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    stamp:=clock_timestamp();
    if mode='advance' then
        if not public.password_v2_keys(payload,array['version','state','window','diagnostics','touched_episode_keys']) then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        next_st:=payload->'state'; win:=payload->'window'; diag:=payload->'diagnostics'; touched:=payload->'touched_episode_keys';
        perform public.password_v2_check_state(next_st,s,c.pin);
        if not public.password_v2_keys(win,array['version','read_from','read_to','finalizable_through','candidate_count',
            'truncated','unverifiable_count','oversized_count','error_code','native_checked_count','native_checks_complete'])
            or win->>'version' is distinct from 'sli.password.v2.window.1'
            or not public.password_v2_uint(win->'candidate_count',10000)
            or not public.password_v2_uint(win->'native_checked_count',10000)
            or win->'native_checked_count' is distinct from win->'candidate_count'
            or win->'native_checks_complete' is distinct from 'true'::jsonb
            or win->'truncated' is distinct from 'false'::jsonb
            or win->'unverifiable_count' is distinct from '0'::jsonb
            or win->'oversized_count' is distinct from '0'::jsonb
            or win->'error_code' is distinct from 'null'::jsonb then
            raise exception 'password_v2_window_incomplete' using errcode='55000'; end if;
        t:=public.password_v2_time(win->'read_to'); f:=public.password_v2_time(win->'finalizable_through');
        lower_bound:=public.password_v2_time(win->'read_from'); next_epoch:=(next_st->>'epoch')::bigint;
        if t<c.last_attempt_at or t>stamp or lower_bound<>t-interval '720 seconds' or f<>t-interval '120 seconds'
            or public.password_v2_time(next_st->'watermark')<>f or (c.watermark is not null and f<c.watermark)
            or next_epoch<>c.coverage_epoch+(case when c.watermark is not null and lower_bound>c.watermark then 1 else 0 end) then
            raise exception 'password_v2_window_conflict' using errcode='55000'; end if;
        if exists(select 1 from jsonb_object_keys(diag) d(code) where d.code<>all(array[
            'too_late','coverage_gap','episode_evidence_budget_exhausted','missing_target','unclassified_failure',
            'ambiguous_failure','conflicting_client','missing_client'])) then
            raise exception 'password_v2_window_incomplete' using errcode='55000'; end if;
        if jsonb_typeof(touched) is distinct from 'array' or jsonb_array_length(touched)>10000
            or jsonb_typeof(diag) is distinct from 'object' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        for w in select a.value from jsonb_array_elements(touched) a(value) loop
            if jsonb_typeof(w) is distinct from 'string' or w#>>'{}' !~ '^[a-f0-9]{64}$' then
                raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        end loop;
        with current_entities as materialized (
            select q.entity from public.semantic_password_episode_budgets q
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved
                order by q.entity limit 10001
        )
        select coalesce(array_agg(distinct entity),'{}'::text[]) into entities from (
            select a.value->>'entity' as entity from jsonb_array_elements(next_st->'episodes') a(value)
            union select q.entity from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest
                and q.pin=c.pin and q.episode_key in(select a.value#>>'{}' from jsonb_array_elements(touched) a(value))
            union select ce.entity from current_entities ce
        ) all_entities;
    elsif mode='qualified_denial' then
        if not public.password_v2_keys(payload,array['version','episode_key','predecessor','endpoint'])
            or jsonb_typeof(payload->'episode_key') is distinct from 'string'
            or payload->>'episode_key' !~ '^[a-f0-9]{64}$' then
            raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
        select a.value into old_e from jsonb_array_elements(c.state_document->'episodes') a(value)
            where a.value->>'key'=payload->>'episode_key';
        if old_e is null or old_e->>'sequence'='0' or old_e->'frozen'<>'false'::jsonb then
            raise exception 'password_v2_denial_unproved' using errcode='55000'; end if;
        entities:=array[old_e->>'entity']; touched:=jsonb_build_array(payload->'episode_key');
        next_st:=c.state_document; next_epoch:=c.coverage_epoch; f:=c.watermark; diag:='{}';
    else raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;

    if cardinality(entities)>10000 then raise exception 'password_v2_context_bound' using errcode='54000'; end if;
    -- Never acquire a missing ENTITY lock after callers may have staged ledger UPDATEs.
    foreach k in array entities loop perform public.password_v2_require_entity_lock(c.scope_digest,c.pin,k); end loop;
    perform 1 from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and (q.episode_key in(select a.value#>>'{}' from jsonb_array_elements(touched) a(value))
            or q.episode_key in(select a.value->>'key' from jsonb_array_elements(next_st->'episodes') a(value))
            or (mode='advance' and q.barrier_unresolved and q.entity=any(entities)))
        order by q.episode_key for update;

    if mode='qualified_denial' then
        select q.* into l from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=payload->>'episode_key';
        if not found or l.scope_json is distinct from s or l.execution_json is distinct from execution
            or l.last_sequence<=0 or l.frozen or old_e->>'entity' is distinct from l.entity
            or old_e->'seed' is distinct from l.seed or old_e->>'root_id' is distinct from l.root_id
            or old_e->>'last_emission' is distinct from l.last_emission_id
            or (old_e->>'sequence')::integer<>l.last_sequence or old_e->'budget' is distinct from public.password_v2_totals(l)
            or old_e->'last' is distinct from l.last_admitted_endpoint
            or payload->'predecessor' is distinct from l.last_admitted_endpoint then
            raise exception 'password_v2_denial_unproved' using errcode='55000'; end if;
        perform public.password_v2_check_witness(payload->'endpoint',s);
        if payload#>>'{endpoint,ref,native_id}'=payload#>>'{predecessor,ref,native_id}'
            or (public.password_v2_time(payload#>'{endpoint,at}'),(payload#>>'{endpoint,ref,native_id}')::bigint)
                <=(public.password_v2_time(payload#>'{predecessor,at}'),(payload#>>'{predecessor,ref,native_id}')::bigint)
            or public.password_v2_time(payload#>'{endpoint,at}')>public.password_v2_time(payload#>'{predecessor,at}')+interval '600 seconds'
            or public.password_v2_time(payload#>'{endpoint,at}')>stamp-interval '120 seconds' then
            raise exception 'password_v2_denial_unproved' using errcode='55000'; end if;
        pair_bytes:=public.password_v2_native_cost(s,jsonb_build_array(payload->'predecessor',payload->'endpoint'));
        if l.reserved_ref_occurrences+2<=10000 and l.reserved_portions+1<=256 and l.reserved_xml_bytes+pair_bytes<=33554432 then
            raise exception 'password_v2_denial_unproved' using errcode='55000'; end if;
        e:=jsonb_set(jsonb_set(old_e,'{frozen}','true'),'{last}',payload->'endpoint');
        select jsonb_set(next_st,'{episodes}',jsonb_agg(case when a.value->>'key'=l.episode_key then e else a.value end order by a.ord))
            into next_st from jsonb_array_elements(next_st->'episodes') with ordinality a(value,ord);
        diag:=jsonb_build_object('episode_evidence_budget_exhausted',jsonb_build_object('count',1,'from',null,'to',null));
    end if;

    -- State is trusted working data, but its native commitments are not caller cost authority.
    -- Deduplicate exact same-pass needs; lifetime occurrence charges stay in reservation.
    if mode='advance' then
        select coalesce(jsonb_agg(needed.w order by needed.w#>>'{ref,native_id}'),'[]'::jsonb) into witnesses from (
            select distinct a.value->'witness' as w from jsonb_array_elements(next_st->'window') a(value)
            union select a.value->'seed' from jsonb_array_elements(next_st->'episodes') a(value)
            union select a.value->'last' from jsonb_array_elements(next_st->'episodes') a(value)
            union select p.value from jsonb_array_elements(next_st->'episodes') a(value)
                cross join lateral jsonb_array_elements(a.value->'prequalification') p(value)
            union select q.tracking_endpoint from public.semantic_password_episode_budgets q
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
        ) needed;
        actual:=public.password_v2_native_cost(s,witnesses);
    end if;

    for e in select a.value from jsonb_array_elements(next_st->'episodes') a(value) loop
        if e->>'sequence'='0' then
            if e->'frozen'<>'false'::jsonb or e->'budget'<>jsonb_build_object('ref_occurrences',0,'portions',0,'xml_bytes',0)
                or e->>'key'<>public.password_v2_episode_key(c.pin,next_epoch,e->>'entity',e->'seed') then
                raise exception 'password_v2_state_ledger_conflict' using errcode='55000'; end if;
            continue;
        end if;
        select q.* into l from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=e->>'key';
        if not found or l.scope_json is distinct from s or l.execution_json is distinct from execution
            or e->>'entity' is distinct from l.entity or e->'seed' is distinct from l.seed
            or e->>'root_id' is distinct from l.root_id or e->>'last_emission' is distinct from l.last_emission_id
            or (e->>'sequence')::integer<>l.last_sequence or e->'budget' is distinct from public.password_v2_totals(l)
            or (e->'frozen'='false'::jsonb and (l.frozen or l.coverage_epoch<>next_epoch
                or e->'last' is distinct from l.last_admitted_endpoint)) then
            raise exception 'password_v2_state_ledger_conflict' using errcode='55000'; end if;
        if e->'frozen'='true'::jsonb and not l.frozen then
            select a.value into old_e from jsonb_array_elements(c.state_document->'episodes') a(value) where a.value->>'key'=l.episode_key;
            if old_e is null or old_e->>'sequence'='0' or old_e->'budget' is distinct from public.password_v2_totals(l)
                or old_e->>'last_emission' is distinct from l.last_emission_id then
                raise exception 'password_v2_freeze_conflict' using errcode='55000'; end if;
            update public.semantic_password_episode_budgets q set frozen=true,frozen_at=stamp,
                frozen_reason='episode_evidence_budget_exhausted',barrier_unresolved=true,
                tracking_endpoint=e->'last',tracking_epoch=next_epoch,
                tracking_through=case when mode='advance' then f else public.password_v2_time(e#>'{last,at}') end
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=l.episode_key;
        end if;
    end loop;

    if mode='advance' then
        for l in select q.* from public.semantic_password_episode_budgets q
            where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
            order by q.episode_key loop
            track_endpoint:=l.tracking_endpoint; tracked:=false;
            -- EXACT structural Member.entity(Rule), using trusted typed working
            -- fields. This never reads/parses/classifies native XML in SQL.
            for w in select m.value->'witness' from jsonb_array_elements(next_st->'window') m(value)
                where m.value->'reason'='null'::jsonb and m.value->'failure'<>'null'::jsonb
                    and m.value->'client_key'<>'null'::jsonb and m.value->'target_key'<>'null'::jsonb
                    and (case when execution->>'rule_id'='qw.password-spray'
                        then case when m.value->>'client_kind'='ip' then m.value->>'client_key' else null end
                        else encode(sha256(convert_to(public.password_v2_json_compact(jsonb_build_array(
                            m.value->'client_kind',m.value->'client_key',m.value->'target_key')),'UTF8')),'hex') end)=l.entity
                    and public.password_v2_time(m.value#>'{witness,at}') between lower_bound and f
                    and (c.watermark is null or public.password_v2_time(m.value#>'{witness,at}')>c.watermark)
                    and (public.password_v2_time(m.value#>'{witness,at}'),(m.value#>>'{witness,ref,native_id}')::bigint)
                        >(public.password_v2_time(track_endpoint->'at'),(track_endpoint#>>'{ref,native_id}')::bigint)
                order by public.password_v2_time(m.value#>'{witness,at}'),(m.value#>>'{witness,ref,native_id}')::bigint loop
                -- A first genuine quiet gap remains provisional until actual
                -- successor admission. Never freeze an immutable speculative K.
                if not tracked and l.tracking_epoch=next_epoch and lower_bound<=l.tracking_through
                    and public.password_v2_time(w->'at')>public.password_v2_time(track_endpoint->'at')+interval '600 seconds' then
                    exit;
                end if;
                perform public.track_password_frozen_entity_v2(s,execution,attempt_token,expected_revision,
                    l.episode_key,w,next_epoch,lower_bound,f);
                track_endpoint:=w; tracked:=true;
            end loop;
            if not tracked then
                perform public.track_password_frozen_entity_v2(s,execution,attempt_token,expected_revision,
                    l.episode_key,track_endpoint,next_epoch,lower_bound,f);
            end if;
        end loop;
    end if;

    -- Reuse the existing bounded DB-observation buckets. The token is observed once.
    if diag<>'{}'::jsonb then
        perform public.observe_password_failure_v2(s,execution,attempt_token,diag);
    end if;
    stamp:=clock_timestamp();
    select exists(select 1 from public.semantic_password_episode_budgets q
        where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved) into unresolved;
    update public.semantic_password_checkpoints q set state_document=next_st,state_revision=c.state_revision+1,
        watermark=f,coverage_epoch=next_epoch,history_started=true,last_observed_token=attempt_token,last_completed_at=stamp,
        last_successful_cutoff=case when mode='advance' then f else q.last_successful_cutoff end,
        health_status=case when unresolved or mode='qualified_denial' or diag<>'{}'::jsonb then 'partial' else 'healthy' end,
        health_reason=case when unresolved or mode='qualified_denial' then 'episode_evidence_budget_exhausted'
            when diag<>'{}'::jsonb then 'recent_loss' else null end
        where q.scope_digest=c.scope_digest and q.pin=c.pin;
    delete from public.semantic_password_window_members q where q.scope_digest=c.scope_digest and q.pin=c.pin;
    insert into public.semantic_password_window_members(scope_digest,pin,member_document)
        select c.scope_digest,c.pin,a.value from jsonb_array_elements(next_st->'window') a(value);
    select q.* into c from public.semantic_password_checkpoints q where q.scope_digest=c.scope_digest and q.pin=c.pin;
    perform public.password_v2_assert_checkpoint(c);
    -- Independent deferred admission hooks still cover omitted touched keys/all new sequences.
    for l in select q.* from public.semantic_password_episode_budgets q where q.scope_digest=c.scope_digest and q.pin=c.pin
        and (q.admission_xid=pg_current_xact_id() or q.episode_key in(select a.value->>'key' from jsonb_array_elements(next_st->'episodes') a(value)))
        order by q.episode_key loop perform public.password_v2_assert_episode(l); end loop;
    select coalesce(jsonb_agg(a.value->'key' order by a.value->>'key'),'[]'::jsonb) into frozen_keys
        from jsonb_array_elements(next_st->'episodes') a(value) where a.value->'frozen'='true'::jsonb;
    return jsonb_build_object('status','staged','revision',c.state_revision,'watermark',public.password_v2_iso(c.watermark),
        'epoch',c.coverage_epoch,'frozen_episode_keys',frozen_keys,'health',public.password_v2_health(c,stamp));
end $$;

revoke all on function public.password_v2_require_entity_lock(bytea,text,text),
    public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[]),
    public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.prepare_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text[]),
    public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb) to adlog_semantic_worker;
do $$ begin
    if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        cross join lateral aclexplode(coalesce(p.proacl,'{}'::aclitem[])) a where n.nspname='public'
        and p.proname=any(array['password_v2_require_entity_lock','prepare_password_producer_batch_v2','complete_password_producer_batch_v2'])
        and a.grantee<>p.proowner and not(a.grantee='adlog_semantic_worker'::regrole and a.privilege_type='EXECUTE'
            and not a.is_grantable and p.proname in('prepare_password_producer_batch_v2','complete_password_producer_batch_v2'))) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
end $$;


-- Explicit owner metadata; no source issuer, native proof or inferred domain.
alter table public.sli_agent_module_bindings add column password_detection_domain_id bigint
    references public.domains(id) on delete restrict,
    add constraint password_v2_live_domain_only check(password_detection_domain_id is null or module_id='sli.windows.ad-dc');
alter table public.semantic_password_checkpoints add column owner_domain_id bigint
    references public.domains(id) on delete restrict;
create index password_v2_owned_checkpoints on public.semantic_password_checkpoints(owner_domain_id,scope_digest,pin)
    where owner_domain_id is not null;
do $$ declare prior text; begin
    select pg_get_expr(conbin,conrelid) into strict prior from pg_constraint
        where conrelid='public.sli_agent_audit'::regclass and conname='sli_agent_audit_action_check';
    alter table public.sli_agent_audit drop constraint sli_agent_audit_action_check;
    execute format('alter table public.sli_agent_audit add constraint sli_agent_audit_action_check check ((%s) or action=''password_domain_bind'')',prior);
end $$;

create function public.password_v2_owner_immutable() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin
    if tg_table_name='sli_agent_module_bindings' then
        if old.password_detection_domain_id is not null and new.password_detection_domain_id is distinct from old.password_detection_domain_id then
            raise exception 'password_v2_ownership_immutable' using errcode='55000'; end if;
    elsif old.owner_domain_id is not null and new.owner_domain_id is distinct from old.owner_domain_id then
        raise exception 'password_v2_ownership_immutable' using errcode='55000'; end if;
    return new;
end $$;
create trigger password_v2_domain_immutable before update on public.sli_agent_module_bindings
    for each row execute function public.password_v2_owner_immutable();
create trigger password_v2_cp_owner_immutable before update on public.semantic_password_checkpoints
    for each row execute function public.password_v2_owner_immutable();

create function public.password_v2_configured_identity(p_agent uuid) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare a public.sli_agents%rowtype; m public.sli_agent_module_bindings%rowtype; assignment jsonb;
    n bigint; installation uuid; s jsonb;
begin
    select * into a from public.sli_agents where id=p_agent;
    select * into m from public.sli_agent_module_bindings where agent_id=p_agent and module_id='sli.windows.ad-dc';
    if a.id is null or a.status<>'active' or m.agent_id is null or jsonb_typeof(a.assigned_modules) is distinct from 'array' then return null; end if;
    select count(*) into n from jsonb_array_elements(a.assigned_modules) v
        where v->>'module_id'='sli.windows.ad-dc';
    if n<>1 then return null; end if;
    select v into assignment from jsonb_array_elements(a.assigned_modules) v where v->>'module_id'='sli.windows.ad-dc';
    if assignment->'enabled' is distinct from 'true'::jsonb
       or jsonb_typeof(assignment->'config') is distinct from 'object'
       or jsonb_typeof(assignment#>'{config,source_name}') is distinct from 'string'
       or jsonb_typeof(assignment#>'{config,connect_address}') is distinct from 'string'
       or length(assignment#>>'{config,connect_address}')=0
       or jsonb_typeof(assignment#>'{config,policy_revision}') is distinct from 'string'
       or assignment#>>'{config,policy_revision}' !~ '^[1-9][0-9]{0,15}$'
       or jsonb_typeof(assignment#>'{config,channels}') is distinct from 'object'
       or jsonb_typeof(assignment#>'{config,channel_generations}') is distinct from 'object'
       or m.source_instance_id is distinct from a.host_id::text
       or m.source_name is distinct from assignment#>>'{config,source_name}'
       or m.policy_revision is distinct from assignment#>>'{config,policy_revision}'
       or m.channel<>'ad-dc' or m.module_version<>'1.0.0' then return null; end if;
    select count(*) into n from public.semantic_default_installation;
    if n<>1 then return null; end if;
    select installation_id into installation from public.semantic_default_installation;
    if installation is null then return null; end if;
    -- All live principal copies of this canonical source must agree on residual native identity.
    select count(distinct (f.agent_id,f.log_source_id)) into n
    from public.finding_evidence_source_bindings f join pg_roles r on r.oid=f.principal_oid and r.rolname=f.principal_name
    where f.installation_id=installation and f.plugin_id=m.module_id and f.source_instance_id=m.source_instance_id
      and f.source_generation=m.source_instance_id and f.collection_scope_id='' and f.storage_kind='core_event';
    if n<>1 then return null; end if;
    -- DISTINCT is allowed only after proving equality; no latest/first authority choice.
    select distinct jsonb_build_object('installation_id',f.installation_id::text,'plugin_id',f.plugin_id,
        'source_instance_id',f.source_instance_id,'source_generation',f.source_generation,'collection_scope_id',f.collection_scope_id) into s
    from public.finding_evidence_source_bindings f join pg_roles r on r.oid=f.principal_oid and r.rolname=f.principal_name
    where f.installation_id=installation and f.plugin_id=m.module_id and f.source_instance_id=m.source_instance_id
      and f.source_generation=m.source_instance_id and f.collection_scope_id='' and f.storage_kind='core_event'
      and f.agent_id=p_agent and f.log_source_id>0 and f.agent_key is null;
    if s is null then return null; end if;
    return jsonb_build_object('scope',s,'domain_id',m.password_detection_domain_id,'issued_revision',m.policy_revision);
end $$;

create function public.password_v2_coverage_execution(s jsonb,rule text) returns jsonb
language sql immutable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('version','sli.qw.execution.v1','kind','threshold','rule_id',rule,'rule_version',2,'scope',s,
        'rule_sha256',encode(sha256(convert_to(public.password_v2_json_compact(jsonb_build_object(
        'contract','sli.password.v2.phase-a.1','rule',rule,'window',600,'inclusive',true,
        'threshold',case when rule='qw.password-brute-force' then 10 else 5 end,'holdback',120,'horizon',720,
        'rows',10000,'lifetime_refs',10000,'lifetime_portions',256,'lifetime_xml_bytes',33554432,
        'classification','bad-unknown-other/native-v1','client','native-ip-mapped-or-explicit-workstation/v1',
        'late','drop-finalized/v1','gap','new-epoch/v1','continuity','native-adjacency/v1')),'UTF8')),'hex'))
$$;

create function public.provision_password_detection_domain_v2(p_agent uuid,p_revision bigint,p_expected_domain bigint,p_fqdn text,p_actor text)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare a public.sli_agents%rowtype; m public.sli_agent_module_bindings%rowtype; context jsonb; rechecked jsonb;
    s jsonb; digest bytea; domain bigint; pin_value text; adopted bigint;
begin
    if p_agent is null or p_revision is null or p_revision<1 or p_revision>9007199254740991
       or (p_expected_domain is not null and p_expected_domain<=0) or p_fqdn is null or length(p_fqdn)>253
       or p_fqdn !~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$' or p_actor is null
       or p_actor !~ '^(session|api_key):[1-9][0-9]*$' or length(p_actor)>128 then
        raise exception 'password_v2_domain_arguments_invalid' using errcode='22023'; end if;
    select * into a from public.sli_agents where id=p_agent for update;
    if a.id is null or a.status<>'active' then return jsonb_build_object('status','unavailable','domain_id',null,'domain_fqdn',null); end if;
    if a.policy_revision<>p_revision then raise exception 'password_v2_revision_conflict' using errcode='40001'; end if;
    context:=public.password_v2_configured_identity(p_agent);
    if context is null then return jsonb_build_object('status','unavailable','domain_id',null,'domain_fqdn',null); end if;
    select id into domain from public.domains where lower(fqdn)=p_fqdn;
    if domain is null or (select count(*) from public.domains where lower(fqdn)=p_fqdn)<>1 then
        raise exception 'password_v2_domain_unknown' using errcode='22023'; end if;
    s:=context->'scope'; digest:=public.password_v2_scope_key(s);
    perform pg_advisory_xact_lock(hashtextextended(encode(digest,'hex'),0));
    select * into m from public.sli_agent_module_bindings where agent_id=p_agent and module_id='sli.windows.ad-dc' for update;
    rechecked:=public.password_v2_configured_identity(p_agent);
    if rechecked is distinct from context then raise exception 'password_v2_domain_conflict' using errcode='40001'; end if;
    if m.password_detection_domain_id is distinct from p_expected_domain then
        raise exception 'password_v2_domain_conflict' using errcode='40001'; end if;
    if m.password_detection_domain_id is not null and m.password_detection_domain_id<>domain then
        raise exception 'password_v2_ownership_immutable' using errcode='55000'; end if;
    -- Stable pin ordering matches the source->checkpoint worker order.
    for pin_value in select encode(sha256(convert_to(public.password_v2_json_compact(public.password_v2_coverage_execution(s,r)),'UTF8')),'hex')
        from unnest(array['qw.password-brute-force','qw.password-spray']) r order by 1 loop
        perform 1 from public.semantic_password_checkpoints c where c.scope_digest=digest and c.pin=pin_value for update;
    end loop;
    if exists(select 1 from public.semantic_password_checkpoints c where c.scope_digest=digest
        and c.scope_json=s and c.execution_json=public.password_v2_coverage_execution(s,c.execution_json->>'rule_id')
        and c.owner_domain_id is not null and c.owner_domain_id<>domain) then
        raise exception 'password_v2_ownership_immutable' using errcode='55000'; end if;
    update public.semantic_password_checkpoints c set owner_domain_id=domain where c.scope_digest=digest
        and c.scope_json=s and c.execution_json=public.password_v2_coverage_execution(s,c.execution_json->>'rule_id')
        and c.execution_json->>'rule_id' in ('qw.password-brute-force','qw.password-spray')
        and c.pin=encode(sha256(convert_to(public.password_v2_json_compact(c.execution_json),'UTF8')),'hex') and c.owner_domain_id is null;
    get diagnostics adopted=row_count;
    if m.password_detection_domain_id is not null and adopted=0 then
        return jsonb_build_object('status','unchanged','domain_id',domain,'domain_fqdn',p_fqdn); end if;
    update public.sli_agent_module_bindings set password_detection_domain_id=domain where agent_id=p_agent and module_id='sli.windows.ad-dc';
    insert into public.sli_agent_audit(action,actor,target,details) values('password_domain_bind',p_actor,p_agent::text,
        jsonb_build_object('old_domain_id',m.password_detection_domain_id,'new_domain_id',domain,'scope',s,'expected_revision',p_revision,'issued_revision',m.policy_revision,'adopted_checkpoints',adopted));
    return jsonb_build_object('status','configured','domain_id',domain,'domain_fqdn',p_fqdn);
end $$;

create function public.password_v2_coverage_policy(x jsonb) returns text
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    -- Exact execution custom-ID disable precedence is the existing262 rule.
    if exists(select 1 from public.semantic_risk_policies p left join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=x
          and (a.enabled is false or p.lifecycle_status in ('disabled','deprecated'))) then return 'disabled'; end if;
    if exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        join public.semantic_risk_policy_subscriptions sub using(policy_id,policy_version)
        where p.source_kind='qw_signal' and sub.source_kind='qw_signal' and p.definition_json#>'{source_selector,execution}'=x
          and sub.selector_value=x->>'rule_id' and sub.definition_sha256=p.definition_sha256
          and p.definition_sha256=sha256(convert_to(public.password_v2_json_compact(p.definition_json),'UTF8'))
          and a.enabled and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled') then return 'enabled'; end if;
    return 'unknown';
end $$;

create function public.read_password_detection_coverage(allowed_domains bigint[]) returns jsonb
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
declare stamp timestamptz:=statement_timestamp(); m record; context jsonb;
    item record; c public.semantic_password_checkpoints%rowtype; health jsonb;
    policy text; status text; reason text; frozen_count bigint; snapshot timestamptz; rows_json jsonb:='[]'::jsonb; n integer:=0;
begin
    if allowed_domains is null or exists(select 1 from unnest(allowed_domains) d where d is null or d<=0) then
        raise exception 'password_v2_domain_arguments_invalid' using errcode='22023'; end if;
    if cardinality(allowed_domains)=0 then return jsonb_build_object('as_of',public.password_v2_iso(stamp),'rows',rows_json,'has_more',false); end if;
    for m in select agent_id,password_detection_domain_id from public.sli_agent_module_bindings
        where module_id='sli.windows.ad-dc' and password_detection_domain_id=any(allowed_domains) loop
        context:=public.password_v2_configured_identity(m.agent_id);
        if context is null then raise exception 'password_v2_coverage_metadata_unavailable' using errcode='55000'; end if;
    end loop;
    for item in with current_rows as (
        select module.password_detection_domain_id as domain_id,ctx.identity->'scope' as scope,
            public.password_v2_coverage_execution(ctx.identity->'scope',rules.rule_id) as execution,true as current_scope
        from public.sli_agent_module_bindings module
        cross join lateral (select public.password_v2_configured_identity(module.agent_id) as identity) ctx
        cross join unnest(array['qw.password-brute-force','qw.password-spray']) rules(rule_id)
        where module.module_id='sli.windows.ad-dc' and module.password_detection_domain_id=any(allowed_domains)
    ), candidates as (
        select * from current_rows union all
        select cp.owner_domain_id,cp.scope_json,cp.execution_json,false from public.semantic_password_checkpoints cp
        where cp.owner_domain_id=any(allowed_domains)
          and exists(select 1 from public.semantic_password_episode_budgets l where l.scope_digest=cp.scope_digest and l.pin=cp.pin and l.barrier_unresolved)
    ), keyed as (
        select *,public.password_v2_scope_key(scope) as digest,
            encode(sha256(convert_to(public.password_v2_json_compact(execution),'UTF8')),'hex') as pin_value
        from candidates
    ), dedup as (
        select distinct on(domain_id,digest,pin_value) * from keyed order by domain_id,digest,pin_value,current_scope desc
    ) select *,encode(sha256(digest||decode(pin_value,'hex')),'hex') as scope_ref from dedup
      order by domain_id,execution->>'rule_id',scope_ref limit 257 loop
        n:=n+1; if n>256 then exit; end if;
        select cp.* into c from public.semantic_password_checkpoints cp where cp.scope_digest=item.digest and cp.pin=item.pin_value
            and cp.scope_json=item.scope and cp.execution_json=item.execution and cp.owner_domain_id=item.domain_id;
        policy:=case when item.current_scope then public.password_v2_coverage_policy(item.execution) else 'unknown' end;
        if c.pin is null then
            health:=jsonb_build_object('last_attempt_at',null,'last_completed_at',null,'last_successful_cutoff',null,'loss','{}'::jsonb);
            status:='unknown'; reason:='checkpoint_absent'; frozen_count:=0; snapshot:=null;
        else
            perform public.password_v2_assert_checkpoint(c);
            health:=public.password_v2_health(c,stamp); status:=health->>'status'; reason:=health->>'reason';
            select count(*),max(l.last_admitted_as_of) into frozen_count,snapshot from public.semantic_password_episode_budgets l
                where l.scope_digest=c.scope_digest and l.pin=c.pin and l.scope_json=c.scope_json and l.execution_json=c.execution_json and l.barrier_unresolved;
        end if;
        if policy='unknown' and status='healthy' then status:='unknown'; reason:='policy_unconfirmed'; end if;
        if policy='unknown' and c.pin is null then reason:='policy_unconfirmed'; end if;
        if frozen_count>0 then status:='frozen'; reason:='episode_evidence_budget_exhausted'; end if;
        if reason is not null and public.password_v2_diagnostic(reason) is not true and reason not in ('attempt_stale','recent_loss','checkpoint_absent','policy_unconfirmed') then
            raise exception 'password_v2_coverage_metadata_unavailable' using errcode='55000'; end if;
        rows_json:=rows_json||jsonb_build_array(jsonb_build_object('domain_id',item.domain_id,'rule_id',item.execution->>'rule_id',
            'scope_ref',item.scope_ref,'policy_state',policy,'status',status,'reason',reason,
            'last_attempt_at',health->'last_attempt_at','last_completed_at',health->'last_completed_at',
            'last_successful_cutoff',health->'last_successful_cutoff','loss',health->'loss',
            'frozen_episode_count',frozen_count,'evidence_snapshot_as_of',public.password_v2_iso(snapshot)));
    end loop;
    return jsonb_build_object('as_of',public.password_v2_iso(stamp),'rows',rows_json,'has_more',n>256);
end $$;

revoke all on function public.password_v2_owner_immutable(),public.password_v2_configured_identity(uuid),
    public.password_v2_coverage_execution(jsonb,text),public.password_v2_coverage_policy(jsonb),
    public.provision_password_detection_domain_v2(uuid,bigint,bigint,text,text),public.read_password_detection_coverage(bigint[])
    from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
grant execute on function public.provision_password_detection_domain_v2(uuid,bigint,bigint,text,text),
    public.read_password_detection_coverage(bigint[]) to adlog_user;
do $$ begin
    if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        cross join lateral aclexplode(coalesce(p.proacl,'{}'::aclitem[])) a where n.nspname='public'
        and p.proname in('password_v2_owner_immutable','password_v2_configured_identity','password_v2_coverage_execution',
            'password_v2_coverage_policy','provision_password_detection_domain_v2','read_password_detection_coverage')
        and a.grantee<>p.proowner and not(a.grantee='adlog_user'::regrole and a.privilege_type='EXECUTE'
            and not a.is_grantable and p.proname in('provision_password_detection_domain_v2','read_password_detection_coverage'))) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
end $$;

set local search_path=pg_catalog,pg_temp;
do $$
declare f record; role_name text;
begin
    foreach role_name in array array['adlog_user','adlog_storage_worker','adlog_semantic_worker'] loop
        if pg_has_role(role_name,'adlog_storage_owner','MEMBER') then
            raise exception 'password_v2_private_role_inheritance' using errcode='42501'; end if;
    end loop;
    for f in select p.oid,p.proname,p.proowner,p.proacl from pg_proc p
        join pg_namespace n on n.oid=p.pronamespace where n.nspname='public' and p.proname=any(array[
            'password_v2_json_compact','password_v2_json_bytes','password_v2_keys','password_v2_uint',
            'password_v2_iso','password_v2_time','password_v2_identity','password_v2_check_witness',
            'password_v2_check_state','password_v2_assert_checkpoint','password_v2_locked_checkpoint',
            'password_v2_diagnostic','password_v2_health','begin_password_attempt','read_password_checkpoint_v2',
            'commit_password_state_v2','observe_password_failure_v2']) loop
        execute format('revoke all on function %s from public,adlog_user,adlog_storage_worker,adlog_semantic_worker',f.oid::regprocedure);
        if f.proname=any(array['begin_password_attempt','read_password_checkpoint_v2','commit_password_state_v2','observe_password_failure_v2']) then
            execute format('grant execute on function %s to adlog_semantic_worker',f.oid::regprocedure);
        end if;
    end loop;
    -- Explicit revokes are not an assumption about inherited/default ACLs:
    -- unexpected grants on these NEW private objects abort the migration.
    if exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace
        cross join lateral aclexplode(coalesce(c.relacl,'{}'::aclitem[])) a
        where n.nspname='public' and c.relname in ('semantic_password_checkpoints','semantic_password_window_members','semantic_password_attempt_seq')
          and a.grantee<>c.relowner) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
    if exists(select 1 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
        cross join lateral aclexplode(coalesce(p.proacl,'{}'::aclitem[])) a
        where n.nspname='public' and p.proname=any(array[
            'password_v2_json_compact','password_v2_json_bytes','password_v2_keys','password_v2_uint','password_v2_iso',
            'password_v2_time','password_v2_identity','password_v2_check_witness','password_v2_check_state',
            'password_v2_assert_checkpoint','password_v2_locked_checkpoint','password_v2_diagnostic','password_v2_health',
            'begin_password_attempt','read_password_checkpoint_v2','commit_password_state_v2','observe_password_failure_v2'])
          and a.grantee<>p.proowner and not(a.grantee='adlog_semantic_worker'::regrole
              and p.proname=any(array['begin_password_attempt','read_password_checkpoint_v2','commit_password_state_v2','observe_password_failure_v2'])
              and a.privilege_type='EXECUTE' and not a.is_grantable)) then
        raise exception 'password_v2_private_acl_unexpected' using errcode='42501'; end if;
end $$;

insert into public.schema_migrations(version,name) values(273,'password_attacks_v2');
commit;
