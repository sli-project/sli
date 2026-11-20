begin;
select pg_advisory_xact_lock(hashtext('sli_password_live_first388'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=387 and name='password_window_capacity')
       or exists(select 1 from public.schema_migrations where version>=388) then
        raise exception 'password_live_first388_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
create table public.password_restore388(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.password_restore388 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore388(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_v2_identity(jsonb,jsonb)'::regprocedure,
    'public.password_v2_managed(jsonb)'::regprocedure,
    'public.password_v2_decode(jsonb,jsonb,jsonb)'::regprocedure,
    'public.password_v2_qw_allowed(text,text,jsonb)'::regprocedure,
    'public.password_policy_ensure_v275(text,integer,text)'::regprocedure,
    'public.ensure_default_qw_policy(text,integer,text)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.password_read_from385(jsonb,jsonb,timestamp with time zone)'::regprocedure,
    'public.enqueue_qw_finding_notifications(uuid)'::regprocedure]);

-- Every fork is immutable. The previous checkpoint, its native overlap, token,
-- episode reservations and deferred checks stay in place. Execution revisions
-- distinguish independent proof chains, including a later restart during catch-up.
create table public.password_passes388(
    scope_digest bytea not null,previous_pin text not null,live_pin text not null,
    live_execution jsonb not null,previous_watermark timestamptz,history_from timestamptz not null,
    live_from timestamptz not null,created_at timestamptz not null default clock_timestamp(),
    actor text not null default session_user,
    primary key(scope_digest,previous_pin),unique(scope_digest,live_pin),
    foreign key(scope_digest,previous_pin) references public.semantic_password_checkpoints(scope_digest,pin),
    foreign key(scope_digest,live_pin) references public.semantic_password_checkpoints(scope_digest,pin) deferrable initially deferred,
    check(history_from<=live_from),check(previous_pin<>live_pin));
revoke all on public.password_passes388 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create function public.password_pass_immutable388() returns trigger
language plpgsql set search_path=pg_catalog,pg_temp as $$
begin raise exception 'password_pass_immutable388' using errcode='55000'; end $$;
revoke all on function public.password_pass_immutable388() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
create trigger password_pass_immutable388 before update or delete or truncate on public.password_passes388
    for each statement execute function public.password_pass_immutable388();

create function public.password_execution388(s jsonb,r text,revision integer) returns jsonb
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare x jsonb; definition jsonb;
begin
    if revision<2 or r not in('qw.password-brute-force','qw.password-spray') then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    if revision=2 then return public.password_v2_coverage_execution(s,r); end if;
    definition:=jsonb_build_object('contract','sli.password.v2.live.'||revision,'rule',r,'window',600,'inclusive',true,
        'threshold',case when r='qw.password-brute-force' then 10 else 5 end,'holdback',120,'horizon',720,
        'rows',10000,'lifetime_refs',10000,'lifetime_portions',256,'lifetime_xml_bytes',33554432,
        'classification','bad-unknown-other/native-v1','client','native-ip-mapped-or-explicit-workstation/v1',
        'late','drop-finalized/v1','gap','new-epoch/v1','continuity','native-adjacency/v1');
    x:=public.password_v2_coverage_execution(s,r);
    return x||jsonb_build_object('rule_version',revision,
        'rule_sha256',encode(sha256(convert_to(public.password_v2_json_compact(definition),'UTF8')),'hex'));
end $$;
revoke all on function public.password_execution388(jsonb,text,integer) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

-- Retain the complete existing identity, native, ancestry, suffix, reservation,
-- window and deferred journal checks. Only admit the exact new execution codec.
do $$ declare r record; body text; begin
    for r in select * from public.password_restore388 where signature not in
        ('password_event_clock362(jsonb,jsonb)','password_read_from385(jsonb,jsonb,timestamp with time zone)',
         'enqueue_qw_finding_notifications(uuid)') loop
        if r.owner_oid<>'adlog_storage_owner'::regrole then raise exception 'password_live_first388_owner' using errcode='55000'; end if;
        body:=r.definition;
        case r.signature
        when 'password_v2_identity(jsonb,jsonb)' then
            body:=replace(body,'x->>''rule_version'' is distinct from ''2''',
                '(not public.password_v2_uint(x->''rule_version'',2147483647) or (x->>''rule_version'')::numeric<2)');
            body:=replace(body,'    if jsonb_typeof(x->''rule_sha256'')',
                E'    if (x->>''rule_version'')::integer>2 then definition:=jsonb_set(definition,''{contract}'',to_jsonb(''sli.password.v2.live.''||(x->>''rule_version''))); end if;\n    if jsonb_typeof(x->''rule_sha256'')');
            body:=replace(body,'    return jsonb_build_object(''scope_digest''',
                E'    if (x->>''rule_version'')::integer>2 and not exists(select 1 from public.password_passes388 p where p.scope_digest=public.password_v2_scope_key(s) and p.live_execution=x) then raise exception ''password_pass_unregistered388'' using errcode=''55000''; end if;\n    return jsonb_build_object(''scope_digest''');
        when 'password_v2_managed(jsonb)' then
            body:=replace(body,'d->>''rule_version''=''2''','d->''rule_version''>=''2''::jsonb');
        when 'password_v2_decode(jsonb,jsonb,jsonb)' then
            body:=replace(body,'d->''rule_version'' is distinct from ''2''::jsonb','d->''rule_version'' is distinct from x->''rule_version''');
        when 'password_v2_qw_allowed(text,text,jsonb)' then
            body:=replace(body,'d->>''rule_version''<>''2''','not public.password_v2_uint(d->''rule_version'',2147483647) or (d->>''rule_version'')::numeric<2');
        when 'password_policy_ensure_v275(text,integer,text)' then
            body:=replace(body,'public.password_v2_coverage_execution(s,r)',
                'public.password_execution388(s,r,(x->>''rule_version'')::integer)');
        when 'ensure_default_qw_policy(text,integer,text)' then
            body:=replace(body,'pin->>''rule_version''=''2''','public.password_v2_uint(pin->''rule_version'',2147483647) and (pin->>''rule_version'')::numeric>=2');
        else raise exception 'password_live_first388_signature' using errcode='55000';
        end case;
        if body=r.definition then raise exception 'password_live_first388_shape:%',r.signature using errcode='55000'; end if;
        execute body;
    end loop;
end $$;

create function public.password_plan388(s jsonb,r text) returns jsonb
language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints; fresh public.semantic_password_checkpoints; x jsonb; next_x jsonb;
    started timestamptz; effective timestamptz; backlog jsonb;
begin
    -- Same global order as configuration/publication: family, policy rows,
    -- source, checkpoint. This transaction never requests an entity lock.
    perform public.password_policy_family_lock_v275(s,r);
    perform 1 from public.semantic_risk_policies p where p.source_kind='qw_signal'
        and p.definition_json#>'{source_selector,execution,scope}'=s
        and p.definition_json#>>'{source_selector,execution,rule_id}'=r order by p.policy_id,p.policy_version for update;
    perform pg_advisory_xact_lock(hashtextextended(encode(public.password_v2_scope_key(s),'hex'),0));
    if public.password_source_ready_v314(s) is not true then return null; end if;
    select p.live_execution into x from public.password_passes388 p where p.scope_digest=public.password_v2_scope_key(s)
        and p.live_execution->>'rule_id'=r order by (p.live_execution->>'rule_version')::integer desc limit 1;
    x:=coalesce(x,public.password_v2_coverage_execution(s,r));
    c:=public.password_v2_locked_checkpoint(s,x,true);
    effective:=c.watermark;
    if effective is null then
        select p.live_from into effective from public.password_passes388 p
            where p.scope_digest=c.scope_digest and p.live_pin=c.pin;
    end if;
    if effective is null then
    select min(h.time_created_utc) into effective from public.event_hot h
        where h.source_sha256 is not null and h.method->>'$channel'='Security'
        and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
        and (h.method->'$origin')-'agent_id'-'log_source_id'=s
        and h.event_kind in(4624,4625,4771,4776);
    end if;
    -- 600s rule window plus the rule's existing 120s holdback. Never advance
    -- an old checkpoint to skip its history; it becomes a finite catch-up pass.
    if effective<statement_timestamp()-interval '720 seconds' then
        started:=statement_timestamp()-interval '600 seconds';
        next_x:=public.password_execution388(s,r,(x->>'rule_version')::integer+1);
        insert into public.password_passes388(scope_digest,previous_pin,live_pin,live_execution,
            previous_watermark,history_from,live_from)
            values(c.scope_digest,c.pin,encode(sha256(convert_to(public.password_v2_json_compact(next_x),'UTF8')),'hex'),
                next_x,c.watermark,coalesce(c.watermark,effective),started);
        fresh:=public.password_v2_locked_checkpoint(s,next_x,true);
        insert into public.semantic_control_audit(actor,action,target,details)
            values('system:password-producer','password_live_first',fresh.pin,jsonb_build_object(
                'db_actor',session_user,'scope',s,'rule',r,'previous_pin',c.pin,'live_pin',fresh.pin,
                'previous_watermark',public.password_v2_iso(c.watermark),'history_from',public.password_v2_iso(coalesce(c.watermark,effective)),
                'live_from',public.password_v2_iso(started),'at',public.password_v2_iso(clock_timestamp())));
        x:=next_x;
    end if;
    select coalesce(jsonb_agg(q.execution_json order by p.created_at),'[]'::jsonb) into backlog
        from public.password_passes388 p join public.semantic_password_checkpoints q
        on q.scope_digest=p.scope_digest and q.pin=p.previous_pin
        where p.scope_digest=c.scope_digest and p.live_execution->>'rule_id'=r
        and (q.watermark is null or q.watermark<p.live_from);
    return jsonb_build_object('live',x,'catchup',backlog);
end $$;
revoke all on function public.password_plan388(jsonb,text) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.password_plan388(jsonb,text) to adlog_semantic_worker;

-- The live bootstrap includes 600s BEFORE its start. A threshold reached on
-- either side of the seam is consequently evaluated in a complete rule window.
do $$ declare body text; begin
    select definition into strict body from public.password_restore388 where signature='password_read_from385(jsonb,jsonb,timestamp with time zone)';
    body:=replace(body,'t-interval ''2520 seconds'')))',
        '(select p.live_from-interval ''600 seconds'' from public.password_passes388 p where p.scope_digest=public.password_v2_scope_key(s) and p.live_pin=public.password_v2_identity(s,execution)->>''pin''),t-interval ''2520 seconds'')))');
    if body=(select definition from public.password_restore388 where signature='password_read_from385(jsonb,jsonb,timestamp with time zone)') then
        raise exception 'password_live_first388_lower_shape' using errcode='55000'; end if;
    execute body;
    select definition into strict body from public.password_restore388 where signature='password_event_clock362(jsonb,jsonb)';
    body:=replace(body,'    select min(e.time_created_utc)', $clock$
    select least(final_target,p.live_from) into final_target from (select 1) seed
        left join public.password_passes388 p on p.scope_digest=decode(identity->>'scope_digest','hex') and p.previous_pin=identity->>'pin';
    if cutoff>=final_target then return cutoff+interval '120 seconds'; end if;
    select coalesce(cutoff,p.live_from) into cutoff from (select 1) seed
        left join public.password_passes388 p on p.scope_digest=decode(identity->>'scope_digest','hex') and p.live_pin=identity->>'pin';
    select min(e.time_created_utc)$clock$);
    if body=(select definition from public.password_restore388 where signature='password_event_clock362(jsonb,jsonb)') then
        raise exception 'password_live_first388_clock_shape' using errcode='55000'; end if;
    execute body;
end $$;

create function public.password_catchup_status388() returns jsonb
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select case when count(*)=0 then null else jsonb_build_object(
        'from',public.password_v2_iso(min(p.history_from)),'to',public.password_v2_iso(max(p.live_from)),
        'cursor',public.password_v2_iso(min(coalesce(c.watermark,p.history_from))),
        'heartbeat',public.password_v2_iso(max(c.last_completed_at))) end
    from public.password_passes388 p join public.semantic_password_checkpoints c
        on c.scope_digest=p.scope_digest and c.pin=p.previous_pin
    where c.watermark is null or c.watermark<p.live_from
$$;
revoke all on function public.password_catchup_status388() from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.password_catchup_status388() to adlog_user,adlog_semantic_worker;

create function public.password_is_catchup388(x jsonb) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select exists(select 1 from public.password_passes388 p where p.scope_digest=public.password_v2_scope_key(x->'scope')
        and p.previous_pin=encode(sha256(convert_to(public.password_v2_json_compact(x),'UTF8')),'hex'))
$$;
revoke all on function public.password_is_catchup388(jsonb) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.password_is_catchup388(jsonb) to adlog_semantic_worker;

-- Multiple independently proved scenarios of the same rule/entity publish to
-- one finding. Each immutable scenario/publication link and its proof remain.
alter table public.semantic_finding_publications drop constraint semantic_finding_publications_finding_id_key;
alter table public.semantic_finding_publications drop constraint semantic_finding_publications_finding_fingerprint_key;
create index password_publication_finding388 on public.semantic_finding_publications(finding_id);
create index password_finding_entity388 on public.semantic_security_scenarios(partition_key,scenario_kind,(strict_keys_json->>'entity'))
    where scenario_kind in('qw.password-brute-force','qw.password-spray');

-- Dedupe overlap using exact native references and the current delivery binding.
-- The existing admission gate, queue lock and subscription locks remain in force.
do $$ declare body text;
    declaration text:='    contextual boolean;';
    subscription_lock text:='    perform 1 from public.notification_subscriptions where enabled order by id for share;';
    existing_count text:=$count$select distinct recipient_user_id,channel from public.notification_subscriptions s
        where enabled and not exists ($count$;
    candidates text:=$candidates$from (select distinct on(recipient_user_id,channel) * from public.notification_subscriptions
          where enabled order by recipient_user_id,channel,id) s$candidates$;
    eligible text:='where not (s.id=any(blocked_subscriptions))';
begin
    select definition into strict body from public.password_restore388 where signature='enqueue_qw_finding_notifications(uuid)';
    if strpos(body,declaration)=0 or strpos(body,subscription_lock)=0 or strpos(body,existing_count)=0
        or strpos(body,candidates||E'\n    on conflict')=0 then
        raise exception 'password_live_first388_notification_shape' using errcode='55000'; end if;
    body:=replace(body,declaration,'    blocked_subscriptions uuid[];'||E'\n'||declaration);
    body:=replace(body,subscription_lock,subscription_lock||$dedup$
    select coalesce(array_agg(distinct subscription.id),'{}'::uuid[]) into blocked_subscriptions
        from public.semantic_finding_publications current_publication
        join public.semantic_security_scenarios current_scenario using(scenario_id)
        join public.semantic_finding_publications prior_publication on prior_publication.finding_id=current_publication.finding_id
            and prior_publication.scenario_id<>current_publication.scenario_id
        join public.notification_outbox prior_delivery on prior_delivery.object_kind='semantic_finding'
            and prior_delivery.object_id=prior_publication.scenario_id and prior_delivery.change_key=delivery_key
            and prior_delivery.state in ('pending','sending','retry','accepted','delivery_unknown')
        join public.notification_subscriptions prior_subscription on prior_subscription.id=prior_delivery.subscription_id
            and prior_subscription.revision=prior_delivery.subscription_revision
            and prior_subscription.recipient_user_id=prior_delivery.recipient_user_id and prior_subscription.channel=prior_delivery.channel
            and prior_subscription.enabled
        join public.notification_subscriptions subscription on subscription.recipient_user_id=prior_subscription.recipient_user_id
            and subscription.channel=prior_subscription.channel and subscription.enabled
        join public.semantic_scenario_steps prior_step on prior_step.scenario_id=prior_publication.scenario_id
        join public.semantic_qw_signals prior_signal on prior_signal.signal_id=prior_step.qw_signal_id
        cross join lateral jsonb_array_elements(prior_signal.document_json->'evidence_refs') prior_ref
        join public.semantic_scenario_steps current_step on current_step.scenario_id=current_publication.scenario_id
        join public.semantic_qw_signals current_signal on current_signal.signal_id=current_step.qw_signal_id
        where current_publication.scenario_id=p_scenario_id
            and current_scenario.scenario_kind in ('qw.password-brute-force','qw.password-spray')
            and (current_signal.document_json->'evidence_refs') @> jsonb_build_array(prior_ref);
$dedup$);
    body:=replace(body,candidates||E'\n    on conflict',candidates||E'\n    '||eligible||E'\n    on conflict');
    body:=replace(body,existing_count,'select recipient_user_id,channel '||candidates||E'\n        '||eligible||' and not exists (');
    execute body;
end $$;

insert into public.password_restore388(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.attest_short_event337()'::regprocedure,'public.short_detection_sources337()'::regprocedure]);

-- Generic Event Log keeps its own evidence. The AD-only digest still marks
-- short rows admitted for domain detections and can be acquired on AD replay.
create function public.generic_short_event_proof388(p_packet uuid,p_ordinal integer,p_event bigint,
    p_at timestamptz,p_kind integer,p_domain bigint,p_method jsonb)
returns table(origin jsonb,record_id bigint)
language sql stable set search_path=pg_catalog,pg_temp as $$
    select jsonb_build_object('installation_id',installation.installation_id::text,
        'plugin_id','sli.windows-eventlog','source_instance_id',binding.source_instance_id,
        'source_generation',i.envelope->>'generation','collection_scope_id','',
        'agent_id',r.agent_id::text,'log_source_id',ls.id),
        a.event_record_id
    from public.sli_agent_packet_inbox i
    join public.sli_agent_receipts r on r.packet_id=i.packet_id and r.envelope=i.envelope
        and r.module_id='sli.windows-eventlog' and r.receipt->>'status'='committed'
    join public.sli_agents agent on agent.id=r.agent_id and agent.status='active'
    -- Ingress checks the exact policy revision before committing the receipt.
    -- A later policy revision does not invalidate that acknowledgement.
    join public.sli_agent_module_bindings binding on binding.agent_id=r.agent_id and binding.module_id=r.module_id
        and binding.source_instance_id=i.envelope->>'source_instance_id'
        and binding.module_version=i.envelope->>'module_version' and binding.channel=i.envelope->>'channel'
    join public.servers server on server.id::text=p_method->>'$server_id' and server.domain_id=p_domain
        and server.is_active and server.hostname=binding.source_name and server.hostname=i.packet#>>'{header,source}'
    join public.storage_v2_event_identity_allocations a on a.id=p_event and a.server_id=server.id and a.time_created_utc=p_at
    join public.storage_v2_channel ch on ch.id=a.channel_id and ch.value=binding.channel
    join public.log_sources ls on ls.name=ch.value
    join public.event_source_representations_v2 rep on rep.event_id=a.id and rep.normalized_hash=a.normalized_hash
    cross join lateral (select i.event_rows->p_ordinal as doc) native
    cross join lateral (select regexp_match(native.doc->>'time_created',
        '^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})\.([0-9]{6})([0-9]+)(Z|[+-][0-9]{2}:[0-9]{2})$') as parts) clock
    cross join public.semantic_default_installation installation
    where i.packet_id=p_packet and i.imported_at is not null and i.module_disabled_at is null
      and not exists(select 1 from public.sli_agent_packet_quarantine q where q.packet_id=i.packet_id)
      and public.agent_module_enabled_v380(r.module_id)
      and i.envelope->>'module_id'=r.module_id and i.envelope->>'agent_id'=r.agent_id::text
      and i.envelope->>'packet_id'=i.packet_id::text and i.envelope->>'payload_contract'='sli.collection-packet.v1'
      and nullif(i.envelope->>'generation','') is not null
      and (select count(*)=1 and bool_and(
               case jsonb_typeof(m) when 'string' then true else m->'enabled'='true'::jsonb end)
           from jsonb_array_elements(agent.assigned_modules) m
           where coalesce(m->>'module_id',m#>>'{}')=r.module_id)
      and ch.value=p_method->>'$channel'
      and p_ordinal>=0 and native.doc->>'xml'=rep.representation->>'xml'
      and native.doc->>'xml'=i.packet->'records'->p_ordinal->'payload'->>'xml'
      and native.doc->>'record_id'=a.event_record_id::text and native.doc->>'event_id'=p_kind::text
      and native.doc->>'channel'=ch.value and native.doc->>'computer_name'=binding.source_name
      and native.doc->>'time_created'=rep.representation->>'time_created'
      and (case when clock.parts is not null then
          (clock.parts[1]||clock.parts[4])::timestamptz
          + (clock.parts[2]::integer + case when left(clock.parts[3],1) in ('6','7','8','9')
              or left(clock.parts[3],1)='5' and (substr(clock.parts[3],2) ~ '[1-9]'
                  or clock.parts[2]::integer%2=1) then 1 else 0 end)*interval '1 microsecond'
          when pg_input_is_valid(native.doc->>'time_created','timestamp with time zone')
              then (native.doc->>'time_created')::timestamptz end)=p_at
      and rep.representation->>'provider_name'=p_method->>'$provider'
$$;
revoke all on function public.generic_short_event_proof388(uuid,integer,bigint,timestamptz,integer,bigint,jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $generic388$ declare old text; patched text; begin
    select pg_get_functiondef('public.attest_short_event337()'::regprocedure) into strict old;
    patched:=replace(old,
        $match$if found then new.method:=new.method||jsonb_build_object('$origin',origin);$match$,
        $replace$if not found then
        select proof.origin,proof.record_id into origin,record_id
        from public.generic_short_event_proof388(admission_packet::uuid,admission_ordinal::integer,
            new.event_id,new.time_created_utc,new.event_kind,new.domain_id,new.method) proof;
        if found then
            if tg_op='UPDATE' and old.method#>>'{$origin,plugin_id}'='sli.windows-eventlog' then
                origin:=old.method->'$origin';
            end if;
            new.method:=new.method||jsonb_build_object('$origin',origin);
            new.event_record_id:=record_id;
            return new;
        end if;
    end if;
    if found then new.method:=new.method||jsonb_build_object('$origin',origin);$replace$);
    if patched=old then raise exception 'generic_short_events388_attestation_shape' using errcode='55000'; end if;
    execute patched;

    select pg_get_functiondef('public.short_detection_sources337()'::regprocedure) into strict old;
    patched:=replace(old,$match$where h.source_sha256 is not null and public.semantic_source_active320$match$,
        $replace$where h.source_sha256 is not null and o->>'plugin_id'='sli.windows.ad-dc'
      and public.semantic_source_active320$replace$);
    if patched=old then raise exception 'generic_short_events388_discovery_shape' using errcode='55000'; end if;
    execute patched;
end $generic388$;

create function public.write_generic_short_events388(p_rows jsonb)
returns table(groups bigint,summaries bigint,attested bigint)
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    select written.groups,written.summaries into groups,summaries from public.write_short_events349(p_rows) written;
    select count(*) into attested
    from jsonb_array_elements(p_rows) j
    cross join lateral jsonb_populate_record(null::public.event_hot,j.value) r
    join public.event_hot h using(event_id,time_created_utc)
    cross join lateral public.generic_short_event_proof388(
        case when pg_input_is_valid(r.method->>'$packet_id','uuid') then (r.method->>'$packet_id')::uuid end,
        case when r.method->>'$packet_ordinal' ~ '^[0-9]{1,9}$' then (r.method->>'$packet_ordinal')::integer end,
        r.event_id,r.time_created_utc,r.event_kind,r.domain_id,r.method) proof
    where h.event_record_id=proof.record_id
      and (h.event_kind,h.domain_id,h.actor,h.target,h.source,h.computer,h.method-'$origin',h.outcome,h.fields)
          is not distinct from
          (r.event_kind,r.domain_id,r.actor,r.target,r.source,r.computer,r.method-'$origin'-'$packet_id'-'$packet_ordinal',r.outcome,r.fields);
    if attested<>jsonb_array_length(p_rows) then
        raise exception 'generic_short_event_attestation_failed' using errcode='55000'; end if;
    return next;
end $$;
revoke all on function public.write_generic_short_events388(jsonb)
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.write_generic_short_events388(jsonb) to adlog_user;

update public.password_restore388 d set installed_definition=pg_get_functiondef(d.signature::regprocedure);
do $$ begin
    if exists(select 1 from public.password_restore388 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_live_first388_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(388,'password_live_first');
reset role;
commit;
