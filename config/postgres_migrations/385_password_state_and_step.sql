begin;
select pg_advisory_xact_lock(hashtext('sli_password_state_and_step385'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=384 and name='password_commit_cost')
       or exists(select 1 from public.schema_migrations where version>=385) then
        raise exception 'password_state_and_step385_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;
create table public.password_restore385(signature text primary key,definition text not null,installed_definition text,
    owner_oid oid not null,acl aclitem[]);
revoke all on public.password_restore385 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_restore385(signature,definition,owner_oid,acl)
select oid::regprocedure::text,pg_get_functiondef(oid),proowner,proacl from pg_proc where oid=any(array[
    'public.password_v2_check_state(jsonb,jsonb,text)'::regprocedure,
    'public.password_v2_assert_episode(public.semantic_password_episode_budgets)'::regprocedure,
    'public.password_v2_deferred()'::regprocedure,
    'public.track_password_frozen_entity_v2(jsonb,jsonb,bigint,bigint,text,jsonb,bigint,timestamp with time zone,timestamp with time zone)'::regprocedure,
    'public.password_v2_state_ledger_complete()'::regprocedure,
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure,
    'public.password_event_clock362(jsonb,jsonb)'::regprocedure,
    'public.read_password_event_window362(jsonb,jsonb)'::regprocedure]);
do $$ begin
    if exists(select 1 from public.password_restore385 where owner_oid<>'adlog_storage_owner'::regrole) then
        raise exception 'password_state_and_step385_owner' using errcode='55000'; end if;
end $$;

-- Only the checkpoint encoding changes. Expand every indexed witness before
-- the existing shape, native, ancestry, budget and ledger checks see it.
create function public.password_state_episodes385(st jsonb) returns setof jsonb
language plpgsql immutable set search_path=pg_catalog,pg_temp as $$
declare e jsonb; refs jsonb; w jsonb; k text; origin jsonb; indexes jsonb; n integer;
begin
    for e in select a.value from jsonb_array_elements((st->'episodes')||coalesce(st->'closed_admissions','[]'::jsonb)) a(value) loop
        if e ? 'witnesses' then
            refs:=e->'witnesses';
            if not public.password_v2_keys(e,array['budget','entity','frozen','key','last','last_emission','prequalification','root_id','seed','sequence','witnesses'])
               or jsonb_typeof(refs) is distinct from 'array' or jsonb_typeof(e->'prequalification') is distinct from 'array' then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
            n:=jsonb_array_length(refs);
            if n<1 or n>10000 or jsonb_array_length(e->'prequalification')>10000 then
                raise exception 'password_v2_state_bound' using errcode='54000'; end if;
            indexes:=jsonb_build_array(e->'seed',e->'last')||(e->'prequalification');
            for w in select a.value from jsonb_array_elements(indexes) a(value) loop
                if not public.password_v2_uint(w,n-1) then
                    raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
            end loop;
            if (select count(distinct a.value) from jsonb_array_elements(indexes) a(value))<>n
               or (select count(distinct a.value) from jsonb_array_elements(refs) a(value))<>n then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
            select coalesce(jsonb_agg(refs->(a.value#>>'{}')::integer order by a.ord),'[]'::jsonb) into origin
                from jsonb_array_elements(e->'prequalification') with ordinality a(value,ord);
            foreach k in array array['seed','last'] loop e:=jsonb_set(e,array[k],refs->(e->>k)::integer); end loop;
            e:=jsonb_set(e-'witnesses','{prequalification}',origin);
        end if;
        return next e;
    end loop;
end $$;
revoke all on function public.password_state_episodes385(jsonb) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $$ declare r record; body text; begin
    for r in select * from public.password_restore385
        where signature not in ('password_event_clock362(jsonb,jsonb)','read_password_event_window362(jsonb,jsonb)') loop
        body:=r.definition;
        if r.signature='password_v2_check_state(jsonb,jsonb,text)' then
            body:=replace(body,'declare m jsonb;', 'declare stored jsonb:=st; closed385 jsonb; seen385 text[]:=array[]::text[]; m jsonb;');
            body:=replace(body,E'begin\n    if not public.password_v2_keys(st',
                $expand$begin
    if octet_length(stored::text)>4194304 then raise exception 'password_v2_state_bound' using errcode='54000'; end if;
    if st ? 'closed_admissions' then
        if jsonb_typeof(st->'closed_admissions') is distinct from 'array'
           or jsonb_array_length(st->'episodes')+jsonb_array_length(st->'closed_admissions')>10000 then
            raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
        -- A long slice may admit several episodes of one entity. Expired
        -- admissions still carry their full checkpoint proof for this COMMIT;
        -- they are never active continuity state in the following batch.
        for closed385 in select expanded.value from public.password_state_episodes385(
            jsonb_build_object('episodes',st->'closed_admissions')) expanded(value) loop
            if closed385->>'sequence'='0' or closed385->'frozen' is distinct from 'false'::jsonb
               or closed385->'prequalification' is distinct from '[]'::jsonb
               or st->'watermark'='null'::jsonb
               or public.password_v2_time(closed385#>'{last,at}')>=public.password_v2_time(st->'watermark')-interval '600 seconds'
               or closed385->>'key'=any(seen385)
               or exists(select 1 from jsonb_array_elements(st->'episodes') active(value) where active.value->>'key'=closed385->>'key') then
                raise exception 'password_v2_state_invalid' using errcode='22023'; end if;
            perform public.password_v2_check_state(jsonb_set(jsonb_set(st-'closed_admissions','{window}','[]'::jsonb),
                '{episodes}',jsonb_build_array(closed385)),s,p_pin);
            seen385:=array_append(seen385,closed385->>'key');
        end loop;
        st:=st-'closed_admissions';
    end if;
    st:=jsonb_set(st,'{episodes}',(select coalesce(jsonb_agg(expanded.value),'[]'::jsonb) from public.password_state_episodes385(st) expanded(value)));
    if not public.password_v2_keys(st$expand$);
            body:=replace(body,'octet_length(st::text)>4194304','octet_length(stored::text)>4194304');
            body:=replace(body,'public.password_v2_json_bytes(st);','public.password_v2_json_bytes(stored);');
        else
            body:=replace(body,'jsonb_array_elements(c.state_document->''episodes'')','public.password_state_episodes385(c.state_document)');
            body:=replace(body,'jsonb_array_elements(next_st->''episodes'')','public.password_state_episodes385(next_st)');
            if r.signature='complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)' then
                -- Qualified denial can freeze only an active episode. Keep
                -- expired confirmations separate when replacing that episode.
                body:=replace(body,E'public.password_state_episodes385(c.state_document) a(value)\n            where a.value->>''key''=payload->>''episode_key'';',
                    E'public.password_state_episodes385(c.state_document-''closed_admissions'') a(value)\n            where a.value->>''key''=payload->>''episode_key'';');
                body:=replace(body,'into next_st from public.password_state_episodes385(next_st) with ordinality',
                    'into next_st from jsonb_array_elements(next_st->''episodes'') with ordinality');
            end if;
        end if;
        if r.signature like 'track_password_frozen_entity_v2(%' then
            body:=replace(body,'or covered_from<finalized_through-interval ''600 seconds''',
                'or (covered_from<finalized_through-interval ''600 seconds'' and
                    (covered_from is distinct from public.password_read_from385(s,execution,finalized_through+interval ''120 seconds'')
                     or finalized_through is distinct from public.password_event_clock362(s,execution)-interval ''120 seconds''))');
        end if;
        if body=r.definition then raise exception 'password_state_and_step385_state_shape:%',r.signature using errcode='55000'; end if;
        execute body;
    end loop;
end $$;

-- 215 decisions/minute * 28 minutes = 6020. With the 600s history and
-- 120s holdback this is about 8600 native rows, below the unchanged 10000 /
-- 32MiB gates. The old stand batch cost ~125s: 1800/125=14.4x before
-- eliminating inter-cycle waits. The local six-hour test measures actual cost.
do $$ declare body text; begin
    select definition into strict body from public.password_restore385 where signature='password_event_clock362(jsonb,jsonb)';
    if strpos(body,'decision_members integer:=1495')=0 or strpos(body,'cutoff+interval ''600 seconds'' else first_at+interval ''480 seconds''')=0 then
        raise exception 'password_state_and_step385_clock_shape' using errcode='55000'; end if;
    body:=replace(body,'decision_members integer:=1495','decision_members integer:=6000');
    body:=replace(body,'cutoff+interval ''600 seconds'' else first_at+interval ''480 seconds''',
        'cutoff+interval ''1800 seconds'' else first_at+interval ''1800 seconds''');
    execute body;
end $$;

create function public.password_read_from385(s jsonb,execution jsonb,t timestamptz) returns timestamptz
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select greatest(t-interval '2520 seconds',least(t-interval '720 seconds',
        coalesce((select c.watermark-interval '600 seconds' from public.semantic_password_checkpoints c
            where c.scope_digest=public.password_v2_scope_key(s) and c.pin=public.password_v2_identity(s,execution)->>'pin'),
            t-interval '2520 seconds')))
$$;
revoke all on function public.password_read_from385(jsonb,jsonb,timestamptz) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

do $$ declare body text; begin
    select definition into strict body from public.password_restore385 where signature='read_password_event_window362(jsonb,jsonb)';
    if strpos(body,'t-interval ''720 seconds''')=0 then raise exception 'password_state_and_step385_reader_shape' using errcode='55000'; end if;
    execute replace(body,'t-interval ''720 seconds''','public.password_read_from385(s,execution,t)');
    select pg_get_functiondef('public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure) into body;
    if strpos(body,'lower_bound<>t-interval ''720 seconds''')=0 then raise exception 'password_state_and_step385_finalizer_shape' using errcode='55000'; end if;
    execute replace(body,'lower_bound<>t-interval ''720 seconds''','lower_bound is distinct from public.password_read_from385(s,execution,t)');
end $$;

update public.password_restore385 d set installed_definition=pg_get_functiondef(d.signature::regprocedure);
do $$ begin
    if exists(select 1 from public.password_restore385 d join pg_proc p on p.oid=d.signature::regprocedure
        where p.proowner is distinct from d.owner_oid or p.proacl is distinct from d.acl) then
        raise exception 'password_state_and_step385_metadata_changed' using errcode='55000'; end if;
end $$;
insert into public.schema_migrations(version,name) values(385,'password_state_and_step');
reset role;
commit;
