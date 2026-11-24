begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_password_checkpoint_proof403'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=409 and name='password_checkpoint_continuity')
       or exists(select 1 from public.schema_migrations where version>=410) then
        raise exception 'password_origin_prefix410_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create table public.password_origin_prefix410(
    scope_digest bytea not null, pin text not null, episode_key text not null,
    revision bigint not null check(revision>0), coverage_epoch bigint not null check(coverage_epoch>=0),
    witnesses jsonb not null check(jsonb_typeof(witnesses)='array' and jsonb_array_length(witnesses) between 1 and 10000),
    primary key(scope_digest,pin,episode_key),
    foreign key(scope_digest,pin) references public.semantic_password_checkpoints(scope_digest,pin)
);
revoke all on public.password_origin_prefix410 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create function public.password_assert_origin_prefix410(c public.semantic_password_checkpoints)
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
begin
    if c.execution_json->>'rule_id' is distinct from 'qw.password-brute-force' then return; end if;
    if exists (
        with active as (
            select a.e->>'key' as episode_key,
                case when a.e ? 'witnesses' then a.e->'witnesses'->(a.e->>'seed')::integer else a.e->'seed' end as seed,
                case when a.e ? 'witnesses' then a.e->'witnesses'->(a.e#>>'{prequalification,0}')::integer
                    else a.e->'prequalification'->0 end as first,
                case when a.e ? 'witnesses' then a.e->'witnesses'->(a.e#>>'{prequalification,-1}')::integer
                    else a.e->'prequalification'->-1 end as last,
                case when a.e ? 'witnesses' then a.e->'witnesses'->(a.e->>'last')::integer else a.e->'last' end as endpoint
            from jsonb_array_elements(c.state_document->'episodes') a(e)
            where a.e->>'sequence'='0' and a.e->'frozen'='false'::jsonb
        ), prefixes as (
            select p.* from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin
        )
        select 1 from active a full join prefixes p using(episode_key)
        where a.episode_key is null or (a.first is distinct from a.seed)<>(p.episode_key is not null)
            or (p.episode_key is not null and (
                p.revision<>c.state_revision or p.coverage_epoch<>c.coverage_epoch
                or p.witnesses->0 is distinct from a.seed
                or a.first is null or a.last is distinct from a.endpoint
                or (public.password_v2_time(p.witnesses->-1->'at'),(p.witnesses->-1#>>'{ref,native_id}')::bigint)>=
                    (public.password_v2_time(a.first->'at'),(a.first#>>'{ref,native_id}')::bigint)
                or public.password_v2_time(a.first->'at')-
                    public.password_v2_time(p.witnesses->-1->'at')>interval '600 seconds'
            ))
    ) then raise exception 'password_v2_checkpoint_corrupt' using errcode='55000'; end if;
end $$;

create function public.read_password_checkpoint410(s jsonb,execution jsonb)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare c public.semantic_password_checkpoints%rowtype;
begin
    c:=public.password_v2_locked_checkpoint(s,execution,false);
    if c.pin is null then raise exception 'password_v2_checkpoint_absent' using errcode='55000'; end if;
    return jsonb_build_object('state_revision',c.state_revision,'state_document',c.state_document,
        'watermark',public.password_v2_iso(c.watermark),'epoch',c.coverage_epoch,'active_token',c.active_token,
        'last_observed_token',c.last_observed_token,'health',public.password_v2_health(c,clock_timestamp()),
        'origin_prefixes',coalesce((select jsonb_agg(p.episode_key order by p.episode_key collate "C")
            from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin),'[]'::jsonb));
end $$;

create function public.read_password_origin_prefix410(s jsonb,execution jsonb,attempt_token bigint,expected_revision bigint,p_key text,p_offset integer)
returns jsonb language plpgsql volatile security definer set search_path=pg_catalog,pg_temp as $$
declare identity jsonb; digest bytea; pin_id text; full_prefix jsonb; part jsonb; total integer;
begin
    identity:=public.password_v2_identity(s,execution);
    digest:=decode(identity->>'scope_digest','hex'); pin_id:=identity->>'pin';
    perform pg_advisory_xact_lock(hashtextextended(identity->>'scope_digest',0));
    -- The full checkpoint reader validated the state. Bind each bounded
    -- page to the same locked source, pin, attempt and revision.
    select p.witnesses into full_prefix from public.semantic_password_checkpoints c
    join public.password_origin_prefix410 p on p.scope_digest=c.scope_digest and p.pin=c.pin
        and p.revision=c.state_revision and p.coverage_epoch=c.coverage_epoch
    where c.scope_digest=digest and c.pin=pin_id and c.scope_json=s and c.execution_json=execution
        and c.state_revision=expected_revision and c.active_token=attempt_token and c.last_observed_token<attempt_token
        and p.episode_key=p_key for update of c;
    if full_prefix is null then
        raise exception 'password_v2_attempt_conflict' using errcode='55000'; end if;
    total:=jsonb_array_length(full_prefix);
    if p_offset is null or p_offset<0 or p_offset>=total then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;
    select jsonb_agg(w order by n) into part from jsonb_array_elements(full_prefix) with ordinality a(w,n)
        where n>p_offset and n<=p_offset+512;
    if octet_length(part::text)>4194304 then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
    return jsonb_build_object('total',total,'witnesses',part);
end $$;

-- Any extension must start with the entire authoritative old origin, including
-- its inline suffix. Extra witnesses have to be new decisions after its fence.
create function public.password_check_origin_extension410(old_origin jsonb,next_origin jsonb,watermark timestamptz)
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
begin
    if jsonb_typeof(next_origin) is distinct from 'array' or jsonb_array_length(next_origin)<jsonb_array_length(old_origin)
       or exists(select 1 from jsonb_array_elements(next_origin) with ordinality a(w,n)
           where case when n<=jsonb_array_length(old_origin) then a.w is distinct from old_origin->(n::integer-1)
               else public.password_v2_time(a.w->'at')<=watermark
                 or public.password_v2_time(a.w->'at')-
                     public.password_v2_time(next_origin->(n::integer-2)->'at')>interval '600 seconds' end)
    then raise exception 'password_v2_origin_prefix_conflict' using errcode='55000'; end if;
end $$;

create function public.password_check_origin_admission410(c public.semantic_password_checkpoints,em jsonb)
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare prefix jsonb; old_episode jsonb;
begin
    select p.witnesses into prefix from public.password_origin_prefix410 p
        where p.scope_digest=c.scope_digest and p.pin=c.pin and p.episode_key=em->>'episode_key';
    if not found then return; end if;
    select a.value into strict old_episode from public.password_state_episodes385(c.state_document-'closed_admissions') a(value)
        where a.value->>'key'=em->>'episode_key';
    if em->'seed' is distinct from old_episode->'seed' or em->>'entity' is distinct from old_episode->>'entity'
       or em->'epoch' is distinct from to_jsonb(c.coverage_epoch) then
        raise exception 'password_v2_origin_prefix_conflict' using errcode='55000';
    end if;
    perform public.password_check_origin_extension410(prefix||(old_episode->'prequalification'),em->'origin',c.watermark);
end $$;

-- Charge every spilled native witness again. Units are dynamically packed,
-- independently bounded, and checked by the same native verifier as 409.
create function public.password_verify_origins410(c public.semantic_password_checkpoints,st jsonb,entities text[])
returns void language plpgsql stable set search_path=pg_catalog,pg_temp as $$
declare proof jsonb; conflicted boolean;
begin
    if not exists(select 1 from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin) then return; end if;
    for proof,conflicted in
        with archives as materialized (
            select distinct a.w from public.password_origin_prefix410 p
            cross join lateral jsonb_array_elements(p.witnesses) a(w)
            where p.scope_digest=c.scope_digest and p.pin=c.pin
        ), active as materialized (
            select a.value from public.password_state_episodes385(st) a(value)
        ), obligations as (
            select w from archives
            union select value->'seed' from active
            union select value->'last' from active
            union select b.w from active cross join lateral jsonb_array_elements(value->'prequalification') b(w)
            union select value->'witness' from jsonb_array_elements(st->'window')
            union select q.tracking_endpoint from public.semantic_password_episode_budgets q
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.barrier_unresolved and q.entity=any(entities)
        ), exact_ids as (
            select coalesce(count(*)<>count(distinct w#>>'{ref,native_id}'),false) as conflict from obligations
        ), numbered as (
            select w,w#>>'{ref,native_id}' as id,
                (row_number() over n-1)/10000 as ref_group,
                (sum((w->>'xml_bytes')::bigint) over n-(w->>'xml_bytes')::bigint)/29360128 as byte_group
            from archives window n as (order by (w#>>'{ref,native_id}') collate "C" rows unbounded preceding)
        )
        select jsonb_agg(n.w order by n.id collate "C"),i.conflict
        from numbered n cross join exact_ids i group by n.ref_group,n.byte_group,i.conflict
        order by n.ref_group,n.byte_group
    loop
        if conflicted then raise exception 'password_v2_native_content_conflict' using errcode='55000'; end if;
        perform public.password_v2_native_cost(c.scope_json,proof);
    end loop;
end $$;

create function public.password_sync_origin_prefix410(c public.semantic_password_checkpoints,st jsonb,mode text,
    f timestamptz,next_epoch bigint,entities text[])
returns void language plpgsql volatile set search_path=pg_catalog,pg_temp as $$
declare old_episode jsonb; next_episode jsonb; prefix jsonb; spill jsonb; keep jsonb; full_origin jsonb; admitted boolean;
begin
    if mode='qualified_denial' then
        update public.password_origin_prefix410 p set revision=c.state_revision+1
            where p.scope_digest=c.scope_digest and p.pin=c.pin;
        return;
    end if;
    for old_episode,next_episode,prefix in
        with previous as materialized (
            select a.value as e from public.password_state_episodes385(c.state_document-'closed_admissions') a(value)
            where a.value->>'sequence'='0' and a.value->'frozen'='false'::jsonb
        ), proposed as materialized (
            select a.value as e from public.password_state_episodes385(st-'closed_admissions') a(value)
        )
        select o.e,n.e,coalesce(p.witnesses,'[]'::jsonb) from previous o
        left join proposed n on n.e->>'entity'=o.e->>'entity'
        left join public.password_origin_prefix410 p
            on p.scope_digest=c.scope_digest and p.pin=c.pin and p.episode_key=o.e->>'key'
    loop
        if next_epoch<>c.coverage_epoch then continue; end if;
        if next_episode->>'key'=old_episode->>'key' and next_episode->>'sequence'='0' then
            select coalesce(jsonb_agg(w order by n) filter (where at<c.watermark-interval '600 seconds'),'[]'::jsonb),
                   coalesce(jsonb_agg(w order by n) filter (where at>=c.watermark-interval '600 seconds'),'[]'::jsonb)
                into spill,keep
                from (select w,n,public.password_v2_time(w->'at') as at
                    from jsonb_array_elements(old_episode->'prequalification') with ordinality a(w,n)) ordered;
            prefix:=prefix||spill;
            if prefix='[]'::jsonb then continue; end if;
            if next_episode->'seed' is distinct from old_episode->'seed' or next_episode->'frozen'<>'false'::jsonb
                or keep='[]'::jsonb then raise exception 'password_v2_origin_prefix_conflict' using errcode='55000'; end if;
            perform public.password_check_origin_extension410(keep,next_episode->'prequalification',c.watermark);
            full_origin:=prefix||(next_episode->'prequalification');
            if jsonb_array_length(full_origin)>10000 or
                (select sum((w->>'xml_bytes')::bigint) from jsonb_array_elements(full_origin) a(w))>33554432
            then raise exception 'password_v2_proof_budget_exceeded' using errcode='54000'; end if;
            insert into public.password_origin_prefix410(scope_digest,pin,episode_key,revision,coverage_epoch,witnesses)
                values(c.scope_digest,c.pin,old_episode->>'key',c.state_revision+1,c.coverage_epoch,prefix)
                on conflict(scope_digest,pin,episode_key) do update
                set revision=excluded.revision,witnesses=excluded.witnesses;
        elsif prefix<>'[]'::jsonb then
            select exists(select 1 from public.semantic_password_episode_budgets q
                where q.scope_digest=c.scope_digest and q.pin=c.pin and q.episode_key=old_episode->>'key'
                  and q.admission_xid=pg_current_xact_id() and q.admission_first_sequence=1
                  and q.last_sequence>0 and q.admitted_revision=c.state_revision+1) into admitted;
            if not admitted and (public.password_v2_time(old_episode#>'{last,at}')>=f-interval '600 seconds'
                or (next_episode is not null and public.password_v2_time(next_episode#>'{seed,at}')<=
                    public.password_v2_time(old_episode#>'{last,at}')+interval '600 seconds')) then
                raise exception 'password_v2_origin_prefix_conflict' using errcode='55000';
            end if;
        end if;
    end loop;
    -- Include prefixes retiring on this advance. Failure leaves both state
    -- and prefixes at the preceding revision.
    perform public.password_verify_origins410(c,st,entities);
    delete from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin
        and p.revision=c.state_revision;
end $$;

revoke all on function public.password_assert_origin_prefix410(public.semantic_password_checkpoints),
    public.read_password_checkpoint410(jsonb,jsonb),public.read_password_origin_prefix410(jsonb,jsonb,bigint,bigint,text,integer),
    public.password_check_origin_extension410(jsonb,jsonb,timestamptz),
    public.password_check_origin_admission410(public.semantic_password_checkpoints,jsonb),
    public.password_verify_origins410(public.semantic_password_checkpoints,jsonb,text[]),
    public.password_sync_origin_prefix410(public.semantic_password_checkpoints,jsonb,text,timestamptz,bigint,text[])
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.read_password_checkpoint410(jsonb,jsonb),
    public.read_password_origin_prefix410(jsonb,jsonb,bigint,bigint,text,integer) to adlog_semantic_worker;

create table public.password_origin_restore410(
    signature regprocedure primary key,definition text not null,owner_oid oid not null,acl aclitem[],
    installed_definition text);
revoke all on public.password_origin_restore410 from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
insert into public.password_origin_restore410(signature,definition,owner_oid,acl)
select oid,pg_get_functiondef(oid),proowner,proacl from pg_proc
where oid in (
    'public.password_v2_assert_checkpoint(public.semantic_password_checkpoints)'::regprocedure,
    'public.read_password_checkpoint_v2(jsonb,jsonb)'::regprocedure,
    'public.reserve_password_episode_emission(jsonb,jsonb,bigint,bigint,jsonb,jsonb)'::regprocedure,
    'public.complete_password_producer_batch_v2(jsonb,jsonb,bigint,bigint,text,jsonb)'::regprocedure
) and proowner='adlog_storage_owner'::regrole and provolatile='v'
  and proconfig=array['search_path=pg_catalog, pg_temp'];

do $patch$
declare saved record; replacements jsonb; replacement jsonb; old_text text; new_text text; body text; at integer;
begin
    for saved in select * from public.password_origin_restore410 loop
        if saved.signature='public.password_v2_assert_checkpoint(public.semantic_password_checkpoints)'::regprocedure then
            replacements:=jsonb_build_array(jsonb_build_array(
                '    if checked=to_jsonb(c) then return; end if;',
                E'    perform public.password_assert_origin_prefix410(c);\n    if checked=to_jsonb(c) then return; end if;'));
        elsif saved.signature='public.read_password_checkpoint_v2(jsonb,jsonb)'::regprocedure then
            replacements:=jsonb_build_array(jsonb_build_array(
                E'    return jsonb_build_object(\'state_revision\',c.state_revision,\'state_document\',c.state_document,',
                $legacy_read$    if exists(select 1 from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin) then
        raise exception 'password_v2_origin_prefix_reader_required' using errcode='55000'; end if;
    return jsonb_build_object('state_revision',c.state_revision,'state_document',c.state_document,$legacy_read$));
        elsif saved.signature='public.reserve_password_episode_emission(jsonb,jsonb,bigint,bigint,jsonb,jsonb)'::regprocedure then
            replacements:=jsonb_build_array(jsonb_build_array(
                $reserve$    p_key:=em->>'episode_key'; seq:=(em->>'sequence')::integer;$reserve$,
                $guard$    p_key:=em->>'episode_key'; seq:=(em->>'sequence')::integer;
    if seq=1 then perform public.password_check_origin_admission410(c,em); end if;$guard$));
        else
            replacements:=jsonb_build_array(jsonb_build_array(
                $old_version$    if payload->>'version' is distinct from 'sli.password.v2.producer-batch.1' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023'; end if;$old_version$,
                $prefix_version$    if payload->>'version'='sli.password.v2.producer-batch.410' and execution->>'rule_id'='qw.password-brute-force' then
        null;
    elsif payload->>'version' is distinct from 'sli.password.v2.producer-batch.1' then
        raise exception 'password_v2_arguments_invalid' using errcode='22023';
    elsif exists(select 1 from public.password_origin_prefix410 p where p.scope_digest=c.scope_digest and p.pin=c.pin) then
        raise exception 'password_v2_origin_prefix_reader_required' using errcode='55000';
    end if;$prefix_version$),
                jsonb_build_array(E'    stamp:=clock_timestamp();\n    select exists(select 1 from public.semantic_password_episode_budgets q',
                $sync$    if payload->>'version'='sli.password.v2.producer-batch.410' then
        perform public.password_sync_origin_prefix410(c,next_st,mode,f,next_epoch,entities);
    end if;
    stamp:=clock_timestamp();
    select exists(select 1 from public.semantic_password_episode_budgets q$sync$));
        end if;
        body:=saved.definition;
        for replacement in select value from jsonb_array_elements(replacements) loop
            old_text:=replacement->>0; new_text:=replacement->>1;
            at:=strpos(body,old_text);
            if at=0 or strpos(substr(body,at+length(old_text)),old_text)<>0 then
                raise exception 'password_origin_prefix410_shape: %',saved.signature using errcode='55000';
            end if;
            body:=replace(body,old_text,new_text);
        end loop;
        execute body;
        if not exists(select 1 from pg_proc p where p.oid=saved.signature and p.proowner=saved.owner_oid
            and p.proacl is not distinct from saved.acl) then
            raise exception 'password_origin_prefix410_metadata' using errcode='55000';
        end if;
        update public.password_origin_restore410 r set installed_definition=pg_get_functiondef(saved.signature)
            where r.signature=saved.signature;
    end loop;
    if (select count(*) from public.password_origin_restore410)<>4 then
        raise exception 'password_origin_prefix410_metadata' using errcode='55000';
    end if;
end $patch$;

reset role;
insert into public.schema_migrations(version,name) values(410,'password_origin_prefix');
commit;
