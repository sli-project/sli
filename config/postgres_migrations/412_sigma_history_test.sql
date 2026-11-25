begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_sigma_history_test412'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=409 and name='password_checkpoint_continuity')
       or not exists(select 1 from public.schema_migrations where version=411 and name='password_successor_coverage')
       or exists(select 1 from public.schema_migrations where version>=412) then
        raise exception 'sigma_history_test412_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

create function public.sigma_test_scope_allowed411(s jsonb,p_kinds integer[]) returns boolean
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select coalesce(cardinality(p_kinds) between 1 and 3
        and p_kinds <@ array[4698,4702,7045] and array_position(p_kinds,null) is null
        and exists (
            select 1 from public.finding_evidence_source_bindings b
            join pg_roles r on r.oid=b.principal_oid and r.rolname=b.principal_name and r.rolname=session_user
            where b.storage_kind='core_event' and b.plugin_id='sli.windows.ad-dc' and b.collection_scope_id=''
              and b.installation_id::text=s->>'installation_id' and b.source_instance_id=s->>'source_instance_id'
              and b.source_generation=s->>'source_generation'
              and s=jsonb_build_object('installation_id',b.installation_id::text,'plugin_id',b.plugin_id,
                  'source_instance_id',b.source_instance_id,'source_generation',b.source_generation,
                  'collection_scope_id',b.collection_scope_id)
              and (not (p_kinds && array[4698,4702]) or public.semantic_source_active320(b.agent_id,b.plugin_id,'Security'))
              and (not (7045=any(p_kinds)) or public.semantic_source_active320(b.agent_id,b.plugin_id,'System'))
        ),false)
$$;
revoke all on function public.sigma_test_scope_allowed411(jsonb,integer[]) from public,adlog_user,adlog_storage_worker;
grant execute on function public.sigma_test_scope_allowed411(jsonb,integer[]) to adlog_semantic_worker;

create function public.sigma_test_candidates411(s jsonb,p_start timestamptz,p_end timestamptz,p_kinds integer[])
returns setof public.event_hot language sql stable set search_path=pg_catalog,pg_temp as $$
    select h.* from public.event_hot h
    where h.time_created_utc>=p_start and h.time_created_utc<p_end
      and h.method#>>'{$origin,source_instance_id}'=s->>'source_instance_id'
      and ((h.method->'$origin')-'agent_id'-'log_source_id')=s
      and h.event_kind=any(p_kinds) and h.source_sha256 is not null
      and h.method->>'$channel'=case when h.event_kind=7045 then 'System' else 'Security' end
$$;
revoke all on function public.sigma_test_candidates411(jsonb,timestamptz,timestamptz,integer[])
    from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;

create function public.sigma_test_ceiling411(s jsonb,p_start timestamptz,p_end timestamptz,p_kinds integer[])
returns bigint language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.sigma_test_scope_allowed411(s,p_kinds) then
        raise exception 'sigma_test_source_denied' using errcode='42501';
    end if;
    if p_start is null or p_end is null or not isfinite(p_start) or not isfinite(p_end) or p_start>=p_end
       or p_end>date_trunc('day',p_start,'UTC')+interval '24 hours' then
        raise exception 'sigma_test_snapshot_bounds' using errcode='22023';
    end if;
    return coalesce((select max(h.event_id) from public.sigma_test_candidates411(s,p_start,p_end,p_kinds) h),0);
end $$;
revoke all on function public.sigma_test_ceiling411(jsonb,timestamptz,timestamptz,integer[])
    from public,adlog_user,adlog_storage_worker;
grant execute on function public.sigma_test_ceiling411(jsonb,timestamptz,timestamptz,integer[])
    to adlog_semantic_worker;

-- The caller holds a read-only REPEATABLE READ transaction on the enumeration connection.
create function public.sigma_test_next411(s jsonb,p_start timestamptz,p_end timestamptz,p_kinds integer[],
    p_after bigint,p_high bigint)
returns table(native_id bigint,occurred_at timestamptz,kind integer,channel text,provider text,record_id bigint,
    event_sha text,representation_sha text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if not public.sigma_test_scope_allowed411(s,p_kinds) then
        raise exception 'sigma_test_source_denied' using errcode='42501';
    end if;
    if p_start is null or p_end is null or not isfinite(p_start) or not isfinite(p_end) or p_start>=p_end
       or p_end>date_trunc('day',p_start,'UTC')+interval '24 hours'
       or p_high is null or p_after is null or p_high<0 or p_after<0 or p_after>p_high then
        raise exception 'sigma_test_snapshot_bounds' using errcode='22023';
    end if;
    return query
    select h.event_id,h.time_created_utc,h.event_kind,h.method->>'$channel',h.method->>'$provider',h.event_record_id,
        encode(h.source_sha256,'hex'),encode(r.representation_sha256,'hex')
    from public.sigma_test_candidates411(s,p_start,p_end,p_kinds) h
    left join public.event_source_representations_v2 r on r.event_id=h.event_id and r.normalized_hash=h.source_sha256
    where h.event_id>p_after and h.event_id<=p_high
      and public.short_ref_allowed337(s,h.event_id::text,encode(h.source_sha256,'hex'))
    order by h.event_id
    limit 1;
end $$;
revoke all on function public.sigma_test_next411(jsonb,timestamptz,timestamptz,integer[],bigint,bigint)
    from public,adlog_user,adlog_storage_worker;
grant execute on function public.sigma_test_next411(jsonb,timestamptz,timestamptz,integer[],bigint,bigint)
    to adlog_semantic_worker;

-- Read original XML in the fresh ACL statement. Return metadata for absent and oversized
-- representations without transferring any oversized representation to the worker.
create function public.sigma_test_payload411(s jsonb,p_native bigint,p_at timestamptz,p_kind integer,p_event_sha text,
    p_rep_sha text,p_max_bytes integer)
returns table(state text,source_bytes integer,representation text)
language plpgsql stable security definer set search_path=pg_catalog,pg_temp as $$
begin
    if p_native is null or p_native<1 or p_kind is null or p_kind not in (4698,4702,7045)
       or p_at is null or not isfinite(p_at) or p_max_bytes is null or p_max_bytes not between 1 and 4194304 then
        raise exception 'sigma_test_payload_bounds' using errcode='22023';
    end if;
    if not public.short_ref_allowed337(s,p_native::text,p_event_sha) then
        raise exception 'sigma_test_source_denied' using errcode='42501';
    end if;
    return query
    select case
            when encode(r.representation_sha256,'hex') is distinct from p_rep_sha then 'changed'
            when r.event_id is null or jsonb_typeof(r.representation->'xml') is distinct from 'string' then 'missing'
            else 'present'
        end,
        coalesce(octet_length(r.representation::text),0),
        case when encode(r.representation_sha256,'hex')=p_rep_sha
                  and jsonb_typeof(r.representation->'xml')='string'
                  and octet_length(r.representation::text)<=p_max_bytes then r.representation::text end
    from public.event_hot h
    left join public.event_source_representations_v2 r on r.event_id=h.event_id and r.normalized_hash=h.source_sha256
    where h.event_id=p_native and h.time_created_utc=p_at and h.event_kind=p_kind
      and h.source_sha256=decode(p_event_sha,'hex') and ((h.method->'$origin')-'agent_id'-'log_source_id')=s
      and h.method->>'$channel'=case when p_kind=7045 then 'System' else 'Security' end;
end $$;
revoke all on function public.sigma_test_payload411(jsonb,bigint,timestamptz,integer,text,text,integer)
    from public,adlog_user,adlog_storage_worker;
grant execute on function public.sigma_test_payload411(jsonb,bigint,timestamptz,integer,text,text,integer)
    to adlog_semantic_worker;

insert into public.schema_migrations(version,name) values(412,'sigma_history_test');
reset role;
commit;
