begin;
select pg_advisory_xact_lock(hashtext('sli_password_detection_status400'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
       or not exists(select 1 from public.schema_migrations where version=399 and name='password_queue_projection')
       or exists(select 1 from public.schema_migrations where version>=400) then
        raise exception 'password_detection_status400_preflight' using errcode='55000'; end if;
end $$;
set local role adlog_storage_owner;

-- Aggregated operational state for the existing operations.view endpoint.
-- Only the current live execution can report a live failure. The history
-- interval remains pending until its own checkpoint reaches the boundary.
create function public.read_password_live_status400(allowed_domains bigint[])
returns table(rule_id text, state text, observed_at timestamptz)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with rules(rule_id) as (
        values ('qw.password-brute-force'::text),('qw.password-spray'::text)
    ), mapped_sources as materialized (
        select m.agent_id,m.password_detection_domain_id as domain_id,
            public.password_v2_configured_identity(m.agent_id)->'scope' as scope
        from public.sli_agent_module_bindings m
        where m.module_id='sli.windows.ad-dc' and m.password_detection_domain_id=any(allowed_domains)
          and public.semantic_source_active320(m.agent_id,m.module_id,'Security')
    ), sources as materialized (
        -- Domain reconciliation can precede native source attestation.
        select agent_id,domain_id,scope from mapped_sources where scope is not null
    ), checkpoints as materialized (
        select s.*,r.rule_id,c.watermark,c.last_attempt_at,c.last_completed_at,c.health_status,c.loss_buckets,
            public.password_v2_coverage_policy(c.execution_json) as policy,(c.execution_json->>'rule_version')::integer as rule_version,
            p.history_pin is not null and (h.watermark is null or h.watermark<p.history_to) as history_pending,
            case when h.last_completed_at<=statement_timestamp() then h.last_completed_at end as history_progress
        from sources s cross join rules r
        left join public.password_pass_state393 p
            on p.scope_digest=public.password_v2_scope_key(s.scope) and p.rule_id=r.rule_id
        left join public.semantic_password_checkpoints c
            on c.scope_digest=p.scope_digest and c.pin=p.live_pin
              and c.owner_domain_id=s.domain_id and c.scope_json=s.scope
        left join public.semantic_password_checkpoints h on h.scope_digest=p.scope_digest and h.pin=p.history_pin
              and h.owner_domain_id=s.domain_id and h.scope_json=s.scope
    ), observations as (
        select c.*,e.at as latest_eligible,f.at as last_failure,
            statement_timestamp()-interval '300 seconds' as progress_deadline
        from checkpoints c
        left join lateral (
            -- Match the event clock's source and 120-second holdback. Use
            -- the source/clock index and read only the latest eligible row.
            select e.time_created_utc as at from public.event_hot e
            where c.health_status in ('healthy','partial') and c.policy<>'disabled'
              and e.source_sha256 is not null and e.method->>'$channel'='Security'
              and e.method#>>'{$origin,agent_id}'=c.agent_id::text
              and e.method#>>'{$origin,source_instance_id}'=c.scope->>'source_instance_id'
              and (e.method->'$origin')-'agent_id'-'log_source_id'=c.scope
              and e.time_created_utc<=statement_timestamp()-interval '120 seconds'
              and (e.event_kind in(4625,4771,4776) or (e.event_kind=4624 and c.rule_version>=395))
            order by e.time_created_utc desc,e.event_id desc limit 1
        ) e on true
        left join lateral (
            select max(public.password_v2_time(slot->'observed_max')) as at
            from jsonb_each(c.loss_buckets) entry(code,buckets)
            cross join lateral jsonb_array_elements(entry.buckets) slots(slot)
            where entry.code in ('source_error','password_v2_native_unavailable','xml_invalid','clock_regression')
              and slot<>'null'::jsonb
        ) f on true
    ), classified as (
        select o.*,
            case
                when policy='disabled' then 'disabled'
                when health_status='error' then 'failed'
                when policy='unknown' or health_status not in ('healthy','partial') or watermark is null
                    or last_completed_at is null or last_completed_at>statement_timestamp() then 'unknown'
                when latest_eligible>watermark and last_completed_at<=progress_deadline then 'behind'
                when latest_eligible>watermark then 'catching_up'
                when history_pending then 'history_pending'
                when last_failure<last_completed_at and last_failure>=statement_timestamp()-interval '24 hours' then 'recovered'
                when latest_eligible is null or latest_eligible<=progress_deadline-interval '120 seconds' then 'quiet'
                else 'current'
            end as state
        from observations o
    ), best as (
        select distinct on (c.rule_id) c.rule_id,c.state,t.observed_at
        from classified c
        cross join lateral (
            select case when c.state in ('disabled','unknown') then null
                        when c.state='failed' then coalesce(c.last_failure,c.last_attempt_at,c.last_completed_at)
                        when c.state='history_pending' then c.history_progress
                        else c.last_completed_at end as observed_at
        ) t
        order by c.rule_id,case c.state when 'failed' then 1 when 'behind' then 2
            when 'catching_up' then 3 when 'history_pending' then 4 when 'unknown' then 5
            when 'recovered' then 6 when 'current' then 7 when 'quiet' then 8 else 9 end,
             (case when c.state='failed' then t.observed_at end) desc nulls last,
            c.last_completed_at desc nulls last
    )
    select r.rule_id,coalesce(b.state,'unknown'),b.observed_at from rules r
    left join best b using(rule_id) order by r.rule_id
$$;
revoke all on function public.read_password_live_status400(bigint[]) from public,adlog_user,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.read_password_live_status400(bigint[]) to adlog_user;

insert into public.schema_migrations(version,name) values(400,'password_detection_status');
reset role;
commit;
