using Sli.Server.Problems;

namespace Sli.Server.Domains;

internal static class HomePeriodSql
{
    // A single admitted population serves both the period totals and the current queue count.
    internal static readonly string Problems = $$"""
        with population as materialized (
            select findings.id,findings.rule_code,findings.severity,
                   findings.actor,findings.target,findings.source,findings.fingerprint,findings.first_seen_utc::timestamptz as first_seen,
                   findings.closed_at::timestamptz as closed_at,({{HomeSummarySql.EffectiveStatus}}) as status
            {{HomeSummarySql.Population}}
            where is_semantic_finding_published_v1(findings.id)
              and (findings.rule_code<>'semantic.qw.file-acl-broad-write' or semantic_finding_in_domains_v265(findings.id,null))
              and not coalesce(risk.state='active' and risk.expires_at>statement_timestamp(),false)
              and not ({{ProblemRepository.Suppressed}})
              and semantic_finding_in_domains_v265(findings.id,@ids)
        ), open_findings as materialized (
            select id,rule_code,target,source,fingerprint
            from population where status in ('new','confirmed','repeated','active','review')
        ), recent as materialized (
            select id,rule_code,severity,actor,target,first_seen,closed_at,status
            from population where first_seen>=@from and first_seen<@to
              and severity in ('critical','high','medium')
              and rule_code not in ('qw.ad-hardening.privileged-nonexpiring','qw.ad-hardening.machine-account-quota',
                                    'qw.ad-hardening.lockout-threshold')
        ), top as (
            select * from recent order by case severity when 'critical' then 0 when 'high' then 1 else 2 end,
                first_seen desc,id desc limit 7
        )
        select count(*) filter(where first_seen>=@from and first_seen<@to) as new_count,
               count(*) filter(where closed_at>=@from and closed_at<@to) as closed_count,
               (select count(distinct cohort.key) from open_findings findings {{ProblemCohorts.Sql("queue-cohort")}}) as open_count,
               (select jsonb_agg(to_jsonb(top) || jsonb_build_object('entity',(
                   select jsonb_build_object('id',min(entity.id),'name',min(entity.display_name)) from finding_entities linked
                   join entities_v2_active entity on entity.id=linked.entity_id and entity.domain_id=any(@ids)
                   where @identity and linked.finding_id=top.id
                   having count(distinct entity.id)=1),'entity_name',(
                   select coalesce(nullif(entity.display_name,''),nullif(linked.display_name,''))
                   from finding_entities linked
                   left join entities_v2_active entity on entity.id=linked.entity_id and entity.domain_id=any(@ids)
                   where @identity and linked.finding_id=top.id and (linked.entity_id is null or entity.id is not null)
                     and linked.entity_role in ('target','target_entity','affected_entity','object','container_entity')
                   order by (linked.entity_role in ('target','target_entity')) desc,entity.id,linked.display_name limit 1)) ||
                   case when @technical then jsonb_build_object('observations',(
                       select jsonb_agg(to_jsonb(observation) order by observation.at desc,observation.event_id desc)
                       from (select distinct c.time_created_utc as at,c.event_id,c.event_kind,c.computer as source
                             from finding_event_copies337 c
                             where c.finding_id=top.id and c.domain_id=any(@ids)
                              and c.time_created_utc>=@from and c.time_created_utc<@to
                             order by at desc,c.event_id desc limit 20) observation))
                   else '{}'::jsonb end || jsonb_build_object('password',to_jsonb(password),'subject',to_jsonb(subject))
                   order by case top.severity when 'critical' then 0 when 'high' then 1 else 2 end,
                            top.first_seen desc,top.id desc) from top
                left join lateral (
                    select count(distinct (c.event_id,c.time_created_utc)) filter (where c.event_kind<>4624) as attempts,
                           min(c.time_created_utc) as first_at,max(c.time_created_utc) as last_at,
                           bool_or(c.event_kind=4624) as password_success,
                           count(distinct lower(account.name)) as accounts,min(account.name) as account,
                           count(distinct address.name) as addresses,min(address.name) as address
                    from finding_event_copies337 c
                    cross join lateral (select left(btrim(c.method#>>'{$principals,TargetUserName}'),512) as name,
                        btrim(coalesce(c.method#>>'{$principals,IpAddress}',c.method#>>'{$principals,ClientAddress}')) as ip) principal
                    cross join lateral (select case when @identity and principal.name not in ('','-','—')
                        and principal.name !~* '^(sid:|S-1-)' then principal.name end as name) account
                    cross join lateral (select case when @technical and principal.ip ~ '^[0-9a-fA-F:.]+$'
                        and pg_input_is_valid(principal.ip,'inet') then host(principal.ip::inet) end as name) address
                    where c.finding_id=top.id and c.domain_id=any(@ids) and c.time_created_utc>=@from and c.time_created_utc<@to
                      and c.event_kind in (4624,4625,4771,4776)
                      and top.rule_code in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                    having count(*)>0
                ) password on true
                left join lateral (
                    select case when c.event_kind in (4728,4729,4732,4733,4756,4757)
                                then c.method#>>'{$principals,TargetUserName}' end as group_name,
                           case when c.event_kind in (4728,4729,4732,4733,4756,4757)
                                then c.fields->>'MemberName' end as member_name,
                           c.method#>>'{$principals,TargetUserName}' as account,c.computer
                    from finding_event_copies337 c
                    where @identity and top.rule_code not in ('semantic.qw.password-brute-force','semantic.qw.password-spray')
                      and c.finding_id=top.id and c.domain_id=any(@ids) and c.time_created_utc>=@from and c.time_created_utc<@to
                    order by (c.event_kind in (4728,4729,4732,4733,4756,4757,4719)) desc,c.time_created_utc desc,c.event_id desc
                    limit 1
                ) subject on true) as items,
               (select jsonb_agg(jsonb_build_object('at',first_seen,'severity',severity,'id',id) order by first_seen)
                from recent) as markers
        from population
        """;

    internal const string Controllers = """
        select distinct on (e.id) e.id as entity_id, e.display_name as name,
               v.attributes_json->'attributes' as attributes, observed.observed_at_utc as observed_at
        from entities_v2_active e join storage_v2_entity_type kind on kind.id=e.entity_type_id
        join ad_context_entity_versions v on v.entity_id=e.id and v.source_section='domain_health'
        join lateral (
            select source.observed_at_utc
            from ad_context_evidence source join ad_context_runs run on run.run_id=source.source_run_id
            where run.domain_id=e.domain_id and run.status='completed'
              and source.evidence_type='entity_observation'
              and source.locator_json->>'section'='domain_health'
              and source.locator_json->>'record_key'=v.attributes_json->>'record_key'
              and source.observed_at_utc>=v.valid_from_utc and source.observed_at_utc<@to
              and not exists (
                  select 1 from ad_snapshot_manifest_sources ms
                  join sli_agent_snapshot_cycles cycle on cycle.manifest_id=ms.manifest_id
                  where ms.family='ad_domain_health' and ms.source_id=source.source_run_id::text
                  group by ms.source_id having (bool_or(cycle.publication_state='published')) is not true
              )
            order by source.observed_at_utc desc limit 1
        ) observed on true
        where e.domain_id=any(@ids) and kind.value='ad_computer'
          and v.attributes_json#>>'{attributes,infrastructure_role}'='domain_controller'
          and v.valid_from_utc<@to and (v.valid_to_utc is null or v.valid_to_utc>=@to)
        order by e.id,observed.observed_at_utc desc,v.valid_from_utc desc
        """;

    internal const string PasswordPolicyChanges = """
        select e.display_name as name, v.valid_from_utc as at, field.key as field,
               prior.attributes_json->'attributes'->field.key as before, field.value as after
        from entities_v2_active e join storage_v2_entity_type kind on kind.id=e.entity_type_id
        join ad_context_entity_versions v on v.entity_id=e.id and v.source_section='domain_posture'
        join ad_context_entity_versions prior on prior.entity_id=e.id and prior.source_section=v.source_section
          and prior.valid_to_utc=v.valid_from_utc
        join ad_context_sections current_section on current_section.run_id=v.source_run_id
          and current_section.section_name=v.source_section and current_section.status='complete'
        join ad_context_sections prior_section on prior_section.run_id=prior.source_run_id
          and prior_section.section_name=prior.source_section and prior_section.status='complete'
        cross join lateral jsonb_each(v.attributes_json->'attributes') field
        where e.domain_id=any(@ids) and kind.value='password_policy'
          and v.valid_from_utc>=@from and v.valid_from_utc<@to
          and field.key in ('password_min_length','password_history_length','password_min_age','password_max_age',
                            'lockout_threshold','lockout_duration','lockout_observation_window')
          and prior.attributes_json->'attributes'->field.key is distinct from field.value
          and prior.attributes_json->'attributes'->field.key is not null
        order by at desc,e.id,field.key limit 200
        """;

    internal const string GpoPresentation = """
        with changes as materialized (
            select c.record_id,c.before_value,c.after_value,c.payload_json::jsonb as diff,
                   h.manifest_id,h.previous_manifest_id,h.domain_id
            from ad_snapshot_change_history c join ad_snapshot_history_confirmations h
              on (h.observed_at,h.manifest_id,h.batch_id,h.domain_id,h.family)=
                 (c.observed_at,c.manifest_id,c.batch_id,c.domain_id,c.family)
            where c.domain_id=any(@ids) and c.family='gpo_v2' and c.record_kind='history'
              and c.observed_at>=@from and c.observed_at<@to and c.record_id=any(@records)
        ), manifests as (
            select distinct manifest.id,c.domain_id from changes c
            cross join lateral (values(c.manifest_id),(c.previous_manifest_id)) manifest(id)
            where manifest.id is not null
        ), snapshots as materialized (
            select m.id,m.domain_id,s.payload_json
            from manifests m
            left join ad_snapshot_manifest_sources ms on ms.manifest_id=m.id and ms.family='gpo_v2'
            left join sli_agent_snapshot_cycles cycle on cycle.cycle_id=m.id
            join gpo_report_v2_source_snapshots s on s.domain_id=m.domain_id and s.import_status='completed'
              and s.source_run_id=coalesce(ms.source_id::uuid,cycle.gpo_source_run_id)
        ), names as materialized (
            select s.id,s.domain_id,gpo->>'id' as object_id,gpo->>'display_name' as name
            from snapshots s cross join lateral jsonb_array_elements(s.payload_json->'gpos') gpo
        ), settings as materialized (
            select s.id,s.domain_id,setting->>'id' as object_id,
                   setting->>'setting_name' as label
            from snapshots s cross join lateral jsonb_array_elements(s.payload_json->'settings') setting
        )
        select c.record_id,c.before_value,c.after_value,coalesce(current_name.name,previous_name.name) as name,
               coalesce(current_setting.label,previous_setting.label) as label
        from changes c
        left join names current_name on current_name.id=c.manifest_id and current_name.domain_id=c.domain_id
          and current_name.object_id=coalesce(nullif(c.diff->>'related_object_id',''),c.diff->>'object_id')
        left join names previous_name on previous_name.id=c.previous_manifest_id and previous_name.domain_id=c.domain_id
          and previous_name.object_id=coalesce(nullif(c.diff->>'related_object_id',''),c.diff->>'object_id')
        left join settings current_setting on current_setting.id=c.manifest_id and current_setting.domain_id=c.domain_id
          and current_setting.object_id=c.diff->>'object_id'
        left join settings previous_setting on previous_setting.id=c.previous_manifest_id and previous_setting.domain_id=c.domain_id
          and previous_setting.object_id=c.diff->>'object_id'
        """;

    internal static string EventChanges(string source, string scope) => $$"""
        with short_events as ({{source}})
        select e.id, e.time_created_utc as at, e.event_id,
               coalesce(nullif(e.method#>>'{$principals,SubjectUserName}',''),e.actor) as initiator,
               coalesce(nullif(e.method#>>'{$principals,TargetUserName}',''),e.target,e.fields->>'SamAccountName') as name,
               case when e.event_id in (4728,4729,4732,4733,4756,4757)
                    then nullif(e.fields->>'MemberName','-')
                    when e.event_id=4738 then nullif(e.fields->>'UserPrincipalName','-') end as value
        from short_events e
        where ({{scope}}) and e.time_created_utc<@to
          and e.event_id in (4728,4729,4732,4733,4756,4757,4720,4725,4726,4738)
          and not exists (
              select 1 from finding_event_copies337 copy
              where copy.event_kind=e.event_id and copy.event_id=e.id and copy.time_created_utc=e.time_created_utc
                and copy.domain_id=e.domain_id and is_semantic_finding_published_v1(copy.finding_id)
          )
        order by at desc,e.id desc limit 200
        """;

    internal static string Activity(string source, string scope) => $$"""
        with short_events as not materialized ({{source}}),
        counts as materialized (
            select date_bin(interval '1 hour',e.time_created_utc,@hour) as at,
                   count(*) filter(where e.event_id=4625 and e.time_created_utc>=@from) as failed,
                   count(*) filter(where e.event_id=4624 and e.time_created_utc>=@from) as succeeded,
                   count(*) filter(where e.event_id=4625) as all_failed
            from short_events e
            where ({{scope}}) and e.event_id in (4624,4625) and e.time_created_utc<@to
            group by 1
        ), observed as (select min(at) as first_hour from counts),
        samples as materialized (
            select date_trunc('hour',sample.at at time zone @zone) as local_hour,
                   sum(coalesce(counts.all_failed,0)) as failed
            from observed
            cross join lateral generate_series(date_bin(interval '1 hour',@read_from,@hour),
                @to-interval '1 hour',interval '1 hour') sample(at)
            left join counts on counts.at=sample.at
            where sample.at>=greatest(@read_from,observed.first_hour) and observed.first_hour is not null
            group by 1
        )
        select greatest(bucket.at,@from) as at,
               case when greatest(bucket.at,@from)>=@read_from and bucket.at>=observed.first_hour
                    then coalesce(counts.failed,0) end as failed,
               case when greatest(bucket.at,@from)>=@read_from and bucket.at>=observed.first_hour
                    then coalesce(counts.succeeded,0) end as succeeded,
               baseline.typical
        from generate_series(@hour,@to,interval '1 hour') bucket(at)
        cross join observed
        left join counts on counts.at=bucket.at
        cross join lateral (
            select percentile_cont(0.5) within group (order by samples.failed::double precision) as typical
            from generate_series(1,7) days(n)
            join samples on samples.local_hour=date_trunc('hour',bucket.at at time zone @zone)-days.n*interval '1 day'
        ) baseline
        where bucket.at<@to order by bucket.at
        """;
}

