namespace Sli.Server.Semantic;
internal static class SemanticRiskSql
{
    internal const string select_scenario0 = """
        insert into semantic_security_scenarios(
                    scenario_id,scenario_kind,result_class,identity_key,scenario_key,
                    partition_key,strict_keys_json,merge_window_seconds,title,explanation,
                    first_seen_utc,last_seen_utc,risk_class,raw_score,display_score,
                    hard_critical,confidence,confidence_score,confidence_factors_json,
                    coverage_status
                ) values ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19::jsonb,$20)
                on conflict(scenario_key) do nothing
        """;
    internal const string select_scenario1 = """
        select * from semantic_security_scenarios where scenario_key=$1 for update
        """;
    internal const string persist_step0 = """
        insert into semantic_scenario_steps(
                    step_id,scenario_id,step_key,source_kind,canonical_action_id,
                    correlation_candidate_id,control_reference,occurred_at_utc,title,
                    explanation,confidence,confidence_score,confidence_factors_json,detection_match_id,qw_signal_id
                ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13::jsonb,$14,$15)
                on conflict(step_key) do nothing
        """;
    internal const string persist_step1 = """
        select * from semantic_scenario_steps where step_key=$1
        """;
    internal const string persist_evidence0 = """
        select evidence_order from semantic_scenario_evidence
                    where scenario_id=$1 and normalized_event_id=$2
        """;
    internal const string persist_evidence1 = """
        select coalesce(max(evidence_order),-1) as last_order
                    from semantic_scenario_evidence where scenario_id=$1
        """;
    internal const string persist_evidence2 = """
        insert into semantic_scenario_evidence(
                        scenario_id,normalized_event_id,evidence_order
                    ) values ($1,$2,$3)
        """;
    internal const string persist_contribution0 = """
        insert into semantic_risk_contributions(
                    contribution_id,scenario_id,contribution_key,source_kind,
                    canonical_action_id,correlation_candidate_id,control_reference,
                    policy_id,policy_version,policy_sha256,risk_class,raw_score,
                    display_points,hard_critical,rationale,detection_match_id,qw_signal_id
                ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
                on conflict(contribution_key) do nothing
        """;
    internal const string persist_contribution1 = """
        select * from semantic_risk_contributions where contribution_key=$1
        """;
    internal const string persist_coverage0 = """
        insert into semantic_scenario_coverage_history(
                        coverage_id,scenario_id,assessment_key,control_id,
                        coverage_status,reason,observed_at_utc
                    ) values ($1,$2,$3,$4,$5,$6,$7)
                    on conflict(scenario_id,assessment_key) do nothing
        """;
    internal const string refresh_scenario0 = """
        select contribution.source_kind,canonical_action_id,correlation_candidate_id,
                       contribution.detection_match_id,contribution.qw_signal_id,
                       coalesce(detection.evidence_key,
                           encode(sha256(convert_to((signal.document_json->'evidence_refs')::text,'UTF8')),'hex'),'') as evidence_key,
                       control_reference,policy_id,policy_version,policy_sha256,
                       risk_class,raw_score,display_points,hard_critical,rationale,
                       encode(contribution_key,'hex') as contribution_key_hex
                from semantic_risk_contributions contribution
                left join semantic_detection_matches detection on detection.match_id=contribution.detection_match_id
                left join semantic_qw_signals signal on signal.signal_id=contribution.qw_signal_id
                where scenario_id=$1 order by contribution_id
        """;
    internal const string refresh_scenario1 = """
        select confidence_factors_json from semantic_scenario_steps
                where scenario_id=$1
                order by occurred_at_utc,step_id
        """;
    internal const string refresh_scenario2 = """
        select distinct on(control_id)
                       control_id,coverage_status,reason,observed_at_utc
                from semantic_scenario_coverage_history
                where scenario_id=$1
                order by control_id,observed_at_utc desc,coverage_id desc
        """;
    internal const string refresh_scenario3 = """
        select min(occurred_at_utc) as first_seen_utc,
                       max(occurred_at_utc) as last_seen_utc,
                       count(*) as step_count,
                       (select count(*) from semantic_scenario_evidence
                        where scenario_id=$1) +
                       (select count(distinct detection.evidence_key)
                        from semantic_scenario_steps step join semantic_detection_matches detection
                          on detection.match_id=step.detection_match_id
                        where step.scenario_id=$2) +
                       (select count(distinct ref) from semantic_scenario_steps step
                        join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id,
                        lateral jsonb_array_elements(signal.document_json->'evidence_refs') ref
                        where step.scenario_id=$3) as evidence_count,
                       (select count(*) from semantic_risk_contributions
                        where scenario_id=$4) as contribution_count,
                       (select coalesce(max((signal.document_json->>'evidence_total')::integer),0)
                        from semantic_scenario_steps step join semantic_qw_signals signal on signal.signal_id=step.qw_signal_id
                        where step.scenario_id=$5) as expected_evidence_count
                from semantic_scenario_steps where scenario_id=$6
        """;
    internal const string refresh_scenario4 = """
        update semantic_security_scenarios
                set first_seen_utc=$1,last_seen_utc=$2,risk_class=$3,raw_score=$4,
                    display_score=$5,hard_critical=$6,confidence=$7,
                    confidence_score=$8,confidence_factors_json=$9::jsonb,
                    coverage_status=$10,step_count=$11,evidence_count=$12,
                    contribution_count=$13,evidence_state=$14,updated_at=now()
                where scenario_id=$15
                returning scenario_id,scenario_status,risk_class,raw_score,display_score,
                          hard_critical,confidence,confidence_score,coverage_status,
                          step_count,evidence_count,contribution_count,evidence_state
        """;
    internal const string publish_enabled_scenario_finding0 = """
        select result.evaluation_mode,result.conclusion_state,
                       result.scenario_id,job.policy_id,job.policy_version,job.source_kind,job.qw_signal_id,
                       admission.enabled as policy_admitted
                from semantic_risk_evaluation_results result
                join semantic_risk_evaluation_jobs job on job.job_id=result.job_id
                join semantic_risk_policies policy
                  on policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
                join semantic_policy_admission admission
                  on admission.policy_id=policy.policy_id
                 and admission.policy_version=policy.policy_version and admission.enabled is true
                where result.job_id=$1
                  and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)='enabled'
                for share of policy
        """;
    internal const string publish_enabled_scenario_finding1 = """
        select identity_key from semantic_security_scenarios where scenario_id=$1
        """;
    internal const string publish_enabled_scenario_finding2 = """
        select pg_advisory_xact_lock(hashtextextended($1,0))
        """;
    internal const string publish_enabled_scenario_finding3 = """
        select policy.policy_id,policy.policy_version
                from semantic_risk_contributions contribution
                join semantic_risk_policies policy
                  on policy.policy_id=contribution.policy_id
                 and policy.policy_version=contribution.policy_version
                where contribution.scenario_id=$1
                order by policy.policy_id,policy.policy_version
                for share of policy
        """;
    internal const string publish_enabled_scenario_finding4 = """
        select contribution.policy_sha256,policy.definition_sha256,
                       policy.lifecycle_status,admission.enabled as admitted
                from semantic_risk_contributions contribution
                join semantic_risk_policies policy
                  on policy.policy_id=contribution.policy_id
                 and policy.policy_version=contribution.policy_version
                left join semantic_policy_admission admission
                  on admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                where contribution.scenario_id=$1
                for share of policy
        """;
    internal const string publish_enabled_scenario_finding5 = """
        select scenario_id,scenario_kind,scenario_key,strict_keys_json,
                       title,explanation,first_seen_utc,last_seen_utc,risk_class,
                       confidence_score,evidence_state
                from semantic_security_scenarios
                where scenario_id=$1
                for share
        """;
    internal const string publish_enabled_scenario_finding6 = """
        select pg_advisory_xact_lock(hashtextextended($1,0))
        """;
    internal const string publish_enabled_scenario_finding7 = """
        insert into findings(
                    fingerprint,rule_code,title,severity,confidence,status,
                    first_seen_utc,last_seen_utc,actor,target,source,summary,
                    why_it_matters,recommended_action,evidence_count,status_reason,
                    repeat_count,last_evidence_event_id
                ) values(
                    $1,$2,$3,$4,$5,'new',$6,$7,$8,$9,$10,$11,$12,$13,0,
                    'created from enabled semantic scenario',0,null
                )
                on conflict(fingerprint) do nothing
                returning id
        """;
    internal const string publish_enabled_scenario_finding8 = """
        select id,rule_code from findings
                where fingerprint=$1
                for update
        """;
    internal const string publish_enabled_scenario_finding9 = """
        insert into finding_evidence(finding_id,event_id,evidence_role,note)
                select $1,normalized.source_event_id,'semantic_scenario',
                       'enabled semantic scenario evidence'
                from semantic_scenario_evidence evidence
                join normalized_events normalized
                  on normalized.normalized_event_id=evidence.normalized_event_id
                where evidence.scenario_id=$2
                order by evidence.evidence_order
                on conflict(finding_id,event_id,evidence_role) do nothing
                returning event_id
        """;
    internal const string publish_enabled_scenario_finding10 = """
        insert into finding_entities(
                        finding_id,entity_type,display_name,entity_role
                    )
                    select $1,$2,$3,$4
                    where not exists (
                        select 1 from finding_entities
                        where finding_id=$5
                          and coalesce(entity_type,'')=$6
                          and coalesce(display_name,'')=$7
                          and entity_role=$8
                    )
        """;
    internal const string publish_enabled_scenario_finding11 = """
        select count(*)::bigint as count,max(event_id)::bigint as max_event_id
                from (
                    select event_id from finding_evidence
                    where finding_id=$1 and evidence_role='semantic_scenario'
                    union
                    select event_id from finding_event_copies337 where finding_id=$1 and evidence_role='semantic_scenario'
                    union all
                    select null::bigint as event_id from public.finding_evidence_refs
                    where finding_id=$2 and evidence_role='semantic_scenario' and storage_kind<>'core_event'
                ) exact_evidence
        """;
    internal const string publish_enabled_scenario_finding12 = """
        update findings
                set title=$1,severity=$2,confidence=$3,
                    repeat_count=case when rule_code in('semantic.qw.kerberoasting','semantic.qw.asrep-roasting')
                        and evidence_count>0 and evidence_count<$12 then coalesce(repeat_count,0)+1
                        when $15::integer is null then repeat_count
                        else greatest(coalesce(repeat_count,0),$15::integer) end,
                    first_seen_utc=$4,last_seen_utc=$5,
                    actor=coalesce($6,actor),target=coalesce($7,target),
                      source=coalesce($8,source),summary=$9,why_it_matters=$10,
                      recommended_action=$11,evidence_count=$12,
                      last_evidence_event_id=$13,updated_at=now()
                where id=$14
        """;
    internal const string publish_enabled_scenario_finding13 = """
        insert into semantic_finding_publications(
                    scenario_id,finding_id,first_job_id,finding_fingerprint,
                    published_evidence_count
                ) values($1,$2,$3,$4,$5)
                on conflict(scenario_id) do nothing
        """;
    internal const string publish_enabled_scenario_finding14 = """
        select finding_id,finding_fingerprint
                from semantic_finding_publications
                where scenario_id=$1
        """;
    internal const string publish_enabled_scenario_finding15 = """
        insert into finding_status_history(
                        finding_id,old_status,new_status,changed_by,note
                    ) values($1,null,'new','semantic-worker',
                             'created from enabled semantic scenario')
        """;
    internal const string publish_enabled_scenario_finding16 = """
        select public.enqueue_qw_finding_notifications($1) as enqueued
        """;
}
