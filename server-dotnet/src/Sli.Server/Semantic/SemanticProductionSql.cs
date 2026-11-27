namespace Sli.Server.Semantic;
internal static class SemanticProductionSql
{
    internal const string Guard0 = """
        select exists(
                             select 1 from schema_migrations
                             where version=55 and name='semantic_finding_publication'
                           ) as schema_ready,
                           array(
                             select policy_id || ':' || policy_version::text
                             from semantic_risk_policies
                             where semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='enabled'
                             order by policy_id,policy_version
                           ) as enabled_policies,
                           array(
                             select p.policy_id || ':' || p.policy_version::text
                             from semantic_risk_policies p
                             where p.lifecycle_status='enabled' and not exists(
                                 select 1 from semantic_policy_admission a
                                 where a.policy_id=p.policy_id and a.policy_version=p.policy_version)
                             order by p.policy_id,p.policy_version
                           ) as unmanaged_enabled_policies,
                           exists(select 1 from semantic_policy_admission) as admission_configured,
                           exists(
                             select 1 from semantic_risk_policies
                             where semantic_policy_mode_v160(policy_id,policy_version,lifecycle_status)='test'
                           ) as test_policy_exists
        """;
    internal const string Guard1 = """
        select exists(
                                 select 1 from schema_migrations
                                 where version=54 and name='semantic_worker_runtime_schema_guard'
                               ) as facts_schema_ready,
                               exists(
                                 select 1 from schema_migrations
                                 where version=142 and name='semantic_processor_version_gate_and_repair'
                               ) as processor_version_gate_schema_ready,
                               has_table_privilege(
                                 current_user, 'semantic_processing_outbox', 'SELECT,INSERT,UPDATE'
                               ) and has_table_privilege(
                                 current_user, 'normalized_events', 'SELECT,INSERT,UPDATE'
                               ) and has_table_privilege(
                                 current_user, 'canonical_actions', 'SELECT,INSERT,UPDATE'
                               ) as facts_capability_ready,
                               exists(
                                 select 1 from schema_migrations
                                 where version=27 and name='semantic_dispatch_foundation'
                               ) as investigation_schema_ready,
                               exists(
                                 select 1 from schema_migrations
                                 where version=141 and name='semantic_dispatch_rule_lock_acl'
                               ) as investigation_rule_lock_schema_ready,
                               exists(
                                 select 1 from schema_migrations
                                 where version=140 and name='semantic_investigation_context_acl'
                               ) and exists(
                                 select 1 from pg_constraint
                                 where conrelid='semantic_processing_outbox'::regclass
                                   and conname='semantic_processing_outbox_job_kind_check'
                                   and pg_get_constraintdef(oid) like '%investigation_context%'
                               ) as investigation_context_schema_ready,
                               has_table_privilege(
                                 current_user, 'semantic_correlation_candidates', 'SELECT,INSERT,UPDATE'
                               ) and has_table_privilege(
                                 current_user, 'semantic_correlation_candidate_evidence', 'SELECT,INSERT,UPDATE'
                               ) and has_table_privilege(
                                 current_user, 'semantic_correlation_dispatch_jobs', 'SELECT,INSERT,UPDATE'
                               ) as investigation_capability_ready,
                               has_table_privilege(
                                 current_user, 'semantic_correlation_rules', 'SELECT'
                               ) and has_column_privilege(
                                 current_user, 'semantic_correlation_rules', 'updated_at', 'UPDATE'
                               ) and not has_table_privilege(
                                 current_user, 'semantic_correlation_rules', 'UPDATE'
                               ) and not has_column_privilege(
                                 current_user, 'semantic_correlation_rules', 'updated_at',
                                 'UPDATE WITH GRANT OPTION'
                               ) and not exists(
                                 select 1
                                 from pg_attribute rule_column
                                 where rule_column.attrelid='semantic_correlation_rules'::regclass
                                   and rule_column.attnum > 0
                                   and not rule_column.attisdropped
                                   and rule_column.attname <> 'updated_at'
                                   and has_column_privilege(
                                     current_user,
                                     rule_column.attrelid,
                                     rule_column.attname,
                                     'UPDATE'
                                   )
                               ) as investigation_rule_lock_capability_ready,
                               has_table_privilege(
                                 current_user, 'storage_v2_keywords', 'SELECT'
                               ) as investigation_context_capability_ready
        """;
    internal const string Backlog0 = """
        with effective_policy as materialized (
                    select policy.policy_id,policy.policy_version,policy.definition_sha256,
                           policy.lifecycle_status,policy.definition_json,
                           semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status) as effective_mode
                    from semantic_risk_policies policy
                    where exists (
                        select 1 from semantic_risk_policy_subscriptions subscription
                        where subscription.policy_id=policy.policy_id
                          and subscription.policy_version=policy.policy_version
                          and subscription.definition_sha256=policy.definition_sha256
                    )
                )
                select source_kind,source_id from (
                    select distinct 'canonical_action' as source_kind,
                           canonical_action_id::text as source_id,
                           occurred_at_utc as source_time
                    from semantic_risk_policy_subscriptions subscription
                    join effective_policy policy
                      on policy.policy_id=subscription.policy_id
                     and policy.policy_version=subscription.policy_version
                     and policy.definition_sha256=subscription.definition_sha256
                    cross join lateral (
                        select action.canonical_action_id,action.occurred_at_utc
                        from canonical_actions action
                        where subscription.selector_value=action.action_kind
                          and action_status not in ('contradicted','superseded','quarantined')
                          and not exists (
                              select 1 from semantic_risk_evaluation_jobs job
                              where job.policy_id=policy.policy_id
                                and job.policy_version=policy.policy_version
                                and job.source_kind='canonical_action'
                                and job.source_reference=action.canonical_action_id::text
                                and job.evaluation_mode=policy.effective_mode
                          )
                        order by action.occurred_at_utc,action.canonical_action_id
                        limit $1
                    ) action
                    where subscription.source_kind='canonical_action'
                      and policy.effective_mode=any($2)
                      and (policy.effective_mode<>'enabled'
                           or exists(select 1 from semantic_policy_admission admission
                               where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                 and admission.enabled is true))
                    union all
                    select 'correlation_candidate' as source_kind,candidate_id::text as source_id,
                           first_matched_at as source_time
                    from semantic_correlation_candidates candidate
                    where candidate_status='matched' and exists (
                        select 1 from semantic_risk_policy_subscriptions subscription
                        join effective_policy policy
                          on policy.policy_id=subscription.policy_id
                         and policy.policy_version=subscription.policy_version
                         and policy.definition_sha256=subscription.definition_sha256
                        where subscription.source_kind='correlation_candidate'
                          and subscription.selector_value=candidate.relation_kind
                          and policy.effective_mode=any($3)
                          and (policy.effective_mode<>'enabled'
                               or exists(select 1 from semantic_policy_admission admission
                                   where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                     and admission.enabled is true))
                          and not exists (
                              select 1 from semantic_risk_evaluation_jobs job
                              where job.policy_id=policy.policy_id
                                and job.policy_version=policy.policy_version
                                and job.source_kind='correlation_candidate'
                                and job.source_reference=candidate.candidate_id::text
                                and job.evaluation_mode=policy.effective_mode
                          )
                    )
                    union all
                    select 'control_health',observation_id::text,observed_at_utc
                    from semantic_control_health_observations health
                    where exists (
                        select 1 from semantic_risk_policy_subscriptions subscription
                        join effective_policy policy
                          on policy.policy_id=subscription.policy_id
                         and policy.policy_version=subscription.policy_version
                         and policy.definition_sha256=subscription.definition_sha256
                        where subscription.source_kind='control_health'
                          and subscription.selector_value=health.control_id
                          and policy.effective_mode=any($4)
                          and (policy.effective_mode<>'enabled'
                               or exists(select 1 from semantic_policy_admission admission
                                   where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                     and admission.enabled is true))
                          and not exists (
                              select 1 from semantic_risk_evaluation_jobs job
                              where job.policy_id=policy.policy_id
                                and job.policy_version=policy.policy_version
                                and job.source_kind='control_health'
                                and job.source_reference=health.observation_id::text
                                and job.evaluation_mode=policy.effective_mode
                          )
                    )
                    union all
                    select 'detection_match',detection.match_id,detection.occurred_at_utc
                    from semantic_detection_matches detection
                    where exists (
                        select 1 from semantic_risk_policy_subscriptions subscription
                        join effective_policy policy
                          on policy.policy_id=subscription.policy_id
                         and policy.policy_version=subscription.policy_version
                         and policy.definition_sha256=subscription.definition_sha256
                        where subscription.source_kind='detection_match'
                          and subscription.selector_value=detection.rule_id
                          and policy.effective_mode=detection.evaluation_mode
                          and policy.definition_json#>'{source_selector,execution}'=jsonb_build_object(
                              'version','sli.sigma.execution.v1','rule_id',detection.rule_id,
                              'rule_sha256',detection.document_json->'rule_sha256',
                              'manifest_sha256',detection.document_json->'manifest_sha256',
                              'compiler_version',detection.document_json->'compiler_version',
                              'mapping_version',detection.document_json->'mapping_version',
                              'overlay_sha256',detection.document_json->'overlay_sha256',
                              'scope',detection.document_json#>'{evidence,scope}')
                          and (detection.evaluation_mode<>'enabled' or exists(
                              select 1 from semantic_policy_admission admission
                              where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                and admission.enabled is true))
                          and not exists (
                              select 1 from semantic_risk_evaluation_jobs job
                              where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version
                                and job.source_kind='detection_match' and job.source_reference=detection.match_id
                                and job.evaluation_mode=detection.evaluation_mode
                          )
                    )
                    union all
                    select 'qw_signal',signal.signal_id,signal.created_at
                    from semantic_qw_signals signal
                    where exists (
                        select 1 from semantic_risk_policy_subscriptions subscription
                        join effective_policy policy
                          on policy.policy_id=subscription.policy_id
                         and policy.policy_version=subscription.policy_version
                         and policy.definition_sha256=subscription.definition_sha256
                        where subscription.source_kind='qw_signal'
                          and subscription.selector_value=signal.document_json->>'rule_id'
                          and to_jsonb(policy.policy_version)=signal.document_json->'policy_revision'
                          and policy.effective_mode=signal.evaluation_mode
                          and policy.definition_json#>'{source_selector,execution}'=case when signal.document_json->>'kind'='acl'
                            then jsonb_build_object('version','sli.qw.file-acl-execution.v1','kind','acl',
                              'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',
                              'rule_sha256',signal.document_json->'rule_sha256','resource',signal.document_json#>'{acl_context,resource}')
                            else jsonb_build_object(
                              'version','sli.qw.execution.v1','kind',signal.document_json->'kind',
                              'rule_id',signal.document_json->'rule_id','rule_version',signal.document_json->'rule_version',
                              'rule_sha256',signal.document_json->'rule_sha256',
                              'scope',signal.document_json#>'{evidence_refs,0,scope}') end
                          and (signal.evaluation_mode<>'enabled' or exists(
                              select 1 from semantic_policy_admission admission
                              where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                and admission.enabled is true))
                          and not exists (
                              select 1 from semantic_risk_evaluation_jobs job
                              where job.policy_id=policy.policy_id and job.policy_version=policy.policy_version
                                and job.source_kind='qw_signal' and job.source_reference=signal.signal_id
                                and job.evaluation_mode=signal.evaluation_mode
                          )
                    )
                ) source
                order by source_time,source_kind,source_id limit $5
        """;
    internal const string RiskClaim0 = """
        with candidates as (
                    select job_id from semantic_risk_evaluation_jobs job
                    where attempt_count < max_attempts and available_at <= now()
                      and exists(select 1 from semantic_risk_policies policy
                          where policy.policy_id=job.policy_id and policy.policy_version=job.policy_version
                          and semantic_policy_mode_v160(policy.policy_id,policy.policy_version,policy.lifecycle_status)=job.evaluation_mode
                          and (job.evaluation_mode<>'enabled' or exists(
                              select 1 from semantic_policy_admission admission
                              where admission.policy_id=policy.policy_id and admission.policy_version=policy.policy_version
                                and admission.enabled is true)))
                      and (evaluation_status in ('queued','failed')
                           or (evaluation_status='leased' and lease_until < now()))
                    order by available_at,created_at,
                        case when job.policy_id like 'default:qw.password-spray:%' then (
                            select signal.document_json#>>'{password_threshold_context,facts,first}'
                            from public.semantic_qw_signals signal where signal.signal_id=job.qw_signal_id
                        ) end,job_id
                    for update skip locked limit $1
                )
                update semantic_risk_evaluation_jobs job
                set evaluation_status='leased',attempt_count=attempt_count+1,
                    lease_token=$2,lease_until=now()+($3 * interval '1 second'),
                    heartbeat_at=now(),updated_at=now(),
                    last_error_code=null,last_error_detail=null
                from candidates where job.job_id=candidates.job_id
                returning job.*
        """;
}
