using System.Text.Json.Nodes;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

internal static class PasswordRiskPublication
{
    internal static async Task<long> Publish(RiskSql sql,PasswordRiskWork work,JsonObject scenario,CancellationToken ct)
    {
        Guid sid=Guid.Parse(RiskJson.String(scenario,"scenario_id"));
        var results=await sql.Rows("""
            select result.evaluation_mode,result.conclusion_state,result.scenario_id::text as scenario_id,a.enabled as policy_admitted
            from public.semantic_risk_evaluation_results result join public.semantic_risk_evaluation_jobs job on job.job_id=result.job_id
            join public.semantic_risk_policies p on p.policy_id=job.policy_id and p.policy_version=job.policy_version
            join public.semantic_policy_admission a on a.policy_id=p.policy_id and a.policy_version=p.policy_version and a.enabled is true
            where result.job_id=@job and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled' for share of p nowait
            """,ct,("job",work.Lease.Id));
        RiskJson.Require(results.Count==1&&RiskJson.String(results[0],"evaluation_mode")=="enabled"&&RiskJson.String(results[0],"conclusion_state")=="observed"&&RiskJson.String(results[0],"scenario_id")==sid.ToString()&&results[0]["policy_admitted"]?.GetValue<bool>()==true,"password_risk_publication_admission_required");
        // Lock all contributing policies before rechecking admission in a fresh statement.
        await sql.Rows("""
            select p.policy_id,p.policy_version from public.semantic_risk_contributions c join public.semantic_risk_policies p
              on p.policy_id=c.policy_id and p.policy_version=c.policy_version
            where c.scenario_id=@scenario order by p.policy_id,p.policy_version for share of p nowait
            """,ct,("scenario",sid));
        var contributions=await sql.Rows("""
            select encode(c.policy_sha256,'hex') as contribution_sha,encode(p.definition_sha256,'hex') as policy_sha,
              p.lifecycle_status,a.enabled as admitted
            from public.semantic_risk_contributions c join public.semantic_risk_policies p on p.policy_id=c.policy_id and p.policy_version=c.policy_version
            left join public.semantic_policy_admission a on a.policy_id=p.policy_id and a.policy_version=p.policy_version
            where c.scenario_id=@scenario for share of p
            """,ct,("scenario",sid));
        RiskJson.Require(contributions.Count>0&&contributions.All(c=>c["admitted"]?.GetValue<bool>()==true&&(RiskJson.String(c,"lifecycle_status") is "shadow" or "enabled")&&RiskJson.String(c,"contribution_sha")==RiskJson.String(c,"policy_sha")),"password_risk_contributions_not_admitted");
        var scenarios=await sql.Rows("select * from public.semantic_security_scenarios where scenario_id=@scenario for share",ct,("scenario",sid));
        RiskJson.Require(scenarios.Count==1,"password_risk_scenario_unavailable");scenario=scenarios[0];
        RiskJson.Require(RiskJson.String(scenario,"scenario_kind")==work.Proposal.Policy.Rule.Id&&RiskJson.String(scenario,"evidence_state")=="ready","password_risk_evidence_pending");
        // Complete fresh immutable native proof before the first finding write.
        await PasswordRiskProof.VerifyScenario(sql,sid,work.Proposal.Signal,ct);
        string entityFingerprint="semantic:"+RiskJson.Hash(new JsonArray(work.Proposal.Partition,work.Proposal.Policy.Rule.Id,work.Proposal.Signal.Entity));
        string ruleCode="semantic."+RiskJson.String(scenario,"scenario_kind");
        await sql.Execute("select pg_advisory_xact_lock(hashtextextended(@fingerprint,0))",ct,("fingerprint",entityFingerprint));
        // Published scenarios keep their immutable mapping, including when old
        // releases created distinct findings for episodes of the same entity.
        var published=await sql.Rows("""
            select case when to_regclass('public.password_passes388') is null then @legacy
                else coalesce((
                    select p.finding_fingerprint from public.semantic_finding_publications p
                    join public.semantic_security_scenarios s on s.scenario_id=p.scenario_id
                    where s.partition_key=@partition and s.scenario_kind=@kind and s.strict_keys_json->>'entity'=@entity
                    order by (p.scenario_id=@scenario) desc,p.created_at,p.scenario_id limit 1
                ),@fingerprint) end as finding_fingerprint
            """,ct,("legacy","semantic:"+RiskJson.String(scenario,"scenario_key")),("fingerprint",entityFingerprint),
            ("scenario",sid),("partition",work.Proposal.Partition),("kind",work.Proposal.Policy.Rule.Id),("entity",work.Proposal.Signal.Entity));
        string fingerprint=RiskJson.String(published[0],"finding_fingerprint");
        string severity = RiskJson.String(scenario,"risk_class") == "critical" ? "critical" : "medium";
        var created=await sql.Rows("""
            insert into public.findings(fingerprint,rule_code,title,severity,confidence,status,first_seen_utc,last_seen_utc,
              actor,target,source,summary,why_it_matters,recommended_action,evidence_count,status_reason,repeat_count,last_evidence_event_id)
            values(@fingerprint,@rule,@title,@risk,@confidence,'new',@first,@last,null,null,null,@explanation,@explanation,
              'Review the linked evidence and validate the security impact.',0,'created from enabled semantic scenario',0,null)
            on conflict(fingerprint) do nothing returning id
            """,ct,("fingerprint",fingerprint),("rule",ruleCode),("title",RiskJson.String(scenario,"title")),("risk",severity),("confidence",RiskJson.Int(scenario,"confidence_score")/100.0),("first",RiskJson.String(scenario,"first_seen_utc")),("last",RiskJson.String(scenario,"last_seen_utc")),("explanation",RiskJson.String(scenario,"explanation")));
        var findings=await sql.Rows("select id,rule_code from public.findings where fingerprint=@fingerprint for update",ct,("fingerprint",fingerprint));
        RiskJson.Require(findings.Count==1&&RiskJson.String(findings[0],"rule_code")==ruleCode,"password_risk_finding_replay_conflict");long finding=RiskJson.Long(findings[0],"id");
        // Re-resolve and reparse again before linking. No preflight cache/verdict is reused.
        var batches=await PasswordRiskProof.VerifyScenario(sql,sid,work.Proposal.Signal,ct);
        await sql.Execute("""
            insert into public.finding_evidence(finding_id,event_id,evidence_role,note)
            select @finding,normalized.source_event_id,'semantic_scenario','enabled semantic scenario evidence'
            from public.semantic_scenario_evidence evidence join public.normalized_events normalized on normalized.normalized_event_id=evidence.normalized_event_id
            where evidence.scenario_id=@scenario order by evidence.evidence_order on conflict(finding_id,event_id,evidence_role) do nothing
            """,ct,("finding",finding),("scenario",sid));
        foreach(var batch in batches)foreach(var witness in batch) {
            var scope=witness.Scope;
            var linked=await sql.Rows("""
                select public.link_finding_evidence_ref(@finding,@installation,@plugin,@instance,@generation,@collection,'core_event',@native,@sha) as added
                """,ct,("finding",finding),("installation",Guid.Parse(scope.InstallationId)),("plugin",scope.PluginId),("instance",scope.SourceInstanceId),("generation",scope.SourceGeneration),("collection",scope.CollectionScopeId),("native",witness.NativeId.ToString(System.Globalization.CultureInfo.InvariantCulture)),("sha",witness.Sha256));
            RiskJson.Require(linked.Count==1&&linked[0]["added"] is JsonValue v&&v.TryGetValue<bool>(out _),"password_risk_evidence_link_failed");
        }
        // QW strict keys kind/entity/episode are opaque identities, so the source deliberately creates no display-name entities.
        var evidence=await sql.Rows("""
            select count(*)::bigint as count,max(event_id)::bigint as max_event_id from(
              select event_id from public.finding_evidence where finding_id=@finding and evidence_role='semantic_scenario'
              union select event_id from public.finding_event_copies337 where finding_id=@finding and evidence_role='semantic_scenario'
              union all select null::bigint as event_id from public.finding_evidence_refs
                where finding_id=@finding and evidence_role='semantic_scenario' and storage_kind<>'core_event') exact_evidence
            """,ct,("finding",finding));
        RiskJson.Require(evidence.Count==1&&RiskJson.Long(evidence[0],"count")>0,"password_risk_finding_without_evidence");long count=RiskJson.Long(evidence[0],"count");
        var reopened=await sql.Rows("""
            update public.findings set status='repeated',closed_at=null,repeat_count=coalesce(repeat_count,0)+1,
              last_repeat_detected_at=@at::timestamptz,status_reason=null,updated_at=now()
            where id=@finding and status='closed' and closed_at is not null
              and @at::timestamptz>closed_at::timestamptz and @at::timestamptz>last_seen_utc::timestamptz
            returning id
            """,ct,("at",PasswordJson.Stamp(work.Proposal.At)),("finding",finding));
        if(reopened.Count>0)await sql.Execute("""
            insert into public.finding_status_history(finding_id,old_status,new_status,changed_by)
            values(@finding,'closed','repeated','semantic-worker')
            """,ct,("finding",finding));
        await sql.Execute("""
            update public.findings set title=@title,severity=case when severity='critical' then severity else @risk end,
              confidence=greatest(confidence,@confidence),first_seen_utc=least(first_seen_utc,@first),last_seen_utc=greatest(last_seen_utc,@last),
              summary=@explanation,why_it_matters=@explanation,recommended_action='Review the linked evidence and validate the security impact.',
              evidence_count=@count,last_evidence_event_id=@last_event::bigint,updated_at=now() where id=@finding
            """,ct,("title",RiskJson.String(scenario,"title")),("risk",severity),("confidence",RiskJson.Int(scenario,"confidence_score")/100.0),("first",RiskJson.String(scenario,"first_seen_utc")),("last",RiskJson.String(scenario,"last_seen_utc")),("explanation",RiskJson.String(scenario,"explanation")),("count",count),("last_event",evidence[0]["max_event_id"]==null?null:RiskJson.Long(evidence[0],"max_event_id")),("finding",finding));
        await sql.Execute("""
            insert into public.semantic_finding_publications(scenario_id,finding_id,first_job_id,finding_fingerprint,published_evidence_count)
            values(@scenario,@finding,@job,@fingerprint,@count) on conflict(scenario_id) do nothing
            """,ct,("scenario",sid),("finding",finding),("job",work.Lease.Id),("fingerprint",fingerprint),("count",count));
        var replay=await sql.Rows("select finding_id,finding_fingerprint from public.semantic_finding_publications where scenario_id=@scenario",ct,("scenario",sid));
        RiskJson.Require(replay.Count==1&&RiskJson.Long(replay[0],"finding_id")==finding&&RiskJson.String(replay[0],"finding_fingerprint")==fingerprint,"password_risk_publication_replay_conflict");
        if(created.Count>0)await sql.Execute("""
            insert into public.finding_status_history(finding_id,old_status,new_status,changed_by,note)
            values(@finding,null,'new','semantic-worker','created from enabled semantic scenario')
            """,ct,("finding",finding));
        await sql.Rows("select public.enqueue_qw_finding_notifications(@scenario) as enqueued",ct,("scenario",sid));
        await SupersedeFinding(sql,sid,finding,ct);return finding;
    }

    internal static async Task SupersedeScenario(RiskSql sql,Guid scenario,CancellationToken ct)
    {
        var available=await sql.Rows("select to_regclass('public.entity_identity_scenario_supersessions_v2') is not null as available",ct);
        if(available[0]["available"]?.GetValue<bool>()!=true)return;
        await sql.Execute("""
            insert into public.entity_identity_scenario_supersessions_v2(merge_id,old_scenario_id,new_scenario_id)
            select distinct replay.merge_id,old_evidence.scenario_id,@scenario from public.semantic_scenario_evidence new_evidence
            join public.entity_identity_semantic_replays_v2 replay on replay.new_normalized_event_id=new_evidence.normalized_event_id
            join public.semantic_scenario_evidence old_evidence on old_evidence.normalized_event_id=replay.old_normalized_event_id
            join public.semantic_security_scenarios old_scenario on old_scenario.scenario_id=old_evidence.scenario_id
            join public.semantic_security_scenarios new_scenario on new_scenario.scenario_id=@scenario
            where new_evidence.scenario_id=@scenario and old_evidence.scenario_id<>@scenario
              and old_scenario.scenario_kind=new_scenario.scenario_kind and old_scenario.result_class=new_scenario.result_class on conflict do nothing
            """,ct,("scenario",scenario));
    }

    private static async Task SupersedeFinding(RiskSql sql,Guid scenario,long finding,CancellationToken ct)
    {
        var available=await sql.Rows("select to_regclass('public.entity_identity_finding_supersessions_v2') is not null as available",ct);
        if(available[0]["available"]?.GetValue<bool>()!=true)return;
        await sql.Execute("""
            insert into public.entity_identity_finding_supersessions_v2(merge_id,old_scenario_id,new_scenario_id,old_finding_id,new_finding_id)
            select supersession.merge_id,supersession.old_scenario_id,supersession.new_scenario_id,old_publication.finding_id,@finding
            from public.entity_identity_scenario_supersessions_v2 supersession join public.semantic_finding_publications old_publication
              on old_publication.scenario_id=supersession.old_scenario_id
            where supersession.new_scenario_id=@scenario and old_publication.finding_id<>@finding on conflict do nothing
            """,ct,("scenario",scenario),("finding",finding));
    }
}
