using System.Text.Json.Nodes;
using Sli.Server.Auth.Lifecycle.Security;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

internal static class PasswordRiskScenario
{
    private static void Identity(JsonObject row,PasswordRiskProposal p)
    {
        RiskJson.Require(RiskJson.String(row,"identity_key")==p.Identity&&RiskJson.String(row,"scenario_kind")==p.Policy.Rule.Id&&RiskJson.String(row,"result_class")=="security_incident"&&RiskJson.String(row,"partition_key")==p.Partition&&JsonNode.DeepEquals(row["strict_keys_json"],p.Strict)&&RiskJson.Int(row,"merge_window_seconds")==600,"password_risk_scenario_replay_conflict");
    }
    internal static async Task<JsonObject?> Find(RiskSql sql,PasswordRiskProposal p,CancellationToken ct)
    {
        var replay=await sql.Rows("select * from public.semantic_risk_contributions where contribution_key=@key",ct,("key",Convert.FromHexString(p.ContributionKey)));
        if(replay.Count>0) {
            VerifyContribution(replay[0],p);Guid id=Guid.Parse(RiskJson.String(replay[0],"scenario_id"));
            var rows=await sql.Rows("select * from public.semantic_security_scenarios where scenario_id=@id for update",ct,("id",id));RiskJson.Require(rows.Count==1,"password_risk_scenario_replay_conflict");Identity(rows[0],p);return rows[0];
        }
        // QW episode identity, unlike generic activities, survives merge windows/status changes.
        var existing=await sql.Rows("select * from public.semantic_security_scenarios where identity_key=@identity order by last_seen_utc desc,scenario_id for update limit 1",ct,("identity",Convert.FromHexString(p.Identity)));
        if(existing.Count==0)return null;Identity(existing[0],p);return existing[0];
    }

    private static void VerifyContribution(JsonObject row,PasswordRiskProposal p)
    {
        RiskJson.Require(RiskJson.String(row,"source_kind")=="qw_signal"&&RiskJson.String(row,"qw_signal_id")==p.Signal.Id&&RiskJson.String(row,"policy_id")==p.Policy.Id&&RiskJson.Int(row,"policy_version")==p.Policy.Version&&RiskJson.String(row,"policy_sha256")==p.Policy.Sha256&&RiskJson.String(row,"risk_class")==p.Assessment.Risk&&row["raw_score"]!.GetValue<decimal>()==p.Assessment.Raw&&RiskJson.Int(row,"display_points")==p.Assessment.Display&&!row["hard_critical"]!.GetValue<bool>()&&RiskJson.String(row,"rationale")==RiskJson.Text(p.Policy.Definition["risk"]!["rationale"]),"password_risk_contribution_replay_conflict");
    }

    internal static async Task<JsonObject> Persist(RiskSql sql,PasswordRiskProposal p,JsonObject? existing,CancellationToken ct)
    {
        // Native authorization precedes internal scenario writes as in verify_qw_proposal.
        await PasswordRiskProof.VerifyPortion(sql,p.Signal,ct);
        Guid scenario=existing!=null?Guid.Parse(RiskJson.String(existing,"scenario_id")):AuthAudit.Uuid5("adlog:semantic-scenario:"+p.Identity);
        if(existing==null) {
            await sql.Execute("""
                insert into public.semantic_security_scenarios(scenario_id,scenario_kind,result_class,identity_key,scenario_key,
                  partition_key,strict_keys_json,merge_window_seconds,title,explanation,first_seen_utc,last_seen_utc,
                  risk_class,raw_score,display_score,hard_critical,confidence,confidence_score,confidence_factors_json,coverage_status)
                values(@scenario,@kind,'security_incident',@identity,@identity,@partition,@strict::jsonb,600,@title,@explanation,@at,@at,
                  @risk,@raw,@display,false,@confidence,@score,@factors::jsonb,'unknown') on conflict(scenario_key) do nothing
                """,ct,("scenario",scenario),("kind",p.Policy.Rule.Id),("identity",Convert.FromHexString(p.Identity)),("partition",p.Partition),("strict",p.Strict),("title",RiskJson.String(p.Policy.Definition,"title")),("explanation",RiskJson.String(p.Policy.Definition,"explanation")),("at",p.At),("risk",p.Assessment.Risk),("raw",p.Assessment.Raw),("display",p.Assessment.Display),("confidence",p.Assessment.Confidence),("score",p.Assessment.Score),("factors",p.Assessment.Factors));
            var rows=await sql.Rows("select * from public.semantic_security_scenarios where scenario_key=@key for update",ct,("key",Convert.FromHexString(p.Identity)));
            RiskJson.Require(rows.Count==1&&RiskJson.String(rows[0],"scenario_id")==scenario.ToString(),"password_risk_scenario_identity_conflict");Identity(rows[0],p);
        }
        Guid step=AuthAudit.Uuid5("adlog:scenario-step:"+p.StepKey);
        await sql.Execute("""
            insert into public.semantic_scenario_steps(step_id,scenario_id,step_key,source_kind,occurred_at_utc,title,explanation,
              confidence,confidence_score,confidence_factors_json,qw_signal_id)
            values(@step,@scenario,@key,'qw_signal',@at,@title,@explanation,@confidence,@score,@factors::jsonb,@signal) on conflict(step_key) do nothing
            """,ct,("step",step),("scenario",scenario),("key",Convert.FromHexString(p.StepKey)),("at",p.At),("title",RiskJson.String(p.Policy.Definition,"title")),("explanation",RiskJson.String(p.Policy.Definition,"explanation")),("confidence",p.Assessment.Confidence),("score",p.Assessment.Score),("factors",p.Assessment.Factors),("signal",p.Signal.Id));
        var steps=await sql.Rows("select * from public.semantic_scenario_steps where step_key=@key",ct,("key",Convert.FromHexString(p.StepKey)));
        RiskJson.Require(steps.Count==1,"password_risk_step_replay_conflict");var stored=steps[0];
        RiskJson.Require(RiskJson.String(stored,"step_id")==step.ToString()&&RiskJson.String(stored,"scenario_id")==scenario.ToString()&&RiskJson.String(stored,"source_kind")=="qw_signal"&&RiskJson.String(stored,"qw_signal_id")==p.Signal.Id&&PasswordJson.Time(stored["occurred_at_utc"])==p.At&&RiskJson.String(stored,"title")==RiskJson.String(p.Policy.Definition,"title")&&RiskJson.String(stored,"explanation")==RiskJson.String(p.Policy.Definition,"explanation")&&RiskJson.String(stored,"confidence")==p.Assessment.Confidence&&RiskJson.Int(stored,"confidence_score")==p.Assessment.Score&&JsonNode.DeepEquals(stored["confidence_factors_json"],p.Assessment.Factors),"password_risk_step_replay_conflict");
        Guid contribution=AuthAudit.Uuid5("adlog:risk-contribution:"+p.ContributionKey);
        await sql.Execute("""
            insert into public.semantic_risk_contributions(contribution_id,scenario_id,contribution_key,source_kind,policy_id,policy_version,
              policy_sha256,risk_class,raw_score,display_points,hard_critical,rationale,qw_signal_id)
            values(@id,@scenario,@key,'qw_signal',@policy,@version,@sha,@risk,@raw,@display,false,@rationale,@signal) on conflict(contribution_key) do nothing
            """,ct,("id",contribution),("scenario",scenario),("key",Convert.FromHexString(p.ContributionKey)),("policy",p.Policy.Id),("version",p.Policy.Version),("sha",Convert.FromHexString(p.Policy.Sha256)),("risk",p.Assessment.Risk),("raw",p.Assessment.Raw),("display",p.Assessment.Display),("rationale",RiskJson.Text(p.Policy.Definition["risk"]!["rationale"])),("signal",p.Signal.Id));
        var contributions=await sql.Rows("select * from public.semantic_risk_contributions where contribution_key=@key",ct,("key",Convert.FromHexString(p.ContributionKey)));
        RiskJson.Require(contributions.Count==1&&RiskJson.String(contributions[0],"contribution_id")==contribution.ToString()&&RiskJson.String(contributions[0],"scenario_id")==scenario.ToString(),"password_risk_contribution_assignment_conflict");VerifyContribution(contributions[0],p);
        // Managed default compiled contract has no controls or normalized evidence. Native QW evidence stays on immutable steps.
        return await Refresh(sql,scenario,ct);
    }

    private static string Coverage(IReadOnlyList<JsonObject> rows)
    {
        var statuses=rows.Select(r=>RiskJson.String(r,"coverage_status")).ToHashSet(StringComparer.Ordinal);
        if(statuses.Count==0||statuses.SetEquals(["unknown"]))return "unknown";
        if(statuses.SetEquals(["complete"]))return "complete";
        return statuses.IsSubsetOf(["unavailable","unknown"])?"unavailable":"partial";
    }

    private static async Task<JsonObject> Refresh(RiskSql sql,Guid scenario,CancellationToken ct)
    {
        var contributions=await sql.Rows("""
            select contribution.source_kind,contribution.risk_class,contribution.raw_score,contribution.display_points,contribution.hard_critical,
              encode(sha256(convert_to((signal.document_json->'evidence_refs')::text,'UTF8')),'hex') as evidence_key
            from public.semantic_risk_contributions contribution left join public.semantic_qw_signals signal on signal.signal_id=contribution.qw_signal_id
            where contribution.scenario_id=@scenario order by contribution.contribution_id
            """,ct,("scenario",scenario));
        RiskJson.Require(contributions.Count>0&&contributions.All(r=>RiskJson.String(r,"source_kind")=="qw_signal"&&r["evidence_key"]!=null),"password_risk_scenario_invalid");
        var risk=Aggregate(contributions);
        var factors=await sql.Rows("select confidence_factors_json from public.semantic_scenario_steps where scenario_id=@scenario order by occurred_at_utc,step_id",ct,("scenario",scenario));
        var coverageRows=await sql.Rows("""
            select distinct on(control_id) control_id,coverage_status,reason,observed_at_utc from public.semantic_scenario_coverage_history
            where scenario_id=@scenario order by control_id,observed_at_utc desc,coverage_id desc
            """,ct,("scenario",scenario));
        string coverage=Coverage(coverageRows);RiskJson.Require(factors.Count>0,"password_risk_steps_unavailable");
        var assessment=factors.Select(f=>PasswordRiskProposal.Assess(risk.Raw,risk.Display,risk.Hard,risk.Class,RiskJson.Obj(f["confidence_factors_json"]),coverage)).MinBy(a=>a.Score)!;
        var countRows=await sql.Rows("""
            select min(occurred_at_utc) as first_seen_utc,max(occurred_at_utc) as last_seen_utc,count(*)::integer as step_count,
              (select count(*) from public.semantic_scenario_evidence where scenario_id=@scenario)+
              (select count(distinct ref) from public.semantic_scenario_steps step join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id,
                lateral jsonb_array_elements(signal.document_json->'evidence_refs') ref where step.scenario_id=@scenario) as evidence_count,
              (select count(*)::integer from public.semantic_risk_contributions where scenario_id=@scenario) as contribution_count,
              (select coalesce(max((signal.document_json->>'evidence_total')::integer),0) from public.semantic_scenario_steps step
                join public.semantic_qw_signals signal on signal.signal_id=step.qw_signal_id where step.scenario_id=@scenario) as expected_evidence_count
            from public.semantic_scenario_steps where scenario_id=@scenario
            """,ct,("scenario",scenario));
        RiskJson.Require(countRows.Count==1,"password_risk_scenario_counts_invalid");var counts=countRows[0];
        var rows=await sql.Rows("""
            update public.semantic_security_scenarios set first_seen_utc=@first,last_seen_utc=@last,risk_class=@risk,raw_score=@raw,
              display_score=@display,hard_critical=@hard,confidence=@confidence,confidence_score=@score,confidence_factors_json=@factors::jsonb,
              coverage_status=@coverage,step_count=@steps,evidence_count=@evidence,contribution_count=@contributions,evidence_state=@state,updated_at=now()
            where scenario_id=@scenario returning *
            """,ct,("first",PasswordJson.Time(counts["first_seen_utc"])),("last",PasswordJson.Time(counts["last_seen_utc"])),("risk",assessment.Risk),("raw",assessment.Raw),("display",assessment.Display),("hard",assessment.HardCritical),("confidence",assessment.Confidence),("score",assessment.Score),("factors",assessment.Factors),("coverage",assessment.Coverage),("steps",RiskJson.Int(counts,"step_count")),("evidence",RiskJson.Long(counts,"evidence_count")),("contributions",RiskJson.Int(counts,"contribution_count")),("state",RiskJson.Long(counts,"evidence_count")<RiskJson.Int(counts,"expected_evidence_count")?"evidence_pending":"ready"),("scenario",scenario));
        RiskJson.Require(rows.Count==1,"password_risk_scenario_aggregate_missing");return rows[0];
    }

    internal static (decimal Raw,int Display,string Class,bool Hard) Aggregate(IReadOnlyList<JsonObject> contributions)
    {
        var groups=contributions.GroupBy(c=>RiskJson.String(c,"evidence_key"));
        decimal raw=Math.Min(100000,groups.Sum(g=>g.Max(c=>c["raw_score"]!.GetValue<decimal>())));
        int display=Math.Min(100,groups.Sum(g=>g.Max(c=>RiskJson.Int(c,"display_points"))));
        string[] order=["info","low","medium","high","critical"];
        bool hard=contributions.Any(c=>c["hard_critical"]!.GetValue<bool>());string risk=contributions.Select(c=>RiskJson.String(c,"risk_class")).MaxBy(c=>Array.IndexOf(order,c))!;
        return(raw,display,hard?"critical":risk,hard);
    }

    internal static RiskAssessment Assessment(JsonObject scenario)=>new(scenario["raw_score"]!.GetValue<decimal>(),RiskJson.Int(scenario,"display_score"),RiskJson.String(scenario,"risk_class"),scenario["hard_critical"]!.GetValue<bool>(),RiskJson.String(scenario,"confidence"),RiskJson.Int(scenario,"confidence_score"),RiskJson.Obj(scenario["confidence_factors_json"]),RiskJson.String(scenario,"coverage_status"));
}
