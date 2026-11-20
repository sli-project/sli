using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Risk;

public sealed class PasswordRiskFailure(string code):Exception(code);

internal static class RiskJson
{
    internal static string Hash(JsonNode node)=>Hash(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(node,ensureAscii:false)));
    internal static string Hash(byte[] bytes)=>Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static string Text(JsonNode? node)=>PasswordJson.Text(node);
    internal static string String(JsonObject row,string name)=>Text(row[name]);
    internal static int Int(JsonObject row,string name)=>row[name]!.GetValue<int>();
    internal static long Long(JsonObject row,string name)=>row[name]!.GetValue<long>();
    internal static JsonObject Obj(JsonNode? node)=>PasswordJson.Obj(node);
    internal static void Require(bool condition,string code="password_risk_source_conflict"){if(!condition)throw new PasswordRiskFailure(code);}
}

// A deliberately explicit compiled contract: unsupported families/custom policies are never leased.
internal sealed record PasswordRiskPolicy(string Id,int Version,string Sha256,PasswordRule Rule,JsonObject Definition)
{
    internal static PasswordRiskPolicy Compile(string id,int version,JsonObject definition)
    {
        try {
            var execution=definition["source_selector"]!["execution"]!;
            var rule=new PasswordRule(PasswordScope.Read(execution["scope"]),RiskJson.Text(execution["rule_id"]) switch {PasswordRule.RuleId=>"brute","qw.password-spray"=>"spray",_=>throw new PasswordRiskFailure("password_risk_policy_unsupported")},execution["rule_version"]!.GetValue<int>());
            RiskJson.Require(version==1&&id==PasswordSignal.PolicyId(rule)&&JsonNode.DeepEquals(definition,PasswordSignal.PolicyDefinition(rule)),"password_risk_policy_unsupported");
            return new(id,version,RiskJson.Hash(definition),rule,(JsonObject)definition.DeepClone());
        }catch(PasswordRiskFailure){throw;}
        catch(Exception error)when(error is ArgumentException or InvalidOperationException or NullReferenceException or KeyNotFoundException or PasswordFailure or FormatException){throw new PasswordRiskFailure("password_risk_policy_unsupported");}
    }
}

internal sealed record PasswordRiskSignal(PasswordRule Rule,JsonObject Document,IReadOnlyList<PasswordWitness> Witnesses)
{
    internal string Id=>PasswordSignal.Id(Document);
    internal string Entity=>RiskJson.String(Document,"entity_key");
    internal string Episode=>RiskJson.String(Document,"episode_key");
    internal string Mode=>RiskJson.String(Document,"evaluation_mode");
    internal DateTimeOffset At=>PasswordJson.Time(Document["occurred_at_utc"]);
    internal JsonObject Context=>RiskJson.Obj(Document["password_context"]);
    internal JsonArray Refs=>Document["evidence_refs"]!.AsArray();
    internal static PasswordRiskSignal Read(JsonObject document)
    {
        try {
            string[] fields=["kind","rule_id","rule_version","rule_sha256","policy_revision","evaluation_mode","entity_key","episode_key","occurred_at_utc","received_at_utc","evidence_refs","base_severity","effective_severity","severity_reasons","quality","conclusion_state","evidence_total","password_context"];
            RiskJson.Require(fields.All(document.ContainsKey)&&document.All(p=>fields.Contains(p.Key)||p.Key=="processing_mode"));
            RiskJson.Require(document["processing_mode"]==null||RiskJson.String(document,"processing_mode") is "live" or "historical_replay" or "history_import");
            RiskJson.Require(RiskJson.String(document,"kind")=="threshold"&&(RiskJson.String(document,"rule_id") is PasswordRule.RuleId or "qw.password-spray")&&RiskJson.Int(document,"rule_version")>=2&&RiskJson.Int(document,"policy_revision")==1);
            RiskJson.Require(RiskJson.String(document,"evaluation_mode") is "enabled" or "shadow" or "test");
            var reasons=document["severity_reasons"]!.AsArray().Select(RiskJson.Text).ToArray();bool spray=RiskJson.String(document,"rule_id")=="qw.password-spray";
            RiskJson.Require(reasons.Distinct().Count()==reasons.Length&&reasons.All(r=>spray&&r is "machine_tempo_spray" or "regular_intervals" or "success_after_spray")&&RiskJson.String(document,"base_severity")=="high"&&RiskJson.String(document,"effective_severity")== (reasons.Contains("success_after_spray")?"critical":"high")&&RiskJson.String(document,"quality")=="good"&&RiskJson.String(document,"conclusion_state")=="observed");
            var refs=document["evidence_refs"]!.AsArray();RiskJson.Require(refs.Count is >=1 and <=256);
            var rule=new PasswordRule(PasswordScope.Read(refs[0]!["scope"]),RiskJson.String(document,"rule_id")==PasswordRule.RuleId?"brute":"spray",RiskJson.Int(document,"rule_version"));var context=RiskJson.Obj(document["password_context"]);
            string[] contextKeys=["version","episode_key","pin","epoch","entity","sequence","emission_id","root_id","previous_id","seed","endpoint_ordinal","origin_count","root_from","root_count","new_from","new_count","occurrence_total","portion_total","known_bad_password","unknown_account","other_failure","distinct_names","portion_index","occurrence_from","occurrences"];
            RiskJson.Require(context.Count==contextKeys.Length&&contextKeys.All(context.ContainsKey)&&RiskJson.String(context,"version")=="sli.password.v2.portion.1");
            RiskJson.Require(RiskJson.String(document,"rule_sha256")==RiskJson.Text(rule.Execution["rule_sha256"])&&RiskJson.String(context,"pin")==rule.Pin&&RiskJson.String(context,"entity")==RiskJson.String(document,"entity_key")&&RiskJson.String(context,"episode_key")==RiskJson.String(document,"episode_key"));
            foreach(var name in new[]{"entity_key","episode_key","rule_sha256"})RiskJson.Require(PasswordJson.Hex(RiskJson.String(document,name)));
            foreach(var name in new[]{"emission_id","root_id"})RiskJson.Require(PasswordJson.Hex(RiskJson.String(context,name)));
            int index=RiskJson.Int(context,"portion_index"),total=RiskJson.Int(context,"portion_total"),occurrences=RiskJson.Int(context,"occurrence_total");
            RiskJson.Require(index>=0&&index<total&&total is >=1 and <=256&&occurrences is >=1 and <=10000&&total==(occurrences+255)/256&&RiskJson.Int(context,"occurrence_from")==256*index&&RiskJson.Int(document,"evidence_total")==occurrences&&RiskJson.Int(context,"endpoint_ordinal")==occurrences-1&&RiskJson.Int(context,"sequence")>0&&RiskJson.Long(context,"epoch")>=0);
            var witnesses=context["occurrences"]!.AsArray().Select(w=>PasswordWitness.FromCompact(rule.Scope,w)).ToArray();
            RiskJson.Require(witnesses.Length==Math.Min(256,occurrences-256*index)&&witnesses.Select(w=>w.NativeId).Distinct().Count()==witnesses.Length);
            var ordered=witnesses.OrderBy(w=>w.NativeId.ToString(System.Globalization.CultureInfo.InvariantCulture),StringComparer.Ordinal).ToArray();
            RiskJson.Require(JsonNode.DeepEquals(refs,PasswordJson.Array(ordered,w=>w.Ref)));
            var at=PasswordJson.Time(document["occurred_at_utc"]);var received=PasswordJson.Time(document["received_at_utc"]);
            RiskJson.Require(index!=total-1||at==witnesses[^1].At);
            RiskJson.Require(PasswordJson.SpacedSize(document)<=524288);
            var normalized=(JsonObject)document.DeepClone();normalized["occurred_at_utc"]=PasswordJson.Stamp(at);normalized["received_at_utc"]=PasswordJson.Stamp(received);
            if(normalized["processing_mode"]?.GetValue<string>()=="live")normalized.Remove("processing_mode");
            return new(rule,normalized,witnesses);
        }catch(PasswordRiskFailure){throw;}
        catch(Exception error)when(error is ArgumentException or InvalidOperationException or NullReferenceException or KeyNotFoundException or PasswordFailure or FormatException or IndexOutOfRangeException or OverflowException){throw new PasswordRiskFailure("password_risk_signal_invalid");}
    }
}

internal sealed record PasswordRiskEpisode(PasswordRule Rule,IReadOnlyList<PasswordRiskSignal> Signals,IReadOnlyList<PasswordEmission> Emissions)
{
    internal IReadOnlyList<PasswordWitness> Witnesses=>Emissions.SelectMany(e=>e.Occurrences).ToArray();
    internal static PasswordRiskEpisode Read(IReadOnlyList<PasswordRiskSignal> signals,string sourceId)
    {
        RiskJson.Require(signals.Count is >=1 and <=256,"password_risk_evidence_pending");
        var rule=signals[0].Rule;var contexts=new List<JsonObject>();var group=new List<PasswordRiskSignal>();var emissions=new List<PasswordEmission>();
        foreach(var signal in signals) {
            RiskJson.Require(signal.Rule.Pin==rule.Pin&&signal.Episode==signals[0].Episode&&signal.Entity==signals[0].Entity&&signal.Mode==signals[0].Mode,"password_risk_chain_invalid");
            RiskJson.Require(RiskJson.Int(signal.Context,"sequence")==emissions.Count+1&&RiskJson.Int(signal.Context,"portion_index")==contexts.Count,"password_risk_chain_invalid");
            contexts.Add(signal.Context);group.Add(signal);
            if(contexts.Count==RiskJson.Int(signal.Context,"portion_total")) {
                var emission=PasswordEmission.Reassemble(rule.Scope,contexts);
                foreach(var item in group) {
                    var expected=PasswordSignal.Create(rule,emission,item.Context,PasswordJson.Time(item.Document["received_at_utc"]));expected["evaluation_mode"]=item.Mode;
                    // Native verification below derives these again for the entire chain.
                    expected["severity_reasons"]=item.Document["severity_reasons"]!.DeepClone();expected["effective_severity"]=item.Document["effective_severity"]!.DeepClone();
                    if(item.Document["processing_mode"]!=null&&RiskJson.String(item.Document,"processing_mode")!="live")expected["processing_mode"]=item.Document["processing_mode"]!.DeepClone();
                    var actual=(JsonObject)item.Document.DeepClone();if(actual["processing_mode"]?.GetValue<string>()=="live")actual.Remove("processing_mode");
                    RiskJson.Require(JsonNode.DeepEquals(actual,expected),"password_risk_chain_invalid");
                }
                if(emissions.Count>0)RiskJson.Require(RiskJson.String(signal.Context,"root_id")==emissions[0].Id&&emission.PreviousId==emissions[^1].Id&&emission.Seed==emissions[0].Seed&&emission.Epoch==emissions[0].Epoch,"password_risk_chain_invalid");
                emissions.Add(emission);contexts=[];group=[];
            }
        }
        RiskJson.Require(contexts.Count==0&&emissions.Count>0&&signals.Any(s=>s.Id==sourceId),"password_risk_evidence_pending");
        RiskJson.Require(emissions.Sum(e=>e.Occurrences.Count)<=10000,"password_risk_proof_bound");
        return new(rule,signals,emissions);
    }
    internal bool ContainsExactly(IEnumerable<string> ids)=>Signals.Select(s=>s.Id).ToHashSet(StringComparer.Ordinal).SetEquals(ids);
    internal PasswordBudget Verify(IEnumerable<PasswordNative> native)
    {
        var records=native.ToArray();var budget=Rule.VerifyChain(Emissions,records);
        foreach(var signal in Signals){int sequence=RiskJson.Int(signal.Context,"sequence");var expected=PasswordSignal.Create(Rule,Emissions[sequence-1],signal.Context,PasswordJson.Time(signal.Document["received_at_utc"]),records,Emissions.Take(sequence-1).ToArray());RiskJson.Require(JsonNode.DeepEquals(expected["severity_reasons"],signal.Document["severity_reasons"])&&JsonNode.DeepEquals(expected["effective_severity"],signal.Document["effective_severity"]),"password_risk_native_severity_conflict");}return budget;
    }
}

internal sealed record RiskAssessment(decimal Raw,int Display,string Risk,bool HardCritical,string Confidence,int Score,JsonObject Factors,string Coverage);

internal sealed record PasswordRiskProposal(PasswordRiskPolicy Policy,PasswordRiskSignal Signal,string Partition,string EvidenceKey,JsonObject Strict,string Identity,string StepKey,string ContributionKey,RiskAssessment Assessment)
{
    internal DateTimeOffset At=>Signal.At;
    internal static PasswordRiskProposal Create(PasswordRiskPolicy policy,PasswordRiskSignal signal)
    {
        RiskJson.Require(policy.Rule.Pin==signal.Rule.Pin&&policy.Version==RiskJson.Int(signal.Document,"policy_revision"),"password_risk_policy_mismatch");
        string partition=PasswordJson.Hash(signal.Rule.Scope.Document);
        var refs=signal.Witnesses.OrderBy(w=>w.NativeId.ToString(System.Globalization.CultureInfo.InvariantCulture),StringComparer.Ordinal);
        string evidenceKey=PasswordJson.Hash(PasswordJson.Array(refs,w=>w.Params));
        var strict=new JsonObject{["kind"]="threshold",["entity"]=signal.Entity,["episode"]=signal.Episode};
        string identity=RiskJson.Hash(new JsonObject{["scenario_kind"]=policy.Rule.Id,["result_class"]="security_incident",["partition_key"]=partition,["strict_keys"]=strict.DeepClone(),["merge_window_seconds"]=600});
        string contribution=$"risk-policy:{policy.Id}:{policy.Version}:qw_signal:{signal.Id}";
        var factors=new JsonObject{["identity_resolution"]="exact",["state_confirmed"]=false,["multi_source_confirmed"]=false,["sequence_completeness"]=Math.Min(100,100*signal.Refs.Count),["time_quality"]="good",["parser_quality"]="good"};
        bool critical=RiskJson.String(signal.Document,"effective_severity")=="critical";
        return new(policy,signal,partition,evidenceKey,strict,identity,RiskJson.Hash(Encoding.UTF8.GetBytes("policy-step:"+contribution)),RiskJson.Hash(Encoding.UTF8.GetBytes(contribution)),Assess(critical?80:60,critical?80:60,false,critical?"critical":"high",factors,"unknown"));
    }
    internal static RiskAssessment Assess(decimal raw,int display,bool hard,string risk,JsonObject factors,string coverage)
    {
        int score=(RiskJson.String(factors,"identity_resolution") switch{"exact"=>25,"partial"=>12,"unresolved"=>0,"unknown"=>5,_=>throw new PasswordRiskFailure("password_risk_factors_invalid")})
            +(factors["state_confirmed"]!.GetValue<bool>()?15:0)+(factors["multi_source_confirmed"]!.GetValue<bool>()?15:0)+RiskJson.Int(factors,"sequence_completeness")/5;
        foreach(string name in new[]{"time_quality","parser_quality"})score+=RiskJson.String(factors,name) switch{"good"=>10,"degraded"=>5,"poor"=>0,"unknown"=>2,_=>throw new PasswordRiskFailure("password_risk_factors_invalid")};
        score=Math.Min(100,score+(coverage switch{"complete"=>5,"partial"=>2,_=>0}));
        bool hasSignal=RiskJson.String(factors,"identity_resolution")!="unknown"||factors["state_confirmed"]!.GetValue<bool>()||factors["multi_source_confirmed"]!.GetValue<bool>()||RiskJson.Int(factors,"sequence_completeness")>0||RiskJson.String(factors,"time_quality")!="unknown"||RiskJson.String(factors,"parser_quality")!="unknown"||coverage!="unknown";
        return new(raw,display,risk,hard,!hasSignal?"unknown":score>=80?"high":score>=50?"medium":"low",score,(JsonObject)factors.DeepClone(),coverage);
    }
}

internal static class PasswordRiskCompleteness
{
    // Source QW _source_channel_measurements returns no channels. Never infer freshness or absence.
    internal static JsonObject Capture(DateTimeOffset captured,DateTimeOffset at,JsonArray? catalogEntries=null)
    {
        using var stream=catalogEntries is null?typeof(PasswordRiskCompleteness).Assembly.GetManifestResourceStream("Sli.Server.Semantic.Risk.event_catalog.json")??throw new PasswordRiskFailure("password_risk_catalog_unavailable"):null;
        var entries=(catalogEntries??JsonNode.Parse(stream!)!["entries"]!.AsArray()).OfType<JsonObject>().ToArray();
        string[] classified=["base_risk","purpose_tier","noise_class","category"],schema=["lifecycle","correlation","required_fields"];
        bool Present(JsonNode? node)=>node!=null&&(node switch{JsonArray a=>a.Count>0,JsonObject o=>o.Count>0,JsonValue v=>v.ToJsonString()!="\"\"",_=>true});
        int full=entries.Count(e=>classified.All(k=>Present(e[k]))),ready=entries.Count(e=>schema.All(e.ContainsKey));
        return new(){["captured_at_utc"]=PasswordJson.Stamp(captured),["catalog_completeness"]=new JsonObject{["entry_count"]=entries.Length,["fully_classified"]=full,["classification_ratio"]=entries.Length==0?1.0:(double)full/entries.Length,["schema_v2_ready"]=ready},["collection_freshness"]=new JsonObject{["max_age_seconds"]=null,["budget_seconds"]=1800,["complete"]=false},["channel_availability"]=new JsonObject{["required"]=new JsonArray(),["available"]=new JsonArray(),["available_count"]=0,["required_count"]=0,["complete"]=false},["window_closure"]=new JsonObject{["window_end_utc"]=PasswordJson.Stamp(at),["descriptor_close_timeout_seconds"]=null,["allowed_lateness_seconds"]=null,["close_deadline_utc"]=null,["closed"]=false},["supports_negative_conclusion"]=false};
    }
}
