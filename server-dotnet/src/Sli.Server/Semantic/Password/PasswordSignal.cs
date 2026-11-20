using System.Text.Json.Nodes;
using Sli.Agent.Protocol;

namespace Sli.Server.Semantic.Password;

public static class PasswordSignal
{
    public static JsonObject Create(PasswordRule rule,PasswordEmission emission,JsonObject context,DateTimeOffset received,IEnumerable<PasswordNative>? native=null,IReadOnlyList<PasswordEmission>? history=null)
    {
        int index=context["portion_index"]!.GetValue<int>();
        // QW evidence ordering is lexicographic over ref.params, not numeric native ID.
        var refs=emission.Occurrences.Skip(index*256).Take(256).OrderBy(w=>w.NativeId.ToString(System.Globalization.CultureInfo.InvariantCulture),StringComparer.Ordinal).ToArray();
        var document=new JsonObject{["kind"]="threshold",["rule_id"]=rule.Id,["rule_version"]=rule.Revision,["rule_sha256"]=rule.Execution["rule_sha256"]!.DeepClone(),["policy_revision"]=1,["evaluation_mode"]="enabled",["entity_key"]=emission.Entity,["episode_key"]=emission.EpisodeKey,["occurred_at_utc"]=PasswordJson.Stamp(emission.Endpoint.At),["received_at_utc"]=PasswordJson.Stamp(received),["evidence_refs"]=PasswordJson.Array(refs,w=>w.Ref),["base_severity"]="high",["effective_severity"]="high",["severity_reasons"]=new JsonArray(),["quality"]="good",["conclusion_state"]="observed",["evidence_total"]=emission.Occurrences.Count,["password_context"]=context.DeepClone()};
        var reasons=SprayEvidence(rule,(history??[]).Append(emission),native??[]);document["severity_reasons"]=PasswordJson.Array(reasons,s=>JsonValue.Create(s));document["effective_severity"]=reasons.Contains("success_after_spray")?"critical":"high";
        if(PasswordJson.SpacedSize(document)>524288)throw new PasswordFailure("password_v2_signal_invalid");return document;
    }
    internal static string[] SprayEvidence(PasswordRule rule,IEnumerable<PasswordEmission> emissions,IEnumerable<PasswordNative> native)
    {
        if(rule.Kind!="spray")return [];var refs=emissions.SelectMany(e=>e.Occurrences).Select(w=>w.Ref.ToJsonString()).ToHashSet();var rows=native.Where(n=>refs.Contains(n.Witness.Ref.ToJsonString())).DistinctBy(n=>n.Witness).OrderBy(n=>n.Witness.At).ThenBy(n=>n.Witness.NativeId).ToArray();var failures=rows.Where(n=>n.Member.Reason==null&&n.EventId!=4624).ToArray();var reasons=new List<string>();
        var counts=failures.GroupBy(n=>n.Member.TargetKey).Select(g=>g.Count()).ToArray();if(counts.Length>0&&counts.Max()<=2)reasons.Add("machine_tempo_spray");var intervals=failures.Zip(failures.Skip(1),(a,b)=>(b.Witness.At-a.Witness.At).TotalSeconds).ToArray();
        if(intervals.Length>=3&&intervals.Min()>0){double mean=intervals.Average();if(intervals.Max(i=>Math.Abs(i-mean))<=mean*0.10)reasons.Add("regular_intervals");}
        foreach(var success in rows.Where(n=>n.EventId==4624)){var preceding=failures.Where(n=>n.Witness.At>=success.Witness.At.AddSeconds(-600)&&n.Witness.At<success.Witness.At&&n.Member.ClientKey==success.Member.ClientKey).ToArray();if(preceding.Select(n=>n.Member.TargetKey).Distinct().Count()>=5&&preceding.Any(n=>n.Member.TargetKey==success.Member.TargetKey)){reasons.Add("success_after_spray");break;}}
        return reasons.ToArray();
    }
    public static string Id(JsonObject document){var copy=(JsonObject)document.DeepClone();copy.Remove("received_at_utc");return PasswordJson.Hash(copy);}
    // Family identity spans v1/v2. It grants no source or execution authority.
    public static string FamilyKey(object? scope,object? ruleId)
    {
        const string code="password_policy_family_invalid";
        if(ruleId is not string id||id is not (PasswordRule.RuleId or "qw.password-spray"))throw new PasswordFailure(code);
        var document=scope switch{PasswordScope value=>value.Document,JsonObject value=>value,_=>null};
        string[] fields=["installation_id","plugin_id","source_instance_id","source_generation","collection_scope_id"];
        if(document==null||document.Count!=fields.Length||fields.Any(f=>document[f] is not JsonValue v||!v.TryGetValue<string>(out _)))throw new PasswordFailure(code);
        string Text(string field)=>document[field]!.GetValue<string>();
        string installation=Text("installation_id");
        if(!Guid.TryParseExact(installation,"D",out var uuid)||uuid.ToString("D")!=installation)throw new PasswordFailure(code);
        foreach(var (field,minimum,maximum) in new[]{("plugin_id",1,128),("source_instance_id",1,256),("source_generation",1,512),("collection_scope_id",0,256)})
        {
            string value=Text(field);int length=value.EnumerateRunes().Count();
            if(value!=PasswordJson.Trim(value)||length<minimum||length>maximum)throw new PasswordFailure(code);
        }
        return "sli.password.policy-family.1:"+PasswordJson.Hash(document)+":"+id;
    }
    private static PasswordRule PolicyRule(PasswordRule? rule)=>rule??throw new PasswordFailure("password_policy_rule_invalid");
    public static string PolicyId(PasswordRule? rule){rule=PolicyRule(rule);return "default:"+rule.Id+":"+rule.Pin[..32];}
    public static JsonObject PolicyDefinition(PasswordRule? rule)
    {
        rule=PolicyRule(rule);
        return new(){["type"]="scenario_policy",["source_selector"]=new JsonObject{["rule_id"]=rule.Id,["execution"]=rule.Execution},["scenario_kind"]=rule.Id,["result_class"]="security_incident",["merge_window_seconds"]=600,["title"]=rule.Kind=="brute"?"Repeated password attempts against one account":"Passwords tried across several accounts",["explanation"]="Review the linked sign-in attempts and secure the affected accounts.",["risk"]=new JsonObject{["class"]="high",["raw_score"]="60",["display_points"]=60,["rationale"]="Observed password attack evidence requires review."}};
    }
}
