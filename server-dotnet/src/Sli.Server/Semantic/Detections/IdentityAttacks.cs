using System.Net;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic.Detections;

public sealed record IdentityAttackPolicy(int KerberoastServices=5,int KerberoastSeconds=60,int FanoutHosts=4,int FanoutSeconds=600,int NewAccountSeconds=600,IReadOnlyList<string>? ServiceAccounts=null)
{
    public JsonObject Document=>new(){["kerberoast_services"]=KerberoastServices,["kerberoast_seconds"]=KerberoastSeconds,["fanout_hosts"]=FanoutHosts,["fanout_seconds"]=FanoutSeconds,["new_account_seconds"]=NewAccountSeconds,["service_accounts"]=D.Array(ServiceAccounts??[],s=>JsonValue.Create(s))};
    public void Validate(){D.Require(new[]{KerberoastServices,FanoutHosts}.All(n=>n is >=1 and <=256)&&new[]{KerberoastSeconds,FanoutSeconds,NewAccountSeconds}.All(n=>n is >=1 and <=600)&&(ServiceAccounts?.Count??0)<=256&&(ServiceAccounts??[]).All(s=>s.Length is >=1 and <=256&&s==s.Trim()),"identity_attack_policy_invalid");}
    public static IdentityAttackPolicy Read(JsonNode? n)
    {
        if(n is null)return new();D.Require(n.AsObject().Count==6,"identity_attack_policy_invalid");var p=new IdentityAttackPolicy(n["kerberoast_services"]!.GetValue<int>(),n["kerberoast_seconds"]!.GetValue<int>(),n["fanout_hosts"]!.GetValue<int>(),n["fanout_seconds"]!.GetValue<int>(),n["new_account_seconds"]!.GetValue<int>(),n["service_accounts"]!.AsArray().Select(v=>v!.GetValue<string>()).ToArray());p.Validate();return p;
    }
}

public static class IdentityAttacks
{
    public static readonly IReadOnlyDictionary<string,string> Rules=new Dictionary<string,string>{["qw.kerberoasting"]="kerberoasting",["qw.asrep-roasting"]="asrep",["qw.ad-preauth-disabled"]="preauth",["qw.logon-fanout"]="fanout",["qw.privileged-group-addition"]="privilege"};
    private static bool Match(string s,string pattern)=>Regex.IsMatch(s,"\\A(?:"+pattern+")\\z",RegexOptions.IgnoreCase|RegexOptions.CultureInvariant);
    private static string Text(string s)=>s.Length<=512?UnicodeCaseFold.TrimAndFold(s):"";
    private static string? Client(string s)
    {
        if(!PasswordNative.StrictIp(s,out var ip,out _))return null;if(ip!.IsIPv4MappedToIPv6)ip=ip.MapToIPv4();var bytes=ip.GetAddressBytes();
        return ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)||IPAddress.IsLoopback(ip)||ip.IsIPv6Multicast||bytes.Length==4&&bytes[0] is >=224 and <=239?null:PasswordNative.CanonicalAddress(ip);
    }
    public static JsonObject Execution(PasswordScope scope,string rule,IdentityAttackPolicy? policy=null)
    {
        policy??=new();policy.Validate();D.Require(Rules.ContainsKey(rule),"identity_attack_rule_invalid");
        return new(){["version"]="sli.qw.execution.v1",["kind"]="threshold",["rule_id"]=rule,["rule_version"]=1,["rule_sha256"]=D.Hash(new JsonObject{["version"]=1,["rule_id"]=rule,["policy"]=policy.Document}),["scope"]=scope.Document};
    }
    private static JsonObject Signal(PasswordScope scope,string rule,JsonNode entity,IReadOnlyList<DetectionRow> rows,DateTimeOffset now,IdentityAttackPolicy policy,string[]? reasons=null,int? count=null)
    {
        var ordered=rows.OrderBy(r=>r.At).ThenBy(r=>long.Parse(r.Ref.NativeId)).ToArray();
        // Thresholds are evaluated per client, but the problem belongs to the account.
        if(rule is "qw.kerberoasting" or "qw.asrep-roasting")entity=new JsonArray(Text(ordered[0].Get("TargetDomainName")),Text(ordered[0].Get("TargetUserName")));
        JsonNode seed=rule=="qw.ad-preauth-disabled"?entity.DeepClone():JsonValue.Create(long.Parse(ordered[0].Ref.NativeId))!;
        return DetectionSignal.Create(rule,"threshold",D.Text(Execution(scope,rule,policy)["rule_sha256"]),D.Hash(entity),D.Hash(new JsonArray(JsonValue.Create(rule),entity.DeepClone(),seed)),ordered.Select(r=>r.Ref),ordered[^1].At,now,rule=="qw.ad-preauth-disabled"?"medium":"high","identity_context",new(){["version"]=1,["policy"]=policy.Document,["count"]=count??ordered.Length},reasons,ordered.Length);
    }
    public static IReadOnlyList<JsonObject> Evaluate(PasswordScope scope,IReadOnlyList<DetectionRow> rows,DateTimeOffset now,IdentityAttackPolicy? policy=null)
    {
        policy??=new();policy.Validate();D.Require(scope.PluginId=="sli.windows.ad-dc"&&scope.CollectionScopeId=="","identity_attack_source_invalid");D.Require(rows.Count<=10000,"identity_attack_window_truncated");
        var unique=new Dictionary<string,DetectionRow>();foreach(var r in rows){D.Require(r.Ref.Scope==scope,"identity_attack_source_invalid");if(unique.TryGetValue(r.Ref.NativeId,out var old))D.Require(old.Ref==r.Ref&&old.At==r.At&&old.EventId==r.EventId&&old.Host==r.Host&&JsonNode.DeepEquals(old.Fields,r.Fields),"identity_attack_native_conflict");unique[r.Ref.NativeId]=r;}
        var groups=new SortedDictionary<string,(string Rule,JsonNode Entity,List<(DetectionRow Row,string Dimension)> Rows)>(StringComparer.Ordinal);var created=new Dictionary<string,DetectionRow>(StringComparer.OrdinalIgnoreCase);var privilege=new Dictionary<string,(JsonNode Entity,List<DetectionRow> Proof,string[] Reasons)>();
        var excluded=(policy.ServiceAccounts??[]).Select(UnicodeCaseFold.Fold).ToHashSet(StringComparer.Ordinal);
        void Add(string rule,JsonNode entity,DetectionRow row,string dimension=""){string key=rule+":"+Sli.Agent.Protocol.CanonicalJson.Serialize(entity);if(!groups.TryGetValue(key,out var g))g=(rule,entity,[]);g.Rows.Add((row,dimension));groups[key]=g;}
        foreach(var row in unique.Values.Where(r=>r.At<=now).OrderBy(r=>r.At).ThenBy(r=>long.Parse(r.Ref.NativeId))){
            string account=Text(row.Get("TargetUserName")),domain=Text(row.Get("TargetDomainName"));var address=Client(row.Get("IpAddress"));long? Num(string k)=>D.Number(row.Fields?[k]);
            if(row.EventId==4769&&address!=null&&account is not ("" or "-")&&Num("Status")==0&&Num("TicketEncryptionType")==23){string service=Text(row.Get("ServiceName"));if(service is not ("" or "-" or "krbtgt")&&!service.StartsWith("krbtgt/",StringComparison.Ordinal)&&!service.EndsWith('$'))Add("qw.kerberoasting",new JsonArray(address,domain,account),row,service);}
            if(row.EventId==4768&&Num("PreAuthType")==0&&Num("Status")==0&&account is not ("" or "-"))Add("qw.asrep-roasting",new JsonArray(address,domain,account),row);
            if(row.EventId==4624&&Num("LogonType") is 3 or 10&&account is not ("" or "-")){
                string host=Text(row.Get("Computer"));if(host=="")host=Text(row.Host);string sid=Text(row.Get("TargetUserSid"));JsonNode entity=Match(sid,@"S-1-5-21-\d+-\d+-\d+-\d+")?new JsonArray("sid",sid):new JsonArray(domain,account);
                if(host!=""&&!account.EndsWith('$')&&!excluded.Contains(account)&&!excluded.Contains(domain+"\\"+account)&&!excluded.Contains(sid))Add("qw.logon-fanout",entity,row,host);
            }
            string target=row.Get("TargetSid").ToUpperInvariant();if(row.EventId==4720&&Match(target,@"S-1-5-21-\d+-\d+-\d+-\d+"))created[target]=row;
            if(row.EventId is 4728 or 4732 or 4756&&(Match(target,@"S-1-5-21-\d+-\d+-\d+-(512|518|519)")||new[]{"S-1-5-32-544","S-1-5-32-548","S-1-5-32-549","S-1-5-32-551"}.Contains(target))){
                string member=row.Get("MemberSid").ToUpperInvariant();if(!Match(member,@"S-1-\d+(?:-\d+)+"))continue;
                var proof=new List<DetectionRow>{row};string[] reasons=[];if(created.TryGetValue(member,out var prior)&&row.At-prior.At<=TimeSpan.FromSeconds(policy.NewAccountSeconds)){proof.Insert(0,prior);reasons=["new_account_privileged"];}
                string key=member+":"+target+":"+row.Ref.NativeId;
                privilege[key]=(new JsonArray(member,target),proof,reasons);
            }
        }
        var result=new List<JsonObject>();foreach(var g in groups.Values){
            if(g.Rule=="qw.asrep-roasting"){result.Add(Signal(scope,g.Rule,g.Entity,g.Rows.TakeLast(256).Select(r=>r.Row).ToArray(),now,policy));continue;}
            int seconds=g.Rule=="qw.kerberoasting"?policy.KerberoastSeconds:policy.FanoutSeconds,threshold=g.Rule=="qw.kerberoasting"?policy.KerberoastServices:policy.FanoutHosts;
            var window=new Queue<(DetectionRow Row,string Dimension)>();DetectionRow[] proof=[];
            foreach(var member in g.Rows){while(window.TryPeek(out var first)&&member.Row.At-first.Row.At>TimeSpan.FromSeconds(seconds))window.Dequeue();window.Enqueue(member);if(window.Select(r=>r.Dimension).Distinct().Count()>=threshold){var dimensions=new Dictionary<string,DetectionRow>();foreach(var r in window)dimensions[r.Dimension]=r.Row;proof=dimensions.Values.Take(256).ToArray();}}
            if(proof.Length>0)result.Add(Signal(scope,g.Rule,g.Entity,proof,now,policy,count:proof.Length));
        }
        foreach(var p in privilege.OrderBy(p=>p.Key,StringComparer.Ordinal).Select(p=>p.Value))result.Add(Signal(scope,"qw.privileged-group-addition",p.Entity,p.Proof,now,policy,p.Reasons));return result;
    }
    public static IReadOnlyList<JsonObject> EvaluateSnapshot(PasswordScope scope,IReadOnlyList<DetectionRow> rows,DateTimeOffset now,IdentityAttackPolicy? policy=null)
    {
        policy??=new();policy.Validate();D.Require(scope.PluginId=="sli.ad-snapshot"&&scope.CollectionScopeId==""&&rows.Count<=10000,"identity_attack_snapshot_invalid");var result=new List<JsonObject>();var seen=new HashSet<string>();
        foreach(var row in rows){if(row.At>now||!seen.Add(row.Ref.NativeId))continue;var record=row.Record!;var uac=D.Number(record["attributes"]?["user_account_control"]);var entity=D.Text(record["identity"]?["object_guid"]);if(entity=="")entity=D.Text(record["identity"]?["object_sid"]);
            if(D.Text(record["identity"]?["kind"])=="ad_user"&&uac.HasValue&&(uac.Value&0x400000)!=0&&entity!="")result.Add(Signal(scope,"qw.ad-preauth-disabled",JsonValue.Create(entity)!,[row],now,policy));
        }return result;
    }
    public static IdentityAttackPolicy Validate(JsonObject signal)
    {
        DetectionSignal.ValidateEnvelope(signal);var context=signal["identity_context"]!.AsObject();var policy=IdentityAttackPolicy.Read(context["policy"]);string rule=D.Text(signal["rule_id"]);var scope=DetectionRef.Read(signal["evidence_refs"]![0]).Scope;
        bool snapshot=rule=="qw.ad-preauth-disabled";string severity=snapshot?"medium":"high";var reasons=signal["severity_reasons"]!.AsArray().Select(D.Text).ToArray();
        D.Require(context.Count==3&&context["version"]!.GetValue<int>()==1&&context["count"]!.GetValue<int>() is >=1 and <=10000&&JsonNode.DeepEquals(DetectionSignal.Execution(signal),Execution(scope,rule,policy))&&scope.PluginId==(snapshot?"sli.ad-snapshot":"sli.windows.ad-dc")&&scope.CollectionScopeId==""&&D.Text(signal["quality"])=="good"&&D.Text(signal["base_severity"])==severity&&D.Text(signal["effective_severity"])==severity&&signal["evidence_total"]!.GetValue<int>()==signal["evidence_refs"]!.AsArray().Count&&(reasons.Length==0||rule=="qw.privileged-group-addition"&&reasons.SequenceEqual(new[]{"new_account_privileged"}))&&signal["evidence_refs"]!.AsArray().Select(DetectionRef.Read).All(r=>r.Kind==(snapshot?"ad_directory_observation":"core_event")),"identity_attack_signal_invalid");return policy;
    }
    public static JsonObject PolicyDefinition(PasswordScope scope,string rule,IdentityAttackPolicy? policy=null)
    {
        bool snapshot=rule=="qw.ad-preauth-disabled";string prefix="security.problems.presentation."+Rules[rule];return new(){["type"]="scenario_policy",["source_selector"]=new JsonObject{["rule_id"]=rule,["execution"]=Execution(scope,rule,policy)},["scenario_kind"]=rule,["result_class"]="security_incident",["merge_window_seconds"]=600,["title"]=DetectionMessages.Text(prefix+"_title"),["explanation"]=DetectionMessages.Text(prefix+"_what"),["risk"]=new JsonObject{["class"]=snapshot?"medium":"high",["raw_score"]=snapshot?"25":"60",["display_points"]=snapshot?25:60,["rationale"]=DetectionMessages.Text(prefix+"_why")}};
    }
}
