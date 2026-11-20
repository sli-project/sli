using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Semantic.Detections;

public sealed record PrecursorPolicy(int FastFiles=30,int FastSeconds=30,int ReadFiles=200,int ReadShares=10,int ReadSeconds=300,int SilenceCorrelationSeconds=3600,IReadOnlyList<string>? BackupSids=null,IReadOnlyList<string>? BackupServices=null)
{
    public static readonly string[] DefaultBackupServices=["vss","swprv","wbengine","veeamendpointbackupsvc","veeamvsssupport"];
    public JsonObject Document=>new(){["fast_files"]=FastFiles,["fast_seconds"]=FastSeconds,["read_files"]=ReadFiles,["read_shares"]=ReadShares,["read_seconds"]=ReadSeconds,["silence_correlation_seconds"]=SilenceCorrelationSeconds,["backup_sids"]=D.Array(BackupSids??[],s=>JsonValue.Create(s)),["backup_services"]=D.Array(BackupServices??DefaultBackupServices,s=>JsonValue.Create(s))};
    public void Validate()
    {
        D.Require(new[]{FastFiles,ReadFiles,ReadShares}.All(v=>v is >=1 and <=255)&&new[]{FastSeconds,ReadSeconds,SilenceCorrelationSeconds}.All(v=>v is >=1 and <=86400),"t109_policy_invalid");
        foreach(var (values,pattern) in new[]{(BackupSids??[],@"S-1-(?:[0-9]+-)*[0-9]+"),(BackupServices??DefaultBackupServices,@"[a-zA-Z0-9_. -]{1,128}")})D.Require(values.Count<=100&&values.All(v=>v.Length<=184&&Regex.IsMatch(v,"\\A"+pattern+"\\z",RegexOptions.CultureInvariant)),"t109_policy_invalid");
    }
    public static PrecursorPolicy Read(JsonNode? n)
    {
        if(n is null)return new();var o=n.AsObject();string[] keys=["fast_files","fast_seconds","read_files","read_shares","read_seconds","silence_correlation_seconds","backup_sids","backup_services"];D.Require(!o.Select(p=>p.Key).Except(keys).Any(),"t109_policy_invalid");
        int N(string k,int def)=>o[k]?.GetValue<int>()??def;IReadOnlyList<string>? A(string k)=>o[k]?.AsArray().Select(v=>v!.GetValue<string>()).ToArray();
        var p=new PrecursorPolicy(N(keys[0],30),N(keys[1],30),N(keys[2],200),N(keys[3],10),N(keys[4],300),N(keys[5],3600),A(keys[6]),A(keys[7]));p.Validate();return p;
    }
}

public static class AttackPrecursors
{
    public static readonly string[] Rules=["qw.ransom-precursor","qw.security-log-cleared","qw.audit-disabled","qw.agent-tamper","qw.agent-silenced","qw.file-ransom-fast","qw.mass-file-read"];
    public static readonly string[] AgentServices=["sliagent","sliagentnet","sli agent","sli agent .net"];
    private static bool Match(string value,string regex)=>Regex.IsMatch(value,regex,RegexOptions.CultureInvariant,TimeSpan.FromSeconds(1));
    public static string SafeLabel(string value)=>Regex.Replace(value,@"\s+"," ").Trim() is var s?Escape(s[..Math.Min(s.Length,160)]):"";
    private static string Escape(string s)=>s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace("\"","&quot;").Replace("'","&#x27;");
    public static string Normalize(string command)=>Regex.Replace(UnicodeCaseFold.Fold(command[..Math.Min(command.Length,65536)].Replace("`\r\n","").Replace("`\n","")).Replace("\"","").Replace("'","").Replace("`",""),@"\s+"," ").Trim();
    private static bool ServiceCommand(string command,IEnumerable<string> names)
    {
        string pattern="(?:"+string.Join('|',names.Select(n=>Regex.Escape(UnicodeCaseFold.Fold(n))))+")(?=\\s|[;|&]|$)";
        return Match(command,@"\b(?:stop-service|remove-service)\s+(?:-name\s+)?"+pattern)||Match(command,@"\b(?:net(?:\.exe)?\s+stop|sc(?:\.exe)?\s+(?:stop|delete))\s+"+pattern);
    }
    public static string? PrecursorReason(string command,PrecursorPolicy? policy=null)
    {
        policy??=new();policy.Validate();string c=Normalize(command);if(Match(c,@"^(?:echo|write-output|write-host)\b"))return null;
        // .exe covers the actual vssadmin.EXE path as well as renamed binaries.
        if(Match(c,@"\b(?:(?:vssadmin|[\w.-]+\.exe)\s+delete\s+shadows|shadowcopy\b[^;|&]*\bdelete)\b")||Match(c,@"\b(?:wbadmin(?:\.exe)?|[\w.-]+\.exe)\s+delete\s+(?:catalog|systemstatebackup)\b"))return "backup_destruction";
        if(Match(c,@"/set\s+(?:\S+\s+)?(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)\b"))return "recovery_disabled";
        if(Match(c,@"\bwin32_shadowcopy\b.*(?:\|\s*(?:remove-[a-z]+|%|foreach)|\.delete\s*\()"))return "backup_destruction";
        return ServiceCommand(c,policy.BackupServices??PrecursorPolicy.DefaultBackupServices)?"backup_service_stopped":null;
    }
    public static (string Rule,string Reason)? EventReason(DetectionRow row,PrecursorPolicy policy,IEnumerable<string>? agentServices=null)
    {
        agentServices??=AgentServices;int eid=row.EventId;
        // Event 104 is written to System regardless of which log was cleared.
        if (eid == 1102 || eid == 104 && row.Channel == "System" && row.Provider == "Microsoft-Windows-Eventlog" &&
            row.Get("Channel").Equals("Security", StringComparison.OrdinalIgnoreCase))
            return (Rules[1], "security_log_cleared");
        if (eid == 4719 && Match(row.Get("AuditPolicyChanges"), @"%%(?:8448|8450)\b"))
            return (Rules[2], "audit_removed");
        string service=row.Get("ServiceName");if(service==""&&eid==7040)service=row.Get("param4");if(service=="")service=row.Get("param1");service=UnicodeCaseFold.Fold(service);
        if(agentServices.Select(UnicodeCaseFold.Fold).Contains(service)){
            string state=Normalize(row.Get("param2") is {Length:>0} stateValue ? stateValue : row.Get("State")),start=row.Get("StartType");if(start=="")start=row.Get("param3");if(start=="")start=row.Get("NewStartType");start=Normalize(start);
            if(eid==7036&&state is "stopped" or "остановлена" or "остановлено" or "1"||eid is 7040 or 7045&&start is "disabled" or "отключена" or "отключено" or "4")return(Rules[3],"agent_service_stopped");
        }
        if(eid is 4688 or 4104){string c=row.Get(eid==4688?"CommandLine":"ScriptBlockText");if(ServiceCommand(Normalize(c),agentServices))return(Rules[3],"agent_service_stopped");if(PrecursorReason(c,policy) is {} reason)return(Rules[0],reason);}
        return null;
    }
    private static JsonObject Signal(string rule,IReadOnlyList<DetectionRow> rows,PrecursorPolicy policy,DateTimeOffset now,string reason,string? entity=null)
    {
        var refs=rows.Select(r=>r.Ref).Distinct().OrderBy(r=>r.SortKey,StringComparer.Ordinal).ToArray();entity??=D.Hash(new JsonArray(refs[0].Scope.Document,JsonValue.Create(rows[0].Host)));
        var context=new JsonObject{["version"]=1,["policy"]=policy.Document,["host"]=SafeLabel(rows[0].Host),["reason"]=reason,["count"]=rows.Select(r=>r.Record?.ContainsKey("path")==true?D.Text(r.Record["path"]):r.Ref.NativeId).Distinct().Count(),["shares"]=rows.Select(r=>D.Text(r.Record?["share_name"])).Where(s=>s!="").Distinct().Count(),["first"]=D.Stamp(rows.Min(r=>r.At)),["last"]=D.Stamp(rows.Max(r=>r.At))};
        if(rule==Rules[6])context["anchor_ref"]=refs[0].Document;
        var result=DetectionSignal.Create(rule,rule==Rules[0]||rule==Rules[5]?"ransom":"threshold",D.Hash(new JsonArray("t109b.v1",rule,policy.Document)),entity,D.Hash(new JsonArray(rule,entity,refs[0].Params)),refs,rows.Max(r=>r.At),now,"high","attack_context",context,[reason]);result.Remove("evidence_total");return result;
    }
    public static IReadOnlyList<JsonObject> DetectEvents(IReadOnlyList<DetectionRow> rows,DateTimeOffset now,PrecursorPolicy? policy=null,IEnumerable<string>? agentServices=null)
    {
        policy??=new();policy.Validate();D.Require(rows.Count<=10000,"t109_source_window_truncated");var result=new SortedDictionary<string,JsonObject>(StringComparer.Ordinal);
        foreach(var row in rows.Where(r=>r.At<=now))if(EventReason(row,policy,agentServices) is {} match){var item=Signal(match.Rule,[row],policy,now,match.Reason);result[DetectionSignal.Id(item)]=item;}return result.Values.ToArray();
    }
    public static IReadOnlyList<JsonObject> DetectFiles(IReadOnlyList<DetectionRow> rows,DateTimeOffset now,PrecursorPolicy? policy=null)
    {
        policy??=new();policy.Validate();D.Require(rows.Count<=20000,"t109_source_window_truncated");var groups=new SortedDictionary<string,(JsonArray Key,string Rule,Dictionary<string,DetectionRow> Rows)>(StringComparer.Ordinal);
        foreach(var row in rows){var data=row.Record!;string S(string k)=>D.Text(data[k]);string sid=S("subject_sid");if(sid==""||(policy.BackupSids??[]).Contains(sid)||S("outcome")!="success"||S("object_type")!="file"||S("correlation_state")!="complete"||S("path")==""||row.At>now)continue;
            string op=S("operation"),rule=op is "write" or "delete"?Rules[5]:op is "read" or "read_check"?Rules[6]:"";if(rule=="")continue;var scope=row.Ref.Scope;
            var key=new JsonArray(rule,new JsonArray(scope.InstallationId,scope.PluginId,scope.SourceInstanceId,scope.SourceGeneration),rule==Rules[5]?scope.CollectionScopeId:"",sid,rule==Rules[5]?op:"read");string index=Sli.Agent.Protocol.CanonicalJson.Serialize(key);if(!groups.TryGetValue(index,out var group))group=(key,rule,new(StringComparer.Ordinal));group.Rows[row.Ref.SortKey]=row;groups[index]=group;
        }
        var result=new List<JsonObject>();foreach(var group in groups.Values){bool fast=group.Rule==Rules[5];int seconds=fast?policy.FastSeconds:policy.ReadSeconds,threshold=fast?policy.FastFiles:policy.ReadFiles;var window=new Queue<DetectionRow>();List<DetectionRow>? selected=null;var bursts=new List<List<DetectionRow>>();
            foreach(var row in group.Rows.Values.OrderBy(r=>r.At).ThenBy(r=>r.Ref.SortKey,StringComparer.Ordinal)){
                while(window.TryPeek(out var first)&&first.At<row.At.AddSeconds(-seconds))window.Dequeue();window.Enqueue(row);
                string Path(DetectionRow r)=>D.Text(r.Record!["path"]).Replace('/','\\').ToLowerInvariant();string Share(DetectionRow r)=>UnicodeCaseFold.Fold(D.Text(r.Record!["share_name"]));
                int count=window.Select(Path).Distinct().Count(),shares=window.Select(Share).Where(s=>s!="").Distinct().Count();
                if(count>=threshold||!fast&&shares>=policy.ReadShares){if(selected==null){var witnesses=new Dictionary<string,DetectionRow>(StringComparer.Ordinal);foreach(var r in window){witnesses.TryAdd(count>=threshold?Path(r):Share(r),r);if(witnesses.Count>=(count>=threshold?threshold:policy.ReadShares))break;}selected=witnesses.Values.ToList();}}
                else if(selected!=null){bursts.Add(selected);selected=null;}
            }if(selected!=null)bursts.Add(selected);foreach(var burst in bursts)result.Add(Signal(group.Rule,burst,policy,now,fast?"mass_file_changes":"mass_read_access",D.Hash(group.Key)));
        }return result;
    }
    public static JsonObject? SilenceSignal(JsonObject threat,JsonObject health,DateTimeOffset now)
    {
        var policy=PrecursorPolicy.Read(threat["attack_context"]!["policy"]);var at=D.Time(threat["occurred_at_utc"]);if(!Rules.Take(3).Contains(D.Text(threat["rule_id"]))||D.Text(health["connection"])!="online"||D.Text(health["state"])!="error"||now<=at||now-at>TimeSpan.FromSeconds(policy.SilenceCorrelationSeconds))return null;
        var failures=(health["modules"]?.AsArray()??[]).SelectMany(m=>m!["channels"]!.AsArray()).Where(c=>D.Text(c?["state"])=="error"&&D.Text(c?["failure_reason"])=="packet_stale"&&c?["issue_since_utc"]!=null&&c["last_packet_at"]!=null&&D.Time(c["last_packet_at"])>=at&&D.Time(c["issue_since_utc"])>=at&&D.Time(c["issue_since_utc"])<=now).ToArray();if(failures.Length==0)return null;
        var item=(JsonObject)threat.DeepClone();item["rule_id"]=Rules[4];item["kind"]="threshold";item["rule_sha256"]=D.Hash(new JsonArray("t109b.v1",Rules[4],policy.Document));item["episode_key"]=D.Hash(new JsonArray(Rules[4],D.Text(threat["entity_key"]),D.Text(threat["episode_key"])));item["occurred_at_utc"]=D.Stamp(now);item["received_at_utc"]=D.Stamp(now);item["severity_reasons"]=new JsonArray("silence_after_attack");item["attack_context"]!["reason"]="silence_after_attack";item["attack_context"]!["health"]=new JsonObject{["connection"]="online",["state"]="error",["checked_at"]=D.Stamp(now),["issue_since"]=D.Stamp(failures.Min(c=>D.Time(c!["issue_since_utc"])))};return item;
    }
    public static PrecursorPolicy Validate(JsonObject signal)
    {
        DetectionSignal.ValidateEnvelope(signal);var c=signal["attack_context"]!.AsObject();var p=PrecursorPolicy.Read(c["policy"]);string rule=D.Text(signal["rule_id"]);string[] keys=["version","policy","host","reason","count","shares","first","last","health","anchor_ref"];
        D.Require(Rules.Contains(rule)&&!c.Select(v=>v.Key).Except(keys).Any()&&c["version"]!.GetValue<int>()==1&&D.Text(c["host"]).Length<=960&&!D.Text(c["host"]).Any(ch=>"<>\"'".Contains(ch))&&c["count"]!.GetValue<int>() is >=1 and <=32768&&c["shares"]!.GetValue<int>() is >=0 and <=32768&&D.Time(c["first"])<=D.Time(c["last"])&&D.Text(signal["rule_sha256"])==D.Hash(new JsonArray("t109b.v1",rule,p.Document))&&D.Text(signal["base_severity"])=="high"&&D.Text(signal["effective_severity"])=="high"&&JsonNode.DeepEquals(signal["severity_reasons"],new JsonArray(D.Text(c["reason"])))&&D.Text(signal["kind"])==(rule==Rules[0]||rule==Rules[5]?"ransom":"threshold"),"t109_signal_invalid");
        if(rule==Rules[6])D.Require(JsonNode.DeepEquals(c["anchor_ref"],signal["evidence_refs"]![0]),"t109_signal_invalid");return p;
    }
    public static JsonObject PolicyDefinition(JsonObject signal)
    {
        var p=Validate(signal);string rule=D.Text(signal["rule_id"]);string[] titles=["Ransomware preparation detected","Security log cleared","Windows auditing weakened","SLI agent service tampering","SLI delivery stopped after a dangerous event","Rapid mass file changes","Mass file reads or read access checks"];
        return new(){["type"]="scenario_policy",["source_selector"]=new JsonObject{["rule_id"]=rule,["execution"]=DetectionSignal.Execution(signal)},["scenario_kind"]=rule,["result_class"]="security_incident",["merge_window_seconds"]=300,["detector_policy"]=p.Document,["expected_evidence_count"]=rule==Rules[5]?p.FastFiles:rule==Rules[6]?Math.Min(p.ReadFiles,p.ReadShares):1,["title"]=titles[Array.IndexOf(Rules,rule)],["explanation"]="Early attack warning; review native evidence.",["risk"]=new JsonObject{["class"]="high",["raw_score"]="60",["display_points"]=60,["rationale"]="Early attack or loss of observation requires immediate investigation."}};
    }
}
