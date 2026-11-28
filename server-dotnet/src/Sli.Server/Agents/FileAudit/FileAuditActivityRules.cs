using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Ingress;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.FileAudit;

// Source: file_audit/rules.py activity_findings and core/working_time.py.
internal static class FileAuditActivityRules
{
    private static string? S(JsonNode? n)=>n?.GetValue<string>();
    private static DateTimeOffset T(JsonNode? n)=>DateTimeOffset.Parse(S(n)!,CultureInfo.InvariantCulture);
    private static string FoldPath(string p)=>UnicodeLower.Lower(p.Replace('/','\\'));
    private static bool InRoot(string path,string root) { path=FoldPath(AgentFileAuditPolicy.NormalizePath(path)); root=FoldPath(AgentFileAuditPolicy.NormalizePath(root)); return path==root || path.StartsWith(root.TrimEnd('\\')+"\\",StringComparison.Ordinal); }
    private static JsonObject Finding(string code,string agent,string source,string scope,string subject,string at,IEnumerable<JsonObject> actions,IEnumerable<JsonObject> snapshots,JsonObject details)
    {
        var aids=new JsonArray(actions.Select(x=>S(x["action_id"])!).Distinct().Order(StringComparer.Ordinal).Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());
        var sids=new JsonArray(snapshots.Select(x=>S(x["snapshot_id"])!).Distinct().Order(StringComparer.Ordinal).Select(x=>(JsonNode?)JsonValue.Create(x)).ToArray());
        var binding=new JsonArray(agent,source,scope); var identity=new JsonArray(code,1,binding.DeepClone(),subject,aids.DeepClone(),sids.DeepClone(),details.DeepClone());
        return new JsonObject { ["result_id"]=Packets.Digest(identity),["rule_code"]=code,["rule_version"]=1,["agent_id"]=agent,["source_instance_id"]=source,["collection_scope_id"]=scope,["subject_sid"]=subject,["observed_at"]=at,["conclusion_state"]="observed",["action_ids"]=aids,["snapshot_ids"]=sids,["details"]=details };
    }
    private static (string Kind,JsonObject? Snapshot) Inventory(JsonObject action,JsonArray snapshots)
    {
        var instant=T(action["observed_at"]); var rows=snapshots.OfType<JsonObject>().Where(x=>new[]{"agent_id","source_instance_id","collection_scope_id"}.All(k=>S(x[k])==S(action[k])) && T(x["observed_at_utc"])>=instant.AddDays(-1) && T(x["observed_at_utc"])<=instant)
            .OrderByDescending(x=>S(x["completeness"])=="complete").ThenByDescending(x=>T(x["observed_at_utc"])).ThenByDescending(x=>S(x["snapshot_id"]),StringComparer.Ordinal);
        string path=FoldPath(S(action["old_path"]) ?? S(action["path"])!);
        foreach(var snapshot in rows) { var kinds=snapshot["objects"]!.AsArray().OfType<JsonObject>().Where(x=>FoldPath(S(x["path"])!)==path).Select(x=>S(x["object_type"])!).Distinct().ToList(); if(kinds.Count==1) return (kinds[0],snapshot); }
        return ("unknown",null);
    }
    public static (JsonArray Results, int DistinctFiles, bool MissingKinds) Evaluate(
        JsonArray actions,JsonObject config,string agent,string source,JsonArray snapshots,JsonObject? calendar)
    {
        var zone=calendar is null ? null : WorkingTime.Validate(calendar);
        var roots=config["roots"]!.AsArray().OfType<JsonObject>().ToDictionary(x=>S(x["collection_scope_id"])!);
        var eligible=new Dictionary<string,(JsonObject Action,JsonObject? Snapshot)>();
        var orderedActions=actions.OfType<JsonObject>().OrderBy(x=>T(x["observed_at"])).ThenBy(x=>S(x["action_id"]),StringComparer.Ordinal);
        var knownKinds=new Dictionary<(string Scope,string Subject,string Path),string>();
        bool missingKinds = false;
        foreach(var item in orderedActions) {
            string scope=S(item["collection_scope_id"])!,op=S(item["operation"])!,subject=S(item["subject_sid"]) ?? "",path=S(item["path"]) ?? "",state=S(item["correlation_state"])!;
            if(S(item["agent_id"])!=agent || S(item["source_instance_id"])!=source || !roots.TryGetValue(scope,out var root) || subject.Length==0 || config["service_account_exclusions"]!.AsArray().Any(x=>S(x)==subject) || S(item["outcome"])!="success" || op is not ("read" or "write" or "rename" or "delete" or "delete_right") || item["evidence"] is not JsonArray evidence || evidence.Count==0 || path.Length==0 || state is "ambiguous" or "not_attempted" || op=="delete" && state!="complete" || op=="read" && !root["important"]!.GetValue<bool>()) continue;
            if(!InRoot(path,S(root["path"])!)) continue;
            string kind=S(item["object_type"])!; JsonObject? snapshot=null;
            if(kind=="unknown" && op is "rename" or "delete")
                kind=knownKinds.GetValueOrDefault((scope,subject,FoldPath(S(item["old_path"]) ?? path)),"unknown");
            if(kind=="unknown") (kind,snapshot)=Inventory(item,snapshots);
            if(kind is "file" or "directory") knownKinds[(scope,subject,FoldPath(path))]=kind;
            if(kind=="unknown" && op is "write" or "rename" or "delete") missingKinds = true;
            if(kind!="file" || op=="delete_right") continue;
            string id=S(item["action_id"])!;
            if(eligible.TryGetValue(id,out var old) && !PythonMetadataEquality.Equal(old.Action,item)) throw new InvalidDataException("file_audit_action_replay_conflict");
            eligible[id]=(item,snapshot);
        }
        var result=new List<JsonObject>();
        var ordered=eligible.Values.OrderBy(x=>T(x.Action["observed_at"])).ThenBy(x=>S(x.Action["action_id"]),StringComparer.Ordinal).ToList();
        foreach(var (item,snapshot) in ordered) if(calendar is not null && WorkingTime.Outside(S(item["observed_at"])!,S(item["subject_sid"])!,calendar,zone!,out var local)) {
            var details=new JsonObject { ["local_time"]=local,["calendar"]=calendar.DeepClone(),["operation"]=item["operation"]!.DeepClone() };
            result.Add(Finding("file-audit.out-of-hours",agent,source,S(item["collection_scope_id"])!,S(item["subject_sid"])!,S(item["observed_at"])!,[item],snapshot is null?[]:[snapshot],details));
        }
        int seconds=config["mass_operation_seconds"]!.GetValue<int>(),threshold=config["mass_operation_files"]!.GetValue<int>();
        int distinctFiles = 0;
        foreach(var group in ordered.GroupBy(x=>(Scope:S(x.Action["collection_scope_id"])!,Subject:S(x.Action["subject_sid"])!,
            Read:S(x.Action["operation"])=="read"))) {
            var window=new List<(JsonObject Action,JsonObject? Snapshot)>(); (List<(JsonObject Action,JsonObject? Snapshot)> Rows,int Count)? selected=null;
            void Emit() { if(selected is null) return; var (rows,count)=selected.Value; var first=rows[0].Action;var last=rows[^1].Action;
                var details=new JsonObject { ["distinct_files"]=count,["threshold"]=threshold,["window_seconds"]=seconds,["window_start"]=first["observed_at"]!.DeepClone(),["window_end"]=last["observed_at"]!.DeepClone() };
                string operation=group.Key.Read ? "read" : rows.All(x=>S(x.Action["operation"])=="delete") ? "delete" : "write";
                result.Add(Finding("file-audit.mass-"+operation,agent,source,group.Key.Scope,group.Key.Subject,S(last["observed_at"])!,rows.Select(x=>x.Action),rows.Where(x=>x.Snapshot is not null).Select(x=>x.Snapshot!),details)); selected=null; }
            foreach(var row in group) {
                var cutoff=T(row.Action["observed_at"]).AddSeconds(-seconds);
                window.RemoveAll(x=>T(x.Action["observed_at"])<cutoff);
                window.Add(row);
                int count=DistinctFiles(window.Select(x=>x.Action));
                if (!group.Key.Read) distinctFiles = Math.Max(distinctFiles,count);
                if(count>=threshold) selected=(window.ToList(),count); else Emit();
            }
            Emit();
        }
        return (new JsonArray(result.OrderBy(x=>S(x["result_id"]),StringComparer.Ordinal).Select(x=>(JsonNode?)x).ToArray()),
            distinctFiles,missingKinds);
    }

    private static int DistinctFiles(IEnumerable<JsonObject> window)
    {
        var aliases=new Dictionary<string,string>(StringComparer.Ordinal);
        var files=new HashSet<string>(StringComparer.Ordinal);
        foreach(var action in window)
        {
            string path=FoldPath(S(action["path"])!);
            if(S(action["old_path"]) is { } old)
            {
                string original=FoldPath(old);
                aliases[path]=aliases.GetValueOrDefault(original,original);
                aliases.Remove(original);
            }
            files.Add(aliases.GetValueOrDefault(path,path));
        }
        return files.Count;
    }
}

internal static class WorkingTime
{
    private static DateTimeOffset Utc(JsonNode? n) => PythonIsoDateTime.TryParseUtc(n?.GetValue<string>(),out var utc) ? utc : throw new FormatException();
    public static TimeZoneInfo Validate(JsonObject c)
    {
        if(!JsonRead.HasExactly(c,"timezone","weekdays","start","end","excluded_dates","exceptions")) throw new FormatException();
        var zone=TimeZoneInfo.FindSystemTimeZoneById(c["timezone"]!.GetValue<string>());var days=c["weekdays"]!.AsArray();
        if(days.Count is <1 or >7 || days.Any(x=>!JsonRead.TryInteger(x,out var n) || n<0 || n>6) || days.Select(x=>x!.ToString()).Distinct().Count()!=days.Count) throw new FormatException();
        string start=c["start"]!.GetValue<string>(),end=c["end"]!.GetValue<string>(); if(!Regex.IsMatch(start,@"\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z") || !Regex.IsMatch(end,@"\A(?:[01][0-9]|2[0-3]):[0-5][0-9]\z") || start==end) throw new FormatException();
        var dates=c["excluded_dates"]!.AsArray();if(dates.Count>366 || dates.Any(x=>!DateOnly.TryParseExact(x!.GetValue<string>(),"yyyy-MM-dd",CultureInfo.InvariantCulture,DateTimeStyles.None,out _))) throw new FormatException();
        var exceptions=c["exceptions"]!.AsArray();if(exceptions.Count>100) throw new FormatException();
        foreach(var e in exceptions.OfType<JsonObject>()) if(!JsonRead.HasExactly(e,"subject_sid","start_utc","end_utc","reason") || !Regex.IsMatch(e["subject_sid"]!.GetValue<string>(),@"\AS-1-(?:[0-9]+-)*[0-9]+\z") || e["reason"]!.GetValue<string>().EnumerateRunes().Count() is <1 or >256 || Utc(e["start_utc"])>=Utc(e["end_utc"])) throw new FormatException();
        if(exceptions.Any(x=>x is not JsonObject)) throw new FormatException(); return zone;
    }
    public static bool Outside(string instant,string subject,JsonObject c,TimeZoneInfo zone,out string localText)
    {
        var utc=Utc(JsonValue.Create(instant)); var local=TimeZoneInfo.ConvertTime(utc,zone);
        localText=local.ToString(local.Ticks%TimeSpan.TicksPerSecond==0?"yyyy-MM-dd'T'HH:mm:sszzz":"yyyy-MM-dd'T'HH:mm:ss.ffffffzzz",CultureInfo.InvariantCulture);
        foreach(var e in c["exceptions"]!.AsArray().OfType<JsonObject>()) if(e["subject_sid"]!.GetValue<string>()==subject && Utc(e["start_utc"])<=utc && utc<Utc(e["end_utc"])) return false;
        string clock=local.ToString("HH:mm",CultureInfo.InvariantCulture),start=c["start"]!.GetValue<string>(),end=c["end"]!.GetValue<string>();var day=DateOnly.FromDateTime(local.DateTime);
        bool inside;if(string.CompareOrdinal(start,end)<0) inside=string.CompareOrdinal(clock,start)>=0 && string.CompareOrdinal(clock,end)<0; else { inside=string.CompareOrdinal(clock,start)>=0 || string.CompareOrdinal(clock,end)<0; if(string.CompareOrdinal(clock,end)<0) day=day.AddDays(-1); }
        int weekday=((int)day.DayOfWeek+6)%7; inside &= c["weekdays"]!.AsArray().Any(x=>JsonRead.TryInteger(x,out var n) && n==weekday) && !c["excluded_dates"]!.AsArray().Any(x=>x!.GetValue<string>()==day.ToString("yyyy-MM-dd",CultureInfo.InvariantCulture));
        return !inside;
    }
}
