using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.Ingress;

/// <summary>Shared policy parser plus source code-point fallback for astral-bound paths and names.</summary>
internal static class AgentFileAuditPolicy
{
    private static AgentException Invalid()=>new("file_audit_policy_invalid");
    private static bool PythonTrimmed(string value)=>UnicodeCaseFold.Fold(value)==UnicodeCaseFold.TrimAndFold(value);
    public static FileAuditPolicy Parse(JsonObject input)
    {
        if (input["source_name"] is JsonValue name && JsonRead.TryString(name,out var text) && !PythonTrimmed(text)) throw Invalid();
        if (input["roots"] is JsonArray roots)
            foreach(var root in roots.OfType<JsonObject>())
                if (JsonRead.TryString(root["share_name"],out var share) && !PythonTrimmed(share)) throw Invalid();
        try { return FileAuditPolicy.Parse(input); }
        catch (AgentException)
        {
            // Do not alter the real policy or feed fabricated paths through the client parser.
            // A source-sized string which exceeds its UTF-16 bound is the only fallback trigger.
            bool wider=input["source_name"] is JsonValue n && JsonRead.TryString(n,out var s) && s.Length>255 && JsonRead.CodePoints(s)<=255;
            if (input["roots"] is JsonArray list) foreach(var root in list.OfType<JsonObject>())
            {
                if (JsonRead.TryString(root["path"],out var path) && path.Length>4096 && JsonRead.CodePoints(path)<=4096) wider=true;
                if (JsonRead.TryString(root["share_name"],out var share) && share.Length>80 && JsonRead.CodePoints(share)<=80) wider=true;
            }
            if (!wider) throw;
            return ParseWide(input);
        }
    }
    private static FileAuditPolicy ParseWide(JsonObject input)
    {
        var limits=new Dictionary<string,(int Default,int Low,int High)> { ["max_events"]=(1000,1,10000),["max_bytes"]=(1048576,1024,8388608),["wall_seconds"]=(30,1,120),["spool_bytes"]=(268435456,1048576,1073741824),["inventory_depth"]=(16,0,64),["inventory_objects"]=(10000,1,100000),["mass_operation_files"]=(100,1,1000000),["mass_operation_seconds"]=(300,1,86400) };
        var allowed=limits.Keys.Concat(["policy_revision","source_name","roots","source_kind","optional_events","service_account_exclusions","initial_read_hours"]).ToHashSet();
        if (input.Any(p=>!allowed.Contains(p.Key))) throw Invalid();
        string Text(string key,string fallback) => !input.ContainsKey(key) ? fallback : JsonRead.TryString(input[key],out var result) ? result : throw Invalid();
        string kind=Text("source_kind","server"), revision=Text("policy_revision","1");
        if (kind is not ("server" or "workstation") || !Regex.IsMatch(revision,"\\A[1-9][0-9]{0,15}\\z") || long.Parse(revision)>9007199254740991) throw Invalid();
        var value=(JsonObject)input.DeepClone(); value["policy_revision"]=revision;
        if (input.ContainsKey("source_name"))
        {
            string name=Text("source_name","");
            if (JsonRead.CodePoints(name) is < 1 or > 255 || !PythonTrimmed(name) || name.Any(c=>c<33 || c is '/' or '\\')) throw Invalid();
        }
        if (input.ContainsKey("initial_read_hours") && !(JsonRead.TryString(input["initial_read_hours"],out var all) && all=="all")
            && (!JsonRead.TryInteger(input["initial_read_hours"],out var hours) || hours<0 || hours>876000)) throw Invalid();
        foreach(var (key,spec) in limits)
        {
            if (!input.ContainsKey(key)) value[key]=spec.Default;
            else if (!JsonRead.TryInteger(input[key],out var number) || number<spec.Low || number>spec.High) throw Invalid();
        }
        if (!input.ContainsKey("optional_events")) value["optional_events"]=false;
        if (!Bool(value["optional_events"])) throw Invalid();
        if (!input.ContainsKey("service_account_exclusions")) value["service_account_exclusions"]=new JsonArray();
        if (!Sids(value["service_account_exclusions"],true) || value["roots"] is not JsonArray roots || roots.Count is < 1 or > 100) throw Invalid();
        var scopes=new HashSet<string>();
        foreach(var item in roots)
        {
            if (item is not JsonObject root || !JsonRead.HasExactly(root,"collection_scope_id","share_name","path","important","sacl")
                || !JsonRead.TryString(root["collection_scope_id"],out var scope) || !Regex.IsMatch(scope,"\\A[a-zA-Z0-9_.:-]{1,256}\\z") || !scopes.Add(scope)
                || !JsonRead.TryString(root["share_name"],out var share) || (kind=="workstation" ? share!="" : JsonRead.CodePoints(share) is < 1 or > 80)
                || !PythonTrimmed(share) || share.Any(c=>c<32 || "\\/:*?\"<>|".Contains(c)) || !Bool(root["important"])
                || root["sacl"] is not JsonObject sacl || !JsonRead.HasExactly(sacl,"trustee_sids","inherit_files","inherit_directories")
                || !Sids(sacl["trustee_sids"],false) || !Bool(sacl["inherit_files"]) || !Bool(sacl["inherit_directories"])
                || !JsonRead.TryString(root["path"],out var path)) throw Invalid();
            root["path"]=NormalizePath(path);
        }
        return new FileAuditPolicy(value);
    }
    private static bool Bool(JsonNode? value)=>value is JsonValue flag && flag.TryGetValue<bool>(out _);
    private static bool Sids(JsonNode? value,bool empty)=>value is JsonArray array && array.Count >= (empty ? 0 : 1) && array.Count<=100
        && array.All(x=>JsonRead.TryString(x,out var s) && JsonRead.CodePoints(s)<=184 && Regex.IsMatch(s,"\\AS-1-(?:[0-9]+-)*[0-9]+\\z"))
        && array.Select(x=>x!.GetValue<string>()).Distinct().Count()==array.Count;
    public static string NormalizePath(string path)
    {
        if (JsonRead.CodePoints(path) is < 3 or > 4096 || !char.IsAsciiLetter(path[0]) || path[1]!=':' || path[2] is not ('\\' or '/')
            || path.Any(c=>c<32 || "*?\"<>|".Contains(c)) || path[2..].Contains(':')) throw new AgentException("file_audit_path_invalid");
        var parts=path[3..].Replace('/','\\').Split('\\');
        if (parts.Any(part=>part is "." or ".." || part.TrimEnd(' ','.')!=part)) throw new AgentException("file_audit_path_invalid");
        return path[..2]+"\\"+string.Join('\\',parts.Where(part=>part.Length>0));
    }
}
