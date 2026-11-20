using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Strict port of sli_agent/file_audit_policy.py. Assignment disabled/absent means no collection.</summary>
public sealed record FileAuditPolicy(JsonObject Value)
{
    public const string ModuleId = "sli.file-audit";
    public const string ActionContract = "sli.file-audit.action.v1";
    public JsonArray Roots => Value["roots"]!.AsArray();
    public string Revision => Value["policy_revision"]!.GetValue<string>();
    public bool Workstation => Value["source_kind"]?.GetValue<string>() == "workstation";
    public int Number(string key) => Value[key]!.GetValue<int>();
    public static readonly int[] Events = [4656,4659,4660,4663,4670,4907,5140,5142,5143,5144,5145,5168];
    public static readonly int[] ContextEvents = [4608,4624,4625,4634,4719,1102];
    public const string Provider = "Microsoft-Windows-Security-Auditing";

    public static string LocalPath(string value)
    {
        if (value.Length is < 3 or > 4096 || !char.IsAsciiLetter(value[0]) || value[1] != ':' || value[2] is not ('\\' or '/')
            || value.Any(c => c < 32 || "*?\"<>|".Contains(c)) || value[2..].Contains(':')) throw new AgentException("file_audit_path_invalid");
        var parts = value[3..].Replace('/', '\\').Split('\\');
        if (parts.Any(p => p is "." or ".." || p.TrimEnd(' ', '.') != p)) throw new AgentException("file_audit_path_invalid");
        return value[..2] + "\\" + string.Join('\\', parts.Where(p => p.Length > 0));
    }

    public static bool InRoot(string path, string root)
    {
        path = LocalPath(path); root = LocalPath(root);
        return path.Equals(root, StringComparison.OrdinalIgnoreCase) || path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    }

    public static FileAuditPolicy Parse(JsonObject config)
    {
        static AgentException Invalid() => new("file_audit_policy_invalid");
        var limits = new Dictionary<string, (int Default, int Low, int High)>
        {
            ["max_events"]=(1000,1,10000), ["max_bytes"]=(1048576,1024,8388608), ["wall_seconds"]=(30,1,120),
            ["spool_bytes"]=(268435456,1048576,1073741824), ["inventory_depth"]=(16,0,64), ["inventory_objects"]=(10000,1,100000),
            ["mass_operation_files"]=(100,1,1000000), ["mass_operation_seconds"]=(300,1,86400)
        };
        var allowed = limits.Keys.Concat(["policy_revision","source_name","roots","source_kind","optional_events","service_account_exclusions","initial_read_hours"]).ToHashSet();
        if (config.Any(p => !allowed.Contains(p.Key))) throw Invalid();
        var result = (JsonObject)config.DeepClone();
        string Text(string key, string fallback) => !config.ContainsKey(key) ? fallback : JsonRead.TryString(config[key], out var t) ? t : throw Invalid();
        var kind = Text("source_kind", "server");
        var revision = Text("policy_revision", "1");
        if (kind is not ("server" or "workstation") || !Regex.IsMatch(revision, "\\A[1-9][0-9]{0,15}\\z") || long.Parse(revision, System.Globalization.CultureInfo.InvariantCulture) > 9007199254740991) throw Invalid();
        result["policy_revision"] = revision;
        if (config.ContainsKey("source_name") && (Text("source_name", "").Length is < 1 or > 255 || Text("source_name", "").Any(c => c < 33 || c is '/' or '\\'))) throw Invalid();
        if (config.ContainsKey("initial_read_hours") && !(JsonRead.TryString(config["initial_read_hours"], out var all) && all == "all")
            && (!JsonRead.TryInteger(config["initial_read_hours"], out var hours) || hours < 0 || hours > 876000)) throw Invalid();
        foreach (var (key, spec) in limits)
        {
            if (!config.ContainsKey(key)) result[key] = spec.Default;
            else if (!JsonRead.TryInteger(config[key], out var n) || n < spec.Low || n > spec.High) throw Invalid();
        }
        static bool Flag(JsonNode? value) => value is JsonValue v && v.TryGetValue<bool>(out _);
        if (!config.ContainsKey("optional_events")) result["optional_events"] = false;
        if (!Flag(result["optional_events"])) throw Invalid();
        static bool Sids(JsonNode? value, bool empty) => value is JsonArray a && a.Count >= (empty ? 0 : 1) && a.Count <= 100
            && a.All(x => JsonRead.TryString(x, out var s) && s.Length <= 184 && Regex.IsMatch(s, "\\AS-1-(?:[0-9]+-)*[0-9]+\\z"))
            && a.Select(x => x!.GetValue<string>()).Distinct().Count() == a.Count;
        if (!config.ContainsKey("service_account_exclusions")) result["service_account_exclusions"] = new JsonArray();
        if (!Sids(result["service_account_exclusions"], true) || result["roots"] is not JsonArray roots || roots.Count is < 1 or > 100) throw Invalid();
        var scopes = new HashSet<string>();
        foreach (var item in roots)
        {
            if (item is not JsonObject r || !JsonRead.HasExactly(r,"collection_scope_id","share_name","path","important","sacl")
                || !JsonRead.TryString(r["collection_scope_id"], out var scope) || !Regex.IsMatch(scope,"\\A[a-zA-Z0-9_.:-]{1,256}\\z") || !scopes.Add(scope)
                || !JsonRead.TryString(r["share_name"], out var share) || (kind == "workstation" ? share != "" : share.Length is < 1 or > 80)
                || share.Trim() != share || share.Any(c => c < 32 || "\\/:*?\"<>|".Contains(c)) || !Flag(r["important"])
                || r["sacl"] is not JsonObject s || !JsonRead.HasExactly(s,"trustee_sids","inherit_files","inherit_directories")
                || !Sids(s["trustee_sids"], false) || !Flag(s["inherit_files"]) || !Flag(s["inherit_directories"])
                || !JsonRead.TryString(r["path"], out var path)) throw Invalid();
            r["path"] = LocalPath(path);
        }
        return new(result);
    }

    public static JsonObject ParseRequest(JsonObject value)
    {
        static AgentException Invalid() => new("file_audit_command_invalid");
        if (!JsonRead.HasExactly(value,"config","command") || value["config"] is not JsonObject cfg || value["command"] is not JsonObject c) throw Invalid();
        var p = Parse(cfg);
        if (!JsonRead.HasExactly(c,"contract_id","command_id","action","policy_revision","collection_scope_ids")
            || c["contract_id"]?.ToString() != "sli.file-audit.audit-command.v1" || !JsonRead.TryString(c["command_id"], out var id)
            || !Regex.IsMatch(id,"\\A[a-zA-Z0-9_-]{1,128}\\z") || c["action"]?.ToString() is not ("check" or "apply" or "restore")
            || !JsonRead.TryString(c["policy_revision"], out var rev) || rev != p.Revision || c["collection_scope_ids"] is not JsonArray ids
            || ids.Count == 0 || ids.Any(x => !JsonRead.TryString(x, out var s) || !p.Roots.Any(r => r!["collection_scope_id"]!.GetValue<string>() == s))
            || ids.Select(x => x!.GetValue<string>()).Distinct().Count() != ids.Count) throw Invalid();
        return new JsonObject { ["config"] = p.Value.DeepClone(), ["command"] = c.DeepClone() };
    }

    public Dictionary<string,int> RequiredMasks()
    {
        var values = new Dictionary<string,int> { ["921d"]=3,["9224"]=3,["9244"]=Roots.Any(r => r!["important"]!.GetValue<bool>()) ? 3 : 2,["922f"]=1,["9215"]=3 };
        if (Workstation) { values.Remove("9224"); values.Remove("9244"); }
        if (Value["optional_events"]!.GetValue<bool>()) values["9223"] = 1;
        return values.ToDictionary(x => $"0cce{x.Key}-69ae-11d9-bed3-505054503030", x => x.Value);
    }

    public static JsonArray DesiredAces(JsonObject root)
    {
        var s = root["sacl"]!;
        var flags = (s["inherit_files"]!.GetValue<bool>() ? 1 : 0) | (s["inherit_directories"]!.GetValue<bool>() ? 2 : 0);
        return new JsonArray(s["trustee_sids"]!.AsArray().SelectMany(sid => new[] {64,128}.Select(outcome => (JsonNode?)new JsonObject
        { ["sid"]=sid!.DeepClone(),["flags"]=flags|outcome,["mask"]=0xd0046 | (outcome == 128 || root["important"]!.GetValue<bool>() ? 1 : 0) })).ToArray());
    }
}
