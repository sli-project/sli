using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Semantic.Password;

namespace Sli.Server.Semantic;

internal sealed record DetectorRule(string Kind, JsonObject Scope, string Mode, int Revision, string Processing, string? Agent, JsonObject Config, JsonArray Exclusions)
{
    internal string RuleId => Kind switch { "account-watch" => "qw.account-watch", "account-decoy" => "qw.account-decoy", "file-decoy" => "qw.file-decoy", "file-ransom" => "qw.file-ransom", _ => "qw.nps-denials" };
    internal static DetectorRule Read(string kind, JsonObject input, string? processing = null)
    {
        void Require(bool valid) { if (!valid) throw new InvalidDataException(kind.Replace('-', '_') + "_rule_invalid"); }
        Require(kind is "account-watch" or "account-decoy" or "file-decoy" or "file-ransom" or "nps-threshold");
        var allowed = new HashSet<string> { "scope", "policy_revision", "evaluation_mode" };
        if (kind is "account-watch" or "account-decoy" or "file-decoy") allowed.Add("processing_mode");
        if (kind.StartsWith("file-", StringComparison.Ordinal)) allowed.Add("agent_id");
        if (kind == "file-ransom") allowed.UnionWith(["source_policy_revision", "threshold", "window_seconds", "exclusions"]);
        if (kind == "nps-threshold") allowed.UnionWith(["dimension", "threshold", "window_seconds", "surge_factor"]);
        Require(input.All(p => allowed.Contains(p.Key)) && input["scope"] is JsonObject);
        var scope = input["scope"]!.DeepClone().AsObject(); Require(scope.All(p => new[] { "installation_id", "plugin_id", "source_instance_id", "source_generation", "collection_scope_id" }.Contains(p.Key)));
        string Text(JsonObject o, string key, string fallback = "") { if (!o.ContainsKey(key)) return fallback; Require(o[key] is JsonValue v && v.TryGetValue<string>(out _)); return o[key]!.GetValue<string>(); }
        int Number(string key, int fallback, int min, int max) { if (!input.ContainsKey(key)) return fallback; Require(input[key] is JsonValue v && v.TryGetValue<int>(out var n) && n >= min && n <= max); return input[key]!.GetValue<int>(); }
        string installation = Text(scope, "installation_id"); Require(Guid.TryParseExact(installation, "D", out var uuid) && uuid.ToString() == installation);
        foreach (var (key, max, min) in new[] { ("plugin_id",128,1), ("source_instance_id",256,1), ("source_generation",512,1), ("collection_scope_id",256,0) }) { string s = Text(scope,key); Require(s.Length >= min && s.Length <= max && s.Trim() == s); }
        scope["collection_scope_id"] ??= "";
        string plugin = Text(scope, "plugin_id"), collection = Text(scope,"collection_scope_id"); bool file = kind.StartsWith("file-", StringComparison.Ordinal);
        Require(file ? plugin == "sli.file-audit" && collection.Length > 0 : collection.Length == 0 && (kind == "nps-threshold" ? plugin is "sli.windows.ad-dc" or "sli.vpn-nps" : plugin == "sli.windows.ad-dc"));
        string mode = Text(input,"evaluation_mode","shadow"), provenance = processing ?? Text(input,"processing_mode","live"); Require(mode is "test" or "shadow" or "enabled"); Require(provenance is "live" or "historical_replay" or "history_import");
        string? agent = file ? Text(input,"agent_id") : null; if (file) Require(Guid.TryParseExact(agent,"D",out var a) && a.ToString() == agent);
        int revision = Number("policy_revision",1,1,int.MaxValue); var config = new JsonObject(); var exclusions = new JsonArray();
        if (kind == "file-ransom")
        {
            string sourceRevision = Text(input,"source_policy_revision"); Require(Regex.IsMatch(sourceRevision,@"\A[1-9][0-9]{0,15}\z") && long.TryParse(sourceRevision,out long n) && n <= 9007199254740991);
            config["policy_revision"] = sourceRevision; config["mass_operation_files"] = Number("threshold",100,1,1000000); config["mass_operation_seconds"] = Number("window_seconds",300,1,86400);
            Require(!input.ContainsKey("exclusions") || input["exclusions"] is JsonArray); exclusions = input["exclusions"]?.DeepClone().AsArray() ?? []; Require(exclusions.Count <= 100);
            foreach (var item in exclusions)
            {
                Require(item is JsonObject); var e = item!.AsObject(); Require(e.Count == 6 && e.All(p => new[] { "subject_sid", "collection_scope_id", "reason", "approved_by", "active_from", "active_to" }.Contains(p.Key)));
                foreach (var (key,max) in new[] { ("subject_sid",184), ("collection_scope_id",256), ("reason",500), ("approved_by",128) }) { string s = Text(e,key); Require(s.Length > 0 && s.Length <= max && s.Trim() == s && !s.Any(c => c < 32 || c == 127)); }
                Require(Regex.IsMatch(Text(e,"subject_sid"),@"\AS-1-(?:[0-9]+-)*[0-9]+\z") && Text(e,"collection_scope_id") == collection);
                var from = SigmaProjection.At(e,"active_from"); var to = SigmaProjection.At(e,"active_to"); Require(to > from && to-from <= TimeSpan.FromDays(31));
            }
        }
        if (kind == "nps-threshold") { string dimension = Text(input,"dimension","account"); Require(new[] { "account", "nas_identifier", "network_policy", "reason_code", "client_ip" }.Contains(dimension)); config["dimension"] = dimension; config["threshold"] = Number("threshold",20,1,10000); config["window_seconds"] = Number("window_seconds",300,60,3600); config["surge_factor"] = Number("surge_factor",3,2,100); }
        return new(kind,scope,mode,revision,provenance,agent,config,exclusions);
    }
    internal JsonObject Definition()
    {
        var definition = SemanticProduction.Definition(RuleId, Scope, Agent, Config);
        if (Kind == "nps-threshold") { definition["merge_window_seconds"] = Config["window_seconds"]!.DeepClone(); definition["expected_evidence_count"] = Config["threshold"]!.DeepClone(); definition["source_selector"]!["execution"]!["rule_sha256"] = PasswordJson.Hash(new JsonObject { ["contract"] = "sli.nps-threshold.v1", ["dimension"] = Config["dimension"]!.DeepClone(), ["threshold"] = Config["threshold"]!.DeepClone(), ["window_seconds"] = Config["window_seconds"]!.DeepClone(), ["surge_factor"] = Config["surge_factor"]!.DeepClone() }); }
        return definition;
    }
    internal JsonObject Apply(JsonObject document)
    { document["evaluation_mode"] = Mode; document["policy_revision"] = Revision; if (Processing != "live") document["processing_mode"] = Processing; return document; }
}

public static class DetectorCommand
{
    public static async Task<int> RunAsync(string kind, string[] args)
    {
        var file = new Option<string>("--rule-file") { Required = true }; var processing = new Option<string?>("--processing-mode");
        var command = new RootCommand("Evaluate one approved native scope in one transaction."); command.Options.Add(file);
        command.Options.Add(new Option<bool>("--once")); // Already one transaction; match the other worker entry points.
        if (kind is "account-watch" or "account-decoy" or "file-decoy") command.Options.Add(processing);
        command.SetAction(async (parse, ct) =>
        {
            try
            {
                await using var stream = File.OpenRead(parse.GetValue(file)!); int max = kind == "nps-threshold" ? 8192 : 131072; byte[] bytes = new byte[max+1]; int count = 0, n;
                while (count < bytes.Length && (n = await stream.ReadAsync(bytes.AsMemory(count),ct)) > 0) count += n;
                if (count > max) throw new InvalidDataException(); var rule = DetectorRule.Read(kind, JsonNode.Parse(bytes.AsSpan(0,count))!.AsObject(), kind is "account-watch" or "account-decoy" or "file-decoy" ? parse.GetValue(processing) : null);
                await using var runtime = PasswordProducerRuntime.TryCreate() ?? throw new InvalidOperationException(); await using var db = await runtime.OpenAsync(ct); await using var tx = await db.BeginTransactionAsync(ct);
                var result = await SemanticProduction.RunDetector(new SemanticSession(db,tx),rule,DateTimeOffset.UtcNow,ct); await tx.CommitAsync(ct); Console.WriteLine(result.ToJsonString()); return 0;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return 1; }
            catch { Console.WriteLine(new JsonObject { ["state"] = "failed", ["code"] = kind.Replace('-','_') + "_unavailable" }.ToJsonString()); return 1; }
        });
        return await command.Parse(args, new ParserConfiguration { ResponseFileTokenReplacer = null }).InvokeAsync(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
    }
}
