using System.Text.Json.Nodes;
using System.Numerics;
using System.Globalization;

namespace Sli.Server.Jobs;

public sealed class CoreJobRegistry
{
    private readonly Dictionary<string, JsonObject> handlers = new(StringComparer.Ordinal);
    private readonly List<JsonObject> manifests = [];
    public IReadOnlyList<JsonObject> Handlers => handlers.Values.Select(x => (JsonObject)x.DeepClone()).ToArray();
    public IReadOnlyList<JsonObject> Manifests => manifests.Select(x => (JsonObject)x.DeepClone()).ToArray();
    internal static readonly JsonObject Schema = CoreJobJson.Resource("plugin_architecture_v3.json");
    public static JsonObject Bundled(string plugin) => CoreJobJson.Resource(plugin == "sli.workstations.projection" ? "sli.workstations.projection-jobs-v3.json" : plugin + ".jobs-v3.json");
    public static readonly IReadOnlyDictionary<string, (long Wall, long Memory, long Records)> Profiles =
        new Dictionary<string, (long, long, long)> { ["light"] = (90, 268435456, 500000), ["heavy"] = (300, 1073741824, 1000000), ["long"] = (1800, 1073741824, 1000000) };
    private static readonly Dictionary<string, (string Profile, string Rights)> Allowlist = new()
    {
        ["sli.remote-access/radius-session-observation/1.0.0"] = ("light", "vpn-read"),
        ["sli.remote-access/radius-acquisition/1.0.0"] = ("light", "vpn-read"),
        ["sli.ad/ad-snapshot-manifest-coordinator/1.0.0"] = ("heavy", "ad-read"),
        ["sli.ad/ad-snapshot-projection/1.0.0"] = ("heavy", "ad-read"),
        ["sli.ad/ad-context-snapshot/1.0.0"] = ("heavy", "ad-read"),
        ["sli.ad/computers-v6-source/1.0.0"] = ("heavy", "ad-read"),
        ["sli.ad/users-report-v2-snapshot/1.0.0"] = ("heavy", "ad-read"),
        ["sli.gpo/gpo-snapshot/1.0.0"] = ("long", "gpo-read"),
        ["sli.gpo/gpo-acquisition/1.0.0"] = ("long", "gpo-read"),
        ["sli.workstations/workstations.evidence-retention/1.0.0"] = ("light", "workstations-retention"),
        ["sli.workstations/workstations.overview-project/1.0.0"] = ("light", "workstations-projection")
    };
    private static string Key(JsonObject job) => string.Join('/', new[] { "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256" }.Select(job.Text));
    public void Register(JsonObject manifest, bool active = true)
    {
        CoreJobJson.Validate(manifest, Schema, Schema);
        static int CompareApi(JsonNode? node)
        {
            var parts = node!.GetValue<string>().Split('.').Select(x => BigInteger.Parse(x, CultureInfo.InvariantCulture)).ToArray();
            for (int index = 0; index < 3; index++)
            {
                int compared = parts[index].CompareTo(index == 0 ? BigInteger.One : BigInteger.Zero);
                if (compared != 0) return compared;
            }
            return 0;
        }
        var api = manifest["core_api"]!;
        if (CompareApi(api["minimum"]) > 0 || CompareApi(api["maximum_exclusive"]) <= 0) throw new CoreJobContractException("handler_core_api_incompatible");
        if (manifest["dependencies"]!.AsArray().Any(d => d!["required"]!.GetValue<bool>())) throw new CoreJobContractException("handler_dependency_unavailable");
        var pending = new Dictionary<string, JsonObject>(); var ids = new HashSet<string>();
        foreach (var handler in manifest["handlers"]!.AsArray().OfType<JsonObject>())
        {
            string id = handler.Text("handler_id"), profile = handler.Text("resource_profile");
            string allow = $"{manifest.Text("plugin_id")}/{id}/{handler.Text("handler_version")}";
            if (!Allowlist.TryGetValue(allow, out var permitted) || permitted != (profile, handler.Text("rights_profile")) || !ids.Add(id)) throw new CoreJobContractException("handler_not_allowlisted");
            var registered = (JsonObject)handler.DeepClone();
            registered["plugin_id"] = manifest["plugin_id"]!.DeepClone();
            registered["plugin_version"] = manifest["plugin_version"]!.DeepClone();
            registered["manifest_sha256"] = CoreJobJson.Digest(manifest);
            string key = Key(registered);
            if (handlers.ContainsKey(key)) throw new CoreJobContractException("handler_registration_duplicate");
            var budget = registered["budget"]!.AsObject(); var caps = Profiles[profile];
            foreach (var (field, cap) in new (string, long)[] { ("wall_seconds", caps.Wall), ("cpu_seconds", caps.Wall), ("memory_bytes", caps.Memory), ("max_records", caps.Records), ("max_result_bytes", 65536), ("statement_timeout_ms", 10000), ("lock_timeout_ms", 1000) })
                budget[field] = (long)BigInteger.Min(BigInteger.Parse(budget[field]!.ToJsonString(), CultureInfo.InvariantCulture), cap);
            budget["max_db_connections"] = 1;
            pending.Add(key, registered);
        }
        var scheduleIds = new HashSet<string>();
        foreach (var schedule in manifest["schedules"]!.AsArray().OfType<JsonObject>())
        {
            if (!ids.Contains(schedule.Text("handler_id")) || !scheduleIds.Add(schedule.Text("schedule_id"))) throw new CoreJobContractException("schedule_reference_invalid");
            bool interval = schedule["interval_seconds"] is not null, calendar = schedule["calendar"] is not null;
            if (schedule.Text("trigger") switch { "interval" => !interval || calendar, "calendar" => interval || !calendar, _ => interval || calendar }) throw new CoreJobContractException("schedule_trigger_invalid");
            try { TimeZoneInfo.FindSystemTimeZoneById(schedule.Text("timezone")); }
            catch (TimeZoneNotFoundException) { throw new CoreJobContractException("schedule_trigger_invalid"); }
        }
        foreach (var item in pending) handlers.Add(item.Key, item.Value);
        if (active) manifests.Add((JsonObject)manifest.DeepClone());
    }
    internal void Activate(JsonObject manifest)
    {
        if (!manifests.Any(m => CoreJobJson.Digest(m) == CoreJobJson.Digest(manifest))) manifests.Add((JsonObject)manifest.DeepClone());
    }
    public JsonArray Identities(string profile) => new(handlers.Values.Where(h => h.Text("resource_profile") == profile)
        .Select(h => (JsonNode)CoreJobJson.Pick(h, "plugin_id", "handler_id", "handler_version", "plugin_version", "manifest_sha256")).ToArray());
    public JsonObject Resolve(JsonObject job)
    {
        if (!handlers.TryGetValue(Key(job), out var handler) || new[] { "resource_profile", "rights_profile", "input_contract", "result_contract", "budget", "max_attempts" }.Any(f => !JsonNode.DeepEquals(job[f], handler[f])) || job.Text("job_type") != handler.Text("kind")) throw new CoreJobContractException("handler_version_unavailable");
        if (CoreJobJson.Digest(job["pinned_input"]) != job.Text("input_sha256")) throw new CoreJobContractException("job_input_hash_conflict");
        return (JsonObject)handler.DeepClone();
    }
}
