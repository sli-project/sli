using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Owner-bound snapshot policy, identical to sli_agent.snapshot_stream.policy.</summary>
public sealed record SnapshotPolicy(string ModuleId, JsonObject Config)
{
    public const string Ad = "sli.ad-snapshot";
    public const string Gpo = "sli.gpo-snapshot";
    public static readonly string[] AdFamilies = ["ad_context_base", "ad_privileged_membership", "ad_vpn_membership", "ad_domain_posture", "ad_domain_health", "computers_v6"];
    public static readonly string[] GpoFamilies = ["ad_gpo_governance", "gpo_v2"];
    public string SourceId => Config["source_instance_id"]!.GetValue<string>();
    public string Revision => Config["policy_revision"]!.GetValue<string>();
    public string[] Families => Config["families"]!.AsArray().Select(n => n!.GetValue<string>()).ToArray();
    public int Number(string key) => Config[key]!.GetValue<int>();

    public static SnapshotPolicy Parse(string moduleId, JsonObject input)
    {
        static AgentException Invalid() => new("agent_snapshot_policy_invalid");
        var cfg = (JsonObject)input.DeepClone();
        var allowed = new[] { "source_instance_id", "domain_sid", "domain_dns", "scope", "families", "policy_revision", "schedule", "capture_seconds", "buffer_bytes", "max_objects", "max_bytes", "dc", "search_bases", "groups", "expensive_flags" };
        if (moduleId is not (Ad or Gpo) || cfg.Any(p => !allowed.Contains(p.Key))) throw Invalid();
        string Text(string key) => JsonRead.TryString(cfg[key], out var s) ? s : throw Invalid();
        var source = Text("source_instance_id");
        if (!Guid.TryParseExact(source, "D", out var id) || id.ToString() != source
            || !Regex.IsMatch(Text("domain_sid"), @"\AS-1-5-21-\d+-\d+-\d+\z")
            || !Regex.IsMatch(Text("domain_dns"), @"\A[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\z")
            || Text("scope").Length is < 1 or > 512) throw Invalid();
        if (!cfg.ContainsKey("policy_revision")) cfg["policy_revision"] = "1";
        var revision = Text("policy_revision");
        if (!Regex.IsMatch(revision, @"\A\d+\z") || !long.TryParse(revision, out var rev) || rev is < 1 or > 9007199254740991) throw Invalid();
        var families = moduleId == Ad ? AdFamilies : GpoFamilies;
        if (!cfg.ContainsKey("families")) cfg["families"] = new JsonArray(families.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
        if (cfg["families"] is not JsonArray selected || selected.Count == 0
            || selected.Any(n => !JsonRead.TryString(n, out var f) || !families.Contains(f))
            || selected.Select(n => n!.GetValue<string>()).Distinct().Count() != selected.Count) throw Invalid();
        if (!cfg.ContainsKey("schedule")) cfg["schedule"] = new JsonObject { ["timezone"] = "Asia/Novosibirsk", ["hours"] = new JsonArray(6, 18) };
        if (cfg["schedule"] is not JsonObject schedule || !JsonRead.HasExactly(schedule, "timezone", "hours")
            || !JsonRead.TryString(schedule["timezone"], out var zone) || schedule["hours"] is not JsonArray hours || hours.Count is < 1 or > 24) throw Invalid();
        try { TimeZoneInfo.FindSystemTimeZoneById(zone); } catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { throw Invalid(); }
        var previous = -1;
        foreach (var hour in hours)
        {
            if (!JsonRead.TryInteger(hour, out var h) || h <= previous || h > 23) throw Invalid();
            previous = (int)h;
        }
        foreach (var (key, fallback, ceiling) in new[] { ("capture_seconds", 300, 3600), ("buffer_bytes", 128 * 1024 * 1024, 128 * 1024 * 1024),
            ("max_objects", moduleId == Gpo ? 10000 : 50000, moduleId == Gpo ? 10000 : 50000),
            ("max_bytes", moduleId == Gpo ? 64 * 1024 * 1024 : 25 * 1024 * 1024, moduleId == Gpo ? 64 * 1024 * 1024 : 25 * 1024 * 1024) })
        {
            if (!cfg.ContainsKey(key)) cfg[key] = fallback;
            if (!JsonRead.TryInteger(cfg[key], out var number) || number < 1 || number > ceiling) throw Invalid();
            cfg[key] = (int)number;
        }
        foreach (var key in new[] { "dc", "search_bases", "groups" })
        {
            if (!cfg.ContainsKey(key)) cfg[key] = new JsonArray();
            if (cfg[key] is not JsonArray values || values.Count > 64 || values.Any(n => !JsonRead.TryString(n, out var s) || s.Length is < 1 or > 512)) throw Invalid();
        }
        if (!cfg.ContainsKey("expensive_flags")) cfg["expensive_flags"] = new JsonObject();
        if (cfg["expensive_flags"] is not JsonObject flags || flags.Any(p => !new[] { "exact_last_logon", "dns", "ad_site", "inventory" }.Contains(p.Key)
            || p.Value is not JsonValue v || !v.TryGetValue<bool>(out _))) throw Invalid();
        return new(moduleId, cfg);
    }

    public string DueSlot(DateTimeOffset now)
    {
        var schedule = Config["schedule"]!;
        var zone = TimeZoneInfo.FindSystemTimeZoneById(schedule["timezone"]!.GetValue<string>());
        var date = TimeZoneInfo.ConvertTime(now, zone).Date;
        var slots = from day in new[] { 0, 1 }
                    from h in schedule["hours"]!.AsArray()
                    let local = date.AddDays(-day).AddHours(h!.GetValue<int>())
                    where !zone.IsInvalidTime(local)
                    let utc = new DateTimeOffset(TimeZoneInfo.ConvertTimeToUtc(local, zone))
                    where utc <= now
                    select utc;
        return Iso8601.Format(slots.Max());
    }
}
