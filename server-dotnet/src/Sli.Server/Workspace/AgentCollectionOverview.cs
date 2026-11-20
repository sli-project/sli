using System.Text.Json;
using System.Text.RegularExpressions;
using Sli.Server.Access;
using static Sli.Server.Workspace.WorkspaceJson;

namespace Sli.Server.Workspace;

public sealed class AgentCollectionOverview(IWorkspaceRows rows)
{
    public sealed record StreamRequest(string agent_id, string module_id, string revision, string? channel, bool snapshot);
    private sealed record Check(string? channel, string state, string? failure_reason, string? issue_since_utc,
        string? issue_observed_at_utc, string? last_packet_at, string? last_import_at,
        long? import_lag_seconds, long budget_seconds)
    {
        [System.Text.Json.Serialization.JsonExtensionData]
        public Dictionary<string, object?>? Diagnostics { get; init; }
    }
    private sealed record Module(string module_id, IReadOnlyList<Check> channels);
    private sealed record Agent(string id, string host_id, string name, string[] domains, string state, string connection,
        object completeness, string? last_seen, string? last_packet_at, IReadOnlyList<Module> modules,
        long policy_revision, long applied_policy_revision, string href);

    public async Task<object> ReadAsync(CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            var agents = await rows.ReadAsync(ReadResource("agents.sql"), ct);
            var requests = RequestedStreams(agents);
            try
            {
                var streams = requests.Count > 0
                    ? await rows.ReadAsync(ReadResource("streams.sql"), ct, JsonParameter("requested", requests)) : [];
                return Compose(agents, streams, now);
            }
            catch (Exception error) when (!ct.IsCancellationRequested && error is not UnauthorizedAccessException)
            {
                var result = JsonSerializer.SerializeToNode(Compose(agents, [], now, false))!.AsObject();
                result["diagnostics"] = JsonSerializer.SerializeToNode(new { state = "unavailable", reason = error is TimeoutException
                    || error is Npgsql.PostgresException { SqlState: "57014" } ? "timeout" : "read_failed" });
                return result;
            }
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            return new { state = "unavailable", items = Array.Empty<object>(), active_agents = 0, current_agents = 0,
                completeness = new { state = "not_assessed" }, checked_at_utc = Iso(now) };
        }
    }

    public static IReadOnlyList<StreamRequest> RequestedStreams(IReadOnlyList<JsonElement> agents) => agents
        .SelectMany(agent => agent.Get("assigned_modules").Items().Where(a => a.ValueKind == JsonValueKind.Object && Flag(a, "enabled"))
            .SelectMany(assignment => Channels(assignment.Text("module_id"), assignment.Get("config"))
                .Select(channel => new StreamRequest(agent.Text("id"), assignment.Text("module_id"), Revision(assignment.Get("config")),
                    channel, Snapshot(assignment.Text("module_id")))))).ToArray();

    public static object Compose(IReadOnlyList<JsonElement> agents, IReadOnlyList<JsonElement> streams, DateTimeOffset now, bool diagnosticsAvailable = true)
    {
        var byStream = streams.ToDictionary(s => (s.Text("agent_id"), s.Text("module_id"), s.Text("revision"), s.Text("channel")));
        var items = new List<Agent>();
        foreach (var agent in agents)
        {
            var policy = agent.Get("collection_policy");
            bool enabled = agent.Text("status") == "active" && policy.Text("state", "active") == "active";
            bool applied = Number(agent, "policy_revision") == Number(agent, "applied_policy_revision") && agent.Text("applied_collection_state") == "active";
            long interval = Number(policy, "interval_seconds", 60);
            long? contact = Age(Time(agent, "last_seen"), now);
            string connection = contact is null ? "never_seen" : contact <= Math.Max(300, interval * 3) ? "online" : "offline";
            var domains = new HashSet<string>(StringComparer.Ordinal);
            if (agent.Text("domain").Length > 0) domains.Add(agent.Text("domain"));
            var modules = new List<Module>();
            foreach (var assignment in agent.Get("assigned_modules").Items().Where(a => a.ValueKind == JsonValueKind.Object && Flag(a, "enabled")))
            {
                string module = assignment.Text("module_id");
                var config = assignment.Get("config");
                if (config.Text("domain_dns").Length > 0) domains.Add(config.Text("domain_dns"));
                var channels = Channels(module, config);
                bool moduleEnabled = enabled && !Flag(config, "paused");
                long budget = Budget(module, config, interval, channels.Count);
                var checks = new List<Check>();
                foreach (var channel in channels)
                {
                    byStream.TryGetValue((agent.Text("id"), module, Revision(config), channel ?? ""), out var stream);
                    var packet = Time(stream, "last_packet_at"); var imported = Time(stream, "last_import_at");
                    long? age = Age(packet, now), pending = Age(Time(stream, "pending_since"), now);
                    var graceStart = Time(agent, "policy_applied_at") ?? Time(agent, "created_at");
                    long? grace = Age(graceStart, now);
                    var deadline = graceStart?.AddSeconds(budget);
                    long importBudget = 900 + (Snapshot(module) ? Number(config, "capture_seconds", 300) : 0);
                    string state = agent.Text("status") == "active" && !moduleEnabled ? "paused" : !enabled ? "disabled" : "waiting";
                    string? reason = null;
                    DateTimeOffset? since = null, observed = null;
                    if (moduleEnabled && !diagnosticsAvailable) state = "unknown";
                    else if (moduleEnabled && (applied || connection != "online" && grace > budget))
                    {
                        if (Flag(stream, "read_error")) { state = "error"; reason = "read_error"; observed = packet <= now ? packet : null; }
                        else if (pending > importBudget) { state = "error"; reason = "import_overdue"; since = Time(stream, "pending_since")?.AddSeconds(importBudget); }
                        else if (age is null) { state = grace > budget ? "error" : "waiting"; if (state == "error") { reason = "packet_missing"; since = deadline; } }
                        else if (age > budget)
                        {
                            state = grace <= budget ? "waiting" : "error";
                            if (state == "error") { reason = "packet_stale"; since = Later(packet?.AddSeconds(budget), deadline); }
                        }
                        else if (Age(imported, now) > budget) { state = "error"; reason = "import_overdue"; since = imported?.AddSeconds(budget); }
                        else if (pending is not null) state = "lagging";
                        else if (module == "sli.file-audit" && stream.Get("read_error").ValueKind is JsonValueKind.Undefined or JsonValueKind.Null) state = "unknown";
                        else state = imported is not null ? "current" : "unknown";
                    }
                    if (since is not null) { if (!applied) since = Later(since, deadline); observed = now; }
                    long? lag = pending ?? (packet is not null && imported is not null ? Math.Max(0, (long)(imported.Value - packet.Value).TotalSeconds) : null);
                    checks.Add(new(channel, state, reason, Iso(since), Iso(observed), Iso(packet), Iso(imported), lag, budget)
                    {
                        Diagnostics = diagnosticsAvailable ? new() { ["historical_unimported_packets"] = Number(stream, "historical_unimported_packets"),
                            ["historical_error_at"] = Iso(Time(stream, "historical_error_at")) } : null
                    });
                }
                modules.Add(new(module, checks));
            }
            var activeChecks = modules.SelectMany(m => m.channels).Where(c => c.state is not ("paused" or "disabled")).ToArray();
            string agentState = agent.Text("status") != "active" ? "disabled" : !enabled ? "paused" : !diagnosticsAvailable ? "unknown"
                : activeChecks.Any(c => c.state == "error") ? "error" : !applied || activeChecks.Length == 0 ? "waiting"
                : activeChecks.All(c => c.state == "current") ? "current" : activeChecks.Any(c => c.state == "lagging") ? "lagging"
                : activeChecks.Any(c => c.state == "waiting") ? "waiting" : "unknown";
            string hostName = HumanName(agent.Text("host_name")) ?? ReportedName(agent.Text("registration_host_name"))
                ?? agent.Get("assigned_modules").Items().FirstOrDefault(a => a.Text("module_id") == "sli.windows.ad-dc").Get("config").Text("source_name").Trim();
            if (hostName == agent.Text("host_id") || hostName == agent.Text("id")) hostName = "";
            var packets = activeChecks.Where(c => c.last_packet_at is not null).Select(c => c.last_packet_at).Order(StringComparer.Ordinal).ToArray();
            items.Add(new(agent.Text("id"), agent.Text("host_id"), string.Join(" · ", new[] { hostName, agent.Text("instance_name") }.Where(s => s.Length > 0)),
                domains.Order(StringComparer.Ordinal).ToArray(), agentState, connection,
                new { state = Time(agent, "last_accepted_gap_at") is null ? "not_assessed" : "known_gaps", last_accepted_gap_at = Iso(Time(agent, "last_accepted_gap_at")) },
                Iso(Time(agent, "last_seen")), Iso(Time(agent, "last_packet_at")) ?? packets.LastOrDefault(), modules,
                Number(agent, "policy_revision"), Number(agent, "applied_policy_revision"),
                "/app/agents?agent_id=" + Uri.EscapeDataString(agent.Text("id")) + "#agent-" + Uri.EscapeDataString(agent.Text("id"))));
        }
        items = items.OrderBy(i => string.Join('\0', i.domains), StringComparer.Ordinal).ThenBy(i => i.name, StringComparer.Ordinal).ThenBy(i => i.id, StringComparer.Ordinal).ToList();
        var active = items.Where(i => i.state is not ("paused" or "disabled")).ToArray();
        return new { state = active.Any(i => i.state == "error") ? "error" : active.Length > 0 && active.All(i => i.state == "current") ? "current" : active.Length > 0 ? "partial" : "unknown",
            items, checked_at_utc = Iso(now), completeness = new { state = agents.Any(a => Time(a, "last_accepted_gap_at") is not null) ? "known_gaps" : "not_assessed" },
            active_agents = active.Length, current_agents = active.Count(i => i.state == "current") };
    }

    private static bool Snapshot(string module) => module is "sli.ad-snapshot" or "sli.gpo-snapshot";
    private static string Revision(JsonElement config) => config.Get("policy_revision").ValueKind is JsonValueKind.String or JsonValueKind.Number ? config.Get("policy_revision").ToString() : "1";
    internal static bool Flag(JsonElement row, string key) => row.Get(key).ValueKind == JsonValueKind.True;
    internal static long Number(JsonElement row, string key, long fallback = 0) => row.Get(key).ValueKind == JsonValueKind.Number && row.Get(key).TryGetInt64(out var n) ? n : fallback;
    private static DateTimeOffset? Later(DateTimeOffset? a, DateTimeOffset? b) => a is null ? b : b is null || a > b ? a : b;
    private static string? HumanName(string value) => string.IsNullOrWhiteSpace(value) || value.Trim().ToLowerInvariant() is "localhost" or "unknown" || Guid.TryParse(value.Trim(), out _) ? null : value.Trim();
    private static string? ReportedName(string value) => HumanName(value) is not null && value.Length <= 253
        && value.ToLowerInvariant() != "localhost.localdomain" && !Regex.IsMatch(value, @"\A[0-9]+(?:\.[0-9]+){3}\z")
        && value.Split('.').All(label => Regex.IsMatch(label, @"\A[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z")) ? value : null;

    private static IReadOnlyList<string?> Channels(string module, JsonElement config)
    {
        if (Snapshot(module)) return [null];
        if (module == "sli.windows.ad-dc") return new[] { "Security", "System", "Directory Service" }.Where(c => config.Get("channels").Get(c).ValueKind != JsonValueKind.False).ToArray();
        if (module is "sli.vpn-nps" or "sli.radius-accounting")
        {
            if (config.Get("families").Get(module == "sli.vpn-nps" ? "nps" : "radius_accounting").ValueKind == JsonValueKind.False) return [];
            return [module == "sli.vpn-nps" ? "Security" : "radius-accounting"];
        }
        if (module == "sli.file-audit") return ["Security"];
        if (module == "sli.windows-eventlog") return config.Text("channel").Length > 0 ? [config.Text("channel")] : [];
        if (module != "sli.workstations") return [];
        bool Family(string name) => config.Get("families").Get(name).ValueKind != JsonValueKind.False;
        var result = new List<string?>();
        if (new[] { "logons", "processes", "usb", "local_admins", "protection" }.Any(Family)) result.Add("Security");
        if (Family("protection")) result.AddRange(["System", "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-TaskScheduler/Operational"]);
        if (Family("usb")) result.AddRange(["Microsoft-Windows-DriverFrameworks-UserMode/Operational", "Microsoft-Windows-Kernel-PnP/Configuration"]);
        if (Family("protection")) result.Add("Microsoft-Windows-PowerShell/Operational");
        return result;
    }
    private static long Budget(string module, JsonElement config, long interval, int count)
    {
        if (!Snapshot(module)) return Math.Max(900, interval * Math.Max(1, count) * 3);
        var hours = config.Get("schedule").Get("hours").Items().Select(h => h.GetInt32()).ToArray();
        if (hours.Length == 0) hours = [6, 18];
        return hours.Select((h, i) => (i + 1 < hours.Length ? hours[i + 1] : hours[0] + 24) - h).Max() * 3600L + Number(config, "capture_seconds", 300) + 900;
    }
}
