using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Ingress;

namespace Sli.Server.InstallationSetup;

// Source collection_health: registry contact, current policy streams and retained
// completeness evidence are independent. Never infer delivery from last_seen.
public static class SetupCollectionHealth
{
    static string T(JsonNode? n) => InstallationPackages.Text(n);
    static bool B(JsonNode? n) => n is JsonValue v && v.TryGetValue<bool>(out bool b) && b;
    static long N(JsonNode? n, long fallback = 0) => n is JsonValue v && v.TryGetValue<long>(out long l) ? l
        : n is JsonValue i && i.TryGetValue<int>(out int number) ? number : fallback;
    static JsonArray Array(JsonNode? n) => n as JsonArray ?? new();
    static DateTimeOffset? Time(JsonNode? n) => DateTimeOffset.TryParse(T(n), out var t) ? t : null;
    static string? Iso(DateTimeOffset? time) => time?.ToString("yyyy-MM-ddTHH:mm:ss.ffffffzzz");
    static long? Age(JsonNode? n, DateTimeOffset now) => Time(n) is { } t ? Math.Max(0, (long)(now - t).TotalSeconds) : null;
    static bool Snapshot(string module) => module is "sli.ad-snapshot" or "sli.gpo-snapshot";
    internal static JsonArray DataGaps(JsonNode? expiry) => new((expiry as JsonObject ?? new())
        .Where(m => m.Value?["data_gap"] is JsonObject gap
            && Time(gap["from_utc"]) is {} from && Time(gap["to_utc"]) is {} to && from <= to)
        .Select(m =>
        {
            var gap = new JsonObject
            {
                ["module_id"] = m.Key,
                ["from_utc"] = m.Value!["data_gap"]!["from_utc"]?.DeepClone(),
                ["to_utc"] = m.Value!["data_gap"]!["to_utc"]?.DeepClone(),
            };
            if (m.Key == FileAuditPolicy.ModuleId && JsonRead.TryString(m.Value["last_rejection_reason"],out var reason)
                && AgentFileAuditValidator.IsRejectionReason(reason) && N(m.Value["rejected_count"]) is > 0 and var count)
            {
                gap["last_rejection_reason"] = reason;
                gap["rejected_count"] = count;
            }
            return (JsonNode?)gap;
        }).ToArray());
    internal static long ContactBudgetSeconds(long interval) => Math.Max(300, interval * 3);
    internal static string FreshStreamState(long? pendingAge, bool missingReadEvidence, bool hasImport)
    {
        if (pendingAge is not null) return "current";
        return !missingReadEvidence && hasImport ? "current" : "unknown";
    }
    public static string?[] Channels(string module, JsonObject config)
    {
        if (Snapshot(module)) return [null];
        if (module == "sli.windows.ad-dc") return new[] { "Security", "System", "Directory Service" }.Where(c => config["channels"]?[c] is null || B(config["channels"]![c])).ToArray();
        if (module is "sli.vpn-nps" or "sli.radius-accounting")
        {
            string family = module == "sli.vpn-nps" ? "nps" : "radius_accounting";
            if (config["families"]?[family] is not null && !B(config["families"]![family])) return [];
            return [module == "sli.vpn-nps" ? "Security" : "radius-accounting"];
        }
        if (module == "sli.file-audit") return ["Security"];
        if (module == "sli.windows-eventlog") return T(config["channel"]) is { Length: > 0 } channel ? [channel] : [];
        if (module != "sli.workstations") return [];
        var workstation = WorkstationPolicy.Parse(config);
        return Enumerable.Range(0, WorkstationPolicy.Channels.Length).Where(workstation.ChannelEnabled).Select(i => WorkstationPolicy.Channels[i]).ToArray();
    }
    static long Budget(string module, JsonObject config, long interval, int channels)
    {
        if (!Snapshot(module)) return Math.Max(900, interval * Math.Max(1, channels) * 3);
        long[] hours = config["schedule"]?["hours"] is JsonArray h ? h.Select(x => N(x)).ToArray() : [6, 18];
        if (hours.Length == 0) throw new InvalidOperationException("invalid_snapshot_schedule");
        return hours.Select((hour, i) => (i + 1 < hours.Length ? hours[i + 1] : hours[0] + 24) - hour).Max() * 3600 + N(config["capture_seconds"], 300) + 900;
    }
    public static JsonArray Requested(JsonArray agents)
    {
        var result = new JsonArray();
        foreach (var agent in agents.OfType<JsonObject>())
            foreach (var assignment in Array(agent["assigned_modules"]).OfType<JsonObject>().Where(a => B(a["enabled"])))
            {
                string module = T(assignment["module_id"]); var config = assignment["config"] as JsonObject ?? new();
                foreach (string? channel in Channels(module, config))
                    result.Add(new JsonObject { ["agent_id"] = T(agent["id"]), ["module_id"] = module,
                        ["revision"] = config["policy_revision"] is null ? "1" : config["policy_revision"]!.ToString(), ["channel"] = channel, ["snapshot"] = Snapshot(module) });
            }
        return result;
    }
    public static async Task<JsonObject> ReadAsync(IInstallationDatabase database, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        try
        {
            var agents = await database.ReadAsync(s => s.QueryAsync(InstallationService.Sql("setup-agents.sql"), ct), ct);
            JsonArray streams;
            JsonObject? diagnostics = null;
            try
            {
                var requested = Requested(agents);
                streams = requested.Count == 0 ? new() : await database.WriteAsync(async s => {
                    await s.QueryAsync("set local jit=off", ct);
                    return await s.QueryAsync(InstallationService.Sql("setup-streams.sql"), ct, requested.ToJsonString()); }, ct);
            }
            catch (Exception e) when (e is NpgsqlException or InvalidOperationException or ArgumentException or AgentException or TimeoutException)
            {
                streams = new(); diagnostics = new() { ["state"] = "unavailable", ["reason"] = e is PostgresException p && p.SqlState == "57014" || e is TimeoutException ? "timeout" : "read_failed" };
            }
            var result = View(agents, streams, now, diagnostics is null);
            if (diagnostics is not null) result["diagnostics"] = diagnostics;
            result["_setup_bindings"] = Bindings(agents);
            return result;
        }
        catch (Exception e) when (e is NpgsqlException or InvalidOperationException or ArgumentException or AgentException or TimeoutException)
        {
            return new() { ["state"] = "unavailable", ["items"] = new JsonArray(), ["active_agents"] = 0, ["current_agents"] = 0,
                ["completeness"] = new JsonObject { ["state"] = "not_assessed" }, ["checked_at_utc"] = Iso(now), ["_setup_bindings"] = new JsonArray() };
        }
    }
    public static JsonObject View(JsonArray agents, JsonArray streams, DateTimeOffset now, bool diagnosticsAvailable = true)
    {
        var items = new JsonArray();
        var connectedControllers = new HashSet<(string Kind, string Id)>();
        foreach (var agent in agents.OfType<JsonObject>())
        {
            var policy = agent["collection_policy"] as JsonObject ?? new();
            bool enabled = T(agent["status"]) == "active" && (T(policy["state"]) is "" or "active");
            bool applied = N(agent["policy_revision"]) == N(agent["applied_policy_revision"]) && T(agent["applied_collection_state"]) == "active";
            long interval = N(policy["interval_seconds"], 60);
            long? connectionAge = Age(agent["last_seen"], now);
            string connection = connectionAge is null ? "never_seen" : connectionAge <= ContactBudgetSeconds(interval) ? "online" : "offline";
            var assignments = Array(agent["assigned_modules"]);
            if (T(agent["status"]) == "active" && connection == "online" && assignments.Any(a =>
                T(a is JsonObject assignment ? assignment["module_id"] : a) is "sli.windows.ad-dc" or "sli.windows.ad-dc-history"))
            {
                connectedControllers.Add(T(agent["server_id"]) is { Length: > 0 } server ? ("server", server)
                    : T(agent["host_id"]) is { Length: > 0 } host ? ("host", host) : ("agent", T(agent["id"])));
            }
            var modules = new JsonArray(); var domains = new SortedSet<string>(StringComparer.Ordinal);
            if (T(agent["domain"]).Length > 0) domains.Add(T(agent["domain"]));
            foreach (var assignment in assignments.OfType<JsonObject>().Where(a => B(a["enabled"])))
            {
                string module = T(assignment["module_id"]); var config = assignment["config"] as JsonObject ?? new();
                if (T(config["domain_dns"]).Length > 0) domains.Add(T(config["domain_dns"]));
                string?[] channels = Channels(module, config);
                bool moduleEnabled = enabled && !B(config["paused"]);
                long budget = Budget(module, config, interval, Snapshot(module) ? 0 : channels.Length);
                var checks = new JsonArray();
                foreach (string? channel in channels)
                {
                    string revision = config["policy_revision"]?.ToString() ?? "1";
                    var stream = streams.OfType<JsonObject>().FirstOrDefault(s => T(s["agent_id"]) == T(agent["id"]) && T(s["module_id"]) == module
                        && T(s["revision"]) == revision && (channel is null ? s["channel"] is null : T(s["channel"]) == channel)) ?? new();
                    long? age = Age(stream["last_packet_at"], now), pending = Age(stream["pending_since"], now), grace = Age(agent["policy_applied_at"] ?? agent["created_at"], now);
                    DateTimeOffset? graceStart = Time(agent["policy_applied_at"] ?? agent["created_at"]), graceDeadline = graceStart?.AddSeconds(budget);
                    long importBudget = 900 + (Snapshot(module) ? N(config["capture_seconds"], 300) : 0);
                    string state = T(agent["status"]) == "active" && !moduleEnabled ? "paused" : !enabled ? "disabled" : "waiting";
                    string? failure = null; DateTimeOffset? since = null, observed = null;
                    if (moduleEnabled && !diagnosticsAvailable) state = "unknown";
                    else if (moduleEnabled && stream["import_failure_reason"] is not null)
                    { state = "error"; failure = "import_rejected"; observed = Time(stream["import_failure_at"]); }
                    else if (moduleEnabled && (applied || connection != "online" && grace > budget))
                    {
                        if (B(stream["read_error"]))
                        { state = "error"; failure = "read_error"; var receipt = Time(stream["last_packet_at"]); observed = receipt <= now ? receipt : null; }
                        else if (pending > importBudget) { state = "error"; failure = "import_overdue"; since = Time(stream["pending_since"])?.AddSeconds(importBudget); }
                        else if (age is null) { state = grace > budget ? "error" : "waiting"; if (state == "error") { failure = "packet_missing"; since = graceDeadline; } }
                        else if (age > budget)
                        {
                            state = grace <= budget ? "waiting" : "error";
                            if (state == "error") { failure = "packet_stale"; since = Time(stream["last_packet_at"])?.AddSeconds(budget); if (graceDeadline > since) since = graceDeadline; }
                        }
                        else if (Age(stream["last_import_at"], now) > budget) { state = "error"; failure = "import_overdue"; since = Time(stream["last_import_at"])?.AddSeconds(budget); }
                        else state = FreshStreamState(pending, module == "sli.file-audit" && stream["read_error"] is null,
                            stream["last_import_at"] is not null);
                    }
                    if (since is not null) { if (!applied && graceDeadline > since) since = graceDeadline; observed = now; }
                    long? lag = pending;
                    if (lag is null && Time(stream["last_packet_at"]) is { } packet && Time(stream["last_import_at"]) is { } imported) lag = Math.Max(0, (long)(imported - packet).TotalSeconds);
                    var check = new JsonObject { ["channel"] = channel, ["state"] = state, ["failure_reason"] = failure,
                        ["issue_since_utc"] = Iso(since), ["issue_observed_at_utc"] = Iso(observed), ["last_packet_at"] = Iso(Time(stream["last_packet_at"])),
                        ["last_import_at"] = Iso(Time(stream["last_import_at"])), ["import_lag_seconds"] = lag, ["budget_seconds"] = budget };
                    if (diagnosticsAvailable) {
                        check["historical_unimported_packets"] = N(stream["historical_unimported_packets"]); check["historical_error_at"] = Iso(Time(stream["historical_error_at"]));
                        check["import_failure_reason"] = stream["import_failure_reason"]?.DeepClone(); check["import_failure_at"] = Iso(Time(stream["import_failure_at"]));
                    }
                    checks.Add(check);
                }
                modules.Add(new JsonObject { ["module_id"] = module, ["channels"] = checks });
            }
            var activeChecks = modules.OfType<JsonObject>().SelectMany(m => Array(m["channels"]).OfType<JsonObject>()).Where(c => T(c["state"]) is not ("paused" or "disabled")).ToArray();
            string stateForAgent = T(agent["status"]) != "active" ? "disabled" : !enabled ? "paused" : !diagnosticsAvailable ? "unknown"
                : activeChecks.Any(c => T(c["state"]) == "error") ? "error" : !applied || activeChecks.Length == 0 ? "waiting"
                : activeChecks.All(c => T(c["state"]) == "current") ? "current"
                : activeChecks.Any(c => T(c["state"]) == "waiting") ? "waiting" : "unknown";
            string name = HumanName(T(agent["canonical_host_name"]));
            if(name.Length==0) name=HumanName(T(agent["host_name"]));
            if (name.Length == 0) name = ReportedName(T(agent["registration_host_name"]));
            if (name.Length == 0) name = Array(agent["assigned_modules"]).OfType<JsonObject>().Where(a => T(a["module_id"]) == "sli.windows.ad-dc")
                .Select(a => T(a["config"]?["source_name"]).Trim()).FirstOrDefault() ?? "";
            if (name == T(agent["host_id"]) || name == T(agent["id"])) name = "";
            if(agent["server_id"] is null) name = string.Join(" · ", new[] { name, T(agent["instance_name"]) }.Where(s => s.Length > 0));
            var packetStamps = activeChecks.Select(c => Time(c["last_packet_at"])).Where(t => t.HasValue).ToArray();
            items.Add(new JsonObject { ["id"] = T(agent["id"]), ["host_id"] = T(agent["host_id"]), ["name"] = name,
                ["can_restore"]=B(agent["can_restore"]), ["server_id"]=agent["server_id"]?.DeepClone(),["status"]=agent["status"]?.DeepClone(),["agent_version"]=agent["agent_version"]?.DeepClone(),["replaced_by"]=agent["replaced_by"]?.DeepClone(),["identity_conflict"]=B(agent["identity_conflict"]),
                ["certificate_reissue_required"]=B(agent["certificate_reissue_required"]),
                ["domains"] = new JsonArray(domains.Select(d => (JsonNode?)JsonValue.Create(d)).ToArray()), ["state"] = stateForAgent, ["connection"] = connection,
                ["data_gaps"] = DataGaps(agent["packet_expiry"]),
                ["completeness"] = new JsonObject { ["state"] = agent["last_accepted_gap_at"] is null ? "not_assessed" : "known_gaps", ["last_accepted_gap_at"] = Iso(Time(agent["last_accepted_gap_at"])) },
                ["last_seen"] = Iso(Time(agent["last_seen"])), ["last_packet_at"] = Iso(Time(agent["last_packet_at"]) ?? (packetStamps.Length > 0 ? packetStamps.Max() : null)),
                ["modules"] = modules, ["policy_revision"] = agent["policy_revision"]?.DeepClone(), ["applied_policy_revision"] = agent["applied_policy_revision"]?.DeepClone(),
                ["collection_interval_seconds"] = interval,
                ["windows_audit"] = agent["windows_audit"] is JsonObject audit && audit["families"] is JsonObject
                    ? audit.DeepClone() : null,
                ["eventlog_diagnostics"] = agent["eventlog_diagnostics"]?.DeepClone(),
                ["href"] = "/app/agents?agent_id=" + T(agent["id"]) + "#agent-" + T(agent["id"]) });
            if (B(agent["password_domain_required"])) items[^1]!["password_domain_required"] = true;
        }
        var replaced=ConsolidateDcSources(items);
        var sorted = items.OfType<JsonObject>().OrderBy(a => string.Join('\0', Array(a["domains"]).Select(T)), StringComparer.Ordinal).ThenBy(a => T(a["name"]), StringComparer.Ordinal).ThenBy(a => T(a["id"]), StringComparer.Ordinal).ToArray();
        var active = sorted.Where(a => T(a["state"]) is not ("paused" or "disabled")).ToArray();
        string overallState = active.Any(a => T(a["state"]) == "error") ? "error" : active.Length > 0 && active.All(a => T(a["state"]) == "current") ? "current" : active.Length > 0 ? "partial" : "unknown";
        return new() { ["state"] = overallState, ["items"] = new JsonArray(sorted.Select(a => a.DeepClone()).ToArray()),["replaced_agents"]=replaced, ["checked_at_utc"] = Iso(now),
            ["completeness"] = new JsonObject { ["state"] = sorted.Any(a => T(a["completeness"]?["state"]) == "known_gaps") ? "known_gaps" : "not_assessed" },
            ["connected_domain_controllers"] = connectedControllers.Count,
            ["active_agents"] = active.Length, ["current_agents"] = active.Count(a => T(a["state"]) == "current") };
    }
    internal static JsonArray ConsolidateDcSources(JsonArray items)
    {
        var replaced=new JsonArray();
        foreach(var group in items.OfType<JsonObject>().Where(a=>a["server_id"] is not null).GroupBy(a=>T(a["server_id"])).ToArray())
        {
            static Version VersionOf(JsonObject a) => Version.TryParse(T(a["agent_version"]),out var version) ? version : new Version(0,0,0);
            var current=group.Where(a=>T(a["status"])=="active").OrderByDescending(VersionOf).ThenByDescending(a=>Time(a["last_seen"])).ThenBy(a=>T(a["id"]),StringComparer.Ordinal).FirstOrDefault();
            if(current is not null)
            {
                current["duplicate_agents"]=group.Count(a=>T(a["status"])=="active");
                current["identity_conflict"]=group.Any(a=>T(a["status"])=="active" && B(a["identity_conflict"]));
                var checks=Array(current["modules"]).OfType<JsonObject>().SelectMany(m=>Array(m["channels"]).OfType<JsonObject>())
                    .Where(c=>T(c["state"]) is not ("paused" or "disabled")).ToArray();
                var prior=group.Where(a=>T(a["status"])=="replaced" && Time(a["last_packet_at"]) is not null && !B(a["identity_conflict"]))
                    .OrderByDescending(a=>Time(a["last_packet_at"])).ThenBy(a=>T(a["id"]),StringComparer.Ordinal).FirstOrDefault();
                if(T(current["connection"])=="online" && !B(current["identity_conflict"]) && checks.Length>0
                    && checks.All(c=>T(c["failure_reason"]) is "packet_missing" or "packet_stale") && prior is not null)
                    current["delivery_fallback"]=new JsonObject { ["agent_id"]=T(prior["id"]),["last_packet_at"]=prior["last_packet_at"]?.DeepClone(),
                        ["since"]=Iso(checks.Select(c=>Time(c["issue_since_utc"])).Max()),["can_restore"]=B(prior["can_restore"]) };

            }
            foreach(var row in group.Where(a=>T(a["status"])=="replaced"))
            {
                var retired=(JsonObject)row.DeepClone(); retired["replacement_version"]=current?["agent_version"]?.DeepClone();
                retired["replaced_by"]=current?["id"]?.DeepClone() ?? retired["replaced_by"]?.DeepClone();
                replaced.Add(retired); items.Remove(row);
            }
            if(current is not null)
                foreach(var duplicate in group.Where(a=>a!=current && T(a["status"])!="replaced").ToArray()) items.Remove(duplicate);
        }
        return replaced;
    }
    static string HumanName(string text) => text.Trim() is { Length: > 0 } name && name.ToLowerInvariant() is not ("localhost" or "unknown") && !Guid.TryParse(name, out _) ? name : "";
    static string ReportedName(string text) => text.Length is >= 1 and <= 253 && text.ToLowerInvariant() is not ("localhost" or "localhost.localdomain" or "unknown")
        && !InstallationPackages.Match(text, "[0-9]+(?:\\.[0-9]+){3}") && InstallationPackages.Match(text, "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*") && !Guid.TryParse(text, out _) ? text : "";
    public static JsonArray Bindings(JsonArray agents)
    {
        var result = new JsonArray();
        foreach (var agent in agents.OfType<JsonObject>())
        {
            bool enabled = T(agent["status"]) == "active" && T(agent["collection_policy"]?["state"]) is "" or "active";
            foreach (var assignment in Array(agent["assigned_modules"]).OfType<JsonObject>())
            {
                string module = T(assignment["module_id"]);
                if (module is not ("sli.windows.ad-dc" or "sli.ad-snapshot" or "sli.gpo-snapshot")) continue;
                var config = assignment["config"] as JsonObject ?? new();
                string source = T(config["source_name"]);
                if (source.Length == 0) source = Array(agent["source_bindings"]).OfType<JsonObject>().Where(b => T(b["module_id"]) == module).Select(b => T(b["source_name"])).FirstOrDefault() ?? "";
                if (source.Trim().Equals(T(agent["id"]), StringComparison.OrdinalIgnoreCase) || source.Trim().Equals(T(agent["host_id"]), StringComparison.OrdinalIgnoreCase)) source = "";
                result.Add(new JsonObject { ["agent_id"] = T(agent["id"]), ["module_id"] = module, ["source_name"] = module == "sli.windows.ad-dc" && source.Length > 0 ? source : null,
                    ["domain_dns"] = Snapshot(module) ? config["domain_dns"]?.DeepClone() : null, ["enabled"] = enabled && B(assignment["enabled"]) && !B(config["paused"]),
                    ["paused"] = T(agent["status"]) == "active" && B(assignment["enabled"]) && (!enabled || B(config["paused"])) });
            }
        }
        return result;
    }
}
