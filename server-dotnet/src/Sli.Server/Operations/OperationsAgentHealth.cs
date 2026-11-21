using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Operations;

public sealed partial class OperationsService
{
    static bool Snapshot(string module) => module is "sli.ad-snapshot" or "sli.gpo-snapshot";
    internal static string?[] Channels(string module, JsonObject config)
    {
        if (Snapshot(module)) return [null];
        if (module == "sli.windows.ad-dc") return new[] { "Security", "System", "Directory Service" }.Where(c => config["channels"]?[c] is null || B(config["channels"]?[c])).ToArray();
        if (module is "sli.vpn-nps" or "sli.radius-accounting")
        {
            if (config["families"]?[module == "sli.vpn-nps" ? "nps" : "radius_accounting"] is JsonValue enabled && !B(enabled)) return [];
            return [module == "sli.vpn-nps" ? "Security" : "radius-accounting"];
        }
        if (module == "sli.file-audit") return ["Security"];
        if (module == "sli.windows-eventlog" && S(config["channel"]).Length > 0) return [S(config["channel"])];
        if (module == "sli.workstations")
        {
            bool Family(string key) => config["families"]?[key] is null || B(config["families"]?[key]);
            var channels = new List<string>();
            if (new[] { "logons", "processes", "usb", "local_admins", "protection" }.Any(Family)) channels.Add("Security");
            if (Family("protection")) { channels.Add("System"); channels.Add("Microsoft-Windows-Windows Defender/Operational"); channels.Add("Microsoft-Windows-TaskScheduler/Operational"); }
            if (Family("usb")) { channels.Add("Microsoft-Windows-DriverFrameworks-UserMode/Operational"); channels.Add("Microsoft-Windows-Kernel-PnP/Configuration"); }
            if (Family("protection")) channels.Add("Microsoft-Windows-PowerShell/Operational");
            return channels.ToArray();
        }
        return [];
    }
    internal async Task<JsonObject> AgentHealthAsync(CancellationToken ct)
    {
        try
        {
            var agents = await queries.ReadAsync(OperationsSql.Agents, ct); var requested = new JsonArray();
            foreach (var agent in agents.OfType<JsonObject>()) foreach (var assignment in (agent["assigned_modules"] as JsonArray ?? []).OfType<JsonObject>().Where(a => B(a["enabled"])))
            {
                string module = S(assignment["module_id"]); var config = assignment["config"] as JsonObject ?? new();
                foreach (string? channel in Channels(module, config)) requested.Add(new JsonObject { ["agent_id"] = Copy(agent["id"]), ["module_id"] = module, ["revision"] = S(config["policy_revision"], "1"), ["channel"] = channel, ["snapshot"] = Snapshot(module) });
            }
            JsonArray streams = []; JsonObject? failure = null;
            try { if (requested.Count > 0) streams = await queries.ReadAsync(OperationsSql.Streams, ct, ("requested", requested.ToJsonString())); }
            catch (Exception e) when (!ct.IsCancellationRequested) { failure = StreamFailure(e); }
            var result = AgentView(agents, streams, Now, failure is null);
            if (failure is not null) result["diagnostics"] = failure;
            return result;
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        { return new() { ["state"] = "unavailable", ["items"] = new JsonArray(), ["active_agents"] = 0, ["current_agents"] = 0, ["completeness"] = new JsonObject { ["state"] = "not_assessed" }, ["checked_at_utc"] = Generated }; }
    }
    internal static JsonObject StreamFailure(Exception error)
    {
        // A fixed database code distinguishes timeout, missing schema and denied
        // reads without exposing SQL, parameters, paths or exception messages.
        string? sqlstate = error is Npgsql.PostgresException pg && System.Text.RegularExpressions.Regex.IsMatch(pg.SqlState, "\\A[0-9A-Z]{5}\\z") ? pg.SqlState : null;
        return new() { ["state"] = "unavailable", ["reason"] = error is TimeoutException || error is Npgsql.NpgsqlException { InnerException: TimeoutException } || sqlstate == "57014" ? "timeout" : "read_failed", ["sqlstate"] = sqlstate };
    }
    internal static JsonObject AgentView(JsonArray agents, JsonArray streams, DateTimeOffset now, bool diagnostics = true)
    {
        long? Age(JsonNode? n) => Time(n) is {} t ? Math.Max(0, (long)(now - t).TotalSeconds) : null;
        var items = new JsonArray();
        foreach (var agent in agents.OfType<JsonObject>())
        {
            var policy = agent["collection_policy"] as JsonObject ?? new();
            bool enabled = S(agent["status"]) == "active" && S(policy["state"], "active") == "active", applied = N(agent["policy_revision"]) == N(agent["applied_policy_revision"]) && S(agent["applied_collection_state"]) == "active";
            long interval = N(policy["interval_seconds"], 60); long? connectionAge = Age(agent["last_seen"]);
            string connection = connectionAge is null ? "never_seen" : connectionAge <= Math.Max(300, interval * 3) ? "online" : "offline";
            var modules = new JsonArray(); var domains = new SortedSet<string>(); if (S(agent["domain"]) is { Length: > 0 } domain) domains.Add(domain);
            foreach (var assignment in (agent["assigned_modules"] as JsonArray ?? []).OfType<JsonObject>().Where(a => B(a["enabled"])))
            {
                string module = S(assignment["module_id"]); var config = assignment["config"] as JsonObject ?? new();
                if (S(config["domain_dns"]) is { Length: > 0 } d) domains.Add(d);
                var channels = Channels(module, config); bool moduleEnabled = enabled && !B(config["paused"]);
                long budget = Math.Max(900, interval * Math.Max(1, channels.Length) * 3);
                if (Snapshot(module))
                {
                    var hours = (config["schedule"]?["hours"] as JsonArray ?? new JsonArray(6, 18)).Select(n => N(n)).ToArray();
                    budget = hours.Zip(hours.Skip(1).Append(hours[0] + 24), (a, b) => b - a).Max() * 3600 + N(config["capture_seconds"], 300) + 900;
                }
                var checks = new JsonArray();
                foreach (string? channel in channels)
                {
                    var stream = streams.OfType<JsonObject>().FirstOrDefault(r => S(r["agent_id"]) == S(agent["id"]) && S(r["module_id"]) == module && S(r["revision"]) == S(config["policy_revision"], "1") && S(r["channel"]) == (channel ?? "")) ?? new();
                    long? age = Age(stream["last_packet_at"]), pending = Age(stream["pending_since"]), grace = Age(agent["policy_applied_at"] ?? agent["created_at"]);
                    var graceStart = Time(agent["policy_applied_at"] ?? agent["created_at"]); DateTimeOffset? graceDeadline = graceStart?.AddSeconds(budget);
                    long importBudget = 900 + (Snapshot(module) ? N(config["capture_seconds"], 300) : 0);
                    string state = S(agent["status"]) == "active" && !moduleEnabled ? "paused" : !enabled ? "disabled" : "waiting";
                    string? failure = null; DateTimeOffset? since = null, observed = null;
                    if (moduleEnabled && !diagnostics) state = "unknown";
                    else if (moduleEnabled && stream["import_failure_reason"] is not null)
                    { state = "error"; failure = "import_rejected"; observed = Time(stream["import_failure_at"]); }
                    else if (moduleEnabled && (applied || connection != "online" && grace > budget))
                    {
                        if (B(stream["read_error"])) { state = "error"; failure = "read_error"; var receipt = Time(stream["last_packet_at"]); observed = receipt <= now ? receipt : null; }
                        else if (pending > importBudget) { state = "error"; failure = "import_overdue"; since = Time(stream["pending_since"])?.AddSeconds(importBudget); }
                        else if (age is null) { state = grace > budget ? "error" : "waiting"; if (state == "error") { failure = "packet_missing"; since = graceDeadline; } }
                        else if (age > budget)
                        {
                            state = grace <= budget ? "waiting" : "error";
                            if (state == "error") { failure = "packet_stale"; since = Time(stream["last_packet_at"])?.AddSeconds(budget); if (graceDeadline > since) since = graceDeadline; }
                        }
                        else if (Age(stream["last_import_at"]) > budget) { state = "error"; failure = "import_overdue"; since = Time(stream["last_import_at"])?.AddSeconds(budget); }
                        else state = SetupCollectionHealth.FreshStreamState(pending,
                            module == "sli.file-audit" && stream["read_error"] is null, stream["last_import_at"] is not null);
                    }
                    if (since is not null) { if (!applied && graceDeadline > since) since = graceDeadline; observed = now; }
                    long? lag = pending;
                    if (lag is null && Time(stream["last_packet_at"]) is {} packet && Time(stream["last_import_at"]) is {} imported) lag = Math.Max(0, (long)(imported - packet).TotalSeconds);
                    var check = new JsonObject { ["channel"] = channel, ["state"] = state, ["failure_reason"] = failure, ["issue_since_utc"] = since is {} s ? Stamp(s) : null, ["issue_observed_at_utc"] = observed is {} o ? Stamp(o) : null,
                        ["last_packet_at"] = Copy(stream["last_packet_at"]), ["last_import_at"] = Copy(stream["last_import_at"]), ["import_lag_seconds"] = lag, ["budget_seconds"] = budget };
                    if (diagnostics) {
                        check["historical_unimported_packets"] = N(stream["historical_unimported_packets"]); check["historical_error_at"] = Copy(stream["historical_error_at"]);
                        check["import_failure_reason"] = Copy(stream["import_failure_reason"]); check["import_failure_at"] = Copy(stream["import_failure_at"]);
                    }
                    checks.Add(check);
                }
                modules.Add(new JsonObject { ["module_id"] = module, ["channels"] = checks });
            }
            var activeChecks = modules.OfType<JsonObject>().SelectMany(m => m["channels"]!.AsArray()).OfType<JsonObject>().Where(c => S(c["state"]) is not ("paused" or "disabled")).ToArray();
            bool Has(string state) => activeChecks.Any(c => S(c["state"]) == state);
            string stateAgent = S(agent["status"]) != "active" ? "disabled" : !enabled ? "paused" : !diagnostics ? "unknown" : Has("error") ? "error" : !applied || activeChecks.Length == 0 ? "waiting" : activeChecks.All(c => S(c["state"]) == "current") ? "current" : Has("waiting") ? "waiting" : "unknown";
            string name = S(agent["canonical_host_name"],S(agent["host_name"], S(agent["registration_host_name"])));
            if (name.Length == 0) name = (agent["assigned_modules"] as JsonArray ?? []).OfType<JsonObject>().Where(a => S(a["module_id"]) == "sli.windows.ad-dc").Select(a => S(a["config"]?["source_name"]).Trim()).FirstOrDefault() ?? "";
            if (name == S(agent["id"]) || name == S(agent["host_id"]) || Guid.TryParse(name, out _)) name = "";
            if(agent["server_id"] is null) name = string.Join(" · ", new[] { name, S(agent["instance_name"]) }.Where(s => s.Length > 0));
            items.Add(new JsonObject { ["id"] = Copy(agent["id"]), ["host_id"] = Copy(agent["host_id"]), ["name"] = name, ["domains"] = new JsonArray(domains.Select(d => JsonValue.Create(d)).ToArray()), ["state"] = stateAgent, ["connection"] = connection,
                ["server_id"]=Copy(agent["server_id"]),["status"]=Copy(agent["status"]),["agent_version"]=Copy(agent["agent_version"]),["replaced_by"]=Copy(agent["replaced_by"]),["identity_conflict"]=B(agent["identity_conflict"]),
                ["data_gaps"] = SetupCollectionHealth.DataGaps(agent["packet_expiry"]),
                ["windows_audit"] = N(agent["windows_audit"]?["policy_revision"], -1) == N(agent["policy_revision"]) ? Copy(agent["windows_audit"]) : null,
                ["completeness"] = new JsonObject { ["state"] = agent["last_accepted_gap_at"] is null ? "not_assessed" : "known_gaps", ["last_accepted_gap_at"] = Copy(agent["last_accepted_gap_at"]) },
                ["last_seen"] = Copy(agent["last_seen"]), ["last_packet_at"] = Copy(agent["last_packet_at"]) ?? activeChecks.Select(c => S(c["last_packet_at"])).Where(s => s.Length > 0).Order().LastOrDefault(),
                ["modules"] = modules, ["policy_revision"] = Copy(agent["policy_revision"]), ["applied_policy_revision"] = Copy(agent["applied_policy_revision"]), ["href"] = "/app/agents?agent_id=" + S(agent["id"]) + "#agent-" + S(agent["id"]) });
        }
        var replaced=SetupCollectionHealth.ConsolidateDcSources(items);
        var active = items.OfType<JsonObject>().Where(i => S(i["state"]) is not ("paused" or "disabled")).ToArray();
        return new() { ["state"] = active.Any(i => S(i["state"]) == "error") ? "error" : active.Length > 0 && active.All(i => S(i["state"]) == "current") ? "current" : active.Length > 0 ? "partial" : "unknown",
            ["items"] = A(items.OfType<JsonObject>().OrderBy(i => i["domains"]!.ToJsonString()).ThenBy(i => S(i["name"])).ThenBy(i => S(i["id"]))),["replaced_agents"]=replaced, ["checked_at_utc"] = Stamp(now), ["active_agents"] = active.Length,
            ["current_agents"] = active.Count(i => S(i["state"]) == "current"), ["completeness"] = new JsonObject { ["state"] = items.Any(i => S(i?["completeness"]?["state"]) == "known_gaps") ? "known_gaps" : "not_assessed" } };
    }
}
