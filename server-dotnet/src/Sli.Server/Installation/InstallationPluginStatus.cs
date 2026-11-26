using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService
{
    internal static (string State, DateTimeOffset? LastDataAt, DateTimeOffset? ErrorAt) DerivePluginStatus(
        bool enabled, bool hasSource, DateTimeOffset? latest, TimeSpan interval, DateTimeOffset? failure, DateTimeOffset now)
    {
        if (!enabled) return ("disabled", null, null);
        if (failure is not null) return ("error", null, failure);
        if (!hasSource) return ("no_sources", null, null);
        if (latest is null) return ("waiting", null, null);
        return now - latest <= interval ? ("working", latest, null) : ("error", null, latest + interval);
    }

    // The installation's configured flag controls admission. Agent assignments describe actual sources.
    private async Task<JsonArray?> PluginSourcesAsync(JsonArray items, CancellationToken ct)
    {
        string[] modules = items.OfType<JsonObject>()
            .SelectMany(item => PluginModules.GetValueOrDefault(Text(item["plugin_id"])) ?? [])
            .Where(module => module is not ("sli.vpn-nps" or "sli.radius-accounting")).Distinct().ToArray();
        if (modules.Length == 0) return new JsonArray();
        try
        {
            return await database.ReadAsync(s => s.QueryAsync("""
                select module, a.id as agent_id, a.collection_policy->>'interval_seconds' as interval_seconds,
                       m->'config'->'schedule'->'hours' as snapshot_hours,
                       m->'config'->>'capture_seconds' as capture_seconds,
                       case when module='sli.file-audit' and a.file_audit->>'state' in ('blocked','failed')
                            then a.file_audit->>'reported_at' end as failure_at,
                       left(coalesce(nullif(btrim(a.registration_host_name), ''), nullif(btrim(m->'config'->>'source_name'), '')), 253) as source_name,
                       (module <> 'sli.file-audit' or (jsonb_typeof(m->'config'->'roots')='array'
                         and m->'config'->'roots' <> '[]'::jsonb)
                         or exists (select 1 from sli_agent_module_bindings b where b.agent_id=a.id and b.module_id=module)) is true as collects
                from sli_agents a
                cross join lateral jsonb_array_elements(a.assigned_modules) m
                cross join lateral (select coalesce(m->>'module_id',m#>>'{}') as module) assigned
                where a.status='active' and module=any(@p0)
                  and (jsonb_typeof(m)='string' or m->'enabled'='true'::jsonb)
                """, ct, (object)modules), ct);
        }
        catch (Exception e) when (e is NpgsqlException or TimeoutException or InvalidOperationException)
        { return null; }
    }

    private async Task<JsonObject?> SigmaStatusAsync(CancellationToken ct)
    {
        try
        {
            return await database.ReadAsync(async s => First(await s.QueryAsync("""
                select exists (select 1 from semantic_risk_policies p join semantic_policy_admission a using(policy_id,policy_version)
                    where p.source_kind='detection_match' and a.enabled
                      and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled'
                      and jsonb_typeof(p.definition_json#>'{source_selector,execution,scope}')='object') as has_source,
                    (select jsonb_build_object('last_data_at',coalesce(details_json->>'sigma_last_data_at',details_json#>>'{result,sigma,last_data_at}'),
                        'failure_at',coalesce(details_json->>'sigma_failure_at',details_json#>>'{result,sigma,failure_at}'),
                        'interval_seconds',expected_interval_seconds::text)
                     from runtime_worker_heartbeats where worker_name='semantic' and details_json->>'manual_runtime'='false') as telemetry
                """, ct)), ct);
        }
        catch (Exception e) when (e is NpgsqlException or TimeoutException or InvalidOperationException)
        { return null; }
    }

    private static JsonObject PluginPresentation(JsonObject item, JsonObject receipts,
        IReadOnlyDictionary<string, JsonObject> moduleReceipts, JsonArray? sources, JsonObject? sigma, DateTimeOffset now)
    {
        string id = Text(item["plugin_id"]);
        bool enabled = Bool(item["enabled"]);
        bool remote = id == "sli.remote-access";
        bool sigmaPlugin = id == "sli.sigma";
        bool agentBacked = PluginModules.TryGetValue(id, out var modules) && !remote;
        var assigned = agentBacked ? sources?.OfType<JsonObject>()
            .Where(row => modules!.Contains(Text(row["module"]))).ToArray() ?? [] : [];
        var collecting = assigned.Where(row => Bool(row["collects"])).ToArray();
        if (agentBacked && sources is not null)
        {
            var agents = (id == "sli.file-audit" ? assigned : collecting).GroupBy(row => Text(row["agent_id"])).ToArray();
            item["source_count"] = agents.Length;
            item["source_names"] = new JsonArray(agents.Select(group => group.Select(row => Text(row["source_name"]))
                .FirstOrDefault(name => name.Length > 0)).Where(name => name is not null)
                .Order(StringComparer.OrdinalIgnoreCase).Select(name => (JsonNode?)JsonValue.Create(name)).ToArray());
        }
        var failed = collecting.Where(row => StatusTime(row["failure_at"], now) is not null)
            .MaxBy(row => StatusTime(row["failure_at"], now));
        var telemetry = sigma?["telemetry"] as JsonObject;
        bool hasSource = remote ? Bool(item["configured"]) : sigmaPlugin ? Bool(sigma?["has_source"]) : collecting.Length > 0;
        // Use the cadence of the module that produced each timestamp. A snapshot's
        // schedule must never make a stale event stream appear current.
        var evidence = collecting.Select(source =>
            (At: EvidenceTime(moduleReceipts.GetValueOrDefault(Text(source["module"])),
                       source["snapshot_hours"] is JsonArray, now), Interval: SourceInterval(source))).ToArray();
        if (remote)
            evidence = [(EvidenceTime(receipts, false, now) ?? StatusTime(item["last_data_at_utc"], now), TimeSpan.FromMinutes(10))];
        if (sigmaPlugin && telemetry is not null)
            evidence = [(StatusTime(telemetry["last_data_at"], now), SourceInterval(telemetry))];
        var observation = evidence.Where(value => value.At is not null)
            .OrderByDescending(value => now - value.At <= value.Interval)
            .ThenByDescending(value => now - value.At <= value.Interval ? value.At : value.At + value.Interval)
            .FirstOrDefault();
        bool unavailable = agentBacked && sources is null || sigmaPlugin && sigma is null
            || hasSource && Text(receipts["state"]) == "unavailable" && observation.At is null;
        var failure = StatusTime(failed?["failure_at"], now) ?? (hasSource ? StatusTime(telemetry?["failure_at"], now) : null)
            ?? (unavailable ? now : (DateTimeOffset?)null);
        var status = DerivePluginStatus(enabled, hasSource, observation.At, observation.Interval, failure, now);

        if (status.State == "error" && failure is null && collecting.Select(row => Text(row["agent_id"])).Distinct().Count() == 1)
            failed = collecting.FirstOrDefault(row => Text(row["source_name"]).Length > 0);

        return new JsonObject
        {
            ["state"] = status.State,
            ["last_data_at"] = status.LastDataAt?.ToString("O", CultureInfo.InvariantCulture),
            ["error_at"] = status.ErrorAt?.ToString("O", CultureInfo.InvariantCulture),
            ["error_object"] = status.State == "error" ? failed?["source_name"]?.DeepClone() : null
        };
    }

    private static DateTimeOffset? StatusTime(JsonNode? value, DateTimeOffset now) =>
        DateTimeOffset.TryParse(Text(value), CultureInfo.InvariantCulture, DateTimeStyles.None, out var time) && time <= now ? time : null;

    private static DateTimeOffset? EvidenceTime(JsonObject? row, bool snapshot, DateTimeOffset now) =>
        new[] { StatusTime(row?["last_imported_at"], now), StatusTime(row?[snapshot ? "last_snapshot_completed_at" : "last_received_at"], now) }.Max();

    private static TimeSpan SourceInterval(JsonObject source)
    {
        if (source["snapshot_hours"] is JsonArray { Count: > 0 } hours)
        {
            var sorted = hours.Select(hour => (int)Number(hour)).Order().ToArray();
            int longestGap = sorted.Zip(sorted.Skip(1).Append(sorted[0] + 24), (hour, next) => next - hour).Max();
            int.TryParse(Text(source["capture_seconds"]), out int capture);
            return TimeSpan.FromHours(longestGap) + TimeSpan.FromSeconds(capture);
        }
        return TimeSpan.FromSeconds(SetupCollectionHealth.ContactBudgetSeconds(
            long.TryParse(Text(source["interval_seconds"]), out long interval) ? interval : 60));
    }
}
