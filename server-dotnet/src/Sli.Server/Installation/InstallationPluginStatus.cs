using System.Globalization;
using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Agents.FileAudit;

namespace Sli.Server.InstallationSetup;

public sealed partial class InstallationService
{
    internal static (string State, DateTimeOffset? LastDataAt, DateTimeOffset? ErrorAt) DerivePluginStatus(
        bool enabled, bool hasSource, DateTimeOffset? latest, TimeSpan interval, DateTimeOffset? failure, DateTimeOffset now,
        bool hasCurrentHeartbeat = false)
    {
        if (!enabled) return ("disabled", null, null);
        if (failure is not null) return ("error", null, failure);
        if (!hasSource) return ("no_sources", null, null);
        if (latest is null) return ("waiting", null, null);
        return hasCurrentHeartbeat || now - latest <= interval ? ("working", latest, null) : ("error", null, latest + interval);
    }

    // The installation's configured flag controls admission. Agent assignments describe actual sources.
    private async Task<JsonArray?> PluginSourcesAsync(JsonArray items, CancellationToken ct)
    {
        string[] modules = items.OfType<JsonObject>()
            .SelectMany(item => PluginModules.GetValueOrDefault(Text(item["plugin_id"])) ?? [])
            .Concat(items.OfType<JsonObject>().Any(item => Text(item["plugin_id"]) == "sli.sigma") ? ["sli.windows.ad-dc"] : Array.Empty<string>())
            .Where(module => module is not ("sli.vpn-nps" or "sli.radius-accounting")).Distinct().ToArray();
        if (modules.Length == 0) return new JsonArray();
        try
        {
            var rows = await database.ReadAsync(s => s.QueryAsync("""
                select module, a.id as agent_id, a.collection_policy->>'interval_seconds' as interval_seconds,
                       m->'config'->'schedule'->'hours' as snapshot_hours,
                       m->'config'->>'capture_seconds' as capture_seconds,
                       case when module='sli.file-audit' and not check_only and a.file_audit->>'state' in ('blocked','failed')
                            then a.file_audit->>'reported_at' end as failure_at,
                       left(coalesce(nullif(btrim(a.registration_host_name), ''), nullif(btrim(m->'config'->>'source_name'), '')), 253) as source_name,
                       (not check_only and (module <> 'sli.file-audit' or (jsonb_typeof(m->'config'->'roots')='array'
                         and m->'config'->'roots' <> '[]'::jsonb)
                         or exists (select 1 from sli_agent_module_bindings b where b.agent_id=a.id and b.module_id=module))) is true as collects,
                       check_only, check_version, a.rights_probe->>'agent_version' as current_version
                from sli_agents a
                cross join lateral (
                    select m, false as check_only, null::text as check_version
                    from jsonb_array_elements(a.assigned_modules) m
                    union all
                    select jsonb_build_object('module_id','sli.file-audit','enabled',true,'config',a.file_audit#>'{request,config}'),
                           true, scope.value->>'agent_version'
                    from jsonb_each(case when jsonb_typeof(a.file_audit->'scopes')='object'
                                         then a.file_audit->'scopes' else '{}'::jsonb end) scope
                    where 'sli.file-audit'=any(@p0)
                      and a.file_audit#>>'{request,command,action}'='check'
                      and a.file_audit#>>'{request,config,source_kind}'='server'
                      and scope.value->>'state'='failed' and scope.value->>'reason_code'='native_unavailable'
                ) sources
                cross join lateral (select coalesce(m->>'module_id',m#>>'{}') as module) assigned
                where a.status='active' and module=any(@p0)
                  and (jsonb_typeof(m)='string' or m->'enabled'='true'::jsonb)
                """, ct, (object)modules), ct);
            // A server can send a check result before an audit collection assignment exists.
            for (int index = rows.Count - 1; index >= 0; index--)
            {
                if (rows[index] is not JsonObject row || !Bool(row["check_only"])) continue;
                var current = FileAuditResult.ReportedAgentVersion(Text(row["current_version"]));
                var checkedWith = FileAuditResult.ReportedAgentVersion(Text(row["check_version"])) ?? current;
                var requirement = FileAuditResult.CheckAgentRequirement(checkedWith);
                if (current >= FileAuditResult.MinimumNativeCheckVersion || requirement is null)
                    rows.RemoveAt(index);
                else
                    row["check_agent_requirement"] = requirement;
            }
            return rows;
        }
        catch (Exception e) when (e is NpgsqlException or TimeoutException or InvalidOperationException)
        { return null; }
    }

    private async Task<JsonArray?> RadiusStatusSourcesAsync(CancellationToken ct)
    {
        try
        {
            return await database.ReadAsync(s => s.QueryAsync("""
                select distinct source_instance_id, left(source_display_name, 253) as source_name
                from public.radius_vpn_operations_v1
                where source_activation='manual_enabled' and subscription_activation='manual_enabled'
                order by source_name, source_instance_id
                """, ct), ct);
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
                        'interval_seconds',expected_interval_seconds::text, 'heartbeat_at',heartbeat_at, 'status',status)
                     from runtime_worker_heartbeats where worker_name='semantic' and details_json->>'manual_runtime'='false') as telemetry
                """, ct)), ct);
        }
        catch (Exception e) when (e is NpgsqlException or TimeoutException or InvalidOperationException)
        { return null; }
    }

    private static JsonObject PluginPresentation(JsonObject item, JsonObject receipts,
        IReadOnlyDictionary<string, JsonObject> moduleReceipts, JsonArray? sources, JsonArray? radius, JsonObject? sigma, DateTimeOffset now)
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
        if (remote && radius is not null)
        {
            item["source_count"] = radius.Count;
            item["source_names"] = new JsonArray(radius.OfType<JsonObject>().Select(row => Text(row["source_name"]))
                .Where(name => name.Length > 0).Select(name => (JsonNode?)JsonValue.Create(name)).ToArray());
        }
        var failed = collecting.Where(row => StatusTime(row["failure_at"], now) is not null)
            .MaxBy(row => StatusTime(row["failure_at"], now));
        var telemetry = sigma?["telemetry"] as JsonObject;
        bool hasSource = remote ? radius?.Count > 0 : sigmaPlugin
            ? Bool(sigma?["has_source"]) || sources?.OfType<JsonObject>().Any(row => Text(row["module"]) == "sli.windows.ad-dc") == true
            : collecting.Length > 0;
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
        bool unavailable = (agentBacked || sigmaPlugin) && sources is null || sigmaPlugin && sigma is null || remote && radius is null
            || hasSource && Text(receipts["state"]) == "unavailable" && observation.At is null;
        var failure = StatusTime(failed?["failure_at"], now) ?? (hasSource ? StatusTime(telemetry?["failure_at"], now) : null)
            ?? (unavailable ? now : (DateTimeOffset?)null);
        // Sigma can poll successfully without consuming a match for an extended period.
        bool hasCurrentSigmaHeartbeat = telemetry is not null && Text(telemetry["status"]) is "running" or "idle"
            && StatusTime(telemetry["heartbeat_at"], now) is DateTimeOffset heartbeatAt
            && now - heartbeatAt <= SourceInterval(telemetry);
        var status = DerivePluginStatus(enabled, hasSource, observation.At, observation.Interval, failure, now,
            hasCurrentHeartbeat: hasCurrentSigmaHeartbeat);

        var outdated = enabled && id == "sli.file-audit" ? assigned
            .Where(row => row["check_agent_requirement"] is JsonObject)
            .OrderBy(row => Text(row["source_name"]), StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault() : null;
        if (outdated is not null)
            return new JsonObject
            {
                ["state"] = "error",
                ["reason"] = "outdated_agent",
                ["next_action"] = null,
                ["last_data_at"] = status.LastDataAt?.ToString("O", CultureInfo.InvariantCulture),
                ["error_at"] = null,
                ["error_object"] = outdated["source_name"]?.DeepClone(),
                ["check_agent_requirement"] = outdated["check_agent_requirement"]?.DeepClone()
            };

        if (status.State == "error" && failure is null && collecting.Select(row => Text(row["agent_id"])).Distinct().Count() == 1)
            failed = collecting.FirstOrDefault(row => Text(row["source_name"]).Length > 0);

        string reason = status.State switch
        {
            "no_sources" when id == "sli.file-audit" && assigned.Length > 0 => "no_folders",
            "error" when unavailable => "status_unavailable",
            "error" when failure is null => "collection_delayed",
            "error" => "collection_failed",
            _ => status.State
        };
        string? action = reason switch
        {
            "no_folders" => "select_file_folders",
            "no_sources" => id switch
            {
                "sli.file-audit" => "connect_file_server",
                "sli.workstations" => "install_workstation_agent",
                "sli.remote-access" => "connect_nps",
                "sli.sigma" => "connect_sigma_events",
                _ => "connect_domain_controller"
            },
            "waiting" => "check_first_delivery",
            "collection_delayed" or "collection_failed" => "check_collection",
            "status_unavailable" => "reload_status",
            _ => null
        };
        return new JsonObject
        {
            ["state"] = status.State,
            ["reason"] = reason,
            ["next_action"] = action,
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
