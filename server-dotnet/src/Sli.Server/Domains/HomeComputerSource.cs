using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Domains;

// The retained collector document must pass the source's schema and state gates before it overrides inventory.
internal static class HomeComputerSource
{
    private static readonly string[] Metadata = ["snapshot_id", "label", "started_at", "completed_at", "query_dc", "domain", "search_base", "collection_status", "object_count", "collector_version", "sources", "errors"];
    private static readonly string[] ObjectFields = ["id", "objectGuid", "name", "dnsHostName", "enabled", "deviceType", "classification", "ipv4s", "ipv6s", "osName", "osVersion", "osBuild", "osFamily", "servicePack", "ou", "distinguishedName", "canonicalName", "domain", "adSite", "lastLogonTimestamp", "exactLastLogon", "eventLastSeen", "passwordLastSet", "whenCreated", "whenChanged", "description", "location", "managedBy", "sid", "userAccountControl", "spns", "trustedForDelegation", "trustedToAuthForDelegation", "roleHint", "roleEvidence", "collectedAt", "queryDc", "collectorVersion", "sources", "collectionErrors"];
    private static readonly string[] SourceNames = ["ad", "dns", "os", "site", "last_logon_timestamp", "exact_last_logon", "dc_events"];
    private static readonly HashSet<string> Statuses = ["observed", "not_collected", "not_evaluated", "missing_in_source", "no_record", "partial", "failed", "access_denied", "parse_error", "not_applicable"];
    private static bool Timestamp(JsonNode? node) => node is JsonValue v && v.TryGetValue<string>(out var text)
        && Regex.IsMatch(text, @"(?:Z|[+-]\d\d:\d\d)$") && DateTimeOffset.TryParse(text, out _);
    internal static bool Valid(JsonObject payload)
    {
        if (payload["schema_version"]?.ToString() != "2.0" || payload["metadata"] is not JsonObject metadata
            || Metadata.Any(k => !metadata.ContainsKey(k)) || !Timestamp(metadata["started_at"]) || !Timestamp(metadata["completed_at"])
            || metadata.Stamp("completed_at") < metadata.Stamp("started_at") || payload["objects"] is not JsonArray objects
            || objects.Count > 250000 || metadata["object_count"]?.GetValueKind() != JsonValueKind.Number || metadata.Number("object_count") != objects.Count
            || !Guid.TryParse(metadata.Text("snapshot_id"), out _) || metadata.Text("collection_status") is not ("complete" or "partial" or "failed")
            || new[] { "query_dc", "domain", "collector_version" }.Any(k => string.IsNullOrWhiteSpace(metadata.Text(k)))
            || metadata["sources"] is not JsonArray stages) return false;
        var provenance = string.Join(" ", new[] { "snapshot_id", "label", "collector_version" }.Select(metadata.Text)).ToLowerInvariant();
        if (provenance.Contains("demo") || provenance.Contains("пример")) return false;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var stage in stages)
        {
            var name = stage.Text("name");
            if (string.IsNullOrEmpty(name) || !names.Add(name) || !Statuses.Contains(stage.Text("status") ?? "")
                || stage.Boolean("requested") is null) return false;
        }
        if (objects.Count > 0 && SourceNames.Any(s => !names.Contains(s))) return false;
        var ad = stages.FirstOrDefault(s => s.Text("name") == "ad");
        if (metadata.Text("collection_status") == "failed")
        { if (objects.Count != 0 || ad.Text("status") == "observed") return false; }
        else if (ad.Text("status") != "observed") return false;
        var events = stages.FirstOrDefault(s => s.Text("name") == "dc_events");
        if (objects.Count > 0 && (events.Text("status") != "not_collected" || events.Boolean("requested") != false)) return false;
        var guids = new HashSet<Guid>();
        foreach (var raw in objects)
        {
            if (raw is not JsonObject item || ObjectFields.Any(k => !item.ContainsKey(k))
                || !Guid.TryParse(item.Text("id"), out var id) || !Guid.TryParse(item.Text("objectGuid"), out var guid) || id != guid || !guids.Add(id)
                || item["sources"] is not JsonObject sources || SourceNames.Any(k => !sources.ContainsKey(k))
                || sources["ad"].Text("status") != "observed" || sources["dc_events"].Text("status") != "not_collected") return false;
            foreach (var (name, rawState) in sources)
            {
                if (rawState is not JsonObject state || new[] { "status", "source", "value", "observed_at", "error", "details" }.Any(k => !state.ContainsKey(k))
                    || state.Text("source") != name || !Statuses.Contains(state.Text("status") ?? "")) return false;
                var status = state.Text("status"); var observed = state["observed_at"];
                if ((status is "observed" or "missing_in_source" or "no_record" or "partial" or "failed" or "access_denied" or "parse_error") && !Timestamp(observed)) return false;
                if (observed is not null && !Timestamp(observed)) return false;
                if (status == "not_collected" && (state["value"] is not null || observed is not null)) return false;
                if (status is "not_evaluated" or "partial" && state["details"] is null) return false;
                if (status is "failed" or "access_denied" or "parse_error" && !Sli.Server.Agents.SnapshotPublication.GpoGovernanceSettings.IsTruthy(state["error"])) return false;
            }
        }
        return true;
    }
}
