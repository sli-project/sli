using System.Globalization;
using System.Text.Json.Nodes;
namespace Sli.Server.Entities;
internal static class WhatWhereWhenSnapshots
{
    static string T(JsonObject value, string key) => EntityReader.Text(value, key);
    static void Require(bool ok, string code) { if (!ok) throw new InvalidDataException(code); }
    static JsonObject Object(JsonNode? value, string path) => value as JsonObject ?? throw new InvalidDataException("mapping_required:" + path);
    internal static DateTimeOffset Instant(JsonNode? node, string path)
    {
        string text = node?.ToString() ?? "";
        Require(DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var stamp), "timestamp_invalid:" + path);
        Require(text.Contains('T') && (text.EndsWith('Z') || text.LastIndexOf('+') > 9 || text.LastIndexOf('-') > 9), "timestamp_timezone_required:" + path);
        return stamp.ToUniversalTime();
    }
    internal static JsonObject Validate(JsonObject snapshot)
    {
        Require(T(snapshot, "schema_version") == "2.0", "unsupported_schema_version");
        var meta = Object(snapshot["metadata"], "metadata");
        Require(REQUIRED_METADATA_FIELDS.All(meta.ContainsKey), "metadata_fields_missing");
        Require(Instant(meta["completed_at"], "metadata.completed_at") >= Instant(meta["started_at"], "metadata.started_at"), "snapshot_time_window_invalid");
        var objects = snapshot["objects"] as JsonArray ?? throw new InvalidDataException("objects_must_be_array");
        string provenance = string.Join(' ', new[] { T(meta, "snapshot_id"), T(meta, "label"), T(meta, "collector_version") }).ToLowerInvariant();
        Require(!provenance.Contains("demo", StringComparison.Ordinal) && !provenance.Contains("пример", StringComparison.Ordinal), "demo_source_snapshot_forbidden");
        Require(Guid.TryParse(T(meta, "snapshot_id"), out _), "snapshot_id_invalid");
        string collection = T(meta, "collection_status"); Require(collection is "complete" or "partial" or "failed", "collection_status_invalid");
        foreach (string key in new[] { "query_dc", "domain", "collector_version" }) Require(T(meta, key).Trim().Length > 0, "metadata_" + key + "_required");
        var stages = meta["sources"] as JsonArray ?? throw new InvalidDataException("metadata_sources_must_be_array");
        var names = new HashSet<string>(); var statuses = new Dictionary<string, string>(); var requested = new Dictionary<string, bool>();
        foreach (var raw in stages)
        {
            var stage = Object(raw, "metadata.sources"); string name = T(stage, "name"), status = T(stage, "status");
            Require(stage.ContainsKey("name") && stage.ContainsKey("status") && stage.ContainsKey("requested"), "metadata_source_fields_missing");
            Require(name.Length > 0 && names.Add(name), "metadata_source_name_duplicate");
            Require(SOURCE_STATUS_MEANINGS.Contains(status), "metadata_source_status_invalid");
            Require(stage["requested"] is JsonValue value && value.TryGetValue<bool>(out _), "metadata_source_requested_invalid");
            statuses[name] = status; requested[name] = stage["requested"]!.GetValue<bool>();
        }
        Require(meta["object_count"] is JsonValue countValue && countValue.TryGetValue<int>(out _), "object_count_must_be_integer");
        int count = meta["object_count"]!.GetValue<int>();
        Require(count == objects.Count, "object_count_mismatch"); Require(count is >= 0 and <= 250000, "object_count_out_of_bounds");
        Require(count == 0 || REQUIRED_SOURCE_NAMES.All(names.Contains), "metadata_required_sources_missing");
        Require(collection == "failed" ? count == 0 && statuses.GetValueOrDefault("ad") != "observed" : statuses.GetValueOrDefault("ad") == "observed", collection == "failed" ? "failed_base_ad_snapshot_invalid" : "base_ad_stage_not_observed");
        Require(count == 0 || statuses.GetValueOrDefault("dc_events") == "not_collected" && requested.GetValueOrDefault("dc_events") == false, "dc_events_stage_must_remain_not_collected");
        var seen = new HashSet<Guid>();
        for (int i = 0; i < objects.Count; i++)
        {
            var item = Object(objects[i], $"objects[{i}]");
            Require(REQUIRED_OBJECT_FIELDS.All(item.ContainsKey), "object_fields_missing:" + i);
            Require(Guid.TryParse(T(item, "id"), out var id) && Guid.TryParse(T(item, "objectGuid"), out _), "object_stable_identity_invalid:" + i);
            Require(id == Guid.Parse(T(item, "objectGuid")), "object_stable_identity_mismatch:" + i); Require(seen.Add(id), "object_stable_identity_duplicate:" + id);
            var sources = Object(item["sources"], $"objects[{i}].sources");
            Require(REQUIRED_SOURCE_NAMES.All(sources.ContainsKey), "object_required_sources_missing:" + i);
            Require(sources["ad"]?["status"]?.ToString() == "observed", "object_base_ad_not_observed:" + i);
            Require(sources["dc_events"]?["status"]?.ToString() == "not_collected", "object_dc_events_must_remain_not_collected:" + i);
            foreach (var (name, raw) in sources)
            {
                string path = $"objects[{i}].sources.{name}"; var state = Object(raw, path); string status = T(state, "status");
                Require(SOURCE_STATE_FIELDS.All(state.ContainsKey), $"source_state_fields_missing:{i}:{name}"); Require(T(state, "source") == name, $"source_state_name_mismatch:{i}:{name}");
                Require(SOURCE_STATUS_MEANINGS.Contains(status), "source_state_status_invalid:" + path);
                if (status is "observed" or "missing_in_source" or "no_record" or "partial" or "failed" or "access_denied" or "parse_error") Require(state["observed_at"] is not null && state["observed_at"]!.ToString().Length > 0, $"source_state_observed_at_required:{path}:{status}");
                if (state["observed_at"] is not null) Instant(state["observed_at"], path + ".observed_at");
                if (status == "not_collected") Require(state["value"] is null && state["observed_at"] is null, "source_state_not_collected_must_not_observe:" + path);
                if (status is "not_evaluated" or "partial") Require(state["details"] is not null, $"source_state_details_required:{path}:{status}");
                if (status is "failed" or "access_denied" or "parse_error") Require(state["error"] is not null && state["error"]!.ToString().Length > 0, $"source_state_error_required:{path}:{status}");
            }
        }
        return snapshot;
    }
    static readonly string[] SOURCE_STATE_FIELDS = ["details","error","observed_at","source","status","value"];
    static readonly string[] SOURCE_STATUS_MEANINGS = ["access_denied","failed","missing_in_source","no_record","not_applicable","not_collected","not_evaluated","observed","parse_error","partial"];
    static readonly string[] REQUIRED_METADATA_FIELDS = ["collection_status","collector_version","completed_at","domain","errors","label","object_count","query_dc","search_base","snapshot_id","sources","started_at"];
    static readonly string[] REQUIRED_OBJECT_FIELDS = ["adSite","canonicalName","classification","collectedAt","collectionErrors","collectorVersion","description","deviceType","distinguishedName","dnsHostName","domain","enabled","eventLastSeen","exactLastLogon","id","ipv4s","ipv6s","lastLogonTimestamp","location","managedBy","name","objectGuid","osBuild","osFamily","osName","osVersion","ou","passwordLastSet","queryDc","roleEvidence","roleHint","servicePack","sid","sources","spns","trustedForDelegation","trustedToAuthForDelegation","userAccountControl","whenChanged","whenCreated"];
    static readonly string[] REQUIRED_SOURCE_NAMES = ["ad","dc_events","dns","exact_last_logon","last_logon_timestamp","os","site"];
}
