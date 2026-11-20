using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;

namespace Sli.Server.Agents.SnapshotPublication;

internal static class ComputersSnapshotValidation
{
    internal const int MaxSnapshotBytes = 64 * 1024 * 1024;
    internal const int MaxObjects = 250000;
    private const string Statuses = "observed not_collected not_evaluated missing_in_source no_record partial failed access_denied parse_error not_applicable";
    private static void Bound(int value, int maximum, int minimum, string kind)
    {
        if (value < minimum || value > maximum) throw new ProtocolException(kind + "_limit_out_of_bounds");
    }
    internal static JsonObject Parse(ReadOnlySpan<byte> payload, int maxBytes = MaxSnapshotBytes, int maxObjects = MaxObjects)
    {
        Bound(maxBytes, MaxSnapshotBytes, 1, "byte");
        Bound(maxObjects, MaxObjects, 0, "object");
        if (payload.Length > maxBytes) throw new ProtocolException("snapshot_size_out_of_bounds");
        string text;
        try { text = new UTF8Encoding(false, true).GetString(payload); }
        catch (DecoderFallbackException) { throw new ProtocolException("snapshot_utf8_invalid"); }
        if (text.StartsWith('\uFEFF')) text = text[1..];
        JsonObject snapshot;
        try { snapshot = JsonNode.Parse(text) as JsonObject ?? throw new ProtocolException("snapshot_must_be_object"); }
        catch (JsonException) { throw new ProtocolException("snapshot_json_invalid"); }
        return Validate(snapshot, maxObjects);
    }
    internal static JsonObject Validate(JsonObject snapshot, int maxObjects = MaxObjects)
    {
        Bound(maxObjects, MaxObjects, 0, "object");
        Require(Text(snapshot["schema_version"]) == "2.0");
        var m = snapshot["metadata"]!.AsObject();
        Require("snapshot_id label started_at completed_at query_dc domain search_base collection_status object_count collector_version sources errors".Split(' ').All(m.ContainsKey));
        Require(DateTimeOffset.Parse(Utc(m["completed_at"])) >= DateTimeOffset.Parse(Utc(m["started_at"])) && Guid.TryParse(Text(m["snapshot_id"]), out _));
        string provenance = UnicodeCaseFold.Fold(string.Join(' ', new[] { Optional(m["snapshot_id"]), Optional(m["label"]), Optional(m["collector_version"]) }));
        Require(!provenance.Contains("demo", StringComparison.Ordinal) && !provenance.Contains("пример", StringComparison.Ordinal));
        Require(new[] { "complete", "partial", "failed" }.Contains(Text(m["collection_status"])));
        foreach (var field in new[] { "query_dc", "domain", "collector_version" }) Text(m[field]);
        var stages = new Dictionary<string, JsonObject>();
        foreach (var raw in m["sources"]!.AsArray()) {
            var s = raw!.AsObject(); Require(s.ContainsKey("requested") && s["requested"]?.GetValueKind() is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False && Statuses.Split(' ').Contains(Text(s["status"])) && stages.TryAdd(Text(s["name"]), s));
        }
        var objects = snapshot["objects"]!.AsArray();
        Require(objects.Count <= maxObjects && m["object_count"]?.GetValueKind() == JsonValueKind.Number
            && m["object_count"]!.AsValue().TryGetValue<int>(out var count) && count == objects.Count);
        string[] sources = ["ad", "dns", "os", "site", "last_logon_timestamp", "exact_last_logon", "dc_events"];
        if (objects.Count > 0) Require(sources.All(stages.ContainsKey) && Text(stages["dc_events"]["status"]) == "not_collected" && stages["dc_events"]["requested"]!.GetValue<bool>() == false);
        if (Text(m["collection_status"]) == "failed") Require(objects.Count == 0 && (!stages.ContainsKey("ad") || Text(stages["ad"]["status"]) != "observed"));
        else Require(stages.ContainsKey("ad") && Text(stages["ad"]["status"]) == "observed");
        var seen = new HashSet<Guid>();
        foreach (var raw in objects) {
            var o = raw!.AsObject();
            Require("id objectGuid name dnsHostName enabled deviceType classification ipv4s ipv6s osName osVersion osBuild osFamily servicePack ou distinguishedName canonicalName domain adSite lastLogonTimestamp exactLastLogon eventLastSeen passwordLastSet whenCreated whenChanged description location managedBy sid userAccountControl spns trustedForDelegation trustedToAuthForDelegation roleHint roleEvidence collectedAt queryDc collectorVersion sources collectionErrors".Split(' ').All(o.ContainsKey));
            Guid id = Guid.Parse(Text(o["id"])); Require(id == Guid.Parse(Text(o["objectGuid"])) && seen.Add(id));
            var states = o["sources"]!.AsObject(); Require(sources.All(states.ContainsKey) && Text(states["ad"]!["status"]) == "observed" && Text(states["dc_events"]!["status"]) == "not_collected");
            foreach (var (name, rawState) in states) {
                var state = rawState!.AsObject();
                Require("status source value observed_at error details".Split(' ').All(state.ContainsKey) && Text(state["source"]) == name);
                string status = Text(state["status"]); Require(Statuses.Split(' ').Contains(status));
                if (status is "observed" or "missing_in_source" or "no_record" or "partial" or "failed" or "access_denied" or "parse_error") Require(state["observed_at"] is not null);
                if (state["observed_at"] is not null) Utc(state["observed_at"]);
                if (status == "not_collected") Require(state["value"] is null && state["observed_at"] is null);
                if (status is "not_evaluated" or "partial") Require(state["details"] is not null);
                if (status is "failed" or "access_denied" or "parse_error") Require(GpoGovernanceSettings.IsTruthy(state["error"]));
            }
        }
        return (JsonObject)snapshot.DeepClone();
    }
}
