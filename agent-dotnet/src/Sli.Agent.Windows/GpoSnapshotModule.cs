using System.Text.Json.Nodes;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using static Sli.Agent.Windows.SnapshotJson;

namespace Sli.Agent.Windows;

public sealed class GpoSnapshotModule(IDirectorySnapshotReader reader)
{
    public async Task<IReadOnlyDictionary<string, SnapshotFamily>> CaptureAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
    {
        var raw = await reader.ReadAsync(policy, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        try { return Normalize(raw, policy); }
        catch (Exception e) when (e is InvalidOperationException or NullReferenceException or FormatException or KeyNotFoundException)
        { throw new AgentException("agent_gpo_capture_invalid"); }
    }

    public static IReadOnlyDictionary<string, SnapshotFamily> Normalize(JsonObject raw, SnapshotPolicy policy, Func<Guid>? newId = null)
    {
        var error = Text(raw["error_code"]);
        if (error is "agent_gpo_group_policy_unavailable" or "agent_gpo_capture_failed") throw new AgentException(error);
        var cfg = policy.Config; var domain = raw["domain"]!;
        var keys = "schema_version collector_version demo demo_notice started_at completed_at observed_at collection_status domain scope source_states gpos scopes links settings permissions acl wmi_filters unresolved_links collection_errors".Split(' ');
        var arrays = "gpos scopes links settings permissions acl wmi_filters unresolved_links collection_errors".Split(' ');
        var snapshot = new JsonObject();
        foreach (var (key, value) in raw["snapshot"]!.AsObject()) if (keys.Contains(key)) snapshot[key] = Copy(value);
        var dns = Text(cfg["domain_dns"]); var sid = Text(cfg["domain_sid"]);
        var searchBase = string.Join(',', dns.Split('.').Select(s => "DC=" + s));
        if (Text(domain["sid"]) != sid || !string.Equals(Text(domain["dns_name"]), dns, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(Text(snapshot["domain"]!["dns_name"]), dns, StringComparison.OrdinalIgnoreCase) || Text(snapshot["domain"]!["sid"]) != sid) throw new AgentException("agent_gpo_domain_mismatch");
        var bases = cfg["search_bases"]!.AsArray();
        if (!string.Equals(Text(domain["default_nc"]), searchBase, StringComparison.OrdinalIgnoreCase) || bases.Count != 0 && (bases.Count != 1 || Text(bases[0]) != searchBase)) throw new AgentException("agent_gpo_scope_mismatch");
        var dc = cfg["dc"]!.AsArray();
        if (dc.Count != 0 && !string.Equals(Text(snapshot["domain"]!["query_dc"]), Text(dc[0]), StringComparison.OrdinalIgnoreCase)) throw new AgentException("agent_gpo_dc_mismatch");
        var records = raw["records"]!.DeepClone().AsArray();
        if (!snapshot.ContainsKey("acl")) snapshot["acl"] = new JsonArray();
        var complete = Text(snapshot["collection_status"]) == "complete";
        var bundle = Bundle(cfg, Text(snapshot["observed_at"]), (newId ?? Guid.NewGuid)(), new JsonObject
        { ["search_base"] = searchBase, ["collection_profile"] = "gpo_governance_v4", ["privileged_group_sids"] = new JsonArray(), ["vpn_group_sids"] = new JsonArray() }, records,
            new JsonArray(new JsonObject { ["name"] = "gpo_governance", ["status"] = complete ? "complete" : "partial", ["record_count"] = records.Count,
                ["duration_ms"] = 0, ["error_code"] = complete ? null : "agent_gpo_source_partial" }));
        bundle["mode"] = "full";
        var original = new JsonObject { ["gpo_v2"] = snapshot, ["ad_gpo_governance"] = bundle };
        var masked = SnapshotPrivacy.Mask(original, true)!.AsObject();
        var wasMasked = !JsonNode.DeepEquals(masked, original) || raw["snapshot"]!.AsObject().Any(p => !keys.Contains(p.Key));
        masked["gpo_v2"]!["privacy"] = new JsonObject { ["masked"] = wasMasked, ["raw_content_collected"] = false };
        Dictionary<string, SnapshotFamily> Families() => policy.Families.ToDictionary(f => f, f => new SnapshotFamily(masked[f]!.DeepClone(), masked[f]![f == "gpo_v2" ? "gpos" : "records"]!.AsArray().Count));
        var families = Families();
        if (Flag(raw["overflow"]) || snapshot["gpos"]!.AsArray().Count > policy.Number("max_objects") || records.Count > policy.Number("max_objects")
            || families.Values.Sum(f => CanonicalJson.ToBytes(f.Data).Length) > policy.Number("max_bytes"))
        {
            snapshot = masked["gpo_v2"]!.AsObject();
            snapshot["collection_status"] = "partial";
            snapshot["collection_errors"] = new JsonArray(new JsonObject { ["code"] = "agent_gpo_size_limit", ["status"] = "partial" });
            foreach (var name in arrays.Where(n => n != "collection_errors")) snapshot[name] = new JsonArray();
            var states = new JsonObject();
            foreach (var name in "gpo_list gpo_reports gpc_directory sysvol_gpt links permissions wmi_filters".Split(' ')) states[name] = new JsonObject { ["status"] = "partial", ["source"] = name, ["error"] = "agent_gpo_size_limit" };
            snapshot["source_states"] = states;
            bundle = masked["ad_gpo_governance"]!.AsObject(); bundle["mode"] = "targeted"; bundle["records"] = new JsonArray();
            var section = bundle["sections"]![0]!; section["status"] = "partial"; section["record_count"] = 0; section["error_code"] = "agent_gpo_size_limit";
            families = Families();
            if (families.Values.Sum(f => CanonicalJson.ToBytes(f.Data).Length) > policy.Number("max_bytes")) throw new AgentException("agent_gpo_size_limit");
        }
        return families;
    }

    private static JsonObject Bundle(JsonObject cfg, string stamp, Guid id, JsonObject scope, JsonArray records, JsonArray sections)
        => SnapshotJson.Bundle(cfg, stamp, id.ToString(), scope, records, sections);
}
