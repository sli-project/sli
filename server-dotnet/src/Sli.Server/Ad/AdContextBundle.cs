using System.Text.Json.Nodes;
using Sli.Server.Agents.SnapshotPublication;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

// AD Context normalization. GPO publication has its own stricter native-snapshot contract.
public static class AdContextBundle
{
    static readonly JsonObject Contract = JsonNode.Parse(new StreamReader(typeof(AdContextBundle).Assembly.GetManifestResourceStream("Sli.Server.Ad.context-contract.json")!).ReadToEnd())!.AsObject();
    internal static void Require(bool condition, string code = "agent_ad_family_invalid") { if (!condition) throw new Sli.Agent.Protocol.ProtocolException(code); }
    static string Required(JsonNode? value)
    { string text = value?.ToString().Trim() ?? ""; Require(text.Length > 0 && text.EnumerateRunes().Count() <= 4096); return text; }
    static void Keys(JsonObject value, string keys) => Require(value.All(p => keys.Split(' ').Contains(p.Key)));
    static string? Optional(JsonNode? value, int max)
    { if (value is null) return null; string text = value.ToString().Trim(); Require(text.EnumerateRunes().Count() <= max); return text.Length == 0 ? null : text; }
    static string Enum(JsonNode? value, string choices) { string text = Required(value); Require(choices.Split(' ').Contains(text)); return text; }
    public static JsonObject Normalize(JsonObject raw)
    {
        Keys(raw, "schema_version source_pack_id source_pack_version run_id mode domain scope observed_at_utc sections records bundle_sha256");
        Require(raw.Text("schema_version") == "ad-context-bundle/v1" && raw.Text("source_pack_id") == "sli.windows.ad-context");
        var normalized = new JsonObject { ["schema_version"] = "ad-context-bundle/v1", ["source_pack_id"] = "sli.windows.ad-context", ["source_pack_version"] = Required(raw["source_pack_version"]), ["run_id"] = Guid.Parse(Required(raw["run_id"])).ToString("D"), ["mode"] = Enum(raw["mode"], "full targeted reconcile"), ["observed_at_utc"] = Iso(raw.Time("observed_at_utc")) };
        var domain = raw["domain"]!.AsObject(); Keys(domain, "sid dns_name"); string sid = Required(domain["sid"]);
        normalized["domain"] = Obj(new { sid, dns_name = Required(domain["dns_name"]).ToLowerInvariant() });
        var scope = raw["scope"]!.AsObject(); Keys(scope, "search_base privileged_group_sids vpn_group_sids collection_profile computer_membership_collected");
        var cleanScope = new JsonObject { ["search_base"] = Required(scope["search_base"]) };
        foreach (string key in new[] { "privileged_group_sids", "vpn_group_sids" })
        {
            Require(scope[key] is null or JsonArray);
            var values = (scope[key] as JsonArray ?? []).Select(Required).ToArray(); Require(values.Distinct(StringComparer.OrdinalIgnoreCase).Count() == values.Length);
            cleanScope[key] = Array(values.Order(StringComparer.OrdinalIgnoreCase));
        }
        if (scope.ContainsKey("computer_membership_collected"))
        { Require(scope["computer_membership_collected"]?.GetValueKind() is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False); cleanScope["computer_membership_collected"] = scope["computer_membership_collected"]!.DeepClone(); }
        string? profile = Optional(scope["collection_profile"], 128); if (profile is not null) cleanScope["collection_profile"] = profile;
        normalized["scope"] = cleanScope;
        Require(raw["sections"] is JsonArray { Count: > 0 } && raw["records"] is JsonArray { Count: <= 200000 });
        var sections = new JsonArray();
        foreach (var node in raw["sections"]!.AsArray())
        {
            var section = node!.AsObject(); Keys(section, "name status record_count duration_ms error_code"); string name = Required(section["name"]);
            Require(Contract["SUPPORTED_SECTIONS"]!.AsArray().Any(n => n!.GetValue<string>() == name));
            Require(section["record_count"]?.GetValueKind() == System.Text.Json.JsonValueKind.Number && section["record_count"]!.AsValue().TryGetValue<long>(out var count) && count is >= 0 and <= 200000);
            Require(section["duration_ms"] is null || section["duration_ms"]!.GetValueKind() == System.Text.Json.JsonValueKind.Number && section["duration_ms"]!.AsValue().TryGetValue<long>(out var duration) && duration >= 0);
            sections.Add(Obj(new { name, status = Enum(section["status"], "complete partial failed skipped"), record_count = section.Int("record_count"), duration_ms = Math.Max(0, section.Int("duration_ms")), error_code = Optional(section["error_code"], 128) }));
        }
        var names = sections.Select(n => n!.Text("name")!).ToArray(); Require(names.Distinct().Count() == names.Length);
        if (profile is not null) Require(names.Length == 1 && Contract["SECTION_PROFILES"]![names[0]]?.GetValue<string>() == profile || profile == "ad_snapshot_base_v1" && names.SequenceEqual(new[] { "directory_accounts", "directory_group_graph", "directory_exact_logon" }));
        if (cleanScope["computer_membership_collected"]?.GetValue<bool>() == true) Require(sections.Any(s => s!.Text("name") == "directory_group_graph" && s.Text("status") == "complete"));
        normalized["sections"] = sections;
        var records = new List<JsonObject>();
        foreach (var node in raw["records"]!.AsArray())
        {
            var r = node!.AsObject(); string type = Enum(r["record_type"], "entity relation data_quality"), section = Required(r["section"]);
            Require(names.Contains(section) && Iso(r.Time("observed_at_utc")) == normalized.Text("observed_at_utc"));
            var row = Obj(new { record_type = type, record_key = Required(r["record_key"]), section, observed_at_utc = normalized.Text("observed_at_utc") });
            if (type == "entity")
            {
                Keys(r, "record_type record_key section observed_at_utc identity attributes"); var identity = r["identity"]!.AsObject(); Keys(identity, "kind domain_sid object_guid object_sid");
                string kind = Required(identity["kind"]); Require(Contract["ENTITY_KINDS"]!.AsArray().Any(n => n!.GetValue<string>() == kind) && Required(identity["domain_sid"]).Equals(sid, StringComparison.OrdinalIgnoreCase));
                row["identity"] = Obj(new { kind, domain_sid = Required(identity["domain_sid"]), object_guid = Guid.Parse(Required(identity["object_guid"])).ToString("D"), object_sid = Optional(identity["object_sid"], 256) });
                var attrs = (JsonObject)(r["attributes"]?.DeepClone() ?? new JsonObject());
                var provenance = new JsonObject();
                foreach (string key in new[] { "attribute_states", "computer_reference_attribute_states" })
                {
                    if (attrs[key] is not null)
                    {
                        Require(kind == "ad_computer" && section == "directory_accounts");
                        var states = attrs[key]!.AsObject(); var expected = Contract[key == "attribute_states" ? "COMPUTER_ATTRIBUTE_SOURCES" : "COMPUTER_REFERENCE_ATTRIBUTE_SOURCES"]!.AsObject();
                        Require(states.Select(p => p.Key).ToHashSet().SetEquals(expected.Select(p => p.Key)));
                        var clean = new JsonObject();
                        foreach (var (k, value) in expected)
                        { Keys(states[k]!.AsObject(), "state source_attribute"); Require(Required(states[k]!["source_attribute"]) == value!.GetValue<string>()); clean[k] = Obj(new { state = Enum(states[k]!["state"], "present absent_in_source"), source_attribute = value.GetValue<string>() }); }
                        provenance[key] = clean;
                    }
                    attrs.Remove(key);
                }
                Require(!attrs.ContainsKey("gpo_settings")); GpoGovernanceAttributes.Validate(attrs);
                if (Version.TryParse(normalized.Text("source_pack_version"), out var version) && version >= new Version(0, 9, 0) && kind == "ad_computer" && section == "directory_accounts") Require(provenance.ContainsKey("computer_reference_attribute_states"));
                foreach (var (key, value) in provenance) attrs[key] = value!.DeepClone(); row["attributes"] = attrs;
            }
            else if (type == "relation")
            {
                Keys(r, "record_type record_key section observed_at_utc relation_kind source_record_key target_record_key attributes");
                row["relation_kind"] = Enum(r["relation_kind"], "member_of"); row["source_record_key"] = Required(r["source_record_key"]); row["target_record_key"] = Required(r["target_record_key"]);
                var attrs = r["attributes"] as JsonObject ?? new(); Keys(attrs, "membership_type source_section");
                if (attrs.ContainsKey("membership_type")) Enum(attrs["membership_type"], "direct primary"); row["attributes"] = attrs.DeepClone();
            }
            else
            {
                Keys(r, "record_type record_key section observed_at_utc classification code message"); Require(r["classification"] is null || r.Text("classification") == "DataQuality");
                row["classification"] = "DataQuality"; row["code"] = Required(r["code"]); row["message"] = Required(r["message"]);
            }
            records.Add(row);
        }
        Require(records.Select(r => r.Text("record_key")).Distinct().Count() == records.Count);
        if (profile == "ad_snapshot_base_v1" && sections.FirstOrDefault(s => s!.Text("name") == "directory_exact_logon")?.Text("status") == "complete")
            foreach (var user in records.Where(r => r.Text("record_type") == "entity" && r.Text("section") == "directory_accounts" && r["identity"]!.Text("kind") == "ad_user"))
                Require(new[] { "exact_last_logon_status", "exact_last_logon_discovered_dc_count", "exact_last_logon_successful_dc_count", "exact_last_logon_failed_dcs" }.All(key => user["attributes"]!.AsObject().ContainsKey(key)));
        foreach (var s in sections) Require(s!.Int("record_count") == records.Count(r => r.Text("section") == s.Text("name")));
        var entities = records.Where(r => r.Text("record_type") == "entity").ToDictionary(r => r.Text("record_key")!);
        foreach (var r in records.Where(r => r.Text("record_type") == "relation")) Require(entities.ContainsKey(r.Text("source_record_key")!) && entities.ContainsKey(r.Text("target_record_key")!));
        foreach (var (section, key) in new[] { ("privileged_membership", "privileged_group_sids"), ("vpn_membership", "vpn_group_sids") })
        {
            var roots = cleanScope[key]!.AsArray().Select(s => s!.GetValue<string>()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (names.Contains(section) && roots.Count == 0) Require(sections.First(s => s!.Text("name") == section)!.Text("status") is "skipped" or "failed");
            var reachable = entities.Where(p => p.Value["identity"]!.Text("kind") == "ad_group" && roots.Contains(p.Value["identity"]!.Text("object_sid") ?? "")).Select(p => p.Key).ToHashSet();
            Require(roots.All(sidValue => entities.Values.Any(e => e["identity"]!.Text("kind") == "ad_group" && string.Equals(e["identity"]!.Text("object_sid"), sidValue, StringComparison.OrdinalIgnoreCase))));
            var edges = records.Where(r => r.Text("record_type") == "relation" && r.Text("section") == section).ToArray();
            bool changed; do { changed = false; foreach (var edge in edges) if (reachable.Contains(edge.Text("target_record_key")!) && entities[edge.Text("source_record_key")!]["identity"]!.Text("kind") == "ad_group") changed |= reachable.Add(edge.Text("source_record_key")!); } while (changed);
            Require(edges.All(e => reachable.Contains(e.Text("target_record_key")!)));
        }
        normalized["records"] = Array(records.OrderBy(r => r.Text("record_key"), StringComparer.Ordinal));
        string digest = AdJobPlugin.Digest(normalized);
        Require(raw.Text("bundle_sha256") is null || raw.Text("bundle_sha256")!.ToLowerInvariant() == digest);
        normalized["bundle_sha256"] = digest; return normalized;
    }
}
