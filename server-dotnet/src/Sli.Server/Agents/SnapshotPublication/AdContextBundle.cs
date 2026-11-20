using System.Globalization;
using System.Text.Json.Nodes;
using Sli.Agent.Protocol;
using Sli.Agent.Protocol.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.Agents.SnapshotPublication;

// AD-only normalization from ad/context/contracts.py. GPO has its own validator.
public static class AdContextBundle
{
    internal static string Text(JsonNode? n) => GpoGovernanceSettings.Text(n);
    internal static string? Optional(JsonNode? n, int limit = 4096)
    {
        if (n is null || n.ToJsonString() == "\"\"") return null;
        string s = GpoGovernanceSettings.PythonTrim(Sli.Gpo.SnapshotModel.GpoSnapshotDocument.PythonString(System.Text.Json.JsonSerializer.SerializeToElement(n)));
        Require(GpoGovernanceSettings.Count(s) <= limit);
        return s.Length == 0 ? null : s;
    }
    internal static void Require(bool ok) { if (!ok) throw new ProtocolException("agent_ad_family_invalid"); }
    internal static void Keys(JsonObject o, string names) => Require(o.All(p => names.Split(' ').Contains(p.Key, StringComparer.Ordinal)));
    internal static string Utc(JsonNode? n)
    {
        string s = Text(n);
        Require(PythonIsoDateTime.TryParse(s, out var value) && value.TryToUtc(out _));
        value.TryToUtc(out var utc);
        return utc.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture)
            + (utc.Ticks % TimeSpan.TicksPerSecond == 0 ? "" : "." + (utc.Ticks % TimeSpan.TicksPerSecond / 10).ToString("D6", CultureInfo.InvariantCulture)) + "Z";
    }
    private static string Enum(JsonNode? n, string values) { string s = Text(n); Require(values.Split(' ').Contains(s, StringComparer.Ordinal)); return s; }
    private static readonly Dictionary<string, string> ComputerSources = new() {
        ["enabled"]="Enabled", ["last_logon_utc"]="LastLogonDate", ["dns_host_name"]="DNSHostName", ["operating_system"]="OperatingSystem", ["operating_system_version"]="OperatingSystemVersion"
    };
    private static readonly Dictionary<string, string> ReferenceSources = new(ComputerSources) {
        ["operating_system_service_pack"]="OperatingSystemServicePack", ["canonical_name"]="CanonicalName", ["description"]="Description", ["location"]="Location", ["managed_by"]="ManagedBy", ["password_last_set_utc"]="PasswordLastSet", ["created_utc"]="whenCreated", ["when_changed_utc"]="whenChanged", ["service_principal_names"]="servicePrincipalName", ["trusted_for_delegation"]="TrustedForDelegation", ["trusted_to_auth_for_delegation"]="TrustedToAuthForDelegation", ["user_account_control"]="userAccountControl"
    };
    private static JsonObject States(JsonNode raw, Dictionary<string, string> sources)
    {
        var data = raw.AsObject(); Require(data.Select(p => p.Key).ToHashSet().SetEquals(sources.Keys));
        var result = new JsonObject();
        foreach (var (key, source) in sources) {
            var item = data[key]!.AsObject(); Keys(item, "state source_attribute"); Require(Text(item["source_attribute"]) == source);
            result[key] = new JsonObject { ["state"] = Enum(item["state"], "present absent_in_source"), ["source_attribute"] = source };
        }
        return result;
    }
    public static JsonObject Normalize(JsonObject raw)
    {
        Keys(raw, "schema_version source_pack_id source_pack_version run_id mode domain scope observed_at_utc sections records bundle_sha256");
        Require(Text(raw["schema_version"]) == "ad-context-bundle/v1" && Text(raw["source_pack_id"]) == "sli.windows.ad-context");
        string version = Text(raw["source_pack_version"]), observed = Utc(raw["observed_at_utc"]);
        Guid run = Guid.Parse(Text(raw["run_id"]));
        var domain = raw["domain"]!.AsObject(); Keys(domain, "sid dns_name"); string sid = Text(domain["sid"]);
        var scope = raw["scope"]!.AsObject(); Keys(scope, "search_base privileged_group_sids vpn_group_sids collection_profile computer_membership_collected");
        var normalizedScope = new JsonObject { ["search_base"] = Text(scope["search_base"]) };
        foreach (string key in new[] { "privileged_group_sids", "vpn_group_sids" }) {
            Require(!scope.ContainsKey(key) || scope[key] is JsonArray);
            var values = (scope[key] as JsonArray ?? new JsonArray()).Select(Text).ToArray();
            Require(values.Select(UnicodeCaseFold.Fold).Distinct().Count() == values.Length);
            normalizedScope[key] = new JsonArray(values.OrderBy(UnicodeCaseFold.Fold, Comparer<string>.Create(GpoGovernanceSettings.CompareCodepoints)).Select(x => (JsonNode?)JsonValue.Create(x)).ToArray());
        }
        string? profile = Optional(scope["collection_profile"], 128);
        if (profile is not null) normalizedScope["collection_profile"] = profile;
        if (scope.ContainsKey("computer_membership_collected")) {
            Require(scope["computer_membership_collected"]?.GetValueKind() is System.Text.Json.JsonValueKind.True or System.Text.Json.JsonValueKind.False);
            normalizedScope["computer_membership_collected"] = scope["computer_membership_collected"]!.DeepClone();
        }
        var sections = new JsonArray(); var names = new HashSet<string>();
        foreach (var item in raw["sections"]!.AsArray()) {
            var s = item!.AsObject(); Keys(s, "name status record_count duration_ms error_code");
            string name = Enum(s["name"], "privileged_membership directory_accounts vpn_membership directory_group_graph directory_exact_logon domain_posture domain_health");
            Require(names.Add(name));
            var count = GovernanceInteger.Parse(s["record_count"]); Require(count >= 0);
            var duration = s["duration_ms"] is null ? 0 : GovernanceInteger.Parse(s["duration_ms"]);
            sections.Add(new JsonObject { ["name"] = name, ["status"] = Enum(s["status"], "complete partial failed skipped"), ["record_count"] = JsonNode.Parse(count.ToString(CultureInfo.InvariantCulture)), ["duration_ms"] = JsonNode.Parse(System.Numerics.BigInteger.Max(0, duration).ToString(CultureInfo.InvariantCulture)), ["error_code"] = Optional(s["error_code"], 128) });
        }
        Require(sections.Count > 0);
        if (profile is not null) {
            bool valid = profile == "ad_snapshot_base_v1"
                ? sections.Select(s => Text(s!["name"])).SequenceEqual(new[] { "directory_accounts", "directory_group_graph", "directory_exact_logon" })
                : sections.Count == 1 && profile == (Text(sections[0]!["name"]) switch { "directory_accounts" => "directory_security_v1", "vpn_membership" => "vpn_security_v1", var n => n + "_v1" });
            Require(valid);
        }
        if (scope["computer_membership_collected"]?.GetValueKind() == System.Text.Json.JsonValueKind.True) Require(sections.Any(s => Text(s!["name"]) == "directory_group_graph" && Text(s["status"]) == "complete"));
        var records = new List<JsonObject>(); var recordKeys = new HashSet<string>();
        foreach (var item in raw["records"]!.AsArray()) {
            var r = item!.AsObject(); string type = Enum(r["record_type"], "entity relation data_quality"), section = Text(r["section"]), key = Text(r["record_key"]);
            Require(records.Count < 200000 && names.Contains(section) && recordKeys.Add(key) && Utc(r["observed_at_utc"]) == observed);
            var record = new JsonObject { ["record_type"] = type, ["record_key"] = key, ["section"] = section, ["observed_at_utc"] = observed };
            if (type == "entity") {
                Keys(r, "record_type record_key section observed_at_utc identity attributes");
                var identity = r["identity"]!.AsObject(); Keys(identity, "kind domain_sid object_guid object_sid");
                string kind = Enum(identity["kind"], "ad_user ad_group ad_computer security_principal domain domain_trust domain_controller password_policy replication_link");
                Require(UnicodeCaseFold.Fold(Text(identity["domain_sid"])) == UnicodeCaseFold.Fold(sid));
                record["identity"] = new JsonObject { ["kind"] = kind, ["domain_sid"] = Text(identity["domain_sid"]), ["object_guid"] = Guid.Parse(Text(identity["object_guid"])).ToString("D"), ["object_sid"] = Optional(identity["object_sid"], 256) };
                var attrs = GpoGovernanceSettings.IsTruthy(r["attributes"]) ? r["attributes"]!.DeepClone().AsObject() : new JsonObject();
                var states = new Dictionary<string, JsonNode>();
                foreach (var name in new[] { "attribute_states", "computer_reference_attribute_states" }) {
                    if (attrs[name] is not null) { Require(kind == "ad_computer" && section == "directory_accounts"); states[name] = States(attrs[name]!, name == "attribute_states" ? ComputerSources : ReferenceSources); }
                    attrs.Remove(name);
                }
                Require(attrs["gpo_settings"] is null); attrs.Remove("gpo_settings"); GpoGovernanceAttributes.Validate(attrs);
                if (kind == "ad_computer" && section == "directory_accounts" && Version.TryParse(version, out var v) && v >= new Version(0, 9, 0)) Require(states.ContainsKey("computer_reference_attribute_states"));
                foreach (var pair in states) attrs[pair.Key] = pair.Value;
                record["attributes"] = attrs;
            }
            else if (type == "relation") {
                Keys(r, "record_type record_key section observed_at_utc relation_kind source_record_key target_record_key attributes");
                record["relation_kind"] = Enum(r["relation_kind"], "member_of"); record["source_record_key"] = Text(r["source_record_key"]); record["target_record_key"] = Text(r["target_record_key"]);
                var attrs = GpoGovernanceSettings.IsTruthy(r["attributes"]) ? r["attributes"]!.DeepClone().AsObject() : new JsonObject(); Keys(attrs, "membership_type source_section");
                foreach (var p in attrs) {
                    if (p.Value?.GetValueKind() == System.Text.Json.JsonValueKind.String) Require(GpoGovernanceSettings.Count(p.Value.GetValue<string>()) <= 4096);
                    if (p.Value is JsonArray array) Require(array.Count <= 256 && array.All(n => JsonRead.TryString(n, out var text) && GpoGovernanceSettings.Count(text) <= 4096));
                }
                if (attrs.ContainsKey("membership_type")) Enum(attrs["membership_type"], "direct primary");
                record["attributes"] = attrs;
            }
            else {
                Keys(r, "record_type record_key section observed_at_utc classification code message");
                Require(r["classification"] is null || Text(r["classification"]) == "DataQuality");
                record["classification"] = "DataQuality"; record["code"] = Text(r["code"]); record["message"] = Text(r["message"]);
            }
            records.Add(record);
        }
        foreach (var s in sections) Require(GovernanceInteger.Parse(s!["record_count"]) == records.Count(r => Text(r["section"]) == Text(s["name"])));
        var entities = records.Where(r => Text(r["record_type"]) == "entity").ToDictionary(r => Text(r["record_key"]));
        foreach (var r in records.Where(r => Text(r["record_type"]) == "relation")) Require(entities.ContainsKey(Text(r["source_record_key"])) && entities.ContainsKey(Text(r["target_record_key"])));
        foreach (var (section, scopeKey) in new[] { ("privileged_membership", "privileged_group_sids"), ("vpn_membership", "vpn_group_sids") }) {
            var roots = normalizedScope[scopeKey]!.AsArray().Select(Text).Select(UnicodeCaseFold.Fold).ToHashSet();
            var groups = entities.Values.Where(e => Text(e["identity"]!["kind"]) == "ad_group").GroupBy(e => UnicodeCaseFold.Fold(Optional(e["identity"]!["object_sid"]) ?? "")).ToDictionary(g => g.Key, g => Text(g.Last()["record_key"]));
            Require(roots.All(groups.ContainsKey));
            var selected = sections.FirstOrDefault(s => Text(s!["name"]) == section);
            if (selected is not null && roots.Count == 0) Require(Text(selected["status"]) is "skipped" or "failed");
            var reachable = roots.Select(s => groups[s]).ToHashSet(); var relations = records.Where(r => Text(r["record_type"]) == "relation" && Text(r["section"]) == section).ToArray();
            bool changed;
            do { changed = false; foreach (var r in relations) if (reachable.Contains(Text(r["target_record_key"])) && Text(entities[Text(r["source_record_key"])]["identity"]!["kind"]) == "ad_group") changed |= reachable.Add(Text(r["source_record_key"])); } while (changed);
            Require(relations.All(r => reachable.Contains(Text(r["target_record_key"]))));
        }
        if (profile == "ad_snapshot_base_v1" && sections.Any(s => Text(s!["name"]) == "directory_exact_logon" && Text(s["status"]) == "complete"))
            foreach (var r in entities.Values.Where(r => Text(r["section"]) == "directory_accounts" && Text(r["identity"]!["kind"]) == "ad_user")) Require(new[] { "exact_last_logon_status", "exact_last_logon_discovered_dc_count", "exact_last_logon_successful_dc_count", "exact_last_logon_failed_dcs" }.All(r["attributes"]!.AsObject().ContainsKey));
        var normalized = new JsonObject { ["schema_version"] = "ad-context-bundle/v1", ["source_pack_id"] = "sli.windows.ad-context", ["source_pack_version"] = version, ["run_id"] = run.ToString("D"), ["mode"] = Enum(raw["mode"], "full targeted reconcile"), ["domain"] = new JsonObject { ["sid"] = sid, ["dns_name"] = Sli.Agent.Protocol.Compatibility.UnicodeLower.Lower(Text(domain["dns_name"])) }, ["scope"] = normalizedScope, ["observed_at_utc"] = observed, ["sections"] = sections, ["records"] = new JsonArray(records.OrderBy(r => Text(r["record_key"]), Comparer<string>.Create(GpoGovernanceSettings.CompareCodepoints)).Select(r => (JsonNode?)r).ToArray()) };
        string hash = Convert.ToHexStringLower(GpoIdentityWriter.Hash(normalized, false));
        Require(Optional(raw["bundle_sha256"]) is not string supplied || supplied.ToLowerInvariant() == hash);
        normalized["bundle_sha256"] = hash; return normalized;
    }
}
