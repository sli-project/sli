using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using static Sli.Server.Ad.AdJson;
using static Sli.Server.Ad.AdContextBundle;

namespace Sli.Server.Ad;

public static class AdSnapshotPreparation
{
    static readonly string[] BaseSections = ["directory_accounts", "directory_group_graph", "directory_exact_logon"];
    static readonly Dictionary<string, string[]> Sections = new()
    {
        ["ad_context_base"] = BaseSections, ["ad_privileged_membership"] = ["privileged_membership"], ["ad_vpn_membership"] = ["vpn_membership"], ["ad_domain_posture"] = ["domain_posture"], ["ad_domain_health"] = ["domain_health"]
    };
    static readonly HashSet<string> Blocking = ["directory_accounts_truncated", "directory_accounts_failed", "directory_group_graph_truncated", "directory_group_memberships_truncated", "directory_group_links_unresolved", "directory_group_graph_failed", "exact_last_logon_users_truncated", "exact_last_logon_dc_coverage_partial", "directory_exact_logon_failed"];
    public static IReadOnlyDictionary<string, JsonObject> Prepare(JsonObject policy, IReadOnlyDictionary<string, JsonObject> families)
    {
        Require(families.Keys.ToHashSet().SetEquals(SnapshotPolicy.AdFamilies), "agent_ad_required_families_missing");
        var bundles = new Dictionary<string, JsonObject>();
        foreach (var (family, sections) in Sections)
        {
            var bundle = AdContextBundle.Normalize(families[family]);
            Require(bundle["domain"]!.Text("sid") == policy.Text("domain_sid") && bundle["domain"]!.Text("dns_name") == policy.Text("domain_dns") && bundle["sections"]!.AsArray().Select(s => s!.Text("name")).SequenceEqual(sections));
            bundles.Add(family, bundle);
        }
        Require(bundles.Values.Select(b => b.Text("run_id")).Distinct().Count() == bundles.Count);
        Require(bundles.Values.Select(b => b.Text("observed_at_utc")).Distinct().Count() == 1, "agent_ad_observation_mismatch");
        var baseBundle = bundles["ad_context_base"]; var baseSections = baseBundle["sections"]!.AsArray();
        bool targeted = policy["search_bases"]!.AsArray().Count > 0;
        Require(targeted ? baseBundle.Text("mode") == "targeted" : baseBundle.Text("mode") is "full" or "reconcile", "agent_ad_base_incomplete");
        bool exact = policy["expensive_flags"]?["exact_last_logon"]?.GetValue<bool>() == true;
        Require(baseSections[2]!.Text("status") == (exact ? "complete" : "skipped"), "agent_ad_exact_logon_incomplete");
        var quality = baseBundle["records"]!.AsArray().Where(r => r!.Text("record_type") == "data_quality" && BaseSections.Contains(r.Text("section"))).ToArray();
        foreach (var record in quality)
        {
            string code = record!.Text("code")!;
            Require(code is "sensitive_fields_masked" or "password_expiry_partial" || !Blocking.Contains(code) && Regex.IsMatch(code, @"\Atechnical_inventory_[a-z0-9][a-z0-9.-]{0,252}_(?:timeout|failed)\z"), "agent_ad_base_incomplete");
        }
        foreach (var section in baseSections)
        {
            if (section!.Text("name") == "directory_exact_logon" && !exact) continue;
            bool passwordPartial = quality.Any(r => r!.Text("section") == "directory_accounts" && r.Text("code") == "password_expiry_partial");
            Require(section.Text("name") == "directory_accounts" && section.Text("status") == "partial"
                ? section.Text("error_code") == "collection_incomplete" && passwordPartial
                : section.Text("status") == "complete" && section!["error_code"] is null && (section.Text("name") != "directory_accounts" || !passwordPartial), "agent_ad_base_incomplete");
        }
        string search = baseBundle["scope"]!.Text("search_base")!;
        Require(bundles.Values.All(b => b["scope"]!.Text("search_base") == search), "agent_ad_scope_mismatch");
        string expected = targeted ? policy["search_bases"]![0]!.GetValue<string>() : string.Join(',', policy.Text("domain_dns")!.Split('.').Select(part => "DC=" + part));
        Require(!targeted || policy["search_bases"]!.AsArray().Count == 1, "agent_ad_scope_incomplete");
        Require(string.Equals(search, expected, StringComparison.OrdinalIgnoreCase), "agent_ad_scope_mismatch");
        foreach (var (family, bundle) in bundles)
        {
            foreach (var (key, allowedFamily) in new[] { ("privileged_group_sids", "ad_privileged_membership"), ("vpn_group_sids", "ad_vpn_membership") })
                Require(family == allowedFamily || bundle["scope"]![key]!.AsArray().Count == 0, "agent_ad_group_scope_mismatch");
        }
        foreach (var (family, area, key) in new[] { ("ad_privileged_membership", "privileged", "privileged_group_sids"), ("ad_vpn_membership", "vpn", "vpn_group_sids") })
        {
            var refs = policy["groups"]!.AsArray().Select(n => n!.GetValue<string>()).Where(s => area == "vpn" ? s.StartsWith("vpn:") : !s.StartsWith("vpn:")).Select(s => s.StartsWith("privileged:") ? s[11..] : s.StartsWith("vpn:") ? s[4..] : s).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var bundle = bundles[family];
            var groups = bundle["records"]!.AsArray().Where(r => r!.Text("record_type") == "entity" && r!["identity"]!.Text("kind") == "ad_group").ToArray();
            var resolved = groups.Where(r => refs.Contains(r!["identity"]!.Text("object_sid") ?? "") || refs.Contains(r!["attributes"]!.Text("distinguished_name") ?? "")).Select(r => r!["identity"]!.Text("object_sid") ?? "").ToHashSet(StringComparer.OrdinalIgnoreCase);
            Require(resolved.SetEquals(bundle["scope"]![key]!.AsArray().Select(n => n!.ToString())), "agent_ad_group_scope_mismatch");
            Require(refs.Count == 0 ? bundle["sections"]![0]!.Text("status") == "skipped" && bundle["records"]!.AsArray().Count == 0 : bundle["sections"]![0]!.Text("status") == "complete" && refs.All(reference => groups.Any(r => string.Equals(r!["identity"]!.Text("object_sid"), reference, StringComparison.OrdinalIgnoreCase) || string.Equals(r!["attributes"]!.Text("distinguished_name"), reference, StringComparison.OrdinalIgnoreCase))), "agent_ad_membership_incomplete");
        }
        var computers = families["computers_v6"]; ValidateComputers(computers);
        var meta = computers["metadata"]!;
        Require(meta.Text("domain") == policy.Text("domain_dns") && meta.Text("completed_at") == baseBundle.Text("observed_at_utc") && meta.Text("search_base") == search && meta.Text("collection_status") != "failed", "agent_ad_computers_invalid");
        var expectedGuids = baseBundle["records"]!.AsArray().Where(r => r!.Text("record_type") == "entity" && r.Text("section") == "directory_accounts" && r!["identity"]!.Text("kind") == "ad_computer").Select(r => r!["identity"]!.Text("object_guid")).ToHashSet();
        Require(expectedGuids.SetEquals(computers["objects"]!.AsArray().Select(r => r!.Text("objectGuid"))), "agent_ad_computer_population_mismatch");
        long count = bundles.Values.Sum(b => b["records"]!.AsArray().Count) + computers["objects"]!.AsArray().Count;
        long bytes = Sections.Keys.Sum(family => CanonicalJson.Length(families[family]));
        Require(count <= policy.Int("max_objects") && bytes <= policy.Int("max_bytes"), "agent_ad_size_limit");
        return bundles;
    }
    static readonly JsonObject ComputerContract = JsonNode.Parse(new StreamReader(typeof(AdSnapshotPreparation).Assembly.GetManifestResourceStream("Sli.Server.Ad.computer-contract.json")!).ReadToEnd())!.AsObject();
    public static void ValidateComputers(JsonObject snapshot)
    {
        void RequiredFields(JsonObject obj, string key) => Require(ComputerContract[key]!.AsArray().All(n => obj.ContainsKey(n!.GetValue<string>())), "agent_ad_computers_invalid");
        bool Status(string? value) => value is not null && ComputerContract["SOURCE_STATUS_MEANINGS"]!.AsObject().ContainsKey(value);
        Require(snapshot.Text("schema_version") == "2.0" && snapshot["metadata"] is JsonObject && snapshot["objects"] is JsonArray, "agent_ad_computers_invalid");
        var meta = snapshot["metadata"]!.AsObject(); RequiredFields(meta, "REQUIRED_METADATA_FIELDS");
        Require(meta.Time("started_at") <= meta.Time("completed_at") && Guid.TryParse(meta.Text("snapshot_id"), out _));
        string provenance = string.Join(' ', new[] { meta.Text("snapshot_id"), meta.Text("label"), meta.Text("collector_version") }).ToLowerInvariant();
        Require(!provenance.Contains("demo") && !provenance.Contains("пример"));
        Require(meta.Text("collection_status") is "complete" or "partial" or "failed" && new[] { "query_dc", "domain", "collector_version" }.All(k => meta.Text(k) is not null) && meta["sources"] is JsonArray);
        var objects = snapshot["objects"]!.AsArray(); Require(meta["object_count"]?.GetValueKind()==JsonValueKind.Number&&meta["object_count"]!.AsValue().TryGetValue<int>(out int count)&&count==objects.Count&&objects.Count<=250000);
        var sources = meta["sources"]!.AsArray(); Require(sources.Select(s => s!.Text("name")).Distinct().Count() == sources.Count && sources.All(s => s!.Text("name") is not null && Status(s.Text("status")) && s!["requested"]?.GetValueKind() is JsonValueKind.True or JsonValueKind.False));
        var ad = sources.FirstOrDefault(s => s!.Text("name") == "ad");
        Require(meta.Text("collection_status") == "failed" ? objects.Count == 0 && ad?.Text("status") != "observed" : ad?.Text("status") == "observed");
        if (objects.Count > 0) Require(ComputerContract["REQUIRED_SOURCE_NAMES"]!.AsArray().All(n => sources.Any(s => s!.Text("name") == n!.ToString())) && sources.Any(s => s!.Text("name") == "dc_events" && s.Text("status") == "not_collected" && s!["requested"]!.GetValue<bool>() == false));
        var seen = new HashSet<Guid>();
        foreach (var node in objects)
        {
            var obj = node!.AsObject(); RequiredFields(obj, "REQUIRED_OBJECT_FIELDS");
            Require(Guid.TryParse(obj.Text("id"), out var guid) && Guid.TryParse(obj.Text("objectGuid"), out var objectGuid) && guid == objectGuid && seen.Add(guid));
            var states = obj["sources"]!.AsObject(); Require(ComputerContract["REQUIRED_SOURCE_NAMES"]!.AsArray().All(n => states.ContainsKey(n!.ToString())) && states["ad"]!.Text("status") == "observed" && states["dc_events"]!.Text("status") == "not_collected");
            foreach (var (name, state) in states)
            {
                RequiredFields(state!.AsObject(), "SOURCE_STATE_FIELDS"); string? status = state.Text("status"); Require(Status(status) && state.Text("source") == name);
                if (status is "observed" or "missing_in_source" or "no_record" or "partial" or "failed" or "access_denied" or "parse_error") Require(state.Text("observed_at") is not null);
                if (state["observed_at"] is not null) _ = state.Time("observed_at");
                if (status == "not_collected") Require(state["value"] is null && state["observed_at"] is null);
                if (status is "not_evaluated" or "partial") Require(state["details"] is not null);
                if (status is "failed" or "access_denied" or "parse_error") Require(Sli.Server.Agents.SnapshotPublication.GpoGovernanceSettings.IsTruthy(state["error"]));
            }
        }
    }
}
