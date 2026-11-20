using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;

namespace Sli.Server.Agents.SnapshotPublication;

public sealed record AdPreparedCycle(IReadOnlyDictionary<string, JsonObject> Bundles, JsonObject Computers);

public static class AdPublicationPreparation
{
    internal static readonly Dictionary<string, string[]> Sections = new() {
        ["ad_context_base"] = ["directory_accounts", "directory_group_graph", "directory_exact_logon"],
        ["ad_privileged_membership"] = ["privileged_membership"], ["ad_vpn_membership"] = ["vpn_membership"],
        ["ad_domain_posture"] = ["domain_posture"], ["ad_domain_health"] = ["domain_health"]
    };
    public static AdPreparedCycle Prepare(JsonObject policy, IReadOnlyDictionary<string, JsonObject> families)
    {
        if (!families.Keys.ToHashSet().SetEquals(SnapshotPolicy.AdFamilies)) throw new ProtocolException("agent_ad_required_families_missing");
        var bundles = new Dictionary<string, JsonObject>(); var runs = new HashSet<string>(); string? observed = null;
        int count = 0; long bytes = 0;
        foreach (var (family, sections) in Sections) {
            var b = Normalize(families[family]);
            Require(Text(b["domain"]!["sid"]) == Text(policy["domain_sid"]) && Text(b["domain"]!["dns_name"]) == Text(policy["domain_dns"]));
            Require(b["sections"]!.AsArray().Select(s => Text(s!["name"])).SequenceEqual(sections) && runs.Add(Text(b["run_id"])));
            string stamp = Text(b["observed_at_utc"]); if (observed is not null && observed != stamp) throw new ProtocolException("agent_ad_observation_mismatch");
            observed = stamp; bundles[family] = b; count += b["records"]!.AsArray().Count; bytes += CanonicalJson.Length(families[family]);
        }
        var basis = bundles["ad_context_base"]; var baseSections = basis["sections"]!.AsArray().ToDictionary(s => Text(s!["name"]), s => s!.AsObject());
        bool targeted = policy["search_bases"]!.AsArray().Count > 0;
        if (targeted ? Text(basis["mode"]) != "targeted" : Text(basis["mode"]) is not ("full" or "reconcile")) throw new ProtocolException("agent_ad_base_incomplete");
        bool exact = policy["expensive_flags"]?["exact_last_logon"]?.GetValue<bool>() == true;
        if (Text(baseSections["directory_exact_logon"]["status"]) != (exact ? "complete" : "skipped")) throw new ProtocolException("agent_ad_exact_logon_incomplete");
        var quality = basis["records"]!.AsArray().Where(r => Text(r!["record_type"]) == "data_quality" && Optional(r["code"]) != "sensitive_fields_masked").ToArray();
        foreach (var (name, section) in baseSections) {
            string state = Text(section["status"]); string? error = Optional(section["error_code"]);
            if (name == "directory_exact_logon" && !exact) { state = "complete"; error = null; }
            bool passwordPartial = quality.Any(r => Text(r!["section"]) == name && Text(r["code"]) == "password_expiry_partial");
            if (name == "directory_accounts" && state == "partial") { if (error != "collection_incomplete" || !passwordPartial) throw new ProtocolException("agent_ad_base_incomplete"); }
            else if (state != "complete" || error is not null || name == "directory_accounts" && passwordPartial) throw new ProtocolException("agent_ad_base_incomplete");
        }
        foreach (var r in quality) {
            string code = Text(r!["code"]);
            if (code != "password_expiry_partial" && !Regex.IsMatch(code, @"\Atechnical_inventory_[a-z0-9][a-z0-9.-]{0,252}_(?:timeout|failed)\z")) throw new ProtocolException("agent_ad_base_incomplete");
        }
        string search = Text(basis["scope"]!["search_base"]), expected = targeted ? Text(policy["search_bases"]![0]) : string.Join(',', Text(policy["domain_dns"]).Split('.').Select(s => "DC=" + s));
        if (targeted && (policy["search_bases"]!.AsArray().Count != 1 || Text(policy["search_bases"]![0]) != search)) throw new ProtocolException("agent_ad_scope_incomplete");
        Require(UnicodeCaseFold.Fold(search) == UnicodeCaseFold.Fold(expected));
        foreach (var (family, b) in bundles) {
            Require(Text(b["scope"]!["search_base"]) == search);
            foreach (var (key, owner) in new[] { ("privileged_group_sids", "ad_privileged_membership"), ("vpn_group_sids", "ad_vpn_membership") }) Require(family == owner || b["scope"]![key]!.AsArray().Count == 0);
        }
        foreach (var (family, area, scopeKey) in new[] { ("ad_privileged_membership", "privileged", "privileged_group_sids"), ("ad_vpn_membership", "vpn", "vpn_group_sids") }) {
            var refs = policy["groups"]!.AsArray().Select(Text).Select(r => { var p = r.Split(':', 2); return (Area: p[0], Value: p.Length == 2 ? p[1] : "", Original: r); })
                .Where(r => area == "vpn" ? r.Area == "vpn" : r.Area != "vpn")
                .Select(r => r.Area is "vpn" or "privileged" ? r.Value : r.Original).Select(UnicodeCaseFold.Fold).ToHashSet();
            var b = bundles[family]; var records = b["records"]!.AsArray(); var groups = records.Where(r => Text(r!["record_type"]) == "entity" && Text(r["identity"]!["kind"]) == "ad_group").ToArray();
            bool Matches(JsonNode? g, string reference) => new[] { Optional(g!["identity"]!["object_sid"]) ?? "", Optional(g["attributes"]!["distinguished_name"]) ?? "" }.Select(UnicodeCaseFold.Fold).Contains(reference);
            var resolved = groups.Where(g => refs.Any(r => Matches(g, r))).Select(g => UnicodeCaseFold.Fold(Optional(g!["identity"]!["object_sid"]) ?? "")).ToHashSet();
            Require(resolved.SetEquals(b["scope"]![scopeKey]!.AsArray().Select(Text).Select(UnicodeCaseFold.Fold)));
            if (refs.Count > 0 && (Text(b["sections"]![0]!["status"]) != "complete" || refs.Any(r => !groups.Any(g => Matches(g, r))))) throw new ProtocolException("agent_ad_membership_incomplete");
            if (refs.Count == 0) Require(Text(b["sections"]![0]!["status"]) == "skipped" && records.Count == 0);
        }
        var computer = ComputersSnapshotValidation.Validate(families["computers_v6"]);
        Require(Text(computer["metadata"]!["domain"]) == Text(policy["domain_dns"]) && Text(computer["metadata"]!["completed_at"]) == observed && Text(computer["metadata"]!["search_base"]) == search && Text(computer["metadata"]!["collection_status"]) != "failed");
        var expectedComputers = basis["records"]!.AsArray().Where(r => Text(r!["record_type"]) == "entity" && Text(r["section"]) == "directory_accounts" && Text(r["identity"]!["kind"]) == "ad_computer").Select(r => Text(r!["identity"]!["object_guid"])).ToHashSet();
        Require(expectedComputers.SetEquals(computer["objects"]!.AsArray().Select(r => Text(r!["objectGuid"]))));
        if (count + computer["objects"]!.AsArray().Count > policy["max_objects"]!.GetValue<int>() || bytes > policy["max_bytes"]!.GetValue<long>()) throw new ProtocolException("agent_ad_size_limit");
        return new(bundles, computer);
    }
}
