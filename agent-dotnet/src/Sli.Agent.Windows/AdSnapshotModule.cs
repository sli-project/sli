using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Core;
using Sli.Agent.Protocol;
using static Sli.Agent.Windows.SnapshotJson;

namespace Sli.Agent.Windows;

public sealed class AdSnapshotModule(IDirectorySnapshotReader reader, TimeProvider clock)
{
    private static readonly Dictionary<string, string[]> Sections = new()
    {
        ["ad_context_base"] = ["directory_accounts", "directory_group_graph", "directory_exact_logon"],
        ["ad_privileged_membership"] = ["privileged_membership"], ["ad_vpn_membership"] = ["vpn_membership"],
        ["ad_domain_posture"] = ["domain_posture"], ["ad_domain_health"] = ["domain_health"]
    };
    private static readonly Dictionary<string, string> Profiles = new()
    {
        ["ad_context_base"] = "ad_snapshot_base_v1", ["ad_privileged_membership"] = "privileged_membership_v1",
        ["ad_vpn_membership"] = "vpn_security_v1", ["ad_domain_posture"] = "domain_posture_v1", ["ad_domain_health"] = "domain_health_v1"
    };
    private static readonly string[] Checks = ["advertising_state", "connectivity_state", "services_state", "sysvol_state", "netlogon_state", "dns_state"];
    public async Task<IReadOnlyDictionary<string, SnapshotFamily>> CaptureAsync(SnapshotPolicy policy, CancellationToken cancellationToken)
    {
        var raw = await reader.ReadAsync(policy, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        try { return Normalize(raw, policy, clock.GetUtcNow()); }
        catch (AgentException e)
        { throw SnapshotCaptureException.Describe(policy.ModuleId, e.Code == "agent_ad_size_limit" ? "size" : "normalize", e); }
        catch (Exception e) when (e is InvalidOperationException or NullReferenceException or FormatException or KeyNotFoundException or OverflowException or ArgumentException)
        { throw SnapshotCaptureException.Describe(policy.ModuleId, "normalize", e); }
    }

    public static IReadOnlyDictionary<string, SnapshotFamily> Normalize(JsonObject raw, SnapshotPolicy policy, DateTimeOffset observedAt, Func<Guid>? newId = null)
    {
        newId ??= Guid.NewGuid;
        var cfg = policy.Config; var domain = raw["domain"]!; var sid = Text(cfg["domain_sid"]); var dns = Text(cfg["domain_dns"]);
        if (Text(domain["sid"]) != sid || !string.Equals(Text(domain["dns_name"]), dns, StringComparison.OrdinalIgnoreCase)) throw new AgentException("agent_ad_domain_mismatch");
        var observed = Stamp(observedAt); var bases = cfg["search_bases"]!.AsArray(); var searchBase = bases.Count == 0 ? Text(domain["default_nc"]) : Text(bases[0]);
        var flags = cfg["expensive_flags"]!;
        var states = Sections.Values.SelectMany(s => s).ToDictionary(s => s, s => Text(raw["states"]?[s], "complete"));
        var records = states.Keys.ToDictionary(s => s, _ => new List<JsonObject>());
        var objects = new Dictionary<string, (JsonObject Record, JsonObject Props)>();
        var byDn = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); var bySid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var masked = false;
        JsonObject Entity(string key, string section, string kind, string guid, JsonNode? objectSid, JsonObject attrs) => new()
        { ["record_type"] = "entity", ["record_key"] = key, ["section"] = section, ["observed_at_utc"] = observed,
            ["identity"] = new JsonObject { ["kind"] = kind, ["domain_sid"] = sid, ["object_guid"] = guid, ["object_sid"] = Copy(objectSid) }, ["attributes"] = attrs };
        JsonObject Quality(string key, string section, string code, string message) => new()
        { ["record_type"] = "data_quality", ["record_key"] = key, ["section"] = section, ["observed_at_utc"] = observed, ["classification"] = "DataQuality", ["code"] = code, ["message"] = message };
        foreach (var item in Rows(raw["objects"]))
        {
            var props = new JsonObject(item["properties"]!.AsObject().Select(p => KeyValuePair.Create(p.Key.ToLowerInvariant(), Copy(p.Value))));
            masked |= props.Any(p => !Rows(AdSnapshotAttributes.Schema["ldap_attributes"]).Any(n => Text(n) == p.Key) && !p.Key.StartsWith("member;range=", StringComparison.Ordinal));
            var guid = Guid.Parse(Text(props["objectguid"])).ToString(); var key = $"ad:{sid.ToLowerInvariant()}:{guid}"; var kind = Text(item["kind"]);
            var classes = Values(props["objectclass"]).Select(n => Text(n)).ToArray();
            var section = kind == "ad_group" || classes.Contains("foreignSecurityPrincipal") ? "directory_group_graph" : kind is "ad_user" or "ad_computer" ? "directory_accounts" : kind is "domain_controller" or "replication_link" ? "domain_health" : "domain_posture";
            var attrs = AdSnapshotAttributes.Attributes(props, kind, raw["schema_attributes"]);
            if (kind == "domain")
            {
                attrs["display_name"] = dns;
                foreach (var name in "pdc_emulator rid_master infrastructure_master schema_master domain_naming_master".Split(' ')) attrs[name] = Copy(raw["fsmo"]?[name]);
                attrs["forest_name"] = string.Join('.', Text(domain["forest_nc"]).Split(',').Where(s => s.StartsWith("DC=", StringComparison.OrdinalIgnoreCase)).Select(s => s[3..]));
                attrs["ldap_signing_requirement"] = "not_collected"; attrs["ldap_channel_binding_requirement"] = "not_collected";
            }
            else if (kind == "security_principal") attrs["infrastructure_role"] = classes.Contains("organizationalUnit") ? "organizational_unit" : classes.Contains("site") ? "site" : "security_principal";
            else if (kind == "domain_controller")
            {
                attrs["infrastructure_role"] = "domain_controller"; attrs["is_global_catalog"] = (Int(props["options"]) & 1) != 0;
                attrs["is_read_only"] = Copy(props["msds-isrodc"]); attrs["operation_master_roles"] = new JsonArray();
                attrs["site_name"] = Text(props["distinguishedname"]).Split(",CN=Sites,", 2)[0].Split(",CN=").Last();
                foreach (var check in Checks) attrs[check] = "not_collected";
            }
            else if (kind == "replication_link")
            { attrs["source_dc"] = Copy(props["fromserver"]); attrs["destination_dc"] = Text(props["distinguishedname"]).Split(',', 2).Last(); attrs["replication_state"] = "not_collected"; }
            else if (kind == "domain_trust") attrs["display_name"] = Copy(attrs["trust_partner"] ?? attrs["display_name"]);
            var record = Entity(key, section, kind, guid, props["objectsid"], attrs);
            if (!objects.TryAdd(key, (record, props))) throw new AgentException("agent_ad_duplicate_object");
            if (Text(props["distinguishedname"]) is { Length: > 0 } dn) byDn[dn] = key;
            if (Text(props["objectsid"]) is { Length: > 0 } osid) bySid[osid] = key;
            records[section].Add(record);
        }
        foreach (var (record, _) in objects.Values)
        {
            if (Text(record["identity"]!["kind"]) != "domain") continue;
            var stable = dns + ":default-password-policy";
            var attrs = new JsonObject(record["attributes"]!.AsObject().Where(p => p.Key.StartsWith("password_", StringComparison.Ordinal) || p.Key.StartsWith("lockout_", StringComparison.Ordinal)).Select(p => KeyValuePair.Create(p.Key, Copy(p.Value))));
            attrs["display_name"] = "Default domain policy";
            records["domain_posture"].Add(Entity("ad-infrastructure:password_policy:" + stable, "domain_posture", "password_policy", StableGuid(stable), null, attrs));
        }
        foreach (var item in Rows(raw["health"]))
        {
            var props = item["properties"]!.AsObject(); var attrs = AdSnapshotAttributes.Attributes(props, "ad_computer");
            attrs.Remove("attribute_states"); attrs.Remove("computer_reference_attribute_states"); attrs["infrastructure_role"] = "domain_controller";
            foreach (var key in new[] { "site_name", "is_global_catalog", "is_read_only", "operation_master_roles" }) attrs[key] = Copy(item["metadata"]?[key]);
            foreach (var key in Checks) attrs[key] = Text(item["checks"]?[key], "not_collected");
            attrs["health_error_codes"] = Array((item["checks"]?.AsObject() ?? []).Where(p => Checks.Contains(p.Key) && Text(p.Value) is "failed" or "timeout" or "unavailable" or "not_collected").Select(p => p.Key + "_" + Text(p.Value)));
            var hostname = Text(props["dnshostname"], Text(props["name"]));
            records["domain_health"].Add(Entity("ad-infrastructure:ad_computer:" + hostname.ToLowerInvariant(), "domain_health", "ad_computer", Guid.Parse(Text(props["objectguid"])).ToString(), props["objectsid"], attrs));
        }
        foreach (var item in Rows(raw["replication"]))
        {
            var attrs = new JsonObject();
            foreach (var key in "source_dc destination_dc naming_context last_replication_attempt_utc last_replication_success_utc consecutive_failure_count last_replication_result".Split(' ')) attrs[key] = Copy(item[key]);
            var stable = string.Join('|', new[] { "source_dc", "destination_dc", "naming_context" }.Select(k => attrs[k]?.ToString() ?? "None"));
            attrs["display_name"] = $"{Text(attrs["source_dc"], "None")} -> {Text(attrs["destination_dc"], "None")}";
            attrs["replication_state"] = attrs["consecutive_failure_count"] is not null && attrs["last_replication_result"] is not null && Int(attrs["consecutive_failure_count"]) == 0 && Int(attrs["last_replication_result"]) == 0 ? "passed" : "failed";
            records["domain_health"].Add(Entity("ad-infrastructure:replication_link:" + stable.ToLowerInvariant(), "domain_health", "replication_link", StableGuid(stable), null, attrs));
        }
        var edges = new HashSet<(string Source, string Target, string Membership)>(); var unresolved = false;
        foreach (var (key, (record, props)) in objects)
        {
            var kind = Text(record["identity"]!["kind"]); var attrs = record["attributes"]!;
            if (kind is not ("ad_user" or "ad_computer" or "ad_group")) continue;
            var missing = new List<string>();
            foreach (var dn in Values(props["memberof"]).Select(n => Text(n)))
                if (byDn.TryGetValue(dn, out var parent) && Text(objects[parent].Record["identity"]!["kind"]) == "ad_group") edges.Add((key, parent, "direct"));
                else { missing.Add(dn); unresolved = true; }
            attrs[kind == "ad_group" ? "unresolved_parent_dns" : "unresolved_group_dns"] = Array(missing.Take(256));
            if (kind == "ad_group")
            {
                var (members, complete) = Members(props); unresolved |= !complete;
                foreach (var dn in members)
                    if (byDn.TryGetValue(dn, out var member)) edges.Add((member, key, "direct"));
                    else { unresolved = true; records["directory_group_graph"].Add(Quality("quality:unresolved-member:" + Hash(key + "|" + dn.ToLowerInvariant()), "directory_group_graph", "directory_group_links_unresolved", "Unresolved member DN: " + dn)); }
                continue;
            }
            if (props["primarygroupid"] is not null)
            {
                var primarySid = sid + "-" + Int(props["primarygroupid"]);
                if (bySid.TryGetValue(primarySid, out var target) && Text(objects[target].Record["identity"]!["kind"]) == "ad_group") edges.Add((key, target, "primary"));
                else { attrs["unresolved_primary_group_sid"] = primarySid; unresolved = true; }
            }
        }
        foreach (var (source, target, membership) in edges.OrderBy(e => e.Source, StringComparer.Ordinal).ThenBy(e => e.Target, StringComparer.Ordinal).ThenBy(e => e.Membership, StringComparer.Ordinal))
            records["directory_group_graph"].Add(new JsonObject { ["record_type"] = "relation", ["record_key"] = $"member-of:{source}:{target}:{membership}", ["section"] = "directory_group_graph", ["observed_at_utc"] = observed,
                ["relation_kind"] = "member_of", ["source_record_key"] = source, ["target_record_key"] = target, ["attributes"] = new JsonObject { ["membership_type"] = membership, ["source_section"] = "directory_group_graph" } });
        if (unresolved)
        { states["directory_group_graph"] = "partial"; records["directory_group_graph"].Add(Quality("quality:directory_group_links_unresolved", "directory_group_graph", "directory_group_links_unresolved", "Unresolved references or incomplete member ranges were retained.")); }

        var surveys = Flag(flags["exact_last_logon"]) ? Rows(raw["surveys"]).ToArray() : [];
        var successful = surveys.Where(s => Text(s["status"]) == "complete").ToArray(); var failed = surveys.Where(s => Text(s["status"]) != "complete").Select(s => Text(s["dc"])).ToArray();
        if (!Flag(flags["exact_last_logon"])) states["directory_exact_logon"] = "skipped";
        else if (failed.Length > 0 || successful.Length == 0) states["directory_exact_logon"] = successful.Length > 0 ? "partial" : "failed";
        foreach (var (record, _) in objects.Values)
        {
            if (Text(record["identity"]!["kind"]) is not ("ad_user" or "ad_computer")) continue;
            var guid = Text(record["identity"]!["object_guid"]); var max = successful.Select(s => Int(s["values"]?[guid])).DefaultIfEmpty(0).Max();
            var exactUtc = Utc(JsonValue.Create(max));
            var exact = new JsonObject { ["exact_last_logon_utc"] = exactUtc,
                ["exact_last_logon_status"] = !Flag(flags["exact_last_logon"]) ? "not_collected" : failed.Length > 0 && successful.Length > 0 ? "partial" : successful.Length == 0 ? "failed" : exactUtc is not null ? "observed" : "no_record",
                ["exact_last_logon_discovered_dc_count"] = surveys.Length, ["exact_last_logon_successful_dc_count"] = successful.Length, ["exact_last_logon_failed_dcs"] = Array(failed.Take(256)) };
            var copy = (JsonObject)record.DeepClone(); copy["record_key"] = Text(record["record_key"]) + ":exact-logon"; copy["section"] = "directory_exact_logon"; copy["attributes"] = exact;
            records["directory_exact_logon"].Add(copy);
            foreach (var (key, value) in exact) record["attributes"]![key] = Copy(value);
        }
        var optional = raw["optional"];
        foreach (var (record, _) in objects.Values)
        {
            if (Text(record["identity"]!["kind"]) != "ad_computer") continue;
            var attrs = record["attributes"]!; var guid = Text(record["identity"]!["object_guid"]);
            if (Flag(flags["dns"])) attrs["ip_addresses"] = Array(Rows(optional?["dns"]?["values"]?[guid]?["value"]).Take(256).Select(n => System.Net.IPAddress.Parse(Text(n)).ToString()));
            if (Flag(flags["inventory"]))
            {
                var inventory = optional?["inventory"]?["values"]?[guid]; attrs["technical_inventory_status"] = Text(inventory?["status"], "not_evaluated"); attrs["technical_inventory_observed_at_utc"] = observed;
                attrs["logical_disks"] = Array(Rows(inventory?["value"]).Take(64).Select(item => CanonicalJson.Serialize(new JsonObject(item.AsObject().Where(p => new[] { "device_id", "size", "free_space" }.Contains(p.Key)).Select(p => KeyValuePair.Create(p.Key, Copy(p.Value)))))));
            }
        }
        var refs = new Dictionary<string, List<string>> { ["privileged_membership"] = [], ["vpn_membership"] = [] };
        foreach (var reference in Rows(cfg["groups"]).Select(n => Text(n)))
        {
            var parts = reference.Split(':', 2); var area = parts[0]; refs[area == "vpn" ? "vpn_membership" : "privileged_membership"].Add(area is "vpn" or "privileged" ? parts.ElementAtOrDefault(1) ?? "" : reference);
        }
        string? Resolve(string reference) => bySid.GetValueOrDefault(reference) ?? byDn.GetValueOrDefault(reference);
        foreach (var (section, references) in refs)
        {
            if (references.Count == 0) { states[section] = "skipped"; continue; }
            var targets = new HashSet<string>();
            foreach (var reference in references) if (Resolve(reference) is { } target) targets.Add(target); else states[section] = "partial";
            var pending = new Stack<string>(targets.Order(StringComparer.Ordinal)); var selected = new List<JsonObject>();
            while (pending.TryPop(out var target))
            {
                foreach (var relation in records["directory_group_graph"].Where(r => Text(r["record_type"]) == "relation" && Text(r["target_record_key"]) == target))
                {
                    selected.Add(relation); var source = Text(relation["source_record_key"]);
                    if (Text(objects[source].Record["identity"]!["kind"]) == "ad_group" && targets.Add(source)) pending.Push(source);
                }
            }
            var keys = targets.Concat(selected.Select(r => Text(r["source_record_key"]))).Distinct().Order(StringComparer.Ordinal);
            foreach (var key in keys)
            {
                var record = (JsonObject)objects[key].Record.DeepClone(); record["section"] = section;
                record["attributes"]!.AsObject().Remove("attribute_states"); record["attributes"]!.AsObject().Remove("computer_reference_attribute_states"); records[section].Add(record);
            }
            foreach (var relation in selected) { var record = (JsonObject)relation.DeepClone(); record["section"] = section; record["attributes"]!["source_section"] = section; records[section].Add(record); }
            if (states["directory_group_graph"] != "complete") states[section] = "partial";
        }
        if (masked) records["directory_accounts"].Add(Quality("quality:sensitive_fields_masked", "directory_accounts", "sensitive_fields_masked", "Unallowlisted source fields were excluded before persistence."));
        var families = new Dictionary<string, SnapshotFamily>();
        foreach (var family in policy.Families)
        {
            if (family == "computers_v6")
            {
                var snapshot = ComputerSnapshot.Normalize(objects.Values.Select(o => o.Record).Where(r => Text(r["identity"]!["kind"]) == "ad_computer"), cfg, observed, Text(raw["query_dc"], dns), searchBase, optional, newId);
                families[family] = new(snapshot, snapshot["objects"]!.AsArray().Count); continue;
            }
            var sections = Sections[family]; var scope = new JsonObject { ["search_base"] = searchBase, ["collection_profile"] = Profiles[family], ["privileged_group_sids"] = new JsonArray(), ["vpn_group_sids"] = new JsonArray() };
            foreach (var (section, scopeKey) in new[] { ("privileged_membership", "privileged_group_sids"), ("vpn_membership", "vpn_group_sids") })
            {
                if (!sections.Contains(section)) continue;
                var roots = refs[section].Select(Resolve).ToHashSet();
                scope[scopeKey] = Array(records[section].Where(r => Text(r["record_type"]) == "entity" && roots.Contains(Text(r["record_key"])) && r["identity"]?["object_sid"] is not null).Select(r => Text(r["identity"]!["object_sid"])).Distinct().Order(StringComparer.Ordinal));
                if (scope[scopeKey]!.AsArray().Count == 0 && refs[section].Count > 0) { states[section] = "failed"; records[section] = []; }
            }
            if (family == "ad_context_base") scope["computer_membership_collected"] = states["directory_group_graph"] == "complete";
            var familyRecords = Array(sections.SelectMany(s => records[s]));
            var sectionRows = new JsonArray(sections.Select(s => (JsonNode)new JsonObject { ["name"] = s, ["status"] = states[s], ["record_count"] = records[s].Count, ["duration_ms"] = 0,
                ["error_code"] = states[s] == "complete" ? null : states[s] == "skipped" ? "not_collected" : "collection_incomplete" }).ToArray());
            families[family] = new(Bundle(cfg, observed, newId().ToString(), scope, familyRecords, sectionRows), familyRecords.Count);
        }
        var attributeLimit = families.Where(p => p.Key != "computers_v6").SelectMany(p => Rows(p.Value.Data["records"])).SelectMany(r => r["attributes"] is JsonObject a ? a.Select(p => p.Value) : [])
            .Any(n => JsonRead.TryString(n, out var s) && s.Length > 4096 || n is JsonArray a && (a.Count > 256 || a.Any(v => !JsonRead.TryString(v, out var text) || text.Length > 4096)));
        if (attributeLimit || families.Values.Sum(f => f.Count) > policy.Number("max_objects") || families.Where(p => p.Key != "computers_v6").Sum(p => CanonicalJson.ToBytes(p.Value.Data).Length) > policy.Number("max_bytes"))
        {
            foreach (var (family, info) in families.ToArray())
            {
                var data = info.Data;
                if (family == "computers_v6")
                {
                    data["objects"] = new JsonArray(); var meta = data["metadata"]!; meta["object_count"] = 0; meta["collection_status"] = "failed"; meta["errors"] = new JsonArray("agent_ad_size_limit");
                    Rows(meta["sources"]).First(s => Text(s["name"]) == "ad")["status"] = "partial";
                }
                else
                {
                    data["records"] = new JsonArray(); data["mode"] = "targeted"; data["scope"]!["privileged_group_sids"] = new JsonArray(); data["scope"]!["vpn_group_sids"] = new JsonArray(); data["scope"]!["computer_membership_collected"] = false;
                    foreach (var s in Rows(data["sections"])) { s["status"] = Text(s["name"]) is "privileged_membership" or "vpn_membership" || Text(s["status"]) == "skipped" ? "skipped" : "partial"; s["error_code"] = "agent_ad_size_limit"; s["record_count"] = 0; }
                }
                families[family] = new(data, 0);
            }
            if (families.Where(p => p.Key != "computers_v6").Sum(p => CanonicalJson.ToBytes(p.Value.Data).Length) > policy.Number("max_bytes")) throw new AgentException("agent_ad_size_limit");
        }
        return families;
    }

    private static (List<string>, bool) Members(JsonObject props)
    {
        if (props.ContainsKey("member")) return (Values(props["member"]).Select(n => Text(n)).ToList(), true);
        var ranges = props.Select(p => (Match: Regex.Match(p.Key, @"\Amember;range=(\d+)-(\d+|\*)\z"), p.Value)).Where(p => p.Match.Success).OrderBy(p => int.Parse(p.Match.Groups[1].Value)).ToArray();
        if (ranges.Length == 0) return ([], true);
        var members = new List<string>(); var offset = 0; var terminal = false;
        foreach (var (match, value) in ranges)
        {
            var start = int.Parse(match.Groups[1].Value); var end = match.Groups[2].Value;
            if (start != offset || terminal) return (members, false);
            var values = Values(value).Select(n => Text(n)).ToArray(); members.AddRange(values); terminal = end == "*";
            if (!terminal && values.Length != int.Parse(end) - start + 1) return (members, false);
            offset = start + values.Length;
        }
        return (members, terminal);
    }
}
