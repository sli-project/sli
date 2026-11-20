using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using static Sli.Server.Ad.AdJson;

namespace Sli.Server.Ad;

public static class AdUsersSnapshot
{
    static readonly JsonObject Attributes = JsonNode.Parse(new StreamReader(typeof(AdUsersSnapshot).Assembly.GetManifestResourceStream("Sli.Server.Ad.user-attributes.json")!).ReadToEnd())!.AsObject();
    static string State(string? value) => value switch { "complete" => "observed", "partial" => "partial", "failed" => "failed", _ => "not_collected" };
    static JsonObject Source(string status, string source, string? observed, JsonNode? value = null, string? detail = null, JsonNode? coverage = null) => new() { ["status"] = status, ["source"] = source, ["observed_at"] = observed, ["value"] = value?.DeepClone(), ["detail"] = detail, ["error"] = null, ["coverage"] = coverage?.DeepClone() };
    public static string Ou(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn)) return "Расположение не получено";
        var parts = Regex.Split(dn, @"(?<!\\),").Skip(1).Select(s => s.Trim()).Where(s => s.StartsWith("OU=", StringComparison.OrdinalIgnoreCase) || s.StartsWith("CN=", StringComparison.OrdinalIgnoreCase)).Select(s => s[3..].Replace("\\,", ",").Trim()).Reverse();
        string value = string.Join(" / ", parts); return value.Length == 0 ? "Корень домена" : value;
    }
    public static JsonObject Build(IReadOnlyDictionary<string, JsonObject> bundles, long domain, string dns, IReadOnlyDictionary<string, long> ids)
    {
        var baseBundle = bundles["ad_context_base"]; string observed = baseBundle.Text("observed_at_utc")!, version = baseBundle.Text("source_pack_version")!;
        var sections = baseBundle["sections"]!.AsArray().ToDictionary(s => s!.Text("name")!, s => State(s!.Text("status")));
        var allRecords = bundles.Values.SelectMany(b => b["records"]!.AsArray()).OfType<JsonObject>().ToArray();
        var entities = allRecords.Where(r => r.Text("record_type") == "entity").ToArray();
        long Id(JsonObject r) => ids[r["identity"]!.Text("object_guid")!];
        var merged = new Dictionary<long, JsonObject>();
        foreach (var r in entities.Where(r => r.Text("section") is "directory_accounts" or "directory_group_graph" or "directory_exact_logon"))
        {
            long id = Id(r); if (!merged.TryGetValue(id, out var attrs)) merged[id] = attrs = new();
            foreach (var member in r["attributes"]!.AsObject()) if (member.Key != "display_name" || r.Text("section") == "directory_accounts") attrs[member.Key] = member.Value?.DeepClone();
        }
        var baseEntities = baseBundle["records"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("record_type") == "entity").ToDictionary(r => r.Text("record_key")!);
        var graphRecords = entities.Where(r => r.Text("section") == "directory_group_graph" && r["identity"]!.Text("kind") == "ad_group").DistinctBy(Id).OrderBy(Id).ToArray();
        var references = new Dictionary<long, JsonObject>();
        var watch = (bundles.GetValueOrDefault("ad_privileged_membership")?["records"] as JsonArray ?? []).OfType<JsonObject>().Where(r => r.Text("record_type") == "relation").Select(r => r.Text("target_record_key")!).Where(baseEntities.ContainsKey).Select(k => Id(baseEntities[k])).ToHashSet();
        foreach (var r in graphRecords)
        {
            long id = Id(r); var a = r["attributes"]!; var identity = r["identity"]!; string? sid = identity.Text("object_sid");
            bool standard = sid is not null && (Regex.IsMatch(sid, @"\AS-1-5-21-\d+-\d+-\d+-(512|518|519|520)\z", RegexOptions.IgnoreCase) || Regex.IsMatch(sid, @"\AS-1-5-32-(544|548|549|550|551)\z", RegexOptions.IgnoreCase) || sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && string.Equals(a.Text("sam_account_name"), "dnsadmins", StringComparison.OrdinalIgnoreCase));
            references[id] = Obj(new { id = "group:" + id, entityId = id, objectGuid = identity.Text("object_guid"), sid, name = a.Text("display_name") ?? a.Text("sam_account_name") ?? id.ToString(), samAccountName = a.Text("sam_account_name"), distinguishedName = a.Text("distinguished_name"), canonicalName = a.Text("canonical_name"), category = a.Text("group_category"), scope = a.Text("group_scope"), watchGroup = watch.Contains(id) || standard });
        }
        var userEdges = new Dictionary<long, List<(long Target, string Type)>>(); var parentEdges = new Dictionary<long, List<long>>();
        foreach (var r in baseBundle["records"]!.AsArray().OfType<JsonObject>().Where(r => r.Text("record_type") == "relation"))
        {
            var source = baseEntities[r.Text("source_record_key")!]; var target = baseEntities[r.Text("target_record_key")!]; long from = Id(source), to = Id(target);
            if (source["identity"]!.Text("kind") == "ad_user") { if (!userEdges.ContainsKey(from)) userEdges[from] = []; userEdges[from].Add((to, r["attributes"]!.Text("membership_type") ?? "direct")); }
            if (source["identity"]!.Text("kind") == "ad_group") { if (!parentEdges.ContainsKey(from)) parentEdges[from] = []; parentEdges[from].Add(to); }
        }
        var groups = new List<JsonObject>();
        foreach (var r in graphRecords)
        {
            long id = Id(r); var group = (JsonObject)references[id].DeepClone(); group["parentGroupIds"] = Array((parentEdges.GetValueOrDefault(id) ?? []).Where(references.ContainsKey).Order().Select(p => "group:" + p));
            group["unresolvedParentDns"] = r["attributes"]!["unresolved_parent_dns"]?.DeepClone() ?? new JsonArray();
            group["sourceState"] = Source(sections["directory_group_graph"], "directory_group_graph", observed, detail: sections["directory_group_graph"] == "partial" ? "Граф ограничен или содержит неразрешённые внешние ссылки." : null); groups.Add(group);
        }
        var users = new List<JsonObject>();
        var directory = entities.Where(r => r.Text("section") == "directory_accounts" && r["identity"]!.Text("kind") == "ad_user").DistinctBy(Id).ToArray();
        foreach (var r in directory)
        {
            long id = Id(r); var a = merged[id]; var identity = r["identity"]!; string sam = a.Text("sam_account_name") ?? r.Text("record_key")!.Split('\\')[^1]; string name = r["attributes"]!.Text("display_name") ?? a.Text("display_name") ?? sam;
            var row = Obj(new { id = "user:" + id, entityId = id, objectGuid = identity.Text("object_guid") ?? "entity:" + id, domainId = domain, sid = identity.Text("object_sid"), displayName = name, name, samAccountName = sam, distinguishedName = a.Text("distinguished_name"), ou = Ou(a.Text("distinguished_name")), domainName = dns });
            foreach (var (field, names) in Attributes)
            {
                JsonNode? value = names!.AsArray().Select(n => a[n!.GetValue<string>()]).FirstOrDefault(n => n is not null);
                row[field] = value?.DeepClone();
            }
            foreach (string field in new[] { "proxyAddresses", "otherTelephones", "objectClasses", "servicePrincipalNames" }) row[field] ??= new JsonArray();
            foreach (var (field, attr) in new[] { ("enabled", "enabled"), ("lockedOut", "locked_out"), ("passwordLastSet", "password_last_set_utc"), ("passwordNeverExpires", "password_never_expires"), ("department", "department"), ("title", "title"), ("accountExpirationDate", "account_expiration_utc") }) row[field] = a[attr]?.DeepClone();
            row["whenCreated"] = a["when_created_utc"]?.DeepClone(); row["whenChanged"] = (a["when_changed_utc"] ?? a["modified_utc"])?.DeepClone(); row["lastLogonTimestamp"] = (a["last_logon_timestamp_utc"] ?? a["last_logon_utc"])?.DeepClone();
            row["mail"] = (a["mail"] ?? a["email"])?.DeepClone();
            var starts = (userEdges.GetValueOrDefault(id) ?? []).OrderBy(e => e.Type == "primary" ? 0 : 1).ThenBy(e => e.Target).ToArray();
            row["memberships"] = Memberships(id, name, a, starts, parentEdges, references, sections["directory_group_graph"]);
            var privileged = new List<JsonObject>();
            foreach (var edge in bundles["ad_privileged_membership"]["records"]!.AsArray().OfType<JsonObject>().Where(e => e.Text("record_type") == "relation" && baseEntities.TryGetValue(e.Text("source_record_key")!, out var from) && Id(from) == id))
            {
                var group = baseEntities[edge.Text("target_record_key")!]; privileged.Add(Obj(new { group_id = Id(group), group = group["attributes"]!.Text("display_name"), relation = "direct", basis = "privileged_membership" }));
            }
            row["privilegedMemberships"] = Array(privileged);
            JsonObject? manager = null; string managerStatus;
            if (a.Text("manager") is {} dn)
            {
                var found = directory.FirstOrDefault(m => string.Equals(merged[Id(m)].Text("distinguished_name"), dn, StringComparison.OrdinalIgnoreCase));
                if (found is not null) { var ma = merged[Id(found)]; manager = Obj(new { id = "user:" + Id(found), entityId = Id(found), objectGuid = found["identity"]!.Text("object_guid"), name = ma.Text("display_name") ?? ma.Text("sam_account_name") ?? Id(found).ToString(), samAccountName = ma.Text("sam_account_name"), distinguishedName = ma.Text("distinguished_name") }); managerStatus = "observed"; }
                else { manager = Obj(new { name = (string?)null, distinguishedName = dn }); managerStatus = sections["directory_accounts"] == "partial" ? "partial" : "no_record"; }
            }
            else managerStatus = Version.TryParse(version, out var v) && v >= new Version(0, 8, 0) ? "not_applicable" : "not_collected";
            row["manager"] = manager;
            row["effectivePasswordPolicy"] = a.Text("effective_password_policy_dn") is not null || a.Text("effective_password_policy_name") is not null ? Obj(new { name = a.Text("effective_password_policy_name"), distinguishedName = a.Text("effective_password_policy_dn"), source = a.Text("effective_password_policy_source") }) : null;
            string password = a.Text("password_expiry_status") ?? (Version.TryParse(version, out var ver) && ver >= new Version(0, 8, 0) ? "missing_in_source" : "not_collected");
            string exact = a.Text("exact_last_logon_status") ?? sections["directory_exact_logon"];
            row["sourceStates"] = new JsonObject {
                ["directory"] = Source(sections["directory_accounts"], "directory_accounts", observed, detail: "source pack " + version),
                ["group_graph"] = Source(row["memberships"]!.Text("status")!, "directory_group_graph", observed, detail: row["memberships"]!.Text("status") == "partial" ? "Прямые, primary и вложенные связи разделены; неполные пути перечислены отдельно." : null),
                ["exact_last_logon"] = Source(exact, "lastLogon across discovered DCs", observed, a["exact_last_logon_utc"], coverage: Obj(new { discovered_dc_count = a["exact_last_logon_discovered_dc_count"]?.DeepClone(), successful_dc_count = a["exact_last_logon_successful_dc_count"]?.DeepClone(), failed_dcs = a["exact_last_logon_failed_dcs"]?.DeepClone() ?? new JsonArray() })),
                ["password_expiry"] = Source(password, "msDS-UserPasswordExpiryTimeComputed", observed, a["password_expiry_utc"]),
                ["manager_resolution"] = Source(managerStatus, "manager DN + authorized directory user index", observed, manager)
            };
            row["collectionErrors"] = new JsonArray(); users.Add(row);
        }
        string Aggregate(string field)
        { var states = users.Select(u => u["sourceStates"]![field]!.Text("status")).ToArray(); return states.Length == 0 || states.All(s => s == "not_collected") ? "not_collected" : states.All(s => s == "failed") ? "failed" : states.All(s => s is "observed" or "not_applicable") ? "observed" : "partial"; }
        var sources = new JsonArray(
            Obj(new { name = "directory", status = sections["directory_accounts"], observed_at = observed, detail = $"AD attributes; source pack {version}." }),
            Obj(new { name = "group_graph", status = Aggregate("group_graph"), observed_at = observed, detail = "Глубина обхода ограничена 16; циклы и нерешённые ссылки сохраняются." }),
            Obj(new { name = "exact_last_logon", status = sections["directory_exact_logon"], observed_at = observed, detail = "Максимум lastLogon по всем успешно опрошенным DC; отдельный суточный цикл." }),
            Obj(new { name = "password_expiry", status = Aggregate("password_expiry"), observed_at = observed, detail = "msDS-UserPasswordExpiryTimeComputed; resultant PSO указывается только при фактическом наличии." }),
            Obj(new { name = "manager_resolution", status = Aggregate("manager_resolution"), observed_at = observed }));
        string status = users.Count > 0 && sources.All(s => s!.Text("status") == "observed") ? "complete" : "partial";
        var coverage = Obj(new { domains = new[] { new { domain_id = domain, domain_name = dns } }, latest_observed_at_utc = observed });
        var metadata = Obj(new { schema_version = "sli.ad-users.snapshot/1.0", collector_version = "sli/users-v2-production-adapter/2", snapshot_id = "live:" + observed, label = "Текущий серверный снимок SLI", started_at = observed, completed_at = observed, observed_at = observed, query_dc = (string?)null, domain_dns = dns, domain_dn = (string?)null, forest_dns = (string?)null, search_base = "разрешённая область домена SLI", collection_status = status, user_count = users.Count, group_count = groups.Count, watch_groups = groups.Where(g => g["watchGroup"]!.GetValue<bool>()), sources, contract_id = "sli.users-report.v2", report_key = "ad.users.v2", coverage, limitations = new string[0] });
        return new JsonObject { ["metadata"] = metadata, ["groups"] = Array(groups), ["users"] = Array(users), ["collectionErrors"] = new JsonArray() };
    }
    static JsonObject Memberships(long user, string name, JsonObject attrs, (long Target, string Type)[] starts, Dictionary<long, List<long>> parents, Dictionary<long, JsonObject> refs, string graphStatus)
    {
        var unresolved = (attrs["unresolved_group_dns"] as JsonArray ?? []).Select(n => n!.ToString()).ToHashSet(); if (attrs.Text("unresolved_primary_group_sid") is {} primarySid) unresolved.Add(primarySid);
        bool incomplete = graphStatus != "observed" || unresolved.Count > 0;
        var effective = new SortedDictionary<long, JsonObject>(); var paths = new SortedDictionary<long, JsonObject>(); var depths = new Dictionary<long, int>();
        var queue = new Queue<(long Group, string Relation, long[] Path)>();
        foreach (var edge in starts) queue.Enqueue((edge.Target, edge.Type, [edge.Target]));
        JsonObject Reference(long id, string relation) { var r = (JsonObject)refs[id].DeepClone(); r["relation"] = relation; return r; }
        while (queue.TryDequeue(out var step))
        {
            if (!refs.ContainsKey(step.Group)) { incomplete = true; unresolved.Add("group:" + step.Group); continue; }
            if (depths.TryGetValue(step.Group, out int depth) && depth <= step.Path.Length) continue;
            depths[step.Group] = step.Path.Length; effective[step.Group] = Reference(step.Group, step.Relation);
            paths[step.Group] = Obj(new { groupId = "group:" + step.Group, relation = step.Relation, nodes = new[] { Obj(new { id = "user:" + user, name }) }.Concat(step.Path.Where(refs.ContainsKey).Select(id => Obj(new { id = "group:" + id, name = refs[id].Text("name") }))), source = "directory_group_graph" });
            if (effective.Count >= 2048) { incomplete = true; unresolved.Add("Достигнут предел эффективных групп пользователя."); break; }
            var next = parents.GetValueOrDefault(step.Group) ?? [];
            if (next.Count > 0 && step.Path.Length >= 16) { incomplete = true; unresolved.Add("Достигнута глубина 16: " + refs[step.Group].Text("name")); continue; }
            foreach (long parent in next.Order()) if (step.Path.Contains(parent)) { incomplete = true; unresolved.Add("Цикл групп: " + refs[step.Group].Text("name")); } else queue.Enqueue((parent, "nested", [.. step.Path, parent]));
        }
        var primary = starts.FirstOrDefault(e => e.Type == "primary");
        return new JsonObject { ["status"] = !incomplete ? "observed" : graphStatus is "not_collected" or "failed" && starts.Length == 0 && unresolved.Count == 0 ? graphStatus : "partial", ["primary"] = primary.Target > 0 && refs.ContainsKey(primary.Target) ? Reference(primary.Target, "primary") : null, ["direct"] = Array(starts.Where(e => e.Type == "direct" && refs.ContainsKey(e.Target)).Select(e => e.Target).Distinct().Order().Select(id => Reference(id, "direct"))), ["effective"] = Array(effective.Values), ["paths"] = Array(paths.Values), ["unresolved"] = Array(unresolved.Order(StringComparer.OrdinalIgnoreCase)) };
    }
}
