using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Agents.Registry;
using static Sli.Server.Agents.SnapshotPublication.AdContextBundle;

namespace Sli.Server.Agents.SnapshotPublication;

// Exact-cycle adapter: never reads a latest directory snapshot or another domain.
public static class AdUsersSnapshot
{
    private static JsonNode? Copy(JsonNode? n) => n?.DeepClone();
    private static string Status(string raw) => raw switch { "complete" => "observed", "partial" => "partial", "failed" => "failed", _ => "not_collected" };
    private static string FieldStatus(IEnumerable<string> values)
    {
        var v = values.ToArray();
        return v.Length == 0 || v.All(s => s == "not_collected") ? "not_collected" : v.All(s => s == "failed") ? "failed" : v.All(s => s is "observed" or "not_applicable") ? "observed" : "partial";
    }
    private static string? Iso(JsonNode? n) => n is null || !DateTimeOffset.TryParse(Optional(n), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var stamp) ? null : stamp.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss", CultureInfo.InvariantCulture) + (stamp.Ticks % TimeSpan.TicksPerSecond == 0 ? "" : "." + (stamp.Ticks % TimeSpan.TicksPerSecond / 10).ToString("D6", CultureInfo.InvariantCulture)) + "Z";
    private static JsonObject Source(string status, string source, string? observed, JsonNode? value = null, string? detail = null, JsonObject? coverage = null) => new() {
        ["status"] = status, ["source"] = source, ["value"] = Copy(value), ["observed_at"] = observed, ["detail"] = detail, ["error"] = null, ["coverage"] = Copy(coverage)
    };
    private static string Name(JsonObject attrs, long id) => Optional(attrs["display_name"]) ?? Optional(attrs["sam_account_name"]) ?? id.ToString(CultureInfo.InvariantCulture);
    private static bool StandardAdmin(JsonObject attrs, string? sid)
    {
        var domain = Regex.Match(sid ?? "", @"\AS-1-5-21-\d+-\d+-\d+-(\d+)\z", RegexOptions.IgnoreCase);
        if (domain.Success) return new[] { "512", "518", "519", "520" }.Contains(domain.Groups[1].Value) || UnicodeCaseFold.Fold(Optional(attrs["sam_account_name"]) ?? "") == "dnsadmins";
        var builtin = Regex.Match(sid ?? "", @"\AS-1-5-32-(\d+)\z", RegexOptions.IgnoreCase);
        return builtin.Success && new[] { "544", "548", "549", "550", "551" }.Contains(builtin.Groups[1].Value);
    }
    public static JsonObject Build(AdPreparedCycle cycle, long domain, string dns, IReadOnlyDictionary<string, long> ids)
    {
        var basis = cycle.Bundles["ad_context_base"];
        string observed = Text(basis["observed_at_utc"]), version = Text(basis["source_pack_version"]);
        var sections = basis["sections"]!.AsArray().ToDictionary(s => Text(s!["name"]), s => s!.AsObject());
        var records = basis["records"]!.AsArray().Select(r => r!.AsObject()).ToArray();
        var byKey = records.Where(r => Text(r["record_type"]) == "entity").ToDictionary(r => Text(r["record_key"]));
        long Id(JsonObject r) => ids[Text(r["identity"]!["object_guid"])];
        var groupRecords = byKey.Values.Where(r => Text(r["section"]) == "directory_group_graph" && Text(r["identity"]!["kind"]) == "ad_group").OrderBy(Id).ToArray();
        var accounts = byKey.Values.Where(r => Text(r["section"]) == "directory_accounts" && Text(r["identity"]!["kind"]) == "ad_user").ToArray();
        var watched = new HashSet<long>(); var privileged = new Dictionary<long, JsonArray>();
        foreach (var relation in cycle.Bundles["ad_privileged_membership"]["records"]!.AsArray().Where(r => Text(r!["record_type"]) == "relation")) {
            if (!byKey.TryGetValue(Text(relation!["target_record_key"]), out var target)) continue;
            long targetId = Id(target); watched.Add(targetId);
            if (byKey.TryGetValue(Text(relation["source_record_key"]), out var source) && Text(source["identity"]!["kind"]) == "ad_user") {
                long sourceId = Id(source); if (!privileged.TryGetValue(sourceId, out var list)) privileged[sourceId] = list = new JsonArray();
                var g = groupRecords.First(r => Id(r) == targetId);
                list.Add(new JsonObject { ["group_id"] = targetId, ["group"] = Copy(g["attributes"]!["display_name"]), ["relation"] = "direct", ["basis"] = "privileged_membership" });
            }
        }
        string graphStatus = Status(Text(sections["directory_group_graph"]["status"]));
        var references = new Dictionary<long, JsonObject>();
        foreach (var r in groupRecords) {
            long id = Id(r); var a = r["attributes"]!.AsObject(); string? sid = Optional(r["identity"]!["object_sid"]);
            references[id] = new JsonObject { ["id"] = $"group:{id}", ["entityId"] = id, ["objectGuid"] = Copy(r["identity"]!["object_guid"]), ["sid"] = sid, ["name"] = Name(a, id), ["samAccountName"] = Copy(a["sam_account_name"]), ["distinguishedName"] = Copy(a["distinguished_name"]), ["canonicalName"] = Copy(a["canonical_name"]), ["category"] = Copy(a["group_category"]), ["scope"] = Copy(a["group_scope"]), ["watchGroup"] = watched.Contains(id) || StandardAdmin(a, sid) };
        }
        var userEdges = new Dictionary<long, List<(long Target, string Kind)>>(); var parentEdges = new Dictionary<long, List<long>>();
        foreach (var r in records.Where(r => Text(r["record_type"]) == "relation")) {
            var source = byKey[Text(r["source_record_key"])]; long sourceId = Id(source), target = Id(byKey[Text(r["target_record_key"])]);
            if (Text(source["identity"]!["kind"]) == "ad_user") { if (!userEdges.ContainsKey(sourceId)) userEdges[sourceId] = []; userEdges[sourceId].Add((target, Optional(r["attributes"]!["membership_type"]) ?? "direct")); }
            else if (Text(source["identity"]!["kind"]) == "ad_group") { if (!parentEdges.ContainsKey(sourceId)) parentEdges[sourceId] = []; parentEdges[sourceId].Add(target); }
        }
        foreach (var list in userEdges.Values) list.Sort((a, b) => a.Kind == b.Kind ? a.Target.CompareTo(b.Target) : a.Kind == "primary" ? -1 : 1);
        foreach (var list in parentEdges.Values) list.Sort();
        var groups = new JsonArray();
        foreach (var r in groupRecords) {
            long id = Id(r); var g = (JsonObject)references[id].DeepClone();
            g["parentGroupIds"] = new JsonArray((parentEdges.GetValueOrDefault(id) ?? []).Where(references.ContainsKey).Select(p => (JsonNode?)JsonValue.Create($"group:{p}")).ToArray());
            g["unresolvedParentDns"] = Copy(r["attributes"]!["unresolved_parent_dns"]) ?? new JsonArray();
            g["sourceState"] = Source(graphStatus, "directory_group_graph", observed, detail: graphStatus == "partial" ? "Граф ограничен или содержит неразрешённые внешние ссылки." : null); groups.Add(g);
        }
        var seeds = accounts.ToDictionary(Id, r => {
            var a = r["attributes"]!.AsObject(); long id = Id(r); string sam = Optional(a["sam_account_name"]) ?? Text(r["record_key"]).Split('\\')[^1];
            return new JsonObject { ["id"] = $"user:{id}", ["entityId"] = id, ["objectGuid"] = Copy(r["identity"]!["object_guid"]), ["sid"] = Copy(r["identity"]!["object_sid"]), ["displayName"] = Optional(a["display_name"]) ?? sam, ["samAccountName"] = sam, ["distinguishedName"] = Copy(a["distinguished_name"]) };
        });
        var usersByDn = new Dictionary<string, JsonObject>(); foreach (var seed in seeds.Values) if (Optional(seed["distinguishedName"]) is string dn) usersByDn[UnicodeCaseFold.Fold(dn)] = seed;
        var users = new JsonArray(); var passwords = new List<string>(); var managers = new List<string>();
        foreach (var r in accounts) {
            long id = Id(r); var a = (JsonObject)r["attributes"]!.DeepClone();
            foreach (string section in new[] { "directory_group_graph", "directory_exact_logon" }) {
                var supplemental = records.LastOrDefault(s => Text(s["record_type"]) == "entity" && Text(s["section"]) == section && Id(s) == id);
                if (supplemental is not null) foreach (var p in supplemental["attributes"]!.AsObject()) if (p.Key != "display_name") a[p.Key] = Copy(p.Value);
            }
            var seed = seeds[id]; string directoryStatus = Status(Text(sections["directory_accounts"]["status"]));
            bool modern = Version.TryParse(version, out var v) && v >= new Version(0, 8, 0);
            string passwordStatus = Optional(a["password_expiry_status"]) ?? (modern ? "missing_in_source" : "not_collected");
            string exactStatus = Optional(a["exact_last_logon_status"]) ?? Status(Text(sections["directory_exact_logon"]["status"]));
            JsonObject? manager = null; string managerStatus;
            if (Optional(a["manager"]) is string managerDn) {
                if (usersByDn.TryGetValue(UnicodeCaseFold.Fold(managerDn), out var s)) {
                    manager = new JsonObject { ["id"] = Copy(s["id"]), ["entityId"] = Copy(s["entityId"]), ["objectGuid"] = Copy(s["objectGuid"]), ["name"] = Copy(s["displayName"]), ["samAccountName"] = Copy(s["samAccountName"]), ["distinguishedName"] = Copy(s["distinguishedName"]) }; managerStatus = "observed";
                } else { manager = new JsonObject { ["name"] = null, ["distinguishedName"] = managerDn }; managerStatus = directoryStatus == "partial" ? "partial" : "no_record"; }
            } else managerStatus = modern ? "not_applicable" : "not_collected";
            var memberships = Memberships(id, Text(seed["displayName"]), a, references, userEdges.GetValueOrDefault(id) ?? [], parentEdges, graphStatus);
            var sourceStates = new JsonObject {
                ["directory"] = Source(directoryStatus, "directory_accounts", observed, detail: $"source pack {version}"),
                ["group_graph"] = Source(Text(memberships["status"]), "directory_group_graph", observed, detail: Text(memberships["status"]) == "partial" ? "Прямые, primary и вложенные связи разделены; неполные пути перечислены отдельно." : null),
                ["exact_last_logon"] = Source(exactStatus, "lastLogon across discovered DCs", observed, JsonValue.Create(Iso(a["exact_last_logon_utc"])), coverage: new JsonObject { ["discovered_dc_count"] = Copy(a["exact_last_logon_discovered_dc_count"]), ["successful_dc_count"] = Copy(a["exact_last_logon_successful_dc_count"]), ["failed_dcs"] = Copy(a["exact_last_logon_failed_dcs"]) ?? new JsonArray() }),
                ["password_expiry"] = Source(passwordStatus, "msDS-UserPasswordExpiryTimeComputed", observed, JsonValue.Create(Iso(a["password_expiry_utc"]))),
                ["manager_resolution"] = Source(managerStatus, "manager DN + authorized directory user index", observed, manager)
            };
            var user = new JsonObject { ["id"] = Copy(seed["id"]), ["entityId"] = id, ["objectGuid"] = Copy(seed["objectGuid"]), ["domainId"] = domain, ["domainName"] = dns, ["sid"] = Copy(seed["sid"]), ["displayName"] = Copy(seed["displayName"]), ["name"] = Copy(seed["displayName"]), ["samAccountName"] = Copy(seed["samAccountName"]), ["distinguishedName"] = Copy(seed["distinguishedName"]), ["manager"] = Copy(manager), ["memberships"] = memberships, ["privilegedMemberships"] = Copy(privileged.GetValueOrDefault(id)) ?? new JsonArray(), ["sourceStates"] = sourceStates, ["collectionErrors"] = new JsonArray() };
            foreach (string mapping in "givenName:given_name surname:surname userPrincipalName:user_principal_name canonicalName:canonical_name enabled:enabled lockedOut:locked_out department:department title:title company:company office:office description:description employeeID:employee_id employeeNumber:employee_number telephoneNumber:telephone_number mobile:mobile ipPhone:ip_phone fax:fax streetAddress:street_address city:city state:state postalCode:postal_code country:country scriptPath:script_path homeDirectory:home_directory homeDrive:home_drive profilePath:profile_path passwordExpired:password_expired passwordNeverExpires:password_never_expires passwordNotRequired:password_not_required cannotChangePassword:cannot_change_password badPasswordCountAtQueryDc:bad_password_count_at_query_dc smartcardLogonRequired:smartcard_logon_required accountNotDelegated:account_not_delegated allowReversiblePasswordEncryption:allow_reversible_password_encryption trustedForDelegation:trusted_for_delegation trustedToAuthForDelegation:trusted_to_auth_for_delegation doesNotRequirePreAuth:does_not_require_preauth useDesKeyOnly:use_des_key_only adminCount:admin_count userAccountControl:user_account_control msDSSupportedEncryptionTypes:msds_supported_encryption_types".Split(' ')) { var p = mapping.Split(':'); user[p[0]] = Copy(a[p[1]]); }
            foreach (string mapping in "accountExpirationDate:account_expiration_utc whenCreated:when_created_utc whenChanged:when_changed_utc passwordLastSet:password_last_set_utc passwordExpiry:password_expiry_utc lastLogonTimestamp:last_logon_timestamp_utc exactLastLogon:exact_last_logon_utc lastBadPasswordAttempt:last_bad_password_attempt_utc".Split(' ')) { var p = mapping.Split(':'); user[p[0]] = Iso(a[p[1]] ?? (p[0] == "lastLogonTimestamp" ? a["last_logon_utc"] : p[0] == "whenChanged" ? a["modified_utc"] : null)); }
            foreach (string mapping in "proxyAddresses:proxy_addresses otherTelephones:other_telephones objectClasses:object_classes servicePrincipalNames:service_principal_names".Split(' ')) { var p = mapping.Split(':'); user[p[0]] = Copy(a[p[1]]) ?? new JsonArray(); }
            user["mail"] = Copy(a["mail"] ?? a["email"]);
            user["ou"] = Ou(Optional(a["distinguished_name"]));
            user["effectivePasswordPolicy"] = a["effective_password_policy_dn"] is null && a["effective_password_policy_name"] is null ? null : new JsonObject { ["name"] = Copy(a["effective_password_policy_name"]), ["distinguishedName"] = Copy(a["effective_password_policy_dn"]), ["source"] = Copy(a["effective_password_policy_source"]) };
            passwords.Add(passwordStatus); managers.Add(managerStatus); users.Add(user);
        }
        string directoryAggregate = Status(Text(sections["directory_accounts"]["status"])), exactAggregate = Status(Text(sections["directory_exact_logon"]["status"]));
        string graphAggregate = graphStatus is "not_collected" or "failed" ? graphStatus : users.Any(u => Text(u!["memberships"]!["status"]) == "partial") ? "partial" : graphStatus;
        var sources = new JsonArray();
        JsonObject Row(string name, string state, string? detail = null, bool includeDetail = true) { var row = new JsonObject { ["name"] = name, ["status"] = state, ["observed_at"] = observed }; if (includeDetail) row["detail"] = detail; return row; }
        sources.Add(Row("directory", directoryAggregate, $"AD attributes; source pack {version}."));
        sources.Add(Row("group_graph", graphAggregate, "Глубина обхода ограничена 16; циклы и нерешённые ссылки сохраняются."));
        sources.Add(Row("exact_last_logon", exactAggregate, "Максимум lastLogon по всем успешно опрошенным DC; отдельный суточный цикл."));
        sources.Add(Row("password_expiry", FieldStatus(passwords), "msDS-UserPasswordExpiryTimeComputed; resultant PSO указывается только при фактическом наличии."));
        sources.Add(Row("manager_resolution", FieldStatus(managers), includeDetail: false));
        var coverage = new JsonObject { ["domains"] = new JsonArray(new JsonObject { ["domain_id"] = domain, ["domain_name"] = dns }), ["latest_observed_at_utc"] = observed };
        return new JsonObject { ["metadata"] = new JsonObject { ["schema_version"] = "sli.ad-users.snapshot/1.0", ["collector_version"] = "sli/users-v2-production-adapter/2", ["snapshot_id"] = $"live:{observed}", ["label"] = "Текущий серверный снимок SLI", ["started_at"] = observed, ["completed_at"] = observed, ["observed_at"] = observed, ["query_dc"] = null, ["domain_dns"] = dns, ["domain_dn"] = null, ["forest_dns"] = null, ["search_base"] = "разрешённая область домена SLI", ["collection_status"] = users.Count > 0 && sources.All(s => Text(s!["status"]) == "observed") ? "complete" : "partial", ["user_count"] = users.Count, ["group_count"] = groups.Count, ["watch_groups"] = new JsonArray(groups.Where(g => g!["watchGroup"]!.GetValue<bool>()).Select(Copy).ToArray()), ["sources"] = sources, ["contract_id"] = "sli.users-report.v2", ["report_key"] = "ad.users.v2", ["coverage"] = coverage, ["limitations"] = new JsonArray() }, ["groups"] = groups, ["users"] = users, ["collectionErrors"] = new JsonArray() };
    }
    private static string Ou(string? dn)
    {
        if (dn is null) return "Расположение не получено";
        var ous = Regex.Split(dn, @"(?<!\\),").Skip(1).Where(s => s.Trim().StartsWith("OU=", StringComparison.OrdinalIgnoreCase) || s.Trim().StartsWith("CN=", StringComparison.OrdinalIgnoreCase)).Select(s => s.Trim()[3..].Replace(@"\,", ",").Trim()).Reverse().ToArray();
        return ous.Length == 0 ? "Корень домена" : string.Join(" / ", ous);
    }
    private static JsonObject Memberships(long user, string name, JsonObject attrs, Dictionary<long, JsonObject> refs, List<(long Target, string Kind)> starts, Dictionary<long, List<long>> parents, string graphStatus)
    {
        JsonObject Reference(long id, string relation) { var value = (JsonObject)refs[id].DeepClone(); value["relation"] = relation; return value; }
        long? primary = starts.Where(s => s.Kind == "primary").Select(s => (long?)s.Target).FirstOrDefault();
        var directIds = starts.Where(s => s.Kind == "direct").Select(s => s.Target).Distinct().Order().ToArray();
        var unresolved = (attrs["unresolved_group_dns"] as JsonArray ?? new()).Select(Text).ToList(); if (Optional(attrs["unresolved_primary_group_sid"]) is string missing) unresolved.Add(missing);
        bool incomplete = graphStatus != "observed" || unresolved.Count > 0;
        var queue = new Queue<(long Id, string Relation, long[] Path)>(); if (primary is long p) queue.Enqueue((p, "primary", [p])); foreach (long id in directIds) queue.Enqueue((id, "direct", [id]));
        var depths = new Dictionary<long, int>(); var effective = new SortedDictionary<long, JsonObject>(); var paths = new SortedDictionary<long, JsonObject>();
        while (queue.TryDequeue(out var entry)) {
            if (!refs.ContainsKey(entry.Id)) { incomplete = true; unresolved.Add($"group:{entry.Id}"); continue; }
            int depth = entry.Path.Length; if (depths.TryGetValue(entry.Id, out int old) && old <= depth) continue; depths[entry.Id] = depth;
            effective[entry.Id] = Reference(entry.Id, entry.Relation);
            paths[entry.Id] = new JsonObject { ["groupId"] = Copy(refs[entry.Id]["id"]), ["relation"] = entry.Relation, ["nodes"] = new JsonArray(new[] { new JsonObject { ["id"] = $"user:{user}", ["name"] = name } }.Concat(entry.Path.Where(refs.ContainsKey).Select(id => new JsonObject { ["id"] = Copy(refs[id]["id"]), ["name"] = Copy(refs[id]["name"]) })).Select(x => (JsonNode?)x).ToArray()), ["source"] = "directory_group_graph" };
            if (effective.Count >= 2048) { incomplete = true; unresolved.Add("Достигнут предел эффективных групп пользователя."); break; }
            var next = parents.GetValueOrDefault(entry.Id) ?? [];
            if (next.Count > 0 && depth >= 16) { incomplete = true; unresolved.Add($"Достигнута глубина 16: {Text(refs[entry.Id]["name"])}"); continue; }
            foreach (long parent in next) {
                if (entry.Path.Contains(parent)) { incomplete = true; unresolved.Add($"Цикл групп: {Text(refs[entry.Id]["name"])}"); continue; }
                queue.Enqueue((parent, "nested", [.. entry.Path, parent]));
            }
        }
        return new JsonObject { ["status"] = !incomplete ? "observed" : graphStatus is "not_collected" or "failed" && starts.Count == 0 && unresolved.Count == 0 ? graphStatus : "partial", ["primary"] = primary is long id0 && refs.ContainsKey(id0) ? Reference(id0, "primary") : null, ["direct"] = new JsonArray(directIds.Where(refs.ContainsKey).Select(id => (JsonNode?)Reference(id, "direct")).ToArray()), ["effective"] = new JsonArray(effective.Values.Select(v => (JsonNode?)v).ToArray()), ["paths"] = new JsonArray(paths.Values.Select(v => (JsonNode?)v).ToArray()), ["unresolved"] = new JsonArray(unresolved.Distinct().OrderBy(UnicodeCaseFold.Fold, StringComparer.Ordinal).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()) };
    }
}
