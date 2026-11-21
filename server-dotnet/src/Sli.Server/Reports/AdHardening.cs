using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Sli.Server.Reports;

// Evaluates saved directory facts only; callers are responsible for loading an authorized published snapshot.
public static class AdHardening
{
    public static JsonArray Evaluate(JsonObject snapshot, int servicePasswordDays = 365, int adminGroupMembers = 5, int inactiveDays = 90, int objectLimit = 20)
    {
        if (servicePasswordDays is < 1 or > 36500 || adminGroupMembers is < 1 or > 10000 || inactiveDays is < 1 or > 36500 || objectLimit is < 1 or > 1000)
            throw new ArgumentException("ad_hardening_policy_invalid");
        var result = new JsonArray();
        if (Instant(snapshot["observed_at_utc"]) is not { } at) return result;
        var objects = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var obj in ((JsonArray)snapshot["objects"]!).OfType<JsonObject>()) objects[S(obj["record_key"])] = obj;
        var children = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var node in (JsonArray)snapshot["edges"]!) {
            if (node is not JsonArray edge || edge.Count != 2) continue;
            var source = S(edge[0]); var target = S(edge[1]);
            if (!objects.ContainsKey(source) || !objects.ContainsKey(target)) continue;
            if (!children.TryGetValue(target, out var set)) children[target] = set = new(StringComparer.Ordinal);
            set.Add(source);
        }
        var members = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        foreach (var (key, obj) in objects.Where(pair => Kind(pair.Value) == "ad_group" && Protected(pair.Value))) {
            var visited = new HashSet<string>(StringComparer.Ordinal); var pending = new Stack<string>(); pending.Push(key);
            while (pending.TryPop(out var current)) if (visited.Add(current) && children.TryGetValue(current, out var next)) foreach (var item in next) pending.Push(item);
            visited.Remove(key); visited.RemoveWhere(k => Kind(objects[k]) is not ("ad_user" or "ad_computer" or "security_principal")); members[key] = visited;
        }
        var privileged = members.Values.SelectMany(x => x).ToHashSet(StringComparer.Ordinal);
        var found = new SortedDictionary<string, (HashSet<string> Keys, string Severity)>(StringComparer.Ordinal);
        void Add(string check, string key, string severity) {
            if (!found.TryGetValue(check, out var entry)) entry = (new(StringComparer.Ordinal), severity);
            entry.Keys.Add(key); if (severity == "high") entry.Severity = severity; found[check] = entry;
        }
        bool Older(JsonNode? value, int days) => Instant(value) is { } when && when <= at && at - when > TimeSpan.FromDays(days);
        var lapsEligible = new List<string>(); var lapsObserved = false;
        foreach (var (key, obj) in objects) {
            var kind = Kind(obj);
            var a = (JsonObject)obj["attributes"]!;
            if (kind == "domain" && Number(a["machine_account_quota"]) is > 0) Add("machine_account_quota", key, "low");
            if (kind == "password_policy" && Number(a["lockout_threshold"]) == 0) Add("lockout_threshold", key, "low");
            if (kind is not ("ad_user" or "ad_computer")) continue;
            var uac = Number(a["user_account_control"]); if (uac is null || (uac & 2) != 0) continue;
            var spns = Strings(a["service_principal_names"]); bool managed = Strings(a["object_classes"]).Any(x => x.Equals("msds-managedserviceaccount", StringComparison.OrdinalIgnoreCase) || x.Equals("msds-groupmanagedserviceaccount", StringComparison.OrdinalIgnoreCase));
            if (kind == "ad_user" && spns.Length > 0 && !managed) Add("spn_users", key, privileged.Contains(key) ? "high" : "medium");
            var enc = Number(a["msds_supported_encryption_types"]);
            if (kind == "ad_user" && spns.Length > 0 && enc is not null && (enc & 4) != 0 && (enc & 24) == 0) Add("rc4", key, "medium");
            bool dc = kind == "ad_computer" && (uac & 8192) != 0;
            if ((uac & 524288) != 0 && !dc) Add("unconstrained", key, "high");
            if (Strings(a["allowed_to_delegate_to"]).Any(x => new[] { "ldap", "gc", "cifs", "host", "rpcss", "mssqlsvc" }.Contains(x.Split('/')[0], StringComparer.OrdinalIgnoreCase))) Add("constrained", key, "info");
            if (kind == "ad_computer" && !dc) {
                var statuses = new[] { S(a["laps_password_expiration_status"]), S(a["legacy_laps_password_expiration_status"]) };
                if (statuses.Contains("observed")) lapsObserved = true;
                if (statuses.All(x => x is "schema_absent" or "not_returned" or "not_set")) lapsEligible.Add(key);
            }
            if (kind == "ad_user" && spns.Length > 0 && !managed && Older(a["password_last_set_utc"], servicePasswordDays)) Add("old_service_password", key, "medium");
            if (privileged.Contains(key)) {
                if ((uac & 65536) != 0) Add("privileged_nonexpiring", key, "low");
                var activity = new[] { "last_logon_timestamp_utc", "last_logon_utc", "exact_last_logon_utc" }.Select(n => Instant(a[n])).Where(x => x.HasValue).Select(x => x!.Value).ToArray();
                if (activity.Length > 0 && activity.Max() <= at && at - activity.Max() > TimeSpan.FromDays(inactiveDays)) Add("inactive_privileged", key, "high");
            }
        }
        foreach (var key in lapsEligible) Add("laps", key, "medium");
        foreach (var (key, entries) in members) if (Admin(objects[key]) && entries.Count > adminGroupMembers) Add("admin_group_size", key, "high");
        foreach (var (check, entry) in found) {
            var keys = entry.Keys.Order(StringComparer.Ordinal).ToArray(); bool allLapsMissing = check == "laps" && !lapsObserved;
            bool domainPosture = check is "machine_account_quota" or "lockout_threshold";
            var observed = domainPosture ? Instant(snapshot["posture_at"]) ?? at : at;
            var run = domainPosture ? snapshot["posture_run"] ?? snapshot["run_id"] : snapshot["run_id"];
            var labels = new JsonArray();
            if (!allLapsMissing) foreach (var key in keys.Take(objectLimit)) { var a = objects[key]["attributes"]!; var label = S(a["sam_account_name"]); if (label == "") label = S(a["display_name"]); if (label == "") label = key; labels.Add(label[..Math.Min(label.Length, 160)]); }
            var counts = new JsonArray(); if (check == "admin_group_size") foreach (var key in keys.Take(objectLimit)) counts.Add(members[key].Count);
            result.Add(new JsonObject { ["check"] = check, ["rule_code"] = "qw.ad-hardening." + check.Replace('_', '-'), ["severity"] = entry.Severity, ["count"] = keys.Length, ["objects"] = labels, ["objects_truncated"] = !allLapsMissing && keys.Length > objectLimit, ["laps_none_found"] = allLapsMissing, ["observed_at_utc"] = observed.ToUniversalTime().ToString("O"), ["domain_id"] = snapshot["domain_id"]?.DeepClone(), ["source_run_id"] = run?.DeepClone(), ["threshold"] = check switch { "old_service_password" => servicePasswordDays, "inactive_privileged" => inactiveDays, "admin_group_size" => adminGroupMembers, _ => (int?)null }, ["member_counts"] = counts });
        }
        return result;
    }
    private static string S(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : "";
    private static DateTimeOffset? Instant(JsonNode? n)
    {
        string text = S(n);
        // The frozen AD date parser ignores naive timestamps rather than assigning the host's zone.
        if (!Regex.IsMatch(text, @"\A\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\z", RegexOptions.CultureInvariant)) return null;
        return DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal, out var value) ? value : null;
    }
    private static long? Number(JsonNode? n) {
        if (n is not JsonValue v) return null;
        if (v.TryGetValue<long>(out var x) && x >= 0) return x;
        if (v.TryGetValue<int>(out var i) && i >= 0) return i;
        return null;
    }
    private static string[] Strings(JsonNode? n) => n is JsonArray a ? a.Select(S).ToArray() : [];
    private static string Kind(JsonObject o) => S(o["identity"]?["kind"]);
    private static string Sid(JsonObject o) { var sid = S(o["identity"]?["object_sid"]); return sid == "" ? S(o["attributes"]?["sid"]) : sid; }
    private static bool Admin(JsonObject o) => Regex.IsMatch(Sid(o), @"^S-1-5-21-\d+-\d+-\d+-(512|519)$|^S-1-5-32-544$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static bool Protected(JsonObject o) {
        var sid = Sid(o); var domain = Regex.Match(sid, @"^S-1-5-21-\d+-\d+-\d+-(\d+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (domain.Success) return new[] { "512", "518", "519", "520" }.Contains(domain.Groups[1].Value) || S(o["attributes"]?["sam_account_name"]).Equals("dnsadmins", StringComparison.OrdinalIgnoreCase);
        return Regex.IsMatch(sid, @"^S-1-5-32-(544|548|549|550|551)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }
}
