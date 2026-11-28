using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Server.Compatibility;
using Sli.Server.Agents.Registry;

namespace Sli.Server.InstallationSetup;

public static class InstallationSettings
{
    public static readonly IReadOnlyDictionary<string, JsonObject> Specs = Load();
    private static IReadOnlyDictionary<string, JsonObject> Load()
    {
        using var stream = typeof(InstallationSettings).Assembly.GetManifestResourceStream("Sli.Installation.settings-catalog.json")!;
        return JsonNode.Parse(stream)!.AsArray().OfType<JsonObject>().ToDictionary(o => o["key"]!.GetValue<string>());
    }
    public static string Dns(string value)
    {
        string text = PythonText.Strip(value).ToLowerInvariant();
        if (text.Length > 253 || !InstallationPackages.Match(text, "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"))
            throw new InstallationException("value_must_be_dns_name");
        return text;
    }
    public static string? Netbios(string value)
    {
        string text = PythonText.Strip(value).ToUpperInvariant();
        if (text.Length == 0) return null;
        if (text.Length > 15 || !InstallationPackages.Match(text, "[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?"))
            throw new InstallationException("netbios_must_be_up_to_15_letters_digits_hyphen");
        return text;
    }
    public static string Normalize(string key, string value)
    {
        if (!Specs.ContainsKey(key)) throw new InstallationException("unknown_setting", 404);
        if (key == "reports.domain_fqdn") return Dns(value);
        if (key == Agents.SnapshotPublication.AdSnapshotSchedule.SettingKey)
        {
            string zone = PythonText.Strip(value);
            if (zone == Agents.SnapshotPublication.AdSnapshotSchedule.UseHost || Agents.SnapshotPublication.AdSnapshotSchedule.FindIanaZone(zone) is not null)
                return zone;
            throw new InstallationException("invalid_server_timezone");
        }
        if (key == "security.working_time") return WorkingTime(value);
        if (key == "workstations.logon_policy") return LogonPolicy(value);
        if (key == "ad.service_account_exceptions") return Json(Exceptions(value));
        if (key == "file_audit.excluded_accounts")
        {
            try
            {
                if (JsonNode.Parse(value) is JsonArray { Count: <= 100 } accounts
                    && accounts.All(item => item is JsonValue sid && sid.TryGetValue<string>(out var text)
                        && text.Length <= 184 && InstallationPackages.Match(text, "S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+"))
                    && accounts.Select(item => item!.ToString()).Distinct(StringComparer.Ordinal).Count() == accounts.Count)
                    return Json(accounts);
            }
            catch (JsonException) { }
            throw new InstallationException("invalid_plugin_setting_value");
        }
        string text = PythonText.Strip(value);
        int min = key == "ad.snapshot_history_days" ? 7 : 1;
        int max = key.StartsWith("windows_auth.", StringComparison.Ordinal) ? 744 : 3650;
        string error = key switch { "ad.snapshot_history_days" => "ad_snapshot_history_days_must_be_7_to_3650",
            "workstations.evidence_retention_days" => "workstation_retention_days_invalid",
            _ => max == 744 ? "value_must_be_integer_1_744" : "value_must_be_days_1_3650" };
        if (!InstallationPackages.Match(text, "[0-9]+") || !int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out int n) || n < min || n > max)
            throw new InstallationException(error);
        return n.ToString(CultureInfo.InvariantCulture);
    }
    public static JsonArray Exceptions(string raw)
    {
        const string error = "ad_service_account_exceptions_invalid";
        try
        {
            var array = JsonNode.Parse(raw) as JsonArray;
            if (array is null || array.Count > 1000) throw new InstallationException(error);
            var entries = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
            foreach (var item in array)
            {
                var entry = item is JsonValue v && v.TryGetValue<string>(out var sidValue) ? new JsonObject { ["sid"] = sidValue } : item?.DeepClone() as JsonObject;
                if (entry is null || entry.Any(p => p.Key is not ("sid" or "excluded_by" or "excluded_at"))) throw new InstallationException(error);
                string sid = PythonText.Strip(InstallationPackages.Text(entry["sid"])).ToUpperInvariant();
                if (!InstallationPackages.Match(sid, @"S-1-5-21-\d+-\d+-\d+-\d+") || entries.ContainsKey(sid)) throw new InstallationException(error);
                entry["sid"] = sid;
                entries[sid] = entry;
            }
            return new JsonArray(entries.Values.Cast<JsonNode?>().ToArray());
        }
        catch (JsonException) { throw new InstallationException(error); }
    }
    public static string AttributeExceptions(string value, string previous, string actor)
    {
        var prior = Exceptions(previous).OfType<JsonObject>().ToDictionary(e => InstallationPackages.Text(e["sid"]));
        var result = new JsonArray();
        foreach (var entry in Exceptions(value).OfType<JsonObject>())
        {
            string sid = InstallationPackages.Text(entry["sid"]);
            prior.TryGetValue(sid, out var old);
            result.Add(new JsonObject { ["sid"] = sid, ["excluded_by"] = Truthy(old?["excluded_by"]) ? old!["excluded_by"]!.DeepClone() : JsonValue.Create(actor),
                ["excluded_at"] = Truthy(old?["excluded_at"]) ? old!["excluded_at"]!.DeepClone() : JsonValue.Create(DateTimeOffset.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")) });
        }
        return Json(result);
    }
    private static void Calendar(JsonObject value)
    {
        void Check(bool valid) { if (!valid) throw new InstallationException("working_time_invalid"); }
        Check(InstallationPackages.Keys(value, "timezone", "weekdays", "start", "end", "excluded_dates", "exceptions"));
        string zone = InstallationPackages.Text(value["timezone"]);
        Check(zone == "UTC" || TimeZoneInfo.TryConvertIanaIdToWindowsId(zone, out _));
        _ = TimeZoneInfo.FindSystemTimeZoneById(zone);
        var days = value["weekdays"] as JsonArray;
        Check(days is { Count: > 0 and <= 7 } && days.All(d => d is JsonValue dv && dv.TryGetValue<int>(out int day) && day is >= 0 and <= 6)
            && days.Select(d => d!.ToJsonString()).Distinct().Count() == days.Count);
        foreach (string key in new[] { "start", "end" }) Check(InstallationPackages.Match(InstallationPackages.Text(value[key]), "(?:[01][0-9]|2[0-3]):[0-5][0-9]"));
        Check(InstallationPackages.Text(value["start"]) != InstallationPackages.Text(value["end"]));
        Check(value["excluded_dates"] is JsonArray dates && dates.Count <= 366 && dates.All(d => DateOnly.TryParseExact(InstallationPackages.Text(d), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out _)));
        Check(value["exceptions"] is JsonArray { Count: <= 100 });
        foreach (var item in value["exceptions"]!.AsArray())
        {
            Check(item is JsonObject e && InstallationPackages.Keys(e, "subject_sid", "start_utc", "end_utc", "reason"));
            var entry = item!.AsObject();
            Check(InstallationPackages.Match(InstallationPackages.Text(entry["subject_sid"]), "S-1-(?:[0-9]+-)*[0-9]+") && InstallationPackages.Text(entry["reason"]).EnumerateRunes().Count() is >= 1 and <= 256);
            Check(Utc(entry["start_utc"], out var start) && Utc(entry["end_utc"], out var end) && start < end);
        }
    }
    private static bool Utc(JsonNode? n, out DateTimeOffset time)
    {
        string value = InstallationPackages.Text(n);
        return (value.EndsWith('Z') || value.EndsWith("+00:00", StringComparison.Ordinal) || value.EndsWith("+0000", StringComparison.Ordinal))
            && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out time) && time.Offset == TimeSpan.Zero
            ? true : Fail(out time);
        static bool Fail(out DateTimeOffset t) { t = default; return false; }
    }
    public static string WorkingTime(string raw)
    {
        try
        {
            var value = JsonNode.Parse(raw)!.AsObject(); Calendar(value);
            string normalized = Canonical(value);
            if (normalized.EnumerateRunes().Count() > 1024) throw new InstallationException("working_time_invalid");
            return normalized;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or TimeZoneNotFoundException or ArgumentException)
        { throw new InstallationException("working_time_invalid"); }
    }
    public static string LogonPolicy(string raw)
    {
        const string error = "workstation_logon_policy_invalid";
        try
        {
            int rawLength = raw.EnumerateRunes().Count();
            if (rawLength > 1040) throw new InstallationException(error);
            var value = JsonNode.Parse(raw)!.AsObject();
            if (value.Any(entry => entry.Key is not ("version" or "policies" or "enabled"))
                || value.ContainsKey("enabled") && value["enabled"]?.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)
                || value["version"] is not JsonValue version || !version.TryGetValue<int>(out int number)
                || number is < 1 or >= int.MaxValue || value["policies"] is not JsonArray policies) throw new InstallationException(error);
            int limit = LogonPolicyLengthLimit(value);
            if (rawLength > limit) throw new InstallationException(error);
            var scopes = new HashSet<string>(StringComparer.Ordinal);
            foreach (var rule in policies.OfType<JsonObject>())
            {
                if (!InstallationPackages.Keys(rule, "scope", "timezone", "weekdays", "start", "end", "include_cached_interactive")
                    || rule["include_cached_interactive"] is not JsonValue cached || !cached.TryGetValue<bool>(out _) || rule["scope"] is not JsonObject scope)
                    throw new InstallationException(error);
                string kind = InstallationPackages.Text(scope["kind"]);
                if (kind == "station")
                {
                    string station = InstallationPackages.Text(scope["station_id"]);
                    if (!InstallationPackages.Keys(scope, "kind", "station_id") || station.EnumerateRunes().Count() is < 1 or > 256 || station != PythonText.Strip(station)) throw new InstallationException(error);
                }
                else if (kind == "ou")
                {
                    string ou = InstallationPackages.Text(scope["ou_path"]);
                    string[] parts = SplitDn(ou);
                    if (!InstallationPackages.Keys(scope, "kind", "domain_id", "ou_path") || scope["domain_id"] is not JsonValue domain || !domain.TryGetValue<long>(out long id) || id < 1
                        || ou.EnumerateRunes().Count() is < 1 or > 512 || ou.EndsWith('\\') || !parts[0].StartsWith("ou=", StringComparison.OrdinalIgnoreCase)
                        || !parts[^1].StartsWith("dc=", StringComparison.OrdinalIgnoreCase) || parts.Any(p => !p.Contains('=') || p.Split('=', 2)[1].Length == 0)) throw new InstallationException(error);
                    scope["ou_path"] = UnicodeCaseFold.Fold(string.Join(',', parts));
                }
                else throw new InstallationException(error);
                if (!scopes.Add(Canonical(scope))) throw new InstallationException(error);
                var calendar = new JsonObject();
                foreach (string key in new[] { "timezone", "weekdays", "start", "end" }) calendar[key] = rule[key]?.DeepClone();
                calendar["excluded_dates"] = new JsonArray(); calendar["exceptions"] = new JsonArray(); Calendar(calendar);
            }
            if (policies.Any(p => p is not JsonObject)) throw new InstallationException(error);
            string normalized = Canonical(value);
            if (normalized.EnumerateRunes().Count() > limit) throw new InstallationException(error);
            return normalized;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or InstallationException or TimeZoneNotFoundException or ArgumentException)
        { throw new InstallationException(error); }
    }
    // The optional flag does not consume the existing schedule allowance.
    internal static int LogonPolicyLengthLimit(JsonObject value) => 1024 + (value["enabled"]?.GetValueKind() switch
    {
        JsonValueKind.True => 15,
        JsonValueKind.False => 16,
        _ => 0,
    });

    public static void CheckPolicyVersion(string value, string? previous)
    {
        if (previous is null) return;
        string old = LogonPolicy(previous);
        if (value != old && JsonNode.Parse(value)!["version"]!.GetValue<int>() <= JsonNode.Parse(old)!["version"]!.GetValue<int>())
            throw new InstallationException("workstation_logon_policy_invalid");
    }
    static string[] SplitDn(string value)
    {
        var parts = new List<string>(); var current = new StringBuilder(); bool escaped = false;
        foreach (char c in value)
        {
            if (c == ',' && !escaped) { parts.Add(PythonText.Strip(current.ToString())); current.Clear(); continue; }
            current.Append(c); escaped = c == '\\' && !escaped;
        }
        if (current.Length > 0) parts.Add(PythonText.Strip(current.ToString()));
        return parts.ToArray();
    }
    static bool Truthy(JsonNode? value) => value is not null && Sli.Server.Auth.Lifecycle.AuthJsonBody.Truthy(JsonSerializer.SerializeToElement(value));
    public static string Json(JsonNode value) => value.ToJsonString(new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
    public static string Canonical(JsonNode value) => Json(Sorted(value)!);
    private static JsonNode? Sorted(JsonNode? node) => node switch {
        JsonObject obj => new JsonObject(obj.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new KeyValuePair<string, JsonNode?>(p.Key, Sorted(p.Value)))),
        JsonArray array => new JsonArray(array.Select(Sorted).ToArray()), _ => node?.DeepClone() };
}
