using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;
using Sli.Server.Agents.Registry;
using Sli.Server.Compatibility;

namespace Sli.Server.Entities;

internal sealed record ComputerMatchIndex(Dictionary<string, HashSet<string>> Names, Dictionary<string, HashSet<string>> Ips, Dictionary<string, string> Computers);
internal sealed record LogonObservation(long EventId, byte[] Hash, string ComputerGuid, string ComputerName, string UserName, DateTimeOffset Observed);
internal sealed record LogonProjection(string Status, string? Reason = null, LogonObservation? Observation = null);

internal static partial class WhatWhereWhenProjection
{
    internal static string Name(string value) => UnicodeCaseFold.Fold(PythonText.Strip(value).TrimEnd('.'));
    internal static string? Ip(string value)
    {
        if (!IPAddress.TryParse(value.Trim(), out var ip) || IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return null;
        return ip.ToString().ToLowerInvariant();
    }
    internal static ComputerMatchIndex Index(JsonObject snapshot)
    {
        var index = new ComputerMatchIndex([], [], []);
        foreach (var row in ((JsonArray)(snapshot["snapshot"] ?? snapshot)["objects"]!).OfType<JsonObject>())
        {
            string Value(params string[] keys) => keys.Select(k => EntityReader.Text(row, k)).FirstOrDefault(v => v.Length > 0) ?? "";
            if (Name(Value("deviceType", "device_type")) is not ("workstation" or "рабочая станция" or "desktop" or "laptop")) continue;
            string guid = Value("objectGuid", "object_guid").Trim().ToLowerInvariant(); if (guid.Length == 0) continue;
            index.Computers[guid] = Value("name", "dnsHostName", "objectGuid").Trim().TrimEnd('.');
            void Add(Dictionary<string, HashSet<string>> map, string key)
            { if (!map.TryGetValue(key, out var owners)) map[key] = owners = []; owners.Add(guid); }
            foreach (string field in new[] { "name", "dnsHostName", "dns_host_name" })
            {
                string name = Name(EntityReader.Text(row, field)); if (name.Length == 0) continue;
                Add(index.Names, name); if (name.Contains('.')) Add(index.Names, name.Split('.')[0]);
            }
            foreach (string field in new[] { "ipv4s", "ipv6s", "ip_addresses" })
                if (row[field] is JsonArray ips) foreach (var node in ips) if (Ip(node?.ToString() ?? "") is string ip) Add(index.Ips, ip);
        }
        return index;
    }
    internal static bool ServiceAccount(JsonObject row)
    {
        string Value(string a, string b) => EntityReader.Text(row, a) is { Length: > 0 } s ? s : EntityReader.Text(row, b);
        if (ServiceOu().IsMatch(Value("distinguishedName", "distinguished_name").Trim())) return true;
        return new[] { Value("samAccountName", "sam_account_name"), Value("samAccountName", "sam_account_name").Split('\\').Last(), Value("userPrincipalName", "user_principal_name").Split('@')[0], Value("displayName", "display_name") }
            .Select(UnicodeCaseFold.TrimAndFold).Any(v => ServiceName().IsMatch(v) || v.Contains("service", StringComparison.Ordinal));
    }
    internal static JsonObject Normalize(JsonObject row)
    {
        JsonObject data;
        try { data = row["event_data_json"] is JsonObject obj ? obj : JsonNode.Parse(row["event_data_json"]?.ToString() ?? "{}") as JsonObject ?? new(); }
        catch (System.Text.Json.JsonException) { data = new(); }
        var result = new JsonObject { ["source_event_id"] = (row["source_event_id"] ?? row["id"])?.DeepClone(), ["event_id"] = row["event_id"]?.DeepClone() ?? JsonValue.Create(4624),
            ["observed_at_utc"] = (row["observed_at_utc"] ?? row["time_created_utc"])?.DeepClone() };
        foreach (var (key, fallback) in new[] { ("target_user_sid", "TargetUserSid"), ("target_user_name", "TargetUserName"), ("target_domain_name", "TargetDomainName"), ("workstation_name", "WorkstationName"), ("ip_address", "IpAddress"), ("logon_type", "LogonType") })
            result[key] = row[key] is { } v && v.ToString().Length > 0 ? v.DeepClone() : data[fallback]?.DeepClone();
        if ((row["source_event_hash"] ?? row["source_core_sha256"]) is JsonNode hash) result["source_event_hash"] = hash.DeepClone();
        else
        {
            var core = EntityReader.Pick(row, SourceCoreFields);
            result["source_event_hash"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(CanonicalJson.Serialize(core, ensureAscii: false)))).ToLowerInvariant();
        }
        return result;
    }
    internal static LogonProjection Project(JsonObject input, ComputerMatchIndex index, IReadOnlyDictionary<string, bool> serviceAccounts)
    {
        var row = Normalize(input);
        string T(string key) => EntityReader.Text(row, key).Trim();
        string user = T("target_user_name"), normalizedUser = UnicodeCaseFold.Fold(user);
        string? reason = EntityReader.Number(row, "event_id") != 4624 ? "not_successful_logon_event"
            : user.Length == 0 ? "user_missing"
            : T("target_user_sid").ToUpperInvariant() is "S-1-5-18" or "S-1-5-19" or "S-1-5-20" || normalizedUser is "system" or "local service" or "network service" or "anonymous logon" ? "system_account"
            : user.EndsWith('$') ? "machine_account"
            : T("logon_type").Length > 0 && T("logon_type") is not ("2" or "3" or "4" or "5" or "7" or "8" or "9" or "10" or "11") ? "logon_type_not_user_success"
            : !serviceAccounts.TryGetValue(normalizedUser.Split('\\').Last(), out bool service) ? "classification_unknown" : service ? "service_account" : null;
        if (reason is not null) return new("filtered", reason);
        var names = index.Names.GetValueOrDefault(Name(T("workstation_name")), []); var ips = index.Ips.GetValueOrDefault(Ip(T("ip_address")) ?? "", []);
        if (names.Count > 0 && ips.Count > 0 && !names.SetEquals(ips)) return new("ambiguous", "name_ip_conflict");
        var candidates = names.Union(ips).ToArray();
        if (candidates.Length == 0) return new("unmatched", "computer_not_resolved");
        if (candidates.Length != 1) return new("ambiguous", "computer_identity_not_unique");
        var observed = WhatWhereWhenSnapshots.Instant(row["observed_at_utc"], "event_observation");
        string domain = T("target_domain_name"), fullName = domain.Length == 0 ? user : domain + "\\" + user;
        byte[] hash;
        try { hash = Convert.FromHexString(T("source_event_hash")); } catch (FormatException) { throw new InvalidDataException("source_event_hash_invalid"); }
        if (hash.Length != 32) throw new InvalidDataException("source_event_hash_invalid");
        return new("observation", Observation: new(EntityReader.Number(row, "source_event_id"), hash, candidates[0], index.Computers[candidates[0]], fullName, observed));
    }
    internal static DateTime Hour(DateTimeOffset instant)
    {
        var local = TimeZoneInfo.ConvertTime(instant, TimeZoneInfo.FindSystemTimeZoneById("Asia/Novosibirsk"));
        return new DateTime(local.Year, local.Month, local.Day, local.Hour, 0, 0, DateTimeKind.Unspecified);
    }
    [GeneratedRegex(@"(?:^|,)OU=ServiceAcc(?:,|$)", RegexOptions.IgnoreCase)] private static partial Regex ServiceOu();
    [GeneratedRegex(@"(?:^|[._-])svc(?:[._-]|$)", RegexOptions.IgnoreCase)] private static partial Regex ServiceName();
    static readonly string[] SourceCoreFields = ["id","raw_log_file_id","server_id","domain_id","site_id","log_source_id","event_record_id","event_id","version","level","task","opcode","keywords","provider_name","channel","computer","time_created_utc","subject_user_sid","subject_user_name","subject_domain_name","target_user_sid","target_user_name","target_domain_name","ip_address","workstation_name","logon_id","correlation_id","normalized_at","normalized_hash"];
}
