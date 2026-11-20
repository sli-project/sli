using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Sli.Agent.Protocol;

namespace Sli.Agent.Core;

/// <summary>Python snapshot_stream.redact and gpo_privacy.mask_gpo. Runs before source evidence reaches disk.</summary>
public static class SnapshotPrivacy
{
    private const string Hidden = "значение скрыто";
    private static readonly HashSet<string> Secrets = new("password passwordhash unicodepwd dbcspwd ntpwdhistory lmpwdhistory supplementalcredentials msmcsadmpwd mslapspassword mslapsencryptedpassword mslapsencryptedpasswordhistory msdsmanagedpassword mslapsencrypteddsrmpassword mslapsencrypteddsrmpasswordhistory mslapsdsrmpassword msdsmanagedpasswordid msdsmanagedpasswordpreviousid credential credentials apikey clientsecret signingkey passwordhashes pwdhash pwdhashes cpassword secret key privatekey token accesstoken refreshtoken rawxml rawsysvol script scriptcontent".Split(' '));
    private static readonly HashSet<string> Raw = new("rawxml rawsysvol xml xmltext sysvolcontent script scriptcontent scriptbody".Split(' '));
    private static readonly HashSet<string> Named = new("name key valuename property setting_name path source_xml_path".Split(' '));
    private static readonly HashSet<string> Values = new("value values value_display data text valuedata defaultvalue properties".Split(' '));
    private static readonly Regex SensitivePattern = new("password|cpassword|passwd|pwd|secret|privatekey|token|credential|apikey|accesskey|sharedkey|presharedkey|psk|encryptionkey|decryptionkey|symmetrickey|signingkey|keymaterial|passphrase|connectionstring");
    private static string Normalize(string s) => Regex.Replace(s.ToLowerInvariant(), "[^a-z0-9]", "");
    private static bool Sensitive(string s) => SensitivePattern.IsMatch(Normalize(s));
    private static bool ScriptValue(JsonNode? n) => JsonRead.TryString(n, out var s) && (s == "" || Regex.IsMatch(s, "^[^\\r\\n\";<>]+\\.(?:ps1|psm1|cmd|bat|vbs|js|wsf|exe)$", RegexOptions.IgnoreCase));
    private static bool SensitiveValue(string s) => Regex.IsMatch(s, "-----BEGIN .*PRIVATE KEY-----", RegexOptions.IgnoreCase)
        || Regex.Matches(s, "(?:^|[\\s;,{<])[\"']?(?<name>[\\w.:-]+)[\"']?\\s*(?:=|:)\\s*[\"']?(?<label>[\\w.:-]+)?")
            .Any(m => Sensitive(m.Groups["name"].Value) || Named.Contains(m.Groups["name"].Value.ToLowerInvariant()) && Sensitive(m.Groups["label"].Value));

    public static JsonNode? Mask(JsonNode? node, bool gpo, bool registry = false)
    {
        if (node is JsonArray array) return new JsonArray(array.Select(n => Mask(n, gpo, registry)).ToArray());
        if (node is not JsonObject obj)
        {
            if (JsonRead.TryString(node, out var s) && (s.TrimStart().StartsWith('<') || gpo && SensitiveValue(s)))
            {
                if (gpo) return JsonValue.Create(Hidden);
                throw new AgentException("agent_snapshot_invalid");
            }
            return node?.DeepClone();
        }
        if (!gpo)
        {
            var redacted = new JsonObject();
            foreach (var (key, value) in obj) redacted[key] = Secrets.Contains(Normalize(key)) ? new JsonObject { ["redacted"] = true } : Mask(value, false);
            return redacted;
        }
        var named = obj.Any(p => Named.Contains(p.Key.ToLowerInvariant()) && JsonRead.TryString(p.Value, out var s) && Sensitive(s));
        bool HasPath(string area) => new[] { "path", "source_xml_path" }.Any(k => JsonRead.TryString(obj[k], out var p) && Regex.IsMatch(p, "(?:^|/)" + area + "(?:/|$)", RegexOptions.IgnoreCase));
        var script = HasPath("scripts?") || JsonRead.TryString(obj["kind"], out var kind) && Regex.IsMatch(kind, "(?:^|/)scripts?(?:/|$)", RegexOptions.IgnoreCase);
        var registryFact = HasPath("registry") || string.Equals(obj["kind"]?.ToString(), "registry", StringComparison.OrdinalIgnoreCase);
        var result = new JsonObject();
        foreach (var (key, value) in obj)
        {
            var normalized = Normalize(key); var lower = key.ToLowerInvariant();
            if (Raw.Contains(normalized) || normalized.StartsWith("rawsysvol", StringComparison.Ordinal) || normalized.StartsWith("rawxml", StringComparison.Ordinal)) continue;
            if (key is "redacted_fields" or "sensitive_value_present" or "truncated_fields") result[key] = value?.DeepClone();
            else if (Sensitive(key) || normalized == "key" && !registry && JsonRead.TryString(value, out var path) && !Regex.IsMatch(path, @"\A(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|Software|System)(?:\\|$)", RegexOptions.IgnoreCase)
                || named && Values.Contains(lower) || script && (Values.Contains(lower) || lower is "command" or "arguments" or "parameters") && !ScriptValue(value))
                result[key] = value is null ? null : JsonValue.Create(Hidden);
            else if (lower == "source_state" && named && value is JsonObject state)
            {
                var masked = new JsonObject();
                foreach (var (name, data) in state) masked[name] = name is "value" or "detail" or "error" && data is not null ? JsonValue.Create(Hidden) : Mask(data, true);
                result[key] = masked;
            }
            else result[key] = Mask(value, true, registryFact && lower == "properties");
        }
        if (new[] { "scope", "kind", "properties", "sha256" }.All(obj.ContainsKey))
        {
            if (obj["properties"] is not JsonObject props) throw new AgentException("agent_gpo_settings_invalid");
            var removed = props.Select(p => p.Key).Where(k => Sensitive(k) || Raw.Contains(Normalize(k))).Select(k => k.ToLowerInvariant()).ToHashSet();
            var cleaned = Mask(props, true, registryFact)!.AsObject();
            foreach (var key in cleaned.Select(p => p.Key).ToArray())
            {
                if (removed.Contains(key.ToLowerInvariant())) cleaned.Remove(key);
                else if ((named || script) && (Values.Contains(key.ToLowerInvariant()) || key.ToLowerInvariant() is "command" or "arguments" or "parameters") && (named || !ScriptValue(cleaned[key]))) cleaned[key] = Hidden;
            }
            result["properties"] = cleaned;
            if (!JsonNode.DeepEquals(cleaned, props))
            {
                var fields = removed.Concat(cleaned.Where(p => !JsonNode.DeepEquals(p.Value, props[p.Key])).Select(p => p.Key.ToLowerInvariant())).ToHashSet();
                var redacted = (obj["redacted_fields"]?.AsArray().Select(n => n!.GetValue<string>()) ?? []).Concat(fields.Where(Sensitive)).ToHashSet();
                if (fields.Any(f => !Sensitive(f))) redacted.Add("secret");
                result["redacted_fields"] = new JsonArray(redacted.Order(StringComparer.Ordinal).Select(s => (JsonNode?)JsonValue.Create(s)).ToArray());
                result["truncated_fields"] = new JsonArray((obj["truncated_fields"]?.AsArray() ?? []).Where(n => cleaned.ContainsKey(n!.GetValue<string>())).Select(n => n!.DeepClone()).ToArray());
                result["sensitive_value_present"] = true;
                var hashed = new JsonObject();
                foreach (var key in new[] { "scope", "kind", "path", "properties", "redacted_fields", "truncated_fields", "sensitive_value_present" }) hashed[key] = result[key]?.DeepClone();
                result["sha256"] = Convert.ToHexStringLower(SHA256.HashData(CanonicalJson.ToBytes(hashed)));
            }
        }
        return result;
    }
}
