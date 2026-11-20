using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Sli.Server.InstallationSetup;

internal sealed class PluginResourceProfileError(string code) : InvalidOperationException(code);

// Source inventory and status projection only; this contract does not enforce runtime limits.
internal static class PluginResourceProfiles
{
    const string ContractId = "sli.plugin-resource-profiles.v1";
    static readonly string[] HardLimits = ["cpu_hard_limit", "memory_bytes", "pids", "job_object_kill_on_close", "working_directory_acl", "network_allowlist_enforced"];
    static readonly string[] Observability = ["profile_id", "mode", "activation_state", "temporary_profile", "effective_until_utc", "reason", "declared_limits", "enforced_limits", "actual_usage", "deviations", "missing_hard_limits"];
    static string? Text(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    static bool Truthy(JsonNode? n)
    {
        if (n is null) return false;
        if (n is JsonArray a) return a.Count > 0;
        if (n is JsonObject o) return o.Count > 0;
        var value = JsonSerializer.SerializeToElement(n);
        return value.ValueKind switch {
            JsonValueKind.False or JsonValueKind.Null => false, JsonValueKind.String => value.GetString()!.Length > 0,
            JsonValueKind.Number => value.GetDouble() != 0, _ => true };
    }
    static void Require(bool valid, string code) { if (!valid) throw new PluginResourceProfileError(code); }
    static bool Keys(JsonObject value, string[] keys) => value.Count == keys.Length && keys.All(value.ContainsKey);

    internal static JsonObject ValidateRegistry(JsonObject registry)
    {
        var header = new JsonObject { ["schema_version"] = 1, ["contract_id"] = ContractId, ["status"] = "prepared_source_inventory",
            ["runtime_enabled"] = false, ["autostart_enabled"] = false, ["source_contact_allowed"] = false, ["production_configuration_changed"] = false };
        foreach (var (key, expected) in header)
            Require(JsonNode.DeepEquals(registry[key], expected), $"registry_{key}_invalid");
        Require(registry["profile_modes"] is JsonObject modes && Keys(modes, ["normal", "diagnostic", "emergency"]), "profile_modes_invalid");
        Require(registry["profiles"] is JsonArray { Count: > 0 }, "profiles_required");
        var seen = new HashSet<string>(StringComparer.Ordinal); var results = new JsonArray();
        foreach (var item in registry["profiles"]!.AsArray())
        {
            Require(item is JsonObject, "profile_object_required");
            var profile = item!.AsObject(); string? id = Text(profile["profile_id"]);
            Require(!string.IsNullOrEmpty(id) && seen.Add(id), "profile_id_invalid_or_duplicate");
            results.Add(Validate(profile));
        }
        return new() { ["contract_id"] = ContractId, ["profile_count"] = results.Count, ["profiles"] = results,
            ["long_lived_normal_profile_defined"] = Text(registry["profile_modes"]!["normal"]) != "not_defined_for_long_lived_plugin_worker", ["runtime_enabled"] = false };
    }

    internal static JsonObject Validate(JsonObject profile)
    {
        foreach (string key in new[] { "profile_id", "plugin_id", "source_pack_id", "component_id", "source_instance_id" })
            Require(!string.IsNullOrWhiteSpace(Text(profile[key])), $"profile_{key}_invalid");
        Require(Text(profile["mode"]) is "normal" or "diagnostic_manual" or "emergency", "profile_mode_invalid");
        Require(Text(profile["activation_state"]) is "disabled" or "enabled" or "blocked", "profile_activation_state_invalid");
        Require(profile["temporary_profile"] is JsonValue flag && flag.TryGetValue<bool>(out _), "temporary_profile_flag_required");
        Require(!profile["temporary_profile"]!.GetValue<bool>() || Truthy(profile["reason_required_when_active"]), "temporary_profile_reason_guard_missing");
        Require(profile["application_limits"] is JsonArray { Count: > 0 }, "application_limits_required");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var node in profile["application_limits"]!.AsArray())
        {
            Require(node is JsonObject, "application_limit_object_required");
            var limit = node!.AsObject(); string? key = Text(limit["key"]);
            Require(!string.IsNullOrEmpty(key) && keys.Add(key), "application_limit_key_invalid_or_duplicate");
            // Python's isinstance(value, int) also accepts True (but not False).
            var value = limit["value"];
            Require(value?.GetValueKind() == JsonValueKind.True || value?.GetValueKind() == JsonValueKind.Number
                && BigInteger.TryParse(value.ToJsonString(), out var number) && number > 0, "application_limit_value_invalid");
            foreach (string field in new[] { "unit", "enforcement", "change_control" })
                Require(Text(limit[field]) is { Length: > 0 }, $"application_limit_{field}_invalid");
        }
        Require(profile["hard_process_limits"] is JsonObject hard && Keys(hard, HardLimits), "hard_process_limit_shape_invalid");
        Require(JsonNode.DeepEquals(profile["observability_fields"], new JsonArray(Observability.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray())), "observability_fields_invalid");
        var missing = profile["hard_process_limits"]!.AsObject().Where(p => p.Value is null).Select(p => p.Key).Order(StringComparer.Ordinal).ToArray();
        return new() { ["profile_id"] = profile["profile_id"]!.DeepClone(), ["plugin_id"] = profile["plugin_id"]!.DeepClone(), ["source_pack_id"] = profile["source_pack_id"]!.DeepClone(),
            ["application_limit_count"] = keys.Count, ["hard_process_limit_count"] = HardLimits.Length - missing.Length,
            ["missing_hard_limits"] = new JsonArray(missing.Select(s => (JsonNode?)JsonValue.Create(s)).ToArray()),
            ["ready_for_long_lived_worker"] = missing.Length == 0 && Text(profile["mode"]) == "normal" };
    }

    internal static JsonObject Project(JsonObject profile, string? reason = null, JsonObject? actualUsage = null)
    {
        var validated = Validate(profile); bool active = Text(profile["activation_state"]) == "enabled";
        Require(!active || !profile["temporary_profile"]!.GetValue<bool>() || !string.IsNullOrWhiteSpace(reason), "active_temporary_profile_reason_required");
        var result = new JsonObject();
        foreach (string key in new[] { "profile_id", "plugin_id", "source_pack_id", "mode", "activation_state", "temporary_profile", "effective_until_utc" }) result[key] = profile[key]?.DeepClone();
        var declared = new JsonObject(); var enforced = new JsonObject();
        foreach (var limit in profile["application_limits"]!.AsArray().OfType<JsonObject>())
        {
            string key = Text(limit["key"])!;
            declared[key] = new JsonObject { ["value"] = limit["value"]!.DeepClone(), ["unit"] = limit["unit"]!.DeepClone() };
            enforced[key] = limit["enforcement"]!.DeepClone();
        }
        result["reason"] = active ? reason : null; result["declared_limits"] = declared; result["enforced_limits"] = enforced;
        result["actual_usage"] = actualUsage?.DeepClone() ?? new JsonObject(); result["deviations"] = new JsonArray();
        foreach (string key in new[] { "missing_hard_limits", "ready_for_long_lived_worker" }) result[key] = validated[key]!.DeepClone();
        return result;
    }

    internal static JsonObject View(string profileId, JsonObject? registry = null)
    {
        string id = profileId.Trim();
        var result = new JsonObject { ["status"] = id.Length == 0 ? "not_configured" : "not_registered", ["profile_id"] = id.Length == 0 ? null : id, ["ready_for_long_lived_worker"] = false };
        if (id.Length == 0) return result;
        try
        {
            registry ??= InstallationPackages.Contract("stage10_plugin_resource_profiles_v1.json");
            ValidateRegistry(registry);
            var profile = registry["profiles"]!.AsArray().OfType<JsonObject>().SingleOrDefault(p => Text(p["profile_id"]) == id);
            if (profile is null) return result;
            var projection = Project(profile); projection["status"] = "configured_manual_inactive"; return projection;
        }
        catch (PluginResourceProfileError) { result["status"] = "unavailable"; result["error_type"] = nameof(PluginResourceProfileError); return result; }
    }
}
