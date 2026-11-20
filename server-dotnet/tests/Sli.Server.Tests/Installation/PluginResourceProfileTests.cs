using System.Text.Json.Nodes;
using Sli.Server.InstallationSetup;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.InstallationSetup;

public sealed class PluginResourceProfileTests
{
    const string ProfileId = "stage9-radius-manual-bounded-v1";
    static readonly string[] Missing = ["cpu_hard_limit", "job_object_kill_on_close", "memory_bytes", "network_allowlist_enforced", "pids", "working_directory_acl"];
    static JsonObject Registry() => InstallationPackages.Contract("stage10_plugin_resource_profiles_v1.json");
    static JsonObject Profile(JsonObject registry) => registry["profiles"]![0]!.AsObject();
    static void EqualJson(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual), actual?.ToJsonString());

    [Fact]
    public void RegistryIsSourceOnlyAndHasNoFalseNormalProfile()
    {
        var result = PluginResourceProfiles.ValidateRegistry(Registry());
        Assert.Equal("sli.plugin-resource-profiles.v1", (string?)result["contract_id"]);
        Assert.Equal(1, result["profile_count"]!.GetValue<int>());
        Assert.False(result["long_lived_normal_profile_defined"]!.GetValue<bool>());
        Assert.False(result["runtime_enabled"]!.GetValue<bool>());
        var profile = Assert.Single(result["profiles"]!.AsArray())!;
        Assert.Equal(11, profile["application_limit_count"]!.GetValue<int>());
        Assert.Equal(0, profile["hard_process_limit_count"]!.GetValue<int>());
        Assert.Equal(Missing, profile["missing_hard_limits"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.False(profile["ready_for_long_lived_worker"]!.GetValue<bool>());
    }

    [Fact]
    public void ManualProfileProjectsDeclaredLimitsAndMissingHardLimits()
    {
        var profile = Profile(Registry()); string before = profile.ToJsonString();
        var projection = PluginResourceProfiles.Project(profile);
        Assert.Equal(ProfileId, (string?)projection["profile_id"]);
        Assert.Equal("sli.remote-access", (string?)projection["plugin_id"]);
        Assert.Equal("sli.windows.vpn-radius", (string?)projection["source_pack_id"]);
        Assert.Equal("diagnostic_manual", (string?)projection["mode"]);
        Assert.Equal("disabled", (string?)projection["activation_state"]);
        Assert.True(projection["temporary_profile"]!.GetValue<bool>());
        Assert.Null(projection["effective_until_utc"]); Assert.Null(projection["reason"]);
        EqualJson(JsonNode.Parse("""{"value":1000,"unit":"records"}"""), projection["declared_limits"]!["records_per_run"]);
        foreach (var limit in profile["application_limits"]!.AsArray())
        {
            string key = limit!["key"]!.GetValue<string>();
            EqualJson(limit["value"], projection["declared_limits"]![key]!["value"]);
            EqualJson(limit["unit"], projection["declared_limits"]![key]!["unit"]);
            EqualJson(limit["enforcement"], projection["enforced_limits"]![key]);
        }
        Assert.Empty(projection["actual_usage"]!.AsObject()); Assert.Empty(projection["deviations"]!.AsArray());
        Assert.False(projection["ready_for_long_lived_worker"]!.GetValue<bool>());
        Assert.Equal(Missing, projection["missing_hard_limits"]!.AsArray().Select(n => n!.GetValue<string>()));
        Assert.Equal(before, profile.ToJsonString());
    }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData(" \t\n")]
    public void ActiveTemporaryProfileRequiresVisibleReason(string? reason)
    {
        var profile = Profile(Registry()); profile["activation_state"] = "enabled";
        Assert.Equal("active_temporary_profile_reason_required", Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.Project(profile, reason)).Message);
        Assert.Equal("bounded diagnostic run", (string?)PluginResourceProfiles.Project(profile, "bounded diagnostic run")["reason"]);
    }

    // The five fail-closed mutations from tests/sources/test_plugin_resource_profiles.py.
    [Theory]
    [InlineData("duplicate_limit", "application_limit_key_invalid_or_duplicate")]
    [InlineData("missing_pids", "hard_process_limit_shape_invalid")]
    [InlineData("unknown_mode", "profile_mode_invalid")]
    [InlineData("zero_limit", "application_limit_value_invalid")]
    [InlineData("missing_source_pack", "profile_source_pack_id_invalid")]
    public void InvalidOrAmbiguousProfileFailsClosed(string mutation, string error)
    {
        var registry = Registry(); var profile = Profile(registry);
        switch (mutation)
        {
            case "duplicate_limit": profile["application_limits"]!.AsArray().Add(profile["application_limits"]![0]!.DeepClone()); break;
            case "missing_pids": profile["hard_process_limits"]!.AsObject().Remove("pids"); break;
            case "unknown_mode": profile["mode"] = "unknown"; break;
            case "zero_limit": profile["application_limits"]![0]!["value"] = 0; break;
            case "missing_source_pack": profile.Remove("source_pack_id"); break;
        }
        Assert.Equal(error, Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.ValidateRegistry(registry)).Message);
        var view = PluginResourceProfiles.View(ProfileId, registry);
        Assert.Equal("unavailable", (string?)view["status"]);
        Assert.Equal("PluginResourceProfileError", (string?)view["error_type"]);
        Assert.False(view["ready_for_long_lived_worker"]!.GetValue<bool>());
        Assert.False(view.ContainsKey("declared_limits"));
    }

    [Theory]
    [InlineData("schema_version", "2")]
    [InlineData("contract_id", "\"unknown\"")]
    [InlineData("status", "\"active\"")]
    [InlineData("runtime_enabled", "true")]
    [InlineData("autostart_enabled", "true")]
    [InlineData("source_contact_allowed", "true")]
    [InlineData("production_configuration_changed", "true")]
    public void RegistryRejectsActivationAndInvalidHeaders(string key, string value)
    {
        var registry = Registry(); registry[key] = JsonNode.Parse(value);
        Assert.Equal($"registry_{key}_invalid", Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.ValidateRegistry(registry)).Message);
    }

    [Theory]
    [InlineData("modes", "profile_modes_invalid")]
    [InlineData("empty", "profiles_required")]
    [InlineData("non_object", "profile_object_required")]
    [InlineData("duplicate", "profile_id_invalid_or_duplicate")]
    public void RegistryRejectsInvalidShapeAndDuplicateProfiles(string mutation, string error)
    {
        var registry = Registry(); var profiles = registry["profiles"]!.AsArray();
        switch (mutation)
        {
            case "modes": registry["profile_modes"]!.AsObject().Remove("normal"); break;
            case "empty": profiles.Clear(); break;
            case "non_object": profiles[0] = "invalid"; break;
            case "duplicate": profiles.Add(profiles[0]!.DeepClone()); break;
        }
        Assert.Equal(error, Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.ValidateRegistry(registry)).Message);
    }

    [Theory]
    [InlineData("plugin_id", "\" \"", "profile_plugin_id_invalid")]
    [InlineData("activation_state", "\"unknown\"", "profile_activation_state_invalid")]
    [InlineData("temporary_profile", "null", "temporary_profile_flag_required")]
    [InlineData("reason_required_when_active", "false", "temporary_profile_reason_guard_missing")]
    [InlineData("application_limits", "[]", "application_limits_required")]
    [InlineData("observability_fields", "[]", "observability_fields_invalid")]
    public void ProfileRejectsMissingGuardsAndInvalidObservability(string key, string value, string error)
    {
        var profile = Profile(Registry()); profile[key] = JsonNode.Parse(value);
        Assert.Equal(error, Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.Project(profile)).Message);
    }

    [Theory]
    [InlineData("value", "-1", "application_limit_value_invalid")]
    [InlineData("value", "1.5", "application_limit_value_invalid")]
    [InlineData("value", "\"1\"", "application_limit_value_invalid")]
    [InlineData("unit", "\"\"", "application_limit_unit_invalid")]
    [InlineData("enforcement", "null", "application_limit_enforcement_invalid")]
    [InlineData("change_control", "null", "application_limit_change_control_invalid")]
    public void ApplicationLimitValidationFailsClosed(string key, string value, string error)
    {
        var profile = Profile(Registry()); profile["application_limits"]![0]![key] = JsonNode.Parse(value);
        Assert.Equal(error, Assert.Throws<PluginResourceProfileError>(() => PluginResourceProfiles.Project(profile)).Message);
    }

    [Theory]
    [InlineData("disabled")] [InlineData("blocked")] [InlineData("enabled")]
    public void ProjectionPreservesUsageAndOnlyShowsReasonWhenActive(string state)
    {
        var profile = Profile(Registry()); profile["activation_state"] = state;
        profile["effective_until_utc"] = "2026-11-09T12:00:00Z";
        var usage = JsonNode.Parse("""{"records":12,"cpu_seconds":1.5}""")!.AsObject();
        var result = PluginResourceProfiles.Project(profile, "bounded diagnostic run", usage);
        Assert.Equal(state == "enabled" ? "bounded diagnostic run" : null, (string?)result["reason"]);
        EqualJson(profile["effective_until_utc"], result["effective_until_utc"]); EqualJson(usage, result["actual_usage"]);
        result["actual_usage"]!["records"] = 20;
        Assert.Equal(12, usage["records"]!.GetValue<int>());
    }

    [Theory]
    [InlineData("normal", true)] [InlineData("diagnostic_manual", false)] [InlineData("emergency", false)]
    public void OnlyNormalProfileWithAllDeclaredHardLimitsIsReady(string mode, bool ready)
    {
        var profile = Profile(Registry()); profile["mode"] = mode;
        foreach (string key in profile["hard_process_limits"]!.AsObject().Select(p => p.Key).ToArray()) profile["hard_process_limits"]![key] = true;
        var result = PluginResourceProfiles.Project(profile);
        Assert.Equal(ready, result["ready_for_long_lived_worker"]!.GetValue<bool>()); Assert.Empty(result["missing_hard_limits"]!.AsArray());
    }

    [Fact]
    public void BothRuntimeViewsUseTheValidatedProjection()
    {
        var expected = PluginResourceProfiles.Project(Profile(Registry())); expected["status"] = "configured_manual_inactive";
        EqualJson(expected, PluginResourceProfiles.View(ProfileId)); EqualJson(expected, OperationsCatalog.ResourceProfile(ProfileId));
        Assert.Equal("not_configured", (string?)PluginResourceProfiles.View(" ")["status"]);
        Assert.Equal("not_registered", (string?)PluginResourceProfiles.View("unknown")["status"]);
        var registry = Registry(); Profile(registry)["activation_state"] = "enabled";
        Assert.Equal("unavailable", (string?)PluginResourceProfiles.View(ProfileId, registry)["status"]);
    }
}
