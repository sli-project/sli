using System.Text.Json.Nodes;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

public sealed class PluginIsolationFixtureTests
{
    private const string Target = "sli.remote-access";
    private const string Peer = "sli.windows.ad-dc";

    [Fact]
    public void FixtureIsExplicitlySourceProcessAndDatabaseFree()
    {
        var config = PluginIsolationFixture.Load();
        Assert.True(config["fixture_only"]!.GetValue<bool>());
        foreach (var key in new[] { "runtime_enabled", "source_contact_allowed", "database_access_allowed", "process_control_allowed", "autostart_enabled", "production_read_path_cutover" })
            Assert.False(config[key]!.GetValue<bool>());
        Assert.Equal("sli.plugin-architecture.v2", config["architecture_decision_id"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("disable", "disabled_fixture", "stopped_fixture", "available_fixture", "drained_fixture")]
    [InlineData("inject_failure", "failed_fixture", "failed_fixture", "blocked_fixture", "drained_fixture")]
    [InlineData("inject_resource_exhaustion", "resource_exhausted_fixture", "terminated_fixture", "blocked_fixture", "quarantined_fixture")]
    public void TargetFailureOrStopDoesNotChangePeerOrCore(string action, string health, string runtime, string dataset, string queue)
    {
        var model = PluginIsolationFixture.FromConfig();
        var before = model.Snapshot();
        switch (action)
        {
            case "disable": model.Disable(Target); break;
            case "inject_failure": model.InjectFailure(Target); break;
            case "inject_resource_exhaustion": model.InjectResourceExhaustion(Target); break;
        }
        var after = model.Snapshot();
        Equal(before["core"], after["core"]);
        Equal(before["plugins"]![Peer], after["plugins"]![Peer]);
        var target = after["plugins"]![Target]!;
        Assert.Equal(health, target["observed_health"]!.GetValue<string>());
        Assert.Equal(runtime, target["component_runtime"]!.GetValue<string>());
        Assert.Equal(dataset, target["dataset_state"]!.GetValue<string>());
        Assert.Equal(queue, target["queue_state"]!.GetValue<string>());
    }

    [Fact]
    public void UpgradeRequiresDisabledDrainedStateAndRollsBackExactly()
    {
        var model = PluginIsolationFixture.FromConfig();
        var initial = model.Snapshot();
        Error("upgrade_requires_disabled_drained_plugin", () => model.Upgrade(Target, "1.1.0-fixture"));
        Equal(initial, model.Snapshot());
        model.Disable(Target);
        var disabled = model.Snapshot();
        model.Upgrade(Target, "1.1.0-fixture");
        Assert.Equal("1.1.0-fixture", model.Snapshot()["plugins"]![Target]!["package_version"]!.GetValue<string>());
        model.Rollback(Target);
        Equal(disabled, model.Snapshot());
    }

    [Theory]
    [InlineData("desired_activation", "enabled_fixture")]
    [InlineData("component_runtime", "running_fixture")]
    [InlineData("queue_state", "pending_fixture")]
    public void UpgradeAndDetachRequireEveryDisabledDrainedCondition(string key, string value)
    {
        var config = PluginIsolationFixture.Load();
        var plugin = config["plugins"]![0]!;
        plugin["desired_activation"] = "disabled_fixture";
        plugin["component_runtime"] = "stopped_fixture";
        plugin[key] = value;
        var model = new PluginIsolationFixture(config);
        var before = model.Snapshot();
        Error("upgrade_requires_disabled_drained_plugin", () => model.Upgrade(Target, "1.1.0-fixture"));
        Error("detach_preconditions_not_met", () => model.Detach(Target));
        Equal(before, model.Snapshot());
    }

    [Theory]
    [InlineData("read_report_parity")]
    [InlineData("detach_reader_ready")]
    public void DetachRequiresReaderAndParity(string guard)
    {
        var config = PluginIsolationFixture.Load();
        config["plugins"]![0]![guard] = false;
        var model = new PluginIsolationFixture(config);
        model.Disable(Target);
        var before = model.Snapshot();
        Error("detach_preconditions_not_met", () => model.Detach(Target));
        Equal(before, model.Snapshot());
    }

    [Fact]
    public void DetachPreservesEvidencePeerAndCore()
    {
        var model = PluginIsolationFixture.FromConfig();
        var before = model.Snapshot();
        model.Disable(Target);
        model.Detach(Target);
        var after = model.Snapshot();
        Equal(before["plugins"]![Target]!["immutable_evidence_refs"], after["plugins"]![Target]!["immutable_evidence_refs"]);
        Equal(before["core"], after["core"]);
        Equal(before["plugins"]![Peer], after["plugins"]![Peer]);
        Assert.Equal("retained_read_only_fixture", after["plugins"]![Target]!["dataset_state"]!.GetValue<string>());
        Assert.Equal("detached_fixture", after["plugins"]![Target]!["package_lifecycle"]!.GetValue<string>());
    }

    [Fact]
    public void CutoverIsOnlyNonexecutingPlanAndRequiresParity()
    {
        var model = PluginIsolationFixture.FromConfig();
        var before = model.Snapshot();
        Equal(JsonNode.Parse("""{"eligible":true,"executed":false,"production_read_path_cutover":false}"""), model.PlanOwnershipCutover(Target));
        Equal(before, model.Snapshot());
        var config = PluginIsolationFixture.Load();
        config["plugins"]![0]!["read_report_parity"] = false;
        Error("read_report_parity_required", () => new PluginIsolationFixture(config).PlanOwnershipCutover(Target));
    }

    [Theory]
    [InlineData("runtime_enabled")]
    [InlineData("source_contact_allowed")]
    [InlineData("database_access_allowed")]
    [InlineData("process_control_allowed")]
    [InlineData("autostart_enabled")]
    [InlineData("production_read_path_cutover")]
    [InlineData("package_version")]
    public void FixtureCannotClaimRealVersionOrRuntime(string key)
    {
        var config = PluginIsolationFixture.Load();
        if (key == "package_version") config["plugins"]![0]![key] = "1.0.0";
        else config[key] = true;
        var path = Path.Combine(Path.GetTempPath(), "sli-isolation-" + Guid.NewGuid().ToString("N") + ".json");
        try
        {
            File.WriteAllText(path, config.ToJsonString());
            Error(key == "package_version" ? "isolation_fixture_version_invalid" : $"isolation_fixture_{key}_invalid",
                () => PluginIsolationFixture.Load(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void VersionsUseFixtureSuffixAndRollbackStack()
    {
        var model = PluginIsolationFixture.FromConfig();
        model.Disable(Target);
        var before = model.Snapshot();
        Error("rollback_version_missing", () => model.Rollback(Target));
        Error("upgrade_fixture_version_required", () => model.Upgrade(Target, "1.1.0"));
        Equal(before, model.Snapshot());
        model.Upgrade(Target, "1.1.0-fixture");
        model.Upgrade(Target, "1.2.0-fixture");
        model.Rollback(Target);
        Assert.Equal("1.1.0-fixture", model.Snapshot()["plugins"]![Target]!["package_version"]!.GetValue<string>());
        model.Rollback(Target);
        Equal(before, model.Snapshot());
    }

    [Fact]
    public void ConfigurationAndSnapshotsDoNotShareMutableState()
    {
        var config = PluginIsolationFixture.Load();
        var model = new PluginIsolationFixture(config);
        var before = model.Snapshot();
        config["core"]!["health"] = "changed_fixture";
        ((JsonArray)config["plugins"]![0]!["immutable_evidence_refs"]!).Clear();
        var snapshot = model.Snapshot();
        snapshot["core"]!["health"] = "changed_fixture";
        ((JsonArray)snapshot["plugins"]![Target]!["immutable_evidence_refs"]!).Clear();
        Equal(before, model.Snapshot());
        Error("isolation_fixture_plugin_not_found", () => model.Disable("sli.unknown"));
    }

    private static void Equal(JsonNode? expected, JsonNode? actual) => Assert.True(JsonNode.DeepEquals(expected, actual),
        $"Expected {expected}; actual {actual}");
    private static void Error(string code, Action action) => Assert.Equal(code, Assert.Throws<PluginIsolationFixtureError>(action).Message);
}
