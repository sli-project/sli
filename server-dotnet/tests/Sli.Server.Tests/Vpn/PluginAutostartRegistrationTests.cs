using System.Text.Json.Nodes;
using Sli.Server.Operations;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

public sealed class PluginAutostartRegistrationTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-09T10:00:00Z");

    private static JsonObject Heartbeat(string component = "radius-acquisition", double age = 0) => new() {
        ["plugin_id"] = "sli.remote-access", ["component_id"] = component,
        ["status"] = "blocked", ["phase"] = "cycle_failed", ["heartbeat_at_utc"] = Now.AddSeconds(-age).ToString("O")
    };

    [Fact]
    public void OperationsMapsTwoSeparatePluginComponents()
    {
        var components = OperationsService.Components.Where(c => c.Plugin is not null).ToArray();
        Assert.Equal(2, components.Length);
        Assert.Equal("radius-acquisition", Assert.Single(components, c => c.Name == "plugin_radius_acquisition").Plugin);
        Assert.Equal("radius-session-observation", Assert.Single(components, c => c.Name == "plugin_radius_session_observation").Plugin);
    }

    // These vectors inspect shipped PowerShell artifacts in the Python suite too.
    // Read them as text; never install a task or provision a real credential.
    private static string Script(string name)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent) {
            string path = Path.Combine(directory.FullName, "scripts", "ops", name);
            if (File.Exists(path)) return File.ReadAllText(path);
        }
        throw new FileNotFoundException("Supervisor installation artifact missing", name);
    }

    [Fact]
    public void InstallerDerivesTaskAndRuntimeIdentityFromCurrentSession()
    {
        string source = Script("Install-SLIWorkerSupervisor.ps1");
        Assert.Contains("ADLOG_COLLECTION_PRINCIPAL", source);
        Assert.Contains("ADLOG_COLLECTION_PRINCIPAL_SID", source);
        Assert.DoesNotContain("$ExpectedPrincipal = \"EXAMPLE\\operator\"", source);
    }

    [Fact]
    public void InstallerUsesPeriodicSelfHealingBootstrap()
    {
        string installer = Script("Install-SLIWorkerSupervisor.ps1"), bootstrap = Script("Start-SLIWorkerSupervisor.ps1");
        Assert.Contains("Start-SLIWorkerSupervisor.ps1", installer);
        Assert.Contains("RepetitionInterval", installer);
        Assert.Contains("Minutes 5", installer);
        Assert.Contains("worker-supervisor-bootstrap.json", bootstrap);
    }

    [Fact]
    public void InstallerCanRepairTaskWithoutReprovisioningSecrets()
    {
        string source = Script("Install-SLIWorkerSupervisor.ps1");
        Assert.Contains("[switch]$RepairTaskOnly", source);
        Assert.Contains("if (-not $RepairTaskOnly)", source);
        Assert.Contains("environment_provisioned", source);
    }

    [Fact]
    public void InstallerAcceptsSchedulerShortPrincipalReadback()
    {
        string source = Script("Install-SLIWorkerSupervisor.ps1");
        Assert.Contains("$ConfiguredShortPrincipal", source);
        Assert.Contains("principal_matches = (", source);
    }

    [Theory]
    [InlineData("radius-acquisition", "enabled_manual", "running", "open", true)]
    [InlineData("radius-session-observation", "enabled_manual", "running", "open", true)]
    [InlineData("radius-session-observation", "disabled", "draining", "drain_only", true)]
    [InlineData("radius-acquisition", "disabled", "draining", "drain_only", false)]
    [InlineData("radius-session-observation", "disabled", "stopped", "closed", false)]
    [InlineData("radius-session-observation", "enabled_manual", "running", "drain_only", false)]
    [InlineData("radius-session-observation", "disabled", "running", "open", false)]
    [InlineData("unknown", "enabled_manual", "running", "open", false)]
    public void GuardAllowsOnlyExactRuntimeStates(string component, string activation, string runtime, string admission, bool expected)
    {
        var state = new JsonObject { ["desired_activation"] = activation, ["component_runtime"] = runtime, ["admission_mode"] = admission };
        Assert.Equal(expected, RadiusPluginLaunchGuard.Allowed(component, state));
        Assert.False(RadiusPluginLaunchGuard.Allowed(component, null));
        Assert.False(RadiusPluginLaunchGuard.Allowed(component, new JsonObject()));
    }

    [Theory]
    [InlineData(0, 1800)]
    [InlineData(1, 1799)]
    [InlineData(1799, 1)]
    public void RecentBlockedHeartbeatEnforcesReferenceRetryPolicy(double age, long retry)
    {
        foreach (string component in new[] { "radius-acquisition", "radius-session-observation" }) {
            var block = RadiusPluginLaunchGuard.RecentBlock(component, Heartbeat(component, age), Now);
            Assert.NotNull(block);
            Assert.Equal(retry, block["retry_after_seconds"]!.GetValue<long>());
            Assert.Equal((long)age, block["heartbeat_age_seconds"]!.GetValue<long>());
            Assert.Equal("cycle_failed", block["phase"]!.GetValue<string>());
        }
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(1800)]
    [InlineData(1801)]
    public void FutureAndExpiredHeartbeatsDoNotBlock(double age) =>
        Assert.Null(RadiusPluginLaunchGuard.RecentBlock("radius-acquisition", Heartbeat(age: age), Now));

    [Theory]
    [InlineData("plugin_id", "another-plugin")]
    [InlineData("component_id", "radius-session-observation")]
    [InlineData("status", "running")]
    [InlineData("heartbeat_at_utc", "2026-11-09T10:00:00")]
    [InlineData("heartbeat_at_utc", "invalid")]
    public void UnrelatedOrInvalidEvidenceDoesNotBlock(string key, string value)
    {
        var heartbeat = Heartbeat(); heartbeat[key] = value;
        Assert.Null(RadiusPluginLaunchGuard.RecentBlock("radius-acquisition", heartbeat, Now));
        heartbeat[key] = null;
        Assert.Null(RadiusPluginLaunchGuard.RecentBlock("radius-acquisition", heartbeat, Now));
        heartbeat[key] = 123;
        Assert.Null(RadiusPluginLaunchGuard.RecentBlock("radius-acquisition", heartbeat, Now));
    }

    [Fact]
    public void OffsetTimestampUsesUtcAge()
    {
        var heartbeat = Heartbeat(); heartbeat["heartbeat_at_utc"] = "2026-11-09T16:59:00+07:00";
        Assert.Equal(1740L, RadiusPluginLaunchGuard.RecentBlock("radius-acquisition", heartbeat, Now)!["retry_after_seconds"]!.GetValue<long>());
    }

    [Fact]
    public async Task FileBackoffPreservesFailureAndSeparatesComponentsBeforeAnyCycle()
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-plugin-guard-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            string path = Path.Combine(directory, "plugin-radius-session-observation.json");
            string original = Heartbeat("radius-session-observation").ToJsonString();
            await File.WriteAllTextAsync(path, original, TestContext.Current.CancellationToken);
            int calls = 0;
            Task<int> Cycle() { calls++; return Task.FromResult(0); }
            Assert.Equal(10, await RadiusPluginLaunchGuard.RunAsync("radius-session-observation", Cycle, Now, directory));
            Assert.Equal(0, calls);
            Assert.Equal(original, await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
            Assert.Equal(0, await RadiusPluginLaunchGuard.RunAsync("radius-acquisition", Cycle, Now, directory));
            Assert.Equal(1, calls);
            Assert.Equal(0, await RadiusPluginLaunchGuard.RunAsync("radius-session-observation", Cycle, Now.AddSeconds(1800), directory));
            Assert.Equal(2, calls);
        }
        finally { Directory.Delete(directory, true); }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("{broken")]
    [InlineData("[]")]
    [InlineData("null")]
    [InlineData("{}")]
    public void MissingOrUnreadableHeartbeatIsNotARecentBlock(string? content)
    {
        string directory = Path.Combine(Path.GetTempPath(), "sli-plugin-heartbeat-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try {
            if (content is not null) File.WriteAllText(Path.Combine(directory, "plugin-radius-acquisition.json"), content);
            Assert.Null(RadiusPluginLaunchGuard.ReadRecentBlock("radius-acquisition", Now, directory));
            Assert.Null(RadiusPluginLaunchGuard.ReadRecentBlock("../other", Now, directory));
        }
        finally { Directory.Delete(directory, true); }
    }
}
