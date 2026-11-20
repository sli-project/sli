using System.Net;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class SchedulerCanaryTargetsTests
{
    static Dictionary<string, string?> Settings() => new()
    {
        ["Sli:Operations:ADLOG_DC_CONNECT_MAP"] = "",
        ["Sli:Operations:ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP"] = "",
        ["Sli:Operations:ADLOG_SCHEDULER_CANARY"] = "0",
        ["Sli:Operations:ADLOG_POSTGRES_SCHEDULER_CANARY"] = "0",
        ["Sli:Operations:ADLOG_CANARY_ARCHIVE"] = "0",
        ["Sli:Operations:ADLOG_SCHEDULER_PROFILE"] = "",
        ["Sli:Operations:ADLOG_CANARY_CHANNELS"] = "Security",
        ["Sli:Operations:ADLOG_CANARY_COLLECTION_MODE"] = "current",
        ["Sli:Operations:ADLOG_SCHEDULER_SKIP_REPORT"] = null,
    };

    [Theory]
    [InlineData("ADLOG_DC_CONNECT_MAP")]
    [InlineData("ADLOG_DOMAIN_CONTROLLER_CONNECT_MAP")]
    public async Task EnvironmentEndpointOverrideIsRejectedBeforeReadingTargets(string key)
    {
        var settings = Settings();
        settings["Sli:Operations:" + key] = "DC1=192.0.2.19;DC2=192.0.2.20";
        using var app = await OperationsEndpointTests.Start(settings: settings);
        foreach (string path in new[] { "/api/runtime/status", "/api/domain-controllers" })
        {
            using var response = await OperationsEndpointTests.Request(app, "GET", path);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("Environment DC endpoint override", (string?)(await OperationsEndpointTests.Body(response))["error"]);
        }
        Assert.Equal(0, app.Queries.Reads);
    }

    [Theory]
    [InlineData("ADLOG_SCHEDULER_CANARY", false, false)]
    [InlineData("ADLOG_SCHEDULER_CANARY", false, true)]
    [InlineData("ADLOG_SCHEDULER_CANARY", true, false)]
    [InlineData("ADLOG_SCHEDULER_CANARY", true, true)]
    [InlineData("ADLOG_POSTGRES_SCHEDULER_CANARY", true, false)]
    [InlineData("ADLOG_POSTGRES_SCHEDULER_CANARY", true, true)]
    public async Task RuntimeExposesCanaryArchiveAndFqdnTargets(string flag, bool enabled, bool archive)
    {
        var settings = Settings();
        settings["Sli:Operations:" + flag] = enabled ? "1" : "0";
        settings["Sli:Operations:ADLOG_CANARY_ARCHIVE"] = archive ? "1" : "0";
        using var app = await OperationsEndpointTests.Start(settings: settings);
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/runtime/status");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var scheduler = (await OperationsEndpointTests.Body(response))["scheduler"]!;
        var canary = scheduler["scheduler_canary"]!;
        Assert.False((bool)scheduler["scheduler_enabled"]!);
        Assert.Equal("legacy_collection_disabled", (string?)scheduler["disabled_reason"]);
        Assert.Equal(enabled, (bool)scheduler["scheduler_canary_enabled"]!);
        Assert.Equal(enabled, (bool)canary["enabled"]!);
        Assert.Equal(enabled ? "canary" : "standard", (string?)scheduler["scheduler_profile"]);
        Assert.Equal((string?)scheduler["scheduler_profile"], (string?)canary["profile"]);
        Assert.Equal(archive, (bool)canary["archive_enabled"]!);
        Assert.Equal(archive, (bool)canary["watermark_enabled"]!);
        Assert.Equal(enabled && archive, (bool)canary["archive_watermark_canary"]!);
        Assert.Equal(enabled && archive, (bool)scheduler["scheduler_archive_watermark_canary_enabled"]!);
        Assert.Equal("Security", (string?)Assert.Single(canary["channels"]!.AsArray()));
        Assert.Equal("current", (string?)canary["collection_mode"]);
        var target = Assert.Single(scheduler["domain_controller_targets"]!.AsArray())!;
        Assert.Equal("DC1", (string?)target["hostname"]);
        Assert.Equal("dc1.example.test", (string?)target["connect_address"]);
        Assert.All(app.Queries.Calls, call => Assert.StartsWith("select", call.Sql.TrimStart()));
    }

    [Theory]
    [InlineData("", "current", false)]
    [InlineData("  ", "current", false)]
    [InlineData("current", "current", false)]
    [InlineData(" AUTO ", "auto", true)]
    public async Task CanaryNormalizesCollectionModeAndHonorsExplicitSkipReport(string raw, string mode, bool skip)
    {
        var settings = Settings();
        settings["Sli:Operations:ADLOG_SCHEDULER_CANARY"] = "1";
        settings["Sli:Operations:ADLOG_CANARY_COLLECTION_MODE"] = raw;
        settings["Sli:Operations:ADLOG_SCHEDULER_SKIP_REPORT"] = skip ? "true" : "false";
        using var app = await OperationsEndpointTests.Start(settings: settings);
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/runtime/status");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var scheduler = (await OperationsEndpointTests.Body(response))["scheduler"]!;
        Assert.Equal(mode, (string?)scheduler["scheduler_canary"]?["collection_mode"]);
        Assert.Equal(skip, (bool)scheduler["scheduler_skip_report"]!);
        Assert.Equal(skip, (bool)scheduler["scheduler_canary"]!["skip_report"]!);
    }

    sealed class Queries : IOperationsQueries
    {
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters) => Task.FromResult(new JsonArray());
    }

    [Fact]
    public async Task CanaryCannotStartSchedulerWhileLegacyCollectionIsStopped()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:Legacy:SLI_LEGACY_COLLECTION_DISABLED"] = "1",
            ["Sli:Legacy:ADLOG_ENABLE_INPROCESS_COLLECTION_SCHEDULER"] = "1",
            ["Sli:Legacy:ADLOG_ENABLE_POSTGRES_COLLECTION"] = "1",
            ["Sli:Legacy:ADLOG_SCHEDULER_CANARY"] = "1",
            ["Sli:Legacy:ADLOG_POSTGRES_SCHEDULER_CANARY"] = "1",
        }).Build();
        using var services = new ServiceCollection().BuildServiceProvider();
        using var scheduler = new LegacyScheduler(services.GetRequiredService<IServiceScopeFactory>(), new LegacySettings(config), NullLogger<LegacyScheduler>.Instance);
        await scheduler.StartAsync(TestContext.Current.CancellationToken);
        await scheduler.ExecuteTask!.WaitAsync(TestContext.Current.CancellationToken);
        await scheduler.StopAsync(TestContext.Current.CancellationToken);
        // No database service is registered: any attempt to collect would fail.
        Assert.True(scheduler.ExecuteTask.IsCompletedSuccessfully);
    }
    sealed class ExampleFiles(IConfiguration config, JsonObject example) : OperationsFiles(config)
    {
        public override JsonObject? Json(string relative, int maxBytes = 2097152) => relative == "config/domain_controllers.json" ? example.DeepClone().AsObject() : null;
    }

    [Fact]
    public async Task ExampleConfigurationKeepsBothFqdnEndpointsAndOwnerIpEvidence()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(Settings()).Build();
        var root = new OperationsFiles(config).Root;
        var example = JsonNode.Parse(await File.ReadAllTextAsync(Path.Combine(root, "config", "domain_controllers.example.json"), TestContext.Current.CancellationToken))!.AsObject();
        var service = new OperationsService(new Queries(), new ExampleFiles(config, example), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
        var targets = await service.TargetsAsync(TestContext.Current.CancellationToken);
        Assert.Equal(2, targets.Count);
        for (int i = 0; i < targets.Count; i++)
        {
            Assert.Equal($"DC{i + 1}", (string?)targets[i]?["hostname"]);
            Assert.Equal($"dc{i + 1}.example.test", (string?)targets[i]?["connect_address"]);
            Assert.Equal($"198.51.100.{23 + i}", (string?)targets[i]?["owner_confirmed_ip"]);
        }
    }
}
