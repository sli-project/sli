using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Sli.Server.Storage.Lifecycle;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class OperationsStorageViewTests
{
    [Fact]
    public void PostgresVolumeUsesTheMountContainingTheConfiguredDataDirectory()
    {
        string root = Path.GetPathRoot(Path.GetTempPath())!;
        string volume = Path.Combine(root, "srv", "sli-db");
        string data = Path.Combine(volume, "pgdata", "18", "main");
        var files = new OperationsFiles(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Sli:ProjectRoot"] = Path.Combine(root, "opt", "sli"),
            ["Sli:Operations:SLI_POSTGRES_DATA_DIRECTORY"] = data,
        }).Build());
        Assert.Equal(volume, files.PostgresMount([root, volume, Path.Combine(root, "srv", "sli")]));
        Assert.Equal(root, files.PostgresMount([root, Path.Combine(root, "srv", "sli")]));
    }

    [Theory] [InlineData(false)] [InlineData(true)]
    public async Task ReadinessReportsForeignArchiveRootWithoutExposingPaths(bool foreign)
    {
        using var app = await OperationsEndpointTests.Start();
        string root = foreign ? (OperatingSystem.IsWindows() ? "/var/lib/sli/synthetic" : @"D:\synthetic\archive") : Path.GetTempPath();
        app.Queries.Results[OperationsService.ArchiveRootAvailabilitySql] = new JsonArray(new JsonObject { ["available"] = true });
        app.Queries.Results[OperationsService.ArchiveRootSql] = new JsonArray(new JsonObject { ["archive_root"] = root });
        using var response = await app.Client.GetAsync("/api/v1/operations/overview?view=readiness", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal(foreign ? "invalid_root" : "ok", (string?)body["archive"]?["status"]);
        Assert.DoesNotContain(root, body["archive"]!.ToJsonString());
    }

    [Fact]
    public async Task ReadinessReportsArchiveCheckFailureWithoutExposingException()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.FailContaining = "storage_v2_runtime_authorizations";
        using var response = await app.Client.GetAsync("/api/v1/operations/overview?view=readiness", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal("unavailable", (string?)body["archive"]?["status"]);
        Assert.DoesNotContain("private-db-password", body.ToJsonString());
    }

    [Fact]
    public async Task WorkersViewDoesNotReadQueuesStorageOrCollectors()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Queries.FailContaining = "semantic_processing_outbox";
        using var response = await app.Client.GetAsync("/api/v1/operations/overview?view=workers", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal("ok", (string?)body["workers"]?["status"]);
        Assert.Equal(1, app.Queries.Reads);
        Assert.Null(body["workers"]?["semantic_queues"]);
        Assert.Null(body["postgres"]); Assert.Null(body["collector_health"]);
        Assert.Equal(0, app.Files.FootprintReads);
    }

    [Fact]
    public async Task StorageViewReadsOnlyReadyMeasurementsEvenWhenDatabaseIsDown()
    {
        string root = Path.GetPathRoot(Path.GetTempPath())!;
        using var app = await OperationsEndpointTests.Start(settings: new()
        {
            ["Sli:Operations:SLI_POSTGRES_DATA_DIRECTORY"] = root,
        });
        var before = Stopwatch.StartNew();
        var full = await app.Client.GetAsync("/api/v1/operations/overview", TestContext.Current.CancellationToken);
        await OperationsEndpointTests.Body(full);
        before.Stop();
        Assert.True(full.IsSuccessStatusCode);
        int fullReads = app.Queries.Reads;
        app.Queries.Reads = 0;
        app.Queries.Fail = true;
        app.Files.FootprintValue = JsonNode.Parse("""
            {"generated_at_utc":"2026-11-05T11:00:00Z","components":[{"key":"postgres_database","human":"9.0 GB","bytes":9663676416},
             {"key":"clickhouse_volume_history","human":"11 GB","bytes":11000},
             {"key":"project_root","human":"3 GB"}],
             "backups":{"last_backup_at_utc":"2026-11-13T10:00:00Z","capacity_days":7,"same_disk_as_postgres":true}}
            """)!.AsObject();
        var timer = Stopwatch.StartNew();
        var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        timer.Stop();
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal("9.0 GB", (string?)body["storage"]?["footprint"]?["components"]?[0]?["human"]);
        Assert.Equal(1000000000000L, (long?)body["storage"]?["disk_pressure"]?["disk"]?["free_bytes"]);
        Assert.Equal(root, (string?)body["storage"]?["postgres_volume"]?["mount_point"]);
        Assert.Equal("2026-11-13T10:00:00Z", (string?)body["storage"]?["footprint"]?["backups"]?["last_backup_at_utc"]);
        Assert.True((bool?)body["storage"]?["footprint"]?["backups"]?["same_disk_as_postgres"]);
        Assert.Null(body["collector_health"]); Assert.Null(body["workers"]); Assert.Null(body["plugin_pilots"]);
        Assert.Equal(0, app.Queries.Reads); Assert.Equal(0, app.Files.Scans); Assert.Equal(0, app.Files.Inventories);
        Assert.Equal(0, app.Files.RuntimeStorageReads);
        Assert.DoesNotContain("project_root", body.ToJsonString());
        Console.WriteLine($"HTTP in-memory host: full overview {before.Elapsed.TotalMilliseconds:F2} ms ({fullReads} SQL reads); storage view {timer.Elapsed.TotalMilliseconds:F2} ms (0 SQL reads)");
    }

    [Theory]
    [InlineData(1048576L, -2, true)]
    [InlineData(0L, -1, true)]
    [InlineData(null, -1, false)]
    [InlineData(-1L, -1, false)]
    [InlineData(1048576L, -25, false)]
    [InlineData(1048576L, 1, false)]
    public async Task StorageViewReadsFreshLogicalSizeWithoutPhysicalFootprint(long? bytes, int hours, bool measured)
    {
        using var state = new Sli.Server.Tests.Storage.StorageLifecycleTests.State();
        using var app = await OperationsEndpointTests.Start(settings: new() { ["Sli:DataDirectory"] = state.Path });
        app.Queries.Fail = true;
        DateTimeOffset observed = OperationsEndpointTests.Now.AddHours(hours);
        if (bytes is not null)
            state.Files.Write("storage-database-usage.json", new JsonObject {
                ["database_bytes"] = bytes, ["observed_at_utc"] = observed.ToString("O"),
            });

        using var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        var rows = body["storage"]!["footprint"]!["components"]!.AsArray();
        if (measured)
        {
            var row = Assert.Single(rows);
            Assert.Equal("postgres_database", (string?)row?["key"]);
            Assert.Equal(bytes, (long?)row?["bytes"]);
            Assert.Equal(bytes == 0 ? "0 B" : "1.0 MB", (string?)row?["human"]);
            Assert.Equal(observed, DateTimeOffset.Parse((string)row!["observed_at_utc"]!));
        }
        else Assert.Empty(rows);
        Assert.Equal(1000000000000L, (long?)body["storage"]?["disk_pressure"]?["disk"]?["free_bytes"]);
        Assert.Equal(0, app.Queries.Reads);
        Assert.Equal(0, app.Files.Scans);
    }

    [Theory]
    [InlineData(-3, 1048576L)]
    [InlineData(-1, 2097152L)]
    public async Task StorageViewUsesTheNewestValidLogicalMeasurement(int manualAgeHours, long expectedBytes)
    {
        using var state = new Sli.Server.Tests.Storage.StorageLifecycleTests.State();
        using var app = await OperationsEndpointTests.Start(settings: new() { ["Sli:DataDirectory"] = state.Path });
        var now = OperationsEndpointTests.Now;
        state.Files.Write("storage-database-usage.json", new JsonObject {
            ["database_bytes"] = 1048576L, ["observed_at_utc"] = now.AddHours(-2).ToString("O"),
        });
        app.Files.FootprintValue = new JsonObject {
            ["generated_at_utc"] = now.ToString("O"),
            ["components"] = new JsonArray(new JsonObject { ["key"] = "postgres_database", ["bytes"] = 2097152L }),
            ["postgres"] = new JsonObject { ["database"] = new JsonObject { ["checked_at"] = now.AddHours(manualAgeHours).ToString("O") } },
        };

        using var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        var row = Assert.Single(body["storage"]!["footprint"]!["components"]!.AsArray());
        Assert.Equal(expectedBytes, (long?)row?["bytes"]);
        Assert.Equal(0, app.Queries.Reads);
    }

    [Fact]
    public async Task GrowthViewUsesMeasurementsWithoutStartingFallbackFilesystemScans()
    {
        using var app = await OperationsEndpointTests.Start();
        var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage-growth", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Equal(1000, (long?)body["measured_growth"]?["components"]?["database_bytes"]?["bytes_per_day"]);
        Assert.Null(body["measured_growth"]?["components"]?["disk_used_bytes"]);
        Assert.Equal(0, app.Files.Scans); Assert.Equal(0, app.Files.Inventories);
        Assert.Null(body["fallback_estimate"]); Assert.Null(body["workers"]);
    }

    [Fact]
    public async Task GrowthViewDoesNotInventMeasurementsWhenDatabaseIsDown()
    {
        using var app = await OperationsEndpointTests.Start(); app.Queries.Fail = true;
        var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage-growth", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.True(response.IsSuccessStatusCode);
        Assert.Null(body["measured_growth"]); Assert.Null(body["forecast"]);
        Assert.Equal(0, app.Files.Scans);
    }

    [Fact]
    public async Task GrowthViewPreservesMeasuredDiskGrowthAndExistingStopThresholdForecast()
    {
        using var app = await OperationsEndpointTests.Start();
        JsonObject Snapshot(int age, long database, long used) => new() {
            ["captured_at"] = OperationsEndpointTests.Now.AddDays(-age).ToString("O"),
            ["database_bytes"] = database, ["disk_used_bytes"] = used, ["disk_total_bytes"] = 100000, ["disk_free_bytes"] = 100000 - used,
            ["raw_bytes"] = 0, ["raw_archive_bytes"] = 0, ["logs_bytes"] = 0, ["reports_bytes"] = 0, ["backups_bytes"] = 0, ["artifacts_bytes"] = 0 };
        app.Queries.Results[OperationsService.StorageGrowthSql] = new JsonArray(Snapshot(0, 2000, 30000), Snapshot(1, 1000, 29000));
        var response = await app.Client.GetAsync("/api/v1/operations/overview?view=storage-growth", TestContext.Current.CancellationToken);
        var body = await OperationsEndpointTests.Body(response);
        Assert.Equal(1000, (long?)body["measured_growth"]?["components"]?["disk_used_bytes"]?["bytes_per_day"]);
        Assert.Equal(60d, (double?)body["forecast"]?["estimated_days"]);
        Assert.Equal(0, app.Files.Scans);
    }

    [Theory]
    [InlineData("storage")]
    [InlineData("storage-growth")]
    [InlineData("workers")]
    public async Task StorageViewPreservesCapabilityGate(string view)
    {
        using var app = await OperationsEndpointTests.Start(allow: false);
        var response = await app.Client.GetAsync("/api/v1/operations/overview?view=" + view, TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(0, app.Files.FootprintReads);
    }
}
