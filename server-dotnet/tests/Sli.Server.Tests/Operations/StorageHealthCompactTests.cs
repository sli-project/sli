using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Sli.Server.Domains;
using Sli.Server.Operations;
using Xunit;

namespace Sli.Server.Tests.Operations;

public sealed class StorageHealthCompactTests
{
    [Fact]
    public void HealthKeepsDecisionFieldsWithoutTableDump()
    {
        var source = JsonNode.Parse("""
            {"status":"warn","warnings":["полный обход проекта неполон: ошибок чтения 2"],
             "disk_pressure":{"collection_allowed":true,"disk":{"free_human":"100 GB","free_percent":25},"blocking_threshold":{"free_human":"10 GB"}},
             "postgres_operations":{"status":"ok","connectivity_status":"ready","metrics_status":"complete","database":{"database_human":"10 GB"},"tables":[{"table_name":"events"}]},
             "project_overview":{"total_human":"12 GB","scan":{"complete_project_tree":false,"errors":2,"error_paths":["one","two"]}},
             "cleanup_preview":{"total_candidates":0,"total_human":"0 B"}}
            """)!.AsObject();

        var compact = OperationsStorageCompact.Health(source);

        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""
            {"status":"warn","warnings":["полный обход проекта неполон: ошибок чтения 2"],
             "disk":{"free_bytes":null,"free_human":"100 GB","free_percent":25,"collection_allowed":true,"blocking_free_human":"10 GB"},
             "postgres":{"status":"ok","connectivity_status":"ready","metrics_status":"complete","database_name":null,"database_bytes":null,"database_human":"10 GB","checked_at":null},
             "project":{"files_human":null,"database_human":null,"total_human":"12 GB","scan_complete":false,"scan_errors":2,"scan_error_paths":["one","two"]},
             "cleanup_preview":{"total_candidates":0,"total_human":"0 B"},"last_cleanup":null,
             "safety":{"read_only":true,"cleanup_executed":false,"vacuum_executed":false}}
            """), compact));
        Assert.True(source["postgres_operations"]!.AsObject().ContainsKey("tables"));
    }

    [Fact]
    public void EmptyHealthDoesNotInventMeasurementsAndLastCleanupIsCompact()
    {
        var compact = OperationsStorageCompact.Health(new());
        Assert.Null(compact["disk"]!["free_percent"]);
        Assert.Null(compact["project"]!["scan_complete"]);
        Assert.Empty(compact["warnings"]!.AsArray());
        Assert.Empty(compact["project"]!["scan_error_paths"]!.AsArray());
        Assert.Null(compact["last_cleanup"]);
        var source = JsonNode.Parse("""{"last_cleanup":{"status":"ok","mode":"dry-run","generated_at_utc":"2026-07-27T03:00:00+00:00","actions":[{"path":"omitted"}]}}""")!.AsObject();
        compact = OperationsStorageCompact.Health(source);
        Assert.Equal(3, compact["last_cleanup"]!.AsObject().Count);
        Assert.Equal("dry-run", (string?)compact["last_cleanup"]!["mode"]);
        Assert.Equal("2026-07-27T03:00:00+00:00", (string?)compact["last_cleanup"]!["generated_at_utc"]);
    }

    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(1, 1, 0)]
    [InlineData(10, 10, 0)]
    [InlineData(12, 10, 2)]
    public void CleanupOmitsFullActionsButCountsEveryCandidate(int count, int sampled, int omitted)
    {
        var actions = new JsonArray(Enumerable.Range(0, count).Select(i => (JsonNode)new JsonObject
            { ["category"] = i % 2 == 0 ? "logs" : null, ["size_bytes"] = 1024, ["path"] = $"logs/{i}.debug.log" }).ToArray());
        var result = new JsonObject { ["status"] = "ok", ["mode"] = "dry-run", ["actions"] = actions,
            ["total_candidates"] = count, ["total_bytes"] = count * 1024, ["total_human"] = "fixture",
            ["safety"] = new JsonObject { ["dry_run_default"] = true } };
        var compact = OperationsStorageCompact.Cleanup(result);
        Assert.False(compact.ContainsKey("actions"));
        Assert.Equal(count, (int)compact["total_candidates"]!);
        Assert.Equal(count * 1024, (int)compact["total_bytes"]!);
        Assert.Equal(sampled, compact["actions_sample"]!.AsArray().Count);
        Assert.Equal(omitted, (int)compact["actions_omitted"]!);
        Assert.True((bool)compact["safety"]!["dry_run_default"]!);
        Assert.Empty(compact["applied"]!.AsArray());
        Assert.Empty(compact["errors"]!.AsArray());
        if (count > 0)
        {
            Assert.Equal("logs/0.debug.log", (string?)compact["actions_sample"]![0]!["path"]);
            Assert.Equal((count + 1) / 2, (int)compact["by_category"]!["logs"]!["count"]!);
            Assert.Equal((count + 1) / 2 * 1024, (long)compact["by_category"]!["logs"]!["bytes"]!);
        }
        if (count == 12)
        {
            Assert.Equal(6, (int)compact["by_category"]!["unknown"]!["count"]!);
            Assert.Equal("6.0 KB", (string?)compact["by_category"]!["unknown"]!["human"]);
        }
        Assert.Equal(count, actions.Count);
    }

    [Fact]
    public async Task HealthJsonSerializesPostgresTimestampAndLifecycleDecimal()
    {
        var context = new DefaultHttpContext();
        await using var output = new MemoryStream(); context.Response.Body = output;
        var payload = new JsonObject
        {
            ["postgres_operations"] = new JsonObject { ["database"] = new JsonObject { ["checked_at"] = new DateTimeOffset(2026, 7, 27, 3, 0, 0, TimeSpan.Zero) } },
            ["storage_lifecycle"] = new JsonObject { ["latest_snapshot"] = new JsonObject { ["disk_free_percent"] = 12.50m } },
            ["safety"] = new JsonObject { ["read_only"] = true }
        };
        await DomainHttp.WriteAsync(context, payload, 200, TestContext.Current.CancellationToken);
        output.Position = 0;
        var body = (await JsonNode.ParseAsync(output, cancellationToken: TestContext.Current.CancellationToken))!;
        Assert.Equal("2026-07-27T03:00:00+00:00", (string?)body["postgres_operations"]!["database"]!["checked_at"]);
        Assert.Equal(12.5m, (decimal)body["storage_lifecycle"]!["latest_snapshot"]!["disk_free_percent"]!);
        Assert.True((bool)body["safety"]!["read_only"]!);
    }

    [Fact]
    public async Task HealthEndpointSupportsSummaryWithoutChangingDefaultReport()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Files.RuntimeStorageValue = JsonNode.Parse("""{"sizes":{"project":{"human":"12 GB"}},"scan":{"complete_project_tree":false,"errors":2,"error_paths":["one","two"]},"warnings":["полный обход проекта неполон: ошибок чтения 2"]}""")!.AsObject();
        using var fullResponse = await OperationsEndpointTests.Request(app, "GET", "/api/storage/health");
        var full = await OperationsEndpointTests.Body(fullResponse);
        Assert.True(full.ContainsKey("postgres_operations"));
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/storage/health?summary_only=1");
        var compact = await OperationsEndpointTests.Body(response);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(compact.ContainsKey("postgres_operations"));
        Assert.Equal("ready", (string?)compact["postgres"]?["connectivity_status"]);
        Assert.False(compact["postgres"]!.AsObject().ContainsKey("tables"));
        Assert.True((bool)compact["safety"]!["read_only"]!);
        Assert.False((bool)compact["safety"]!["cleanup_executed"]!);
        Assert.Equal("12 GB", (string?)compact["project"]!["files_human"]);
        Assert.False((bool)compact["project"]!["scan_complete"]!);
        Assert.Equal(2, (int)compact["project"]!["scan_errors"]!);
        Assert.Equal(new[] { "one", "two" }, compact["project"]!["scan_error_paths"]!.AsArray().Select(n => (string)n!));
        Assert.Contains(compact["warnings"]!.AsArray(), n => (string?)n == "полный обход проекта неполон: ошибок чтения 2");
    }

    [Fact]
    public async Task ReleaseCheckUsesCompactReadOnlyCleanupWithRealOldLogCandidate()
    {
        string root = Path.Combine(Path.GetTempPath(), "sli-health-compact-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "data", "logs"));
        string old = Path.Combine(root, "data", "logs", "old.debug.log");
        try
        {
            await File.WriteAllTextAsync(old, "x", TestContext.Current.CancellationToken);
            File.SetLastWriteTimeUtc(old, new DateTime(2001, 9, 9, 1, 46, 40, DateTimeKind.Utc));
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(root, "data"), ["Sli:Operations:ADLOG_LOG_RETENTION_DAYS"] = "1" }).Build();
            var service = new OperationsService(new OperationsEndpointTests.Queries(), new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), TimeProvider.System);
            var diagnostics = await service.ReadAsync("/api/diagnostics/overview", new() { ["run_checks"] = ["1"] }, TestContext.Current.CancellationToken);
            var cleanup = diagnostics["parsed_checks"]!["release_check"]!["storage_cleanup_dry_run"]!;
            Assert.Equal(0, (int)cleanup["exit_code"]!);
            var summary = JsonNode.Parse((string)cleanup["stdout_tail"]!)!;
            Assert.Null(summary["actions"]);
            Assert.Equal(1, (int)summary["total_candidates"]!);
            Assert.Equal(old, (string?)summary["actions_sample"]![0]!["path"]);
            Assert.Equal("x", await File.ReadAllTextAsync(old, TestContext.Current.CancellationToken));
            Assert.False(File.Exists(Path.Combine(root, "data", "logs", "audit-actions.log")));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
