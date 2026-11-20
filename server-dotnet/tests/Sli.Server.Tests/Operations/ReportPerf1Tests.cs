using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Operations;
using Sli.Server.Reporting;
using Sli.Server.Storage.EventReports;
using Xunit;
using static Sli.Server.Tests.Operations.OperationsEndpointTests;

namespace Sli.Server.Tests.Operations;

// Behavioral vectors from tests/events/test_report_perf1.py.
public sealed class ReportPerf1Tests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    sealed class Clock : TimeProvider
    {
        public DateTimeOffset Current = Now;
        public override DateTimeOffset GetUtcNow() => Current;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => Current.Ticks;
    }
    static JsonObject Ready(params string[] warnings) => new()
    {
        ["snapshot"] = new JsonObject { ["status"] = "ready", ["refreshing"] = false },
        ["sizes"] = new JsonObject
        {
            ["data"] = new JsonObject { ["bytes"] = 10, ["human"] = "10 Б" },
            ["reports"] = new JsonObject { ["bytes"] = 5, ["human"] = "5 Б" },
            ["logs"] = new JsonObject { ["bytes"] = 2, ["human"] = "2 Б" }
        },
        ["warnings"] = new JsonArray(warnings.Select(w => (JsonNode?)JsonValue.Create(w)).ToArray())
    };
    static async Task<JsonObject> Health(App app, bool force = false)
    {
        using var response = await Request(app, "GET", "/api/system/health" + (force ? "?force=1" : ""));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await Body(response);
    }

    [Fact]
    public async Task System_health_reuses_one_complete_snapshot_across_http_requests()
    {
        var clock = new Clock();
        using var app = await Start(settings: new() { ["Sli:Operations:ADLOG_SYSTEM_HEALTH_CACHE_SECONDS"] = "60" }, clock: clock);
        app.Files.RuntimeStorageValue = Ready();
        app.Queries.SystemInventory = JsonNode.Parse("""
            [{"table_name":"event_hot","estimated_rows":10,"database_size_bytes":100},
             {"table_name":"servers","estimated_rows":2,"database_size_bytes":100},
             {"table_name":"findings","estimated_rows":1,"database_size_bytes":100}]
            """)!.AsArray();
        var first = await Health(app, force: true); int reads = app.Queries.Reads;
        clock.Current += TimeSpan.FromSeconds(1);
        var second = await Health(app);
        Assert.False((bool)first["cache"]!["hit"]!); Assert.True((bool)second["cache"]!["hit"]!);
        Assert.Equal(10,(long)first["db"]!["events"]!);
        Assert.Equal(1000, (long)second["cache"]!["age_ms"]!);
        Assert.Equal(reads, app.Queries.Reads); Assert.Equal(1, app.Files.RuntimeStorageReads);
        Assert.Single(app.Queries.Calls, c => c.Sql.Contains("from pg_class c join pg_namespace"));
        Assert.Equal("full_project_runtime_storage_snapshot", (string?)first["storage"]!["source"]);
        Assert.Equal(10, (int)first["storage"]!["data_dir_bytes"]!);
        Assert.Equal(5, (int)first["storage"]!["reports_dir_bytes"]!);
        Assert.Equal(2, (int)first["storage"]!["logs_dir_bytes"]!);
        Assert.True((bool)first["db"]!["counts_are_estimates"]!);
        Assert.Equal("pg_class.reltuples", (string?)first["db"]!["count_source"]);
        Assert.Equal(100, (long)first["db"]!["size_bytes"]!);
        Assert.Equal(new long[] { 10, 2, 1 }, new[] { "events", "servers", "findings" }.Select(k => (long)first["db"]![k]!));
        clock.Current += TimeSpan.FromSeconds(60);
        Assert.False((bool)(await Health(app))["cache"]!["hit"]!);
        Assert.Equal(2, app.Files.RuntimeStorageReads);
        await Health(app, force: true);
        Assert.Equal(3, app.Files.RuntimeStorageReads);
    }

    [Fact]
    public async Task Warming_storage_reports_unknown_sizes_and_never_caches_partial_health()
    {
        using var app = await Start();
        var first = await Health(app); var second = await Health(app);
        Assert.Equal("warming", (string?)first["runtime_storage"]!["snapshot"]!["status"]);
        Assert.Equal("warn", (string?)first["status"]);
        foreach (string key in new[] { "data", "reports", "logs" })
        { Assert.Null(first["storage"]![key + "_dir_bytes"]); Assert.Equal("—", (string?)first["storage"]![key + "_dir_human"]); }
        Assert.False((bool)second["cache"]!["hit"]!);
        Assert.Equal(2, app.Files.RuntimeStorageReads);
        Assert.Equal(2, app.Queries.Calls.Count(c => c.Sql.Contains("from pg_class c join pg_namespace")));
    }

    [Fact]
    public async Task Postgres_health_deduplicates_warnings_and_omits_a_file_database_path()
    {
        using var app = await Start(); app.Files.RuntimeStorageValue = Ready("same warning", "same warning"); app.Queries.LastEventTime = Now;
        var result = await Health(app, force: true);
        Assert.Equal(new[] { "same warning" }, result["warnings"]!.AsArray().Select(w => (string?)w));
        Assert.Equal("postgres", (string?)result["config"]!["db_backend"]);
        Assert.False(result["config"]!.AsObject().ContainsKey("db_path"));
    }

    sealed class StorageFiles : OperationsFiles, IDisposable
    {
        public readonly List<string> Visited = [];
        public string? Denied;
        public StorageFiles() : this(Path.Combine(Path.GetTempPath(), "report-perf1-" + Guid.NewGuid().ToString("N"))) { }
        StorageFiles(string root) : base(new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = Path.Combine(root, "data") }).Build()) => Directory.CreateDirectory(Root);
        internal override IEnumerable<string> RuntimeEntries(string directory)
        {
            Visited.Add(directory);
            if (directory == Denied) throw new UnauthorizedAccessException("fixture denied");
            return base.RuntimeEntries(directory);
        }
        public override JsonObject DiskPressure() => new() { ["status"] = "ok", ["disk"] = new JsonObject() };
        public void Write(string relative, string value)
        {
            string path = Path.Combine(Root, relative); Directory.CreateDirectory(Path.GetDirectoryName(path)!); File.WriteAllText(path, value, new UTF8Encoding(false));
        }
        public void Dispose() => Directory.Delete(Root, true);
    }

    [Fact]
    public void Runtime_storage_traverses_once_and_preserves_category_sizes_and_counts()
    {
        using var files = new StorageFiles();
        files.Write("data/raw/dc1/events.jsonl", "1234"); files.Write("data/reports/report.html", "123");
        files.Write("backups/source.zip", "12"); files.Write("data/processed/ad_logs.sqlite", "1");
        var data = files.RuntimeStorage(true, Now);
        Assert.Equal("single_pass", (string?)data["scan"]!["mode"]); Assert.Equal(4, (int)data["scan"]!["files_seen"]!);
        Assert.True((bool)data["scan"]!["complete_project_tree"]!);
        foreach (var (key, bytes) in new[] { ("project", 10), ("data", 8), ("raw", 4), ("reports", 3), ("backups", 2), ("sqlite", 1) })
            Assert.Equal(bytes, (long)data["sizes"]![key]!["bytes"]!);
        foreach (string key in new[] { "raw_files", "report_files", "backup_files" }) Assert.Equal(1, (long)data["counts"]![key]!);
        Assert.Equal(files.Visited.Count, files.Visited.Distinct().Count());
        Assert.Equal(Directory.GetDirectories(files.Root, "*", SearchOption.AllDirectories).Length + 1, files.Visited.Count);
    }

    [Fact]
    public void Runtime_storage_reports_an_unreadable_directory_and_an_incomplete_snapshot()
    {
        using var files = new StorageFiles(); files.Denied = Path.Combine(files.Root, "closed"); Directory.CreateDirectory(files.Denied);
        var data = files.RuntimeStorage(true, Now);
        Assert.Equal("project_tree", (string?)data["scan"]!["scope"]);
        Assert.False((bool)data["scan"]!["complete_project_tree"]!); Assert.False((bool)data["scan"]!["follow_symlinks"]!);
        Assert.Equal(1, (int)data["scan"]!["errors"]!);
        Assert.Equal(new[] { files.Denied }, data["scan"]!["error_paths"]!.AsArray().Select(p => (string?)p));
        Assert.Equal("incomplete", (string?)data["snapshot"]!["status"]);
        Assert.Contains(data["warnings"]!.AsArray(), w => w!.ToString().Contains("снимок хранилища неполон"));
    }

    sealed class AuditHttp(bool networkFailure = false) : HttpMessageHandler
    {
        public int Calls;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++; Assert.Equal(HttpMethod.Get, request.Method);
            if (Calls == 1)
            {
                if (networkFailure) throw new HttpRequestException("fixture network failure");
                throw new TimeoutException("fixture timed out");
            }
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                "<!doctype html><html><head><title>ok</title></head><body><h1>content content content content content content content content</h1><p>more report content for audit</p></body></html>", Encoding.UTF8, "text/html") });
        }
    }

    [Fact]
    public async Task Html_audit_classifies_a_timeout_recovered_by_retry_as_performance_only()
    {
        using var handler = new AuditHttp(); using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        var result = await HtmlAudit.RunAsync(client, new Uri("http://127.0.0.1:8080"), [new("only", "/only.html", SlowMs: 10)], Ct);
        Assert.Equal("HTML_AUDIT_2", (string?)result["package_type"]); Assert.Equal("warning", (string?)result["status"]);
        Assert.Equal(0, (int)result["summary"]!["functional_failures"]!); Assert.Equal(1, (int)result["summary"]!["performance_findings"]!);
        var page = Assert.Single(result["pages"]!.AsArray())!;
        Assert.True((bool)page["retried"]!); Assert.Equal(2, handler.Calls);
        Assert.Contains(page["performance_findings"]!.AsArray(), f => (string?)f == "http_timeout");
        Assert.Empty(page["functional_findings"]!.AsArray());
    }

    [Fact]
    public async Task Html_audit_keeps_a_network_failure_functional()
    {
        using var handler = new AuditHttp(networkFailure: true); using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        var result = await HtmlAudit.RunAsync(client, new Uri("http://127.0.0.1:8080"), [new("only", "/only.html", SlowMs: int.MaxValue)], Ct);
        Assert.Equal("failed", (string?)result["status"]); Assert.Equal(1, (int)result["summary"]!["functional_failures"]!);
        Assert.Equal(0, (int)result["summary"]!["performance_findings"]!); Assert.Equal(1, handler.Calls);
    }
}
