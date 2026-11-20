using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Sli.Server.Access;
using Sli.Server.Compatibility;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Operations;

// Input/output vectors from tests/sources/test_collector_health.py.
public sealed class CollectorHealthParityTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-05T12:00:00Z");
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Queries : IOperationsQueries
    {
        public JsonArray History = [];
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            if (sql == OperationsSql.CollectorHistory)
            {
                Assert.Equal(Now.AddHours(-24), DateTimeOffset.Parse((string)Assert.Single(parameters).Value!));
                return Task.FromResult(History.DeepClone().AsArray());
            }
            return Task.FromResult(sql == OperationsSql.CollectorState ? new JsonArray(new JsonObject
            {
                ["server_hostname"] = "DC1", ["channel"] = "Security", ["last_successful_collection_utc"] = Now.ToString("O"),
                ["last_event_time_utc"] = Now.ToString("O"), ["last_event_record_id"] = 9001, ["updated_at"] = Now.ToString("O"),
                ["event_count"] = 1, ["current_limit"] = 500, ["recovery_mode"] = false
            }) : new JsonArray());
        }
    }
    sealed class Fixture : IDisposable
    {
        readonly string root = Path.Combine(Path.GetTempPath(), "sli-collector-parity-" + Guid.NewGuid().ToString("N"));
        public readonly Queries Queries = new();
        public readonly OperationsService Service;
        public readonly OperationsFiles Files;
        public Fixture()
        {
            Directory.CreateDirectory(root);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:ProjectRoot"] = root, ["Sli:DataDirectory"] = root, ["Sli:LogDirectory"] = root
            }).Build();
            Files = new(config);
            Service = new(Queries, Files, new OperationsCatalog(), new OperationsJobs(), new Clock());
        }
        public void Write(params string[] lines) => File.WriteAllLines(Path.Combine(root, "adlog-monitor.log"), lines);
        public void Dispose() => Directory.Delete(root, true);
    }
    static string Record(string text, string? time = "2026-11-05T12:00:00Z", string server = "DC1") =>
        new JsonObject { ["ts"] = time, ["level"] = "ERROR", ["component"] = "collector", ["event"] = "server_collection_failed", ["server"] = server, ["stdout_tail"] = text }.ToJsonString();
    const string Partial = "Timed out channel: Security after 300s partial_count=10\nSecurity.jsonl: inserted=0, skipped=900\n";

    [Fact] public async Task Partial_timeout_and_repeated_backlog_are_visible_without_run_history()
    {
        using var fixture = new Fixture(); fixture.Write(Record(Partial));
        var data = await fixture.Service.CollectorAsync(TestContext.Current.CancellationToken);
        var security = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal("DC1", security["server"]!.ToString()); Assert.Equal("Security", security["channel"]!.ToString());
        Assert.Equal(1, security["partial_timeouts_24h"]!.GetValue<long>());
        Assert.Equal(1, security["timeouts_24h"]!.GetValue<long>());
        Assert.True(security["timeouts_24h_available"]!.GetValue<bool>());
        Assert.Equal(10, security["last_partial_count"]!.GetValue<long>());
        Assert.Equal(900, security["skipped_24h"]!.GetValue<long>());
        Assert.Equal("partial_timeout", security["last_status"]!.ToString());
        Assert.Contains(security["warnings"]!.AsArray(), value => value!.ToString() == "possible repeated backlog read");
        string html = LegacyCollectorHealth.Render(data["items"]!.DeepClone().AsArray(), [], []);
        Assert.Contains("Состояние сбора по каналам", html); Assert.Contains("DC1", html);
    }

    [Fact] public async Task Database_zero_counters_remain_authoritative_over_log_timeouts()
    {
        using var fixture = new Fixture(); fixture.Write(Record(Partial));
        fixture.Queries.History.Add(new JsonObject { ["server"] = "DC1", ["channel"] = "Security", ["last_status"] = "completed", ["timeouts_24h"] = 0, ["partial_timeouts_24h"] = 0 });
        var data = await fixture.Service.CollectorAsync(TestContext.Current.CancellationToken);
        var item = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(0, item["timeouts_24h"]!.GetValue<long>()); Assert.Equal(0, item["partial_timeouts_24h"]!.GetValue<long>());
        Assert.Equal("completed", item["last_status"]!.ToString());
        Assert.DoesNotContain(item["warnings"]!.AsArray(), v => v!.ToString() == "possible repeated backlog read");
    }

    [Theory]
    [InlineData("2026-11-04T11:59:59Z", 0, false)]
    [InlineData("2026-11-04T12:00:00Z", 1, true)]
    [InlineData(null, 1, false)]
    [InlineData("invalid", 1, false)]
    [InlineData("2026-11-05T12:00:01Z", 1, false)]
    public async Task Log_window_and_unknown_timestamps_preserve_counter_availability(string? time, long count, bool available)
    {
        using var fixture = new Fixture(); fixture.Write("invalid json", "[]", Record(Partial, time));
        var data = await fixture.Service.CollectorAsync(TestContext.Current.CancellationToken);
        var item = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(count, item["partial_timeouts_24h"]!.GetValue<long>());
        Assert.Equal(available, item["timeouts_24h_available"]!.GetValue<bool>());
    }

    [Fact] public async Task Missing_log_is_safe_and_report_escapes_untrusted_server()
    {
        using var fixture = new Fixture();
        var data = await fixture.Service.CollectorAsync(TestContext.Current.CancellationToken);
        var item = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(0, item["partial_timeouts_24h"]!.GetValue<long>());
        item["server"] = "<script>alert(1)</script>";
        string html = LegacyCollectorHealth.Render(data["items"]!.DeepClone().AsArray(), [], []);
        Assert.DoesNotContain("<script>", html); Assert.Contains("&lt;script&gt;", html);
    }

    [Fact] public void Non_postgres_configuration_is_rejected_before_collector_queries()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { ["ConnectionStrings:Sli"] = "Data Source=collector-test.db" }).Build();
        var error = Assert.Throws<ServerConfigurationException>(() => new OperationsQueries(new PostgresConnectionFactory(config)));
        Assert.Equal("server_configuration_invalid:ConnectionStrings:Sli:invalid", error.Message);
    }

    sealed class EventReader(JsonObject row) : IEventReadService
    {
        public Task<IReadOnlyList<AccessResource>> ResourcesAsync(long id, CancellationToken ct)
        { Assert.Equal(5, id); return Task.FromResult<IReadOnlyList<AccessResource>>([new("server", 1)]); }
        public async Task<Dictionary<long, JsonObject>> DetailsAsync(long[] ids, bool exact, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct)
        {
            Assert.Equal(new long[] { 5 }, ids); Assert.True(exact); Assert.True(await admitted(5, ct));
            return new() { [5] = EventDetailProjection.Normalize(row, []) };
        }
        public Task<JsonObject> RelationsAsync(long id, Func<long, CancellationToken, Task<bool>> admitted, CancellationToken ct) => throw new InvalidOperationException("Unexpected relations read");
    }
    [Fact] public async Task One_storage_v2_event_preserves_logon_and_investigation_links()
    {
        var row = JsonNode.Parse("""{"id":5,"server":"DC1","channel":"Security","event_id":4624,"event_record_id":1,"time_created_utc":"2026-07-07T10:00:00Z","subject_user_name":"svc_backup","target_user_name":"svc_backup","logon_id":"0xabc","event_data_json":"{}"}""")!.AsObject();
        var reader = new LegacyHttpReader( new EventReader(row), NullLogger<LegacyHttpReader>.Instance);
        var data = await reader.ReadAsync("/api/events/details", new LegacyQuery(new JsonObject { ["event_db_id"] = 5 }), TestContext.Current.CancellationToken);
        Assert.Equal(1, data["total"]!.GetValue<int>());
        var result = Assert.Single(data["items"]!.AsArray())!;
        Assert.Equal(5, result["id"]!.GetValue<int>()); Assert.Equal("0xabc", result["logon_id"]!.ToString());
        var links = result["investigation_links"]!.AsArray();
        var logon = Assert.Single(links, v => v!["label"]!.ToString() == "Тот же LogonId")!;
        Assert.Contains("logon_id=0xabc", logon["url"]!.ToString()); Assert.Contains("server=DC1", logon["url"]!.ToString());
        var near = Assert.Single(links, v => v!["label"]!.ToString() == "Соседние события ±15 минут")!;
        Assert.Contains("time_from=2026-07-07T09%3A45%3A00%2B00%3A00", near["url"]!.ToString());
        Assert.Contains("time_to=2026-07-07T10%3A15%3A00%2B00%3A00", near["url"]!.ToString());
    }
}
