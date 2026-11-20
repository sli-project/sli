using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using NpgsqlTypes;
using Sli.Server.Operations;
using Xunit;
using static Sli.Server.Operations.OpsJson;

namespace Sli.Server.Tests.Operations;

public sealed class CollectorBudgetAccountingTests
{
    static readonly DateTimeOffset Now = OperationsEndpointTests.Now;
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Queries : IOperationsQueries
    {
        internal JsonArray History = [];
        internal JsonArray States = new(State("Security"));
        internal int Stale;
        public Task<JsonArray> ReadAsync(string sql, CancellationToken ct, params (string Name, object? Value)[] parameters)
        {
            JsonArray rows = [];
            if (sql == OperationsSql.CollectorHistory)
            {
                Assert.Contains("status in ('timeout', 'partial_timeout')", sql);
                Assert.Contains("status = 'partial_timeout'", sql);
                Assert.Equal("cutoff", Assert.Single(parameters).Name);
                Assert.Equal(Stamp(Now.AddHours(-24)), parameters[0].Value);
                rows = History;
            }
            else if (sql == OperationsSql.CollectorState) rows = States;
            else if (sql.Contains("post_collection_jobs group by status")) rows = new(new JsonObject { ["status"] = "queued", ["count"] = 2 });
            else if (sql.Contains("from post_collection_jobs order by id"))
                rows = new(Enumerable.Range(0, Stale).Select(_ => (JsonNode)new JsonObject { ["status"] = "running", ["heartbeat_at"] = Stamp(Now.AddHours(-1)) }).ToArray());
            return Task.FromResult(rows.DeepClone().AsArray());
        }
    }
    sealed class Fixture : IDisposable
    {
        readonly string root = Path.Combine(Path.GetTempPath(), "sli-budget-" + Guid.NewGuid().ToString("N"));
        internal readonly Queries Queries = new();
        internal readonly OperationsService Service;
        internal Fixture()
        {
            Directory.CreateDirectory(root);
            var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sli:DataDirectory"] = root, ["Sli:LogDirectory"] = root,
                ["Sli:Operations:ADLOG_COLLECTION_INTERVAL_SECONDS"] = "600"
            }).Build();
            Service = new(Queries, new OperationsFiles(config), new OperationsCatalog(), new OperationsJobs(), new Clock());
        }
        internal void Log(string text, string? timestamp = "now") => File.WriteAllText(Path.Combine(root, "adlog-monitor.log"),
            new JsonObject { ["server"] = "DC1", ["ts"] = timestamp == "now" ? Stamp(Now) : timestamp, ["stdout_tail"] = text }.ToJsonString());
        internal Task<JsonObject> Health() => Service.CollectorAsync(TestContext.Current.CancellationToken);
        public void Dispose() => Directory.Delete(root, true);
    }
    static JsonObject State(string channel) => new() { ["server_hostname"] = "DC1", ["channel"] = channel, ["last_successful_collection_utc"] = Stamp(Now) };
    static JsonObject Stats(string channel, int total, int partial) => new() { ["server"] = "DC1", ["channel"] = channel, ["timeouts_24h"] = total, ["partial_timeouts_24h"] = partial, ["last_status"] = "completed" };
    static JsonObject Budget(JsonObject slo) => slo["error_budget"]!.AsObject();

    [Theory]
    [InlineData("timeout", 20000)] [InlineData("timeout", 500)] [InlineData("timeout", 100)] [InlineData("timeout", 50)]
    [InlineData("partial_timeout", 20000)] [InlineData("partial_timeout", 500)] [InlineData("partial_timeout", 100)] [InlineData("partial_timeout", 50)]
    public void PersistedTimeoutBackoffSurvivesNextPlan(string status, int ceiling)
    {
        long limit = ceiling;
        for (int attempt = 0; attempt < 3; attempt++)
        {
            var transition = CollectorAdaptive.Transition(null, status, limit, 180, Now);
            using var command = CollectorAdaptive.StateCommand("DC1", transition);
            Assert.Contains("on conflict(server,channel) do update", command.CommandText);
            Assert.Equal(NpgsqlDbType.TimestampTz, command.Parameters["updated_at"].NpgsqlDbType);
            // The Python vector uses a fake cursor too: reload the actual upsert
            // parameter values, rather than passing the transition directly to Plan.
            var saved = new JsonObject();
            foreach (var parameter in command.Parameters.Cast<Npgsql.NpgsqlParameter>())
                saved[parameter.ParameterName] = JsonSerializer.SerializeToNode(parameter.Value);
            var state = JsonNode.Parse(saved.ToJsonString())!.AsObject();
            var plan = CollectorAdaptive.Plan(state, 180);
            long expected = Math.Max(100, limit / 2);
            Assert.Equal(expected, N(state["current_limit"]));
            Assert.Equal(expected, N(plan["security_limit"]));
            Assert.Equal(expected, N(plan["channel_limits"]?["Security"]));
            Assert.True(B(plan["recovery_mode"]));
            limit = Math.Min(ceiling, N(plan["security_limit"]));
            Assert.True(limit <= ceiling);
        }
    }

    [Theory]
    [InlineData(null, 180, 20000, true)]
    [InlineData("{\"current_limit\":500,\"recovery_mode\":false}", 180, 20000, true)]
    [InlineData("{\"current_limit\":500,\"recovery_mode\":true}", 180, 500, true)]
    [InlineData("{\"current_limit\":500,\"recovery_mode\":true}", null, 500, true)]
    [InlineData("{\"current_limit\":500,\"recovery_mode\":true}", 2, 500, false)]
    [InlineData("{\"current_limit\":30000,\"recovery_mode\":true}", 180, 30000, true)]
    public void RecoveryEntryAndEstablishedLimits(string? json, int? lag, long expected, bool recovery)
    {
        var plan = CollectorAdaptive.Plan(json is null ? null : JsonNode.Parse(json)!.AsObject(), lag);
        Assert.Equal(expected, N(plan["security_limit"])); Assert.Equal(recovery, B(plan["recovery_mode"]));
    }

    public static IEnumerable<object[]> InclusiveTimeoutVectors()
    {
        foreach (string source in new[] { "database", "log_fallback" })
        foreach (int stale in new[] { 0, 3 })
        foreach (var (partial, full, system) in new[] { (1, 0, 0), (1, 1, 7), (0, 0, 7), (0, 0, 0) })
            yield return [source, partial, full, system, stale];
    }
    [Theory] [MemberData(nameof(InclusiveTimeoutVectors))]
    public async Task SecurityBudgetCountsInclusiveTimeoutsOnce(string source, int partial, int full, int system, int stale)
    {
        using var fixture = new Fixture();
        fixture.Queries.States.Add(State("System")); fixture.Queries.Stale = stale;
        if (source == "database") fixture.Queries.History = new(Stats("Security", partial + full, partial), Stats("System", system, system));
        else
        {
            var lines = new List<string>();
            foreach (var (channel, total, partialCount) in new[] { ("Security", partial + full, partial), ("System", system, system) })
            {
                for (int i = 0; i < total; i++) lines.Add($"Timed out channel: {channel} after 300s{(i < partialCount ? " partial_count=10" : "")}");
                lines.Add($"Completed channel: {channel} count=0");
            }
            fixture.Log(string.Join('\n', lines));
        }
        var health = await fixture.Health(); var summary = health["summary"]!; var slo = health["operations_slo"]!.AsObject(); var budget = Budget(slo);
        Assert.Equal(partial + full + system, N(summary["timeouts_24h"])); Assert.Equal(partial + system, N(summary["partial_timeouts_24h"]));
        Assert.Equal(N(summary["timeouts_24h"]), N(slo["timeouts_24h"])); Assert.Equal(stale, N(slo["stale_post_collection"]));
        Assert.Equal("scheduled_security_checks_model", S(budget["method"])); Assert.Equal(144, N(budget["expected_security_checks"])); Assert.Equal(1, N(budget["allowed_errors"]));
        Assert.Equal(partial + full, N(budget["consumed_errors"])); Assert.Equal(Math.Max(0, 1 - partial - full), N(budget["remaining_errors"]));
        Assert.Equal(100d * (partial + full), budget["consumed_percent"]!.GetValue<double>());
        Assert.Equal(partial + full > 1 ? "exhausted" : partial + full > 0 ? "attention" : "available", S(budget["status"]));
        Assert.Equal(partial + full + system + stale > 0 ? "attention" : "met", S(slo["status"]));
        Assert.Equal(2, N(slo["analysis_queued"]));
    }

    [Theory]
    [InlineData("sql_zero", true)] [InlineData("sql_missing", false)] [InlineData("sql_invalid", false)]
    [InlineData("log_completed", true)] [InlineData("log_import_only", false)] [InlineData("log_missing", false)] [InlineData("log_undated", false)]
    public async Task HealthPreservesCounterAvailability(string source, bool known)
    {
        using var fixture = new Fixture();
        if (source.StartsWith("sql_"))
        {
            var row = Stats("Security", 0, 0);
            row["timeouts_24h"] = source == "sql_missing" ? null : source == "sql_invalid" ? JsonValue.Create("bad") : JsonValue.Create(0);
            fixture.Queries.History.Add(row);
        }
        else if (source != "log_missing") fixture.Log(source == "log_import_only" ? "Security.jsonl: inserted=3, skipped=0" : "Completed channel: Security count=0", source == "log_undated" ? null : "now");
        var health = await fixture.Health(); var item = Assert.Single(health["items"]!.AsArray())!;
        Assert.Equal(0, N(item["timeouts_24h"])); Assert.Equal(known, B(item["timeouts_24h_available"]));
        var budget = Budget(health["operations_slo"]!.AsObject());
        Assert.Equal(known ? "available" : "unknown", S(budget["status"]));
        Assert.Equal(known ? 0L : (long?)null, budget["consumed_errors"]?.GetValue<long>());
    }

    public static IEnumerable<object?[]> InvalidCounters()
    {
        foreach (var value in new JsonNode?[] { null, JsonValue.Create(-1), JsonValue.Create("bad"), JsonValue.Create(true), JsonValue.Create(1.5), JsonValue.Create(double.NaN), JsonValue.Create(double.PositiveInfinity), JsonValue.Create("01"), JsonValue.Create("-1"), JsonValue.Create("1.5") }) yield return [value];
    }
    [Theory] [MemberData(nameof(InvalidCounters))]
    public void InvalidSecurityCounterHasUnknownBudget(JsonNode? value)
    {
        using var fixture = new Fixture();
        var item = new JsonObject { ["channel"] = "Security", ["last_successful_collection_utc"] = Stamp(Now), ["timeouts_24h"] = value?.DeepClone() };
        var budget = Budget(fixture.Service.CollectorSlo(new(item), new(), new())); AssertUnknown(budget);
        Assert.True(N(budget["expected_security_checks"]) > 0); Assert.True(N(budget["allowed_errors"]) >= 1);
        var projected = OperationsCollector.Channel(State("Security"), item, null, Now);
        Assert.Equal(0, N(projected["timeouts_24h"])); Assert.False(B(projected["timeouts_24h_available"]));
    }
    static void AssertUnknown(JsonObject budget)
    {
        Assert.Equal("unknown", S(budget["status"]));
        foreach (string field in new[] { "consumed_errors", "remaining_errors", "consumed_percent" }) Assert.Null(budget[field]);
    }
    [Theory] [InlineData("0")] [InlineData("1")] [InlineData("\"0\"")] [InlineData("\"1\"")]
    public void ValidSecurityCounterRemainsKnown(string json)
    {
        using var fixture = new Fixture(); var value = JsonNode.Parse(json);
        var budget = Budget(fixture.Service.CollectorSlo(new(new JsonObject { ["channel"] = "Security", ["timeouts_24h"] = value }), new(), new()));
        Assert.Equal(N(value), N(budget["consumed_errors"])); Assert.NotEqual("unknown", S(budget["status"]));
    }
    [Fact]
    public void MissingCounterAndPartialSecurityTelemetryCannotIncreaseBudget()
    {
        using var fixture = new Fixture();
        foreach (var items in new[] { new JsonArray(new JsonObject { ["channel"] = "Security" }),
            new JsonArray(new JsonObject { ["channel"] = "Security", ["timeouts_24h"] = 2 }, new JsonObject { ["channel"] = "Security", ["timeouts_24h"] = 0, ["timeouts_24h_available"] = false }) })
        {
            var budget = Budget(fixture.Service.CollectorSlo(items, new(), new())); AssertUnknown(budget);
            Assert.True(N(budget["expected_security_checks"]) > 0); Assert.True(N(budget["allowed_errors"]) >= 1);
        }
    }
    [Fact]
    public void WithoutSecurityObservationsOtherChannelErrorsDoNotConsumeBudget()
    {
        using var fixture = new Fixture(); var items = new JsonArray(Stats("System", 8, 3));
        var slo = fixture.Service.CollectorSlo(items, OperationsCollector.Summary(items), new()); var budget = Budget(slo);
        Assert.Equal("unknown", S(slo["status"])); AssertUnknown(budget);
        Assert.Equal(0, N(budget["expected_security_checks"])); Assert.Equal(0, N(budget["allowed_errors"]));
    }
    [Theory] [InlineData(true)] [InlineData(false)]
    public async Task DatabaseAndLogCountersAreSelectedAtomically(bool databaseKnown)
    {
        using var fixture = new Fixture();
        var primary = Stats("Security", 0, 0); primary["timeouts_24h_available"] = databaseKnown;
        var fallback = Stats("Security", 3, 2); fallback["timeouts_24h_available"] = true;
        var before = primary.ToJsonString();
        var merged = OperationsCollector.MergeStats(primary, fallback);
        Assert.True(JsonNode.DeepEquals(databaseKnown ? primary : fallback, merged)); Assert.Equal(before, primary.ToJsonString());
        fixture.Queries.History.Add(primary);
        fixture.Log("Timed out channel: Security after 300s partial_count=10\nTimed out channel: Security after 300s partial_count=10\nTimed out channel: Security after 300s\nCompleted channel: Security count=0");
        var health = await fixture.Health(); var item = Assert.Single(health["items"]!.AsArray())!;
        Assert.Equal(databaseKnown ? 0 : 3, N(item["timeouts_24h"])); Assert.Equal(databaseKnown ? 0 : 2, N(item["partial_timeouts_24h"]));
        Assert.Equal(databaseKnown ? 0 : 3, N(health["operations_slo"]?["error_budget"]?["consumed_errors"]));
    }
}
