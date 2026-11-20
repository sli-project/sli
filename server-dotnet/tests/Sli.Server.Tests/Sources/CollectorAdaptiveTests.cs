using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Hosting;
using Sli.Server.Infrastructure;
using Sli.Server.Sources;
using Xunit;

namespace Sli.Server.Tests.Sources;

// Vectors from tests/sources/test_collector_adaptive.py; no real source or database.
public sealed class CollectorAdaptiveTests
{
    private static readonly CollectorAdaptiveOptions Options = new();
    private static readonly DateTimeOffset Now = new(2026, 11, 9, 12, 0, 0, TimeSpan.Zero);
    private sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    private static CollectorAdaptive Adaptive => new(Options, new Clock());

    [Fact]
    public void NonPostgresConfigurationIsRejectedBeforeAnyCollection()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> {
            ["ConnectionStrings:Sli"] = "Data Source=unsupported.db"
        }).Build();
        Assert.Throws<ServerConfigurationException>(() => new PostgresConnectionFactory(config));
    }

    [Fact]
    public void DuplicateEventsDoNotDecreaseSecuritySize()
    {
        var next = Adaptive.SecurityTransition(State(50_000), "completed", 0, 50_000, 2, 50_000);
        Assert.Equal(50_000, next["current_limit"]!.GetValue<int>());
        Assert.Equal("keep", next["action"]!.GetValue<string>());
        Assert.Contains(next["reason"]!.GetValue<string>(), new[] { "completed_streak", "completed_fast_recovery" });
        Assert.Equal(0, next["inserted"]!.GetValue<int>());
        Assert.Equal(50_000, next["skipped"]!.GetValue<int>());
    }

    [Fact]
    public void FunctionalFailureDoesNotDecreaseSecuritySize()
    {
        var next = Adaptive.SecurityTransition(State(50_000), "failed", 0, 0, 2, 50_000);
        Assert.Equal(50_000, next["current_limit"]!.GetValue<int>());
        Assert.Equal("keep", next["action"]!.GetValue<string>());
        Assert.Equal("functional_failure", next["reason"]!.GetValue<string>());
    }

    [Theory]
    [InlineData("timeout")]
    [InlineData("partial_timeout")]
    public void SourceReportedTimeoutDecreasesSecuritySize(string status)
    {
        var next = Adaptive.SecurityTransition(State(50_000), status, 0, 0, 2, 50_000);
        Assert.Equal(25_000, next["current_limit"]!.GetValue<int>());
        Assert.Equal("decrease_limit", next["action"]!.GetValue<string>());
        Assert.Equal(status, next["reason"]!.GetValue<string>());
        Assert.True(next["recovery_mode"]!.GetValue<bool>());
    }

    [Fact]
    public async Task FunctionalPartialFailurePersistsUnreducedStateAndFailureEvidence()
    {
        var db = new Database();
        await Store().RecordRunsAsync(db.Query, "dc1.example.test", Summary(new JsonObject {
            ["channel"] = "Security", ["status"] = "partial_timeout", ["partial_kind"] = "failure", ["failure_stage"] = "query",
            ["cursor_commit_allowed"] = false, ["count"] = 100, ["max_events"] = 500,
            ["timeout_seconds"] = 900, ["started_at"] = Now.ToString("O")
        }), Stats("Security", 100), 11, TestContext.Current.CancellationToken);
        var upsert = Assert.Single(db.Writes(CollectorAdaptiveStore.UpsertSql));
        Assert.Equal(500, upsert[2]);
        Assert.Contains("keep:functional_partial_failure", Assert.IsType<string>(upsert[7]));
        var run = Assert.Single(db.Writes(CollectorAdaptiveStore.InsertRunSql));
        Assert.Equal(11L, run[0]); Assert.Equal("Security", run[2]);
        Assert.Equal(100, run[6]); Assert.Equal(100, run[9]);
        Assert.Equal("failure", run[^3]); Assert.Equal("query", run[^2]); Assert.Equal(false, run[^1]);
        Assert.Equal(upsert[7], run[14]);
    }

    [Fact]
    public async Task HighSecurityLagPlansSecurityOnly()
    {
        var db = new Database();
        var plan = await Store().GetPlanAsync(db.Query, "dc1.example.test", TestContext.Current.CancellationToken);
        Assert.True(plan.RecoveryMode); Assert.Equal(new[] { "Security" }, plan.Channels);
        Assert.True(plan.ChannelLimits["Security"] >= 100);
        Assert.True(plan.ChannelTimeouts["Security"] >= 600);
        Assert.Equal("security_lag>60m;backend=postgres_runtime", plan.Reason);
    }

    [Fact]
    public async Task TruncatedSystemRunPersistsRecoveryAndBecomesNextPlanTarget()
    {
        var db = new Database();
        await Store().RecordRunsAsync(db.Query, "dc1.example.test", Summary(new JsonObject {
            ["channel"] = "System", ["status"] = "completed", ["count"] = 100, ["max_events"] = 100,
            ["continuity"] = new JsonObject { ["contract"] = "sli.source-capture-continuity.v1", ["status"] = "not_proven", ["truncated"] = true }
        }), Stats("System", 100), 12, TestContext.Current.CancellationToken);
        Assert.Single(db.Writes(CollectorAdaptiveStore.UpsertSql));
        var plan = await Store().GetPlanAsync(db.Query, "dc1.example.test", TestContext.Current.CancellationToken);
        Assert.Contains("System", plan.RecoveryChannels); Assert.Contains("System", plan.Channels);
        Assert.InRange(plan.ChannelLimits["System"], 101, 50_000);
        Assert.Equal(1_100, plan.ChannelLimits["System"]);
    }

    [Fact]
    public void CompletedNonSecurityBoundaryExitsRecovery()
    {
        var next = Adaptive.NonSecurityTransition(State(5_000, true), "completed", 5_000, false);
        Assert.False(next["recovery_mode"]!.GetValue<bool>());
        Assert.Equal(500, next["current_limit"]!.GetValue<int>());
        Assert.Equal("exit_recovery:source_boundary_reached; 5000->500; recovery=off", next["last_action"]!.GetValue<string>());
    }

    [Fact]
    public async Task BoundaryExitIsSavedAndRemovesNonSecurityRecoveryTarget()
    {
        var db = new Database(); db.States["System"] = State(5_000, true);
        await Store().RecordRunsAsync(db.Query, "dc1.example.test", Summary(new JsonObject {
            ["channel"] = "System", ["status"] = "completed", ["max_events"] = 5_000
        }), Stats("System", 0), 13, TestContext.Current.CancellationToken);
        var plan = await Store().GetPlanAsync(db.Query, "dc1.example.test", TestContext.Current.CancellationToken);
        Assert.DoesNotContain("System", plan.RecoveryChannels);
        Assert.Equal(new[] { "Security" }, plan.Channels);
    }

    [Theory]
    [InlineData(50_000, 50_000)]
    [InlineData(49_000, 50_000)]
    public void TruncatedNonSecurityRecoveryStaysWithinSourceContract(int previous, int expected)
    {
        Assert.Equal(expected, Adaptive.NonSecurityTransition(State(previous, true), "completed", previous, true)["current_limit"]!.GetValue<int>());
    }

    [Fact]
    public void RecoveryPlanPreservesTimeoutReductionAndHysteresis()
    {
        var next = Adaptive.SecurityTransition(State(20_000, true), "timeout", 0, 0, 180, 20_000);
        Assert.Equal(10_000, Adaptive.BuildPlan("dc1.example.test", 180, next).SecurityLimit);
        Assert.True(Adaptive.BuildPlan("dc1.example.test", 60, next).RecoveryMode);
        Assert.False(Adaptive.BuildPlan("dc1.example.test", 15, State(500)).RecoveryMode);
        Assert.False(Adaptive.BuildPlan("dc1.example.test", 14, next).RecoveryMode);
    }

    [Fact]
    public async Task ObserveModeKeepsStateAndRecordsHistory()
    {
        var db = new Database();
        await Store().RecordRunsAsync(db.Query, "dc1.example.test", Summary(new JsonObject {
            ["channel"] = "Security", ["status"] = "timeout", ["max_events"] = 50_000
        }), Stats("Security", 0), 14, TestContext.Current.CancellationToken, " observe ");
        Assert.Empty(db.Writes(CollectorAdaptiveStore.UpsertSql));
        Assert.Equal("observe_only:state_unchanged", Assert.Single(db.Writes(CollectorAdaptiveStore.InsertRunSql))[14]);
        await Assert.ThrowsAsync<ArgumentException>(() => Store().RecordRunsAsync(db.Query, "dc1.example.test", new(), new(), null, TestContext.Current.CancellationToken, "invalid"));
    }

    [Fact]
    public void EnvironmentOptionsMatchFrozenDefaultsWithoutAmbientSettings()
    {
        Assert.Equal(Options, CollectorAdaptiveOptions.FromEnvironment(_ => null));
        var slow = CollectorAdaptiveOptions.FromEnvironment(k => k == "ADLOG_SECURITY_RECOVERY_FAST" ? "false" : null);
        Assert.Equal(500, slow.SecurityStart); Assert.Equal(5_000, slow.SecurityMax); Assert.Equal(1, slow.SecurityFactor);
    }

    private static JsonObject State(int size, bool recovery = false) => new() { ["current_limit"] = size, ["consecutive_completed"] = 0, ["recovery_mode"] = recovery };
    private static JsonObject Summary(JsonObject item) => new() { ["finished_at"] = Now.ToString("O"), ["channels"] = new JsonArray(item) };
    private static JsonObject Stats(string channel, int count) => new() { [channel] = new JsonObject { ["inserted"] = count, ["skipped"] = 0 } };
    private static CollectorAdaptiveStore Store() => new(new NoConnection(), Options, new Clock());
    private sealed class NoConnection : IPostgresConnectionFactory {
        public Task<Npgsql.NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("Unexpected live database access");
    }
    private sealed class Database
    {
        internal readonly Dictionary<string, JsonObject> States = new();
        private readonly List<(string Sql, object?[] Args)> calls = [];
        internal IEnumerable<object?[]> Writes(string sql) => calls.Where(c => c.Sql == sql).Select(c => c.Args);
        internal Task<JsonArray> Query(string sql, CancellationToken ct, params object?[] args)
        {
            ct.ThrowIfCancellationRequested(); calls.Add((sql, args));
            JsonArray rows = [];
            if (sql == CollectorAdaptiveStore.LatestSql) rows.Add(new JsonObject { ["time_created_utc"] = Now.AddMinutes(-180).ToString("O"), ["event_record_id"] = 100 });
            else if (sql.StartsWith("select * from collector_adaptive_state")) {
                foreach (var (channel, state) in States.Where(s => args.Length == 1 || s.Key == (string)args[1]!)) {
                    var copy = (JsonObject)state.DeepClone(); copy["channel"] = channel; rows.Add(copy);
                }
            }
            else if (sql == CollectorAdaptiveStore.UpsertSql) {
                States[(string)args[1]!] = new JsonObject { ["current_limit"] = (int)args[2]!, ["consecutive_completed"] = (int)args[3]!, ["recovery_mode"] = (bool)args[4]! };
            }
            return Task.FromResult(rows);
        }
    }
}
