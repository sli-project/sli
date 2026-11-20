using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration;
using Sli.Server.Legacy;
using Sli.Server.Operations;
using Sli.Server.Semantic;
using Sli.Server.Tests.Operations;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Vectors from tests/sources/test_autocollection_fairness.py.
public sealed class AutocollectionFairnessTests
{
    static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-07-09T04:00:00Z");
    sealed class Clock : TimeProvider { public override DateTimeOffset GetUtcNow() => Now; }
    sealed class Database : ISemanticDatabase, ISemanticSession
    {
        public JsonArray States = new(new JsonObject { ["channel"] = "Security", ["last_event_time_utc"] = Now.AddMinutes(-180).ToString("O") });
        public JsonArray Adaptive = [];
        public List<(string Sql, object?[] Values)> Calls = [];
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct) { Assert.False(write); return Task.FromResult<ISemanticSession>(this); }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Calls.Add((sql, values));
            Assert.StartsWith("select", sql.TrimStart());
            return Task.FromResult((sql.Contains("collection_channel_state") ? States : sql.Contains("collector_adaptive_state") ? Adaptive : new JsonArray()).DeepClone().AsArray());
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("planning_must_not_write");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
    static LegacyAdaptiveCollection Planner(Database db) => new(db, new(new ConfigurationBuilder().AddInMemoryCollection(
        new Dictionary<string, string?> {
            ["Sli:Legacy:ADLOG_CHANNEL_FAIRNESS_ENABLED"] = "true",
            ["Sli:Legacy:ADLOG_CHANNEL_FAIRNESS_STALE_MINUTES"] = "60",
            ["Sli:Legacy:ADLOG_CHANNEL_FAIRNESS_MAX_EVENTS"] = "100",
            ["Sli:Legacy:ADLOG_SECURITY_RECOVERY_FAST"] = "true",
            ["Sli:Legacy:ADLOG_SECURITY_RECOVERY_LAG_MINUTES"] = "60",
            ["Sli:Legacy:ADLOG_SECURITY_RECOVERY_EXIT_LAG_MINUTES"] = "15",
            ["Sli:Legacy:ADLOG_SECURITY_MIN_EVENTS"] = "100",
            ["Sli:Legacy:ADLOG_SECURITY_RECOVERY_MAX_LIMIT"] = "50000",
            ["Sli:Legacy:ADLOG_SECURITY_RECOVERY_START_LIMIT"] = "20000",
            ["Sli:Legacy:ADLOG_NON_SECURITY_MAX_EVENTS"] = "500",
            ["Sli:Legacy:ADLOG_DNS_MAX_EVENTS"] = "200"
        }).Build()), new Clock());

    [Fact]
    public async Task FairnessAddsStaleNonSecurityChannelsDuringSecurityRecovery()
    {
        var db=new Database();
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>Planner(db).GetPlanAsync("dc.example.test",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(db.Calls);
    }

    [Fact]
    public async Task FairnessDoesNotInventChannelsWithoutState()
    {
        var db=new Database();
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>Planner(db).GetPlanAsync("dc.example.test",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData(59, false)] [InlineData(60, true)] [InlineData(61, true)]
    public async Task FairnessUsesLastSuccessfulCheckAndTheStaleBoundary(int age, bool expected)
    {
        var db=new Database();
        db.States.Add(new JsonObject { ["channel"]="System",["last_successful_collection_utc"]=Now.AddMinutes(-age).ToString("O") });
        db.Adaptive.Add(new JsonObject { ["channel"]="Security",["recovery_mode"]=expected });
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>Planner(db).GetPlanAsync("dc.example.test",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData(null)] [InlineData("invalid")]
    public async Task ExistingChannelWithUnknownCheckTimeIsFairlyScheduled(string? marker)
    {
        var db=new Database(); db.States.Add(new JsonObject { ["channel"]="System",["updated_at"]=marker });
        var error=await Assert.ThrowsAsync<InvalidOperationException>(()=>Planner(db).GetPlanAsync("dc.example.test",TestContext.Current.CancellationToken));
        Assert.Equal("module_disabled",error.Message); Assert.Empty(db.Calls);
    }

    [Theory]
    [InlineData(14, true, false)] [InlineData(15, true, true)] [InlineData(60, false, false)] [InlineData(61, false, true)]
    public void FairnessOnlyAppliesDuringSecurityRecovery(long lag, bool previous, bool recovery)
    {
        var plan = Planner(new()).BuildPlan("DC1", lag, new(new JsonObject { ["channel"] = "Security", ["recovery_mode"] = previous }), ["System"]);
        Assert.Equal(recovery, plan.RecoveryMode);
        Assert.Equal(recovery, plan.FairnessChannels.Contains("System"));
    }

    [Fact]
    public async Task SkippedOverlapSummaryIsAggregatedThroughTheStatusEndpoint()
    {
        using var app = await OperationsEndpointTests.Start();
        app.Jobs.Record(new JsonObject { ["id"] = 3, ["status"] = "skipped", ["skipped_reason"] = "overlap", ["created_at"] = "2026-07-09T01:02:00+00:00" });
        app.Jobs.Record(new JsonObject { ["id"] = 2, ["status"] = "skipped", ["skipped_reason"] = "overlap", ["created_at"] = "2026-07-09T01:01:00+00:00" });
        app.Jobs.Record(new JsonObject { ["id"] = 4, ["status"] = "skipped", ["skipped_reason"] = "disk_pressure_guard" });
        using var response = await OperationsEndpointTests.Request(app, "GET", "/api/autocollection/status");
        Assert.Equal(200, (int)response.StatusCode);
        var summary = (await OperationsEndpointTests.Body(response))["skipped_overlap_summary"]!;
        Assert.Equal(2, OpsJson.N(summary["count"])); Assert.True((bool)summary["normal"]!);
        Assert.Contains("активный сбор", (string)summary["message"]!);
        Assert.Equal("2026-07-09T01:01:00+00:00", (string?)summary["first_at"]);
        Assert.Equal("2026-07-09T01:02:00+00:00", (string?)summary["last_at"]);
    }

    [Fact]
    public async Task ProgressLineUpdatesTheActiveJobAndItsHttpSnapshot()
    {
        var store = new LegacyJobStore(); var job = store.Create("collect_all_dc_logs:test", new(["DC1"], 1, 100));
        int id = (int)job["id"]!; store.Update(id, j => j["status"] = "running");
        store.UpdateProgressFromLine(id, "DC1", "Starting channel: DNS Server");
        store.UpdateProgressFromLine(id, "DC1", "Progress channel: DNS Server count=25 record_id=100");
        using var app = await OperationsEndpointTests.Start(legacy: store);
        using var response = await OperationsEndpointTests.Request(app, "GET", $"/api/jobs/{id}");
        Assert.Equal(200, (int)response.StatusCode);
        var snapshot = await OperationsEndpointTests.Body(response);
        Assert.Equal("DC1", (string?)snapshot["current_server"]);
        Assert.Equal("DNS Server", (string?)snapshot["current_channel"]);
        Assert.Equal(25, OpsJson.N(snapshot["events_collected"]));
        Assert.Equal("DNS Server", (string?)Assert.Single(snapshot["channels_in_progress"]!.AsArray()));
        Assert.NotNull(snapshot["last_progress_at"]);
        using var status = await OperationsEndpointTests.Request(app, "GET", "/api/autocollection/status");
        var active = (await OperationsEndpointTests.Body(status))["active_job"]!;
        Assert.Equal(25, OpsJson.N(active["events_collected"]));
        snapshot["current_channel"] = "changed snapshot";
        Assert.Equal("DNS Server", (string?)store.Get(id)?["current_channel"]);
    }

    [Theory]
    [InlineData("Completed channel: DNS Server count=30", 30)]
    [InlineData("Timed out channel: DNS Server after 5 seconds partial_count=30", 30)]
    [InlineData("Failed channel: DNS Server error=denied count=30", 30)]
    [InlineData("Progress channel: DNS Server count=3 record_id=100", 25)]
    [InlineData("Collection channel status: {\"events_collected\":30}", 30)]
    [InlineData("Collection channel status: invalid", 25)]
    public void ProgressNeverDecreasesOrDuplicatesChannelCounts(string line, long expected)
    {
        var store = new LegacyJobStore(); int id = (int)store.Create("collect_all_dc_logs:test", new(["DC1"]))["id"]!;
        store.UpdateProgressFromLine(id, "DC1", "Starting channel: DNS Server");
        store.UpdateProgressFromLine(id, "DC1", "Progress channel: DNS Server count=25 record_id=100");
        store.UpdateProgressFromLine(id, "DC1", line);
        Assert.Equal(expected, OpsJson.N(store.Get(id)?["events_collected"]));
        Assert.Single(store.Get(id)!["channels_in_progress"]!.AsArray());
        store.UpdateProgressFromLine(999, "DC1", line);
        Assert.Single(store.List());
    }
}
