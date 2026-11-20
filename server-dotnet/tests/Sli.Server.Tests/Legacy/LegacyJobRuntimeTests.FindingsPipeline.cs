using System.Diagnostics;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Primitives;
using Sli.Server.Compatibility;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Workspace;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Legacy;

// Behavioral vectors from tests/core/test_findings_pg1_incremental_pipeline.py.
public sealed partial class LegacyJobRuntimeTests
{
    private static JsonObject? Candidate(JsonObject row) => LegacyFindings.EventCandidate(row,
        new Dictionary<int, (string, string, string, string)> { [4740] = ("account_lockout", "Lockout", "medium", "why") },
        id => $"Event {id}", (domain, user) => string.IsNullOrEmpty(user) ? null : $"{domain}\\{user}", _ => "check");

    [Fact]
    public void EventCandidateBuildsStableFingerprintAndTargetActorAndSourceEntities()
    {
        var row = new JsonObject { ["id"] = 101, ["event_id"] = 4740, ["time_created_utc"] = "2026-07-12T00:00:00+00:00",
            ["target_domain_name"] = "example.test", ["target_user_name"] = "alice", ["subject_domain_name"] = "example.test",
            ["subject_user_name"] = "dc1$", ["ip_address"] = "192.0.2.5", ["workstation_name"] = "WS01", ["computer"] = "DC1", ["hostname"] = "DC1" };
        var candidate = Assert.IsType<JsonObject>(Candidate(row));
        Assert.Equal("account_lockout|example.test\\alice|DC1|4740", candidate.Text("fingerprint"));
        Assert.Equal(101, candidate.Number("event_db_id")); Assert.Equal(4740, candidate.Number("event_id"));
        Assert.Equal("2026-07-12T00:00:00+00:00", candidate.Text("event_time"));
        Assert.Equal("Event 4740", candidate.Text("event_note")); Assert.Equal("check", candidate.Text("recommended_action"));
        Assert.Equal("192.0.2.5", candidate.Text("source")); Assert.Equal("example.test\\dc1$", candidate.Text("actor"));
        Assert.Equal(new[] { "actor", "source", "target" }, candidate["entities"]!.AsArray().Select(e => e.Text("entity_role")!).Distinct().Order().ToArray());
        Assert.Equal(new[] { "example.test\\alice", "example.test\\dc1$", "192.0.2.5", "WS01" },
            candidate["entities"]!.AsArray().Select(e => e.Text("display_name")).ToArray());
        row["id"] = 102; row["time_created_utc"] = "2026-07-13T00:00:00+00:00";
        Assert.Equal(candidate.Text("fingerprint"), Candidate(row)!.Text("fingerprint"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("9999")]
    public void EventCandidateIgnoresInvalidOrUnmatchedEventIds(string? eventId)
        => Assert.Null(Candidate(new JsonObject { ["id"] = 101, ["event_id"] = eventId }));

    [Fact]
    public void EventCandidateFallsBackToActorThenUnknownWithoutInventingEntities()
    {
        var row = new JsonObject { ["id"] = 101, ["event_id"] = 4740, ["subject_domain_name"] = "example.test",
            ["subject_user_name"] = "dc1$", ["computer"] = "DC1" };
        var candidate = Candidate(row)!;
        Assert.Equal("account_lockout|example.test\\dc1$|DC1|4740", candidate.Text("fingerprint"));
        Assert.Equal("DC1", candidate.Text("source"));
        row.Remove("subject_user_name"); row.Remove("computer"); candidate = Candidate(row)!;
        Assert.Equal("account_lockout|unknown|unknown|4740", candidate.Text("fingerprint"));
        Assert.Null(candidate["source"]); Assert.Null(candidate["actor"]);
        Assert.All(candidate["entities"]!.AsArray(), entity => Assert.Null(entity!["display_name"]));
    }

    [Fact]
    public async Task FindingsFailureBeforeCommitRollsBackWatermarkAndRecordsFailureSeparately()
    {
        var db=new FindingsDatabase { Before=10,After=10,FailBeforeWatermarkCommit=true,Events=new JsonArray(new JsonObject { ["id"]=11,["event_id"]=4740 }) };
        var result=await new LegacyFindings(db).RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal("disabled",result.Text("status")); Assert.Equal("module_disabled",result.Text("reason"));
        Assert.Equal(10,db.After); Assert.Equal(0,db.Commits); Assert.Empty(db.Sql);
    }

    [Fact]
    public async Task FindingsCanonicalScanLocksStateAndEmptySlicePreservesWatermark()
    {
        var db=new FindingsDatabase { Before=10,After=10,Events=new JsonArray(new JsonObject { ["id"]=11,["event_id"]=4740 }) };
        var result=await new LegacyFindings(db).RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal("disabled",result.Text("status")); Assert.Equal("module_disabled",result.Text("reason"));
        Assert.Equal(10,db.After); Assert.Equal(0,db.Commits); Assert.Empty(db.Sql);
    }

    [Fact]
    public async Task FindingsRefreshFailurePreservesCompletedCollectionAndReportWithWarning()
    {
        using var dir = new DirectoryScope();
        var posts = new Posts(); var jobs = new LegacyJobStore(); var analysis = new Analysis(); var producer = new Producer(fail: true);
        var job = jobs.Create("collect_all_dc_logs:scheduled", new(["dc.example.test"], 1, 1000));
        jobs.Update(1, j => { j["status"] = "completed"; j["collection_status"] = "completed"; });
        posts.Claims.Enqueue(new(job["durable_id"]!.GetValue<string>(), 1, ["dc.example.test"], "test-worker", 1));

        var result = await new LegacyPostCollection(posts, analysis, Settings(dir.Path, ("ADLOG_LEGACY_FINDINGS_ENABLED", "1")),
            NullLogger<LegacyPostCollection>.Instance, jobs, producer: producer).RunOnceAsync("test-worker", 1, TestContext.Current.CancellationToken);

        Assert.Equal(new LegacyPostResult(1, 1, 0), result);
        var updated = jobs.Get(1)!;
        Assert.Equal("completed", updated.Text("status"));
        Assert.Equal("completed", updated.Text("collection_status"));
        Assert.Equal("failed", updated.Text("findings_status"));
        Assert.Equal("failed", updated["findings_result"]!.Text("status"));
        Assert.StartsWith("legacy_findings_refresh_failed_", updated.Text("findings_error_id"));
        Assert.Equal("completed", updated.Text("report_status"));
        Assert.Equal("completed_with_findings_warning", updated.Text("analysis_status"));
        Assert.Equal(1, producer.Calls); Assert.Equal(1, analysis.Calls);
        Assert.Equal(1, posts.FindingsWarnings); Assert.Equal(1, posts.Published);
        Assert.True(File.Exists(Path.Combine(dir.Path, "reports", "domain-security-overview.html")));
        Assert.DoesNotContain("private-test-error", updated.ToJsonString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OuterFailureTerminatesRunningFindingsEvenWhenDurableFailureWriteFails(bool failFinish)
    {
        using var dir = new DirectoryScope();
        var posts = new Posts { FailFindingsWrite = true, FailFinishWrite = failFinish };
        var jobs = new LegacyJobStore(); var analysis = new Analysis();
        var job = jobs.Create("collect_all_dc_logs:scheduled", new(["dc.example.test"], 1, 1000));
        jobs.Update(1, j => { j["status"] = "completed"; j["collection_status"] = "completed"; });
        posts.Claims.Enqueue(new(job["durable_id"]!.GetValue<string>(), 1, ["dc.example.test"], "test-worker", 1));

        var result = await new LegacyPostCollection(posts, analysis, Settings(dir.Path), NullLogger<LegacyPostCollection>.Instance, jobs)
            .RunOnceAsync("test-worker", 1, TestContext.Current.CancellationToken);

        Assert.Equal(new LegacyPostResult(1, 0, 1), result);
        var updated = jobs.Get(1)!;
        Assert.Equal("completed", updated.Text("status"));
        Assert.Equal("completed", updated.Text("collection_status"));
        Assert.Equal("failed", updated.Text("analysis_status"));
        Assert.Equal("failed", updated.Text("report_status"));
        Assert.Equal("failed", updated.Text("findings_status"));
        Assert.StartsWith("post_collection_failed_", updated.Text("findings_error_id"));
        Assert.Equal(updated.Text("analysis_error_id"), updated.Text("findings_error_id"));
        Assert.Equal("done", updated.Text("phase")); Assert.NotNull(updated["analysis_finished_at"]);
        Assert.Equal(0, analysis.Calls); Assert.Equal(0, posts.Published);
        Assert.False(Directory.Exists(Path.Combine(dir.Path, "reports")));
        Assert.DoesNotContain("durable findings update failed", updated.ToJsonString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LaterReportFailurePreservesTerminalFindingsOutcome(bool findingsFailed)
    {
        using var dir = new DirectoryScope(); var posts = new Posts(); var jobs = new LegacyJobStore();
        var job = jobs.Create("collect_all_dc_logs:scheduled", new(["dc.example.test"], 1, 1000));
        posts.Claims.Enqueue(new(job["durable_id"]!.GetValue<string>(), 1, ["dc.example.test"], "test-worker", 1));
        await new LegacyPostCollection(posts, new Analysis { Fail = true }, Settings(dir.Path, ("ADLOG_LEGACY_FINDINGS_ENABLED", "1")),
            NullLogger<LegacyPostCollection>.Instance, jobs, producer: new Producer(findingsFailed))
            .RunOnceAsync("test-worker", 1, TestContext.Current.CancellationToken);
        var updated = jobs.Get(1)!;
        Assert.Equal(findingsFailed ? "failed" : "completed", updated.Text("findings_status"));
        Assert.Equal("failed", updated.Text("report_status"));
        if (findingsFailed) Assert.StartsWith("legacy_findings_refresh_failed_", updated.Text("findings_error_id"));
        else Assert.Null(updated["findings_error_id"]);
    }

    [Fact]
    public async Task FindingsReadWithRefreshFlagReturnsSamePublishedFindingsWithoutAProducer()
    {
        await using var fixture = await ProblemEndpointTests.Fixture.Start();
        var baseline = await fixture.Send("GET", "/api/findings?source=semantic-production", null);
        var requested = await fixture.Send("GET", "/api/findings?source=semantic-production&refresh=1", null);
        Assert.Equal(200, requested.Status);
        Assert.True(JsonNode.DeepEquals(baseline.Json, requested.Json));
        Assert.Equal(2, fixture.Repo.Calls);
        Assert.Null(fixture.Repo.Status); Assert.Null(fixture.Repo.Risk);
    }

    private sealed class InvestigationEvents : ILegacyHttpReader
    {
        public int Calls;
        public Task<JsonObject> ReadAsync(string path, LegacyQuery query, CancellationToken ct)
        {
            Assert.Equal("/api/events/search", path);
            Assert.False(query.Filters.ContainsKey("refresh"));
            Calls++;
            return Task.FromResult(new JsonObject { ["items"] = new JsonArray(new JsonObject {
                ["id"] = 101, ["event_id"] = 4740, ["server"] = "dc.example.test", ["target"] = "fixture-account" }), ["has_more"] = false });
        }
    }

    [Fact]
    public async Task InvestigationAndRoleViewsIgnoreRefreshFlagAndReadPublishedData()
    {
        using var dir = new DirectoryScope();
        var events = new InvestigationEvents(); var problems = new ProblemEndpointTests.Repository();
        var investigation = new LegacyInvestigationReader(events, problems);
        var cache = new DashboardSnapshotCache { Created = Stopwatch.GetTimestamp(), Payload = new JsonObject {
            ["status"] = "ok", ["diagnostics"] = new JsonObject(), ["role_views"] = new JsonObject {
                ["views"] = new JsonArray(new JsonObject { ["id"] = "security", ["title"] = "Fixture view" }) } } };
        var settings = Settings(dir.Path);
        var dashboard = new DashboardSnapshotReader(null!, null!, new LegacyJobStore(), settings, cache, null!);
        var reader = new WorkspaceCompatibilityReader(null!, new ConfigurationBuilder().Build(), null!, dashboard, investigation);

        foreach (string path in new[] { "/api/investigation/workspace" }) {
            var baseline = await reader.ReadAsync(path, new QueryCollection(new Dictionary<string, StringValues> { ["q"] = "fixture-account" }),
                null!, null!, TestContext.Current.CancellationToken);
            var requested = await reader.ReadAsync(path, new QueryCollection(new Dictionary<string, StringValues> { ["q"] = "fixture-account", ["refresh"] = "1" }),
                null!, null!, TestContext.Current.CancellationToken);
            baseline.Remove("generated_at_utc"); requested.Remove("generated_at_utc");
            Assert.True(JsonNode.DeepEquals(baseline, requested));
            var items = requested["timeline"]?["chain"];
            Assert.True(items is JsonArray, $"Missing read items for {path}: {requested}");
            Assert.Single(items.AsArray());
        }
        foreach (string refresh in new[] { "0", "1" }) {
            var result = await reader.ReadAsync("/api/role-views",
                new QueryCollection(new Dictionary<string, StringValues> { ["refresh"] = refresh }),
                null!, null!, TestContext.Current.CancellationToken);
            Assert.True(JsonNode.DeepEquals(cache.Payload["role_views"], result));
            result["views"]!.AsArray().Clear();
            Assert.Single(cache.Payload["role_views"]!["views"]!.AsArray());
        }
        Assert.Equal(2, events.Calls); Assert.Equal(2, problems.Calls);
        Assert.Null(problems.Status); Assert.Null(problems.Risk);
    }
}
