using System.Text.Json.Nodes;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticCompletenessSnapshotCaptureTests
{
    private static readonly DateTimeOffset Now = new(2026, 7, 29, 0, 0, 0, TimeSpan.Zero);
    private static readonly Guid SourceId = Guid.Parse("00000000-0000-0000-0000-000000000001");
    private static readonly Guid EventId = Guid.Parse("00000000-0000-0000-0000-000000000002");

    private static SemanticPolicy Policy(bool controls = false)
    {
        var definition = JsonNode.Parse("""
            {"type":"scenario_policy","source_selector":{"relation_kind":"session"},
             "scenario_kind":"authentication.session","result_class":"security_incident",
             "strict_roles":["session_principal"],"merge_window_seconds":1800,
             "allowed_lateness_seconds":1800,"title":"Session","explanation":"Session evidence",
             "risk":{"class":"high","raw_score":"10","display_points":10,"rationale":"Observed session"}}
            """)!.AsObject();
        if (controls) definition["required_controls"] = new JsonArray("collection.security");
        return SemanticPolicy.Compile(new JsonObject
        {
            ["policy_id"] = "snapshot-test", ["policy_version"] = 1,
            ["source_kind"] = "correlation_candidate", ["definition_json"] = definition
        });
    }

    // The Python vector replaces both catalogue enumeration and descriptor lookup.
    private static JsonArray Catalogue() => new(new JsonObject
    {
        ["base_risk"] = "low", ["purpose_tier"] = "technical", ["noise_class"] = "context",
        ["category"] = "authentication", ["lifecycle"] = new JsonObject(),
        ["correlation"] = new JsonObject { ["close_timeout_seconds"] = 900 },
        ["required_fields"] = new JsonArray("event_id"), ["event_key"] = "4624",
        ["stream"] = "Security", ["provider_name"] = "Microsoft-Windows-Security-Auditing"
    });

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Capture_preserves_exact_measurements_and_requires_completed_backfill(bool backfillCompleted)
    {
        await using var session = new SnapshotSession(backfillCompleted);
        var ct = TestContext.Current.CancellationToken;
        var proposal = await SemanticProduction.Proposal(session, Policy(), SourceId.ToString(), "shadow", ct);
        var snapshot = await SemanticProduction.Completeness(session, proposal, ct, Now.AddSeconds(4000), Catalogue());

        Assert.Equal(Now.AddSeconds(4000), SigmaProjection.At(snapshot, "captured_at_utc"));
        var catalogue = snapshot["catalog_completeness"]!;
        Assert.Equal(1, catalogue["entry_count"]!.GetValue<int>());
        Assert.Equal(1, catalogue["fully_classified"]!.GetValue<int>());
        Assert.Equal(1, catalogue["schema_v2_ready"]!.GetValue<int>());
        var freshness = snapshot["collection_freshness"]!;
        Assert.Equal(60, freshness["max_age_seconds"]!.GetValue<int>());
        Assert.Equal(1800, freshness["budget_seconds"]!.GetValue<int>());
        Assert.True(freshness["complete"]!.GetValue<bool>());
        var channels = snapshot["channel_availability"]!;
        Assert.Equal("dc-1|Security", Assert.Single(channels["required"]!.AsArray())!.GetValue<string>());
        if (backfillCompleted)
            Assert.Equal("dc-1|Security", Assert.Single(channels["available"]!.AsArray())!.GetValue<string>());
        else
            Assert.Empty(channels["available"]!.AsArray());
        Assert.Equal(backfillCompleted, channels["complete"]!.GetValue<bool>());
        var window = snapshot["window_closure"]!;
        Assert.Equal(Now, SigmaProjection.At(window, "window_end_utc"));
        Assert.Equal(900, window["descriptor_close_timeout_seconds"]!.GetValue<int>());
        Assert.Equal(1800, window["allowed_lateness_seconds"]!.GetValue<int>());
        Assert.Equal(Now.AddSeconds(2700), SigmaProjection.At(window, "close_deadline_utc"));
        Assert.True(window["closed"]!.GetValue<bool>());
        Assert.Equal(backfillCompleted, snapshot["supports_negative_conclusion"]!.GetValue<bool>());
    }

    [Fact]
    public async Task Control_health_is_selected_as_of_the_event_time()
    {
        await using var session = new SnapshotSession();
        var proposal = await SemanticProduction.Proposal(session, Policy(controls: true), SourceId.ToString(), "shadow", TestContext.Current.CancellationToken);

        var command = Assert.Single(session.Commands, x => x.Sql.Contains("from semantic_control_health_observations", StringComparison.Ordinal));
        Assert.Contains("partition_key=$1 and control_id=$2 and observed_at_utc<=$3", command.Sql);
        Assert.Contains("order by observed_at_utc desc,observation_id desc limit 1", command.Sql);
        Assert.Equal(new object?[] { "dc-1", "collection.security", Now }, command.Values);
        var coverage = Assert.Single(proposal.Coverage)!;
        Assert.Equal("collection.security", coverage["control_id"]!.GetValue<string>());
        Assert.Equal("complete", coverage["coverage_status"]!.GetValue<string>());
        Assert.Equal("Known at event time", coverage["reason"]!.GetValue<string>());
        Assert.Equal(Now.AddMinutes(-1), SigmaProjection.At(coverage, "observed_at_utc"));
        Assert.True(SigmaProjection.At(coverage, "observed_at_utc") < Now);
    }

    private sealed class SnapshotSession(bool backfillCompleted = true) : ISemanticSession
    {
        internal readonly List<(string Sql, object?[] Values)> Commands = [];

        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Commands.Add((sql, values));
            JsonObject row;
            if (sql.Contains("from semantic_correlation_candidates", StringComparison.Ordinal))
            {
                Assert.Equal(new object?[] { SourceId }, values);
                row = new() { ["relation_kind"] = "session", ["candidate_status"] = "matched", ["partition_key"] = "dc-1", ["confidence"] = "high", ["window_end_utc"] = SemanticJson.Stamp(Now) };
            }
            else if (sql.StartsWith("select n.*", StringComparison.Ordinal))
            {
                Assert.Equal(new object?[] { SourceId }, values);
                row = new()
                {
                    ["normalized_event_id"] = EventId.ToString(), ["roles_json"] = new JsonObject { ["session_principal"] = "dc-1:0x1" },
                    ["quality_json"] = new JsonObject { ["event_data_encoding"] = "named" }
                };
            }
            else if (sql.Contains("from semantic_correlation_candidate_evidence evidence", StringComparison.Ordinal))
            {
                Assert.Equal(new object?[] { "dc-1", SourceId }, values);
                row = new() { ["server_name"] = "dc-1", ["channel_name"] = "Security", ["event_id"] = 4624, ["provider_name"] = "Microsoft-Windows-Security-Auditing" };
            }
            else if (sql.Contains("from collection_channel_state", StringComparison.Ordinal))
            {
                Assert.Equal(new object?[] { "dc-1", "Security" }, values);
                row = new() { ["last_successful_collection_utc"] = SemanticJson.Stamp(Now.AddSeconds(3940)), ["backfill_completed"] = backfillCompleted };
            }
            else if (sql.Contains("from semantic_control_health_observations", StringComparison.Ordinal))
                row = new() { ["control_id"] = "collection.security", ["coverage_status"] = "complete", ["reason"] = "Known at event time", ["observed_at_utc"] = SemanticJson.Stamp(Now.AddMinutes(-1)) };
            else
                throw new InvalidOperationException("Unexpected SQL: " + sql);
            return Task.FromResult(new JsonArray(row));
        }

        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("capture_must_not_commit");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
