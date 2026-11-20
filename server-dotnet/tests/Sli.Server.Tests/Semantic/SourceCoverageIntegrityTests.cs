using System.Text.Json;
using System.Text.Json.Nodes;
using Sli.Server.Access;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Behavioral vectors from tests/sources/test_source_coverage_integrity1.py.
public sealed class SourceCoverageIntegrityTests
{
    [Theory]
    [InlineData(5, "complete", "successful_collection_inside_attention_budget", "observed_complete")]
    [InlineData(35, "partial", "successful_collection_outside_attention_budget", "partial")]
    [InlineData(null, "unavailable", "successful_collection_not_recent", "attention_required")]
    public async Task Channel_integrity_distinguishes_complete_partial_and_unavailable(
        int? age, string status, string reason, string state)
    {
        var db = new Database(age);
        var integrity = await Read(db);
        var channels = integrity["channels"]!;
        var item = Assert.Single(channels["items"]!.AsArray())!;

        Assert.Equal(status, item.Text("status"));
        Assert.Equal(reason, item.Text("reason"));
        Assert.Equal("DC1", item.Text("server"));
        Assert.Equal("Security", item.Text("channel"));
        Assert.Equal("completed", item.Text("last_status"));
        Assert.True(item.Flag("backfill_completed"));
        if (age is null) Assert.Null(item["collection_age_minutes"]);
        else Assert.Equal(age.Value, item.Number("collection_age_minutes"));
        Assert.Equal(1, channels.Number("total"));
        Assert.Equal(1, channels["by_status"].Number(status));
        Assert.Equal(state, integrity.Text("state"));
    }

    [Theory]
    [InlineData(0, "observed_complete", "bounded_metadata_only", "not_observed")]
    [InlineData(2, "attention_required", "uncertain", "unclassified")]
    public async Task Reader_uses_local_metadata_and_does_not_claim_remote_gap_proof(
        int actionable, string state, string gapState, string classification)
    {
        var db = new Database(5, actionable);
        var integrity = await Read(db);

        Assert.False(integrity.Flag("surveyed_servers_contacted"));
        Assert.False(integrity.Flag("payload_read"));
        var gap = integrity["gap_detection"]!;
        Assert.False(gap.Flag("remote_sequence_scan_performed"));
        Assert.Equal(gapState, gap.Text("state"));
        Assert.Equal(actionable > 0
            ? "actionable cursor rollback requires reset/rollover investigation"
            : "local metadata shows no actionable rollback but cannot prove remote record continuity", gap.Text("reason"));
        Assert.Equal(state, integrity.Text("state"));
        var cursor = integrity["cursor_integrity"]!;
        Assert.Equal(3, cursor.Number("stale_empty_proposals"));
        Assert.Equal(actionable, cursor.Number("actionable_rollbacks"));
        Assert.Equal(3 + actionable, cursor.Number("rejected_rollbacks"));
        Assert.Equal(classification, cursor.Text("reset_or_rollover_classification"));

        // Check the executed reader queries, rather than Python module source text.
        Assert.Equal(3, db.IntegrityCalls.Count);
        var states = db.IntegrityCalls[0];
        Assert.Contains("limit 100", states.Sql.ToLowerInvariant());
        Assert.Empty(states.Values);
        Assert.Contains("as stale_empty_proposals", db.IntegrityCalls[2].Sql);
        Assert.Contains("as actionable_rollbacks", db.IntegrityCalls[2].Sql);
        foreach (var call in db.IntegrityCalls.Skip(1)) Assert.Equal(24, Assert.Single(call.Values));
        foreach (string sql in db.Queries)
        {
            Assert.DoesNotContain("events_v2_core", sql.ToLowerInvariant());
            Assert.DoesNotContain(" from events ", sql.ToLowerInvariant());
        }
    }

    private static async Task<JsonNode> Read(Database db)
    {
        var owner = new CapabilityDecisionSet(true, new HashSet<string>(), new HashSet<string>(), [],
            new Dictionary<string, JsonElement>());
        var result = await new SemanticWorkspace(db).ReadAsync("calibration", new SemanticQuery(null), owner,
            TestContext.Current.CancellationToken);
        Assert.Equal(1, db.Opened);
        Assert.True(db.Disposed);
        return result["calibration_readiness"]!["source_coverage_integrity"]!;
    }

    private sealed class Database(int? age, int actionable = 0) : ISemanticDatabase, ISemanticSession
    {
        internal int Opened;
        internal bool Disposed;
        internal readonly List<string> Queries = [];
        internal readonly List<(string Sql, object?[] Values)> IntegrityCalls = [];

        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        {
            Assert.False(write);
            Opened++;
            return Task.FromResult<ISemanticSession>(this);
        }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("Read must not commit");
        public ValueTask DisposeAsync() { Disposed = true; return ValueTask.CompletedTask; }
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            Queries.Add(sql);
            if (sql.Contains("from schema_migrations"))
                return Task.FromResult(new JsonArray(new JsonObject { ["runtime_marker"] = 29, ["semantic_marker"] = 29 }));
            if (sql.Contains("from runtime_worker_heartbeats") || sql == SemanticReadSql.job_rows ||
                sql == SemanticReadSql.result_rows || sql == SemanticReadSql.policy_rows ||
                sql == SemanticReadSql.control_rows || sql == SemanticReadSql.coverage_rows || sql == SemanticReadSql.quality_rows)
                return Task.FromResult(new JsonArray());

            IntegrityCalls.Add((sql, values));
            JsonArray rows = sql switch
            {
                SemanticReadSql.Integrity_state_rows => new(new JsonObject
                {
                    ["server_hostname"] = "DC1", ["channel"] = "Security", ["backfill_completed"] = true,
                    ["last_status"] = "completed",
                    ["last_successful_collection_utc"] = age is { } minutes ? SemanticJson.Stamp(DateTimeOffset.UtcNow.AddMinutes(-minutes)) : null
                }),
                SemanticReadSql.Integrity_run_rows => new(),
                SemanticReadSql.Integrity_audit_rows => new(new JsonObject
                {
                    ["stale_empty_proposals"] = 3, ["actionable_rollbacks"] = actionable, ["rejected_rollbacks"] = 3 + actionable
                }),
                _ => throw new InvalidOperationException("Unexpected calibration query")
            };
            return Task.FromResult(rows);
        }
    }
}
