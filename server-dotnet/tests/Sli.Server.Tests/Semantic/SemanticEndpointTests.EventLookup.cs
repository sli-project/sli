using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Behavioral vectors from tests/semantic/test_semantic_event_lookup.py.
public sealed partial class SemanticEndpointTests
{
    [Theory]
    [InlineData("actions", "UTC", "2026-09-10", "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z")]
    [InlineData("scenarios", "UTC", "2026-09-10", "2026-09-10T00:00:00Z", "2026-09-11T00:00:00Z")]
    [InlineData("actions", "Asia/Bangkok", "2026-09-10", "2026-09-09T17:00:00Z", "2026-09-10T17:00:00Z")]
    [InlineData("actions", "UTC", "2026-09-10T12:00:00Z", "2026-09-10T00:00:00Z", "2026-09-10T12:00:00Z")]
    public async Task Exact_preflight_uses_normalized_proof_and_exclusive_date_bounds(string leaf, string zone, string timeTo, string start, string end)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7&time_from=2026-09-10&time_to={timeTo}&timezone={zone}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var preflight = Assert.Single(db.Calls, x => x.Sql.StartsWith("with candidates as(select distinct item"));
        Assert.Contains("join normalized_events anchor", preflight.Sql);
        Assert.Contains("anchor.source_event_id=$1", preflight.Sql);
        Assert.Contains("anchor.occurred_at_utc >= $2", preflight.Sql);
        Assert.Contains("anchor.occurred_at_utc < $3", preflight.Sql);
        Assert.Equal(7L, preflight.Values[0]);
        Assert.Equal(DateTimeOffset.Parse(start), Assert.IsType<DateTimeOffset>(preflight.Values[1]));
        Assert.Equal(DateTimeOffset.Parse(end), Assert.IsType<DateTimeOffset>(preflight.Values[2]));
        Assert.Equal(new long[] { 7, 8 }, db.Calls.Where(x => x.Sql.Contains("select e.domain_id,e.server_id,c.value as channel",StringComparison.Ordinal)).Select(x => (long)x.Values[0]!));
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("bounded_exact_matches", result["limits"].Text("coverage_state"));
        Assert.Equal(DateTimeOffset.Parse(start), DateTimeOffset.Parse(result["limits"].Text("time_from_utc")!));
        Assert.Equal(DateTimeOffset.Parse(end), DateTimeOffset.Parse(result["limits"].Text("time_to_utc_exclusive")!));
    }

    [Theory] [InlineData("actions")] [InlineData("scenarios")]
    public async Task Scoped_proof_denial_returns_not_found_before_item_read(string leaf)
    {
        var db = new Database { Policies = [JsonSerializer.SerializeToElement(new {
            capability_key = "semantic.review", effect = "deny", scope_json = new { kind = "server", ids = new[] { 9 } }
        })] };
        db.EventServers[7] = 7; db.EventServers[8] = 9;
        using var host = await Host(db, false, "operator", true, "semantic.review", "evidence.exact", "field.security");
        using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["error"] = "not_found" }, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))));
        Assert.Contains(db.Queries, x => x.StartsWith("with candidates as(select distinct item"));
        Assert.DoesNotContain(db.Queries, x => x.Contains("from canonical_actions action") || x.Contains("from semantic_security_scenarios scenario"));
    }

    [Theory] [InlineData("actions")] [InlineData("scenarios")]
    public async Task Denied_anchor_cannot_probe_preflight_or_limits(string leaf)
    {
        var db = new Database { Policies = [JsonSerializer.SerializeToElement(new {
            capability_key = "evidence.exact", effect = "deny", scope_json = new { kind = "server", ids = new[] { 9 } }
        })] };
        db.EventServers[7] = 9;
        using var host = await Host(db, false, "operator", true, "semantic.review", "evidence.exact", "field.security");
        using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["error"] = "not_found" }, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))));
        Assert.DoesNotContain(db.Queries, x => x.StartsWith("with candidates") || x.Contains("from canonical_actions action") || x.Contains("from semantic_security_scenarios scenario"));
    }

    public static TheoryData<string, string, string> UnavailableEvidence => new()
    {
        { "actions", new JsonArray(Enumerable.Range(1, 65).Select(x => (JsonNode?)JsonValue.Create((long)x)).ToArray()).ToJsonString(), "evidence_limit_exceeded" },
        { "actions", "[7,null]", "evidence_unavailable" }, { "actions", "[7,-1]", "evidence_unavailable" },
        { "scenarios", "[7,null]", "evidence_unavailable" }, { "scenarios", "[7,-1]", "evidence_unavailable" }
    };

    [Theory] [MemberData(nameof(UnavailableEvidence))]
    public async Task Unavailable_preflight_never_authorizes_partial_proof_or_publishes_items(string leaf, string evidence, string reason)
    {
        var db = new Database { Seeded = true, PreflightEvidence = JsonNode.Parse(evidence)!.AsArray() };
        using var host = await Host(db); using var client = host.GetTestClient();
        var before = DateTimeOffset.UtcNow;
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal("unavailable", result.Text("state"));
        Assert.Empty(result["items"]!.AsArray()); Assert.False(result.Flag("has_more"));
        Assert.Equal("unavailable", result["limits"].Text("coverage_state"));
        Assert.Equal(reason, result["limits"].Text("reason"));
        Assert.InRange(DateTimeOffset.Parse(result.Text("generated_at_utc")!), before.AddSeconds(-1), DateTimeOffset.UtcNow);
        Assert.NotNull(result["execution"]!["state"]);
        Assert.Single(db.Calls, x => x.Sql.Contains("select e.domain_id,e.server_id,c.value as channel",StringComparison.Ordinal));
        Assert.DoesNotContain(db.Queries, x => x.Contains("from canonical_actions action") || x.Contains("from semantic_security_scenarios scenario"));
    }

    [Theory]
    [InlineData("actions", "event_db_id=1.0", "invalid_event_db_id")]
    [InlineData("scenarios", "event_db_id=1.0", "invalid_event_db_id")]
    [InlineData("actions", "event_db_id=7&time_from=2026-09-10&time_from=2026-09-11", "invalid_semantic_context")]
    [InlineData("scenarios", "event_db_id=7&time_from=2026-09-10&time_from=2026-09-11", "invalid_semantic_context")]
    [InlineData("actions", "event_db_id=7&time_to=2026-09-10&time_to=2026-09-11", "invalid_semantic_context")]
    [InlineData("actions", "event_db_id=7&timezone=UTC&timezone=Asia/Bangkok", "invalid_semantic_context")]
    public async Task Invalid_exact_context_is_rejected_before_authorization_or_global_reads(string leaf, string query, string error)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?{query}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(error, JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.Text("error"));
        Assert.Equal(0, db.FactsLoaded); Assert.Equal(0, db.Opened); Assert.Empty(db.Queries);
    }

    [Theory] [InlineData("actions")] [InlineData("scenarios")]
    public async Task Exact_metadata_sql_excludes_payload_and_rechecks_every_proof(string leaf)
    {
        var db = new Database(); using var host = await Host(db); using var client = host.GetTestClient();
        using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        string from = leaf == "actions" ? "from canonical_actions action" : "from semantic_security_scenarios scenario";
        var read = Assert.Single(db.Calls, x => x.Sql.Contains(from));
        string[] forbidden = leaf == "actions" ? ["action.attributes_json"] :
            ["scenario.title", "scenario.explanation", "scenario.partition_key", "scenario.strict_keys_json", "scenario.confidence_factors_json", "review.rationale", "result.completeness_snapshot_json"];
        foreach (string column in forbidden) Assert.DoesNotContain(column, read.Sql);
        Assert.Contains("not exists", read.Sql);
        Assert.Contains("guard_event.source_event_id is null", read.Sql);
        Assert.Contains("not(guard_event.source_event_id=any(", read.Sql);
        Assert.Equal(new long[] { 7, 8 }, Assert.Single(read.Values.OfType<long[]>()));
        Assert.Equal(new[] { Guid.Parse(Id) }, Assert.Single(read.Values.OfType<Guid[]>()));
        if (leaf == "scenarios") Assert.Contains("result.conclusion_state", read.Sql);
    }

    [Fact]
    public void Metadata_scenario_discards_identity_notes_and_unknown_private_fields()
    {
        var row = new JsonObject();
        foreach (string key in new[] { "title", "explanation", "partition_key", "strict_keys", "confidence_factors", "completeness_snapshot", "latest_review", "future_private_field" })
            row[key] = "sensitive-identity";
        foreach (string key in new[] { "strict_keys_json", "confidence_factors_json", "completeness_snapshot_json" })
            row[key] = new JsonObject { ["secret"] = "sensitive-identity" };
        row["scenario_id"] = Id; row["scenario_kind"] = "kind"; row["scenario_status"] = "open";
        row["latest_review_id"] = Id; row["review_rationale"] = "sensitive-identity";
        var item = SemanticWorkspace.ScenarioItem(row, true);
        Assert.DoesNotContain("sensitive-identity", item.ToJsonString());
        Assert.Null(item["future_private_field"]); Assert.Null(item["latest_review"]);
        Assert.Empty(item["strict_keys"]!.AsObject()); Assert.Empty(item["confidence_factors"]!.AsObject());
        Assert.Equal(Id, item.Text("scenario_id")); Assert.Equal("open", item.Text("status"));
        Assert.Equal("metadata_only", item.Text("payload_state"));
    }

    [Theory] [InlineData("actions", false)] [InlineData("scenarios", false)] [InlineData("scenarios", true)]
    public async Task Investigation_mode_read_responses_preserve_execution_even_when_proof_unavailable(string leaf, bool unavailable)
    {
        var values = new Dictionary<string, string?> {
            ["ADLOG_SEMANTIC_PRODUCTION_ENABLED"] = "1", ["ADLOG_SEMANTIC_RUNTIME_MODE"] = "investigation-v1",
            ["ADLOG_SEMANTIC_NORMALIZATION_ENABLED"] = "1", ["ADLOG_SEMANTIC_ASSEMBLY_ENABLED"] = "1",
            ["ADLOG_SEMANTIC_CORRELATION_ENABLED"] = "1", ["ADLOG_SEMANTIC_DIRECTORY_STATE_ENABLED"] = "0",
            ["ADLOG_SEMANTIC_RISK_ENGINE_ENABLED"] = "0", ["ADLOG_SEMANTIC_FINDING_CREATION_ENABLED"] = "0"
        };
        var previous = values.ToDictionary(p => p.Key, p => Environment.GetEnvironmentVariable(p.Key));
        try
        {
            foreach (var pair in values) Environment.SetEnvironmentVariable(pair.Key, pair.Value);
            var db = new Database { PreflightEvidence = unavailable ? new JsonArray(7L, null) : null };
            if (!unavailable) db.Heartbeat = new JsonObject {
                ["status"] = "idle", ["heartbeat_at"] = SemanticJson.Stamp(DateTimeOffset.UtcNow), ["expected_interval_seconds"] = 30,
                ["details_json"] = new JsonObject { ["runtime_mode"] = "investigation-v1" }
            };
            using var host = await Host(db); using var client = host.GetTestClient();
            using var response = await client.GetAsync($"/api/v1/semantic/{leaf}?event_db_id=7", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var result = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
            Assert.Equal("investigation-v1", result["execution"].Text("runtime_mode"));
            Assert.Equal(unavailable ? "enabled_without_worker" : "active", result["execution"].Text("state"));
            if (!unavailable) Assert.Equal("investigation-v1", result["execution"]!["worker"].Text("runtime_mode"));
            Assert.False(result["execution"].Flag("finding_path_live"));
            Assert.Equal(unavailable ? "unavailable" : "empty", result.Text("state"));
        }
        finally { foreach (var pair in previous) Environment.SetEnvironmentVariable(pair.Key, pair.Value); }
    }
}
