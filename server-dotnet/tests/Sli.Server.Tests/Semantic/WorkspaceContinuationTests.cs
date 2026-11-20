using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Sli.Server.Semantic;
using Xunit;

namespace Sli.Server.Tests.Semantic;

// Vectors from tests/reporting/test_workspace_continuation.py. Only storage is replaced.
public sealed class WorkspaceContinuationTests
{
    static string Id(int n) => $"00000000-0000-0000-0000-{n:000000000000}";
    const string Stamp = "2026-10-01T00:00:00Z";
    static JsonObject Scenario(int n, int evidenceCount = 0) => new()
    {
        ["scenario_id"] = Id(n), ["scenario_kind"] = "synthetic", ["result_class"] = "security_incident",
        ["scenario_status"] = "open", ["partition_key"] = "synthetic", ["title"] = "Synthetic",
        ["explanation"] = "Synthetic", ["risk_class"] = "low", ["updated_at"] = Stamp,
        ["first_seen_utc"] = Stamp, ["last_seen_utc"] = Stamp,
        ["evidence"] = new JsonArray(Enumerable.Range(1, evidenceCount).Select(i => (JsonNode?)new JsonObject
        { ["normalized_event_id"] = Id(i), ["event_db_id"] = i, ["evidence_order"] = 1 }).ToArray())
    };

    sealed class Database(int scenarioCount, int evidenceCount) : ISemanticDatabase, ISemanticSession
    {
        readonly SemanticEndpointTests.Database fallback = new();
        public readonly List<(string Sql, object?[] Values)> Calls = [];
        public int Opened;
        public Task<ISemanticSession> OpenAsync(bool write, CancellationToken ct)
        { Assert.False(write); Opened++; return Task.FromResult<ISemanticSession>(this); }
        public Task CommitAsync(CancellationToken ct) => throw new InvalidOperationException("read_only");
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public Task<JsonArray> QueryAsync(string sql, CancellationToken ct, params object?[] values)
        {
            if (sql.StartsWith("with candidates as(select distinct item")) return Task.FromResult(new JsonArray(new JsonObject
            { ["item_id"] = Id(1), ["evidence_event_ids"] = new JsonArray(1L, 2L, 3L, 4L, 5L, 6L) }));
            if (!sql.Contains("from semantic_security_scenarios scenario")) return fallback.QueryAsync(sql, ct, values);
            Calls.Add((sql, values));
            Assert.DoesNotContain("offset", sql, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("order by item.evidence_order,item.normalized_event_id limit 6", sql);
            Assert.Contains("order by scenario.updated_at desc,scenario.scenario_id desc", sql);
            int index = 0;
            int? exact = sql.Contains("scenario.scenario_id=$") ? int.Parse(((Guid)values[index++]!).ToString()[^12..]) : null;
            int before = scenarioCount + 1;
            if (sql.Contains("(scenario.updated_at,scenario.scenario_id)<("))
            {
                Assert.Equal(DateTimeOffset.Parse(Stamp), values[index++]);
                before = int.Parse(((Guid)values[index++]!).ToString()[^12..]);
            }
            int after = 0;
            if (sql.Contains("(item.evidence_order,item.normalized_event_id)>("))
            {
                // Evidence position precedes the final list limit, including in metadata mode.
                Assert.Equal(1, values[^3]);
                after = int.Parse(((Guid)values[^2]!).ToString()[^12..]);
            }
            var rows = new JsonArray();
            foreach (int n in Enumerable.Range(1, scenarioCount).Reverse().Where(n => n < before && (exact is null || n == exact)).Take((int)values[^1]!))
            {
                var row = Scenario(n, evidenceCount);
                row["evidence"] = new JsonArray(row["evidence"]!.AsArray().Skip(after).Take(6).Select(e => e!.DeepClone()).ToArray());
                rows.Add(row);
            }
            return Task.FromResult(rows);
        }
    }

    static async Task<JsonObject> Read(HttpClient client, string query = "")
    {
        using var response = await client.GetAsync("/api/v1/semantic/scenarios" + query, TestContext.Current.CancellationToken);
        string text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        return JsonNode.Parse(text)!.AsObject();
    }
    static async Task Invalid(HttpClient client, string query)
    {
        using var response = await client.GetAsync("/api/v1/semantic/scenarios" + query, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_cursor", JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)).Text("error"));
    }

    [Fact]
    public async Task Scenario_and_evidence_cursors_preserve_fields_and_reject_changed_context()
    {
        var db = new Database(2, 6); using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        var first = await Read(client, "?limit=1");
        Assert.True(first.Flag("has_more")); var item = Assert.Single(first["items"]!.AsArray())!;
        Assert.Equal(Id(2), item.Text("scenario_id")); Assert.Equal(5, item["evidence"]!.AsArray().Count); Assert.True(item.Flag("evidence_has_more"));
        string listCursor = first.Text("next_cursor")!, evidenceCursor = item.Text("evidence_next_cursor")!;
        Assert.False(string.IsNullOrEmpty(listCursor)); Assert.False(string.IsNullOrEmpty(evidenceCursor));
        var second = await Read(client, "?limit=1&cursor=" + listCursor);
        Assert.Equal(Id(1), Assert.Single(second["items"]!.AsArray()).Text("scenario_id"));
        Assert.Equal(2, db.Calls[^1].Values[^1]); Assert.False(second.Flag("has_more")); Assert.Null(second["next_cursor"]);
        var evidence = Assert.Single((await Read(client, "?scenario_id=" + Id(2) + "&evidence_cursor=" + evidenceCursor))["items"]!.AsArray())!;
        Assert.Equal(6, Assert.Single(evidence["evidence"]!.AsArray()).Number("event_db_id"));
        Assert.False(evidence.Flag("evidence_has_more")); Assert.Null(evidence["evidence_next_cursor"]);
        int opened = db.Opened;
        await Invalid(client, "?status=resolved&cursor=" + listCursor);
        await Invalid(client, "?scenario_id=" + Id(1) + "&evidence_cursor=" + evidenceCursor);
        Assert.Equal(opened, db.Opened);
    }

    [Fact]
    public async Task All_seventy_evidences_are_read_once_with_tied_order_values()
    {
        var db = new Database(1, 70); using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        var page = Assert.Single((await Read(client))["items"]!.AsArray())!;
        var ids = page["evidence"]!.AsArray().Select(e => e.Number("event_db_id")).ToList();
        for (int n = 0; n < 13; n++)
        {
            Assert.True(page.Flag("evidence_has_more")); Assert.NotNull(page["evidence_next_cursor"]);
            page = Assert.Single((await Read(client, "?scenario_id=" + Id(1) + "&evidence_cursor=" + page.Text("evidence_next_cursor")))["items"]!.AsArray())!;
            ids.AddRange(page["evidence"]!.AsArray().Select(e => e.Number("event_db_id")));
        }
        Assert.Equal(Enumerable.Range(1, 70).Select(n => (long)n), ids);
        Assert.False(page.Flag("evidence_has_more")); Assert.Null(page["evidence_next_cursor"]); Assert.Equal(14, db.Calls.Count);
    }

    [Fact]
    public async Task Scenario_list_reads_beyond_thirty_with_tied_timestamps()
    {
        var db = new Database(35, 0); using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        var first = await Read(client); Assert.Equal(30, first["items"]!.AsArray().Count); Assert.True(first.Flag("has_more")); Assert.NotNull(first["next_cursor"]);
        var second = await Read(client, "?cursor=" + first.Text("next_cursor"));
        Assert.Equal(Enumerable.Range(1, 35).Reverse().Select(Id), first["items"]!.AsArray().Concat(second["items"]!.AsArray()).Select(n => n.Text("scenario_id")));
        Assert.All(db.Calls, call => Assert.Equal(31, call.Values[^1])); Assert.False(second.Flag("has_more")); Assert.Null(second["next_cursor"]);
    }

    [Fact]
    public async Task Metadata_only_evidence_continuation_keeps_exact_authorization_guard()
    {
        var db = new Database(1, 6); using var host = await SemanticEndpointTests.Host(db); using var client = host.GetTestClient();
        // The endpoint performs preflight and resource authorization on every page.
        var first = Assert.Single((await Read(client, "?event_db_id=1"))["items"]!.AsArray())!;
        Assert.Equal("", first.Text("partition_key")); Assert.Equal("metadata_only", first.Text("payload_state")); Assert.NotNull(first["evidence_next_cursor"]);
        var second = Assert.Single((await Read(client, "?event_db_id=1&scenario_id=" + Id(1) + "&evidence_cursor=" + first.Text("evidence_next_cursor")))["items"]!.AsArray())!;
        Assert.Equal("", second.Text("partition_key")); Assert.Equal("metadata_only", second.Text("payload_state"));
        foreach (var call in db.Calls)
        {
            Assert.Contains("guard_event.source_event_id is null or not(guard_event.source_event_id=any(", call.Sql);
            Assert.Equal(new long[] { 1, 2, 3, 4, 5, 6 }, Assert.Single(call.Values.OfType<long[]>()));
            Assert.Contains("''::text as partition_key", call.Sql);
        }
        Assert.Equal(2, db.Calls.Count);
    }
}
