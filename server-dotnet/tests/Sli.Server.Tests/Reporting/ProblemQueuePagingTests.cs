using System.Text.Json.Nodes;
using Sli.Server.Auth;
using Sli.Server.Problems;
using Sli.Server.Reporting.V2;
using Sli.Server.Tests.Problems;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Parity vectors from tests/reporting/test_problem_queue_paging.py.
public sealed partial class ProblemQueuePagingTests
{
    static ReportQueryContext Context(JsonObject? parameters = null, bool identity = true)
    {
        var access = ProblemLifecycleTests.Access("security.queue", fields: identity ? ["security", "identity_basic"] : ["security"]);
        return new(new ReportDefinitionRegistry().Get("security.problems")!, access.Decision,
            new("session", 1, "admin", "synthetic-user"), parameters ?? new() { ["population"] = "open" },
            new(null, 50, "UTC", null, "desc", null), ReportScope.All, [7], "view",
            fields => access.Fields(fields.ToArray()), access.Decision.Reports.Single().Grants);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EveryPageReachesDeclaredTotalAndCursorsKeepScope(bool identity)
    {
        int total = 61;
        var calls = new List<FindingQuery>();
        var repository = new RecordingRepository(q => {
            calls.Add(q);
            long end = q.BeforeId ?? total + 1;
            var rows = new JsonArray();
            for (long id = end - 1; id >= Math.Max(1, end - 50); id--) {
                var row = new JsonObject { ["id"] = id, ["status"] = "new" };
                {
                    row["queue_cursor_id"] = id; row["occurrence_count"] = id == 61 ? 149 : 1;
                    row["problem_cohort"] = new JsonArray("finding", id);
                }
                rows.Add(row);
            }
            return new() { ["state"] = "available", ["items"] = rows, ["has_more"] = end - rows.Count > 1,
                ["summary"] = new JsonArray(new JsonObject { ["status"] = "new", ["count"] = total }),
                ["semantic_runtime"] = new JsonObject { ["findings_state"] = "active" } };
        });
        var reader = new SecurityProblemsReader(repository, new NoEvidence());
        var context = Context(identity: identity);
        var loaded = new List<long>(); long occurrences = 0; string? cursor = null;
        // At most five pages are needed by this fixed 209-row fixture.
        for (int page = 0; page < 5; page++) {
            var body = await reader.QueryAsync(context with { Paging = context.Paging with { Cursor = cursor } }, TestContext.Current.CancellationToken);
            Assert.Equal(total, body["filtered_count"]!.GetValue<long>());
            Assert.Equal(total, body["metrics"]!.AsArray().Single(m => m!["key"]!.ToString() == "open")!["value"]!.GetValue<long>());
            var rows = body["items"]!.AsArray();
            loaded.AddRange(rows.Select(r => r!["id"]!.GetValue<long>()));
            occurrences += rows.Sum(r => long.Parse(r!["occurrence_count"]?.ToString() ?? "1"));
            Assert.True(calls[^1].GroupQueue);
            Assert.Equal("open", calls[^1].Population); Assert.True(calls[^1].PageQueue);
            Assert.Null(calls[^1].Status); Assert.Null(calls[^1].Risk);
            cursor = body["next_cursor"]?.ToString();
            if (!body["has_more"]!.GetValue<bool>()) break;
            Assert.NotNull(cursor);
            var next = context with { Paging = context.Paging with { Cursor = cursor } };
            foreach (var changed in new[] { next with { DomainIds = [8] }, next with { Paging = next.Paging with { Timezone = "Europe/Berlin" } } }) {
                int reads = calls.Count;
                Assert.Equal("invalid_cursor", (await Assert.ThrowsAsync<ReportRequestException>(() => reader.QueryAsync(changed, TestContext.Current.CancellationToken))).Message);
                Assert.Equal(reads, calls.Count);
            }
        }
        Assert.Equal(Enumerable.Range(1, total).Reverse().Select(n => (long)n), loaded);
        Assert.Equal(209, occurrences); Assert.Null(cursor);
        Assert.Equal(2, calls.Count);
    }

    [Theory]
    [InlineData("id", "7", null)]
    [InlineData("population", "open", "open")]
    [InlineData("population", "attention", "attention")]
    [InlineData("status", "closed", "open")]
    [InlineData("risk", "accepted", "open")]
    public async Task DetailRechecksSelectedPopulationBeforeReadingEvidence(string key, string value, string? population)
    {
        FindingQuery? input = null;
        var reader = new SecurityProblemsReader(new RecordingRepository(q => { input = q; return new() { ["items"] = new JsonArray() }; }), new NoEvidence());
        var error = await Assert.ThrowsAsync<ReportRequestException>(() => reader.DetailAsync(Context(new() { [key] = value }), "7", TestContext.Current.CancellationToken));
        Assert.Equal("report_row_not_found", error.Message); Assert.Equal(404, error.Status);
        Assert.NotNull(input); Assert.Equal(7, input.FindingId); Assert.Equal(population, input.Population);
        Assert.Equal(key == "status" ? value : null, input.Status); Assert.Equal(key == "risk" ? value : null, input.Risk);
        Assert.False(input.GroupQueue); Assert.True(input.Compact); Assert.Equal(1, input.Limit);
    }

    sealed class NoEvidence : ISecurityProblemEvidence
    {
        public Task<JsonObject> PageAsync(ReportQueryContext c, long finding, JsonObject? cursor, CancellationToken ct) => throw new InvalidOperationException("Evidence must not be read before queue membership is confirmed");
    }

    sealed class RecordingRepository(Func<FindingQuery, JsonObject> read) : IProblemRepository
    {
        public Task<JsonObject> FindingsAsync(FindingQuery q, ProblemAccess a, CancellationToken ct) => Task.FromResult(read(q));
        public Task<JsonObject> StatusAsync(long id, FindingStatusInput input, string actor, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAsync(long id, RiskInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> ResponsiblesAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> RiskAuditAsync(long id, long? before, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> WatchSaveAsync(string? id, WatchInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoyListAsync(RegistryQuery q, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
        public Task<JsonObject> DecoySaveAsync(string? id, DecoyInput input, ProblemAccess a, Principal p, CancellationToken ct) => throw new NotSupportedException();
    }
}
