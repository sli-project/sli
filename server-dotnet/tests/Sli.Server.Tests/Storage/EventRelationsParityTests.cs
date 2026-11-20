using System.Text.Json.Nodes;
using Sli.Server.Storage.EventReports;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/events/test_event_relations.py; only the database boundary is replaced.
public sealed class EventRelationsParityTests
{
    [Theory]
    [InlineData(0, false, new long[] { })]
    [InlineData(1, false, new long[] { 2 })]
    [InlineData(2, false, new long[] { 2, 3 })]
    [InlineData(3, true, new long[] { 2, 3 })]
    public async Task One_extra_candidate_sets_truncation_without_changing_items(int count, bool truncated, long[] expected)
    {
        var probes = new List<int>();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor, int limit, (decimal Delta, long Id)? after, CancellationToken ct)
        {
            probes.Add(limit);
            return Task.FromResult<IReadOnlyList<RelationCandidate>>(
                Enumerable.Range(0, count).Select(index => Candidate(index + 2, index)).Take(limit).ToArray());
        }

        var page = await Read(Query, 2);

        Assert.Equal(new[] { 3 }, probes);
        Assert.Equal(expected, Ids(page));
        Assert.Equal(truncated, page["truncated"]!.GetValue<bool>());
        Assert.Equal("v1", page["api_version"]!.GetValue<string>());
        Assert.Equal(1L, page["event_db_id"]!.GetValue<long>());
        Assert.Equal("explicit_event_link_or_rule_based_correlation", page["contract"]!.GetValue<string>());
        Assert.True(page["confidence_contract"]!.AsObject().ContainsKey("rule_policy_score"));
    }

    [Theory]
    [InlineData(new long[] { 2, 3 }, false)]
    [InlineData(new long[] { 3, 4 }, true)]
    public async Task Truncation_counts_unique_union_of_both_evidence_keys(long[] taskIds, bool truncated)
    {
        var probes = new List<int>();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor, int limit, (decimal Delta, long Id)? after, CancellationToken ct)
        {
            probes.Add(limit);
            var logon = new long[] { 2, 3 }.Select(id => Candidate(id, id)).Take(limit);
            var task = taskIds.Select(id => new RelationCandidate(id, 4624, null, "scheduled_task", "fixture-task",
                "same_task_same_server_time_window", id)).Take(limit);
            return Task.FromResult<IReadOnlyList<RelationCandidate>>([.. logon, .. task]);
        }

        var page = await Read(Query, 2);

        Assert.Equal(new[] { 3 }, probes);
        Assert.Equal(new long[] { 2, 3 }, Ids(page));
        Assert.Equal(truncated, page["truncated"]!.GetValue<bool>());
    }

    [Fact]
    public void Invalid_self_and_duplicate_rows_preserve_selected_order_and_do_not_imply_truncation()
    {
        var rows = new long[] { 0, -1, 1, 2, 2, 3, 3 }.Select(id => Candidate(id, 0)).ToArray();

        var page = EventRelationContract.Build(1, rows, 2);

        Assert.Equal(new long[] { 2, 3 }, Ids(page));
        Assert.False(page["truncated"]!.GetValue<bool>());
        Assert.Null(page["next_cursor"]);
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 1)]
    [InlineData(100, 100)]
    [InlineData(999, 200)]
    public async Task Requested_page_size_is_clamped_and_probes_only_one_extra(int requested, int bound)
    {
        var probes = new List<int>();
        Task<IReadOnlyList<RelationCandidate>> Query(long anchor, int limit, (decimal Delta, long Id)? after, CancellationToken ct)
        {
            probes.Add(limit);
            return Task.FromResult<IReadOnlyList<RelationCandidate>>(
                Enumerable.Range(0, limit).Select(index => Candidate(index + 2, index)).ToArray());
        }

        var page = await Read(Query, requested);

        Assert.Equal(new[] { bound + 1 }, probes);
        Assert.Equal(bound, page["items"]!.AsArray().Count);
        Assert.True(page["truncated"]!.GetValue<bool>());
    }

    static RelationCandidate Candidate(long id, decimal delta) =>
        new(id, 4624, null, "auth_session", "0x123", "same_logon_id_same_server", delta);

    static long[] Ids(JsonObject page) =>
        page["items"]!.AsArray().Select(item => item!["related_event_db_id"]!.GetValue<long>()).ToArray();

    static Task<JsonObject> Read(
        Func<long, int, (decimal Delta, long Id)?, CancellationToken, Task<IReadOnlyList<RelationCandidate>>> query, int limit) =>
        new EventRelationsReader(query, (_, _) => Task.FromResult(true))
            .ReadAsync(1, limit, null, TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
}
