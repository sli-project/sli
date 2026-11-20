using System.Text.Json.Nodes;
using Sli.Server.Domains;
using Xunit;

namespace Sli.Server.Tests.Domains;

public sealed class HomeSummaryReadReuseTests
{
    sealed class Rows : IHomeSummaryRepository
    {
        public int Reads;
        public int Count = 1;
        public Task<IReadOnlyList<JsonObject>> ReadAsync(string sql, IReadOnlyDictionary<string, object?> parameters, CancellationToken ct)
        {
            Reads++;
            return Task.FromResult<IReadOnlyList<JsonObject>>(((long[])parameters["ids"]!).SelectMany(id => Enumerable.Range(0, Count)
                .Select(n => new JsonObject { ["domain_id"] = id, ["entity_id"] = id * 100000 + n })).ToArray());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Per_domain_summary_reuses_complete_reads_without_crossing_domain_scope(bool entities)
    {
        var rows = new Rows(); var reads = new HomeSummaryReaders(rows);
        string sql = entities ? HomeSummarySql.Entities : HomeSummarySql.Sections;
        async Task<IReadOnlyList<JsonObject>> Read(long[] ids, string sections = "domain_posture,domain_health") =>
            await reads.Read(sql, TestContext.Current.CancellationToken, ("ids", ids), ("sections", sections));
        var all = await Read([7, 8]);
        all[0]["domain_id"] = 99; // A consumer must not mutate the cached source.
        Assert.Equal(7, Assert.Single(await Read([7]))["domain_id"]!.GetValue<long>());
        Assert.Equal(8, Assert.Single(await Read([8]))["domain_id"]!.GetValue<long>());
        Assert.Equal(1, rows.Reads);
        Assert.Equal(9, Assert.Single(await Read([9]))["domain_id"]!.GetValue<long>());
        Assert.Equal(2, rows.Reads);
        await Read([7], "directory_accounts"); Assert.Equal(3, rows.Reads);
        await new HomeSummaryReaders(rows).Read(sql, TestContext.Current.CancellationToken, ("ids", new long[] { 7 }), ("sections", "domain_posture,domain_health"));
        Assert.Equal(4, rows.Reads); // No sharing between HTTP requests.
    }

    [Fact]
    public async Task Truncated_inventory_is_read_again_for_a_smaller_domain_scope()
    {
        var rows = new Rows { Count = 5001 }; var reads = new HomeSummaryReaders(rows);
        await reads.Read(HomeSummarySql.Entities, TestContext.Current.CancellationToken, ("ids", new long[] { 7, 8 }), ("sections", "domain_health"));
        rows.Count = 1;
        Assert.Single(await reads.Read(HomeSummarySql.Entities, TestContext.Current.CancellationToken, ("ids", new long[] { 8 }), ("sections", "domain_health")));
        Assert.Equal(2, rows.Reads);
    }
}
