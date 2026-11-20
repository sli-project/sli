using System.Text.Json.Nodes;
using Npgsql;
using Sli.Server.Semantic;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Semantic;

public sealed class SemanticBackfillLowerBoundTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Ten_thousand_decisions_read_only_the_unresolved_tail_and_late_gap(bool gap)
    {
        var ct=TestContext.Current.CancellationToken;
        await using var pg=new PostCollectionPostgres(canonicalSchema:true); await pg.StartAsync(ct);
        await using var db=await pg.OpenAsync(ct);
        await PostCollectionPostgres.Sql(db,"""
            create table semantic_event_source355(id bigint primary key);
            create table semantic_producer_coverage(runtime_mode text,processor_version text,decided_ids int8multirange);
            insert into semantic_event_source355 select generate_series(1,10004);
            analyze semantic_event_source355;
            """,ct);
        await using(var seed=new NpgsqlCommand("insert into semantic_producer_coverage values($1,$2,$3::int8multirange)",db)) {
            seed.Parameters.AddWithValue(SemanticRuntimeSettings.FindingsMode); seed.Parameters.AddWithValue(SemanticEvent.Version);
            seed.Parameters.AddWithValue(gap?"{[1,5000),[5001,10002)}":"{[1,10001)}"); await seed.ExecuteNonQueryAsync(ct);
        }
        await using var query=new NpgsqlCommand(SemanticProducerBackfill.SelectionSql,db);
        query.Parameters.AddWithValue(SemanticRuntimeSettings.FindingsMode); query.Parameters.AddWithValue(SemanticEvent.Version); query.Parameters.AddWithValue(10);
        var ids=new List<long>();
        await using(var reader=await query.ExecuteReaderAsync(ct)) while(await reader.ReadAsync(ct)) ids.Add(reader.GetInt64(0));
        Assert.Equal(gap?new long[]{5000,10002,10003,10004}:new long[]{10001,10002,10003,10004},ids);
        query.CommandText="explain (analyze,format json) "+SemanticProducerBackfill.SelectionSql;
        var plan=JsonNode.Parse((string)(await query.ExecuteScalarAsync(ct))!)!;
        var scans=Nodes(plan).Where(n=>n["Relation Name"]?.GetValue<string>()=="semantic_event_source355").ToArray();
        Assert.NotEmpty(scans);
        double visited=scans.Sum(n=>(n["Actual Rows"]!.GetValue<double>()+(n["Rows Removed by Filter"]?.GetValue<double>()??0)) * n["Actual Loops"]!.GetValue<double>());
        Assert.Equal(4,visited);
        query.CommandText=SemanticProducerBackfill.SelectionSql;
        query.Parameters[2].Value=1;
        Assert.Equal(gap?5000L:10001L,await query.ExecuteScalarAsync(ct));
        // Decisions for a different mode or processor never hide source rows.
        query.Parameters[0].Value=SemanticRuntimeSettings.FactsMode;
        Assert.Equal(1L,await query.ExecuteScalarAsync(ct));
        query.Parameters[0].Value=SemanticRuntimeSettings.FindingsMode;
        query.Parameters[1].Value="synthetic-new-processor";
        Assert.Equal(1L,await query.ExecuteScalarAsync(ct));
    }

    private static IEnumerable<JsonObject> Nodes(JsonNode node)
    {
        if(node is JsonObject obj) { yield return obj; foreach(var child in obj.Select(p=>p.Value).OfType<JsonNode>()) foreach(var nested in Nodes(child)) yield return nested; }
        else if(node is JsonArray array) foreach(var child in array.OfType<JsonNode>()) foreach(var nested in Nodes(child)) yield return nested;
    }
}
