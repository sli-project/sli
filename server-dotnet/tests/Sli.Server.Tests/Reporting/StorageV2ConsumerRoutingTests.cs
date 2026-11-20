using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Sli.Server.Compatibility;
using Sli.Server.Infrastructure;
using Sli.Server.Legacy;
using Sli.Server.Semantic;
using Sli.Server.Storage.EventReports;
using Sli.Server.Workspace;
using Xunit;

namespace Sli.Server.Tests.Reporting;

// Behavior vectors from tests/reporting/test_storage_v2_consumer_routing.py.
public sealed partial class StorageV2ConsumerRoutingTests
{
    static CancellationToken Ct => TestContext.Current.CancellationToken;
    static string Sql(string sql) => string.Join(' ',sql.ToLowerInvariant().Split((char[]?)null,StringSplitOptions.RemoveEmptyEntries));
    static void V2Only(string sql)
    {
        sql=Sql(sql);
        foreach(string legacy in new[]{"from events ","join events ","observed_entities","from event_links ","from event_entity_links ","join event_entity_links "})
            Assert.DoesNotContain(legacy,sql);
    }
    sealed class NeverConnect : IPostgresConnectionFactory
    { public Task<NpgsqlConnection> OpenAsync(CancellationToken ct) => throw new InvalidOperationException("unexpected_database_read"); }

    [Theory]
    [InlineData(1906133L)] [InlineData(2147483648L)] [InlineData(long.MaxValue)]
    public async Task Exact_entities_preserve_bigint_and_extract_short_row_participants(long id)
    {
        var calls=new List<(string Sql,IReadOnlyDictionary<string,object> Parameters)>();
        Task<List<JsonObject>> Query(string sql,IReadOnlyDictionary<string,object> parameters,CancellationToken ct)
        {
            V2Only(sql); calls.Add((Sql(sql),parameters));
            return Task.FromResult<List<JsonObject>>(calls.Count==1 ? [new() { ["time_created_utc"]="2026-07-17T00:30:00Z" }] : []);
        }
        using var host=new HostBuilder().Build();
        await using var reader=new EventReadService(new NeverConnect(),new ConfigurationBuilder().Build(),host.Services.GetService(typeof(IHostEnvironment)) as IHostEnvironment ?? throw new InvalidOperationException());
        var result=await reader.EntitiesAsync(id,Query,Ct);
        Assert.True(result["event_found"]!.GetValue<bool>()); Assert.Equal(id,result["event_db_id"]!.GetValue<long>());
        Assert.Equal("zero_extracted",result["evidence_status"]!.ToString()); Assert.Empty(result["items"]!.AsArray());
        Assert.Equal(2,calls.Count);
        Assert.All(calls,c=>Assert.Equal(id,c.Parameters["id"]));
        Assert.All(calls,c=>Assert.IsType<DateTimeOffset>(c.Parameters["boundary"]));

    }

    [Fact]
    public async Task Missing_V2_anchor_does_not_query_legacy_relations()
    {
        int calls=0;
        Task<List<JsonObject>> Query(string sql,IReadOnlyDictionary<string,object> p,CancellationToken ct)
        { calls++; V2Only(sql); Assert.Contains("relation_events",sql); Assert.Equal(17L,p["id"]); return Task.FromResult(new List<JsonObject>()); }
        var candidates=await new EventRelationStore(Query).QueryAsync(17,101,null,Ct);
        Assert.Empty(EventRelationContract.Build(17,candidates,100)["items"]!.AsArray()); Assert.Equal(1,calls);
    }

    [Fact]
    public async Task Proven_keys_use_separate_indexable_V2_queries_and_return_both_relations()
    {
        const string task=@"\Microsoft\Windows\Example";
        var calls=new List<(string Sql,IReadOnlyDictionary<string,object> Parameters)>();
        Task<List<JsonObject>> Query(string sql,IReadOnlyDictionary<string,object> p,CancellationToken ct)
        {
            V2Only(sql); sql=Sql(sql); calls.Add((sql,p));
            if(calls.Count==1) return Task.FromResult<List<JsonObject>>([new() { ["server_id"]=7,["time_created_utc"]="2026-07-17T07:15:51Z",["logon_id"]="0x123",["task_name"]=task }]);
            bool logon=sql.Contains("e.logon_id=@key");
            return Task.FromResult<List<JsonObject>>([new() { ["id"]=logon?90:92,["event_id"]=logon?4624:140,["time_created_utc"]=logon?"2026-07-17T07:15:52Z":"2026-07-17T07:15:53Z",["entity"]=logon?"0x123":task,["delta"]=logon?1:2 }]);
        }
        var candidates=await new EventRelationStore(Query).QueryAsync(91,101,null,Ct);
        var items=EventRelationContract.Build(91,candidates,100)["items"]!.AsArray();
        Assert.Equal(new long[]{90,92},items.Select(i=>i!["related_event_db_id"]!.GetValue<long>())); Assert.Equal(3,calls.Count);
        Assert.Equal(91L,calls[0].Parameters["id"]); Assert.Contains("where e.id=@id",calls[0].Sql);
        for(int i=1;i<3;i++) {
            var call=calls[i]; Assert.DoesNotContain(" or (",call.Sql); Assert.DoesNotContain("exists (",call.Sql);
            Assert.Contains(i==1?"e.logon_id=@key":"e.task_name=@key",call.Sql);
            Assert.Contains(i==1?"interval '4 hours'":"interval '1 hour'",call.Sql);
            Assert.Equal(i==1?"0x123":task,call.Parameters["key"]); Assert.Equal(7L,call.Parameters["server"]);
            Assert.Equal(91L,call.Parameters["anchor"]); Assert.Equal(101,call.Parameters["limit"]);
            Assert.Equal(DateTime.Parse("2026-07-17T07:15:51Z").ToUniversalTime(),call.Parameters["base"]);
        }
        Assert.Equal("same_logon_id_same_server",items[0]!["relation_rule"]!.ToString());
        Assert.Equal("same_task_same_server_time_window",items[1]!["relation_rule"]!.ToString());
        Assert.Equal("context",items[0]!["source_role"]!.ToString()); Assert.Equal(2L,items[1]!["time_delta_seconds"]!.GetValue<long>());
    }

    [Theory] [InlineData("0x0")] [InlineData("0X0")] [InlineData("-")] [InlineData("")] [InlineData(null)]
    public async Task Unproven_keys_never_broaden_correlation(string? logon)
    {
        int calls=0;
        Task<List<JsonObject>> Query(string sql,IReadOnlyDictionary<string,object> p,CancellationToken ct)
        { calls++; V2Only(sql); return Task.FromResult<List<JsonObject>>([new() { ["server_id"]=7,["time_created_utc"]="2026-07-17T07:15:51Z",["logon_id"]=logon,["task_name"]=null }]); }
        Assert.Empty(await new EventRelationStore(Query).QueryAsync(91,101,null,Ct)); Assert.Equal(1,calls);
    }

}
