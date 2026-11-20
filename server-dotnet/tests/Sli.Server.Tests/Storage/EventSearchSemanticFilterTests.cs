using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Npgsql;
using Sli.Server.Access;
using Sli.Server.Infrastructure;
using Sli.Server.Storage.EventReports;
using Sli.Server.Tests.Agents;
using Xunit;

namespace Sli.Server.Tests.Storage;

// Vectors from tests/events/test_event_search_semantic_filters.py.
public sealed class EventSearchSemanticFilterTests
{
    static EventListInput Input(string query) => EventListInput.Parse(
        new QueryCollection(QueryHelpers.ParseQuery("?time_from="+DateTime.UtcNow.Date.ToString("O")+"&"+query)),DateTimeOffset.UtcNow);
    static long[] Ids(JsonObject page) => page["items"]!.AsArray().Select(i=>i!["event_db_id"]!.GetValue<long>()).ToArray();

    [Theory]
    [InlineData("risk=high",1L)]
    [InlineData("tier=operations",2L)]
    [InlineData("category=accounts",2L)]
    public void Decorated_rows_use_semantic_filters(string query,long expected)
    {
        var rows=new[]{
            new JsonObject { ["event_db_id"]=1L,["severity"]="high",["tier"]="security",["category"]="authentication" },
            new JsonObject { ["event_db_id"]=2L,["severity"]="low",["tier"]="operations",["category"]="account_management" }
        };
        Assert.Equal(expected,Assert.Single(rows,row=>EventListProjection.Matches(row,Input(query)))["event_db_id"]!.GetValue<long>());
    }

    [Theory]
    [InlineData("critical",true)]
    [InlineData("high",true)]
    [InlineData("medium",false)]
    public void Multiple_risks_are_an_or_selection(string severity,bool expected)
    {
        Assert.Equal(expected,EventListProjection.Matches(new JsonObject { ["severity"]=severity },Input("risk=critical,%20high")));
    }

    [Fact]
    public void Canonical_semantics_override_legacy_fields_and_null_uses_compatibility_aliases()
    {
        var item=new JsonObject { ["severity"]="high",["final_security_severity"]="unknown",["tier"]="security",["purpose_tier"]="technical" };
        Assert.False(EventListProjection.Matches(item,Input("risk=high")));
        Assert.True(EventListProjection.Matches(item,Input("risk=unknown&tier=technical")));
        item["final_security_severity"]=null; item["purpose_tier"]=null;
        Assert.True(EventListProjection.Matches(item,Input("risk=high&tier=security")));
        item["final_risk"]="medium";
        Assert.False(EventListProjection.Matches(item,Input("risk=high")));
    }

    [Theory]
    [InlineData(4625,"Security","authentication")]
    [InlineData(4722,"Security","account_management")]
    [InlineData(140,"Microsoft-Windows-TaskScheduler/Operational","service_task")]
    public void Known_rows_without_category_use_backend_family(int id,string channel,string category)
    {
        Assert.Equal(category,EventListProjection.FallbackCategory(new JsonObject { ["event_id"]=id,["channel"]=channel }));
    }

    [Fact]
    public async Task Short_semantics_filter_before_paging_and_scan_until_match_or_exhaustion()
    {
        var ct=TestContext.Current.CancellationToken;
        await using var fixture=new SqlPostgresFixture(); await fixture.StartAsync(ct);
        await using var db=new NpgsqlConnection(fixture.Pg.ConnectionString); await db.OpenAsync(ct);
        long domain=await EventShortReadPostgresTests.SeedRecorderAsync(db,ct);
        await using(var removed=new NpgsqlCommand(
            "select to_regclass('public.events_v2_core') is null and to_regclass('public.event_facts_v2') is null",db))
            Assert.Equal(true,await removed.ExecuteScalarAsync(ct));
        var stamp=new DateTimeOffset(DateTime.UtcNow.Date,TimeSpan.Zero);
        async Task Write(params (long Id,int Kind,DateTimeOffset At)[] events) {
            await using var tx=await db.BeginTransactionAsync(ct);
            await PostCollectionPostgres.Sql(db,"set local role adlog_storage_worker",ct);
            await Sli.Server.Storage.Direct.ShortEventWriter.WriteAsync(db,tx,events.Select(e=>
                EventShortReadPostgresTests.Event(e.Id,e.Kind,e.At,domain).Short).ToArray(),ct);
            await tx.CommitAsync(ct);
        }
        await Write(Enumerable.Range(1,5).Select(n=>((long)n,n is 5 or 3 or 2 ? 4724:4625,stamp.AddSeconds(n))).ToArray());
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?> {
            ["ConnectionStrings:Sli"]=fixture.Dsn("adlog_user"),["Sli:Storage:HistoryReadMode"]="disabled",["Sli:Storage:ShortEventReads"]="false"
        }).Build();
        await using var reader=new EventReadService(new PostgresConnectionFactory(config),config,null!);
        var caps=new CapabilityComposer().Compose(EventQueryEndpointTests.MakeFacts(owner:true));
        Task<JsonObject> Page(string query) => reader.ListAsync(Input(query),caps,ct);

        // Physical and semantic reads use only short rows.
        Assert.Equal(new long[]{5,4,3,2,1},Ids(await Page("limit=10")));
        var risk=await Page("limit=10&risk=high");
        Assert.Equal("high",risk["filters"]!["risk"]!.ToString());
        Assert.Equal(new long[]{5,3,2},Ids(risk));
        Assert.All(risk["items"]!.AsArray(),item=>Assert.Equal("high",item!["final_security_severity"]!.ToString()));
        Assert.Equal(new long[]{4,1},Ids(await Page("limit=10&tier=important")));
        var accounts=await Page("limit=10&category=accounts");
        Assert.Equal("account_management",Input("category=accounts").Category);
        Assert.Equal("account_management",accounts["filters"]!["category"]!.ToString());
        Assert.Equal(new long[]{5,3,2},Ids(accounts));
        Assert.True(accounts["performance"]!["semantic_filter_before_page"]!.GetValue<bool>());

        foreach(string order in new[]{"desc","asc"})
        {
            var first=await Page("limit=2&risk=high&order="+order);
            var second=await Page("limit=2&risk=high&order="+order+"&cursor="+Uri.EscapeDataString(first["next_cursor"]!.ToString()));
            Assert.Equal(order=="desc"?new long[]{5,3}:new long[]{2,3},Ids(first));
            Assert.Equal(order=="desc"?new long[]{2}:new long[]{5},Ids(second));
            Assert.True(first["has_more"]!.GetValue<bool>());
            Assert.False(second["has_more"]!.GetValue<bool>()); Assert.Null(second["next_cursor"]);
        }

        // 200 physical nonmatches, then one high risk: the second batch is needed.
        await PostCollectionPostgres.Sql(db,"delete from event_hot; delete from event_cold_facts; delete from event_cold_daily",ct);
        await Write((200,4724,stamp.AddSeconds(1)));
        await Write(Enumerable.Range(201,200).Select(n=>((long)n,4625,stamp.AddSeconds(2))).ToArray());
        var pastFirst=await Page("limit=1&risk=high");
        Assert.Equal(new long[]{200},Ids(pastFirst));
        Assert.Equal(2,pastFirst["performance"]!["semantic_query_count"]!.GetValue<int>());
        Assert.False(pastFirst["has_more"]!.GetValue<bool>()); Assert.Null(pastFirst["next_cursor"]);

        // Q500 replaces Python's scan cap/query budget: progress continues beyond both.
        await Write(Enumerable.Range(401,5001).Select(n=>((long)n,4625,stamp.AddSeconds(2))).ToArray());
        var beyondCaps=await Page("limit=1&risk=high");
        Assert.Equal(new long[]{200},Ids(beyondCaps));
        Assert.True(beyondCaps["performance"]!["semantic_query_count"]!.GetValue<int>()>8);
        Assert.Equal(5202,beyondCaps["performance"]!["scanned_rows"]!.GetValue<long>());
        Assert.False(beyondCaps["has_more"]!.GetValue<bool>()); Assert.Null(beyondCaps["next_cursor"]);
        var absent=await Page("limit=1&risk=high&tier=important");
        Assert.Empty(Ids(absent)); Assert.False(absent["has_more"]!.GetValue<bool>()); Assert.Null(absent["next_cursor"]);

        await fixture.AssertNoSqlErrorsAsync(ct);
    }
}
