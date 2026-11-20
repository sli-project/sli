using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Npgsql;
using Sli.Server.Vpn;
using Xunit;

namespace Sli.Server.Tests.Vpn;

// Behavioral vectors from tests/reporting/test_vpn_report_resilience.py.
public sealed class VpnReportResilienceTests
{
    static readonly DateTimeOffset Start=DateTimeOffset.Parse("2026-01-01T00:00:00Z"),End=Start.AddDays(90);
    static VpnQuery Query=>new(1,"view","UTC",Start,End,200,0,"");
    static VpnAccess Access(bool owner=true)=>new(VpnRouteTests.MakeFacts(owner));
    static JsonObject Json(object value)=>VpnRouteTests.Json(value);
    static JsonObject Event(int index=1,int code=6273)=>Json(new {event_db_id=index,event_record_id=index,event_id=code,time_created_utc=Start.AddSeconds(index),subject_user_sid="S-1-5-21-100000001-200000002-300000003-7",alias_match_count=0,domain_controller="dc.example.test"});
    static Exception Failure(string kind)=>kind=="postgres"?new PostgresException("synthetic source cancellation","ERROR","ERROR","57014"):new TimeoutException("synthetic source timeout");
    static IQueryCollection Parameters(string tab)=>new QueryCollection(new Dictionary<string,Microsoft.Extensions.Primitives.StringValues>
    {
        ["domain"]="1",["period"]="custom",["from"]=Start.ToString("O"),["to"]=End.ToString("O"),["tab"]=tab
    });
    sealed class Reader : IVpnStore,IVpnReadSession
    {
        readonly VpnRouteTests.Store baseline=new();
        public readonly List<(string Sql,object?[] Values)> Calls=[];
        public Func<string,object?[],List<JsonObject>?>? Read;
        public Task<IVpnReadSession> OpenAsync(CancellationToken ct)=>Task.FromResult<IVpnReadSession>(this);
        public ValueTask DisposeAsync()=>ValueTask.CompletedTask;
        public Task<List<JsonObject>> ReadAsync(string sql,object?[] values,CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();Calls.Add((sql,values));
            return Read?.Invoke(sql,values) is {} rows?Task.FromResult(rows):baseline.ReadAsync(sql,values,ct);
        }
    }
    static async Task<JsonObject> Http(Reader reader,string tab)
    {
        using var host=await VpnRouteTests.Host(reader);using var client=host.GetTestClient();
        string path="/api/v2/reports/vpn.connections/data"+QueryString.Create(Parameters(tab).Select(p=>new KeyValuePair<string,string?>(p.Key,p.Value.ToString())));
        using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
    }
    static void Partial(JsonObject payload,string branch)
    {
        Assert.Equal("partial",payload["state"]!.ToString());
        Assert.Equal("source_read_timeout",payload["branches"]![branch]!["reason"]!.ToString());
    }



    [Theory][InlineData("windows")][InlineData("windows_heatmap")][InlineData("session_overlap")]
    public async Task More_than_ninety_days_is_rejected_before_source_read(string tab)
    {
        var reader=new Reader();var q=Query with {To=End.AddDays(1)};
        var error=await Assert.ThrowsAsync<VpnInputException>(()=>tab switch
        {
            "windows"=>VpnWindows.Read(reader,Access(),q,TestContext.Current.CancellationToken),
            "windows_heatmap"=>VpnReports.Grid(reader,Access(),q,TestContext.Current.CancellationToken),
            _=>VpnOverlap.Read(reader,Access(),q,Parameters(tab),TestContext.Current.CancellationToken)
        });
        Assert.Equal(tab=="session_overlap"?"vpn_overlap_window_invalid":"windows_authentication_period_too_wide",error.Message);
        Assert.Empty(reader.Calls);
    }
    [Theory][InlineData("windows")][InlineData("windows_heatmap")][InlineData("session_overlap")]
    public async Task Ninety_days_does_not_bypass_source_rights(string tab)
    {
        var reader=new Reader();var payload=tab switch
        {
            "windows"=>await VpnWindows.Read(reader,Access(false),Query,TestContext.Current.CancellationToken),
            "windows_heatmap"=>await VpnReports.Grid(reader,Access(false),Query,TestContext.Current.CancellationToken),
            _=>await VpnOverlap.Read(reader,Access(false),Query,Parameters(tab),TestContext.Current.CancellationToken)
        };
        Assert.Equal(tab=="session_overlap"?"denied":"not_authorized",payload["state"]!.ToString());Assert.Empty(reader.Calls);
    }
    [Fact]
    public async Task Busy_nps_window_keeps_display_prefix_and_exact_count()
    {
        var reader=new Reader {Read=(sql,_)=>sql==VpnSql.NpsEvents?Enumerable.Range(1,2001).Select(i=>Event(i)).ToList():sql==VpnSql.NpsCoverage?[Json(new {history_event_present=true,window_success_6272_count=0,window_failed_6273_count=2001})]:null};
        var payload=await VpnAuthorizations.Read(reader,Access(),Query,false,TestContext.Current.CancellationToken);
        Assert.Equal("partial",payload["state"]!.ToString());Assert.Equal(2000,payload["items"]!.AsArray().Count);
        Assert.Equal(1,payload["items"]![0]!["event_db_id"]!.GetValue<int>());Assert.Equal(2000,payload["items"]![1999]!["event_db_id"]!.GetValue<int>());
        Assert.True(payload["result_window"]!["truncated"]!.GetValue<bool>());
        Assert.Equal(2001,payload["collection_coverage"]!["window_failed_6273_count"]!.GetValue<int>());
    }
    [Theory][InlineData("postgres")][InlineData("timeout")]
    public async Task Nps_count_failure_keeps_rows_and_unknown_counts(string kind)
    {
        var reader=new Reader {Read=(sql,_)=>sql==VpnSql.NpsCoverage?throw Failure(kind):null};
        var payload=await VpnAuthorizations.Read(reader,Access(),Query,false,TestContext.Current.CancellationToken);
        Assert.Equal("partial",payload["state"]!.ToString());Assert.Equal(19,payload["items"]![0]!["event_db_id"]!.GetValue<int>());
        Assert.Equal("source_read_timeout",payload["unavailable_reason"]!.ToString());
        Assert.Null(payload["collection_coverage"]!["window_failed_6273_count"]);Assert.Null(payload["collection_coverage"]!["window_success_6272_count"]);
        Assert.DoesNotContain(reader.Calls,c=>c.Sql==VpnSql.Identities);
    }

    [Theory][InlineData("review","postgres")][InlineData("settings","timeout")][InlineData("coverage","postgres")]
    public async Task Windows_optional_read_failure_keeps_history_and_policy_not_evaluated(string stage,string kind)
    {
        var reader=new Reader {Read=(sql,_)=> (stage=="review" && sql==VpnSql.WindowsReview || stage=="coverage" && sql==VpnSql.WindowsCoverage || stage=="settings" && sql.StartsWith("select key,value from platform_settings",StringComparison.Ordinal))?throw Failure(kind):null};
        var payload=await VpnWindows.Read(reader,Access(),Query,TestContext.Current.CancellationToken);
        Assert.Equal("partial",payload["state"]!.ToString());Assert.Equal(21,payload["items"]![0]!["event_db_id"]!.GetValue<int>());
        Assert.Equal("unavailable",payload["manual_review_policy"]!["state"]!.ToString());
        Assert.Equal("not_evaluated",payload["manual_review_policy"]!["coverage_scope"]!.ToString());
        Assert.Empty(payload["manual_review_policy"]!["signals"]!.AsArray());
        if(stage=="coverage") Assert.DoesNotContain(reader.Calls,c=>c.Sql==VpnSql.WindowsReview);
    }
    [Fact]
    public void Windows_review_input_bound_cannot_claim_no_signal()
    {
        var failures=Enumerable.Repeat(Json(new {id=1,at=Start,sid="S-1-5-21-100000001-200000002-300000003-7"}),100001).ToList();
        var policy=VpnWindows.Review(failures,Query);
        Assert.Equal("unavailable",policy["state"]!.ToString());Assert.Equal("not_evaluated",policy["coverage_scope"]!.ToString());
        Assert.Equal("review_input_limit",policy["reason"]!.ToString());Assert.Empty(policy["signals"]!.AsArray());
    }


    [Theory]
    [InlineData("authorizations")][InlineData("failed")][InlineData("windows")]
    [InlineData("windows_heatmap")][InlineData("session_overlap")]
    public async Task Request_cancellation_propagates_without_starting_another_read(string tab)
    {
        using var cancellation=new CancellationTokenSource();
        var reader=new Reader {Read=(_,_)=> {cancellation.Cancel();throw new OperationCanceledException(cancellation.Token);} };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>VpnReports.Read(reader,Access(),"vpn.connections",Parameters(tab),"view",cancellation.Token));
        Assert.Single(reader.Calls);
    }
}
