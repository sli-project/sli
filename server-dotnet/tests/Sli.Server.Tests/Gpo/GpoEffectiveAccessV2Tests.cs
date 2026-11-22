using System.Net;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.TestHost;
using Microsoft.VisualBasic.FileIO;
using Sli.Server.Gpo;
using Xunit;
using static Sli.Server.Gpo.GpoJson;

namespace Sli.Server.Tests.Gpo;

// Report-level vectors from tests/reporting/test_gpo_effective_access_v2.py.
public sealed class GpoEffectiveAccessV2Tests
{
    const string Prefix="/api/v2/reports/ad.gpo.v2";
    const string DomainScope="{\"kind\":\"domain\",\"ids\":[7]}";
    sealed class Store : IGpoReadStore
    {
        internal JsonObject Snapshot,Graph;
        internal JsonObject? History;
        internal readonly List<long[]?> PairDomains=[],GraphDomains=[];
        internal readonly List<(long[]? Domains,DateTimeOffset From,DateTimeOffset To,string Query)> HistoryCalls=[];
        internal Store(bool topology=false)
        {
            var vectors=GpoReportTests.Vectors();
            Snapshot=(topology?vectors["links"]![0]!["snapshot"]:vectors["effective"]![0]!["snapshot"])!.AsObject().Copy();
            Graph=vectors["effective"]![0]!["graph"]!.AsObject().Copy();
            string now=Iso(DateTimeOffset.UtcNow);
            Snapshot["observed_at"]=now;Graph["source"]!["observed_at_utc"]=now;
        }
        public Task<JsonObject> PairAsync(long[]? domains,CancellationToken ct)
        {
            Assert.Null(History);PairDomains.Add(domains);
            return Task.FromResult(new JsonObject { ["state"]="available",["current"]=Snapshot.DeepClone(),["previous"]=null });
        }
        public Task<JsonObject> GraphAsync(JsonObject snapshot,long[]? domains,CancellationToken ct)
        {
            Assert.Null(History);GraphDomains.Add(domains);return Task.FromResult(Graph.Copy());
        }
        public Task<JsonObject> PolicyHistoryAsync(long[] domains,DateTimeOffset from,DateTimeOffset to,string policyId,string guid,CancellationToken ct)
            => throw new InvalidOperationException("Unexpected policy history read");
        public Task<JsonObject> HistoryAsync(long[]? domains,DateTimeOffset from,DateTimeOffset to,string query,CancellationToken ct)
        {
            HistoryCalls.Add((domains,from,to,query));return Task.FromResult(History!.Copy());
        }
    }
    static GpoRequest Request(string tab)=>new("attention","",tab,null,"asc",500,null,"UTC",Stamp("2026-01-01T00:00:00Z"),Stamp("2026-10-01T00:00:00Z"));
    static async Task<JsonObject> Data(HttpClient client,string query)
    {
        using var response=await client.GetAsync(Prefix+"/data?"+query,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        return JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
    }
    static async Task<Dictionary<string,string>> Export(HttpClient client,string query)
    {
        using var response=await client.GetAsync(Prefix+"/export.csv?"+query,TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode);
        Assert.Equal("text/csv",response.Content.Headers.ContentType!.MediaType);
        Assert.Equal("1",Assert.Single(response.Headers.GetValues("X-Sli-Export-Rows")));
        Assert.Equal("false",Assert.Single(response.Headers.GetValues("X-Sli-Export-Truncated")));
        using var parser=new TextFieldParser(new StringReader(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))) { HasFieldsEnclosedInQuotes=true };
        parser.SetDelimiters(",");
        var headers=parser.ReadFields()!;var row=parser.ReadFields()!;
        Assert.True(parser.EndOfData);
        return headers.Zip(row).ToDictionary(p=>p.First,p=>p.Second);
    }

    [Fact]
    public async Task Changes_read_only_confirmed_period_history_and_export_fingerprints()
    {
        var row=new JsonObject { ["observed_at"]="2026-02-01T00:00:00Z",["object_type"]="gpo",["object_id"]="policy-a",["kind"]="attribute_changed",["field"]="gpo_status",["before_sha256"]=new string('a',64),["after_sha256"]=new string('b',64) };
        var store=new Store { History=new JsonObject { ["state"]="partial",["items"]=new JsonArray(row),["coverage"]=new JsonObject { ["state"]="partial" },["truncated"]=false } };
        using var host=await GpoEndpointTests.Host(store,scope:DomainScope);using var client=host.GetTestClient();
        const string query="tab=changes&period=custom&from=2026-01-01T00:00:00Z&to=2026-10-01T00:00:00Z&q=policy-a";
        var data=await Data(client,query);
        Assert.Equal("partial",data.Text("state"));
        Assert.True(JsonNode.DeepEquals(new JsonObject { ["changes"]=new JsonArray(row.DeepClone()) },data["collections"]));
        Assert.Equal("history_partial",data.Rows("limitations").First().Text("code"));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"from_utc":"2026-01-01T00:00:00Z","to_utc_exclusive":"2026-10-01T00:00:00Z"}"""),data["window"]));
        var exported=await Export(client,query);
        Assert.Equal("policy-a",exported["Объект"]);
        Assert.Equal(new string('a',64),exported["Прежний отпечаток"]);
        Assert.Equal(new string('b',64),exported["Новый отпечаток"]);
        Assert.Empty(store.PairDomains);Assert.Empty(store.GraphDomains);Assert.Equal(2,store.HistoryCalls.Count);
        Assert.All(store.HistoryCalls,call=>
        {
            Assert.Equal(new long[]{7},call.Domains);Assert.Equal(Stamp("2026-01-01T00:00:00Z"),call.From);
            Assert.Equal(Stamp("2026-10-01T00:00:00Z"),call.To);Assert.Equal("policy-a",call.Query);
        });
    }

    [Theory]
    [InlineData("filtering")]
    [InlineData("delegation")]
    public async Task Report_exposes_only_the_open_collection_and_authorized_graph(string tab)
    {
        var store=new Store();using var host=await GpoEndpointTests.Host(store,scope:DomainScope);using var client=host.GetTestClient();
        var data=await Data(client,"tab="+tab);
        Assert.Equal("sli.report-result.v2",data.Text("contract_id"));Assert.Equal("ad.gpo.v2",data.Text("report_key"));Assert.Equal("ok",data.Text("state"));
        Assert.Empty(data.Rows("items"));Assert.Equal(tab,Assert.Single(data["collections"]!.AsObject()).Key);Assert.NotEmpty(data["collections"].Rows(tab));
        Assert.Equal(new long[]{7},Assert.Single(store.PairDomains));Assert.Equal(new long[]{7},Assert.Single(store.GraphDomains));
        Assert.Equal("docs/GPO_REPORT_PASSPORT.md",data["coverage"].Text("passport"));
        Assert.Contains(data.Rows("limitations"),l=>l.Text("text").Contains("RSoP",StringComparison.Ordinal));
    }

    [Fact]
    public async Task Search_and_csv_share_the_nested_membership_path()
    {
        var store=new Store();using var host=await GpoEndpointTests.Host(store,scope:DomainScope);using var client=host.GetTestClient();
        var data=await Data(client,"tab=filtering&q=user-a");
        var row=Assert.Single(data["collections"].Rows("filtering"));Assert.Equal("user-a",row.Text("principal"));
        const string path="user-a → group-a → group-b → policy-a [ACE 0]";
        Assert.Equal(path,row.Text("path"));
        var exported=await Export(client,"tab=filtering&q=user-a");
        Assert.Equal(path,exported["Путь членства → GPO ACE"]);Assert.Equal("user-a",exported["Эффективный субъект"]);
        Assert.DoesNotContain(exported.Values,value=>value.Contains("computer-a",StringComparison.Ordinal));
    }

    [Fact]
    public async Task Missing_acl_is_partial_and_old_graph_is_stale_separately()
    {
        var store=new Store();store.Snapshot["gpos"]![0]!["source_states"]!.AsObject().Remove("acl");
        var data=await GpoReport.QueryAsync(store,[7],Request("filtering"),TestContext.Current.CancellationToken);
        Assert.Equal("partial",data.Text("state"));Assert.Equal("not_collected",data["collections"].Rows("filtering").First().Text("outcome"));
        store.Snapshot["gpos"]![0]!["source_states"]!["acl"]=new JsonObject { ["status"]="observed" };
        store.Graph["source"]!["observed_at_utc"]="2020-01-01T00:00:00Z";
        data=await GpoReport.QueryAsync(store,[7],Request("filtering"),TestContext.Current.CancellationToken);
        Assert.Equal("stale",data.Text("state"));
    }

    [Fact]
    public async Task Topology_does_not_read_directory_and_retains_partial_link_state()
    {
        var store=new Store(topology:true);using var host=await GpoEndpointTests.Host(store,scope:DomainScope);using var client=host.GetTestClient();
        var data=await Data(client,"tab=linked_scopes");
        Assert.Equal("ok",data.Text("state"));Assert.Equal(3,data["collections"].Rows("linked_scopes").Count());
        Assert.Equal("linked_scopes",Assert.Single(data["collections"]!.AsObject()).Key);Assert.Empty(data.Rows("items"));
        store.Snapshot["source_states"]!["links"]!["status"]="partial";
        data=await Data(client,"tab=linked_scopes");
        Assert.Equal("partial",data.Text("state"));Assert.Empty(store.GraphDomains);Assert.Empty(store.HistoryCalls);
    }
}
