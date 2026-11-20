using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Sli.Server.Access;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;
using Xunit;
namespace Sli.Server.Tests.Reporting;

public sealed class ReportV2DispatchTests
{
    [Fact]
    public void AllFrozenDeclarationsHaveTheReactWireShape()
    {
        var rules = new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules;
        Assert.Equal(27, rules.Count);
        foreach (var rule in rules) ReadSqlPostgresTests.AssertReactDeclaration(Definition(rule.RegistryKey).Declaration, rule.RegistryKey);
    }
    [Fact]
    public void RuleQualityUsesTheLastClassificationBeforeWindowEndAndPreservesUnknownEstimates()
    {
        var rows = JsonNode.Parse("""
            [{"rule_code":"synthetic-rule","created_at":"2026-01-01T00:00:00Z","repeat_count":1,"complete_evidence":true,"history":[
                {"id":1,"old_status":"new","new_status":"false_positive","changed_at":"2026-01-01T01:00:00Z"},
                {"id":2,"old_status":"false_positive","new_status":"confirmed","changed_at":"2026-01-01T02:00:00Z"},
                {"id":3,"old_status":"confirmed","new_status":"closed","changed_at":"2026-01-01T03:00:00Z"},
                {"id":4,"old_status":"closed","new_status":"false_positive","changed_at":"2026-01-03T00:00:00Z"}]},
             {"rule_code":"synthetic-rule","created_at":"2026-01-01T00:00:00Z","history":[]},
             {"rule_code":"unclassified","created_at":"2026-01-01T00:00:00Z","history":[]}]
            """)!.AsArray();
        var result = RuleQualityReader.Metrics(rows.OfType<JsonObject>(), DateTimeOffset.Parse("2026-01-02T00:00:00Z"));
        var metric = result.Single(r => r["rule_code"]!.ToString() == "synthetic-rule");
        Assert.Equal(1, metric["confirmed"]!.GetValue<long>()); Assert.Equal(0, metric["false_positive"]!.GetValue<long>()); Assert.Equal(1, metric["closed"]!.GetValue<long>());
        Assert.Equal(0, metric["false_positive_rate"]!.GetValue<double>()); Assert.Equal(3600, metric["median_decision_seconds"]!.GetValue<double>()); Assert.Equal(1, metric["missing_history"]!.GetValue<long>());
        Assert.Null(result.Single(r => r["rule_code"]!.ToString() == "unclassified")["false_positive_rate"]);
    }
    [Fact]
    public void LockoutCorrelationsNeverJoinUnknownSidsOrReuseFailuresAtTheLockTimestamp()
    {
        const string sid = "S-1-5-21-100000001-200000002-300000003-1001";
        JsonObject Event(long id,int code,string at,string? identity=sid) => new() { ["event_db_id"]=id,["event_id"]=code,["target_user_sid"]=identity,["target_user_name"]="synthetic-user",["time_created_utc"]="2026-01-01T"+at+"Z",["normalized_event_id"]=id };
        var result = SecurityObservationReader.Lockouts([Event(1,4625,"00:00:00"),Event(2,4740,"00:01:00"),Event(3,4767,"00:02:00"),Event(4,4740,"00:03:00"),Event(5,4625,"00:03:00"),Event(6,4740,"00:04:00",null),Event(7,4740,"00:05:00",null)],15,2);
        var row=Assert.Single(result); Assert.Equal(2,row["lockouts"]!.GetValue<int>()); Assert.Equal(1,row["failures"]!.GetValue<int>()); Assert.Equal(1,row["relocks"]!.GetValue<int>());
    }
    [Fact]
    public void RevocationRequiresTheSameDomainExactSidAndCurrentSemantics()
    {
        JsonObject Event(long id,int code,int domain,string time,string type) => new() { ["event_db_id"]=id,["event_id"]=code,["domain_id"]=domain,["time_created_utc"]="2026-01-01T"+time+"Z",["target_user_sid"]="S-1-5-21-100000001-200000002-300000003-1001",["processing_status"]="normalized",["semantic_type"]=type };
        var rows=SecurityObservationReader.Revocations([Event(1,4725,1,"00:00:00","directory.account.disabled"),Event(2,4624,1,"00:01:00","authentication.session.created"),Event(3,4624,2,"00:02:00","authentication.session.created"),Event(4,4624,1,"00:03:00","old_semantics")],[],DateTimeOffset.Parse("2026-01-01T00:00:00Z"),DateTimeOffset.Parse("2026-01-02T00:00:00Z"),1440);
        Assert.Equal(2,rows.Length); Assert.Single(rows,r=>r["activity_type"]!.ToString()=="logon"); Assert.Single(rows,r=>r["activity_type"]!.ToString()=="insufficient");
    }
    static ReportDefinition Definition(string key) => new ReportDefinitionRegistry().Get(key)!;
    internal static AccessFacts Facts(ReportDefinition d,string scope="{\"kind\":\"all\"}",bool assigned=true)
    {
        var fields=new HashSet<string>(["technical","identity_basic","security","privilege","hr","contact","raw_evidence","computer_logon_observation"]);
        var rows=d.Declaration.ToJsonString();
        // All actual category declarations are metadata in arrays, never authority from a request.
        void Categories(JsonNode? node)
        {
            if(node is JsonObject o) foreach(var pair in o) { if(pair.Key is "field_categories" or "required_fields" && pair.Value is JsonArray a) foreach(var v in a) fields.Add(v!.GetValue<string>()); else Categories(pair.Value); }
            else if(node is JsonArray a) foreach(var child in a) Categories(child);
        }
        Categories(d.Declaration);
        var caps=fields.Select(f=>"field."+f).Concat(d.Rule["required_capabilities"]?.AsArray().Select(v=>v!.GetValue<string>())??[]).Concat(["reports.export","evidence.exact"]).Distinct();
        var policies=caps.Select(c=>ReportFixture.J(JsonSerializer.Serialize(new {capability_key=c,effect="allow",scope_json=new{kind="all"}}))).ToArray();
        var assignment=new JsonObject { ["report_key"]=d.AccessKey,["effect"]="allow",["allowed_actions"]=new JsonArray("view","export"),["field_categories"]=JsonSerializer.SerializeToNode(fields),["scope_json"]=JsonNode.Parse(scope) };
        var definition=new JsonObject { ["report_key"]=d.AccessKey,["version"]=1,["dataset_version"]=1,["definition_json"]=new JsonObject{["actions"]=new JsonArray("view","export")},["actions_json"]=new JsonArray("view","export"),["fields_json"]=JsonSerializer.SerializeToNode(fields.Select(f=>new{category=f})) };
        return new(false,"admin",[],[],policies,[],[],assigned?[ReportFixture.J(assignment.ToJsonString())]:[],[ReportFixture.J(definition.ToJsonString())]);
    }
    public static IEnumerable<object[]> RegisteredReports() => new ReportRuleCatalog(new PluginGenerationReader(null)).Capture().Rules.Select(r=>new object[]{r.RegistryKey,r.OwnerId});
    [Theory]
    [InlineData("persistence-changes")]
    [InlineData("account-revocation")]
    [InlineData("lockout-recurring")]
    [InlineData("daily")]
    [InlineData("chains")]
    public async Task Domain_changes_does_not_publish_or_execute_hidden_tabs(string tab)
    {
        var d = Definition("security.events.chains");
        var reader = new ReportFixture.Reader { ReportKey = d.Key, OwnerId = "sli.core", Query = c => ReportResult.Create(c.Definition.Key, "empty") };
        await using var h = await ReportFixture.Start(Facts(d), d, suppliedReader: reader);
        using var declaration = await h.Client.GetAsync($"/api/v2/reports/{d.Key}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, declaration.StatusCode);
        var body = await ReportFixture.Body(declaration);
        Assert.DoesNotContain(body["views"]!.AsArray(), v => v!["key"]!.GetValue<string>() == tab);
        Assert.Contains(body["views"]!.AsArray(), v => v!["key"]!.GetValue<string>() == "events");
        foreach (string action in new[] { "data", "export.csv" })
        {
            using var response = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/{action}?domain=1&tab={tab}", TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("report_tab_invalid", (await ReportFixture.Body(response))["error"]!.GetValue<string>());
        }
        Assert.Equal(0, reader.Calls);
        using var events = await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data?domain=1&tab=events", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, events.StatusCode);
        Assert.Equal(1, reader.Calls);
    }

    [Theory][MemberData(nameof(RegisteredReports))]
    public async Task FrozenDefinitionsDispatchToTheirOwnerWithActualReactParameters(string key,string owner)
    {
        var d=Definition(key); var reader=new ReportFixture.Reader{ReportKey=key,OwnerId=owner,Query=c=>ReportResult.Create(c.Definition.Key,"empty")};
        await using var h=await ReportFixture.Start(Facts(d),d,suppliedReader:reader);
        string suffix=d.Params.Any(p=>p["key"]!.GetValue<string>()=="domain")?"?domain=1":"";
        using var r=await h.Client.GetAsync($"/api/v2/reports/{key}/data{suffix}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,r.StatusCode); Assert.Equal(1,reader.Calls); Assert.Equal("empty",(await ReportFixture.Body(r))["state"]!.GetValue<string>());
        Assert.All(reader.Last!.Grants,g=>Assert.Equal(1,g.DatasetVersion));
    }
    [Theory][InlineData("?domain_id=1",HttpStatusCode.OK)][InlineData("?domain_id=1&domain=2",HttpStatusCode.BadRequest)]
    [InlineData("?domain_id=0",HttpStatusCode.BadRequest)][InlineData("?domain_id=1&domain_id=1",HttpStatusCode.BadRequest)]
    [InlineData("?domain_id=3",HttpStatusCode.Forbidden)]
    public async Task SharedDomainSelectorValidatesAliasesAndDoesNotWidenGrants(string query,HttpStatusCode expected)
    {
        var d=Definition("ad.users.v2"); var reader=new ReportFixture.Reader{ReportKey=d.Key,OwnerId="sli.ad",Query=c=>ReportResult.Create(c.Definition.Key,"empty")};
        await using var h=await ReportFixture.Start(Facts(d,"{\"kind\":\"domain\",\"ids\":[1,2]}"),d,suppliedReader:reader);
        using var r=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data{query}",TestContext.Current.CancellationToken);
        Assert.Equal(expected,r.StatusCode);
        if(expected==HttpStatusCode.OK)
        {
            var body=await ReportFixture.Body(r); Assert.Equal("domain",body["domain_scope"]!["mode"]!.GetValue<string>());
            Assert.Equal(new long[]{1},reader.Last!.DomainIds); Assert.Equal(1,reader.Last.Params["domain"]!.GetValue<int>());
        }
        else Assert.Equal(0,reader.Calls);
    }
    [Fact]
    public async Task AccessibleDomainSelectionOmitsArchivedDomainsAndPassesExistingSnapshotMetadata()
    {
        var d=Definition("ad.users.v2"); var reader=new ReportFixture.Reader{ReportKey=d.Key,OwnerId="sli.ad",Query=c=>ReportResult.Create(c.Definition.Key,"empty")};
        await using var h=await ReportFixture.Start(Facts(d),d,suppliedReader:reader);
        using var r=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,r.StatusCode); var body=await ReportFixture.Body(r);
        Assert.Single(body["domains"]!.AsArray()); Assert.Equal("one.example",body["domains"]![0]!["display_name"]!.GetValue<string>());
        Assert.Equal("accessible",body["domain_scope"]!["mode"]!.GetValue<string>()); Assert.Equal(new long[]{1},reader.Last!.DomainIds);
    }
    [Theory]
    [InlineData("ad.users.v2")]
    [InlineData("ad.computers.v6")]
    [InlineData("ad.infrastructure")]
    public async Task ExplicitArchivedDomainRemainsAuthorizedAndArchiveMetadataIsSeparateFromFreshness(string key)
    {
        var d = Definition(key);
        var reader = new ReportFixture.Reader { ReportKey = key, OwnerId = "sli.ad", Query = c => ReportResult.Create(c.Definition.Key, "empty") };
        await using var h = await ReportFixture.Start(Facts(d, "{\"kind\":\"domain\",\"ids\":[1,2]}"), d, suppliedReader: reader);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{key}/data?domain_id=2", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(new long[] { 2 }, reader.Last!.DomainIds);
        var domain = Assert.Single((await ReportFixture.Body(response))["domains"]!.AsArray())!;
        Assert.Equal(2, (long)domain["id"]!);
        Assert.True((bool)domain["is_archived"]!);
        Assert.False(domain["freshness"]!.AsObject().ContainsKey("is_archived"));
    }
    [Fact]
    public async Task VpnDefaultsStayInsideSourceOptionsAndDisabledCollectionDoesNotBecomeEmptySuccess()
    {
        var d=Definition("vpn.connections");
        var reader=new ReportFixture.Reader{ReportKey=d.Key,OwnerId="sli.remote-access",Options=ReportFixture.O("""{"domain":[{"value":1,"label":"one"}]}"""),Query=c=>ReportResult.Create(c.Definition.Key,"empty")};
        var metadata=new ReportFixture.Metadata{Preferred="one.example",Plugin=ReportFixture.O("""{"plugin_id":"sli.remote-access","state":"disabled","read_only":true}""")};
        await using var h=await ReportFixture.Start(Facts(d),d,suppliedReader:reader,metadata:metadata);
        using var r=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,r.StatusCode); Assert.Equal(1,reader.Last!.Params["domain"]!.GetValue<int>());
        var body=await ReportFixture.Body(r); Assert.Equal("unavailable",body["state"]!.GetValue<string>()); Assert.Equal("not_collected",body["reason"]!.GetValue<string>());
        metadata.Preferred="invisible.example";
        using var unknown=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,unknown.StatusCode); Assert.Equal(1,reader.Calls);
    }
    [Fact]
    public void DefaultDomainUsesConfirmedObservationAndStableTieBreakWithinNonArchivedDomains()
    {
        static DomainItem D(long id,string? observed,bool archived=false)=>new(id,$"d{id}.example",archived,new(null,null,null,null,observed,null,null));
        var now=DateTimeOffset.Parse("2026-11-05T00:00:00Z");
        var rows=new[]{D(1,"2026-11-04T00:00:00Z"),D(2,"2026-11-04T00:00:00Z"),D(3,"2026-11-06T00:00:00Z"),D(4,"2026-11-04T23:00:00Z",true),D(5,null)};
        Assert.Equal(1,ReportV2Metadata.ChooseDomain(rows,null,now)!.Id); Assert.Equal(5,ReportV2Metadata.ChooseDomain(rows,"D5.EXAMPLE",now)!.Id);
        Assert.Null(ReportV2Metadata.ChooseDomain([D(1,null)],null,now));
    }
    [Fact]
    public async Task LegacyCsvExporterWithUnexpectedHeaderCannotExposeHiddenColumns()
    {
        await using var h=await ReportFixture.Start(); h.Reader.Csv="Private,ID\r\nprivate-value,1\r\n";
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/export.csv",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.DoesNotContain("private-value",await r.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Fact]
    public async Task MissingDetailAndExportCallbacksUse404ContractsBeforeReaderExecution()
    {
        var d=ReportFixture.Definition(); d.Declaration["detail"]="none";d.Declaration["export"]=false;
        await using var h=await ReportFixture.Start(definition:d);
        using var detail=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/rows/1/detail",TestContext.Current.CancellationToken);
        using var export=await h.Client.GetAsync($"/api/v2/reports/{d.Key}/export.csv",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound,detail.StatusCode);Assert.Equal(HttpStatusCode.NotFound,export.StatusCode);Assert.Equal(0,h.Reader.Calls);
    }
}
