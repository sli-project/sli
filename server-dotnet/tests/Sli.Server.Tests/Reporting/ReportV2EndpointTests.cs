using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Domains;
using Sli.Server.Reporting.V2;
using Xunit;
namespace Sli.Server.Tests.Reporting;

internal static class ReportFixture
{
    internal const string Key = "file-audit.actions";
    internal static JsonElement J(string json) => JsonDocument.Parse(json).RootElement.Clone();
    internal static JsonObject O(string json) => JsonNode.Parse(json)!.AsObject();
    internal static ReportDefinition Definition() => new(O("""
        {"key":"file-audit.actions","access_rule":{"report_key":"file-audit.actions","scope":"generic","required_fields":["technical"]},
         "params":[{"key":"q","kind":"text"},{"key":"source_instance_id","kind":"text"},{"key":"private","kind":"text","field_categories":["extra"]}],
         "columns":[{"key":"id","label":"ID","sortable":true},{"key":"secret","path":"nested.secret","label":"Private","sortable":true,"field_categories":["extra"]}],
         "views":[{"key":"table","source":"items"},{"key":"extra","source":"hidden","access_rule":{"report_key":"file-audit.actions","required_fields":["extra"]},"columns":[]}],
         "detail":{"query_available":true,"default_limit":2,"columns":[{"key":"secret","label":"Private","field_categories":["extra"]}]},
         "limits":{"default":5,"max":10},"export":true,"row_categories":{"nested.other":["extra"]},
         "metric_categories":{"secret":["extra"]},"series_categories":{"secret":["extra"]}}
        """));
    internal static AccessFacts Facts(string scope = "{\"kind\":\"all\"}", bool assigned = true, bool export = true, long dataset = 1) => new(false,"viewer",[],[],
        new[] { "field.technical", "field.extra", "reports.export" }.Select(c => J(JsonSerializer.Serialize(new {capability_key=c,effect="allow",scope_json=new {kind="all"}}))).ToArray(),[],[],
        assigned ? [J("""{"report_key":"file-audit.actions","effect":"allow","allowed_actions":["view"$$$],"field_categories":["technical"],"scope_json":$$scope} """.Replace("$$$",export?",\"export\"":"").Replace("$$scope",scope))] : [],
        [J("""{"report_key":"file-audit.actions","version":1,"dataset_version":$$dataset,"definition_json":{"actions":["view","export"]},"actions_json":["view","export"],"fields_json":[{"category":"technical"},{"category":"extra"}]}""".Replace("$$dataset",dataset.ToString()))]);
    internal static AccessDecision Access(string scope = "{\"kind\":\"all\"}")
    { var facts = Facts(scope); return new ReportEligibility().Compose(facts,new CapabilityComposer().Compose(facts)); }
    internal sealed class Auth : IPrincipalAuthenticator
    {
        public bool Deny; public string Role = "viewer";
        public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext context,CancellationToken ct) => ValueTask.FromResult(Deny ? AuthenticationResult.Denied(401,"authentication_required") : AuthenticationResult.Success(new("session",7,Role)));
    }
    internal sealed class FactsRepo(AccessFacts facts) : IAccessFactsRepository
    {
        public AccessFacts Value = facts;
        public Task<AccessFacts> LoadAsync(Principal principal,CancellationToken ct) => Task.FromResult(Value);
    }
    internal sealed class Definitions(ReportDefinition definition) : IReportDefinitionRegistry
    { public ReportDefinition? Get(string key) => key == definition.Key ? new((JsonObject)definition.Declaration.DeepClone()) : null; }
    internal sealed class Reader : IReportV2Reader
    {
        public string OwnerId { get; init; } = "sli.file-audit";
        public string ReportKey { get; init; } = Key;
        public JsonObject Options = new();
        public Task<JsonObject> OptionsAsync(ReportDefinition definition, AccessDecision access, CancellationToken ct) => Task.FromResult(Options);
        public string Csv = "ID,Private\r\n1,private-value\r\n";
        public bool Handles(string key) => key == ReportKey;
        public int Calls; public ReportQueryContext? Last; public string? Row;
        public Func<ReportQueryContext,JsonObject>? Query;
        public Action? DuringRead;
        public Task<JsonObject> QueryAsync(ReportQueryContext context,CancellationToken ct)
        {
            Calls++; Last=context; DuringRead?.Invoke();
            return Task.FromResult(Query?.Invoke(context) ?? O("""{"state":"ok","items":[{"id":1,"nested":{"secret":"private-value","other":"private-value"}}],"has_more":true,"next_cursor":"position-2","metrics":[{"key":"secret","value":"private-value"}],"series":{"secret":["private-value"]},"collections":{"hidden":[{"secret":"private-value"}]},"filter_options":{"private":[{"value":"private-value"}]}}"""));
        }
        public Task<JsonObject> DetailAsync(ReportQueryContext context,string row,CancellationToken ct)
        { Row=row; var result = QueryAsync(context,ct).GetAwaiter().GetResult(); result["items"] = JsonNode.Parse("""[{"id":1,"secret":"private-value"}]"""); return Task.FromResult(result); }
        public Task<ReportExport> ExportAsync(ReportQueryContext context,CancellationToken ct)
        { Calls++; Last=context; DuringRead?.Invoke(); return Task.FromResult(new ReportExport(Csv,1,true)); }
    }
    internal sealed class Domains : IReportDomains
    {
        public long[]? Last;
        public Task<IReadOnlyList<DomainItem>> ReadAsync(long[]? ids,CancellationToken ct)
        { Last=ids; return Task.FromResult<IReadOnlyList<DomainItem>>(new DomainItem[]{new(1,"one.example",false,new(null,null,null,null,null,null,null)),new(2,"old.example",true,new(null,null,null,null,null,null,null))}.Where(d=>ids is null || ids.Contains(d.Id)).ToArray()); }
    }
    internal sealed class Metadata : IReportV2Metadata
    {
        public string? Preferred; public JsonObject? Plugin;
        public Task<string?> PreferredDomainAsync(CancellationToken ct) => Task.FromResult(Preferred);
        public Task<JsonObject?> PluginAsync(string key,CancellationToken ct) => Task.FromResult(key.StartsWith("vpn.",StringComparison.Ordinal)?Plugin:null);
    }
    internal sealed class Host(IHost host,HttpClient client,Reader reader,FactsRepo facts,Auth auth) : IAsyncDisposable
    {
        public HttpClient Client => client; public Reader Reader => reader; public FactsRepo Facts => facts; public Auth Auth => auth;
        public async ValueTask DisposeAsync() { client.Dispose(); await host.StopAsync(); host.Dispose(); }
    }
    internal static async Task<Host> Start(AccessFacts? facts = null, ReportDefinition? definition = null, IReportCatalogProvider? catalog = null, bool withReader = true, Reader? suppliedReader = null, Metadata? metadata = null, IReportV2Reader? nativeReader = null, ILoggerProvider? logger = null, bool workstationRoutes = false)
    {
        var repo=new FactsRepo(facts??Facts()); var reader=suppliedReader??new Reader(); var auth=new Auth {Role=repo.Value.Role};
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();
        var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting(); services.AddLogging(); services.AddSingleton<IConfiguration>(config);
            if (logger is not null) services.AddSingleton(logger);
            services.AddSingleton(new AuthRequestPolicy(config)); services.AddSingleton(new TransportGate(config));
            services.AddSingleton<IPrincipalAuthenticator>(auth); services.AddSingleton<IAccessFactsRepository>(repo);
            services.AddSingleton<IReportDefinitionRegistry>(new Definitions(definition??Definition()));
            services.AddSingleton<IReportCatalogProvider>(catalog??new ReportRuleCatalog(new PluginGenerationReader(null)));
            services.AddSingleton<IReportV2Metadata>(metadata??new Metadata());
            services.AddSingleton<IReportDomains>(new Domains()); services.AddScoped<ReportV2Dispatcher>();
            if(withReader) services.AddSingleton<IReportV2Reader>(nativeReader ?? reader);
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(e=>{e.MapReportV2Engine();if(workstationRoutes) Sli.Server.Workstations.WorkstationEndpoints.MapWorkstationReports(e);});})).StartAsync(TestContext.Current.CancellationToken);
        var client=host.GetTestClient(); client.BaseAddress=new Uri("https://localhost");
        return new(host,client,reader,repo,auth);
    }
    internal static async Task<JsonObject> Body(HttpResponseMessage response) => O(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
}
public sealed class ReportV2EndpointTests
{
    [Theory]
    [InlineData("timeout", "data")]
    [InlineData("postgres", "data")]
    [InlineData("driver", "data")]
    [InlineData("timeout", "export.csv")]
    [InlineData("postgres", "rows/one/detail")]
    public async Task Read_timeout_is_structured_and_does_not_affect_the_next_request(string failure, string action)
    {
        await using var host = await ReportFixture.Start();
        host.Reader.DuringRead = () => throw failure switch
        {
            "postgres" => new Npgsql.PostgresException("private-database-value", "ERROR", "ERROR", "57014"),
            "driver" => new Npgsql.NpgsqlException("private-database-value", new TimeoutException("private-read")),
            _ => new TimeoutException("private-database-value")
        };
        using var response = await host.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        var body = await ReportFixture.Body(response);
        Assert.Equal(2, body.Count);
        Assert.Equal("report_read_timeout", body["error"]!.GetValue<string>());
        Assert.Equal("unavailable", body["state"]!.GetValue<string>());

        host.Reader.DuringRead = null;
        using var next = await host.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, next.StatusCode);
        Assert.Equal(2, host.Reader.Calls);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("\"broken-json\"")]
    public async Task Invalid_scope_cannot_break_an_independent_valid_grant(string invalid)
    {
        var facts = ReportFixture.Facts();
        var bad = JsonNode.Parse(facts.ReportAssignments[0].GetRawText())!.AsObject();
        bad["scope_json"] = JsonNode.Parse(invalid);
        facts = facts with { ReportAssignments = [.. facts.ReportAssignments, ReportFixture.J(bad.ToJsonString())] };
        await using var h = await ReportFixture.Start(facts);
        using var response = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, h.Reader.Calls);
        h.Facts.Value = facts with { ReportAssignments = [ReportFixture.J(bad.ToJsonString())] };
        using var denied = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode); Assert.Equal(1, h.Reader.Calls);
    }

    [Fact] public async Task React_definition_route_returns_projected_declaration_and_options()
    {
        await using var h = await ReportFixture.Start();
        h.Reader.Options = ReportFixture.O("""{"q":[{"value":"visible"}],"private":[{"value":"private-value"}]}""");
        using var response = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ReportFixture.Body(response);
        Assert.Equal(ReportFixture.Key, body["key"]!.GetValue<string>());
        Assert.Single(body["columns"]!.AsArray());
        Assert.DoesNotContain(body["params"]!.AsArray(), p => p!["key"]!.GetValue<string>() == "private");
        Assert.False(body["views"]![1]!["access"]!["allowed"]!.GetValue<bool>());
        Assert.Empty(body["detail"]!["columns"]!.AsArray());
        Assert.NotNull(body["filter_options"]!["q"]); Assert.Null(body["filter_options"]!["private"]);
        Assert.Equal(0, h.Reader.Calls);
        h.Auth.Deny = true;
        using var anonymous = await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }
    [Theory]
    [InlineData("data")][InlineData("rows/ws%3Aad%3A123/detail")][InlineData("export.csv")]
    public async Task EachRegisteredRouteExecutesItsReaderAndProjectsFields(string action)
    {
        await using var h=await ReportFixture.Start();
        using var response=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?limit=5",TestContext.Current.CancellationToken);
        string text=await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,response.StatusCode); Assert.DoesNotContain("private-value",text);
        Assert.Equal(1,h.Reader.Calls); Assert.Equal(7,h.Reader.Last!.Principal.Id);
        Assert.Equal(action=="export.csv"?"export":"view",h.Reader.Last.Action);
        Assert.Equal(action.Contains("rows/")?2:5,h.Reader.Last.Paging.Limit);
        if(action.Contains("rows/")) Assert.Equal("ws:ad:123",h.Reader.Row);
        if(action=="export.csv")
        {
            byte[] bytes=await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken);
            Assert.Equal(new byte[]{0xef,0xbb,0xbf},bytes[..3]); Assert.Equal(bytes.Length,response.Content.Headers.ContentLength);
            Assert.Equal("true",response.Headers.GetValues("X-Sli-Export-Truncated").Single());
            Assert.Equal("1",response.Headers.GetValues("X-Sli-Export-Rows").Single());
            Assert.Contains("INCOMPLETE-first-1-rows",response.Content.Headers.ContentDisposition!.FileName);
            Assert.Equal("ID\r\n1\r\n",text);
        }
        else
        {
            var payload=await ReportFixture.Body(response);
            Assert.True(payload["access"]!["allowed"]!.GetValue<bool>());
            Assert.Equal("report_field_categories_not_allowed",payload["access"]!["reason"]!.GetValue<string>());
            Assert.NotEqual("position-2",payload["next_cursor"]!.GetValue<string>());
        }
    }
    [Theory][InlineData("data")][InlineData("rows/1/detail")][InlineData("export.csv")]
    public async Task EachRouteDeniesMissingGrantBeforeCallingReader(string action)
    {
        await using var h=await ReportFixture.Start(ReportFixture.Facts(assigned:false));
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal("report_access_denied",(await ReportFixture.Body(r))["error"]!.GetValue<string>()); Assert.Equal(0,h.Reader.Calls);
    }
    [Theory][InlineData("data")][InlineData("rows/1/detail")][InlineData("export.csv")]
    public async Task EachRouteRejectsInvalidInputBeforeCallingReader(string action)
    {
        await using var h=await ReportFixture.Start();
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?limit=11",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,r.StatusCode); Assert.Equal("report_limit_invalid",(await ReportFixture.Body(r))["error"]!.GetValue<string>()); Assert.Equal(0,h.Reader.Calls);
    }
    [Theory][InlineData("data")][InlineData("rows/1/detail")][InlineData("export.csv")]
    public async Task EachRouteRequiresAuthentication(string action)
    {
        await using var h=await ReportFixture.Start(); h.Auth.Deny=true;
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized,r.StatusCode); Assert.Equal(0,h.Reader.Calls);
    }
    [Theory][InlineData("?private=x")][InlineData("?sort=secret")][InlineData("?tab=extra")]
    public async Task HiddenFiltersSortAndTabsAreRefused(string query)
    {
        await using var h=await ReportFixture.Start();
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data{query}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,h.Reader.Calls);
    }
    [Fact]
    public async Task ViewGrantCannotExport()
    {
        await using var h=await ReportFixture.Start(ReportFixture.Facts(export:false));
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/export.csv",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,h.Reader.Calls);
    }
    [Theory][InlineData("data")][InlineData("rows/1/detail")]
    public async Task CursorRoundTripRestoresReaderPositionAndCannotChangeContext(string action)
    {
        await using var h=await ReportFixture.Start();
        using var first=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?q=first",TestContext.Current.CancellationToken);
        string cursor=(await ReportFixture.Body(first))["next_cursor"]!.GetValue<string>();
        using var second=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?q=first&cursor={cursor}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK,second.StatusCode); Assert.Equal("position-2",h.Reader.Last!.Paging.Cursor);
        using var changed=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?q=other&cursor={cursor}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,changed.StatusCode); Assert.Equal(2,h.Reader.Calls);
        h.Facts.Value=ReportFixture.Facts(dataset:2);
        using var version=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}?q=first&cursor={cursor}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,version.StatusCode); Assert.Equal(2,h.Reader.Calls);
    }
    [Fact]
    public async Task DetailCursorCannotMoveToAnotherRow()
    {
        await using var h=await ReportFixture.Start();
        using var first=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/rows/one/detail",TestContext.Current.CancellationToken);
        string cursor=(await ReportFixture.Body(first))["next_cursor"]!.GetValue<string>();
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/rows/two/detail?cursor={cursor}",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest,r.StatusCode); Assert.Equal(1,h.Reader.Calls);
    }
    [Fact]
    public async Task ScopeIntersectionRefusesOtherSourceBeforeRead()
    {
        await using var h=await ReportFixture.Start(ReportFixture.Facts("{\"mode\":\"restricted\",\"clauses\":[{\"source_instance_ids\":[\"one\"]}]}"));
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data?source_instance_id=two",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Forbidden,r.StatusCode); Assert.Equal(0,h.Reader.Calls);
        Assert.Equal("report_scope_not_executable",(await ReportFixture.Body(r))["reason"]!.GetValue<string>());
    }
    [Theory][InlineData("%2F")][InlineData("%252F")][InlineData("%25")][InlineData("bad!row")]
    public async Task InvalidEncodedRowsNeverReachReader(string row)
    {
        await using var h=await ReportFixture.Start();
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/rows/{row}/detail",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound,r.StatusCode); Assert.Equal(0,h.Reader.Calls);
    }
    [Fact]
    public async Task MissingReadersReportSourceErrorAndNeverInventRowsOrExport()
    {
        await using var h=await ReportFixture.Start(withReader:false);
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data",TestContext.Current.CancellationToken);
        var body=await ReportFixture.Body(r); Assert.Equal(HttpStatusCode.OK,r.StatusCode); Assert.Equal("error",body["state"]!.GetValue<string>());
        Assert.Equal("report_reader_unavailable",body["state_details"]!["reason"]!.GetValue<string>()); Assert.Empty(body["items"]!.AsArray());
        using var export=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/export.csv",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,export.StatusCode); Assert.Equal("report_reader_unavailable",(await ReportFixture.Body(export))["error"]!.GetValue<string>());
    }
    [Fact]
    public async Task GpoContractFailureHasSanitized503()
    {
        await using var h=await ReportFixture.Start(); h.Reader.Query=_=>throw new GpoReportSourceException();
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,r.StatusCode); Assert.Equal("gpo_snapshot_unavailable",(await ReportFixture.Body(r))["error"]!.GetValue<string>());
    }
    [Fact]
    public async Task StorageFailureCannotBecomeEmptySuccessOrExposeExceptionText()
    {
        await using var h=await ReportFixture.Start(); h.Reader.Query=_=>throw new InvalidOperationException("private-database-value");
        using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.InternalServerError,r.StatusCode); Assert.DoesNotContain("private-database-value",await r.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }
    [Theory][InlineData("data")][InlineData("rows/1/detail")][InlineData("export.csv")]
    public async Task PluginGenerationChangedDuringReadDiscardsResponse(string action)
    {
        string directory=Path.Combine(Path.GetTempPath(),"sli-report-test-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(directory,"sli.file-audit"));
        try
        {
            await using var h=await ReportFixture.Start(catalog:new ReportRuleCatalog(new PluginGenerationReader(directory)));
            h.Reader.DuringRead=()=>File.WriteAllText(Path.Combine(directory,"sli.file-audit","draining.json"),"{}");
            using var r=await h.Client.GetAsync($"/api/v2/reports/{ReportFixture.Key}/{action}",TestContext.Current.CancellationToken);
            Assert.Equal(HttpStatusCode.ServiceUnavailable,r.StatusCode); Assert.DoesNotContain("private-value",await r.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        }
        finally { Directory.Delete(directory,true); }
    }
}
