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
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Workstations;
using Xunit;
namespace Sli.Server.Tests.Workstations;
public sealed class WorkstationEndpointTests
{
    static IEnumerable<string> FrozenKeys => WorkstationReportContract.Keys.Where(key => key != "workstations.overview");
    sealed class Authentication(bool authenticated=true,string role="viewer"):IPrincipalAuthenticator
    {public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(authenticated?AuthenticationResult.Success(new("session",1,role)):AuthenticationResult.Denied(401,"authentication_required"));}
    sealed class Facts(bool allowed,string[]? fields=null):IAccessFactsRepository
    {
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken ct)=>Task.FromResult(new AccessFacts(allowed,p.Role,[],[],[],[],[],[],WorkstationReportContract.Keys.Select(k=>JsonSerializer.SerializeToElement(new{report_key=k,version=1,dataset_version=1,fields_json=(fields??WorkstationReportContract.Fields).Select(f=>new{category=f}),actions_json=new[]{"view"},definition_json=new{field_categories=WorkstationReportContract.Fields,actions=new[]{"view"}}})).ToArray()));
    }
    sealed class Reader:IWorkstationReports
    {
        public int Reads;public WorkstationRequest? Request;public Exception? Error;
        public Task<JsonObject> ReadAsync(WorkstationRequest r,AccessFacts f,AccessDecision a,CancellationToken ct)
        {Reads++;Request=r;if(Error is not null)throw Error;return Task.FromResult(WorkstationReportContract.Result(r.Key,items:new(new JsonObject{["station_id"]="fixture-station"})));}
    }
    static async Task<IHost> Host(Reader reader,bool allowed=true,bool authenticated=true,string role="viewer",string[]? fields=null)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{["Sli:AuthRequired"]="true"}).Build();
        return await new HostBuilder().ConfigureWebHost(w=>w.UseTestServer().ConfigureServices(s=>
        {s.AddRouting();s.AddLogging();s.AddSingleton<IConfiguration>(config);s.AddSingleton(new AuthRequestPolicy(config));s.AddSingleton(new TransportGate(config));s.AddSingleton<IPrincipalAuthenticator>(new Authentication(authenticated,role));s.AddSingleton<IAccessFactsRepository>(new Facts(allowed,fields));s.AddSingleton<IWorkstationReports>(reader);})
        .Configure(app=>{app.UseRouting();app.UseEndpoints(e=>e.MapWorkstationReports());})).StartAsync(TestContext.Current.CancellationToken);
    }
    public static IEnumerable<object[]> Routes()=>FrozenKeys.SelectMany(k=>new[]{new object[]{"/api/v2/reports/"+k},new object[]{"/api/v2/reports/"+k+"/data"}}).Concat(new[]{new object[]{"/api/v2/reports/workstations.processes/rows/"+new string('a',64)+"/detail"},new object[]{"/api/v2/reports/workstations.usb/rows/"+new string('b',64)+"/detail"}});
    [Theory][MemberData(nameof(Routes))]public async Task Every_route_is_disabled_without_reading_data(string path)
    {var reader=new Reader();using var host=await Host(reader);using var client=host.GetTestClient();using var response=await client.GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.DoesNotContain("501",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,reader.Reads);}
    public static IEnumerable<object[]> AllRoutes()=>FrozenKeys.SelectMany(k=>new[]{new object[]{"/api/v2/reports/"+k},new object[]{"/api/v2/reports/"+k+"/data"},new object[]{"/api/v2/reports/"+k+"/rows/"+new string('a',64)+"/detail"},new object[]{"/api/v2/reports/"+k+"/export.csv"}});
    [Theory][MemberData(nameof(AllRoutes))]public async Task Every_route_denies_before_data_without_grant(string path)
    {var reader=new Reader();using var host=await Host(reader,allowed:false);using var response=await host.GetTestClient().GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,reader.Reads);Assert.Contains("report_access_denied",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Single(JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject());}
    [Theory][MemberData(nameof(AllRoutes))]public async Task Every_route_requires_authentication(string path)
    {var reader=new Reader();using var host=await Host(reader,authenticated:false);using var response=await host.GetTestClient().GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Unauthorized,response.StatusCode);Assert.Equal(0,reader.Reads);}
    public static IEnumerable<object[]> QueryRoutes()=>Routes().Where(a=>((string)a[0]).EndsWith("/data")||((string)a[0]).EndsWith("/detail"));
    [Theory][MemberData(nameof(QueryRoutes))]public async Task Every_reader_route_rejects_invalid_input(string path)
    {var reader=new Reader();using var host=await Host(reader);using var response=await host.GetTestClient().GetAsync(path+"?limit=0",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.BadRequest,response.StatusCode);Assert.Contains("report_limit_invalid",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,reader.Reads);}
    [Theory][InlineData("workstations.logons")][InlineData("workstations.protection")]
    public async Task Undeclared_detail_returns_source_404(string key)
    {using var host=await Host(new());using var response=await host.GetTestClient().GetAsync($"/api/v2/reports/{key}/rows/{new string('a',64)}/detail",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);Assert.Contains("report_detail_not_available",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));}
    [Theory][InlineData("workstations.processes")][InlineData("workstations.logons")][InlineData("workstations.usb")][InlineData("workstations.protection")]
    public async Task Undeclared_export_returns_source_404(string key)
    {using var host=await Host(new());using var response=await host.GetTestClient().GetAsync($"/api/v2/reports/{key}/export.csv",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);Assert.Contains("report_export_not_available",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));}
    [Theory][MemberData(nameof(QueryRoutes))]public async Task Every_reader_denies_missing_atomic_field_categories(string path)
    {var reader=new Reader();using var host=await Host(reader,fields:["identity_basic","technical"]);using var response=await host.GetTestClient().GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Contains("report_field_categories_not_allowed",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));Assert.Equal(0,reader.Reads);}
    [Theory][MemberData(nameof(AllRoutes))]public async Task Every_route_denies_unrecognized_coarse_roles(string path)
    {var reader=new Reader();using var host=await Host(reader,role:"unknown");using var response=await host.GetTestClient().GetAsync(path,TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.Forbidden,response.StatusCode);Assert.Equal(0,reader.Reads);}
    [Theory][InlineData("operator")][InlineData("admin")][InlineData("viewer")]
    public async Task Authorized_roles_cannot_reenable_hidden_module(string role)
    {using var host=await Host(new(),role:role);using var response=await host.GetTestClient().GetAsync("/api/v2/reports/workstations.processes/data",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);}
    [Theory][InlineData("workstations.logons")][InlineData("workstations.processes")][InlineData("workstations.usb")][InlineData("workstations.protection")]
    public async Task Disabled_declaration_does_not_read_query_data(string key)
    {var reader=new Reader();using var host=await Host(reader);using var response=await host.GetTestClient().GetAsync($"/api/v2/reports/{key}?limit=0&unknown=fixture",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);Assert.Equal(0,reader.Reads);}
    [Fact]public async Task Frozen_router_does_not_expose_overview_evidence()
    {var reader=new Reader();using var host=await Host(reader);using var response=await host.GetTestClient().GetAsync("/api/v2/reports/workstations.overview/rows/fixture-station/detail?finding_id="+new string('a',64)+"&evidence_index=101",TestContext.Current.CancellationToken);Assert.Equal(HttpStatusCode.NotFound,response.StatusCode);Assert.Equal(0,reader.Reads);}
    [Theory][InlineData("workstations.processes")][InlineData("workstations.usb")]
    public async Task Disabled_detail_does_not_call_a_reader(string key)
    {
        var reader=new Reader{Error=new WorkstationException("workstation_access_denied",403)}; using var host=await Host(reader);
        using var response=await host.GetTestClient().GetAsync("/api/v2/reports/"+key+"/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,reader.Reads);
    }
    [Fact]public async Task Hidden_module_does_not_serve_a_declaration()
    {
        var reader=new Reader(); using var host=await Host(reader);
        using var response=await host.GetTestClient().GetAsync("/api/v2/reports/workstations.processes",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,reader.Reads);
    }
    [Fact]public async Task Disabled_module_does_not_resolve_a_reader()
    {
        var reader=new Reader{Error=new WorkstationException("workstation_access_denied",403)}; using var host=await Host(reader);
        using var response=await host.GetTestClient().GetAsync("/api/v2/reports/workstations.processes/data",TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable,response.StatusCode);
        Assert.Contains("module_disabled",await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken)); Assert.Equal(0,reader.Reads);
    }
}

