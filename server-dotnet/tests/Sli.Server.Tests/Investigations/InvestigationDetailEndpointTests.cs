using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Sli.Server.Access;
using Sli.Server.Auth;
using Sli.Server.Auth.Lifecycle;
using Sli.Server.Investigations;
using Xunit;

namespace Sli.Server.Tests.Investigations;
public class InvestigationDetailEndpointTests
{
    sealed class Facts(bool includeReport=true) : IAccessFactsRepository
    {
        static JsonElement J(string s)=>JsonDocument.Parse(s).RootElement.Clone();
        public Task<AccessFacts> LoadAsync(Principal p,CancellationToken c)=>Task.FromResult(new AccessFacts(false,"viewer",[],[],
          [J("""{"capability_key":"investigations.view","effect":"allow","scope_json":{"kind":"all"}}""")],[],[],
          includeReport?[J("""{"report_key":"investigations.workspace","effect":"allow","allowed_actions":["view"],"field_categories":[],"scope_json":{"kind":"domain","ids":[1]}}""")]:[],
          [J("""{"report_key":"investigations.workspace","version":1,"dataset_version":1,"definition_json":{"actions":["view"]},"actions_json":["view"],"fields_json":[]}""")]));
    }
    sealed class Authentication : IPrincipalAuthenticator { public ValueTask<AuthenticationResult> AuthenticateAsync(HttpContext c,CancellationToken ct)=>ValueTask.FromResult(AuthenticationResult.Success(new("session",1,"viewer"))); }
    sealed class Groups : IInvestigationRepository
    {
        public int Reads; public Task<IReadOnlyList<IReadOnlyList<AccessResource>>> ResourceGroupsAsync(InvestigationIdentity id,CancellationToken ct) {Reads++;return Task.FromResult<IReadOnlyList<IReadOnlyList<AccessResource>>>([[new("domain",2)]]);}
        public Task<InvestigationNote> AddNoteAsync(InvestigationIdentity id,string body,string actor,CancellationToken ct)=>throw new NotImplementedException();
    }
    sealed class Vpn : IInvestigationVpnEvidence { public bool Allowed(AccessDecision access,long domainId)=>true; }
    sealed class Detail : IInvestigationDetailRepository
    {
        public InvestigationEvidenceOptions? Page; public int Reads;
        public Task<JsonObject> ReadAsync(InvestigationIdentity id,AccessDecision access,string report,InvestigationEvidenceOptions? page,IInvestigationVpnEvidence vpn,CancellationToken ct)
        { Reads++; Page=page; return Task.FromResult(JsonNode.Parse("""{"id":1,"title":"case","status":"new","created_by":"a","events":[],"evidence_refs":[],"notes":[],"audit":[{"id":2}],"evidence_page_size":100,"events_total":0,"evidence_refs_total":0,"evidence_refs_state":"available"}""")!.AsObject()); }
    }
    [Fact]
    public async Task EvidencePageDispatchesOptionsAndKeepsAudit()
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build(); var detail=new Detail();
        using var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new Facts()).AddSingleton<IInvestigationDetailRepository>(detail).AddSingleton<IInvestigationVpnEvidence>(new Vpn()).BuildServiceProvider();
        var ctx=new DefaultHttpContext{RequestServices=provider}; ctx.Request.Method="GET";ctx.Request.Scheme="https";ctx.Request.Path="/api/v1/investigations/1";ctx.Request.QueryString=new("?evidence_page=1&event_after=9&anchor_event_id=8");ctx.Response.Body=new MemoryStream();
        await InvestigationDetailEndpoints.HandleAsync(ctx);
        Assert.Equal(200,ctx.Response.StatusCode);Assert.Equal(1,detail.Reads); Assert.Equal("9",detail.Page!.EventAfter);Assert.Equal("8",detail.Page.AnchorEventId);
        ctx.Response.Body.Position=0; using var json=await JsonDocument.ParseAsync(ctx.Response.Body,cancellationToken:TestContext.Current.CancellationToken);Assert.Equal(2,json.RootElement.GetProperty("audit")[0].GetProperty("id").GetInt32());
    }
    [Theory]
    [InlineData(true,404)] [InlineData(false,403)]
    public async Task NormalReadDenialStopsBeforeCaseRead(bool report,int status)
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build();var detail=new Detail();var groups=new Groups();
        using var provider=new ServiceCollection().AddLogging().AddSingleton<IConfiguration>(config).AddSingleton(new AuthRequestPolicy(config)).AddSingleton(new TransportGate(config)).AddSingleton<IPrincipalAuthenticator>(new Authentication()).AddSingleton<IAccessFactsRepository>(new Facts(report)).AddSingleton<IInvestigationRepository>(groups).AddSingleton<IInvestigationDetailRepository>(detail).AddSingleton<IInvestigationVpnEvidence>(new Vpn()).BuildServiceProvider();
        var ctx=new DefaultHttpContext{RequestServices=provider};ctx.Request.Method="GET";ctx.Request.Scheme="https";ctx.Request.Path="/api/v1/investigations/1";ctx.Response.Body=new MemoryStream();
        await InvestigationDetailEndpoints.HandleAsync(ctx);
        Assert.Equal(status,ctx.Response.StatusCode);Assert.Equal(0,detail.Reads);Assert.Equal(report?1:0,groups.Reads);
    }
    [Fact]
    public async Task RegisteredDetailGetDispatchesPageWithoutCapturingWorkspace()
    {
        var config=new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>{{"Sli:AuthRequired","true"}}).Build(); var detail=new Detail();
        using var host=await new HostBuilder().ConfigureWebHost(web=>web.UseTestServer().ConfigureServices(services=>
        {
            services.AddRouting();services.AddLogging();services.AddSingleton<IConfiguration>(config);services.AddSingleton(new AuthRequestPolicy(config));services.AddSingleton(new TransportGate(config));services.AddSingleton<IPrincipalAuthenticator>(new Authentication());services.AddSingleton<IAccessFactsRepository>(new Facts());services.AddSingleton<IInvestigationDetailRepository>(detail);services.AddSingleton<IInvestigationVpnEvidence>(new Vpn());
        }).Configure(app=>{app.UseRouting();app.UseEndpoints(routes=>routes.MapInvestigationDetail());})).StartAsync(TestContext.Current.CancellationToken);
        using var client=host.GetTestClient(); using var detailResponse=await client.GetAsync("/api/v1/investigations/1?evidence_page=1",TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.ServiceUnavailable,detailResponse.StatusCode);Assert.Equal(0,detail.Reads);
        using var workspaceResponse=await client.GetAsync("/api/v1/investigations",TestContext.Current.CancellationToken);
        Assert.Equal(System.Net.HttpStatusCode.NotFound,workspaceResponse.StatusCode);Assert.Equal(0,detail.Reads);
    }
}
